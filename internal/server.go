package tfa

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/thomseddon/traefik-forward-auth/internal/provider"
	muxhttp "github.com/traefik/traefik/v2/pkg/muxer/http"
)

// Server contains muxer and handler methods
type Server struct {
	muxer *muxhttp.Muxer
}

// NewServer creates a new server object and builds muxer
func NewServer() *Server {
	s := &Server{}
	s.buildRoutes()
	return s
}

func (s *Server) buildRoutes() {
	var err error
	s.muxer, err = muxhttp.NewMuxer()
	if err != nil {
		log.Fatal(err)
	}

	// Let's build a muxer
	for name, rule := range config.Rules {
		matchRule := rule.formattedRule()
		if rule.Action == "allow" {
			_ = s.muxer.AddRoute(matchRule, 1, s.AllowHandler(name))
		} else {
			_ = s.muxer.AddRoute(matchRule, 1, s.AuthHandler(rule.Provider, name))
		}
	}

	// Add callback handler
	s.muxer.Handle(config.Path, s.AuthCallbackHandler())

	// Add logout handler
	s.muxer.Handle(config.Path+"/logout", s.LogoutHandler())

	// Add a default handler
	if config.DefaultAction == "allow" {
		s.muxer.NewRoute().Handler(s.AllowHandler("default"))
	} else {
		s.muxer.NewRoute().Handler(s.AuthHandler(config.DefaultProvider, "default"))
	}
}

// RootHandler Overwrites the request method, host and URL with those from the
// forwarded request so it's correctly routed by mux
func (s *Server) RootHandler(w http.ResponseWriter, r *http.Request) {
	// Modify request
	r.Method = r.Header.Get("X-Forwarded-Method")
	r.Host = r.Header.Get("X-Forwarded-Host")

	// Read URI from header if we're acting as forward auth middleware
	if _, ok := r.Header["X-Forwarded-Uri"]; ok {
		r.URL, _ = url.Parse(r.Header.Get("X-Forwarded-Uri"))
	}

	// Pass to mux
	s.muxer.ServeHTTP(w, r)
}

// AllowHandler Allows requests
func (s *Server) AllowHandler(rule string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.logger(r, "Allow", rule, "Allowing request")
		w.WriteHeader(200)
	}
}

// AuthHandler Authenticates requests
func (s *Server) AuthHandler(providerName, rule string) http.HandlerFunc {
	p, _ := config.GetConfiguredProvider(providerName)

	return func(w http.ResponseWriter, r *http.Request) {
		// Logging setup
		logger := s.logger(r, "Auth", rule, "Authenticating request")

		// Get auth cookie
		c, err := r.Cookie(config.CookieName)
		if err != nil {
			s.authRedirect(logger, w, r, p)
			return
		}

		// Validate cookie
		email, err := ValidateCookie(r, c)
		if err != nil {
			if err.Error() == "Cookie has expired" {
				logger.Info("Cookie has expired")
				s.authRedirect(logger, w, r, p)
			} else {
				logger.WithField("error", err).Warn("Invalid cookie")
				http.Error(w, "Not authorized", 401)
			}
			return
		}

		// Validate user
		valid := ValidateEmail(email, rule)
		if !valid {
			logger.WithField("email", email).Warn("Invalid email")
			http.Error(w, "Not authorized", 401)
			return
		}

		// Valid request
		logger.Debug("Allowing valid request")
		w.Header().Set("X-Forwarded-User", email)
		w.WriteHeader(200)
	}
}

// AuthCallbackHandler Handles auth callback request
func (s *Server) AuthCallbackHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Logging setup
		logger := s.logger(r, "AuthCallback", "default", "Handling callback")

		state := r.URL.Query().Get("state")
		code := r.URL.Query().Get("code")

		// Try the normal forward-auth CSRF flow first.
		// FindCSRFCookie requires state to be at least 6 chars (used as cookie name suffix).
		var c *http.Cookie
		var csrfErr error
		if len(state) >= 6 {
			c, csrfErr = FindCSRFCookie(r, state)
		} else {
			csrfErr = http.ErrNoCookie
		}
		if csrfErr == nil {
			// Normal flow: forward-auth initiated the OAuth request
			if err := ValidateState(state); err != nil {
				logger.WithFields(logrus.Fields{
					"error": err,
				}).Warn("Error validating state")
				http.Error(w, "Not authorized", 401)
				return
			}

			valid, providerName, redirect, err := ValidateCSRFCookie(c, state)
			if !valid {
				logger.WithFields(logrus.Fields{
					"error":       err,
					"csrf_cookie": c,
				}).Warn("Error validating csrf cookie")
				http.Error(w, "Not authorized", 401)
				return
			}

			p, err := config.GetConfiguredProvider(providerName)
			if err != nil {
				logger.WithFields(logrus.Fields{
					"error":       err,
					"csrf_cookie": c,
					"provider":    providerName,
				}).Warn("Invalid provider in csrf cookie")
				http.Error(w, "Not authorized", 401)
				return
			}

			http.SetCookie(w, ClearCSRFCookie(r, c))

			token, err := p.ExchangeCode(redirectUri(r), code)
			if err != nil {
				logger.WithField("error", err).Error("Code exchange failed with provider")
				http.Error(w, "Service unavailable", 503)
				return
			}

			user, err := p.GetUser(token)
			if err != nil {
				logger.WithField("error", err).Error("Error getting user")
				http.Error(w, "Service unavailable", 503)
				return
			}

			http.SetCookie(w, MakeCookie(r, user.Email))
			logger.WithFields(logrus.Fields{
				"provider": providerName,
				"redirect": redirect,
				"user":     user.Email,
			}).Info("Successfully generated auth cookie, redirecting user.")
			http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
			return
		}

		// No CSRF cookie found — check for bridge-initiated PKCE flow.
		// The magic-link bridge encodes the PKCE code_verifier in the state as:
		//   {code_verifier}:{session_data}
		// When the bridge initiates auth, forward-auth has no CSRF cookie for the
		// callback. We detect this by the presence of a ':' in state and a non-empty code.
		colonIdx := strings.Index(state, ":")
		if code == "" || colonIdx <= 0 {
			logger.Info("Missing csrf cookie")
			http.Error(w, "Not authorized", 401)
			return
		}

		// Bootstrap mode: extract code_verifier from state and exchange with PKCE
		codeVerifier := state[:colonIdx]
		logger.Info("Bootstrap: bridge-initiated PKCE flow, exchanging code with verifier")

		p, err := config.GetConfiguredProvider(config.DefaultProvider)
		if err != nil {
			logger.WithField("error", err).Warn("Bootstrap: invalid default provider")
			http.Error(w, "Not authorized", 401)
			return
		}

		token, err := p.ExchangeCodeWithPKCE(redirectUri(r), code, codeVerifier)
		if err != nil {
			logger.WithField("error", err).Error("Bootstrap: code exchange failed")
			http.Error(w, "Service unavailable", 503)
			return
		}

		user, err := p.GetUser(token)
		if err != nil {
			logger.WithField("error", err).Error("Bootstrap: error getting user")
			http.Error(w, "Service unavailable", 503)
			return
		}

		http.SetCookie(w, MakeCookie(r, user.Email))
		logger.WithField("user", user.Email).Info("Bootstrap: successfully generated auth cookie, redirecting user.")
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	}
}

// LogoutHandler logs a user out
func (s *Server) LogoutHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Clear cookie
		http.SetCookie(w, ClearCookie(r))

		logger := s.logger(r, "Logout", "default", "Handling logout")
		logger.Info("Logged out user")

		if config.LogoutRedirect != "" {
			http.Redirect(w, r, config.LogoutRedirect, http.StatusTemporaryRedirect)
		} else {
			http.Error(w, "You have been logged out", 401)
		}
	}
}

func (s *Server) authRedirect(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, p provider.Provider) {
	// Error indicates no cookie, generate nonce
	err, nonce := Nonce()
	if err != nil {
		logger.WithField("error", err).Error("Error generating nonce")
		http.Error(w, "Service unavailable", 503)
		return
	}

	// Set the CSRF cookie
	csrf := MakeCSRFCookie(r, nonce)
	http.SetCookie(w, csrf)

	if !config.InsecureCookie && r.Header.Get("X-Forwarded-Proto") != "https" {
		logger.Warn("You are using \"secure\" cookies for a request that was not " +
			"received via https. You should either redirect to https or pass the " +
			"\"insecure-cookie\" config option to permit cookies via http.")
	}

	// Forward them on
	loginURL := p.GetLoginURL(redirectUri(r), MakeState(r, p, nonce))
	http.Redirect(w, r, loginURL, http.StatusTemporaryRedirect)

	logger.WithFields(logrus.Fields{
		"csrf_cookie": csrf,
		"login_url":   loginURL,
	}).Debug("Set CSRF cookie and redirected to provider login url")
}

func (s *Server) logger(r *http.Request, handler, rule, msg string) *logrus.Entry {
	// Create logger
	logger := log.WithFields(logrus.Fields{
		"handler":   handler,
		"rule":      rule,
		"method":    r.Header.Get("X-Forwarded-Method"),
		"proto":     r.Header.Get("X-Forwarded-Proto"),
		"host":      r.Header.Get("X-Forwarded-Host"),
		"uri":       r.Header.Get("X-Forwarded-Uri"),
		"source_ip": r.Header.Get("X-Forwarded-For"),
	})

	// Log request
	logger.WithFields(logrus.Fields{
		"cookies": r.Cookies(),
	}).Debug(msg)

	return logger
}
