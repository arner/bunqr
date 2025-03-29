// oauth provides http handlers for the bunq oauth flow.
package oauth

import (
	"crypto/rand"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
)

// OnError is the function that is called if there is an error in HandleCallback during or after the bunq login.
type OnError func(w http.ResponseWriter, r *http.Request, errorText string, statusCode int)

// OnSuccess is the function that HandleCallback calls if the bunq login is successful.
// It should create the Device and Session, and store the authToken and Session.
type OnSuccess func(w http.ResponseWriter, r *http.Request, authToken string)

// OAuthProvider contains the config for the bunq oauth provider.
type OAuthProvider struct {
	cookieName string
	config     Config
}

// Config mirrors golang.org/x/oauth2 where applicable.
type Config struct {
	ClientID     string
	ClientSecret string
	Endpoint     Endpoint

	// RedirectURL is the URL to redirect users going through
	// the OAuth flow, after the resource owner's URLs.
	RedirectURL string
}

// Endpoint represents an OAuth 2.0 provider's authorization and token
// endpoint URLs.
type Endpoint struct {
	AuthURL       string
	DeviceAuthURL string
	TokenURL      string
}

// NewProdProvider creates a new bunq OAuthProvider based on the production URLs.
func NewProdProvider(clientID, secret, redirectURL string) OAuthProvider {
	return OAuthProvider{
		cookieName: "oauthbunq",
		config: Config{
			ClientID:     clientID,
			ClientSecret: secret,
			RedirectURL:  redirectURL,
			Endpoint: Endpoint{
				AuthURL:  "https://oauth.bunq.com/auth",
				TokenURL: "https://api.oauth.bunq.com/v1/token",
			},
		},
	}
}

// NewSandboxProvider creates a new bunq OAuthProvider based on the sandbox URLs.
func NewSandboxProvider(clientID, secret, redirectURL string) OAuthProvider {
	return OAuthProvider{
		cookieName: "oauthbunqsb",
		config: Config{
			ClientID:     clientID,
			ClientSecret: secret,
			RedirectURL:  redirectURL,
			Endpoint: Endpoint{
				AuthURL:  "https://oauth.sandbox.bunq.com/auth",
				TokenURL: "https://oauth.sandbox.bunq.com/v1/token",
			},
		},
	}
}

// HandleLogin starts the login flow by redirecting to Bunq.
func (o OAuthProvider) HandleLogin() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state := rand.Text()

		http.SetCookie(w, &http.Cookie{
			Name:     o.cookieName,
			Value:    state,
			HttpOnly: true,
			Secure:   r.URL.Scheme == "https",
			Path:     "/",
		})

		// Build URL
		authURL, err := url.Parse(o.config.Endpoint.AuthURL)
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		query := authURL.Query()
		query.Set("response_type", "code")
		query.Set("client_id", o.config.ClientID)
		query.Set("redirect_uri", o.config.RedirectURL)
		query.Set("state", state)
		authURL.RawQuery = query.Encode()

		// Redirect to the authorization page
		http.Redirect(w, r, authURL.String(), http.StatusTemporaryRedirect)
	})
}

// HandleCallback is called by bunq when the user is successfully logged in.
func (o OAuthProvider) HandleCallback(onSuccess OnSuccess, onError OnError) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify state parameter to prevent CSRF
		stateCookie, err := r.Cookie(o.cookieName)
		if err != nil {
			onError(w, r, "Missing state cookie", http.StatusBadRequest)
			return
		}
		state := r.FormValue("state")
		if state != stateCookie.Value {
			http.SetCookie(w, &http.Cookie{Name: o.cookieName, MaxAge: 0})
			onError(w, r, "Invalid state parameter", http.StatusBadRequest)
			return
		}

		// Exchange authorization code for token
		tokenURL, err := url.Parse(o.config.Endpoint.TokenURL)
		if err != nil {
			log.Printf("Failed to parse token URL: %v", err) // TODO validate on create
			http.SetCookie(w, &http.Cookie{Name: o.cookieName, MaxAge: 0})
			onError(w, r, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Add query parameters to the URL
		query := tokenURL.Query()
		query.Set("grant_type", "authorization_code")
		query.Set("code", r.FormValue("code"))
		query.Set("redirect_uri", o.config.RedirectURL)
		query.Set("client_id", o.config.ClientID)
		query.Set("client_secret", o.config.ClientSecret)
		tokenURL.RawQuery = query.Encode()

		// Make the POST request to the token endpoint
		res, err := http.Post(tokenURL.String(), "application/x-www-form-urlencoded", nil)
		if err != nil {
			onError(w, r, "Failed to request token", http.StatusInternalServerError)
			return
		}
		if res.StatusCode != http.StatusOK {
			body, err := io.ReadAll(res.Body)
			res.Body.Close()
			ret := res.Status
			if err != nil && len(body) > 0 {
				ret = string(body)
			}

			onError(w, r, "Failed to exchange token: "+ret, http.StatusInternalServerError)
			return
		}

		var tokenResponse oAuthTokenResponse
		err = json.NewDecoder(res.Body).Decode(&tokenResponse)
		res.Body.Close()
		if err != nil {
			onError(w, r, "Failed to process token response", http.StatusInternalServerError)
			return
		}
		if tokenResponse.State != stateCookie.Value {
			onError(w, r, "Invalid state parameter", http.StatusBadRequest)
			return
		}
		onSuccess(w, r, tokenResponse.AccessToken)
	})
}

type oAuthTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	State       string `json:"state"`
}
