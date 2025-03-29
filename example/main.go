package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/arner/bunqr"
	"github.com/arner/bunqr/client"
	"github.com/arner/bunqr/oauth"
)

// DevOnlySingleUserSessionKey may never be used with multiple users.
// Instead, store every user's API key (securely!) under the users own unique key.
const DevOnlySingleUserSessionKey = "TODO"

func main() {
	// we store a file with the installation token and the server public key.
	persistence := bunqr.NewFilePersistence("installation-prod.json")

	// private key is used to sign your API requests. It's registered with the device.
	key, err := bunqr.ReadKey("./private_key.pem")
	if err != nil {
		log.Fatal(err)
	}

	bnq, err := bunqr.New(bunqr.PROD_URL, persistence, key, slog.Default())
	if err != nil {
		log.Fatal(err)
	}
	if err := bnq.Init(); err != nil {
		log.Fatal(err)
	}

	clientID := os.Getenv("BUNQ_CLIENT_ID")
	clientSecret := os.Getenv("BUNQ_CLIENT_SECRET")
	if clientID == "" || clientSecret == "" {
		log.Fatal("BUNQ_CLIENT_ID and BUNQ_CLIENT_SECRET must be set.")
	}
	oauth := oauth.NewProdProvider(clientID, clientSecret, "http://localhost:8080/callback")

	// this implementation of the SessionStore is not fit for real use.
	// The store should securely persist API keys (perhaps also Sessions), and differentiate between users.
	// This version keeps everything in memory and stores every key and session under the same key).
	store := NewMemSessionStore()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", oauth.HandleLogin())
	mux.HandleFunc("GET /callback", oauth.HandleCallback(authSuccess(bnq, store), authError()))

	// example endpoint that returns accounts of the logged in user.
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		// The session handling could normally probably be part of middleware that adds the Session to the context of the call.
		sess, _ := store.GetSession(DevOnlySingleUserSessionKey)
		if sess == nil || !sess.Valid() {
			// if we don't have an API key, we need to obtain it from the user via the login flow
			apiKey, _ := store.GetAPIKey(DevOnlySingleUserSessionKey)
			if len(apiKey) == 0 {
				log.Print("no api key found, redirect to login")
				http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
				return
			}

			sess, err = createAndStoreSession(r.Context(), bnq, store, apiKey)
			if err != nil {
				log.Print("error creating session")
				http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
				return
			}
		}

		// the actual API call
		res, err := bnq.Client.ListAllMonetaryAccountForUser(r.Context(), sess.AccessToken, sess.APIKeyID, &client.ListAllMonetaryAccountForUserParams{Count: 25})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if len(res.Errors) > 0 {
			http.Error(w, res.Errors[0].ErrorDescription, http.StatusBadRequest)
			return
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.Encode(res.Response)
	})

	log.Printf("visit http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}

// authSuccess stores the API key from the flow; it can be reused indefinitely to create sessions.
// It also creates a new session right away and redirects to the originally requested page (TODO)
func authSuccess(bnq *bunqr.SDK, store SessionStore) oauth.OnSuccess {
	return func(w http.ResponseWriter, r *http.Request, authToken string) {
		// Device should normally only be created once for this application / deployment!
		err := bnq.CreateDevice(r.Context(), authToken, []string{})
		if err != nil {
			log.Print(err.Error())
			http.Error(w, "Error creating device", http.StatusBadRequest)
			return
		}

		// The APIKey can be used indefinitely to create new sessions for this user.
		if err := store.StoreAPIKey(DevOnlySingleUserSessionKey, authToken); err != nil {
			log.Print(err.Error())
			http.Error(w, "Error storing key", http.StatusBadRequest)
			return
		}

		// The session is what we need to call the API.
		sess, err := createAndStoreSession(r.Context(), bnq, store, authToken)
		if err != nil {
			log.Print("error creating session: " + err.Error())
			http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
			return
		}
		log.Printf("login: %s", sess.Nickname)

		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	}
}

func createAndStoreSession(ctx context.Context, bnq *bunqr.SDK, store SessionStore, authToken string) (*Session, error) {
	sv, err := bnq.CreateSession(ctx, authToken)
	if err != nil {
		return nil, fmt.Errorf("error creating session: %w", err)
	}
	log.Printf("login: %s", sv.Nickname)

	sess := Session{
		AccessToken: sv.AccessToken,
		APIKeyID:    sv.APIKeyID,
		UserID:      sv.UserID,
		Nickname:    sv.Nickname,
		Expires:     sv.Expires,
	}
	if err := store.StoreSession(DevOnlySingleUserSessionKey, sess); err != nil {
		return &sess, fmt.Errorf("error storing session: %w", err)
	}
	return &sess, nil
}

func authError() oauth.OnError {
	return func(w http.ResponseWriter, r *http.Request, errorText string, statusCode int) {
		http.Error(w, errorText, statusCode)
	}
}

type Session struct {
	AccessToken string
	APIKeyID    int
	UserID      int
	Nickname    string
	Expires     time.Time
}

func (s *Session) Valid() bool {
	return len(s.AccessToken) > 0 && (s.Expires.IsZero() || time.Until(s.Expires) > time.Hour)
}

type SessionStore interface {
	StoreSession(string, Session) error
	GetSession(string) (*Session, error)
	StoreAPIKey(string, string) error
	GetAPIKey(string) (string, error)
}

// MemSessionStore only keeps sessions and API keys in memory.
// An encrypted persistent store might be more appropriate.
type MemSessionStore struct {
	mutex    sync.Mutex
	sessions map[string]Session
	apiKeys  map[string]string
}

func NewMemSessionStore() *MemSessionStore {
	return &MemSessionStore{
		sessions: make(map[string]Session),
		apiKeys:  make(map[string]string),
	}
}

func (m *MemSessionStore) StoreSession(key string, session Session) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.sessions[key] = session
	return nil
}

func (m *MemSessionStore) GetSession(key string) (*Session, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	session, exists := m.sessions[key]
	if !exists {
		return nil, nil
	}
	return &session, nil
}

func (m *MemSessionStore) StoreAPIKey(key string, value string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.apiKeys[key] = value
	return nil
}

func (m *MemSessionStore) GetAPIKey(key string) (string, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	return m.apiKeys[key], nil
}
