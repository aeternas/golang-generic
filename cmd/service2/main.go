package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang-generic/internal/keycloak"
)

type service struct {
	logger        *log.Logger
	tokenVerifier *keycloak.Verifier
	oauthClient   *keycloak.OAuthClient
	authStates    *stateStore
}

type keycloakConfig struct {
	IssuerURL     string
	ClientID      string
	JWKSURL       string
	IssuerAliases []string
	RedirectURL   string
	Scopes        []string
}

type secureDataResponse struct {
	Service     string    `json:"service"`
	Data        string    `json:"data"`
	RetrievedAt time.Time `json:"retrieved_at"`
}

type keycloakDataResponse struct {
	Service           string   `json:"service"`
	Message           string   `json:"message"`
	Subject           string   `json:"subject"`
	PreferredUsername string   `json:"preferred_username,omitempty"`
	Audience          []string `json:"audience"`
	Issuer            string   `json:"issuer"`
	IssuedAt          string   `json:"issued_at"`
	ExpiresAt         string   `json:"expires_at"`
}

type keycloakAuthResponse struct {
	Service            string       `json:"service"`
	Message            string       `json:"message"`
	AccessToken        string       `json:"access_token"`
	IDToken            string       `json:"id_token,omitempty"`
	RefreshToken       string       `json:"refresh_token,omitempty"`
	TokenType          string       `json:"token_type,omitempty"`
	Scope              string       `json:"scope,omitempty"`
	ExpiresIn          int          `json:"expires_in,omitempty"`
	AccessTokenDetails *tokenClaims `json:"access_token_claims,omitempty"`
}

type tokenClaims struct {
	Subject           string   `json:"subject"`
	PreferredUsername string   `json:"preferred_username,omitempty"`
	Audience          []string `json:"audience"`
	Issuer            string   `json:"issuer"`
	IssuedAt          string   `json:"issued_at,omitempty"`
	ExpiresAt         string   `json:"expires_at,omitempty"`
}

func main() {
	logger := log.New(os.Stdout, "[service2] ", log.LstdFlags)
	cfg := loadKeycloakConfig()

	verifier, err := buildKeycloakVerifier(context.Background(), cfg)
	if err != nil {
		logger.Printf("keycloak verifier disabled: %v", err)
	} else if verifier != nil {
		logger.Printf("keycloak verifier initialised for issuer %s", cfg.IssuerURL)
	}

	var oauthClient *keycloak.OAuthClient
	var authStates *stateStore
	if cfg.IssuerURL != "" && cfg.ClientID != "" && cfg.RedirectURL != "" {
		oauthClient, err = keycloak.NewOAuthClient(keycloak.OAuthConfig{
			IssuerURL:   cfg.IssuerURL,
			ClientID:    cfg.ClientID,
			RedirectURL: cfg.RedirectURL,
			Scopes:      cfg.Scopes,
			HTTPClient:  &http.Client{Timeout: 5 * time.Second},
		})
		if err != nil {
			logger.Printf("keycloak oauth disabled: %v", err)
		} else {
			authStates = newStateStore(authStateTTL)
			logger.Printf("keycloak oauth initialised; redirect URI %s", cfg.RedirectURL)
		}
	} else {
		logger.Printf("keycloak oauth configuration missing; /keycloak/login disabled")
	}

	srv := &service{logger: logger, tokenVerifier: verifier, oauthClient: oauthClient, authStates: authStates}

	mux := http.NewServeMux()
	mux.HandleFunc("/", srv.handleIndex)
	mux.HandleFunc("/healthz", srv.handleHealthz)
	mux.HandleFunc("/secure-data", srv.handleSecureData)
	mux.HandleFunc("/keycloak-data", srv.handleKeycloakData)
	mux.HandleFunc("/keycloak/login", srv.handleKeycloakLogin)
	mux.HandleFunc("/keycloak/callback", srv.handleKeycloakCallback)

	port := strings.TrimSpace(os.Getenv("PORT"))
	if port == "" {
		port = "8081"
	}
	addr := ":" + port

	logger.Printf("service2 listening on %s", addr)
	if err := http.ListenAndServe(addr, logRequests(logger, mux)); err != nil {
		logger.Fatalf("service2 exited: %v", err)
	}
}

func loadKeycloakConfig() keycloakConfig {
	issuer := strings.TrimSpace(os.Getenv("KEYCLOAK_ISSUER_URL"))
	jwksURL := strings.TrimSpace(os.Getenv("KEYCLOAK_JWKS_URL"))
	if issuer != "" && jwksURL == "" {
		jwksURL = strings.TrimSuffix(issuer, "/") + "/protocol/openid-connect/certs"
	}

	scopes := parseScopeList(os.Getenv("KEYCLOAK_SCOPES"))
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}

	return keycloakConfig{
		IssuerURL:     issuer,
		ClientID:      strings.TrimSpace(os.Getenv("KEYCLOAK_CLIENT_ID")),
		JWKSURL:       jwksURL,
		IssuerAliases: parseEnvList(os.Getenv("KEYCLOAK_ISSUER_ALIASES")),
		RedirectURL:   strings.TrimSpace(os.Getenv("KEYCLOAK_REDIRECT_URL")),
		Scopes:        scopes,
	}
}

func parseEnvList(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}

	parts := strings.Split(raw, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			values = append(values, trimmed)
		}
	}
	if len(values) == 0 {
		return nil
	}
	return values
}

func parseScopeList(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}

	fields := strings.FieldsFunc(raw, func(r rune) bool {
		switch r {
		case ',', ' ', '\t':
			return true
		default:
			return false
		}
	})

	scopes := make([]string, 0, len(fields))
	for _, scope := range fields {
		trimmed := strings.TrimSpace(scope)
		if trimmed != "" {
			scopes = append(scopes, trimmed)
		}
	}

	if len(scopes) == 0 {
		return nil
	}

	return scopes
}

func buildKeycloakVerifier(ctx context.Context, cfg keycloakConfig) (*keycloak.Verifier, error) {
	if cfg.IssuerURL == "" || cfg.ClientID == "" {
		return nil, fmt.Errorf("issuer URL and client ID must be configured to enable keycloak endpoint")
	}

	verifier, err := keycloak.NewVerifier(ctx, keycloak.Config{
		IssuerURL:     cfg.IssuerURL,
		ClientID:      cfg.ClientID,
		JWKSURL:       cfg.JWKSURL,
		IssuerAliases: cfg.IssuerAliases,
	})
	if err != nil {
		return nil, err
	}

	return verifier, nil
}

func (s *service) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	resp := map[string]string{
		"status":  "ok",
		"message": "service2 is ready",
	}
	writeJSON(w, resp, http.StatusOK)
}

func (s *service) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

type Cred struct {
	Login    string
	Password string
}

var credentials = []Cred{
	{Login: "demo-user", Password: "demo-pass"},
	{Login: "alice", Password: "s3cr3t"},
	{Login: "bob", Password: "passw0rd"},
	{Login: "carol", Password: "letmein"},
}

func checkCredentials(username, password string) bool {
	for _, c := range credentials {
		loginOK := subtle.ConstantTimeCompare([]byte(c.Login), []byte(username)) == 1
		passOK := subtle.ConstantTimeCompare([]byte(c.Password), []byte(password)) == 1
		if loginOK && passOK {
			return true
		}
	}
	return false
}

func (s *service) handleSecureData(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username, password, ok := r.BasicAuth()
	credsOK := checkCredentials(username, password)
	if !ok || !credsOK {
		w.Header().Set("WWW-Authenticate", "Basic realm=\"service2\"")
		http.Error(w, "unauthorised", http.StatusUnauthorized)
		return
	}

	resp := secureDataResponse{
		Service:     "service2",
		Data:        "confidential data available only via basic auth",
		RetrievedAt: time.Now().UTC(),
	}
	writeJSON(w, resp, http.StatusOK)
}

func (s *service) handleKeycloakData(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.tokenVerifier == nil {
		http.Error(w, "keycloak integration not configured", http.StatusServiceUnavailable)
		return
	}

	authHeader := r.Header.Get("Authorization")
	s.logger.Printf("received Authorization header: %q", authHeader)
	if !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		s.logger.Printf("authorization header missing bearer prefix")
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "bearer token required", http.StatusUnauthorized)
		return
	}

	rawToken := strings.TrimSpace(authHeader[len("Bearer "):])
	if rawToken == "" {
		s.logger.Printf("bearer token was empty after trimming header")
		w.Header().Set("WWW-Authenticate", "Bearer error=\"invalid_token\"")
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}
	claims, err := s.tokenVerifier.VerifyToken(r.Context(), rawToken)
	if err != nil {
		s.logger.Printf("token verification failed: %v", err)
		w.Header().Set("WWW-Authenticate", "Bearer error=\"invalid_token\"")
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}
	s.logger.Printf("token validated successfully: subject=%q issuer=%q audience=%v expires=%d", claims.Subject, claims.Issuer, []string(claims.Audience), claims.Expiry)

	issuedAt := ""
	if claims.IssuedAt != 0 {
		issuedAt = time.Unix(claims.IssuedAt, 0).UTC().Format(time.RFC3339)
	}

	expiresAt := ""
	if claims.Expiry != 0 {
		expiresAt = time.Unix(claims.Expiry, 0).UTC().Format(time.RFC3339)
	}

	resp := keycloakDataResponse{
		Service:           "service2",
		Message:           "secured by keycloak",
		Subject:           claims.Subject,
		PreferredUsername: claims.PreferredUsername,
		Audience:          []string(claims.Audience),
		Issuer:            claims.Issuer,
		IssuedAt:          issuedAt,
		ExpiresAt:         expiresAt,
	}
	writeJSON(w, resp, http.StatusOK)
}

func (s *service) handleKeycloakLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.oauthClient == nil || s.authStates == nil {
		http.Error(w, "keycloak oauth not configured", http.StatusServiceUnavailable)
		return
	}

	state, err := generateState()
	if err != nil {
		s.logger.Printf("failed to generate oauth state: %v", err)
		http.Error(w, "failed to initiate login", http.StatusInternalServerError)
		return
	}

	codeVerifier, err := generateCodeVerifier()
	if err != nil {
		s.logger.Printf("failed to generate code verifier: %v", err)
		http.Error(w, "failed to initiate login", http.StatusInternalServerError)
		return
	}

	codeChallenge := codeChallengeFromVerifier(codeVerifier)

	authURL, err := s.oauthClient.AuthCodeURL(state, codeChallenge)
	if err != nil {
		s.logger.Printf("failed to build auth URL: %v", err)
		http.Error(w, "failed to initiate login", http.StatusInternalServerError)
		return
	}

	s.authStates.store(state, codeVerifier)
	s.logger.Printf("redirecting browser to Keycloak auth endpoint")
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (s *service) handleKeycloakCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.oauthClient == nil || s.authStates == nil {
		http.Error(w, "keycloak oauth not configured", http.StatusServiceUnavailable)
		return
	}

	state := strings.TrimSpace(r.URL.Query().Get("state"))
	code := strings.TrimSpace(r.URL.Query().Get("code"))
	if state == "" || code == "" {
		http.Error(w, "state and code are required", http.StatusBadRequest)
		return
	}

	codeVerifier, ok := s.authStates.consume(state)
	if !ok {
		http.Error(w, "invalid or expired state", http.StatusBadRequest)
		return
	}

	tokenResp, err := s.oauthClient.Exchange(r.Context(), code, codeVerifier)
	if err != nil {
		s.logger.Printf("token exchange failed: %v", err)
		http.Error(w, "failed to exchange code", http.StatusBadGateway)
		return
	}

	response := keycloakAuthResponse{
		Service:      "service2",
		Message:      "authorization code exchanged successfully",
		AccessToken:  tokenResp.AccessToken,
		IDToken:      tokenResp.IDToken,
		RefreshToken: tokenResp.RefreshToken,
		TokenType:    tokenResp.TokenType,
		Scope:        tokenResp.Scope,
		ExpiresIn:    tokenResp.ExpiresIn,
	}

	if s.tokenVerifier != nil && tokenResp.AccessToken != "" {
		if claims, err := s.tokenVerifier.VerifyToken(r.Context(), tokenResp.AccessToken); err != nil {
			s.logger.Printf("access token verification failed: %v", err)
		} else {
			response.AccessTokenDetails = &tokenClaims{
				Subject:           claims.Subject,
				PreferredUsername: claims.PreferredUsername,
				Audience:          []string(claims.Audience),
				Issuer:            claims.Issuer,
				IssuedAt:          formatUnixTime(claims.IssuedAt),
				ExpiresAt:         formatUnixTime(claims.Expiry),
			}
		}
	}

	writeJSON(w, response, http.StatusOK)
}

func writeJSON(w http.ResponseWriter, payload any, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("failed to encode response: %v", err)
	}
}

func logRequests(logger *log.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		uri := r.URL.RequestURI()
		logger.Printf("started %s %s from %s", r.Method, uri, r.RemoteAddr)

		lrw := &loggingResponseWriter{ResponseWriter: w}
		next.ServeHTTP(lrw, r)

		statusCode := lrw.statusCode
		if statusCode == 0 {
			statusCode = http.StatusOK
		}

		logger.Printf(
			"completed %s %s from %s with status %d %s in %s (%d bytes)",
			r.Method,
			uri,
			r.RemoteAddr,
			statusCode,
			http.StatusText(statusCode),
			time.Since(start),
			lrw.bytesWritten,
		)
	})
}

type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int64
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}

func (lrw *loggingResponseWriter) Write(p []byte) (int, error) {
	if lrw.statusCode == 0 {
		lrw.statusCode = http.StatusOK
	}

	n, err := lrw.ResponseWriter.Write(p)
	lrw.bytesWritten += int64(n)
	return n, err
}

const authStateTTL = 5 * time.Minute

type stateStore struct {
	mu      sync.Mutex
	ttl     time.Duration
	entries map[string]stateEntry
}

type stateEntry struct {
	codeVerifier string
	expiresAt    time.Time
}

func newStateStore(ttl time.Duration) *stateStore {
	if ttl <= 0 {
		ttl = authStateTTL
	}
	return &stateStore{
		ttl:     ttl,
		entries: make(map[string]stateEntry),
	}
}

func (s *stateStore) store(state, codeVerifier string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.entries[state] = stateEntry{
		codeVerifier: codeVerifier,
		expiresAt:    time.Now().Add(s.ttl),
	}
}

func (s *stateStore) consume(state string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.entries[state]
	if !ok {
		return "", false
	}
	delete(s.entries, state)

	if time.Now().After(entry.expiresAt) {
		return "", false
	}

	return entry.codeVerifier, true
}

func generateCodeVerifier() (string, error) {
	return randomString(32)
}

func generateState() (string, error) {
	return randomString(24)
}

func randomString(bytes int) (string, error) {
	buf := make([]byte, bytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("failed to read random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func codeChallengeFromVerifier(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func formatUnixTime(ts int64) string {
	if ts == 0 {
		return ""
	}
	return time.Unix(ts, 0).UTC().Format(time.RFC3339)
}
