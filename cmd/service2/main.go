package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"golang-generic/internal/keycloak"
)

const (
	basicAuthUsername = "demo-user"
	basicAuthPassword = "demo-pass"
)

type service struct {
	logger        *log.Logger
	tokenVerifier *keycloak.Verifier
}

type keycloakConfig struct {
	IssuerURL     string
	ClientID      string
	JWKSURL       string
	IssuerAliases []string
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

func main() {
	logger := log.New(os.Stdout, "[service2] ", log.LstdFlags)
	cfg := loadKeycloakConfig()

	verifier, err := buildKeycloakVerifier(context.Background(), cfg)
	if err != nil {
		logger.Printf("keycloak verifier disabled: %v", err)
	} else if verifier != nil {
		logger.Printf("keycloak verifier initialised for issuer %s", cfg.IssuerURL)
	}

	srv := &service{logger: logger, tokenVerifier: verifier}

	mux := http.NewServeMux()
	mux.HandleFunc("/", srv.handleIndex)
	mux.HandleFunc("/healthz", srv.handleHealthz)
	mux.HandleFunc("/secure-data", srv.handleSecureData)
	mux.HandleFunc("/keycloak-data", srv.handleKeycloakData)

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

	return keycloakConfig{
		IssuerURL:     issuer,
		ClientID:      strings.TrimSpace(os.Getenv("KEYCLOAK_CLIENT_ID")),
		JWKSURL:       jwksURL,
		IssuerAliases: parseEnvList(os.Getenv("KEYCLOAK_ISSUER_ALIASES")),
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

func (s *service) handleSecureData(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username, password, ok := r.BasicAuth()
	if !ok || username != basicAuthUsername || password != basicAuthPassword {
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
