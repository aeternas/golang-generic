package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"golang-generic/internal/keycloak"
)

type healthResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

type s2ProxyResponse struct {
	Service    string            `json:"service"`
	Message    string            `json:"message"`
	S2Response secureDataPayload `json:"s2_response"`
}

type secureDataPayload struct {
	Service     string    `json:"service"`
	Data        string    `json:"data"`
	RetrievedAt time.Time `json:"retrieved_at"`
}

type keycloakGreetingResponse struct {
	Service           string   `json:"service"`
	Message           string   `json:"message"`
	Subject           string   `json:"subject"`
	PreferredUsername string   `json:"preferred_username,omitempty"`
	Audience          []string `json:"audience"`
	Issuer            string   `json:"issuer"`
	IssuedAt          string   `json:"issued_at"`
	ExpiresAt         string   `json:"expires_at"`
}

type config struct {
	Port                  string
	S2BaseURL             string
	S2User                string
	S2Password            string
	S2SecurePath          string
	RequestTimeout        time.Duration
	KeycloakIssuerURL     string
	KeycloakClientID      string
	KeycloakJWKSURL       string
	KeycloakIssuerAliases []string
	KeycloakBaseURL       string
	KeycloakRealm         string
	KeycloakAdminUser     string
	KeycloakAdminPassword string
	KeycloakAdminClientID string
	KeycloakRegisterRole  string
}

type server struct {
	logger            *log.Logger
	s2Client          *s2Client
	keycloakVerifier  *keycloak.Verifier
	keycloakRegistrar keycloak.UserRegistrar
}

func main() {
	logger := log.New(os.Stdout, "[service1] ", log.LstdFlags)
	cfg := loadConfig()

	var client *s2Client
	if cfg.S2BaseURL != "" {
		var err error
		client, err = newS2Client(cfg)
		if err != nil {
			logger.Printf("unable to configure S2 client: %v", err)
		}
	} else {
		logger.Printf("S2_BASE_URL not set; /s2/secure-data endpoint will be disabled")
	}

	var keycloakVerifier *keycloak.Verifier
	if cfg.KeycloakIssuerURL != "" && cfg.KeycloakClientID != "" {
		var err error
		keycloakVerifier, err = keycloak.NewVerifier(context.Background(), keycloak.Config{
			IssuerURL:     cfg.KeycloakIssuerURL,
			ClientID:      cfg.KeycloakClientID,
			JWKSURL:       cfg.KeycloakJWKSURL,
			IssuerAliases: cfg.KeycloakIssuerAliases,
		})
		if err != nil {
			logger.Printf("unable to configure Keycloak verifier: %v", err)
		} else {
			logger.Printf("Keycloak verifier initialised for issuer %s", cfg.KeycloakIssuerURL)
		}
	} else {
		logger.Printf("Keycloak configuration not set; /keycloak-greeting endpoint will be disabled")
	}

	var keycloakRegistrar keycloak.UserRegistrar
	if cfg.KeycloakBaseURL != "" && cfg.KeycloakRealm != "" && cfg.KeycloakAdminUser != "" && cfg.KeycloakAdminPassword != "" && cfg.KeycloakRegisterRole != "" {
		adminClient, err := keycloak.NewAdminClient(keycloak.AdminConfig{
			BaseURL:          cfg.KeycloakBaseURL,
			Realm:            cfg.KeycloakRealm,
			Username:         cfg.KeycloakAdminUser,
			Password:         cfg.KeycloakAdminPassword,
			ClientID:         cfg.KeycloakAdminClientID,
			RegistrationRole: cfg.KeycloakRegisterRole,
		})
		if err != nil {
			logger.Printf("unable to configure Keycloak admin client: %v", err)
		} else {
			keycloakRegistrar = adminClient
			logger.Printf("Keycloak self-registration enabled for realm %s with role %s", cfg.KeycloakRealm, cfg.KeycloakRegisterRole)
		}
	} else if cfg.KeycloakAdminUser != "" || cfg.KeycloakAdminPassword != "" || cfg.KeycloakRegisterRole != "" {
		logger.Printf("Keycloak admin configuration incomplete; /keycloak-register endpoint will be disabled")
	} else {
		logger.Printf("Keycloak admin credentials not set; /keycloak-register endpoint will be disabled")
	}

	mux := http.NewServeMux()
	srv := &server{
		logger:            logger,
		s2Client:          client,
		keycloakVerifier:  keycloakVerifier,
		keycloakRegistrar: keycloakRegistrar,
	}

	mux.HandleFunc("/", srv.handleIndex)
	mux.HandleFunc("/healthz", srv.handleHealthz)
	mux.HandleFunc("/s2/secure-data", srv.handleS2SecureData)
	mux.HandleFunc("/keycloak-greeting", srv.handleKeycloakGreeting)
	mux.HandleFunc("/keycloak-register", srv.handleKeycloakRegister)

	port := cfg.Port
	if port == "" {
		port = "8082"
	}

	addr := ":" + port
	logger.Printf("starting HTTP listener on %s", addr)
	if err := http.ListenAndServe(addr, logRequests(logger, mux)); err != nil {
		logger.Fatalf("service exited: %v", err)
	}
}

func loadConfig() config {
	timeout := 5 * time.Second
	if raw := strings.TrimSpace(os.Getenv("S2_REQUEST_TIMEOUT")); raw != "" {
		if parsed, err := time.ParseDuration(raw); err == nil {
			timeout = parsed
		}
	}

	issuer := strings.TrimSpace(os.Getenv("KEYCLOAK_ISSUER_URL"))
	jwksURL := strings.TrimSpace(os.Getenv("KEYCLOAK_JWKS_URL"))
	if issuer != "" && jwksURL == "" {
		jwksURL = strings.TrimSuffix(issuer, "/") + "/protocol/openid-connect/certs"
	}

	baseURL, realm, err := parseKeycloakIssuer(issuer)
	if err != nil {
		baseURL = ""
		realm = ""
	}

	adminClientID := strings.TrimSpace(os.Getenv("KEYCLOAK_ADMIN_CLIENT_ID"))
	if adminClientID == "" {
		adminClientID = "admin-cli"
	}

	return config{
		Port:                  strings.TrimSpace(os.Getenv("PORT")),
		S2BaseURL:             strings.TrimSpace(os.Getenv("S2_BASE_URL")),
		S2User:                os.Getenv("S2_BASIC_USER"),
		S2Password:            os.Getenv("S2_BASIC_PASSWORD"),
		S2SecurePath:          strings.TrimSpace(os.Getenv("S2_SECURE_PATH")),
		RequestTimeout:        timeout,
		KeycloakIssuerURL:     issuer,
		KeycloakClientID:      strings.TrimSpace(os.Getenv("KEYCLOAK_CLIENT_ID")),
		KeycloakJWKSURL:       jwksURL,
		KeycloakIssuerAliases: parseEnvList(os.Getenv("KEYCLOAK_ISSUER_ALIASES")),
		KeycloakBaseURL:       baseURL,
		KeycloakRealm:         realm,
		KeycloakAdminUser:     strings.TrimSpace(os.Getenv("KEYCLOAK_ADMIN_USERNAME")),
		KeycloakAdminPassword: os.Getenv("KEYCLOAK_ADMIN_PASSWORD"),
		KeycloakAdminClientID: adminClientID,
		KeycloakRegisterRole:  strings.TrimSpace(os.Getenv("KEYCLOAK_REGISTRATION_ROLE")),
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

func parseKeycloakIssuer(raw string) (string, string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", nil
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return "", "", fmt.Errorf("invalid Keycloak issuer URL: %w", err)
	}

	segments := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	for i := 0; i < len(segments)-1; i++ {
		if segments[i] != "realms" {
			continue
		}
		realm := segments[i+1]
		if realm == "" {
			break
		}

		prefix := strings.Join(segments[:i], "/")
		if prefix != "" {
			parsed.Path = "/" + prefix
		} else {
			parsed.Path = ""
		}
		parsed.RawQuery = ""
		parsed.Fragment = ""
		base := strings.TrimRight(parsed.String(), "/")
		if base == "" {
			return "", "", errors.New("issuer URL missing scheme or host")
		}
		return base, realm, nil
	}

	return "", "", errors.New("issuer URL must contain /realms/{realm}")
}

func (s *server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	resp := healthResponse{
		Status:  "ok",
		Message: "service1 is running",
	}
	writeJSON(w, resp, http.StatusOK)
}

func (s *server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) handleS2SecureData(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.s2Client == nil {
		http.Error(w, "s2 integration not configured", http.StatusServiceUnavailable)
		return
	}

	payload, err := s.s2Client.FetchSecureData(r.Context())
	if err != nil {
		s.logger.Printf("failed to fetch secure data from S2: %v", err)
		http.Error(w, "failed to fetch secure data from s2", http.StatusBadGateway)
		return
	}

	resp := s2ProxyResponse{
		Service:    "service1",
		Message:    "successfully fetched secure data from service2",
		S2Response: payload,
	}
	writeJSON(w, resp, http.StatusOK)
}

func (s *server) handleKeycloakGreeting(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.keycloakVerifier == nil {
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

	token := strings.TrimSpace(authHeader[len("Bearer "):])
	if token == "" {
		s.logger.Printf("bearer token was empty after trimming header")
		w.Header().Set("WWW-Authenticate", "Bearer error=\"invalid_token\"")
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	claims, err := s.keycloakVerifier.VerifyToken(r.Context(), token)
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

	resp := keycloakGreetingResponse{
		Service:           "service1",
		Message:           "hello from service1",
		Subject:           claims.Subject,
		PreferredUsername: claims.PreferredUsername,
		Audience:          []string(claims.Audience),
		Issuer:            claims.Issuer,
		IssuedAt:          issuedAt,
		ExpiresAt:         expiresAt,
	}
	writeJSON(w, resp, http.StatusOK)
}

func writeJSON(w http.ResponseWriter, payload any, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("failed to encode response: %v", err)
	}
}

func logRequests(logger *log.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		logger.Printf("%s %s from %s completed in %s", r.Method, r.URL.Path, r.RemoteAddr, time.Since(start))
	})
}

type s2Client struct {
	httpClient *http.Client
	baseURL    *url.URL
	username   string
	password   string
	securePath string
}

func newS2Client(cfg config) (*s2Client, error) {
	parsedURL, err := url.Parse(cfg.S2BaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid S2_BASE_URL: %w", err)
	}

	securePath := cfg.S2SecurePath
	if securePath == "" {
		securePath = "/secure-data"
	}

	if !strings.HasPrefix(securePath, "/") {
		securePath = "/" + securePath
	}

	if cfg.S2User == "" || cfg.S2Password == "" {
		return nil, errors.New("S2 basic auth credentials must be provided")
	}

	return &s2Client{
		httpClient: &http.Client{Timeout: cfg.RequestTimeout},
		baseURL:    parsedURL,
		username:   cfg.S2User,
		password:   cfg.S2Password,
		securePath: securePath,
	}, nil
}

func (c *s2Client) FetchSecureData(ctx context.Context) (secureDataPayload, error) {
	endpoint := c.baseURL.ResolveReference(&url.URL{Path: c.securePath})
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return secureDataPayload{}, fmt.Errorf("failed to build request: %w", err)
	}

	req.SetBasicAuth(c.username, c.password)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return secureDataPayload{}, fmt.Errorf("request to service2 failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return secureDataPayload{}, fmt.Errorf("service2 returned status %d", resp.StatusCode)
	}

	var payload secureDataPayload
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return secureDataPayload{}, fmt.Errorf("failed to decode service2 response: %w", err)
	}

	return payload, nil
}
