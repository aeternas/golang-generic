package keycloak

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Config describes the Keycloak realm details required to verify JWTs.
type Config struct {
	IssuerURL string
	ClientID  string
	JWKSURL   string
	// IssuerAliases allows additional issuer URLs that should be accepted when validating tokens.
	// This is useful when the public issuer differs from the URL used to fetch JWKS keys
	// (for example, when accessing Keycloak via an internal hostname).
	IssuerAliases []string
	// HTTPClient allows overriding the HTTP client used to retrieve JWKS keys.
	// When nil, a client with a 5 second timeout is used.
	HTTPClient *http.Client
}

// Verifier validates RSA-signed Keycloak JWTs by fetching the realm's JWKS document.
type Verifier struct {
	issuer      string
	clientID    string
	jwksURL     string
	httpClient  *http.Client
	validIssuer map[string]struct{}
	issuerList  []string

	mu   sync.RWMutex
	keys map[string]*rsa.PublicKey
}

// Claims represents the subset of JWT claims used by the services.
type Claims struct {
	Issuer            string   `json:"iss"`
	Subject           string   `json:"sub"`
	Audience          Audience `json:"aud"`
	AuthorizedParty   string   `json:"azp"`
	Expiry            int64    `json:"exp"`
	IssuedAt          int64    `json:"iat"`
	PreferredUsername string   `json:"preferred_username"`
}

// Audience is a helper type that can unmarshal either a single string or an array of strings.
type Audience []string

type jwksResponse struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	KeyType string `json:"kty"`
	KeyID   string `json:"kid"`
	N       string `json:"n"`
	E       string `json:"e"`
}

// NewVerifier creates a Verifier and preloads the JWKS document.
func NewVerifier(ctx context.Context, cfg Config) (*Verifier, error) {
	if strings.TrimSpace(cfg.IssuerURL) == "" || strings.TrimSpace(cfg.ClientID) == "" {
		return nil, errors.New("issuer URL and client ID must be provided")
	}

	issuer := normaliseIssuer(cfg.IssuerURL)

	jwksURL := strings.TrimSpace(cfg.JWKSURL)
	if jwksURL == "" {
		jwksURL = issuer + "/protocol/openid-connect/certs"
	}

	issuerSet := make(map[string]struct{})
	issuerList := make([]string, 0, len(cfg.IssuerAliases)+1)

	if issuer != "" {
		issuerSet[issuer] = struct{}{}
		issuerList = append(issuerList, issuer)
	}

	for _, alias := range cfg.IssuerAliases {
		trimmed := normaliseIssuer(alias)
		if trimmed == "" {
			continue
		}
		if _, exists := issuerSet[trimmed]; exists {
			continue
		}
		issuerSet[trimmed] = struct{}{}
		issuerList = append(issuerList, trimmed)
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 5 * time.Second}
	}

	verifier := &Verifier{
		issuer:      issuer,
		clientID:    strings.TrimSpace(cfg.ClientID),
		jwksURL:     jwksURL,
		httpClient:  httpClient,
		keys:        make(map[string]*rsa.PublicKey),
		validIssuer: issuerSet,
		issuerList:  issuerList,
	}

	if err := verifier.refreshKeys(ctx); err != nil {
		debugf("initial JWKS refresh failed: %v", err)
		return nil, err
	}

	debugf("verifier initialised for issuer %s with JWKS endpoint %s", verifier.issuer, verifier.jwksURL)
	return verifier, nil
}

// VerifyToken validates the supplied JWT and returns its claims if the token is valid.
func (v *Verifier) VerifyToken(ctx context.Context, token string) (*Claims, error) {
	debugf("verifying token with length %d", len(token))
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		debugf("token split into %d parts, expected 3", len(parts))
		return nil, errors.New("token must contain header, payload and signature")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		debugf("unable to decode token header: %v", err)
		return nil, fmt.Errorf("unable to decode token header: %w", err)
	}
	debugf("token header JSON: %s", string(headerBytes))

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		debugf("unable to decode token payload: %v", err)
		return nil, fmt.Errorf("unable to decode token payload: %w", err)
	}
	debugf("token payload JSON: %s", string(payloadBytes))

	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		debugf("unable to decode token signature: %v", err)
		return nil, fmt.Errorf("unable to decode token signature: %w", err)
	}

	var header struct {
		Algorithm string `json:"alg"`
		KeyID     string `json:"kid"`
		Type      string `json:"typ"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		debugf("unable to parse token header JSON: %v", err)
		return nil, fmt.Errorf("unable to parse token header: %w", err)
	}

	if header.Algorithm != "RS256" {
		debugf("unsupported signing algorithm %q", header.Algorithm)
		return nil, fmt.Errorf("unsupported signing algorithm %q", header.Algorithm)
	}

	debugf("resolving signing key for kid %q", header.KeyID)
	key, err := v.lookupKey(ctx, header.KeyID)
	if err != nil {
		debugf("failed to resolve signing key for kid %q: %v", header.KeyID, err)
		return nil, err
	}
	debugf("signing key for kid %q resolved successfully", header.KeyID)

	signedContent := parts[0] + "." + parts[1]
	hashed := sha256.Sum256([]byte(signedContent))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, hashed[:], signature); err != nil {
		debugf("invalid token signature: %v", err)
		return nil, fmt.Errorf("invalid token signature: %w", err)
	}

	var claims Claims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		debugf("unable to parse token claims: %v", err)
		return nil, fmt.Errorf("unable to parse token claims: %w", err)
	}

	now := time.Now().UTC()
	if time.Unix(claims.Expiry, 0).Before(now) {
		debugf("token expired at %s (current time %s)", time.Unix(claims.Expiry, 0).UTC(), now)
		return nil, errors.New("token has expired")
	}

	if !claims.Audience.Contains(v.clientID) && claims.AuthorizedParty != v.clientID {
		debugf("token audience %v / azp %q does not match client id %q", []string(claims.Audience), claims.AuthorizedParty, v.clientID)
		return nil, fmt.Errorf("token is not intended for client %s", v.clientID)
	}

	if !v.isValidIssuer(claims.Issuer) {
		debugf("token issuer %q does not match any expected issuer %v", claims.Issuer, v.issuerList)
		return nil, fmt.Errorf("unexpected issuer %s", claims.Issuer)
	}

	debugf("token verified successfully for subject %q (issuer %q)", claims.Subject, claims.Issuer)
	return &claims, nil
}

func (v *Verifier) isValidIssuer(issuer string) bool {
	if len(v.validIssuer) == 0 {
		return false
	}

	normalised := normaliseIssuer(issuer)
	if normalised == "" {
		return false
	}

	_, ok := v.validIssuer[normalised]
	return ok
}

func (v *Verifier) lookupKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.RLock()
	key := v.keys[kid]
	v.mu.RUnlock()

	if key != nil {
		debugf("cache hit for signing key %q", kid)
		return key, nil
	}

	debugf("cache miss for signing key %q, refreshing keys", kid)
	if err := v.refreshKeys(ctx); err != nil {
		debugf("failed to refresh keys while resolving %q: %v", kid, err)
		return nil, err
	}

	v.mu.RLock()
	defer v.mu.RUnlock()
	key = v.keys[kid]
	if key == nil {
		debugf("no signing key found for kid %q after refresh", kid)
		return nil, fmt.Errorf("no signing key found for kid %s", kid)
	}
	debugf("signing key %q loaded after refresh", kid)
	return key, nil
}

func (v *Verifier) refreshKeys(ctx context.Context) error {
	debugf("requesting JWKS from %s", v.jwksURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		debugf("failed to build JWKS request: %v", err)
		return fmt.Errorf("failed to build JWKS request: %w", err)
	}

	resp, err := v.httpClient.Do(req)
	if err != nil {
		debugf("failed to fetch JWKS: %v", err)
		return fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		debugf("jwks endpoint returned status %d", resp.StatusCode)
		return fmt.Errorf("jwks endpoint returned status %d", resp.StatusCode)
	}

	var payload jwksResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		debugf("failed to decode JWKS response: %v", err)
		return fmt.Errorf("failed to decode JWKS response: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey, len(payload.Keys))
	for _, key := range payload.Keys {
		debugf("processing JWK with kid %q and kty %q", key.KeyID, key.KeyType)
		if key.KeyType != "RSA" {
			debugf("skipping non-RSA key %q", key.KeyID)
			continue
		}
		pubKey, err := key.toPublicKey()
		if err != nil {
			debugf("failed to parse JWK %q: %v", key.KeyID, err)
			return fmt.Errorf("failed to parse JWK %s: %w", key.KeyID, err)
		}
		keys[key.KeyID] = pubKey
	}

	if len(keys) == 0 {
		debugf("no RSA keys available in JWKS response")
		return errors.New("no RSA keys available in JWKS response")
	}

	v.mu.Lock()
	v.keys = keys
	v.mu.Unlock()

	debugf("JWKS refresh complete with %d signing keys", len(keys))
	return nil
}

func (k jwk) toPublicKey() (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("invalid modulus encoding: %w", err)
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("invalid exponent encoding: %w", err)
	}

	if len(eBytes) == 0 {
		return nil, errors.New("missing exponent value")
	}

	var eInt int
	for _, b := range eBytes {
		eInt = eInt<<8 + int(b)
	}

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: eInt,
	}, nil
}

// UnmarshalJSON allows the audience claim to be either a JSON string or JSON array.
func (a *Audience) UnmarshalJSON(data []byte) error {
	if len(data) == 0 {
		*a = nil
		return nil
	}

	if data[0] == '"' {
		var value string
		if err := json.Unmarshal(data, &value); err != nil {
			return err
		}
		*a = []string{value}
		return nil
	}

	var values []string
	if err := json.Unmarshal(data, &values); err != nil {
		return err
	}
	*a = values
	return nil
}

// Contains checks if the audience includes the provided value.
func (a Audience) Contains(target string) bool {
	for _, value := range a {
		if value == target {
			return true
		}
	}
	return false
}

func debugf(format string, args ...any) {
	log.Printf("[keycloak] "+format, args...)
}

func normaliseIssuer(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}

	parsed, err := url.Parse(trimmed)
	if err != nil {
		return strings.TrimRight(trimmed, "/")
	}

	parsed.Path = strings.TrimRight(parsed.Path, "/")
	parsed.RawPath = strings.TrimRight(parsed.RawPath, "/")

	return parsed.String()
}
