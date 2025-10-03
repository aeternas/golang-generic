package keycloak

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// OAuthConfig contains the configuration values required to perform the
// Authorization Code flow against a Keycloak realm.
type OAuthConfig struct {
	IssuerURL   string
	ClientID    string
	RedirectURL string
	Scopes      []string
	HTTPClient  *http.Client
}

// OAuthClient coordinates the Authorization Code flow for a Keycloak realm.
type OAuthClient struct {
	issuer      string
	clientID    string
	redirectURL string
	scopes      []string
	httpClient  *http.Client
}

// TokenResponse represents the JSON payload returned by the token endpoint.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	TokenType    string `json:"token_type"`
	IDToken      string `json:"id_token"`
}

// NewOAuthClient returns an OAuthClient prepared for the provided configuration.
func NewOAuthClient(cfg OAuthConfig) (*OAuthClient, error) {
	issuer := normaliseIssuer(cfg.IssuerURL)
	if issuer == "" {
		return nil, errors.New("issuer URL must be provided")
	}
	clientID := strings.TrimSpace(cfg.ClientID)
	if clientID == "" {
		return nil, errors.New("client ID must be provided")
	}
	redirect := strings.TrimSpace(cfg.RedirectURL)
	if redirect == "" {
		return nil, errors.New("redirect URL must be provided")
	}

	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid"}
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{}
	}

	return &OAuthClient{
		issuer:      issuer,
		clientID:    clientID,
		redirectURL: redirect,
		scopes:      scopes,
		httpClient:  httpClient,
	}, nil
}

// AuthCodeURL builds the authorization endpoint URL for the provided state and
// PKCE code challenge.
func (c *OAuthClient) AuthCodeURL(state, codeChallenge string) (string, error) {
	if state = strings.TrimSpace(state); state == "" {
		return "", errors.New("state must be provided")
	}
	if codeChallenge = strings.TrimSpace(codeChallenge); codeChallenge == "" {
		return "", errors.New("code challenge must be provided")
	}

	endpoint := c.issuer + "/protocol/openid-connect/auth"

	values := url.Values{}
	values.Set("response_type", "code")
	values.Set("client_id", c.clientID)
	values.Set("redirect_uri", c.redirectURL)
	values.Set("scope", strings.Join(c.scopes, " "))
	values.Set("state", state)
	values.Set("code_challenge", codeChallenge)
	values.Set("code_challenge_method", "S256")

	return endpoint + "?" + values.Encode(), nil
}

// Exchange swaps an authorisation code for tokens using the stored configuration.
func (c *OAuthClient) Exchange(ctx context.Context, code, codeVerifier string) (TokenResponse, error) {
	if code = strings.TrimSpace(code); code == "" {
		return TokenResponse{}, errors.New("code must be provided")
	}
	if codeVerifier = strings.TrimSpace(codeVerifier); codeVerifier == "" {
		return TokenResponse{}, errors.New("code verifier must be provided")
	}

	tokenEndpoint := c.issuer + "/protocol/openid-connect/token"

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", c.clientID)
	data.Set("code", code)
	data.Set("redirect_uri", c.redirectURL)
	data.Set("code_verifier", codeVerifier)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return TokenResponse{}, fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return TokenResponse{}, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return TokenResponse{}, fmt.Errorf("token endpoint returned status %d", resp.StatusCode)
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return TokenResponse{}, fmt.Errorf("failed to decode token response: %w", err)
	}

	return tokenResp, nil
}
