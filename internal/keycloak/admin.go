package keycloak

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ErrUserAlreadyExists indicates that a Keycloak user with the requested username is already present.
var ErrUserAlreadyExists = errors.New("keycloak: user already exists")

// AdminConfig controls how the AdminClient communicates with Keycloak.
type AdminConfig struct {
	BaseURL          string
	Realm            string
	Username         string
	Password         string
	ClientID         string
	RegistrationRole string
	HTTPClient       *http.Client
	PasswordLength   int
}

// RegistrationRequest represents the data used to create a new Keycloak user.
type RegistrationRequest struct {
	Username string
	Email    string
}

// RegistrationResult describes the outcome of a successful registration.
type RegistrationResult struct {
	UserID            string
	Username          string
	TemporaryPassword string
}

// UserRegistrar allows registering new users in Keycloak.
type UserRegistrar interface {
	RegisterUser(ctx context.Context, req RegistrationRequest) (*RegistrationResult, error)
}

// AdminClient performs administrative operations against Keycloak's admin REST API.
type AdminClient struct {
	baseURL          string
	realm            string
	username         string
	password         string
	clientID         string
	registrationRole string
	httpClient       *http.Client
	passwordLength   int

	roleMu     sync.Mutex
	cachedRole *roleRepresentation
}

type roleRepresentation struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

var defaultPasswordCharset = []rune("ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789@#$%")

// NewAdminClient constructs an AdminClient using the supplied configuration.
func NewAdminClient(cfg AdminConfig) (*AdminClient, error) {
	baseURL := strings.TrimSpace(cfg.BaseURL)
	if baseURL == "" {
		return nil, errors.New("keycloak base URL must be provided")
	}
	if _, err := url.Parse(baseURL); err != nil {
		return nil, fmt.Errorf("invalid keycloak base URL: %w", err)
	}
	baseURL = strings.TrimRight(baseURL, "/")

	realm := strings.TrimSpace(cfg.Realm)
	if realm == "" {
		return nil, errors.New("keycloak realm must be provided")
	}

	username := strings.TrimSpace(cfg.Username)
	if username == "" {
		return nil, errors.New("keycloak admin username must be provided")
	}
	password := cfg.Password
	if password == "" {
		return nil, errors.New("keycloak admin password must be provided")
	}

	registrationRole := strings.TrimSpace(cfg.RegistrationRole)
	if registrationRole == "" {
		return nil, errors.New("registration role must be provided")
	}

	clientID := strings.TrimSpace(cfg.ClientID)
	if clientID == "" {
		clientID = "admin-cli"
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 5 * time.Second}
	}

	passwordLength := cfg.PasswordLength
	if passwordLength <= 0 {
		passwordLength = 16
	}

	return &AdminClient{
		baseURL:          baseURL,
		realm:            realm,
		username:         username,
		password:         password,
		clientID:         clientID,
		registrationRole: registrationRole,
		httpClient:       httpClient,
		passwordLength:   passwordLength,
	}, nil
}

// RegisterUser creates a Keycloak user with a temporary password and assigns the configured role.
func (c *AdminClient) RegisterUser(ctx context.Context, req RegistrationRequest) (*RegistrationResult, error) {
	username := strings.TrimSpace(req.Username)
	if username == "" {
		return nil, errors.New("username must be provided")
	}

	token, err := c.obtainToken(ctx)
	if err != nil {
		return nil, err
	}

	userID, err := c.createUser(ctx, token, username, strings.TrimSpace(req.Email))
	if err != nil {
		return nil, err
	}

	password, err := c.generatePassword()
	if err != nil {
		return nil, err
	}

	if err := c.setTemporaryPassword(ctx, token, userID, password); err != nil {
		return nil, err
	}

	if err := c.assignRole(ctx, token, userID); err != nil {
		return nil, err
	}

	return &RegistrationResult{UserID: userID, Username: username, TemporaryPassword: password}, nil
}

func (c *AdminClient) obtainToken(ctx context.Context) (string, error) {
	values := url.Values{}
	values.Set("grant_type", "password")
	values.Set("client_id", c.clientID)
	values.Set("username", c.username)
	values.Set("password", c.password)

	endpoint := c.baseURL + "/realms/master/protocol/openid-connect/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return "", fmt.Errorf("create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("request token: %w", err)
	}
	defer resp.Body.Close()

	body, err := readBody(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint returned %s: %s", resp.Status, body)
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("parse token response: %w", err)
	}
	if tokenResp.AccessToken == "" {
		return "", errors.New("token response missing access_token")
	}
	return tokenResp.AccessToken, nil
}

func (c *AdminClient) createUser(ctx context.Context, token, username, email string) (string, error) {
	payload := map[string]any{
		"username":        username,
		"enabled":         true,
		"requiredActions": []string{"UPDATE_PASSWORD"},
	}
	if email != "" {
		payload["email"] = email
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal create user payload: %w", err)
	}

	endpoint := fmt.Sprintf("%s/admin/realms/%s/users", c.baseURL, c.realm)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("create user request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("create user: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := readBody(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode == http.StatusConflict {
		return "", ErrUserAlreadyExists
	}
	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("create user returned %s: %s", resp.Status, respBody)
	}

	location := resp.Header.Get("Location")
	if location == "" {
		return "", errors.New("create user response missing Location header")
	}

	userID, err := extractUserID(location)
	if err != nil {
		return "", err
	}
	return userID, nil
}

func (c *AdminClient) setTemporaryPassword(ctx context.Context, token, userID, password string) error {
	payload := map[string]any{
		"type":      "password",
		"value":     password,
		"temporary": true,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal password payload: %w", err)
	}

	endpoint := fmt.Sprintf("%s/admin/realms/%s/users/%s/reset-password", c.baseURL, c.realm, userID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create password request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("set temporary password: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		respBody, _ := readBody(resp.Body)
		return fmt.Errorf("set temporary password returned %s: %s", resp.Status, respBody)
	}
	return nil
}

func (c *AdminClient) assignRole(ctx context.Context, token, userID string) error {
	role, err := c.fetchRole(ctx, token)
	if err != nil {
		return err
	}

	payload := []roleRepresentation{{ID: role.ID, Name: role.Name}}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal role assignment payload: %w", err)
	}

	endpoint := fmt.Sprintf("%s/admin/realms/%s/users/%s/role-mappings/realm", c.baseURL, c.realm, userID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create role assignment request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("assign role: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		respBody, _ := readBody(resp.Body)
		return fmt.Errorf("assign role returned %s: %s", resp.Status, respBody)
	}
	return nil
}

func (c *AdminClient) fetchRole(ctx context.Context, token string) (*roleRepresentation, error) {
	c.roleMu.Lock()
	cached := c.cachedRole
	c.roleMu.Unlock()
	if cached != nil {
		return cached, nil
	}

	endpoint := fmt.Sprintf("%s/admin/realms/%s/roles/%s", c.baseURL, c.realm, url.PathEscape(c.registrationRole))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("create role lookup request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("lookup role: %w", err)
	}
	defer resp.Body.Close()

	body, err := readBody(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("lookup role returned %s: %s", resp.Status, body)
	}

	var role roleRepresentation
	if err := json.Unmarshal(body, &role); err != nil {
		return nil, fmt.Errorf("parse role response: %w", err)
	}
	if role.ID == "" || role.Name == "" {
		return nil, errors.New("role response missing id or name")
	}

	c.roleMu.Lock()
	c.cachedRole = &role
	c.roleMu.Unlock()

	return &role, nil
}

func (c *AdminClient) generatePassword() (string, error) {
	result := make([]rune, c.passwordLength)
	charsetLength := big.NewInt(int64(len(defaultPasswordCharset)))
	for i := range result {
		idx, err := rand.Int(rand.Reader, charsetLength)
		if err != nil {
			return "", fmt.Errorf("generate password: %w", err)
		}
		result[i] = defaultPasswordCharset[idx.Int64()]
	}
	return string(result), nil
}

func extractUserID(location string) (string, error) {
	parsed, err := url.Parse(location)
	if err != nil {
		return "", fmt.Errorf("invalid user location: %w", err)
	}

	segments := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	if len(segments) == 0 {
		return "", errors.New("invalid user location path")
	}

	userID := segments[len(segments)-1]
	if userID == "" {
		return "", errors.New("user ID not found in location header")
	}
	return userID, nil
}

func readBody(body io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	return data, nil
}
