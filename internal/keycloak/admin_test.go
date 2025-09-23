package keycloak

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestAdminClientRegisterUser(t *testing.T) {
	var createCalled atomic.Bool
	var passwordSet string
	var roleAssigned bool

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/realms/master/protocol/openid-connect/token":
			if r.Method != http.MethodPost {
				t.Fatalf("expected POST token request, got %s", r.Method)
			}
			if err := r.ParseForm(); err != nil {
				t.Fatalf("parse form: %v", err)
			}
			if got := r.PostForm.Get("client_id"); got != "admin-cli" {
				t.Fatalf("unexpected client_id %q", got)
			}
			if got := r.PostForm.Get("username"); got != "admin" {
				t.Fatalf("unexpected username %q", got)
			}
			if got := r.PostForm.Get("password"); got != "secret" {
				t.Fatalf("unexpected password %q", got)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "test-token"})
		case "/admin/realms/demo/users":
			if r.Method != http.MethodPost {
				t.Fatalf("expected POST create user, got %s", r.Method)
			}
			if auth := r.Header.Get("Authorization"); auth != "Bearer test-token" {
				t.Fatalf("unexpected Authorization header %q", auth)
			}
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode create user payload: %v", err)
			}
			if payload["username"] != "alice" {
				t.Fatalf("unexpected username %v", payload["username"])
			}
			actions, ok := payload["requiredActions"].([]any)
			if !ok || len(actions) != 1 || actions[0] != "UPDATE_PASSWORD" {
				t.Fatalf("expected required action UPDATE_PASSWORD, got %#v", payload["requiredActions"])
			}
			createCalled.Store(true)
			w.Header().Set("Location", server.URL+"/admin/realms/demo/users/12345")
			w.WriteHeader(http.StatusCreated)
		case "/admin/realms/demo/users/12345/reset-password":
			if r.Method != http.MethodPut {
				t.Fatalf("expected PUT reset password, got %s", r.Method)
			}
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode password payload: %v", err)
			}
			if payload["temporary"] != true {
				t.Fatalf("temporary flag not set: %#v", payload)
			}
			if value, ok := payload["value"].(string); ok {
				passwordSet = value
			}
			w.WriteHeader(http.StatusNoContent)
		case "/admin/realms/demo/roles/self-service-user":
			if r.Method != http.MethodGet {
				t.Fatalf("expected GET role lookup, got %s", r.Method)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(roleRepresentation{ID: "role-id", Name: "self-service-user"})
		case "/admin/realms/demo/users/12345/role-mappings/realm":
			if r.Method != http.MethodPost {
				t.Fatalf("expected POST role mapping, got %s", r.Method)
			}
			var payload []roleRepresentation
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode role payload: %v", err)
			}
			if len(payload) != 1 || payload[0].ID != "role-id" {
				t.Fatalf("unexpected role payload %#v", payload)
			}
			roleAssigned = true
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client, err := NewAdminClient(AdminConfig{
		BaseURL:          server.URL,
		Realm:            "demo",
		Username:         "admin",
		Password:         "secret",
		RegistrationRole: "self-service-user",
	})
	if err != nil {
		t.Fatalf("NewAdminClient: %v", err)
	}

	res, err := client.RegisterUser(context.Background(), RegistrationRequest{Username: "alice"})
	if err != nil {
		t.Fatalf("RegisterUser: %v", err)
	}
	if res.Username != "alice" {
		t.Fatalf("unexpected username %q", res.Username)
	}
	if res.UserID != "12345" {
		t.Fatalf("unexpected user ID %q", res.UserID)
	}
	if len(res.TemporaryPassword) == 0 {
		t.Fatalf("temporary password not returned")
	}
	if !createCalled.Load() {
		t.Fatalf("create user endpoint not called")
	}
	if passwordSet == "" {
		t.Fatalf("password payload not observed")
	}
	if !roleAssigned {
		t.Fatalf("role assignment not performed")
	}
}

func TestAdminClientRegisterUser_UserExists(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/realms/master/protocol/openid-connect/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "test-token"})
		case "/admin/realms/demo/users":
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"errorMessage":"exists"}`))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client, err := NewAdminClient(AdminConfig{
		BaseURL:          server.URL,
		Realm:            "demo",
		Username:         "admin",
		Password:         "secret",
		RegistrationRole: "self-service-user",
	})
	if err != nil {
		t.Fatalf("NewAdminClient: %v", err)
	}

	_, err = client.RegisterUser(context.Background(), RegistrationRequest{Username: "alice"})
	if !errors.Is(err, ErrUserAlreadyExists) {
		t.Fatalf("expected ErrUserAlreadyExists, got %v", err)
	}
}

func TestExtractUserID(t *testing.T) {
	tests := []struct {
		location string
		want     string
		wantErr  bool
	}{
		{location: "/admin/realms/demo/users/123", want: "123"},
		{location: "http://example.com/admin/realms/demo/users/abc", want: "abc"},
		{location: "", wantErr: true},
		{location: "not a url", want: "not a url"},
		{location: "http://example.com/", wantErr: true},
	}

	for _, tc := range tests {
		got, err := extractUserID(tc.location)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("expected error for %q", tc.location)
			}
			continue
		}
		if err != nil {
			t.Fatalf("extractUserID(%q): %v", tc.location, err)
		}
		if got != tc.want {
			t.Fatalf("extractUserID(%q) = %q, want %q", tc.location, got, tc.want)
		}
	}
}

func TestNewAdminClientValidation(t *testing.T) {
	_, err := NewAdminClient(AdminConfig{})
	if err == nil {
		t.Fatalf("expected error when config empty")
	}

	_, err = NewAdminClient(AdminConfig{BaseURL: ":://invalid", Realm: "demo", Username: "u", Password: "p", RegistrationRole: "role"})
	if err == nil {
		t.Fatalf("expected error for invalid base URL")
	}

	client, err := NewAdminClient(AdminConfig{BaseURL: "http://example.com", Realm: "demo", Username: "u", Password: "p", RegistrationRole: "role"})
	if err != nil {
		t.Fatalf("NewAdminClient valid config: %v", err)
	}
	if got := client.passwordLength; got != 16 {
		t.Fatalf("unexpected default password length %d", got)
	}
}

func TestGeneratePasswordLength(t *testing.T) {
	client, err := NewAdminClient(AdminConfig{BaseURL: "http://example.com", Realm: "demo", Username: "u", Password: "p", RegistrationRole: "role", PasswordLength: 20})
	if err != nil {
		t.Fatalf("NewAdminClient: %v", err)
	}
	pwd, err := client.generatePassword()
	if err != nil {
		t.Fatalf("generatePassword: %v", err)
	}
	if len(pwd) != 20 {
		t.Fatalf("expected password length 20, got %d", len(pwd))
	}
}

func TestReadBodyLimit(t *testing.T) {
	data := strings.Repeat("a", 1024)
	got, err := readBody(strings.NewReader(data))
	if err != nil {
		t.Fatalf("readBody: %v", err)
	}
	if string(got) != data {
		t.Fatalf("unexpected body contents")
	}
}

func TestFetchRoleCachesResult(t *testing.T) {
	var hits int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/realms/master/protocol/openid-connect/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "test-token"})
		case "/admin/realms/demo/users":
			w.Header().Set("Location", "/admin/realms/demo/users/1")
			w.WriteHeader(http.StatusCreated)
		case "/admin/realms/demo/users/1/reset-password":
			w.WriteHeader(http.StatusNoContent)
		case "/admin/realms/demo/roles/self-service-user":
			atomic.AddInt32(&hits, 1)
			_ = json.NewEncoder(w).Encode(roleRepresentation{ID: "role-id", Name: "self-service-user"})
		case "/admin/realms/demo/users/1/role-mappings/realm":
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client, err := NewAdminClient(AdminConfig{
		BaseURL:          server.URL,
		Realm:            "demo",
		Username:         "admin",
		Password:         "secret",
		RegistrationRole: "self-service-user",
	})
	if err != nil {
		t.Fatalf("NewAdminClient: %v", err)
	}

	if _, err := client.RegisterUser(context.Background(), RegistrationRequest{Username: "alice"}); err != nil {
		t.Fatalf("RegisterUser first call: %v", err)
	}
	if _, err := client.RegisterUser(context.Background(), RegistrationRequest{Username: "bob"}); err != nil {
		t.Fatalf("RegisterUser second call: %v", err)
	}

	if hits != 1 {
		t.Fatalf("expected role lookup to be cached, got %d hits", hits)
	}
}

func TestCreateUserHandlesRelativeLocation(t *testing.T) {
	// Regression test to ensure relative Location headers are accepted.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/realms/master/protocol/openid-connect/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "test-token"})
		case "/admin/realms/demo/users":
			w.Header().Set("Location", "/admin/realms/demo/users/789")
			w.WriteHeader(http.StatusCreated)
		case "/admin/realms/demo/users/789/reset-password":
			w.WriteHeader(http.StatusNoContent)
		case "/admin/realms/demo/roles/self-service-user":
			_ = json.NewEncoder(w).Encode(roleRepresentation{ID: "role-id", Name: "self-service-user"})
		case "/admin/realms/demo/users/789/role-mappings/realm":
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client, err := NewAdminClient(AdminConfig{
		BaseURL:          server.URL,
		Realm:            "demo",
		Username:         "admin",
		Password:         "secret",
		RegistrationRole: "self-service-user",
	})
	if err != nil {
		t.Fatalf("NewAdminClient: %v", err)
	}

	res, err := client.RegisterUser(context.Background(), RegistrationRequest{Username: "charlie"})
	if err != nil {
		t.Fatalf("RegisterUser: %v", err)
	}
	if res.UserID != "789" {
		t.Fatalf("expected user ID 789, got %s", res.UserID)
	}
}

func TestAssignRoleErrorPropagation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/realms/master/protocol/openid-connect/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "test-token"})
		case "/admin/realms/demo/users":
			w.Header().Set("Location", "/admin/realms/demo/users/1")
			w.WriteHeader(http.StatusCreated)
		case "/admin/realms/demo/users/1/reset-password":
			w.WriteHeader(http.StatusNoContent)
		case "/admin/realms/demo/roles/self-service-user":
			w.WriteHeader(http.StatusInternalServerError)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client, err := NewAdminClient(AdminConfig{
		BaseURL:          server.URL,
		Realm:            "demo",
		Username:         "admin",
		Password:         "secret",
		RegistrationRole: "self-service-user",
	})
	if err != nil {
		t.Fatalf("NewAdminClient: %v", err)
	}

	if _, err := client.RegisterUser(context.Background(), RegistrationRequest{Username: "alice"}); err == nil {
		t.Fatalf("expected error when role lookup fails")
	}
}

func TestObtainTokenError(t *testing.T) {
	client, err := NewAdminClient(AdminConfig{BaseURL: "http://example.com", Realm: "demo", Username: "u", Password: "p", RegistrationRole: "role"})
	if err != nil {
		t.Fatalf("NewAdminClient: %v", err)
	}
	client.httpClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("boom")
	})}
	if _, err := client.obtainToken(context.Background()); err == nil {
		t.Fatalf("expected error when requesting token with invalid base URL")
	}
}

func TestParseRoleURL(t *testing.T) {
	client, err := NewAdminClient(AdminConfig{BaseURL: "http://example.com", Realm: "demo", Username: "u", Password: "p", RegistrationRole: "role"})
	if err != nil {
		t.Fatalf("NewAdminClient: %v", err)
	}
	endpoint := fmt.Sprintf("%s/admin/realms/%s/roles/%s", client.baseURL, client.realm, url.PathEscape(client.registrationRole))
	if !strings.Contains(endpoint, "roles/role") {
		t.Fatalf("role endpoint not formatted correctly: %s", endpoint)
	}
}
