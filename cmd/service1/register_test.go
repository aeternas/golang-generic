package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang-generic/internal/keycloak"
)

type fakeRegistrar struct {
	registerFn func(ctx context.Context, req keycloak.RegistrationRequest) (*keycloak.RegistrationResult, error)
}

func (f fakeRegistrar) RegisterUser(ctx context.Context, req keycloak.RegistrationRequest) (*keycloak.RegistrationResult, error) {
	if f.registerFn != nil {
		return f.registerFn(ctx, req)
	}
	return nil, errors.New("not implemented")
}

func TestHandleKeycloakRegisterSuccess(t *testing.T) {
	var captured keycloak.RegistrationRequest
	registrar := fakeRegistrar{registerFn: func(ctx context.Context, req keycloak.RegistrationRequest) (*keycloak.RegistrationResult, error) {
		captured = req
		return &keycloak.RegistrationResult{Username: req.Username, TemporaryPassword: "temp-pass"}, nil
	}}

	srv := &server{
		logger:            log.New(io.Discard, "", 0),
		keycloakRegistrar: registrar,
	}

	body, _ := json.Marshal(registrationRequest{Username: "new-user", Email: "user@example.com"})
	req := httptest.NewRequest(http.MethodPost, "/keycloak-register", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	srv.handleKeycloakRegister(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d", rec.Code)
	}

	if captured.Username != "new-user" {
		t.Fatalf("expected username to be forwarded, got %q", captured.Username)
	}

	var resp registrationResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.TemporaryPassword != "temp-pass" {
		t.Fatalf("unexpected password %q", resp.TemporaryPassword)
	}
}

func TestHandleKeycloakRegisterUserExists(t *testing.T) {
	registrar := fakeRegistrar{registerFn: func(ctx context.Context, req keycloak.RegistrationRequest) (*keycloak.RegistrationResult, error) {
		return nil, keycloak.ErrUserAlreadyExists
	}}
	srv := &server{logger: log.New(io.Discard, "", 0), keycloakRegistrar: registrar}

	req := httptest.NewRequest(http.MethodPost, "/keycloak-register", strings.NewReader(`{"username":"existing"}`))
	rec := httptest.NewRecorder()
	srv.handleKeycloakRegister(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected status 409, got %d", rec.Code)
	}
}

func TestHandleKeycloakRegisterValidation(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		body       string
		wantStatus int
	}{
		{name: "wrong method", method: http.MethodGet, wantStatus: http.StatusMethodNotAllowed},
		{name: "missing registrar", method: http.MethodPost, wantStatus: http.StatusServiceUnavailable},
		{name: "invalid json", method: http.MethodPost, body: "{", wantStatus: http.StatusBadRequest},
		{name: "missing username", method: http.MethodPost, body: `{"username":""}`, wantStatus: http.StatusBadRequest},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var registrar keycloak.UserRegistrar
			if tc.name != "missing registrar" {
				registrar = fakeRegistrar{}
			}
			srv := &server{logger: log.New(io.Discard, "", 0), keycloakRegistrar: registrar}

			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(tc.method, "/keycloak-register", strings.NewReader(tc.body))
			srv.handleKeycloakRegister(recorder, request)
			if recorder.Code != tc.wantStatus {
				t.Fatalf("expected status %d, got %d", tc.wantStatus, recorder.Code)
			}
		})
	}
}

func TestHandleKeycloakRegisterFailure(t *testing.T) {
	registrar := fakeRegistrar{registerFn: func(ctx context.Context, req keycloak.RegistrationRequest) (*keycloak.RegistrationResult, error) {
		return nil, errors.New("boom")
	}}
	srv := &server{logger: log.New(io.Discard, "", 0), keycloakRegistrar: registrar}

	req := httptest.NewRequest(http.MethodPost, "/keycloak-register", strings.NewReader(`{"username":"new"}`))
	rec := httptest.NewRecorder()
	srv.handleKeycloakRegister(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected status 502, got %d", rec.Code)
	}
}
