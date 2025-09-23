package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"golang-generic/internal/keycloak"
)

type registrationRequest struct {
	Username string `json:"username"`
	Email    string `json:"email,omitempty"`
}

type registrationResponse struct {
	Service           string `json:"service"`
	Message           string `json:"message"`
	Username          string `json:"username"`
	TemporaryPassword string `json:"temporary_password"`
}

func (s *server) handleKeycloakRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.keycloakRegistrar == nil {
		http.Error(w, "keycloak registration not configured", http.StatusServiceUnavailable)
		return
	}

	var req registrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON payload", http.StatusBadRequest)
		return
	}

	username := strings.TrimSpace(req.Username)
	if username == "" {
		http.Error(w, "username is required", http.StatusBadRequest)
		return
	}

	registration, err := s.keycloakRegistrar.RegisterUser(r.Context(), keycloak.RegistrationRequest{
		Username: username,
		Email:    strings.TrimSpace(req.Email),
	})
	if err != nil {
		if errors.Is(err, keycloak.ErrUserAlreadyExists) {
			http.Error(w, "user already exists", http.StatusConflict)
			return
		}
		s.logger.Printf("failed to register user %q: %v", username, err)
		http.Error(w, "failed to register user", http.StatusBadGateway)
		return
	}

	s.logger.Printf("registered new Keycloak user %q with temporary password", registration.Username)

	resp := registrationResponse{
		Service:           "service1",
		Message:           "user registered successfully",
		Username:          registration.Username,
		TemporaryPassword: registration.TemporaryPassword,
	}
	writeJSON(w, resp, http.StatusCreated)
}
