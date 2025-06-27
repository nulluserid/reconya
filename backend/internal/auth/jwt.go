package auth

import (
	"encoding/json"
	"net/http"
)

// Stub auth handlers for proxy-based authentication
// These endpoints return success to maintain frontend compatibility
// while authentication is handled by the proxy layer

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type AuthHandlers struct {
	// No config needed - proxy handles auth
}

func NewAuthHandlers() *AuthHandlers {
	return &AuthHandlers{}
}

// LoginHandler - stub that returns success token for frontend compatibility
func (h *AuthHandlers) LoginHandler(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Return a stub token - proxy handles real authentication
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"token": "proxy-authenticated",
		"message": "Authentication handled by proxy",
	})
}

// CheckAuthHandler - stub that always returns success since proxy handles auth
func (h *AuthHandlers) CheckAuthHandler(w http.ResponseWriter, r *http.Request) {
	// Always return success since proxy has already authenticated the user
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "authenticated",
		"message": "Authentication handled by proxy",
	})
}
