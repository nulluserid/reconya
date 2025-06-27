package middleware

import (
	"net/http"
	"reconya-ai/internal/config"
)

type Middleware struct {
	Config *config.Config
}

func NewMiddleware(cfg *config.Config) *Middleware {
	return &Middleware{Config: cfg}
}

// AuthMiddleware - no-op since authentication is handled by proxy
// This maintains compatibility with existing code that might reference it
func (m *Middleware) AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Pass through - proxy has already authenticated the user
		next.ServeHTTP(w, r)
	})
}
