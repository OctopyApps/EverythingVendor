package httpserver

import (
	"net/http"
	"time"

	"platform-core/internal/authsvc"
	"platform-core/internal/coreapi"
	"platform-core/internal/rbac"
	"platform-core/internal/security"
)

type Server struct {
	mux *http.ServeMux
}

func NewServer(authHandlers *authsvc.Handlers, tokens *security.TokenManager, authorizer *rbac.Authorizer, coreHandlers *coreapi.Handlers) *Server {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeOK(w)
	})

	// Публичные маршруты аутентификации — без Authenticate middleware.
	mux.HandleFunc("POST /auth/register", authHandlers.Register)
	mux.HandleFunc("POST /auth/login", authHandlers.Login)
	mux.HandleFunc("POST /auth/refresh", authHandlers.Refresh)
	mux.HandleFunc("POST /auth/logout", authHandlers.Logout)

	authenticated := Authenticate(tokens)

	mux.Handle("GET /api/core/users",
		authenticated(RequirePermission(authorizer, "core", "user", "read", NoRecordID)(
			http.HandlerFunc(coreHandlers.ListUsers))))

	mux.Handle("GET /api/core/users/{id}",
		authenticated(RequirePermission(authorizer, "core", "user", "read", PathUUIDExtractor("id"))(
			http.HandlerFunc(coreHandlers.GetUser))))

	mux.Handle("GET /api/core/users/{id}/roles",
		authenticated(RequirePermission(authorizer, "core", "user", "read", PathUUIDExtractor("id"))(
			http.HandlerFunc(coreHandlers.ListUserRoles))))

	mux.Handle("POST /api/core/users/{id}/roles",
		authenticated(RequirePermission(authorizer, "core", "user", "write", PathUUIDExtractor("id"))(
			http.HandlerFunc(coreHandlers.AssignRole))))

	mux.Handle("DELETE /api/core/users/{id}/roles/{role_id}",
		authenticated(RequirePermission(authorizer, "core", "user", "write", PathUUIDExtractor("id"))(
			http.HandlerFunc(coreHandlers.RevokeRole))))

	mux.Handle("GET /api/core/roles",
		authenticated(RequirePermission(authorizer, "core", "role", "read", NoRecordID)(
			http.HandlerFunc(coreHandlers.ListRoles))))

	return &Server{mux: mux}
}

func (s *Server) Handler() http.Handler {
	return securityHeaders(requestTimeout(s.mux))
}

// securityHeaders выставляет базовые защитные заголовки на каждый ответ.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// requestTimeout защищает от медленных/зависших обработчиков.
func requestTimeout(next http.Handler) http.Handler {
	return http.TimeoutHandler(next, 15*time.Second, `{"error":"request_timeout"}`)
}

func writeOK(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}
