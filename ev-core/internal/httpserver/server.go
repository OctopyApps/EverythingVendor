package httpserver

import (
	"net/http"
	"time"

	"platform-core/internal/authsvc"
	"platform-core/internal/coreapi"
	"platform-core/internal/ratelimit"
	"platform-core/internal/rbac"
	"platform-core/internal/security"
)

type Server struct {
	mux *http.ServeMux
}

// RateLimitConfig — лимиты по IP для публичных auth-эндпоинтов (см. RateLimitByIP
// в middleware.go). Лимит по аккаунту для /auth/login настраивается отдельно,
// внутри authsvc.ServiceConfig — здесь только IP-уровень.
type RateLimitConfig struct {
	LoginPerIP       int
	LoginIPWindow    time.Duration
	RegisterPerIP    int
	RegisterIPWindow time.Duration
}

func NewServer(
	authHandlers *authsvc.Handlers,
	tokens *security.TokenManager,
	authorizer *rbac.Authorizer,
	coreHandlers *coreapi.Handlers,
	limiter *ratelimit.Limiter,
	rlCfg RateLimitConfig,
) *Server {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeOK(w)
	})

	authenticated := Authenticate(tokens)

	// Публичные маршруты аутентификации — без Authenticate middleware, но с rate limit
	// по IP на /register и /login (защита от брутфорса; доп. лимит по аккаунту
	// для /login реализован внутри authsvc.Service.Login, см. docs/security.md).
	mux.Handle("POST /auth/register",
		RateLimitByIP(limiter, "register", rlCfg.RegisterPerIP, rlCfg.RegisterIPWindow)(
			http.HandlerFunc(authHandlers.Register)))

	mux.Handle("POST /auth/login",
		RateLimitByIP(limiter, "login", rlCfg.LoginPerIP, rlCfg.LoginIPWindow)(
			http.HandlerFunc(authHandlers.Login)))

	mux.HandleFunc("POST /auth/refresh", authHandlers.Refresh)
	mux.HandleFunc("POST /auth/logout", authHandlers.Logout)

	// Самообслуживание: отзыв всех своих refresh-токенов, требует только
	// валидный access-токен, без отдельного права через RBAC.
	mux.Handle("POST /auth/logout-all", authenticated(http.HandlerFunc(authHandlers.LogoutAll)))

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

	mux.Handle("POST /api/core/roles",
		authenticated(RequirePermission(authorizer, "core", "role", "write", NoRecordID)(
			http.HandlerFunc(coreHandlers.CreateRole))))

	mux.Handle("DELETE /api/core/roles/{id}",
		authenticated(RequirePermission(authorizer, "core", "role", "write", PathUUIDExtractor("id"))(
			http.HandlerFunc(coreHandlers.DeleteRole))))

	mux.Handle("GET /api/core/roles/{id}/permissions",
		authenticated(RequirePermission(authorizer, "core", "role", "read", PathUUIDExtractor("id"))(
			http.HandlerFunc(coreHandlers.ListRolePermissions))))

	mux.Handle("POST /api/core/roles/{id}/permissions",
		authenticated(RequirePermission(authorizer, "core", "role", "write", PathUUIDExtractor("id"))(
			http.HandlerFunc(coreHandlers.AssignPermissionToRole))))

	mux.Handle("DELETE /api/core/roles/{id}/permissions/{permission_id}",
		authenticated(RequirePermission(authorizer, "core", "role", "write", PathUUIDExtractor("id"))(
			http.HandlerFunc(coreHandlers.RevokePermissionFromRole))))

	// Каталог всех возможных прав платформы — своё отдельное право core.permission:read,
	// чтобы не перегружать семантикой core.role:read (миграция 0003).
	mux.Handle("GET /api/core/permissions",
		authenticated(RequirePermission(authorizer, "core", "permission", "read", NoRecordID)(
			http.HandlerFunc(coreHandlers.ListPermissions))))

	// Управление точечными resource_grants — своё право core.resource_grant:*
	// (миграция 0003), т.к. это мета-уровень контроля над любым модулем/сущностью.
	mux.Handle("GET /api/core/resource-grants",
		authenticated(RequirePermission(authorizer, "core", "resource_grant", "read", NoRecordID)(
			http.HandlerFunc(coreHandlers.ListResourceGrants))))

	mux.Handle("POST /api/core/resource-grants",
		authenticated(RequirePermission(authorizer, "core", "resource_grant", "write", NoRecordID)(
			http.HandlerFunc(coreHandlers.CreateResourceGrant))))

	mux.Handle("DELETE /api/core/resource-grants/{id}",
		authenticated(RequirePermission(authorizer, "core", "resource_grant", "write", PathUUIDExtractor("id"))(
			http.HandlerFunc(coreHandlers.DeleteResourceGrant))))

	// Админский принудительный логаут другого пользователя — то же право, что
	// и управление его ролями (core.user:write).
	mux.Handle("POST /api/core/users/{id}/revoke-sessions",
		authenticated(RequirePermission(authorizer, "core", "user", "write", PathUUIDExtractor("id"))(
			http.HandlerFunc(coreHandlers.RevokeSessions))))

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
