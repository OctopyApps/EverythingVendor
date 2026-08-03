package coreapi

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/google/uuid"

	"platform-core/internal/httpctx"
	"platform-core/internal/rbac"
)

const (
	defaultLimit = 20
	maxLimit     = 100
)

type Handlers struct {
	repo       *Repository
	authorizer *rbac.Authorizer
}

func NewHandlers(repo *Repository, authorizer *rbac.Authorizer) *Handlers {
	return &Handlers{repo: repo, authorizer: authorizer}
}

func (h *Handlers) ListUsers(w http.ResponseWriter, r *http.Request) {
	claims, ok := httpctx.ClaimsFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing_claims"})
		return
	}

	limit := parseIntParam(r, "limit", defaultLimit, 1, maxLimit)
	offset := parseIntParam(r, "offset", 0, 0, 1<<31-1)

	users, err := h.repo.ListUsers(r.Context(), claims.TenantID, limit, offset)
	if err != nil {
		slog.Error("list users failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if users == nil {
		users = []User{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": users, "limit": limit, "offset": offset})
}

func (h *Handlers) GetUser(w http.ResponseWriter, r *http.Request) {
	claims, ok := httpctx.ClaimsFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing_claims"})
		return
	}

	userID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_user_id"})
		return
	}

	user, err := h.repo.GetUser(r.Context(), claims.TenantID, userID)
	if err != nil {
		writeRepoError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, user)
}

func (h *Handlers) ListRoles(w http.ResponseWriter, r *http.Request) {
	claims, ok := httpctx.ClaimsFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing_claims"})
		return
	}

	roles, err := h.repo.ListRoles(r.Context(), claims.TenantID)
	if err != nil {
		slog.Error("list roles failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if roles == nil {
		roles = []Role{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"roles": roles})
}

func (h *Handlers) ListUserRoles(w http.ResponseWriter, r *http.Request) {
	claims, ok := httpctx.ClaimsFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing_claims"})
		return
	}

	userID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_user_id"})
		return
	}

	roles, err := h.repo.ListUserRoles(r.Context(), claims.TenantID, userID)
	if err != nil {
		slog.Error("list user roles failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if roles == nil {
		roles = []Role{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"roles": roles})
}

type assignRoleRequest struct {
	RoleID string `json:"role_id"`
}

func (h *Handlers) AssignRole(w http.ResponseWriter, r *http.Request) {
	claims, ok := httpctx.ClaimsFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing_claims"})
		return
	}

	userID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_user_id"})
		return
	}

	var req assignRoleRequest
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request_body"})
		return
	}

	roleID, err := uuid.Parse(req.RoleID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_role_id"})
		return
	}

	if err := h.repo.AssignRole(r.Context(), claims.TenantID, userID, roleID, claims.UserID); err != nil {
		writeRepoError(w, err)
		return
	}

	// Критично: без этого новая роль подхватится только после истечения TTL кэша.
	if err := h.authorizer.InvalidateUserCache(r.Context(), claims.TenantID, userID); err != nil {
		slog.Error("failed to invalidate rbac cache after role assignment", "error", err)
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) RevokeRole(w http.ResponseWriter, r *http.Request) {
	claims, ok := httpctx.ClaimsFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing_claims"})
		return
	}

	userID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_user_id"})
		return
	}
	roleID, err := uuid.Parse(r.PathValue("role_id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_role_id"})
		return
	}

	if err := h.repo.RevokeRole(r.Context(), claims.TenantID, userID, roleID); err != nil {
		writeRepoError(w, err)
		return
	}

	if err := h.authorizer.InvalidateUserCache(r.Context(), claims.TenantID, userID); err != nil {
		slog.Error("failed to invalidate rbac cache after role revocation", "error", err)
	}

	w.WriteHeader(http.StatusNoContent)
}

// RevokeSessions — админский принудительный логаут другого пользователя
// (отзывает все его refresh-токены). Требует core.user:write — то же право,
// что и управление ролями пользователя.
//
// ВАЖНО: не отзывает уже выданный access-токен (JWT) целевого пользователя —
// он продолжит действовать до истечения своего TTL (см. docs/security.md).
func (h *Handlers) RevokeSessions(w http.ResponseWriter, r *http.Request) {
	claims, ok := httpctx.ClaimsFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing_claims"})
		return
	}

	userID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_user_id"})
		return
	}

	if err := h.repo.RevokeAllSessions(r.Context(), claims.TenantID, userID); err != nil {
		writeRepoError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func parseIntParam(r *http.Request, name string, def, min, max int) int {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return def
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v < min {
		return def
	}
	if v > max {
		return max
	}
	return v
}

func writeRepoError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrUserNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "user_not_found"})
	case errors.Is(err, ErrRoleNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "role_not_found"})
	default:
		slog.Error("coreapi internal error", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		slog.Error("failed to write json response", "error", err)
	}
}
