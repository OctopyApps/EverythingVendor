package coreapi

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

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

// ListPermissions возвращает полный каталог доступных платформе прав —
// справочник, нужен для UI управления правами ролей.
func (h *Handlers) ListPermissions(w http.ResponseWriter, r *http.Request) {
	permissions, err := h.repo.ListPermissions(r.Context())
	if err != nil {
		slog.Error("list permissions failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if permissions == nil {
		permissions = []Permission{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"permissions": permissions})
}

type createRoleRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

func (h *Handlers) CreateRole(w http.ResponseWriter, r *http.Request) {
	claims, ok := httpctx.ClaimsFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing_claims"})
		return
	}

	var req createRoleRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name_required"})
		return
	}

	role, err := h.repo.CreateRole(r.Context(), claims.TenantID, req.Name, req.Description)
	if err != nil {
		writeRepoError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, role)
}

// DeleteRole удаляет кастомную роль. Системные роли (admin/member) удалить нельзя —
// возвращается 409 role_is_system.
func (h *Handlers) DeleteRole(w http.ResponseWriter, r *http.Request) {
	claims, ok := httpctx.ClaimsFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing_claims"})
		return
	}

	roleID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_role_id"})
		return
	}

	if err := h.repo.DeleteRole(r.Context(), claims.TenantID, roleID); err != nil {
		writeRepoError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) ListRolePermissions(w http.ResponseWriter, r *http.Request) {
	claims, ok := httpctx.ClaimsFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing_claims"})
		return
	}

	roleID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_role_id"})
		return
	}

	permissions, err := h.repo.ListRolePermissions(r.Context(), claims.TenantID, roleID)
	if err != nil {
		slog.Error("list role permissions failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if permissions == nil {
		permissions = []Permission{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"permissions": permissions})
}

type assignPermissionRequest struct {
	PermissionID string `json:"permission_id"`
}

// AssignPermissionToRole назначает право роли. В отличие от AssignRole (где
// инвалидируется кэш одного пользователя), здесь изменяется сама роль,
// поэтому инвалидируем кэш всех её носителей (InvalidateRoleCache).
func (h *Handlers) AssignPermissionToRole(w http.ResponseWriter, r *http.Request) {
	claims, ok := httpctx.ClaimsFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing_claims"})
		return
	}

	roleID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_role_id"})
		return
	}

	var req assignPermissionRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	permissionID, err := uuid.Parse(req.PermissionID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_permission_id"})
		return
	}

	if err := h.repo.AssignPermissionToRole(r.Context(), claims.TenantID, roleID, permissionID); err != nil {
		writeRepoError(w, err)
		return
	}

	if err := h.authorizer.InvalidateRoleCache(r.Context(), claims.TenantID, roleID); err != nil {
		slog.Error("failed to invalidate rbac cache after role permission assignment", "error", err)
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) RevokePermissionFromRole(w http.ResponseWriter, r *http.Request) {
	claims, ok := httpctx.ClaimsFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing_claims"})
		return
	}

	roleID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_role_id"})
		return
	}
	permissionID, err := uuid.Parse(r.PathValue("permission_id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_permission_id"})
		return
	}

	if err := h.repo.RevokePermissionFromRole(r.Context(), claims.TenantID, roleID, permissionID); err != nil {
		writeRepoError(w, err)
		return
	}

	if err := h.authorizer.InvalidateRoleCache(r.Context(), claims.TenantID, roleID); err != nil {
		slog.Error("failed to invalidate rbac cache after role permission revocation", "error", err)
	}

	w.WriteHeader(http.StatusNoContent)
}

// ListResourceGrants возвращает точечные разрешения/запреты тенанта
// с необязательными query-фильтрами: user_id, module, entity, record_id.
func (h *Handlers) ListResourceGrants(w http.ResponseWriter, r *http.Request) {
	claims, ok := httpctx.ClaimsFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing_claims"})
		return
	}

	filter := ResourceGrantFilter{
		Module: r.URL.Query().Get("module"),
		Entity: r.URL.Query().Get("entity"),
	}
	if v := r.URL.Query().Get("user_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_user_id"})
			return
		}
		filter.UserID = &id
	}
	if v := r.URL.Query().Get("record_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_record_id"})
			return
		}
		filter.RecordID = &id
	}

	grants, err := h.repo.ListResourceGrants(r.Context(), claims.TenantID, filter)
	if err != nil {
		slog.Error("list resource grants failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if grants == nil {
		grants = []ResourceGrant{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"resource_grants": grants})
}

type createResourceGrantRequest struct {
	UserID   string `json:"user_id"`
	Module   string `json:"module"`
	Entity   string `json:"entity"`
	RecordID string `json:"record_id"`
	Action   string `json:"action"`
	Effect   string `json:"effect"`
}

// CreateResourceGrant создаёт точечное разрешение/запрет на конкретную запись.
// Кэш не инвалидируем — resource_grants всегда проверяются напрямую в БД,
// они не кэшируются (см. docs/rbac.md).
func (h *Handlers) CreateResourceGrant(w http.ResponseWriter, r *http.Request) {
	claims, ok := httpctx.ClaimsFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing_claims"})
		return
	}

	var req createResourceGrantRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	userID, err := uuid.Parse(req.UserID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_user_id"})
		return
	}
	recordID, err := uuid.Parse(req.RecordID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_record_id"})
		return
	}
	if req.Module == "" || req.Entity == "" || req.Action == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing_fields"})
		return
	}

	grant := ResourceGrant{
		UserID:   userID,
		Module:   req.Module,
		Entity:   req.Entity,
		RecordID: recordID,
		Action:   req.Action,
		Effect:   req.Effect,
	}
	created, err := h.repo.CreateResourceGrant(r.Context(), claims.TenantID, grant, claims.UserID)
	if err != nil {
		writeRepoError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

func (h *Handlers) DeleteResourceGrant(w http.ResponseWriter, r *http.Request) {
	claims, ok := httpctx.ClaimsFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing_claims"})
		return
	}

	grantID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant_id"})
		return
	}

	if err := h.repo.DeleteResourceGrant(r.Context(), claims.TenantID, grantID); err != nil {
		writeRepoError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// decodeJSON — общий хелпер декодирования JSON с лимитом размера тела
// и запретом на неизвестные поля (те же правила, что и в authsvc.decodeJSON).
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request_body"})
		return false
	}
	return true
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
	case errors.Is(err, ErrRoleNameTaken):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "role_name_taken"})
	case errors.Is(err, ErrRoleIsSystem):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "role_is_system"})
	case errors.Is(err, ErrPermissionNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "permission_not_found"})
	case errors.Is(err, ErrInvalidEffect):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_effect"})
	case errors.Is(err, ErrResourceGrantNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "resource_grant_not_found"})
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
