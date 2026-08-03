package coreapi

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Repository struct {
	pool *pgxpool.Pool
}

func NewRepository(pool *pgxpool.Pool) *Repository {
	return &Repository{pool: pool}
}

// ListUsers возвращает пользователей тенанта с пагинацией.
func (r *Repository) ListUsers(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]User, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, email, is_active, created_at
		FROM users
		WHERE tenant_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`, tenantID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("query users: %w", err)
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Email, &u.IsActive, &u.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return users, nil
}

func (r *Repository) GetUser(ctx context.Context, tenantID, userID uuid.UUID) (*User, error) {
	var u User
	err := r.pool.QueryRow(ctx, `
		SELECT id, email, is_active, created_at
		FROM users
		WHERE tenant_id = $1 AND id = $2
	`, tenantID, userID).Scan(&u.ID, &u.Email, &u.IsActive, &u.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("query user: %w", err)
	}
	return &u, nil
}

func (r *Repository) ListRoles(ctx context.Context, tenantID uuid.UUID) ([]Role, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, name, description, is_system
		FROM roles
		WHERE tenant_id = $1
		ORDER BY name
	`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("query roles: %w", err)
	}
	defer rows.Close()

	var roles []Role
	for rows.Next() {
		var rl Role
		if err := rows.Scan(&rl.ID, &rl.Name, &rl.Description, &rl.IsSystem); err != nil {
			return nil, fmt.Errorf("scan role: %w", err)
		}
		roles = append(roles, rl)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return roles, nil
}

// ListUserRoles возвращает роли, назначенные конкретному пользователю в рамках тенанта.
func (r *Repository) ListUserRoles(ctx context.Context, tenantID, userID uuid.UUID) ([]Role, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT rl.id, rl.name, rl.description, rl.is_system
		FROM user_roles ur
		JOIN roles rl ON rl.id = ur.role_id
		WHERE ur.user_id = $1 AND rl.tenant_id = $2
		ORDER BY rl.name
	`, userID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("query user roles: %w", err)
	}
	defer rows.Close()

	var roles []Role
	for rows.Next() {
		var rl Role
		if err := rows.Scan(&rl.ID, &rl.Name, &rl.Description, &rl.IsSystem); err != nil {
			return nil, fmt.Errorf("scan role: %w", err)
		}
		roles = append(roles, rl)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return roles, nil
}

// AssignRole назначает роль пользователю. Явно проверяет, что и пользователь,
// и роль принадлежат заявленному tenantID — защита от IDOR (нельзя подсунуть
// чужой role_id/user_id из другого тенанта).
func (r *Repository) AssignRole(ctx context.Context, tenantID, userID, roleID, grantedBy uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `
		INSERT INTO user_roles (user_id, role_id, granted_by)
		SELECT u.id, rl.id, $3
		FROM users u, roles rl
		WHERE u.id = $1 AND u.tenant_id = $4
		  AND rl.id = $2 AND rl.tenant_id = $4
		ON CONFLICT (user_id, role_id) DO NOTHING
	`, userID, roleID, grantedBy, tenantID)
	if err != nil {
		return fmt.Errorf("assign role: %w", err)
	}

	if tag.RowsAffected() == 0 {
		// 0 строк значит либо user/role не найдены в этом тенанте, либо роль
		// уже была назначена ранее (идемпотентный случай, не ошибка).
		if _, err := r.GetUser(ctx, tenantID, userID); err != nil {
			return err
		}
		roles, err := r.ListRoles(ctx, tenantID)
		if err != nil {
			return err
		}
		found := false
		for _, rl := range roles {
			if rl.ID == roleID {
				found = true
				break
			}
		}
		if !found {
			return ErrRoleNotFound
		}
	}
	return nil
}

// RevokeRole отзывает роль у пользователя строго в рамках тенанта.
func (r *Repository) RevokeRole(ctx context.Context, tenantID, userID, roleID uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `
		DELETE FROM user_roles
		WHERE user_id = $1 AND role_id = $2
		  AND role_id IN (SELECT id FROM roles WHERE tenant_id = $3)
	`, userID, roleID, tenantID)
	if err != nil {
		return fmt.Errorf("revoke role: %w", err)
	}
	return nil
}

// RevokeAllSessions отзывает все активные refresh-токены пользователя —
// админский принудительный логаут другого пользователя (см. Handlers.RevokeSessions).
//
// Сначала проверяем принадлежность пользователя тенанту через GetUser — это даёт
// корректный 404 вместо тихого no-op на несуществующего/чужого пользователя
// и защищает от IDOR — нельзя отозвать сессии пользователя чужого тенанта,
// даже подобрав его user_id.
func (r *Repository) RevokeAllSessions(ctx context.Context, tenantID, userID uuid.UUID) error {
	if _, err := r.GetUser(ctx, tenantID, userID); err != nil {
		return err
	}

	if _, err := r.pool.Exec(ctx, `
		UPDATE refresh_tokens
		SET revoked_at = now()
		WHERE user_id = $1 AND revoked_at IS NULL
	`, userID); err != nil {
		return fmt.Errorf("revoke all sessions: %w", err)
	}
	return nil
}

// ListPermissions возвращает полный каталог доступных прав платформы.
// Права глобальны (не привязаны к tenant_id), поэтому фильтрация по тенанту не нужна.
func (r *Repository) ListPermissions(ctx context.Context) ([]Permission, error) {
	rows, err := r.pool.Query(ctx, `SELECT id, module, entity, action FROM permissions ORDER BY module, entity, action`)
	if err != nil {
		return nil, fmt.Errorf("query permissions: %w", err)
	}
	defer rows.Close()

	var permissions []Permission
	for rows.Next() {
		var p Permission
		if err := rows.Scan(&p.ID, &p.Module, &p.Entity, &p.Action); err != nil {
			return nil, fmt.Errorf("scan permission: %w", err)
		}
		permissions = append(permissions, p)
	}
	return permissions, rows.Err()
}

// CreateRole создаёт новую (не системную) роль в тенанте.
func (r *Repository) CreateRole(ctx context.Context, tenantID uuid.UUID, name, description string) (*Role, error) {
	var role Role
	err := r.pool.QueryRow(ctx, `
		INSERT INTO roles (tenant_id, name, description, is_system)
		VALUES ($1, $2, $3, false)
		RETURNING id, name, description, is_system
	`, tenantID, name, description).Scan(&role.ID, &role.Name, &role.Description, &role.IsSystem)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, ErrRoleNameTaken
		}
		return nil, fmt.Errorf("create role: %w", err)
	}
	return &role, nil
}

// DeleteRole удаляет роль. Системные роли (admin/member, is_system=true) удалить нельзя.
func (r *Repository) DeleteRole(ctx context.Context, tenantID, roleID uuid.UUID) error {
	role, err := r.getRoleInTenant(ctx, tenantID, roleID)
	if err != nil {
		return err
	}
	if role.IsSystem {
		return ErrRoleIsSystem
	}
	if _, err := r.pool.Exec(ctx, `DELETE FROM roles WHERE tenant_id = $1 AND id = $2`, tenantID, roleID); err != nil {
		return fmt.Errorf("delete role: %w", err)
	}
	return nil
}

func (r *Repository) getRoleInTenant(ctx context.Context, tenantID, roleID uuid.UUID) (*Role, error) {
	var role Role
	err := r.pool.QueryRow(ctx, `
		SELECT id, name, description, is_system FROM roles WHERE tenant_id = $1 AND id = $2
	`, tenantID, roleID).Scan(&role.ID, &role.Name, &role.Description, &role.IsSystem)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrRoleNotFound
		}
		return nil, fmt.Errorf("get role: %w", err)
	}
	return &role, nil
}

func (r *Repository) getPermissionByID(ctx context.Context, permissionID uuid.UUID) (*Permission, error) {
	var p Permission
	err := r.pool.QueryRow(ctx, `
		SELECT id, module, entity, action FROM permissions WHERE id = $1
	`, permissionID).Scan(&p.ID, &p.Module, &p.Entity, &p.Action)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrPermissionNotFound
		}
		return nil, fmt.Errorf("get permission: %w", err)
	}
	return &p, nil
}

// ListRolePermissions возвращает права, назначенные роли, строго в рамках тенанта.
func (r *Repository) ListRolePermissions(ctx context.Context, tenantID, roleID uuid.UUID) ([]Permission, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT p.id, p.module, p.entity, p.action
		FROM role_permissions rp
		JOIN permissions p ON p.id = rp.permission_id
		JOIN roles r ON r.id = rp.role_id
		WHERE rp.role_id = $1 AND r.tenant_id = $2
		ORDER BY p.module, p.entity, p.action
	`, roleID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("query role permissions: %w", err)
	}
	defer rows.Close()

	var permissions []Permission
	for rows.Next() {
		var p Permission
		if err := rows.Scan(&p.ID, &p.Module, &p.Entity, &p.Action); err != nil {
			return nil, fmt.Errorf("scan permission: %w", err)
		}
		permissions = append(permissions, p)
	}
	return permissions, rows.Err()
}

// AssignPermissionToRole назначает право роли. Проверяет принадлежность
// роли тенанту прямо в запросе (защита от IDOR). Идемпотентно.
//
// ВАЖНО: после вызова обязательно инвалидировать RBAC-кэш всех пользователей
// этой роли (Authorizer.InvalidateRoleCache) — в отличие от AssignRole, здесь
// затрагивается не один пользователь, а все носители роли.
func (r *Repository) AssignPermissionToRole(ctx context.Context, tenantID, roleID, permissionID uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `
		INSERT INTO role_permissions (role_id, permission_id)
		SELECT r.id, p.id
		FROM roles r, permissions p
		WHERE r.id = $1 AND r.tenant_id = $2 AND p.id = $3
		ON CONFLICT (role_id, permission_id) DO NOTHING
	`, roleID, tenantID, permissionID)
	if err != nil {
		return fmt.Errorf("assign permission to role: %w", err)
	}

	if tag.RowsAffected() == 0 {
		// 0 строк значит либо role/permission не найдены, либо уже назначено ранее.
		if _, err := r.getRoleInTenant(ctx, tenantID, roleID); err != nil {
			return err
		}
		if _, err := r.getPermissionByID(ctx, permissionID); err != nil {
			return err
		}
	}
	return nil
}

// RevokePermissionFromRole отзывает право у роли, строго в рамках тенанта.
// Инвалидация кэша носителей роли — ответственность вызывающего кода (Handlers).
func (r *Repository) RevokePermissionFromRole(ctx context.Context, tenantID, roleID, permissionID uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `
		DELETE FROM role_permissions
		WHERE role_id = $1 AND permission_id = $2
		  AND role_id IN (SELECT id FROM roles WHERE tenant_id = $3)
	`, roleID, permissionID, tenantID)
	if err != nil {
		return fmt.Errorf("revoke permission from role: %w", err)
	}
	return nil
}

// ListResourceGrants возвращает точечные разрешения/запреты тенанта с опциональными
// фильтрами. Интерполяция номеров плейсхолдеров безопасна — в SQL попадает только
// индекс "$N", сами значения всегда идут через args-плейсхолдеры pgx.
func (r *Repository) ListResourceGrants(ctx context.Context, tenantID uuid.UUID, filter ResourceGrantFilter) ([]ResourceGrant, error) {
	query := `
		SELECT id, user_id, module, entity, record_id, action, effect, granted_by, created_at
		FROM resource_grants
		WHERE tenant_id = $1
	`
	args := []any{tenantID}

	if filter.UserID != nil {
		args = append(args, *filter.UserID)
		query += fmt.Sprintf(" AND user_id = $%d", len(args))
	}
	if filter.Module != "" {
		args = append(args, filter.Module)
		query += fmt.Sprintf(" AND module = $%d", len(args))
	}
	if filter.Entity != "" {
		args = append(args, filter.Entity)
		query += fmt.Sprintf(" AND entity = $%d", len(args))
	}
	if filter.RecordID != nil {
		args = append(args, *filter.RecordID)
		query += fmt.Sprintf(" AND record_id = $%d", len(args))
	}
	query += " ORDER BY created_at DESC"

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query resource grants: %w", err)
	}
	defer rows.Close()

	var grants []ResourceGrant
	for rows.Next() {
		var g ResourceGrant
		if err := rows.Scan(&g.ID, &g.UserID, &g.Module, &g.Entity, &g.RecordID, &g.Action, &g.Effect, &g.GrantedBy, &g.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan resource grant: %w", err)
		}
		grants = append(grants, g)
	}
	return grants, rows.Err()
}

// CreateResourceGrant создаёт точечное разрешение/запрет. Проверяет, что user_id
// принадлежит тенанту (через GetUser — защита от IDOR). Повторное создание того же
// (tenant_id, user_id, module, entity, record_id, action) обновляет effect, а не
// падает на unique constraint — удобно для перевыпуска allow/deny.
func (r *Repository) CreateResourceGrant(ctx context.Context, tenantID uuid.UUID, g ResourceGrant, grantedBy uuid.UUID) (*ResourceGrant, error) {
	if g.Effect != "allow" && g.Effect != "deny" {
		return nil, ErrInvalidEffect
	}
	if _, err := r.GetUser(ctx, tenantID, g.UserID); err != nil {
		return nil, err
	}

	var created ResourceGrant
	err := r.pool.QueryRow(ctx, `
		INSERT INTO resource_grants (tenant_id, user_id, module, entity, record_id, action, effect, granted_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (tenant_id, user_id, module, entity, record_id, action)
		DO UPDATE SET effect = EXCLUDED.effect, granted_by = EXCLUDED.granted_by
		RETURNING id, user_id, module, entity, record_id, action, effect, granted_by, created_at
	`, tenantID, g.UserID, g.Module, g.Entity, g.RecordID, g.Action, g.Effect, grantedBy).Scan(
		&created.ID, &created.UserID, &created.Module, &created.Entity, &created.RecordID,
		&created.Action, &created.Effect, &created.GrantedBy, &created.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("create resource grant: %w", err)
	}
	return &created, nil
}

// DeleteResourceGrant удаляет точечное разрешение, строго в рамках тенанта.
func (r *Repository) DeleteResourceGrant(ctx context.Context, tenantID, grantID uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM resource_grants WHERE id = $1 AND tenant_id = $2`, grantID, tenantID)
	if err != nil {
		return fmt.Errorf("delete resource grant: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrResourceGrantNotFound
	}
	return nil
}

// isUniqueViolation проверяет, является ли ошибка нарушением UNIQUE constraint
// (Postgres SQLSTATE 23505). Аналогичный хелпер есть в authsvc — не выносили в
// общий пакет ради одной функции на два места использования.
func isUniqueViolation(err error) bool {
	var pgErr interface{ SQLState() string }
	if errors.As(err, &pgErr) {
		return pgErr.SQLState() == "23505"
	}
	return false
}
