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
