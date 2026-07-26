package rbac

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"platform-core/internal/audit"
)

// Authorizer — единая точка принятия решений "доступ разрешён / запрещён"
// для всей платформы. Ни один модуль не должен реализовывать свою логику
// проверки прав в обход этого компонента.
//
// Порядок вычисления решения (от высшего приоритета к низшему):
//  1. Явный "deny" в resource_grants на конкретную запись -> DENY, всегда.
//  2. Явный "allow" в resource_grants на конкретную запись -> ALLOW,
//     даже если роль не даёт доступа (точечное расширение прав).
//  3. Право есть в наборе ролевых прав пользователя -> ALLOW.
//  4. Иначе -> DENY (default deny).
//
// Каждая проверка логируется в audit_log — и разрешённые, и отклонённые.
type Authorizer struct {
	pool   *pgxpool.Pool
	cache  *PermissionCache
	audit  *audit.Logger
}

func NewAuthorizer(pool *pgxpool.Pool, cache *PermissionCache, auditLogger *audit.Logger) *Authorizer {
	return &Authorizer{pool: pool, cache: cache, audit: auditLogger}
}

// Check выполняет полную проверку доступа и пишет результат в аудит-лог.
// Ошибка возвращается только при технических сбоях (БД/кэш недоступны) —
// в этом случае вызывающий код обязан трактовать это как DENY (fail closed),
// а не пропускать запрос.
func (a *Authorizer) Check(ctx context.Context, req CheckRequest) (Decision, error) {
	decision, err := a.evaluate(ctx, req)

	result := "denied"
	if decision.Allowed {
		result = "allowed"
	}

	auditErr := a.audit.Record(ctx, audit.Entry{
		TenantID: req.TenantID,
		ActorID:  &req.UserID,
		Action:   "permission_check",
		Module:   req.Module,
		Entity:   req.Entity,
		RecordID: req.RecordID,
		Result:   result,
		Metadata: map[string]any{"action": req.Action, "reason": decision.Reason},
	})
	if auditErr != nil {
		// Не роняем запрос из-за сбоя аудита, но обязательно делаем это видимым.
		fmt.Printf("audit log write failed: %v\n", auditErr)
	}

	if err != nil {
		return Decision{Allowed: false, Reason: "evaluation_error"}, err
	}
	return decision, nil
}

func (a *Authorizer) evaluate(ctx context.Context, req CheckRequest) (Decision, error) {
	// Шаг 1-2: точечные разрешения на конкретную запись имеют наивысший приоритет.
	if req.RecordID != nil {
		effect, found, err := a.lookupResourceGrant(ctx, req)
		if err != nil {
			return Decision{}, fmt.Errorf("lookup resource grant: %w", err)
		}
		if found {
			if effect == EffectDeny {
				return Decision{Allowed: false, Reason: "resource_grant_deny"}, nil
			}
			return Decision{Allowed: true, Reason: "resource_grant_allow"}, nil
		}
	}

	// Шаг 3: проверка по ролевым правам (с кэшем).
	perms, err := a.getRolePermissions(ctx, req.TenantID, req.UserID)
	if err != nil {
		return Decision{}, fmt.Errorf("load role permissions: %w", err)
	}

	key := PermissionKey{Module: req.Module, Entity: req.Entity, Action: req.Action}.String()
	if _, ok := perms[key]; ok {
		return Decision{Allowed: true, Reason: "role_permission"}, nil
	}

	// Шаг 4: default deny.
	return Decision{Allowed: false, Reason: "default_deny"}, nil
}

func (a *Authorizer) lookupResourceGrant(ctx context.Context, req CheckRequest) (Effect, bool, error) {
	var effect string
	err := a.pool.QueryRow(ctx, `
		SELECT effect FROM resource_grants
		WHERE tenant_id = $1 AND user_id = $2 AND module = $3 AND entity = $4 AND record_id = $5 AND action = $6
	`, req.TenantID, req.UserID, req.Module, req.Entity, req.RecordID, req.Action).Scan(&effect)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", false, nil
		}
		return "", false, err
	}
	return Effect(effect), true, nil
}

func (a *Authorizer) getRolePermissions(ctx context.Context, tenantID, userID uuid.UUID) (map[string]struct{}, error) {
	if cached, ok, err := a.cache.Get(ctx, tenantID, userID); err == nil && ok {
		return cached, nil
	}

	rows, err := a.pool.Query(ctx, `
		SELECT DISTINCT p.module, p.entity, p.action
		FROM user_roles ur
		JOIN role_permissions rp ON rp.role_id = ur.role_id
		JOIN permissions p ON p.id = rp.permission_id
		JOIN roles r ON r.id = ur.role_id
		WHERE ur.user_id = $1 AND r.tenant_id = $2
	`, userID, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	perms := make(map[string]struct{})
	var permList []string
	for rows.Next() {
		var module, entity, action string
		if err := rows.Scan(&module, &entity, &action); err != nil {
			return nil, err
		}
		key := PermissionKey{Module: module, Entity: entity, Action: action}.String()
		perms[key] = struct{}{}
		permList = append(permList, key)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Кэш лучше не завести, чем упасть: ошибку записи в Redis не пробрасываем наверх.
	if err := a.cache.Set(ctx, tenantID, userID, permList); err != nil {
		fmt.Printf("rbac cache write failed: %v\n", err)
	}

	return perms, nil
}

// InvalidateUserCache должен вызываться сразу после любого изменения
// ролей пользователя (назначение/отзыв), чтобы отзыв прав действовал
// немедленно, а не по истечении TTL кэша.
func (a *Authorizer) InvalidateUserCache(ctx context.Context, tenantID, userID uuid.UUID) error {
	return a.cache.Invalidate(ctx, tenantID, userID)
}
