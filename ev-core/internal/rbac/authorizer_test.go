package rbac_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"platform-core/internal/audit"
	"platform-core/internal/rbac"
)

// Интеграционные тесты: бьют в реальный Postgres+Redis (тот же принцип, что и
// чёрно-ящичные HTTP-тесты в ev-core/tests, см. tests/README.md). Это
// сознательный выбор вместо рефакторинга Authorizer на интерфейсы с моками —
// см. обсуждение в истории проекта. Каждый тест сам создаёт себе тенант,
// пользователя, роль и тестовое право с уникальным module (чтобы не задеть
// реальный каталог permissions) и чистит их за собой через t.Cleanup.

func testDatabaseURL() string {
	if v := os.Getenv("TEST_DATABASE_URL"); v != "" {
		return v
	}
	if v := os.Getenv("DATABASE_URL"); v != "" {
		return v
	}
	return "postgres://platform:platform_dev_password@localhost:5432/platform_core?sslmode=disable"
}

func testRedisAddr() string {
	if v := os.Getenv("TEST_REDIS_ADDR"); v != "" {
		return v
	}
	if v := os.Getenv("REDIS_ADDR"); v != "" {
		return v
	}
	return "localhost:6379"
}

// testEnv поднимает реальные подключения к Postgres и Redis и тестовый тенант.
// Если инфраструктура недоступна — тест помечается SKIP, а не падает (тот же
// принцип, что и в ev-core/tests).
func testEnv(t *testing.T) (pool *pgxpool.Pool, authorizer *rbac.Authorizer, tenantID uuid.UUID) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, testDatabaseURL())
	if err != nil {
		t.Skipf("postgres unavailable, skipping: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Skipf("postgres unavailable, skipping: %v", err)
	}

	redisClient := redis.NewClient(&redis.Options{Addr: testRedisAddr()})
	if err := redisClient.Ping(ctx).Err(); err != nil {
		pool.Close()
		t.Skipf("redis unavailable, skipping: %v", err)
	}

	cache := rbac.NewPermissionCache(redisClient, time.Minute)
	auditLogger := audit.NewLogger(pool)
	authorizer = rbac.NewAuthorizer(pool, cache, auditLogger)

	tenantID = uuid.New()
	_, err = pool.Exec(context.Background(), `
		INSERT INTO tenants (id, name, slug) VALUES ($1, 'rbac-test', $2)
	`, tenantID, "rbac-test-"+tenantID.String())
	if err != nil {
		pool.Close()
		redisClient.Close()
		t.Fatalf("create test tenant: %v", err)
	}

	t.Cleanup(func() {
		// ON DELETE CASCADE на users/roles подчищает всё, что от них зависит.
		pool.Exec(context.Background(), `DELETE FROM tenants WHERE id = $1`, tenantID)
		pool.Close()
		redisClient.Close()
	})

	return pool, authorizer, tenantID
}

func createTestUser(t *testing.T, pool *pgxpool.Pool, tenantID uuid.UUID) uuid.UUID {
	t.Helper()
	var userID uuid.UUID
	err := pool.QueryRow(context.Background(), `
		INSERT INTO users (tenant_id, email, is_active) VALUES ($1, $2, true) RETURNING id
	`, tenantID, uuid.NewString()+"@rbac-test.example.com").Scan(&userID)
	if err != nil {
		t.Fatalf("create test user: %v", err)
	}
	return userID
}

func createTestRole(t *testing.T, pool *pgxpool.Pool, tenantID uuid.UUID) uuid.UUID {
	t.Helper()
	var roleID uuid.UUID
	err := pool.QueryRow(context.Background(), `
		INSERT INTO roles (tenant_id, name) VALUES ($1, $2) RETURNING id
	`, tenantID, "rbac-test-role-"+uuid.NewString()[:8]).Scan(&roleID)
	if err != nil {
		t.Fatalf("create test role: %v", err)
	}
	return roleID
}

// createTestPermission создаёт право с уникальным module (рандомный суффикс),
// чтобы гарантированно не пересечься с реальным каталогом permissions платформы
// (core.user, core.role и т.д.), и удаляет его за собой в t.Cleanup.
func createTestPermission(t *testing.T, pool *pgxpool.Pool, action string) (permissionID uuid.UUID, module string) {
	t.Helper()
	module = "rbactest_" + uuid.NewString()[:8]
	err := pool.QueryRow(context.Background(), `
		INSERT INTO permissions (module, entity, action) VALUES ($1, 'widget', $2) RETURNING id
	`, module, action).Scan(&permissionID)
	if err != nil {
		t.Fatalf("create test permission: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM permissions WHERE id = $1`, permissionID)
	})
	return permissionID, module
}

func assignRoleToUser(t *testing.T, pool *pgxpool.Pool, userID, roleID uuid.UUID) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)
	`, userID, roleID); err != nil {
		t.Fatalf("assign role to user: %v", err)
	}
}

func assignPermissionToRole(t *testing.T, pool *pgxpool.Pool, roleID, permissionID uuid.UUID) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)
	`, roleID, permissionID); err != nil {
		t.Fatalf("assign permission to role: %v", err)
	}
}

func insertResourceGrant(t *testing.T, pool *pgxpool.Pool, tenantID, userID uuid.UUID, module string, recordID uuid.UUID, effect string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO resource_grants (tenant_id, user_id, module, entity, record_id, action, effect)
		VALUES ($1, $2, $3, 'widget', $4, 'read', $5)
	`, tenantID, userID, module, recordID, effect); err != nil {
		t.Fatalf("insert resource grant: %v", err)
	}
}

// Таблица истинности Authorizer.evaluate, пункт 4: нет ни ролевого права,
// ни resource_grant -> default deny.
func TestAuthorizer_DefaultDeny(t *testing.T) {
	pool, authorizer, tenantID := testEnv(t)
	userID := createTestUser(t, pool, tenantID)
	_, module := createTestPermission(t, pool, "read") // право существует, но не назначено пользователю

	decision, err := authorizer.Check(context.Background(), rbac.CheckRequest{
		TenantID: tenantID, UserID: userID, Module: module, Entity: "widget", Action: "read",
	})
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if decision.Allowed {
		t.Fatal("expected deny, got allow")
	}
	if decision.Reason != "default_deny" {
		t.Fatalf("expected reason=default_deny, got %s", decision.Reason)
	}
}

// Пункт 3: право есть в наборе ролевых прав пользователя -> allow.
func TestAuthorizer_RolePermissionAllows(t *testing.T) {
	pool, authorizer, tenantID := testEnv(t)
	userID := createTestUser(t, pool, tenantID)
	roleID := createTestRole(t, pool, tenantID)
	permissionID, module := createTestPermission(t, pool, "read")
	assignPermissionToRole(t, pool, roleID, permissionID)
	assignRoleToUser(t, pool, userID, roleID)

	decision, err := authorizer.Check(context.Background(), rbac.CheckRequest{
		TenantID: tenantID, UserID: userID, Module: module, Entity: "widget", Action: "read",
	})
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if !decision.Allowed {
		t.Fatalf("expected allow, got deny (reason=%s)", decision.Reason)
	}
	if decision.Reason != "role_permission" {
		t.Fatalf("expected reason=role_permission, got %s", decision.Reason)
	}
}

// Пункт 2: явный allow в resource_grants даёт доступ даже без роли вообще.
func TestAuthorizer_ResourceGrantAllowsWithoutRole(t *testing.T) {
	pool, authorizer, tenantID := testEnv(t)
	userID := createTestUser(t, pool, tenantID)
	_, module := createTestPermission(t, pool, "read") // роль пользователю вообще не назначена
	recordID := uuid.New()
	insertResourceGrant(t, pool, tenantID, userID, module, recordID, "allow")

	decision, err := authorizer.Check(context.Background(), rbac.CheckRequest{
		TenantID: tenantID, UserID: userID, Module: module, Entity: "widget", Action: "read", RecordID: &recordID,
	})
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if !decision.Allowed {
		t.Fatalf("expected allow via resource_grant, got deny (reason=%s)", decision.Reason)
	}
	if decision.Reason != "resource_grant_allow" {
		t.Fatalf("expected reason=resource_grant_allow, got %s", decision.Reason)
	}
}

// Пункт 1 (наивысший приоритет): явный deny в resource_grants побеждает
// даже при наличии ролевого права на этот же module/entity/action.
func TestAuthorizer_ResourceGrantDenyOverridesRolePermission(t *testing.T) {
	pool, authorizer, tenantID := testEnv(t)
	userID := createTestUser(t, pool, tenantID)
	roleID := createTestRole(t, pool, tenantID)
	permissionID, module := createTestPermission(t, pool, "read")
	assignPermissionToRole(t, pool, roleID, permissionID)
	assignRoleToUser(t, pool, userID, roleID)

	recordID := uuid.New()
	insertResourceGrant(t, pool, tenantID, userID, module, recordID, "deny")

	decision, err := authorizer.Check(context.Background(), rbac.CheckRequest{
		TenantID: tenantID, UserID: userID, Module: module, Entity: "widget", Action: "read", RecordID: &recordID,
	})
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if decision.Allowed {
		t.Fatal("expected deny: explicit resource_grant deny must override role permission")
	}
	if decision.Reason != "resource_grant_deny" {
		t.Fatalf("expected reason=resource_grant_deny, got %s", decision.Reason)
	}
}

// Точечные resource_grants применяются только к запросам с конкретным record_id —
// проверка без record_id (например, список сущностей) их не учитывает.
func TestAuthorizer_ResourceGrantDoesNotApplyWithoutRecordID(t *testing.T) {
	pool, authorizer, tenantID := testEnv(t)
	userID := createTestUser(t, pool, tenantID)
	_, module := createTestPermission(t, pool, "read")
	recordID := uuid.New()
	insertResourceGrant(t, pool, tenantID, userID, module, recordID, "allow")

	// Запрос без RecordID — resource_grant на конкретную запись не должен применяться.
	decision, err := authorizer.Check(context.Background(), rbac.CheckRequest{
		TenantID: tenantID, UserID: userID, Module: module, Entity: "widget", Action: "read",
	})
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if decision.Allowed {
		t.Fatal("expected deny: resource_grant on a specific record must not apply to a no-record-id check")
	}
	if decision.Reason != "default_deny" {
		t.Fatalf("expected reason=default_deny, got %s", decision.Reason)
	}
}

// Явная проверка эффекта кэша: InvalidateUserCache должен давать новому
// ролевому праву подействовать немедленно, не дожидаясь TTL.
func TestAuthorizer_InvalidateUserCachePicksUpNewPermission(t *testing.T) {
	pool, authorizer, tenantID := testEnv(t)
	userID := createTestUser(t, pool, tenantID)
	roleID := createTestRole(t, pool, tenantID)
	permissionID, module := createTestPermission(t, pool, "read")
	assignRoleToUser(t, pool, userID, roleID) // роль назначена, но пока без прав

	req := rbac.CheckRequest{TenantID: tenantID, UserID: userID, Module: module, Entity: "widget", Action: "read"}

	decision, err := authorizer.Check(context.Background(), req)
	if err != nil {
		t.Fatalf("check (before): %v", err)
	}
	if decision.Allowed {
		t.Fatal("expected deny before permission assigned to role")
	}

	// Назначаем право роли в обход API (напрямую в БД) и инвалидируем кэш пользователя.
	assignPermissionToRole(t, pool, roleID, permissionID)
	if err := authorizer.InvalidateUserCache(context.Background(), tenantID, userID); err != nil {
		t.Fatalf("invalidate user cache: %v", err)
	}

	decision, err = authorizer.Check(context.Background(), req)
	if err != nil {
		t.Fatalf("check (after): %v", err)
	}
	if !decision.Allowed {
		t.Fatal("expected allow after permission assigned and cache invalidated")
	}
}

// InvalidateRoleCache должен инвалидировать кэш ВСЕХ пользователей роли разом —
// именно это отличает его от InvalidateUserCache.
func TestAuthorizer_InvalidateRoleCacheAffectsAllHolders(t *testing.T) {
	pool, authorizer, tenantID := testEnv(t)
	roleID := createTestRole(t, pool, tenantID)
	permissionID, module := createTestPermission(t, pool, "read")

	userA := createTestUser(t, pool, tenantID)
	userB := createTestUser(t, pool, tenantID)
	assignRoleToUser(t, pool, userA, roleID)
	assignRoleToUser(t, pool, userB, roleID)

	reqFor := func(userID uuid.UUID) rbac.CheckRequest {
		return rbac.CheckRequest{TenantID: tenantID, UserID: userID, Module: module, Entity: "widget", Action: "read"}
	}

	// Оба пользователя без прав -> оба deny, оба решения оседают в кэше.
	for _, userID := range []uuid.UUID{userA, userB} {
		decision, err := authorizer.Check(context.Background(), reqFor(userID))
		if err != nil {
			t.Fatalf("check (before): %v", err)
		}
		if decision.Allowed {
			t.Fatalf("expected deny before permission assigned for user %s", userID)
		}
	}

	// Назначаем право роли и инвалидируем кэш роли целиком (не по одному пользователю).
	assignPermissionToRole(t, pool, roleID, permissionID)
	if err := authorizer.InvalidateRoleCache(context.Background(), tenantID, roleID); err != nil {
		t.Fatalf("invalidate role cache: %v", err)
	}

	for _, userID := range []uuid.UUID{userA, userB} {
		decision, err := authorizer.Check(context.Background(), reqFor(userID))
		if err != nil {
			t.Fatalf("check (after): %v", err)
		}
		if !decision.Allowed {
			t.Fatalf("expected allow after role cache invalidated for user %s", userID)
		}
	}
}
