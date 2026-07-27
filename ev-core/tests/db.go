package tests

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// defaultTenantID — сидовый тенант для локальной разработки (см. migrations/0002_seed_system_roles.up.sql).
const defaultTenantID = "00000000-0000-0000-0000-000000000001"

// makeAdmin напрямую через SQL назначает пользователю системную роль admin.
//
// Управление ролями через API сейчас доступно только пользователю с правом
// core.user:write — то есть уже существующему admin'у. Для тестов, которые
// сами являются "первым admin", это делается через прямой SQL, в обход API
// (см. docs/rbac.md, раздел "Известные ограничения текущей реализации").
func makeAdmin(t *testing.T, userID string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, databaseURL())
	if err != nil {
		t.Skipf("не удалось создать пул подключений к БД (%v) — см. tests/README.md", err)
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		t.Skipf("БД недоступна по %s (%v) — см. tests/README.md", databaseURL(), err)
	}

	_, err = pool.Exec(ctx, `
		INSERT INTO user_roles (user_id, role_id)
		SELECT $1, r.id
		FROM roles r
		WHERE r.tenant_id = $2 AND r.name = 'admin'
		ON CONFLICT (user_id, role_id) DO NOTHING
	`, userID, defaultTenantID)
	if err != nil {
		t.Fatalf("assign admin role via SQL: %v", err)
	}
}
