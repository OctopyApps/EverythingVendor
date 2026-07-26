package rbac

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// PermissionCache кэширует вычисленный набор ролевых прав пользователя
// ("module.entity:action" -> присутствует/нет), чтобы не ходить в Postgres
// с JOIN'ом на каждый запрос. Кэш инвалидируется явно при изменении ролей
// пользователя и всегда имеет короткий TTL как страховку (RBAC_CACHE_TTL_SECONDS).
//
// ВАЖНО: в кэше хранятся только ролевые (не точечные resource_grants) права —
// точечные разрешения слишком динамичны и всегда проверяются напрямую в БД.
type PermissionCache struct {
	client *redis.Client
	ttl    time.Duration
}

func NewPermissionCache(client *redis.Client, ttl time.Duration) *PermissionCache {
	return &PermissionCache{client: client, ttl: ttl}
}

func cacheKey(tenantID, userID uuid.UUID) string {
	return fmt.Sprintf("rbac:perms:%s:%s", tenantID, userID)
}

func (c *PermissionCache) Get(ctx context.Context, tenantID, userID uuid.UUID) (map[string]struct{}, bool, error) {
	raw, err := c.client.Get(ctx, cacheKey(tenantID, userID)).Bytes()
	if err == redis.Nil {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	var perms []string
	if err := json.Unmarshal(raw, &perms); err != nil {
		return nil, false, err
	}
	set := make(map[string]struct{}, len(perms))
	for _, p := range perms {
		set[p] = struct{}{}
	}
	return set, true, nil
}

func (c *PermissionCache) Set(ctx context.Context, tenantID, userID uuid.UUID, perms []string) error {
	raw, err := json.Marshal(perms)
	if err != nil {
		return err
	}
	return c.client.Set(ctx, cacheKey(tenantID, userID), raw, c.ttl).Err()
}

// Invalidate сбрасывает кэш прав пользователя. Обязательно вызывать
// сразу после изменения его ролей (назначение/отзыв), чтобы не ждать
// истечения TTL для применения нового набора прав.
func (c *PermissionCache) Invalidate(ctx context.Context, tenantID, userID uuid.UUID) error {
	return c.client.Del(ctx, cacheKey(tenantID, userID)).Err()
}
