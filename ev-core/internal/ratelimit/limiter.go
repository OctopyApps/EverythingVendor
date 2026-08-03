package ratelimit

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
)

// FailMode определяет поведение лимитера, если Redis недоступен.
// В отличие от RBAC (см. internal/rbac), rate limiting осознанно допускает
// настраиваемое fail-open поведение: недоступность Redis не должна
// становиться отдельным DoS ("никто не может залогиниться, потому что упал
// кэш"). Выбор между open/closed — конфигурируемый (RATE_LIMIT_FAIL_MODE),
// а не зашитый в код, чтобы можно было ужесточить политику без пересборки.
type FailMode string

const (
	FailOpen   FailMode = "open"   // Redis недоступен -> пропустить запрос
	FailClosed FailMode = "closed" // Redis недоступен -> отклонить запрос
)

// Limiter — простой fixed-window rate limiter поверх Redis (INCR + EXPIRE).
// Fixed window допускает всплеск до ~2x лимита на стыке окон — для защиты от
// брутфорса этого достаточно, и это заметно проще и дешевле sliding window.
type Limiter struct {
	client   *redis.Client
	failMode FailMode
}

func NewLimiter(client *redis.Client, failMode FailMode) *Limiter {
	if failMode != FailOpen && failMode != FailClosed {
		failMode = FailOpen
	}
	return &Limiter{client: client, failMode: failMode}
}

// Result — результат проверки лимита.
type Result struct {
	Allowed    bool
	RetryAfter time.Duration
}

// Allow проверяет и увеличивает счётчик для ключа bucket в пределах окна window.
// limit — максимально допустимое количество запросов за window.
//
// При ошибке обращения к Redis поведение определяется настроенным FailMode:
// FailOpen -> Allowed=true (залогировать и пропустить), FailClosed -> Allowed=false.
func (l *Limiter) Allow(ctx context.Context, bucket string, limit int, window time.Duration) Result {
	key := fmt.Sprintf("ratelimit:%s", bucket)

	count, err := l.client.Incr(ctx, key).Result()
	if err != nil {
		slog.Error("rate limiter: redis incr failed", "error", err, "bucket", bucket, "fail_mode", l.failMode)
		return Result{Allowed: l.failMode == FailOpen}
	}

	if count == 1 {
		// Первый запрос в новом окне — выставляем TTL. Небольшая гонка при
		// параллельных первых запросах не критична: TTL просто выставится
		// повторно с тем же значением window.
		if err := l.client.Expire(ctx, key, window).Err(); err != nil {
			slog.Error("rate limiter: redis expire failed", "error", err, "bucket", bucket)
		}
	}

	if count > int64(limit) {
		ttl, ttlErr := l.client.TTL(ctx, key).Result()
		if ttlErr != nil || ttl < 0 {
			ttl = window
		}
		return Result{Allowed: false, RetryAfter: ttl}
	}

	return Result{Allowed: true}
}
