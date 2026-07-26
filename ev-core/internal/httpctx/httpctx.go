package httpctx

import (
	"context"

	"platform-core/internal/security"
)

type key string

const claimsKey key = "claims"

// WithClaims кладёт claims аутентифицированного пользователя в контекст запроса.
func WithClaims(ctx context.Context, claims *security.Claims) context.Context {
	return context.WithValue(ctx, claimsKey, claims)
}

// ClaimsFromContext достаёт claims, положенные туда middleware Authenticate.
// Вынесено в отдельный пакет от httpserver, чтобы им мог пользоваться
// coreapi (и будущие модули CRM/архив/почта) без циклического импорта.
func ClaimsFromContext(ctx context.Context) (*security.Claims, bool) {
	claims, ok := ctx.Value(claimsKey).(*security.Claims)
	return claims, ok
}
