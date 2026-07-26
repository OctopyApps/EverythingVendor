package httpserver

import (
	"net/http"
	"strings"

	"github.com/google/uuid"

	"platform-core/internal/httpctx"
	"platform-core/internal/rbac"
	"platform-core/internal/security"
)

// Authenticate проверяет Bearer JWT и кладёт claims в контекст запроса.
// Отсутствие/невалидность токена -> 401, дальше запрос не идёт.
func Authenticate(tokens *security.TokenManager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if !strings.HasPrefix(authHeader, "Bearer ") {
				writeError(w, http.StatusUnauthorized, "missing_bearer_token")
				return
			}
			tokenString := strings.TrimPrefix(authHeader, "Bearer ")

			claims, err := tokens.ValidateAccessToken(tokenString)
			if err != nil {
				writeError(w, http.StatusUnauthorized, "invalid_token")
				return
			}

			ctx := httpctx.WithClaims(r.Context(), claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RecordIDExtractor достаёт ID конкретной записи из запроса, когда проверка
// должна учитывать точечные resource_grants на конкретную запись.
type RecordIDExtractor func(r *http.Request) (*uuid.UUID, error)

// NoRecordID — извлекатель для маршрутов без привязки к конкретной записи
// (например, список сущностей или их создание).
func NoRecordID(r *http.Request) (*uuid.UUID, error) { return nil, nil }

// PathUUIDExtractor читает UUID записи из параметра пути (net/http ServeMux, r.PathValue).
// Общий helper для всех будущих модулей, не только core.
func PathUUIDExtractor(paramName string) RecordIDExtractor {
	return func(r *http.Request) (*uuid.UUID, error) {
		raw := r.PathValue(paramName)
		if raw == "" {
			return nil, nil
		}
		id, err := uuid.Parse(raw)
		if err != nil {
			return nil, err
		}
		return &id, nil
	}
}

// RequirePermission — middleware, вызывающий Authorizer.Check для текущего
// пользователя. Fail closed: любая техническая ошибка проверки -> 403.
func RequirePermission(authorizer *rbac.Authorizer, module, entity, action string, extractRecordID RecordIDExtractor) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := httpctx.ClaimsFromContext(r.Context())
			if !ok {
				writeError(w, http.StatusUnauthorized, "missing_claims")
				return
			}

			recordID, err := extractRecordID(r)
			if err != nil {
				writeError(w, http.StatusBadRequest, "invalid_record_id")
				return
			}

			decision, err := authorizer.Check(r.Context(), rbac.CheckRequest{
				TenantID: claims.TenantID,
				UserID:   claims.UserID,
				Module:   module,
				Entity:   entity,
				Action:   action,
				RecordID: recordID,
			})
			if err != nil || !decision.Allowed {
				// fail closed: ошибка проверки трактуется как отказ, не как пропуск.
				writeError(w, http.StatusForbidden, "access_denied")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func writeError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"error":"` + code + `"}`))
}
