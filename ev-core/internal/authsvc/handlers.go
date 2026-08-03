package authsvc

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/google/uuid"

	"platform-core/internal/httpctx"
)

// defaultTenantID — тенант для MVP. Когда появится multi-tenant onboarding,
// tenant будет определяться по поддомену/заголовку, а не хардкодиться.
var defaultTenantID = uuid.MustParse("00000000-0000-0000-0000-000000000001")

type Handlers struct {
	svc *Service
}

func NewHandlers(svc *Service) *Handlers {
	return &Handlers{svc: svc}
}

type registerRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type authResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

func (h *Handlers) Register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	userID, err := h.svc.Register(r.Context(), defaultTenantID, req.Email, req.Password)
	if err != nil {
		writeAuthError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{"user_id": userID.String()})
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (h *Handlers) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	result, err := h.svc.Login(r.Context(), defaultTenantID, req.Email, req.Password)
	if err != nil {
		writeAuthError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, authResponse{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		ExpiresIn:    result.ExpiresIn,
		TokenType:    "Bearer",
	})
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func (h *Handlers) Refresh(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	result, err := h.svc.Refresh(r.Context(), req.RefreshToken)
	if err != nil {
		writeAuthError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, authResponse{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		ExpiresIn:    result.ExpiresIn,
		TokenType:    "Bearer",
	})
}

func (h *Handlers) Logout(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := h.svc.Logout(r.Context(), req.RefreshToken); err != nil {
		slog.Error("logout failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// LogoutAll отзывает все refresh-токены текущего аутентифицированного пользователя
// — самообслуживание, требует только валидный access-токен (без отдельных
// прав через RBAC — отзыв своих же сессий не требует отдельного разрешения).
// Подключается в httpserver через Authenticate middleware, как и остальные
// защищённые эндпоинты.
func (h *Handlers) LogoutAll(w http.ResponseWriter, r *http.Request) {
	claims, ok := httpctx.ClaimsFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing_claims"})
		return
	}

	if err := h.svc.RevokeAllRefreshTokens(r.Context(), claims.UserID); err != nil {
		slog.Error("logout-all failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	defer r.Body.Close()
	// Ограничиваем размер тела запроса, чтобы избежать DoS через огромный payload.
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MiB
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request_body"})
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		slog.Error("failed to write json response", "error", err)
	}
}

func writeAuthError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrInvalidCredentials), errors.Is(err, ErrUserInactive):
		// Одинаковый статус и сообщение для разных внутренних причин —
		// намеренно, чтобы не раскрывать детали (user enumeration).
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_credentials"})
	case errors.Is(err, ErrEmailTaken):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "email_taken"})
	case errors.Is(err, ErrInvalidEmail):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_email"})
	case errors.Is(err, ErrWeakPassword):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "weak_password"})
	case errors.Is(err, ErrTokenInvalid):
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_refresh_token"})
	case errors.Is(err, ErrTooManyAttempts):
		// Без Retry-After здесь: в отличие от httpserver.RateLimitByIP, Service.Login
		// не возвращает оставшееся время окна наружу через ratelimit.Result.
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate_limit_exceeded"})
	default:
		slog.Error("auth handler internal error", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
	}
}
