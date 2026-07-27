package tests

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
)

func TestRegister_Success(t *testing.T) {
	requireServer(t)

	userID, _ := registerUser(t)
	if _, err := uuid.Parse(userID); err != nil {
		t.Fatalf("user_id is not a valid uuid: %s", userID)
	}
}

func TestRegister_DuplicateEmail(t *testing.T) {
	requireServer(t)
	_, email := registerUser(t)

	resp := doRequest(t, "POST", "/auth/register", "", map[string]string{
		"email":    email,
		"password": testPassword,
	})
	if resp.Status != 409 {
		t.Fatalf("expected 409 email_taken, got %d: %s", resp.Status, resp.Raw)
	}
	if resp.Body["error"] != "email_taken" {
		t.Fatalf("expected error=email_taken, got %s", resp.Raw)
	}
}

func TestRegister_InvalidEmail(t *testing.T) {
	requireServer(t)

	resp := doRequest(t, "POST", "/auth/register", "", map[string]string{
		"email":    "not-an-email",
		"password": testPassword,
	})
	if resp.Status != 400 {
		t.Fatalf("expected 400, got %d: %s", resp.Status, resp.Raw)
	}
	// authsvc.writeAuthError отдаёт err.Error() как есть для ErrInvalidEmail/ErrWeakPassword —
	// это расходится с кодом "invalid_email" из docs/api.md, но так ведёт себя код сейчас.
	if resp.Body["error"] != "invalid email format" {
		t.Fatalf("expected error='invalid email format', got %s", resp.Raw)
	}
}

func TestRegister_WeakPassword(t *testing.T) {
	requireServer(t)

	resp := doRequest(t, "POST", "/auth/register", "", map[string]string{
		"email":    fmt.Sprintf("test-%s@example.com", uuid.NewString()),
		"password": "short",
	})
	if resp.Status != 400 {
		t.Fatalf("expected 400, got %d: %s", resp.Status, resp.Raw)
	}
}

func TestLogin_WrongPassword(t *testing.T) {
	requireServer(t)
	_, email := registerUser(t)

	resp := doRequest(t, "POST", "/auth/login", "", map[string]string{
		"email":    email,
		"password": "wrong-password-123",
	})
	if resp.Status != 401 {
		t.Fatalf("expected 401, got %d: %s", resp.Status, resp.Raw)
	}
	if resp.Body["error"] != "invalid_credentials" {
		t.Fatalf("expected error=invalid_credentials, got %s", resp.Raw)
	}
}

func TestLogin_UnknownEmail(t *testing.T) {
	requireServer(t)

	// Ответ должен совпадать с ответом на "неверный пароль" — защита от
	// user enumeration (см. docs/security.md).
	resp := doRequest(t, "POST", "/auth/login", "", map[string]string{
		"email":    fmt.Sprintf("no-such-user-%s@example.com", uuid.NewString()),
		"password": testPassword,
	})
	if resp.Status != 401 {
		t.Fatalf("expected 401, got %d: %s", resp.Status, resp.Raw)
	}
	if resp.Body["error"] != "invalid_credentials" {
		t.Fatalf("expected error=invalid_credentials, got %s", resp.Raw)
	}
}

func TestRefresh_RotationAndReuseDetection(t *testing.T) {
	requireServer(t)
	_, _, refreshToken := registerAndLogin(t)

	// Первое обновление — успешно, старый refresh-токен отзывается.
	resp := doRequest(t, "POST", "/auth/refresh", "", map[string]string{"refresh_token": refreshToken})
	if resp.Status != 200 {
		t.Fatalf("expected 200, got %d: %s", resp.Status, resp.Raw)
	}
	newRefreshToken, _ := resp.Body["refresh_token"].(string)
	if newRefreshToken == "" || newRefreshToken == refreshToken {
		t.Fatalf("expected a new, different refresh_token, got %q", newRefreshToken)
	}

	// Повторное использование старого (уже отозванного) refresh-токена должно быть отклонено.
	reuseResp := doRequest(t, "POST", "/auth/refresh", "", map[string]string{"refresh_token": refreshToken})
	if reuseResp.Status != 401 {
		t.Fatalf("expected 401 on reused refresh_token, got %d: %s", reuseResp.Status, reuseResp.Raw)
	}
	if reuseResp.Body["error"] != "invalid_refresh_token" {
		t.Fatalf("expected error=invalid_refresh_token, got %s", reuseResp.Raw)
	}
}

func TestLogout_RevokesRefreshToken(t *testing.T) {
	requireServer(t)
	_, _, refreshToken := registerAndLogin(t)

	resp := doRequest(t, "POST", "/auth/logout", "", map[string]string{"refresh_token": refreshToken})
	if resp.Status != 204 {
		t.Fatalf("expected 204, got %d: %s", resp.Status, resp.Raw)
	}

	// Токен уже отозван — попытка обновиться им должна провалиться.
	reuseResp := doRequest(t, "POST", "/auth/refresh", "", map[string]string{"refresh_token": refreshToken})
	if reuseResp.Status != 401 {
		t.Fatalf("expected 401 after logout, got %d: %s", reuseResp.Status, reuseResp.Raw)
	}
}
