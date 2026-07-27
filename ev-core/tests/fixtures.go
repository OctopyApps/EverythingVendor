package tests

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
)

// testPassword — фиксированный пароль для тестовых пользователей, длиннее
// минимально допустимых 12 символов (см. docs/security.md).
const testPassword = "TestPassw0rd123"

// registerUser регистрирует нового пользователя со случайным email и
// возвращает его ID. Уникальность email не требует очистки БД между запусками.
func registerUser(t *testing.T) (userID, email string) {
	t.Helper()
	email = fmt.Sprintf("test-%s@example.com", uuid.NewString())

	resp := doRequest(t, "POST", "/auth/register", "", map[string]string{
		"email":    email,
		"password": testPassword,
	})
	if resp.Status != 201 {
		t.Fatalf("register failed: status=%d body=%s", resp.Status, resp.Raw)
	}

	id, _ := resp.Body["user_id"].(string)
	if id == "" {
		t.Fatalf("register response missing user_id: %s", resp.Raw)
	}
	return id, email
}

// loginUser логинит пользователя и возвращает пару access/refresh токенов.
func loginUser(t *testing.T, email, password string) (accessToken, refreshToken string) {
	t.Helper()

	resp := doRequest(t, "POST", "/auth/login", "", map[string]string{
		"email":    email,
		"password": password,
	})
	if resp.Status != 200 {
		t.Fatalf("login failed: status=%d body=%s", resp.Status, resp.Raw)
	}

	accessToken, _ = resp.Body["access_token"].(string)
	refreshToken, _ = resp.Body["refresh_token"].(string)
	if accessToken == "" || refreshToken == "" {
		t.Fatalf("login response missing tokens: %s", resp.Raw)
	}
	return accessToken, refreshToken
}

// registerAndLogin — комбинированный helper для тестов, которым просто нужен
// свежий аутентифицированный пользователь без прав (роль member по умолчанию).
func registerAndLogin(t *testing.T) (userID, accessToken, refreshToken string) {
	t.Helper()
	userID, email := registerUser(t)
	accessToken, refreshToken = loginUser(t, email, testPassword)
	return
}
