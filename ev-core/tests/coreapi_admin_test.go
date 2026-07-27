package tests

import (
	"strings"
	"testing"
)

// TestCoreAPI_AdminCanManageUsersAndRoles требует прямого доступа к БД для
// bootstrap-фикстуры (назначение admin-роли, см. db.go/makeAdmin) — если БД
// недоступна, тест самостоятельно пропустится через makeAdmin.
func TestCoreAPI_AdminCanManageUsersAndRoles(t *testing.T) {
	requireServer(t)
	userID, accessToken, _ := registerAndLogin(t)
	makeAdmin(t, userID)

	t.Run("list users never leaks password_hash", func(t *testing.T) {
		resp := doRequest(t, "GET", "/api/core/users", accessToken, nil)
		if resp.Status != 200 {
			t.Fatalf("expected 200, got %d: %s", resp.Status, resp.Raw)
		}
		if strings.Contains(string(resp.Raw), "password_hash") {
			t.Fatalf("password_hash must never appear in API responses: %s", resp.Raw)
		}
	})

	t.Run("get own user", func(t *testing.T) {
		resp := doRequest(t, "GET", "/api/core/users/"+userID, accessToken, nil)
		if resp.Status != 200 {
			t.Fatalf("expected 200, got %d: %s", resp.Status, resp.Raw)
		}
		if resp.Body["email"] == nil {
			t.Fatalf("expected user object with email, got %s", resp.Raw)
		}
	})

	t.Run("get unknown user returns 404", func(t *testing.T) {
		resp := doRequest(t, "GET", "/api/core/users/00000000-0000-0000-0000-000000000099", accessToken, nil)
		if resp.Status != 404 {
			t.Fatalf("expected 404, got %d: %s", resp.Status, resp.Raw)
		}
		if resp.Body["error"] != "user_not_found" {
			t.Fatalf("expected error=user_not_found, got %s", resp.Raw)
		}
	})

	t.Run("list roles includes seeded system roles", func(t *testing.T) {
		resp := doRequest(t, "GET", "/api/core/roles", accessToken, nil)
		if resp.Status != 200 {
			t.Fatalf("expected 200, got %d: %s", resp.Status, resp.Raw)
		}
		names := roleNames(t, resp)
		if !names["admin"] || !names["member"] {
			t.Fatalf("expected seeded roles admin/member in list, got %s", resp.Raw)
		}
	})

	t.Run("assign, re-assign and revoke role on another user", func(t *testing.T) {
		targetID, _ := registerUser(t)
		memberRoleID := findRoleID(t, accessToken, "member")

		assignResp := doRequest(t, "POST", "/api/core/users/"+targetID+"/roles", accessToken, map[string]string{
			"role_id": memberRoleID,
		})
		if assignResp.Status != 204 {
			t.Fatalf("expected 204, got %d: %s", assignResp.Status, assignResp.Raw)
		}

		// Идемпотентность: повторное назначение той же роли — не ошибка (см. docs/api.md).
		assignAgainResp := doRequest(t, "POST", "/api/core/users/"+targetID+"/roles", accessToken, map[string]string{
			"role_id": memberRoleID,
		})
		if assignAgainResp.Status != 204 {
			t.Fatalf("expected 204 on repeat assignment, got %d: %s", assignAgainResp.Status, assignAgainResp.Raw)
		}

		rolesOfUser := doRequest(t, "GET", "/api/core/users/"+targetID+"/roles", accessToken, nil)
		if rolesOfUser.Status != 200 {
			t.Fatalf("expected 200, got %d: %s", rolesOfUser.Status, rolesOfUser.Raw)
		}
		if !roleNames(t, rolesOfUser)["member"] {
			t.Fatalf("expected target user to have role member, got %s", rolesOfUser.Raw)
		}

		revokeResp := doRequest(t, "DELETE", "/api/core/users/"+targetID+"/roles/"+memberRoleID, accessToken, nil)
		if revokeResp.Status != 204 {
			t.Fatalf("expected 204, got %d: %s", revokeResp.Status, revokeResp.Raw)
		}

		rolesAfterRevoke := doRequest(t, "GET", "/api/core/users/"+targetID+"/roles", accessToken, nil)
		if roleNames(t, rolesAfterRevoke)["member"] {
			t.Fatalf("expected role to be revoked, got %s", rolesAfterRevoke.Raw)
		}
	})

	t.Run("assign role rejects unknown role_id", func(t *testing.T) {
		targetID, _ := registerUser(t)
		resp := doRequest(t, "POST", "/api/core/users/"+targetID+"/roles", accessToken, map[string]string{
			"role_id": "00000000-0000-0000-0000-000000000099",
		})
		if resp.Status != 404 {
			t.Fatalf("expected 404 role_not_found, got %d: %s", resp.Status, resp.Raw)
		}
	})
}

// roleNames извлекает множество имён ролей из ответа вида {"roles":[{"name":"admin",...}]}.
func roleNames(t *testing.T, resp apiResponse) map[string]bool {
	t.Helper()
	names := map[string]bool{}
	roles, _ := resp.Body["roles"].([]any)
	for _, r := range roles {
		m, ok := r.(map[string]any)
		if !ok {
			continue
		}
		if name, ok := m["name"].(string); ok {
			names[name] = true
		}
	}
	return names
}

// findRoleID ищет id роли по имени через GET /api/core/roles.
func findRoleID(t *testing.T, accessToken, name string) string {
	t.Helper()
	resp := doRequest(t, "GET", "/api/core/roles", accessToken, nil)
	if resp.Status != 200 {
		t.Fatalf("list roles failed: status=%d body=%s", resp.Status, resp.Raw)
	}
	roles, _ := resp.Body["roles"].([]any)
	for _, r := range roles {
		m, ok := r.(map[string]any)
		if !ok {
			continue
		}
		if m["name"] == name {
			id, _ := m["id"].(string)
			return id
		}
	}
	t.Fatalf("role %q not found among seeded roles: %s", name, resp.Raw)
	return ""
}
