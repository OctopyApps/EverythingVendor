package tests

import "testing"

func TestCoreAPI_RequiresBearerToken(t *testing.T) {
	requireServer(t)

	resp := doRequest(t, "GET", "/api/core/users", "", nil)
	if resp.Status != 401 {
		t.Fatalf("expected 401 without token, got %d: %s", resp.Status, resp.Raw)
	}
}

func TestCoreAPI_InvalidTokenRejected(t *testing.T) {
	requireServer(t)

	resp := doRequest(t, "GET", "/api/core/users", "not-a-real-jwt", nil)
	if resp.Status != 401 {
		t.Fatalf("expected 401 for garbage token, got %d: %s", resp.Status, resp.Raw)
	}
}

// TestCoreAPI_MemberHasNoPermissions проверяет default deny: свежий пользователь
// получает системную роль member без единого права (см. docs/rbac.md).
func TestCoreAPI_MemberHasNoPermissions(t *testing.T) {
	requireServer(t)
	_, accessToken, _ := registerAndLogin(t)

	cases := []struct {
		name   string
		method string
		path   string
	}{
		{"list users", "GET", "/api/core/users"},
		{"list roles", "GET", "/api/core/roles"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := doRequest(t, tc.method, tc.path, accessToken, nil)
			if resp.Status != 403 {
				t.Fatalf("expected 403 access_denied for member, got %d: %s", resp.Status, resp.Raw)
			}
			if resp.Body["error"] != "access_denied" {
				t.Fatalf("expected error=access_denied, got %s", resp.Raw)
			}
		})
	}
}
