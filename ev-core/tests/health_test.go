package tests

import "testing"

func TestHealth(t *testing.T) {
	requireServer(t)

	resp := doRequest(t, "GET", "/health", "", nil)
	if resp.Status != 200 {
		t.Fatalf("expected 200, got %d: %s", resp.Status, resp.Raw)
	}
	if resp.Body["status"] != "ok" {
		t.Fatalf(`expected {"status":"ok"}, got %s`, resp.Raw)
	}
}
