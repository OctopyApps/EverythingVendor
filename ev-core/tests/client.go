package tests

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"
)

var httpClient = &http.Client{Timeout: 10 * time.Second}

// apiResponse — унифицированный результат вызова API для удобных проверок в тестах.
type apiResponse struct {
	Status int
	Header http.Header
	Body   map[string]any
	Raw    []byte
}

// requireServer пропускает тест, если API недоступен по baseURL() — так тесты
// можно гонять локально без падения всего пакета, если инфраструктура не поднята.
func requireServer(t *testing.T) {
	t.Helper()
	resp, err := httpClient.Get(baseURL() + "/health")
	if err != nil {
		t.Skipf("API недоступен по %s (%v) — подними сервер: см. tests/README.md", baseURL(), err)
	}
	_ = resp.Body.Close()
}

// doRequest выполняет HTTP-запрос к тестируемому API и декодирует JSON-ответ (если есть).
func doRequest(t *testing.T, method, path, token string, body any) apiResponse {
	t.Helper()

	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal request body: %v", err)
		}
		reader = bytes.NewReader(raw)
	}

	req, err := http.NewRequest(method, baseURL()+path, reader)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("request %s %s failed: %v", method, path, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}

	result := apiResponse{Status: resp.StatusCode, Header: resp.Header, Raw: raw}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &result.Body) // не все ответы — JSON-объекты (например 204 без тела)
	}
	return result
}
