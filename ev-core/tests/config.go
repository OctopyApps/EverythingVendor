package tests

import "os"

// baseURL — адрес запущенного API. Переопределяется переменной окружения
// BASE_URL, по умолчанию — локальный запуск через `make run`.
func baseURL() string {
	if v := os.Getenv("BASE_URL"); v != "" {
		return v
	}
	return "http://localhost:8080"
}

// databaseURL — прямое подключение к Postgres для тестовых фикстур
// (например, назначение admin-роли в обход API, см. db.go).
// По умолчанию совпадает с ev-core/.env.example.
func databaseURL() string {
	if v := os.Getenv("TEST_DATABASE_URL"); v != "" {
		return v
	}
	if v := os.Getenv("DATABASE_URL"); v != "" {
		return v
	}
	return "postgres://platform:platform_dev_password@localhost:5432/platform_core?sslmode=disable"
}
