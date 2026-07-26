# platform-core — ядро платформы (MVP)

Ядро реализует: аутентификацию (email/пароль + JWT RS256), ролевую модель
доступа (RBAC) с точечными разрешениями на уровне записи, и сквозной аудит
всех проверок доступа. Модули (CRM, архив, почта, лицензии) в дальнейшем
подключаются к этому ядру по общему контракту `Authenticate -> RequirePermission -> handler`.

## Быстрый старт (macOS)

```bash
# 1. Поднять инфраструктуру (Postgres, Redis, NATS)
make docker-up

# 2. Сгенерировать RSA-ключи для JWT (RS256)
make gen-keys

# 3. Настроить окружение
cp .env.example .env
# при необходимости отредактировать .env

# 4. Скачать зависимости (нужен доступ в интернет — proxy.golang.org)
go mod tidy

# 5. Применить миграции
export DATABASE_URL="postgres://platform:platform_dev_password@localhost:5432/platform_core?sslmode=disable"
# установка инструмента миграций, если ещё не стоит:
#   brew install golang-migrate
make migrate-up

# 6. Экспортировать переменные окружения и запустить сервис
export $(grep -v '^#' .env | xargs)
make run
```

Сервис поднимется на `http://localhost:8080`.

## Проверка работы

```bash
# health-check
curl http://localhost:8080/health

# регистрация
curl -X POST http://localhost:8080/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@example.com","password":"super-secret-pass"}'

# логин
curl -X POST http://localhost:8080/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@example.com","password":"super-secret-pass"}'
# -> {"access_token": "...", "refresh_token": "...", "expires_in": 900, "token_type": "Bearer"}

# запрос к защищённому ресурсу — понадобится право core.user:read.
# По умолчанию свежезарегистрированный пользователь получает роль "member" без прав,
# поэтому этот запрос должен вернуть 403 (access_denied) — это и есть default deny в действии.
curl http://localhost:8080/api/core/users \
  -H "Authorization: Bearer <access_token>"
```

Чтобы выдать себе права администратора вручную для локальной разработки:

```sql
-- psql -h localhost -U platform -d platform_core
INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id
FROM users u, roles r
WHERE u.email = 'admin@example.com'
  AND r.tenant_id = '00000000-0000-0000-0000-000000000001'
  AND r.name = 'admin';
```

После этого нужно либо подождать истечения TTL кэша прав (`RBAC_CACHE_TTL_SECONDS`),
либо перезапустить сервис — в реальном API для этого будет отдельный
эндпоинт `POST /api/core/users/{id}/roles`, который сам вызывает
`Authorizer.InvalidateUserCache`.

## Архитектура прав доступа (RBAC)

Порядок вычисления решения `Authorizer.Check`:

1. Явный `deny` в `resource_grants` на конкретную запись → **DENY**, всегда побеждает.
2. Явный `allow` в `resource_grants` на конкретную запись → **ALLOW** (точечное расширение прав сверх роли).
3. Право есть в наборе ролевых прав пользователя (`roles` → `role_permissions` → `permissions`) → **ALLOW**.
4. Иначе → **DENY** (default deny).

Каждая проверка — успешная и отклонённая — пишется в `audit_log`.

Ролевые права кэшируются в Redis на `RBAC_CACHE_TTL_SECONDS` секунд и
инвалидируются явно (`Authorizer.InvalidateUserCache`) при любом изменении
ролей пользователя — TTL здесь только подстраховка, а не основной механизм.

Точечные `resource_grants` **не кэшируются** — они слишком динамичны и
проверяются напрямую в БД при каждом запросе с `record_id`.

## Security-заметки

- Пароли — **Argon2id** (m=19MiB, t=2, p=1, per OWASP), сравнение хэшей —
  константное время (`subtle.ConstantTimeCompare`).
- Login не различает "нет такого email" и "неверный пароль" в ответе
  (защита от user enumeration), плюс fake-verify при отсутствующем
  пользователе — чтобы не давать тайминг-канал.
- JWT — **RS256**, алгоритм жёстко зафиксирован при валидации
  (`jwt.WithValidMethods`), чтобы исключить atack "alg confusion" (none/HS256).
- Access-токен **не содержит списка прав** — права проверяются на каждый
  запрос через `Authorizer`, поэтому отзыв роли действует немедленно
  (в рамках TTL кэша), а не только после истечения токена.
- Refresh-токены хранятся в БД в виде SHA-256-хэша (не как plaintext),
  поддерживают отзыв и ротацию при каждом использовании.
- Все SQL-запросы — параметризованные (`$1, $2, ...` через pgx), конкатенация
  пользовательского ввода в SQL не используется нигде.
- `tenant_id` заложен во все таблицы с первого дня — заготовка под
  мультитенантность, чтобы не делать дорогой ретрофит позже.
- HTTP: таймауты на чтение/запись/idle, `TimeoutHandler` на весь роутер,
  базовые защитные заголовки (`X-Content-Type-Options`, `X-Frame-Options`,
  `Cache-Control: no-store`), лимит на размер тела запроса (1 MiB).
- `fail closed`: любая техническая ошибка при проверке прав (БД/Redis
  недоступны) трактуется как отказ в доступе, а не как пропуск запроса.

## Известные ограничения MVP (сознательно отложено)

- Тенант сейчас захардкожен (`defaultTenantID`) — полноценный onboarding
  тенантов будет в фазе 6 (мультитенантность "в полную силу").
- Нет пока эндпоинтов управления ролями/правами через API (только SQL
  вручную) — это следующий логичный кусок работы после MVP-ядра.
- Внешний OIDC-провайдер не подключён, но токены уже спроектированы на
  RS256, а сервис аутентификации спрятан за интерфейсом, готовым ко второй
  реализации без изменения остального кода.
- Rate limiting на `/auth/login` и `/auth/register` не реализован — стоит
  добавить перед выходом за пределы локальной разработки (защита от brute-force).

## Структура проекта

```
cmd/core/            — точка входа (main.go)
internal/config/     — загрузка конфигурации из окружения
internal/db/         — пул подключений к Postgres
internal/security/   — argon2id, JWT RS256
internal/rbac/        — модели, Authorizer, кэш прав
internal/audit/       — запись в audit_log
internal/authsvc/     — регистрация/логин/refresh/logout
internal/httpserver/  — роутинг, middleware (auth + RBAC), security headers
migrations/           — SQL-миграции схемы
keys/                 — RSA-ключи для JWT (генерируются локально, не в git)
```

## Важное про сеть при сборке

Проект использует внешние зависимости (`pgx`, `go-redis`, `golang-jwt`,
`golang.org/x/crypto`). Запусти `go mod tidy` на своей машине с обычным
доступом в интернет — он подтянет зависимости и создаст `go.sum`.
