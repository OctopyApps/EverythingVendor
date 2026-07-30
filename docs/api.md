# API — текущие эндпоинты

Базовый URL (локально): `http://localhost:8080`

Все защищённые эндпоинты требуют заголовок:
```
Authorization: Bearer <access_token>
```

Access-токен не содержит прав — они проверяются на каждый запрос через
`Authorizer` (см. `docs/rbac.md`). Отсутствие нужного права → `403 {"error":"access_denied"}`.

---

## Health

### `GET /health`
Публичный, без аутентификации.

```bash
curl http://localhost:8080/health
```
→ `{"status":"ok"}`

---

## Аутентификация (публичные эндпоинты, без Bearer-токена)

### `POST /auth/register`
```json
{"email": "user@example.com", "password": "at-least-12-chars"}
```
→ `201 {"user_id": "<uuid>"}`

Ошибки:
- `400 {"error": "invalid email format"}` — невалидный email
- `400 {"error": "password must be at least 12 characters"}` — слишком короткий пароль
- `409 {"error": "email_taken"}` — email уже занят

Обрати внимание: для первых двух случаев код ошибки — это сырой текст
из `err.Error()` (`authsvc.ErrInvalidEmail` / `authsvc.ErrWeakPassword`),
а не стабильный машиночитаемый код вроде `email_taken`. Если фронтенд
будет сопоставлять текст ошибки с UI-сообщением — сейчас для этого
нужно матчить конкретную строку, а не enum-код. Это несоответствие
зафиксировано как технический долг в `docs/roadmap.md`.

Новый пользователь автоматически получает системную роль `member`
**без прав** — доступ выдаётся отдельно через `POST /api/core/users/{id}/roles`.

### `POST /auth/login`
```json
{"email": "user@example.com", "password": "..."}
```
→ `200 {"access_token": "...", "refresh_token": "...", "expires_in": 900, "token_type": "Bearer"}`

Ошибка при неверных данных: `401 {"error":"invalid_credentials"}` — намеренно
не различает "нет такого email" и "неверный пароль" (защита от user enumeration).

### `POST /auth/refresh`
```json
{"refresh_token": "..."}
```
→ новая пара токенов (старый refresh-токен отзывается — ротация).
Ошибка: `401 {"error":"invalid_refresh_token"}`.

### `POST /auth/logout`
```json
{"refresh_token": "..."}
```
→ `204 No Content`. Отзывает конкретный refresh-токен (логаут с одного устройства).

---

## Core API (требуют Bearer-токен + соответствующее право)

### `GET /api/core/users`
Требует `core.user:read`.

Query-параметры: `limit` (по умолчанию 20, максимум 100), `offset` (по умолчанию 0).

```bash
curl "http://localhost:8080/api/core/users?limit=10&offset=0" \
  -H "Authorization: Bearer $TOKEN"
```
→
```json
{"users": [{"id": "...", "email": "...", "is_active": true, "created_at": "..."}], "limit": 10, "offset": 0}
```

`password_hash` никогда не включается в ответ.

### `GET /api/core/users/{id}`
Требует `core.user:read`.
→ `200` объект `User` или `404 {"error":"user_not_found"}`.

### `GET /api/core/users/{id}/roles`
Требует `core.user:read`.
→ `{"roles": [{"id": "...", "name": "admin", "is_system": true}, ...]}`

### `POST /api/core/users/{id}/roles`
Требует `core.user:write`.
```json
{"role_id": "<uuid роли>"}
```
→ `204 No Content`. Идемпотентно (повторное назначение той же роли — не ошибка).
Ошибки: `404 user_not_found` / `404 role_not_found` (если `user_id`/`role_id`
не принадлежат тенанту вызывающего — защита от IDOR).

После вызова автоматически инвалидируется RBAC-кэш этого пользователя.

### `DELETE /api/core/users/{id}/roles/{role_id}`
Требует `core.user:write`.
→ `204 No Content`. Автоматически инвалидирует RBAC-кэш.

### `GET /api/core/roles`
Требует `core.role:read`.
→ `{"roles": [{"id": "...", "name": "...", "description": "...", "is_system": false}, ...]}`

---

## Сидовые данные (из миграции `0002_seed_system_roles`)

- Тенант по умолчанию: `00000000-0000-0000-0000-000000000001`
- Роль `admin` — все права модуля `core`, существовавшие на момент миграции.
- Роль `member` — без прав, назначается автоматически при регистрации.

## Пример полного сценария (curl)

```bash
# 1. Регистрация
curl -X POST http://localhost:8080/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@example.com","password":"super-secret-pass"}'

# 2. Назначить роль admin (пока только вручную через SQL, см. README.md)

# 3. Логин
TOKEN=$(curl -s -X POST http://localhost:8080/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@example.com","password":"super-secret-pass"}' | jq -r .access_token)

# 4. Список пользователей
curl http://localhost:8080/api/core/users -H "Authorization: Bearer $TOKEN"
```

## Планируемые, но ещё не реализованные эндпоинты

- Управление правами внутри ролей (`POST /api/core/roles`, `POST /api/core/roles/{id}/permissions`)
- Управление `resource_grants` (точечные allow/deny на запись)
- Любые эндпоинты будущих модулей: CRM, архив, почта, лицензии
