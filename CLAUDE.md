# CLAUDE.md — контекст проекта для Claude Code

Этот файл — точка входа для продолжения работы над проектом в Claude Code.
Подробности вынесены в `docs/` — см. ссылки ниже.

## Что это за проект

`platform-core` — ядро единой корпоративной платформы вендора ПО
(CRM + цифровой архив с LLM + почтовый модуль + выдача дистрибутивов).
Полная бизнес- и архитектурная концепция: **`docs/architecture.md`**.

Сейчас в разработке: **Фаза 0 — фундамент (ядро)**: аутентификация, RBAC,
аудит. Модули (CRM и т.д.) ещё не начаты.

## Технологии

- **Go 1.23+** — весь текущий код ядра.
- **PostgreSQL** (pgx/v5, без ORM, только raw SQL с плейсхолдерами).
- **Redis** (go-redis/v9) — кэш вычисленных ролевых прав.
- **NATS JetStream** — поднят в docker-compose, но пока не интегрирован в код
  (появится вместе с первым модулем, который будет публиковать/слушать события).
- JWT **RS256** (golang-jwt/v5), пароли — **argon2id** (golang.org/x/crypto).
- Frontend пока не начат (браузерный SPA, см. architecture.md).

## Структура репозитория

```
cmd/core/             — main.go, точка входа
internal/config/      — конфигурация из env
internal/db/           — пул pgxpool
internal/security/     — argon2id, JWT RS256
internal/rbac/          — Authorizer, PermissionCache, модели прав
internal/audit/         — запись в audit_log
internal/authsvc/       — регистрация/логин/refresh/logout
internal/httpctx/       — claims в context.Context (общий для httpserver и coreapi)
internal/coreapi/       — CRUD-эндпоинты ядра: users, roles, назначение ролей
internal/httpserver/    — роутинг (net/http ServeMux), middleware (auth + RBAC), security headers
migrations/             — SQL-миграции (golang-migrate)
keys/                   — RSA-ключи JWT (генерируются локально, в git не попадают)
docs/                   — вся остальная документация
```

## Как собрать и запустить

```bash
make docker-up          # Postgres, Redis, NATS
make gen-keys            # RSA-ключи для JWT
cp .env.example .env
go mod tidy
export DATABASE_URL="postgres://platform:platform_dev_password@localhost:5432/platform_core?sslmode=disable"
make migrate-up
export $(grep -v '^#' .env | xargs)
make run
```

Подробный список текущих эндпоинтов с примерами curl — **`docs/api.md`**.

## Критичные инварианты (не нарушать при доработке)

Эти правила — не стилистические предпочтения, а осознанные security-решения.
Если правка выглядит так, будто их нужно нарушить — стоит сначала перечитать
**`docs/security.md`**, а не менять инвариант.

1. **Default deny.** Нет явного разрешения — нет доступа. Никаких "allow all except".
2. **Explicit deny в `resource_grants` побеждает всё.** Порядок вычисления решения
   в `Authorizer.evaluate` менять только осознанно — см. `docs/rbac.md`.
3. **Fail closed.** Любая техническая ошибка при проверке прав (БД/Redis
   недоступны) = отказ в доступе, никогда не пропуск запроса.
4. **`tenant_id` в каждом запросе.** Любой новый SQL-запрос к сущностям обязан
   фильтроваться по `tenant_id` — не полагаться на то, что "и так один тенант".
   Это защита от IDOR и заготовка под мультитенантность (см. architecture.md, §3.4).
5. **Только параметризованные SQL-запросы** (`$1, $2, ...` через pgx). Конкатенация
   пользовательского ввода в SQL запрещена без исключений.
6. **password_hash никогда не попадает в API-ответы.** Проверяй SELECT-запросы
   в новых репозиториях/хендлерах.
7. **JWT не хранит permissions.** Права проверяются на каждый запрос через
   `Authorizer`, а не читаются из токена — это даёт мгновенный отзыв доступа
   (в рамках TTL кэша), а не только после истечения токена.
8. **Инвалидация RBAC-кэша обязательна** после любого изменения ролей
   пользователя (`Authorizer.InvalidateUserCache`) — не полагаться только на TTL.
9. **Комментарии в коде — на русском**, идентификаторы — на английском
   (сложившийся стиль проекта, сохранять для консистентности).

## Текущий статус / что уже готово

Подробный чеклист и план по фазам — **`docs/roadmap.md`**. Коротко:

- ✅ Auth: регистрация, логин, refresh (с ротацией), logout.
- ✅ RBAC: `Authorizer` (default deny, explicit deny, кэш в Redis), схема БД.
- ✅ Аудит: все проверки прав (allowed/denied) пишутся в `audit_log`.
- ✅ Core API: список/получение пользователей, список ролей, назначение/отзыв ролей.
- ⬜ Rate limiting на `/auth/login` и `/auth/register` (защита от brute-force) — **следующее в очереди**.
- ⬜ Модуль CRM (Фаза 1) — не начат.
- ⬜ NATS event bus — поднят инфраструктурно, код публикации/подписки не написан.
- ⬜ Тесты — пока нет ни одного (ни unit, ни integration).

## Известные сознательные упрощения MVP

- Тенант захардкожен (`defaultTenantID` в `authsvc/handlers.go`) — полноценный
  onboarding тенантов в Фазе 6.
- Нет внешнего OIDC-провайдера — но `TokenManager` спроектирован на RS256
  специально, чтобы миграция была дешёвой (см. `docs/security.md`).

## Куда смотреть дальше

- Общая бизнес- и техническая архитектура платформы → `docs/architecture.md`
- Как устроен и почему именно так RBAC → `docs/rbac.md`
- Полный справочник текущих API-эндпоинтов → `docs/api.md`
- Security-решения и их обоснование → `docs/security.md`
- Пошаговый план разработки по фазам → `docs/roadmap.md`
