-- 0001_init_schema.up.sql
-- Базовая схема ядра: пользователи, роли, права, точечные разрешения, аудит.

CREATE EXTENSION IF NOT EXISTS pgcrypto; -- для gen_random_uuid()

-- Тенанты (мультитенантность закладывается с первого дня даже для MVP с одним тенантом)
CREATE TABLE tenants (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name       TEXT NOT NULL,
    slug       TEXT NOT NULL UNIQUE,
    is_active  BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email         TEXT NOT NULL,
    password_hash TEXT,              -- NULL допустим для пользователей, заведённых через будущий внешний IdP
    is_active     BOOLEAN NOT NULL DEFAULT true,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, email)
);

-- Роли (например: admin, sales_manager, support_agent)
CREATE TABLE roles (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    description TEXT,
    is_system   BOOLEAN NOT NULL DEFAULT false, -- системные роли нельзя удалить/переименовать через API
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

-- Разрешения — гранулярность "модуль.сущность:действие", общие для всех тенантов
CREATE TABLE permissions (
    id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    module TEXT NOT NULL,   -- core, crm, archive, mail, licensing
    entity TEXT NOT NULL,   -- user, role, deal, contact, document...
    action TEXT NOT NULL,   -- read, write, delete, export, approve...
    UNIQUE (module, entity, action)
);

CREATE TABLE role_permissions (
    role_id       UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE user_roles (
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id    UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    granted_by UUID REFERENCES users(id),
    granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, role_id)
);

-- Точечные разрешения/запреты на уровне конкретной записи.
-- Переопределяют ролевые права. explicit "deny" всегда побеждает "allow".
CREATE TABLE resource_grants (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    module     TEXT NOT NULL,
    entity     TEXT NOT NULL,
    record_id  UUID NOT NULL,
    action     TEXT NOT NULL,
    effect     TEXT NOT NULL CHECK (effect IN ('allow', 'deny')),
    granted_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, user_id, module, entity, record_id, action)
);

CREATE INDEX idx_resource_grants_lookup
    ON resource_grants (tenant_id, user_id, module, entity, record_id);

-- Refresh-токены хранятся в БД, чтобы их можно было отозвать (компрометация, логаут, смена пароля)
CREATE TABLE refresh_tokens (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE, -- хранится хэш, не сам токен
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_refresh_tokens_user ON refresh_tokens (user_id);

-- Аудит: кто/что/когда, включая отказы в доступе
CREATE TABLE audit_log (
    id         BIGSERIAL PRIMARY KEY,
    tenant_id  UUID NOT NULL,
    actor_id   UUID REFERENCES users(id),
    action     TEXT NOT NULL,          -- login, logout, permission_check, entity.create, ...
    module     TEXT,
    entity     TEXT,
    record_id  UUID,
    result     TEXT NOT NULL CHECK (result IN ('allowed', 'denied')),
    metadata   JSONB,
    ip_address INET,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_log_tenant_created ON audit_log (tenant_id, created_at DESC);
CREATE INDEX idx_audit_log_actor ON audit_log (actor_id, created_at DESC);
