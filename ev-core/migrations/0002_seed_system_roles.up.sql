-- 0002_seed_system_roles.up.sql
-- Дефолтный тенант для локальной разработки + системные роли admin/member.

INSERT INTO tenants (id, name, slug)
VALUES ('00000000-0000-0000-0000-000000000001', 'Default Tenant', 'default');

-- Базовые права ядра (модуль "core"): управление пользователями и ролями.
INSERT INTO permissions (module, entity, action) VALUES
    ('core', 'user', 'read'),
    ('core', 'user', 'write'),
    ('core', 'user', 'delete'),
    ('core', 'role', 'read'),
    ('core', 'role', 'write'),
    ('core', 'role', 'delete'),
    ('core', 'audit_log', 'read');

-- Системная роль admin — получает все существующие на момент миграции права.
-- Важно: is_system = true, чтобы её нельзя было удалить/переименовать через API.
WITH admin_role AS (
    INSERT INTO roles (tenant_id, name, description, is_system)
    VALUES ('00000000-0000-0000-0000-000000000001', 'admin', 'Полный доступ ко всей платформе', true)
    RETURNING id
)
INSERT INTO role_permissions (role_id, permission_id)
SELECT admin_role.id, permissions.id
FROM admin_role, permissions;

-- Системная роль member — без прав по умолчанию, права добавляются точечно.
INSERT INTO roles (tenant_id, name, description, is_system)
VALUES ('00000000-0000-0000-0000-000000000001', 'member', 'Базовая роль без прав по умолчанию', true);
