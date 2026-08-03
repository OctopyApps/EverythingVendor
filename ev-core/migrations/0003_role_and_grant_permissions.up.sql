-- 0003_role_and_grant_permissions.up.sql
-- Права для просмотра каталога прав и управления точечными resource_grants.

INSERT INTO permissions (module, entity, action) VALUES
    ('core', 'permission', 'read'),
    ('core', 'resource_grant', 'read'),
    ('core', 'resource_grant', 'write');

-- 0002 назначал admin-роли только права, существовавшие на момент той миграции —
-- новые права нужно явно назначать в каждой следующей миграции, которая их вводит.
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.tenant_id = '00000000-0000-0000-0000-000000000001'
  AND r.name = 'admin'
  AND p.module = 'core'
  AND p.entity IN ('permission', 'resource_grant')
  AND p.action IN ('read', 'write');
