-- 0002_seed_system_roles.down.sql
DELETE FROM role_permissions WHERE role_id IN (
    SELECT id FROM roles WHERE tenant_id = '00000000-0000-0000-0000-000000000001'
);
DELETE FROM roles WHERE tenant_id = '00000000-0000-0000-0000-000000000001';
DELETE FROM permissions WHERE module = 'core';
DELETE FROM tenants WHERE id = '00000000-0000-0000-0000-000000000001';
