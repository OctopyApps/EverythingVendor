-- 0003_role_and_grant_permissions.down.sql
DELETE FROM role_permissions
WHERE permission_id IN (
    SELECT id FROM permissions
    WHERE module = 'core' AND entity IN ('permission', 'resource_grant')
);
DELETE FROM permissions WHERE module = 'core' AND entity IN ('permission', 'resource_grant');
