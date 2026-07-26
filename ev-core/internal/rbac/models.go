package rbac

import "github.com/google/uuid"

// Effect — явный результат точечного разрешения на уровне записи.
type Effect string

const (
	EffectAllow Effect = "allow"
	EffectDeny  Effect = "deny"
)

// PermissionKey — гранулярность прав "модуль.сущность:действие",
// например crm.deal:read, archive.document:delete.
type PermissionKey struct {
	Module string
	Entity string
	Action string
}

func (p PermissionKey) String() string {
	return p.Module + "." + p.Entity + ":" + p.Action
}

// Decision — результат проверки прав, всегда логируется в audit_log
// независимо от того, allowed или denied.
type Decision struct {
	Allowed bool
	Reason  string // человекочитаемая причина: "role_permission", "resource_grant_deny", "default_deny", ...
}

// CheckRequest — параметры одной проверки доступа.
type CheckRequest struct {
	TenantID uuid.UUID
	UserID   uuid.UUID
	Module   string
	Entity   string
	Action   string
	// RecordID опционален: если nil, проверяется только ролевой доступ
	// к типу сущности (например, доступ к списку/созданию), без учёта
	// точечных resource_grants на конкретную запись.
	RecordID *uuid.UUID
}
