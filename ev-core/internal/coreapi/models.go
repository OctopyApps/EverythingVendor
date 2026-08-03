package coreapi

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrUserNotFound          = errors.New("user not found")
	ErrRoleNotFound          = errors.New("role not found")
	ErrRoleNameTaken         = errors.New("role name already exists in this tenant")
	ErrRoleIsSystem          = errors.New("cannot modify or delete a system role")
	ErrPermissionNotFound    = errors.New("permission not found")
	ErrInvalidEffect         = errors.New("effect must be 'allow' or 'deny'")
	ErrResourceGrantNotFound = errors.New("resource grant not found")
)

// User — публичное представление пользователя. password_hash сюда
// намеренно никогда не попадает.
type User struct {
	ID        uuid.UUID `json:"id"`
	Email     string    `json:"email"`
	IsActive  bool      `json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
}

type Role struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description *string   `json:"description,omitempty"`
	IsSystem    bool      `json:"is_system"`
}

// Permission — элемент глобального каталога прав (не привязан к тенанту,
// см. permissions в миграциях — один список на всю платформу).
type Permission struct {
	ID     uuid.UUID `json:"id"`
	Module string    `json:"module"`
	Entity string    `json:"entity"`
	Action string    `json:"action"`
}

// ResourceGrant — точечное разрешение/запрет на конкретную запись,
// переопределяющее ролевые права (см. docs/rbac.md).
type ResourceGrant struct {
	ID        uuid.UUID  `json:"id"`
	UserID    uuid.UUID  `json:"user_id"`
	Module    string     `json:"module"`
	Entity    string     `json:"entity"`
	RecordID  uuid.UUID  `json:"record_id"`
	Action    string     `json:"action"`
	Effect    string     `json:"effect"` // "allow" | "deny"
	GrantedBy *uuid.UUID `json:"granted_by,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// ResourceGrantFilter — необязательные фильтры для Repository.ListResourceGrants.
type ResourceGrantFilter struct {
	UserID   *uuid.UUID
	Module   string
	Entity   string
	RecordID *uuid.UUID
}
