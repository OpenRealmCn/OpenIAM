package domain

import (
	"time"

	"gorm.io/gorm"
)

const (
	RoleStatusActive   = "active"
	RoleStatusDisabled = "disabled"

	WildcardPermission = "*:*"
)

type Role struct {
	ID          uint64         `gorm:"primaryKey;column:id"`
	Code        string         `gorm:"column:code"`
	Name        string         `gorm:"column:name"`
	Description *string        `gorm:"column:description"`
	IsSystem    bool           `gorm:"column:is_system"`
	Status      string         `gorm:"column:status"`
	CreatedAt   time.Time      `gorm:"column:created_at"`
	UpdatedAt   time.Time      `gorm:"column:updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"column:deleted_at"`
}

func (Role) TableName() string { return "roles" }

type Permission struct {
	ID          uint64    `gorm:"primaryKey;column:id"`
	Code        string    `gorm:"column:code"`
	Resource    string    `gorm:"column:resource"`
	Action      string    `gorm:"column:action"`
	Name        string    `gorm:"column:name"`
	Description *string   `gorm:"column:description"`
	CreatedAt   time.Time `gorm:"column:created_at"`
	UpdatedAt   time.Time `gorm:"column:updated_at"`
}

func (Permission) TableName() string { return "permissions" }

type UserRole struct {
	UserID    uint64     `gorm:"primaryKey;column:user_id"`
	RoleID    uint64     `gorm:"primaryKey;column:role_id"`
	GrantedBy *uint64    `gorm:"column:granted_by"`
	GrantedAt time.Time  `gorm:"column:granted_at"`
	ExpiresAt *time.Time `gorm:"column:expires_at"`
}

func (UserRole) TableName() string { return "user_roles" }

type RolePermission struct {
	RoleID       uint64    `gorm:"primaryKey;column:role_id"`
	PermissionID uint64    `gorm:"primaryKey;column:permission_id"`
	GrantedAt    time.Time `gorm:"column:granted_at"`
}

func (RolePermission) TableName() string { return "role_permissions" }
