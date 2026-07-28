package domain

import (
	"time"

	"gorm.io/gorm"
)

const (
	StatusPending  = "pending"
	StatusActive   = "active"
	StatusLocked   = "locked"
	StatusDisabled = "disabled"
)

type User struct {
	ID                uint64         `gorm:"primaryKey;column:id"`
	PublicID          string         `gorm:"column:public_id"`
	Username          string         `gorm:"column:username"`
	Email             string         `gorm:"column:email"`
	PasswordHash      *string        `gorm:"column:password_hash"`
	DisplayName       string         `gorm:"column:display_name"`
	AvatarURL         *string        `gorm:"column:avatar_url"`
	Status            string         `gorm:"column:status"`
	EmailVerifiedAt   *time.Time     `gorm:"column:email_verified_at"`
	PasswordChangedAt *time.Time     `gorm:"column:password_changed_at"`
	LastLoginAt       *time.Time     `gorm:"column:last_login_at"`
	FailedLoginCount  uint           `gorm:"column:failed_login_count"`
	LockedUntil       *time.Time     `gorm:"column:locked_until"`
	CreatedAt         time.Time      `gorm:"column:created_at"`
	UpdatedAt         time.Time      `gorm:"column:updated_at"`
	DeletedAt         gorm.DeletedAt `gorm:"column:deleted_at"`
}

func (User) TableName() string { return "users" }

func (u *User) IsLocked(now time.Time) bool {
	return u.LockedUntil != nil && u.LockedUntil.After(now)
}
