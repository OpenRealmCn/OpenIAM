package audit

import (
	"context"
	"time"

	"github.com/openrealm/openiam/backend/internal/modules/identity/domain"
	"gorm.io/gorm"
)

type Log struct {
	ID           uint64    `gorm:"primaryKey;column:id"`
	RequestID    *string   `gorm:"column:request_id"`
	ActorUserID  *uint64   `gorm:"column:actor_user_id"`
	Action       string    `gorm:"column:action"`
	ResourceType string    `gorm:"column:resource_type"`
	ResourceID   *string   `gorm:"column:resource_id"`
	Result       string    `gorm:"column:result"`
	IPAddress    *string   `gorm:"column:ip_address"`
	UserAgent    *string   `gorm:"column:user_agent"`
	OccurredAt   time.Time `gorm:"column:occurred_at"`
}

func (Log) TableName() string { return "audit_logs" }

const (
	ResultSuccess = "success"
	ResultFailure = "failure"
)

type Service struct {
	db *gorm.DB
}

func NewService(db *gorm.DB) *Service {
	return &Service{db: db}
}

func (s *Service) Record(ctx context.Context, entry Log) {
	if entry.OccurredAt.IsZero() {
		entry.OccurredAt = time.Now().UTC()
	}
	s.db.WithContext(ctx).Create(&entry)
}

func (s *Service) RecordLogin(ctx context.Context, user *domain.User, success bool, ip, userAgent string) {
	result := ResultSuccess
	action := "login"
	if !success {
		result = ResultFailure
	}

	resourceID := user.PublicID
	entry := Log{
		ActorUserID:  &user.ID,
		Action:       action,
		ResourceType: "users",
		ResourceID:   &resourceID,
		Result:       result,
	}
	if ip != "" {
		entry.IPAddress = &ip
	}
	if userAgent != "" {
		entry.UserAgent = &userAgent
	}

	s.Record(ctx, entry)
}

// RecordRoleCreated logs the creation of a new role.
func (s *Service) RecordRoleCreated(ctx context.Context, actorUserID uint64, roleCode string) {
	s.Record(ctx, Log{
		ActorUserID:  &actorUserID,
		Action:       "role:create",
		ResourceType: "roles",
		ResourceID:   &roleCode,
		Result:       ResultSuccess,
	})
}

// RecordRolePermissionsChanged logs changes to a role's permissions.
func (s *Service) RecordRolePermissionsChanged(ctx context.Context, actorUserID uint64, roleCode string) {
	s.Record(ctx, Log{
		ActorUserID:  &actorUserID,
		Action:       "role:update-permissions",
		ResourceType: "roles",
		ResourceID:   &roleCode,
		Result:       ResultSuccess,
	})
}

// RecordUserRolesChanged logs changes to a user's role assignments.
func (s *Service) RecordUserRolesChanged(ctx context.Context, actorUserID, targetUserID uint64, targetPublicID string) {
	s.Record(ctx, Log{
		ActorUserID:  &actorUserID,
		Action:       "user:update-roles",
		ResourceType: "users",
		ResourceID:   &targetPublicID,
		Result:       ResultSuccess,
	})
}
