package jit

import (
	"context"
	"fmt"
	"time"

	"github.com/openrealm/openiam/internal/audit"
	"github.com/openrealm/openiam/internal/models"
	"github.com/openrealm/openiam/internal/notify"
	"github.com/openrealm/openiam/internal/rbac"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type Service struct {
	db        *gorm.DB
	enforcer  *rbac.Enforcer
	notifySvc *notify.Service
	auditSvc  *audit.Service
	logger    *zap.Logger
}

func NewService(
	db *gorm.DB,
	enforcer *rbac.Enforcer,
	notifySvc *notify.Service,
	auditSvc *audit.Service,
	logger *zap.Logger,
) *Service {
	return &Service{
		db:        db,
		enforcer:  enforcer,
		notifySvc: notifySvc,
		auditSvc:  auditSvc,
		logger:    logger,
	}
}

// StartScheduler 启动后台定时巡检协程，定期自动激活到期生效的授权并回收已过期的临时权限。
func (s *Service) StartScheduler(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.ProcessDueGrants(ctx)
			}
		}
	}()
}

// ProcessDueGrants 执行一次 JIT 临时权限巡检：激活到达生效时间的授权，自动回收已过期的授权。
func (s *Service) ProcessDueGrants(ctx context.Context) (activated int, expired int) {
	now := time.Now()

	// 1. 激活到达 starts_at 且尚未过期的 pending 授权
	var toActivate []models.TempRoleGrant
	_ = s.db.WithContext(ctx).
		Where("status = ? AND starts_at <= ? AND expires_at > ?", "pending", now, now).
		Find(&toActivate).Error
	for _, g := range toActivate {
		if _, err := s.enforcer.AddRoleForUserInDomain(g.UserID, g.RoleCode, g.DomainCode); err != nil {
			if s.logger != nil {
				s.logger.Warn("jit activate add role failed", zap.Uint64("grant_id", g.ID), zap.Error(err))
			}
			continue
		}
		_ = s.db.WithContext(ctx).Model(&g).Updates(map[string]interface{}{
			"status":       "active",
			"activated_at": &now,
		}).Error
		activated++
		s.notifyUser(ctx, g, "临时权限已生效", fmt.Sprintf("您在域 %s 下的临时角色「%s」已生效，将在 %s 到期自动回收。", g.DomainCode, g.RoleCode, g.ExpiresAt.Format("2006-01-02 15:04")))
		if s.auditSvc != nil {
			s.auditSvc.Record(audit.Entry{
				ActorID:       g.GrantedBy,
				ActorUsername: "jit-scheduler",
				DomainCode:    g.DomainCode,
				Action:        "rbac.jit.activate",
				ResourceType:  "temp_role_grant",
				ResourceID:    fmt.Sprintf("%d", g.ID),
				After:         g,
				Status:        "success",
			})
		}
	}

	// 2. 回收已到达 expires_at 的 active 或超时未激活的 pending 授权
	var toExpire []models.TempRoleGrant
	_ = s.db.WithContext(ctx).
		Where("status IN ? AND expires_at <= ?", []string{"active", "pending"}, now).
		Find(&toExpire).Error
	for _, g := range toExpire {
		wasActive := g.Status == "active"
		_ = s.db.WithContext(ctx).Model(&g).Updates(map[string]interface{}{
			"status":     "expired",
			"revoked_at": &now,
		}).Error
		expired++

		if wasActive {
			// 若同一用户在同一域同角色没有其他活跃临时授权，则从 Casbin 回收角色
			var otherActive int64
			s.db.WithContext(ctx).Model(&models.TempRoleGrant{}).
				Where("user_id = ? AND domain_code = ? AND role_code = ? AND status = ? AND id <> ?",
					g.UserID, g.DomainCode, g.RoleCode, "active", g.ID).
				Count(&otherActive)
			if otherActive == 0 {
				_, _ = s.enforcer.DeleteRoleForUserInDomain(g.UserID, g.RoleCode, g.DomainCode)
			}
			s.notifyUser(ctx, g, "临时权限已到期回收", fmt.Sprintf("您在域 %s 下的临时角色「%s」已到达有效期上限并被系统自动回收。", g.DomainCode, g.RoleCode))
			if s.auditSvc != nil {
				s.auditSvc.Record(audit.Entry{
					ActorUsername: "jit-scheduler",
					DomainCode:    g.DomainCode,
					Action:        "rbac.jit.expire",
					ResourceType:  "temp_role_grant",
					ResourceID:    fmt.Sprintf("%d", g.ID),
					Before:        g,
					Status:        "success",
				})
			}
		}
	}

	return activated, expired
}

func (s *Service) notifyUser(ctx context.Context, g models.TempRoleGrant, title, content string) {
	if s.notifySvc == nil {
		return
	}
	_, _ = s.notifySvc.SendInApp(ctx, g.UserID, notify.CategorySystemMessage, "info", title, content, models.JSONMap{
		"grant_id": g.ID,
		"domain":   g.DomainCode,
		"role":     g.RoleCode,
	}, g.GrantedBy, nil)
}
