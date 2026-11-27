package seed

import (
	"fmt"

	"github.com/openrealm/openiam/internal/config"
	"github.com/openrealm/openiam/internal/models"
	"github.com/openrealm/openiam/internal/rbac"
	"github.com/openrealm/openiam/internal/security"
	"gorm.io/gorm"
)

// EnsureDefaults 幂等初始化默认域、系统角色、基础权限点与默认超级管理员账号。
func EnsureDefaults(db *gorm.DB, enforcer *rbac.Enforcer, cfg config.SeedConfig) error {
	// 1. 默认域 openiam
	var dom models.Domain
	if err := db.Where("code = ?", rbac.DefaultDomain).First(&dom).Error; err != nil {
		dom = models.Domain{
			Code:        rbac.DefaultDomain,
			Name:        "OpenIAM 核心管理域",
			Description: "OpenRealm 身份与访问控制平台默认核心管理域",
			Status:      "active",
		}
		if err := db.Create(&dom).Error; err != nil {
			return fmt.Errorf("seed default domain: %w", err)
		}
	}

	// 2. 系统角色
	defaultRoles := []models.Role{
		{DomainCode: rbac.DefaultDomain, Code: rbac.SuperAdminRole, Name: "超级管理员", Description: "拥有全平台与所有 OpenRealm 域的完整控制权", IsSystem: true},
		{DomainCode: rbac.DefaultDomain, Code: "domain_admin", Name: "域管理员", Description: "可管理所属域内的用户、角色、权限与 OAuth 应用", IsSystem: true},
		{DomainCode: rbac.DefaultDomain, Code: "auditor", Name: "安全审计员", Description: "可查看审计日志与系统版本健康状态", IsSystem: true},
		{DomainCode: rbac.DefaultDomain, Code: "viewer", Name: "普通用户", Description: "仅可访问个人中心与授权应用", IsSystem: true},
	}
	for _, r := range defaultRoles {
		var existing models.Role
		if err := db.Where("domain_code = ? AND code = ?", r.DomainCode, r.Code).First(&existing).Error; err != nil {
			if err := db.Create(&r).Error; err != nil {
				return fmt.Errorf("seed role %s: %w", r.Code, err)
			}
		}
	}

	// 3. 基础权限点目录
	defaultPerms := []models.Permission{
		{DomainCode: rbac.DefaultDomain, Code: "user:read", Name: "查看用户", Resource: "users", Action: "read"},
		{DomainCode: rbac.DefaultDomain, Code: "user:write", Name: "管理用户", Resource: "users", Action: "write"},
		{DomainCode: rbac.DefaultDomain, Code: "domain:read", Name: "查看域", Resource: "domains", Action: "read"},
		{DomainCode: rbac.DefaultDomain, Code: "domain:write", Name: "管理域", Resource: "domains", Action: "write"},
		{DomainCode: rbac.DefaultDomain, Code: "role:read", Name: "查看角色", Resource: "roles", Action: "read"},
		{DomainCode: rbac.DefaultDomain, Code: "role:write", Name: "管理角色", Resource: "roles", Action: "write"},
		{DomainCode: rbac.DefaultDomain, Code: "permission:read", Name: "查看权限与策略", Resource: "permissions", Action: "read"},
		{DomainCode: rbac.DefaultDomain, Code: "permission:write", Name: "管理权限与策略", Resource: "permissions", Action: "write"},
		{DomainCode: rbac.DefaultDomain, Code: "oauth_client:read", Name: "查看 OAuth 应用", Resource: "oauth_clients", Action: "read"},
		{DomainCode: rbac.DefaultDomain, Code: "oauth_client:write", Name: "管理 OAuth 应用", Resource: "oauth_clients", Action: "write"},
		{DomainCode: rbac.DefaultDomain, Code: "oauth_provider:read", Name: "查看联合登录插件", Resource: "oauth_providers", Action: "read"},
		{DomainCode: rbac.DefaultDomain, Code: "oauth_provider:write", Name: "管理联合登录插件", Resource: "oauth_providers", Action: "write"},
		{DomainCode: rbac.DefaultDomain, Code: "audit:read", Name: "查看审计日志", Resource: "audit_logs", Action: "read"},
		{DomainCode: rbac.DefaultDomain, Code: "system:read", Name: "查看系统与版本信息", Resource: "system", Action: "read"},
	}
	for _, p := range defaultPerms {
		var existing models.Permission
		if err := db.Where("domain_code = ? AND code = ?", p.DomainCode, p.Code).First(&existing).Error; err != nil {
			if err := db.Create(&p).Error; err != nil {
				return fmt.Errorf("seed permission %s: %w", p.Code, err)
			}
		}
	}

	// 4. 初始化 Casbin 策略
	if enforcer != nil {
		// super_admin 拥有全局通配权限
		_, _ = enforcer.AddPolicy(rbac.SuperAdminRole, rbac.DefaultDomain, "*", "*")

		// domain_admin 拥有常见读/写管理权限
		for _, p := range defaultPerms {
			if p.Resource != "domains" || p.Action == "read" {
				_, _ = enforcer.AddPolicy("domain_admin", rbac.DefaultDomain, p.Resource, p.Action)
			}
		}

		// auditor 拥有只读审计与系统权限
		_, _ = enforcer.AddPolicy("auditor", rbac.DefaultDomain, "audit_logs", "read")
		_, _ = enforcer.AddPolicy("auditor", rbac.DefaultDomain, "system", "read")
	}

	// 5. 默认超级管理员账号
	if cfg.Enabled {
		var admin models.User
		if err := db.Where("username = ?", cfg.AdminUsername).First(&admin).Error; err != nil {
			hash, err := security.HashPassword(cfg.AdminPassword)
			if err != nil {
				return fmt.Errorf("hash seed admin password: %w", err)
			}
			admin = models.User{
				Username:     cfg.AdminUsername,
				Email:        cfg.AdminEmail,
				DisplayName:  "超级管理员",
				PasswordHash: hash,
				Status:       "active",
			}
			if err := db.Create(&admin).Error; err != nil {
				return fmt.Errorf("seed admin user: %w", err)
			}
		}
		if enforcer != nil {
			_, _ = enforcer.AddRoleForUserInDomain(admin.ID, rbac.SuperAdminRole, rbac.DefaultDomain)
		}
	}

	return nil
}
