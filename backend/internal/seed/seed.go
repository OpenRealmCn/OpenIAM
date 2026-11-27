package seed

import (
	"context"
	"errors"
	"fmt"

	"github.com/openrealm/openiam/internal/config"
	"github.com/openrealm/openiam/internal/models"
	"github.com/openrealm/openiam/internal/rbac"
	"github.com/openrealm/openiam/internal/security"
	"gorm.io/gorm"
)

// legacyDomainAdminPlatformGrants 是旧版本 seed 错误下放给内置 domain_admin 的平台级只读策略。
// 仅用于升级时清理历史残留；不表示这些权限现在可被委派。
var legacyDomainAdminPlatformGrants = []struct {
	Resource string
	Action   string
}{
	{"settings", "read"},
	{"domains", "read"},
	{"oauth_providers", "read"},
}

// EnsureDefaults 幂等初始化默认域、系统角色、基础权限点与初始超级管理员账号。
// 空库首次初始化必须显式提供满足策略的初始口令；stateStore 用于吊销存量默认口令管理员的旧会话，可为 nil。
func EnsureDefaults(db *gorm.DB, enforcer *rbac.Enforcer, cfg config.SeedConfig, stateStore *security.StateStore) error {
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
		{DomainCode: rbac.DefaultDomain, Code: "oauth_client:create_own", Name: "创建个人 OAuth 应用", Resource: "oauth_clients", Action: "create_own"},
		{DomainCode: rbac.DefaultDomain, Code: "oauth_client:authorize", Name: "使用并授权 OAuth 应用", Resource: "oauth_clients", Action: "authorize"},
		{DomainCode: rbac.DefaultDomain, Code: "oauth_provider:read", Name: "查看联合登录插件", Resource: "oauth_providers", Action: "read"},
		{DomainCode: rbac.DefaultDomain, Code: "oauth_provider:write", Name: "管理联合登录插件", Resource: "oauth_providers", Action: "write"},
		{DomainCode: rbac.DefaultDomain, Code: "audit:read", Name: "查看审计日志", Resource: "audit_logs", Action: "read"},
		{DomainCode: rbac.DefaultDomain, Code: "system:read", Name: "查看系统与版本信息", Resource: "system", Action: "read"},
		{DomainCode: rbac.DefaultDomain, Code: "setting:read", Name: "查看系统设置", Resource: "settings", Action: "read"},
		{DomainCode: rbac.DefaultDomain, Code: "setting:write", Name: "修改系统设置", Resource: "settings", Action: "write"},
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

		// domain_admin 只拿到可委派上限内的本域业务权限（与 rbac.IsDelegable 同一份事实来源），
		// 平台级权限（settings:*、domains:*、oauth_providers:*）一律不下放，
		// 不再依赖「排除清单」兜底，避免新增权限点被默认授予。
		for _, p := range rbac.DelegablePermissions() {
			_, _ = enforcer.AddPolicy("domain_admin", rbac.DefaultDomain, p.Resource, p.Action)
		}

		// 升级兼容：清掉历史版本给内置 domain_admin 角色留下的平台级只读策略。
		// 运行时闸门已经屏蔽这些权限，但「能不能分配角色」读的是原始策略，
		// 残留会让域管理员连内置 domain_admin 角色都分配不出去（403）。
		//
		// 清理范围必须精确，不能按「凡不可委派就删」处理：
		//   1. 只认内置角色（IsSystem=true）。其他域可以自建 code 同名的角色，
		//      平台超管给那种角色配的权限是合法配置，不属于历史残留，不能删。
		//   2. 只删旧 seed 确实授予过的那几对（settings/domains/oauth_providers 的 read）。
		//      旧 seed 的规则是「这三个资源只给 read」，所以只有这三对是历史残留；
		//      超管后来给内置角色另加的业务权限（例如 orders:approve）不在清理范围内。
		var legacyRoleOwners []string
		db.Model(&models.Role{}).
			Where("code = ? AND is_system = ?", "domain_admin", true).
			Distinct().Pluck("domain_code", &legacyRoleOwners)
		for _, d := range legacyRoleOwners {
			for _, legacy := range legacyDomainAdminPlatformGrants {
				_, _ = enforcer.RemovePolicy("domain_admin", d, legacy.Resource, legacy.Action)
			}
		}

		// auditor 拥有只读审计与系统权限
		_, _ = enforcer.AddPolicy("auditor", rbac.DefaultDomain, "audit_logs", "read")
		_, _ = enforcer.AddPolicy("auditor", rbac.DefaultDomain, "system", "read")

		// viewer（普通用户）默认可创建个人 OAuth 应用，并对已接入的 OAuth 应用进行授权与签发授权码
		_, _ = enforcer.AddPolicy("viewer", rbac.DefaultDomain, "oauth_clients", "create_own")
		_, _ = enforcer.AddPolicy("viewer", rbac.DefaultDomain, "oauth_clients", "authorize")
	}

	// 5. 初始超级管理员账号
	// 只在账号不存在时创建，且必须显式提供满足策略的强口令；创建出来的初始管理员一律带强制改密标记。
	// 重复运行初始化不会覆盖已有账号的密码，也不会重复建号。
	if cfg.Enabled {
		var admin models.User
		err := db.Where("username = ?", cfg.AdminUsername).First(&admin).Error
		switch {
		case errors.Is(err, gorm.ErrRecordNotFound):
			if verr := security.ValidateInitialPassword(cfg.AdminPassword); verr != nil {
				return fmt.Errorf("拒绝初始化超级管理员 %q：%v；请通过环境变量 OPENIAM_SEED_ADMIN_PASSWORD 显式设置强口令（至少 %d 位，同时包含大写字母、小写字母与数字，且不得使用历史默认口令）",
					cfg.AdminUsername, verr, security.InitialPasswordMinLength)
			}
			hash, herr := security.HashPassword(cfg.AdminPassword)
			if herr != nil {
				return fmt.Errorf("hash seed admin password: %w", herr)
			}
			admin = models.User{
				Username:           cfg.AdminUsername,
				Email:              cfg.AdminEmail,
				DisplayName:        "超级管理员",
				PasswordHash:       hash,
				Status:             "active",
				MustChangePassword: true,
			}
			if cerr := db.Create(&admin).Error; cerr != nil {
				return fmt.Errorf("seed admin user: %w", cerr)
			}
		case err != nil:
			return fmt.Errorf("lookup seed admin user: %w", err)
		}
		if enforcer != nil {
			_, _ = enforcer.AddRoleForUserInDomain(admin.ID, rbac.SuperAdminRole, rbac.DefaultDomain)
		}
	}

	// 6. 存量库升级：初始超管仍能用历史默认口令通过 bcrypt 校验时，标记为必须改密并吊销其全部旧会话。
	// 已改过密的管理员不会命中，密码与状态都不会被覆盖或重置。
	if cfg.AdminUsername != "" {
		var admin models.User
		if err := db.Where("username = ?", cfg.AdminUsername).First(&admin).Error; err == nil {
			if !admin.MustChangePassword && security.MatchesLegacyDefaultPassword(admin.PasswordHash) {
				if uerr := db.Model(&admin).Update("must_change_password", true).Error; uerr != nil {
					return fmt.Errorf("flag legacy admin for password change: %w", uerr)
				}
				if stateStore != nil {
					if rerr := stateStore.RevokeUserTokens(context.Background(), admin.ID); rerr != nil {
						return fmt.Errorf("revoke legacy admin sessions: %w", rerr)
					}
				}
			}
		}
	}

	return nil
}
