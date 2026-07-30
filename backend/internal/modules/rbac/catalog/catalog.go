package catalog

const WildcardPermission = "*:*"

type Permission struct {
	Code        string
	Resource    string
	Action      string
	Name        string
	Description string
}

type Role struct {
	Code        string
	Name        string
	Description string
	IsSystem    bool
	Permissions []string
}

var Permissions = []Permission{
	{"users:read", "users", "read", "查看用户", "查看用户列表与资料"},
	{"users:create", "users", "create", "创建用户", "创建新用户"},
	{"users:update", "users", "update", "更新用户", "更新用户资料"},
	{"users:disable", "users", "disable", "停用用户", "停用或锁定用户（高权限）"},
	{"roles:read", "roles", "read", "查看角色", "查看角色与其权限集合"},
	{"roles:create", "roles", "create", "创建角色", "创建新的角色（高权限）"},
	{"roles:update", "roles", "update", "更新角色", "调整角色的权限绑定（高权限）"},
	{"roles:assign", "roles", "assign", "分配角色", "为用户分配或回收角色（高权限）"},
	{"roles:delete", "roles", "delete", "删除角色", "删除角色（高权限）"},
	{"permissions:read", "permissions", "read", "查看权限", "查看权限目录"},
	{"oauth-clients:read", "oauth-clients", "read", "查看客户端", "查看 OAuth 客户端配置"},
	{"oauth-clients:create", "oauth-clients", "create", "注册客户端", "注册新的 OAuth 客户端（高权限）"},
	{"oauth-clients:update", "oauth-clients", "update", "更新客户端", "更新 OAuth 客户端配置（高权限）"},
	{"oauth-clients:rotate-secret", "oauth-clients", "rotate-secret", "轮换密钥", "轮换客户端密钥（高权限）"},
	{"audit-logs:read", "audit-logs", "read", "查看审计", "查看审计日志"},
	{"sessions:revoke", "sessions", "revoke", "撤销会话", "撤销活跃会话与刷新令牌"},
	{"groups:read", "groups", "read", "查看身份组", "查看身份组列表与成员"},
	{"groups:create", "groups", "create", "创建身份组", "创建新的身份组（高权限）"},
	{"groups:update", "groups", "update", "更新身份组", "更新身份组信息（高权限）"},
	{"groups:delete", "groups", "delete", "删除身份组", "删除身份组（高权限）"},
	{"groups:assign", "groups", "assign", "管理组成员", "加入或移除身份组成员（高权限）"},
	{"profile:read", "profile", "read", "查看资料", "查看个人资料"},
	{"profile:update", "profile", "update", "更新资料", "更新自己的个人资料与偏好"},
	{"users:invite", "users", "invite", "邀请用户", "邀请新用户加入组织（高权限）"},
	{"system:mail-test", "system", "mail-test", "发送测试邮件", "发送 SMTP 测试邮件（高权限）"},
	{"system:settings", "system", "settings", "系统设置", "读写系统级配置（高权限）"},
}

// PrivilegedPermissions are reserved for the super-admin tier. The operational
// admin role must never be granted any of these.
var PrivilegedPermissions = []string{
	"users:disable",
	"users:invite",
	"roles:create",
	"roles:update",
	"roles:assign",
	"roles:delete",
	"groups:create",
	"groups:update",
	"groups:delete",
	"groups:assign",
	"oauth-clients:create",
	"oauth-clients:update",
	"oauth-clients:rotate-secret",
	"system:mail-test",
	"system:settings",
}

var Roles = []Role{
	{
		Code:        "super-admin",
		Name:        "超级管理员",
		Description: "系统内置角色，拥有全部权限，可管理角色、权限与系统配置。",
		IsSystem:    true,
		Permissions: []string{WildcardPermission},
	},
	{
		Code:        "admin",
		Name:        "管理员",
		Description: "日常运营管理：管理用户、查看角色与审计、撤销会话，但不含角色管理与系统级权限。",
		IsSystem:    true,
		Permissions: []string{
			"users:read",
			"users:create",
			"users:update",
			"roles:read",
			"permissions:read",
			"oauth-clients:read",
			"audit-logs:read",
			"sessions:revoke",
			"groups:read",
			"profile:read",
			"profile:update",
		},
	},
	{
		Code:        "developer",
		Name:        "开发者",
		Description: "应用与服务的日常开发、部署与会话自查。",
		IsSystem:    false,
		Permissions: []string{"users:read", "audit-logs:read"},
	},
	{
		Code:        "auditor",
		Name:        "审计员",
		Description: "只读访问全部审计记录与安全事件。",
		IsSystem:    false,
		Permissions: []string{"audit-logs:read", "users:read", "oauth-clients:read", "roles:read", "permissions:read"},
	},
	{
		Code:        "sre-operator",
		Name:        "运维操作员",
		Description: "基础设施运维、会话撤销与账号状态处置。",
		IsSystem:    false,
		Permissions: []string{"sessions:revoke", "users:update", "audit-logs:read"},
	},
}

func permissionCodes() map[string]bool {
	codes := make(map[string]bool, len(Permissions))
	for _, p := range Permissions {
		codes[p.Code] = true
	}
	return codes
}
