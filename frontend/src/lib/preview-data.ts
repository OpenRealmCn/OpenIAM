export type UserStatus = "active" | "pending" | "locked" | "disabled";
export type StatusTone = "green" | "amber" | "red" | "gray";

export interface PreviewUser {
  id: string;
  name: string;
  email: string;
  department: string;
  roles: string[];
  status: UserStatus;
  lastLogin: string;
}

export const userStatusMeta: Record<
  UserStatus,
  { label: string; tone: StatusTone; pulse?: boolean }
> = {
  active: { label: "活跃", tone: "green", pulse: true },
  pending: { label: "待激活", tone: "amber" },
  locked: { label: "已锁定", tone: "red" },
  disabled: { label: "已禁用", tone: "gray" },
};

export const previewUsers: PreviewUser[] = [
  { id: "u-1001", name: "陈伟", email: "chen.wei@openrealm.io", department: "平台工程部", roles: ["super-admin"], status: "active", lastLogin: "07-28 14:32" },
  { id: "u-1002", name: "林晓雨", email: "lin.xiaoyu@openrealm.io", department: "身份团队", roles: ["developer"], status: "active", lastLogin: "07-28 13:58" },
  { id: "u-1003", name: "赵倩", email: "zhao.qian@openrealm.io", department: "安全部", roles: ["auditor"], status: "active", lastLogin: "07-28 11:20" },
  { id: "u-1004", name: "王芳", email: "wang.fang@openrealm.io", department: "财务部", roles: ["billing-admin"], status: "locked", lastLogin: "07-27 09:12" },
  { id: "u-1005", name: "刘洋", email: "liu.yang@openrealm.io", department: "平台工程部", roles: ["developer"], status: "active", lastLogin: "07-28 10:05" },
  { id: "u-1006", name: "孙丽", email: "sun.li@openrealm.io", department: "人力资源部", roles: [], status: "pending", lastLogin: "—" },
  { id: "u-1007", name: "周杰", email: "zhou.jie@openrealm.io", department: "数据团队", roles: ["developer"], status: "disabled", lastLogin: "07-19 16:44" },
  { id: "u-1008", name: "吴桐", email: "wu.tong@openrealm.io", department: "身份团队", roles: ["developer"], status: "active", lastLogin: "07-28 14:01" },
  { id: "u-1009", name: "郑浩", email: "zheng.hao@openrealm.io", department: "SRE", roles: ["sre-operator"], status: "active", lastLogin: "07-28 08:47" },
  { id: "u-1010", name: "马芸", email: "ma.yun@openrealm.io", department: "市场部", roles: ["viewer"], status: "active", lastLogin: "07-27 18:26" },
];

export interface PreviewRole {
  code: string;
  name: string;
  description: string;
  isSystem: boolean;
  members: number;
  permissions: string[];
}

export const previewRoles: PreviewRole[] = [
  { code: "super-admin", name: "超级管理员", description: "系统内置角色，拥有全部权限，仅限身份平台核心成员。", isSystem: true, members: 1, permissions: ["*:*"] },
  { code: "developer", name: "开发者", description: "应用与服务的日常开发、部署与会话自查。", isSystem: false, members: 3, permissions: ["users:read", "sessions:read", "deploy:write", "logs:read"] },
  { code: "auditor", name: "审计员", description: "只读访问全部审计记录与安全事件。", isSystem: false, members: 1, permissions: ["audit-logs:read", "users:read", "oauth-clients:read"] },
  { code: "billing-admin", name: "账务管理员", description: "账单、订阅与配额管理。", isSystem: false, members: 1, permissions: ["billing:read", "billing:write", "users:read"] },
  { code: "sre-operator", name: "运维操作员", description: "基础设施运维、会话撤销与账号状态处置。", isSystem: false, members: 1, permissions: ["sessions:revoke", "users:update", "audit-logs:read"] },
  { code: "viewer", name: "只读成员", description: "基础组织信息只读访问。", isSystem: false, members: 1, permissions: ["users:read"] },
];

export interface PreviewPermission {
  code: string;
  resource: string;
  action: string;
  description: string;
}

export const previewPermissions: PreviewPermission[] = [
  { code: "users:read", resource: "users", action: "read", description: "查看用户列表与资料" },
  { code: "users:create", resource: "users", action: "create", description: "创建新用户" },
  { code: "users:update", resource: "users", action: "update", description: "更新用户资料与状态" },
  { code: "users:disable", resource: "users", action: "disable", description: "停用或锁定用户" },
  { code: "roles:read", resource: "roles", action: "read", description: "查看角色与其权限集合" },
  { code: "roles:assign", resource: "roles", action: "assign", description: "为用户分配或回收角色" },
  { code: "roles:update", resource: "roles", action: "update", description: "调整角色的权限绑定" },
  { code: "permissions:read", resource: "permissions", action: "read", description: "查看权限目录" },
  { code: "oauth-clients:read", resource: "oauth-clients", action: "read", description: "查看 OAuth 客户端配置" },
  { code: "oauth-clients:create", resource: "oauth-clients", action: "create", description: "注册新的 OAuth 客户端" },
  { code: "oauth-clients:rotate-secret", resource: "oauth-clients", action: "rotate-secret", description: "轮换客户端密钥" },
  { code: "audit-logs:read", resource: "audit-logs", action: "read", description: "查看审计日志" },
  { code: "sessions:revoke", resource: "sessions", action: "revoke", description: "撤销活跃会话与刷新令牌" },
];

export interface PreviewOAuthClient {
  clientId: string;
  name: string;
  type: "public" | "confidential";
  grants: string[];
  scopes: string[];
  redirectUris: string[];
  pkce: boolean;
  status: "active" | "disabled";
  createdAt: string;
}

export const previewOAuthClients: PreviewOAuthClient[] = [
  { clientId: "openrealm-portal", name: "OpenRealm Portal", type: "confidential", grants: ["authorization_code", "refresh_token"], scopes: ["openid", "profile", "email"], redirectUris: ["https://portal.openrealm.io/callback"], pkce: true, status: "active", createdAt: "2026-03-12" },
  { clientId: "openrealm-wiki", name: "OpenRealm Wiki", type: "public", grants: ["authorization_code"], scopes: ["openid", "profile"], redirectUris: ["https://wiki.openrealm.io/auth/callback"], pkce: true, status: "active", createdAt: "2026-04-02" },
  { clientId: "ci-runner", name: "CI 部署机器人", type: "confidential", grants: ["client_credentials"], scopes: ["deploy:read"], redirectUris: [], pkce: false, status: "active", createdAt: "2026-05-20" },
  { clientId: "mobile-app", name: "OpenRealm 移动端", type: "public", grants: ["authorization_code", "refresh_token"], scopes: ["openid", "offline_access"], redirectUris: ["openrealm://oauth/callback"], pkce: true, status: "active", createdAt: "2026-06-08" },
];

export type AuditResult = "success" | "failure";

export const auditResultMeta: Record<
  AuditResult,
  { label: string; tone: StatusTone }
> = {
  success: { label: "成功", tone: "green" },
  failure: { label: "失败", tone: "red" },
};

export interface PreviewAuditEvent {
  occurredAt: string;
  action: string;
  actor: string;
  resource: string;
  ip: string;
  result: AuditResult;
}

export const previewAuditEvents: PreviewAuditEvent[] = [
  { occurredAt: "07-28 14:32:05", action: "login", actor: "陈伟", resource: "users/u-1001", ip: "10.20.1.15", result: "success" },
  { occurredAt: "07-28 14:01:12", action: "login", actor: "吴桐", resource: "users/u-1008", ip: "10.20.1.22", result: "success" },
  { occurredAt: "07-28 13:47:51", action: "login · 密码错误", actor: "王芳", resource: "users/u-1004", ip: "203.0.113.9", result: "failure" },
  { occurredAt: "07-28 11:20:33", action: "role.assign", actor: "陈伟", resource: "roles/auditor → 赵倩", ip: "10.20.1.15", result: "success" },
  { occurredAt: "07-28 10:58:02", action: "client.rotate-secret", actor: "陈伟", resource: "oauth-clients/openrealm-portal", ip: "10.20.1.15", result: "success" },
  { occurredAt: "07-28 10:12:47", action: "session.revoke", actor: "郑浩", resource: "sessions/u-1007", ip: "10.20.3.8", result: "success" },
  { occurredAt: "07-28 09:40:19", action: "consent.grant", actor: "林晓雨", resource: "oauth-clients/openrealm-wiki", ip: "10.20.1.31", result: "success" },
  { occurredAt: "07-28 09:02:11", action: "user.lock · 尝试超限", actor: "system", resource: "users/u-1004", ip: "—", result: "success" },
];

export const loginTrend = [
  { day: "07-15", count: 34 },
  { day: "07-16", count: 41 },
  { day: "07-17", count: 38 },
  { day: "07-18", count: 52 },
  { day: "07-19", count: 47 },
  { day: "07-20", count: 30 },
  { day: "07-21", count: 22 },
  { day: "07-22", count: 36 },
  { day: "07-23", count: 58 },
  { day: "07-24", count: 63 },
  { day: "07-25", count: 55 },
  { day: "07-26", count: 61 },
  { day: "07-27", count: 49 },
  { day: "07-28", count: 42 },
];

export interface ModuleState {
  name: string;
  label: string;
  note: string;
  ready: boolean;
}

export const moduleStatus: ModuleState[] = [
  { name: "identity", label: "身份", note: "用户与凭据", ready: true },
  { name: "rbac", label: "授权", note: "角色与权限", ready: true },
  { name: "session", label: "会话", note: "Cookie 会话", ready: true },
  { name: "oauth", label: "OAuth / OIDC", note: "协议端点开发中", ready: false },
  { name: "audit", label: "审计", note: "事件记录", ready: true },
];
