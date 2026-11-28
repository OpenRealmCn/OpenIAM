package rbac

import (
	_ "embed"
	"fmt"
	"strconv"
	"strings"

	"github.com/casbin/casbin/v3"
	"github.com/casbin/casbin/v3/model"
	gormadapter "github.com/casbin/gorm-adapter/v3"
	"gorm.io/gorm"
)

//go:embed model.conf
var modelConf string

const (
	DefaultDomain  = "openiam"
	SuperAdminRole = "super_admin"

	// 平台级资源：只对平台超管生效，域内角色即使被预置了这些策略也不生效。
	ResourceSettings       = "settings"
	ResourceDomains        = "domains"
	ResourceOAuthProviders = "oauth_providers"
)

// Permission 表示一条资源-动作权限点，对应 Casbin 策略中的 obj 与 act。
type Permission struct {
	Resource string `json:"resource"`
	Action   string `json:"action"`
}

// delegablePermissions 是域管理员可委派的本域业务权限上限。
// 这是代码内固定白名单：不含平台级资源，也不含任何通配形式。
var delegablePermissions = []Permission{
	{Resource: "users", Action: "read"},
	{Resource: "users", Action: "write"},
	{Resource: "roles", Action: "read"},
	{Resource: "roles", Action: "write"},
	{Resource: "permissions", Action: "read"},
	{Resource: "permissions", Action: "write"},
	{Resource: "audit_logs", Action: "read"},
	{Resource: "oauth_clients", Action: "read"},
	{Resource: "oauth_clients", Action: "write"},
	{Resource: "oauth_clients", Action: "create_own"},
	{Resource: "oauth_clients", Action: "authorize"},
	{Resource: "system", Action: "read"},
}

// DelegablePermissions 返回可委派上限的副本，供 seed 与各写入路径共用同一份事实来源。
func DelegablePermissions() []Permission {
	out := make([]Permission, len(delegablePermissions))
	copy(out, delegablePermissions)
	return out
}

// IsDelegable 判断某权限点是否落在域管理员可委派上限内。
func IsDelegable(resource, action string) bool {
	res, act := strings.TrimSpace(resource), strings.TrimSpace(action)
	for _, p := range delegablePermissions {
		if p.Resource == res && p.Action == act {
			return true
		}
	}
	return false
}

// IsPlatformPermission 判断某权限点是否属于平台级能力（只对超管生效）。
// 判定 fail-closed：空值、任何含 * 的通配形式、以及平台级资源一律视为平台级。
func IsPlatformPermission(resource, action string) bool {
	res, act := strings.TrimSpace(resource), strings.TrimSpace(action)
	if res == "" || act == "" {
		return true
	}
	if strings.Contains(res, "*") || strings.Contains(act, "*") {
		return true
	}
	switch res {
	case ResourceSettings, ResourceDomains, ResourceOAuthProviders:
		return true
	}
	return false
}

// PolicyRule 表示一条域内 Casbin 权限策略 p(role, domain, resource, action)。
type PolicyRule struct {
	Role     string `json:"role"`
	Domain   string `json:"domain"`
	Resource string `json:"resource"`
	Action   string `json:"action"`
}

// Enforcer 封装 Casbin SyncedEnforcer，提供多域 RBAC 权限管理与校验能力。
type Enforcer struct {
	enforcer *casbin.SyncedEnforcer
}

func NewEnforcer(db *gorm.DB) (*Enforcer, error) {
	adapter, err := gormadapter.NewAdapterByDB(db)
	if err != nil {
		return nil, fmt.Errorf("create casbin gorm adapter: %w", err)
	}
	m, err := model.NewModelFromString(modelConf)
	if err != nil {
		return nil, fmt.Errorf("load casbin model: %w", err)
	}
	e, err := casbin.NewSyncedEnforcer(m, adapter)
	if err != nil {
		return nil, fmt.Errorf("create casbin synced enforcer: %w", err)
	}
	if err := e.LoadPolicy(); err != nil {
		return nil, fmt.Errorf("load casbin policies: %w", err)
	}
	return &Enforcer{enforcer: e}, nil
}

// SubjectForUser 将用户 ID 统一编码为 Casbin subject。
func SubjectForUser(userID uint64) string {
	return "user:" + strconv.FormatUint(userID, 10)
}

// ParseUserIDFromSubject 从 Casbin subject 解析用户 ID。
func ParseUserIDFromSubject(sub string) (uint64, bool) {
	if !strings.HasPrefix(sub, "user:") {
		return 0, false
	}
	id, err := strconv.ParseUint(strings.TrimPrefix(sub, "user:"), 10, 64)
	if err != nil {
		return 0, false
	}
	return id, true
}

func (e *Enforcer) Enforce(userID uint64, domain, resource, action string) (bool, error) {
	return e.EnforceSubject(SubjectForUser(userID), domain, resource, action)
}

// EnforceSubject 是全部权限判定的唯一入口，在 Casbin 之上加两道平台级闸门：
//  1. 平台级权限（settings/domains/oauth_providers、任何通配形式）只对超管生效，
//     非超管即使被预置了这些策略也一律判为无权；
//  2. 非超管的每一次「放行」都必须能在本域找到一条精确策略（obj/act 字面相等、域完全一致）。
//     Casbin 的 keyMatch2 与域通配能让一条 *:* 或 dom=* 的脏策略放行任意请求，
//     这类策略属于平台级授权，不能代表业务委派 —— 只由它带来的能力一律不生效（fail-closed）。
//     同一身份在本域的其它精确策略不受影响，删掉通配策略即完全恢复。
func (e *Enforcer) EnforceSubject(subject, domain, resource, action string) (bool, error) {
	super := e.IsSuperAdminSubject(subject)
	if !super && IsPlatformPermission(resource, action) {
		return false, nil
	}
	allowed, err := e.enforcer.Enforce(subject, domain, resource, action)
	if err != nil || !allowed {
		return allowed, err
	}
	if super {
		return true, nil
	}
	if !e.hasExactGrant(subject, domain, resource, action) {
		return false, nil
	}
	return true, nil
}

// IsSuperAdmin 判断用户是否持有平台超管角色（openiam 域下的固定常量角色 rbac.SuperAdminRole）。
func (e *Enforcer) IsSuperAdmin(userID uint64) bool {
	if userID == 0 {
		return false
	}
	return e.IsSuperAdminSubject(SubjectForUser(userID))
}

// IsSuperAdminSubject 判断 Casbin subject 是否为超管身份；只认 openiam 域下的固定角色常量。
func (e *Enforcer) IsSuperAdminSubject(subject string) bool {
	if _, ok := ParseUserIDFromSubject(subject); !ok {
		return false
	}
	for _, r := range e.enforcer.GetRolesForUserInDomain(subject, DefaultDomain) {
		if r == SuperAdminRole {
			return true
		}
	}
	return false
}

// hasExactGrant 报告某身份是否在本域至少有一条「精确」策略与该权限点字面相等。
// 只认 obj/act 字面相等且策略域与本域一致的策略，policy 里任何通配（obj、act 或 dom=*）
// 都不算数；查询出错时按「没有」处理（fail-closed）。只统计直接角色，不推导角色继承，
// 因为本仓库的 g 策略只做 user→role，没有 role→role 继承。
func (e *Enforcer) hasExactGrant(subject, domain, resource, action string) bool {
	roles := e.enforcer.GetRolesForUserInDomain(subject, domain)
	for _, role := range roles {
		rules, err := e.GetPolicies(domain, role)
		if err != nil {
			return false
		}
		for _, r := range rules {
			if r.Resource == resource && r.Action == action && r.Domain == domain {
				return true
			}
		}
	}
	return false
}

func (e *Enforcer) AddRoleForUserInDomain(userID uint64, roleCode, domain string) (bool, error) {
	return e.enforcer.AddRoleForUserInDomain(SubjectForUser(userID), roleCode, domain)
}

func (e *Enforcer) DeleteRoleForUserInDomain(userID uint64, roleCode, domain string) (bool, error) {
	return e.enforcer.DeleteRoleForUserInDomain(SubjectForUser(userID), roleCode, domain)
}

func (e *Enforcer) GetRolesForUserInDomain(userID uint64, domain string) []string {
	return e.enforcer.GetRolesForUserInDomain(SubjectForUser(userID), domain)
}

// GetAllUserDomains 返回用户在各个域中拥有的角色映射。
func (e *Enforcer) GetAllUserRoles(userID uint64) (map[string][]string, error) {
	sub := SubjectForUser(userID)
	grouping, err := e.enforcer.GetFilteredGroupingPolicy(0, sub)
	if err != nil {
		return nil, err
	}
	res := make(map[string][]string)
	for _, g := range grouping {
		if len(g) >= 3 {
			res[g[2]] = append(res[g[2]], g[1])
		}
	}
	return res, nil
}

// GetUsersForRoleInDomain 返回某域内拥有指定角色的所有用户 ID。
func (e *Enforcer) GetUsersForRoleInDomain(roleCode, domain string) ([]uint64, error) {
	grouping, err := e.enforcer.GetFilteredGroupingPolicy(1, roleCode, domain)
	if err != nil {
		return nil, err
	}
	var ids []uint64
	for _, g := range grouping {
		if len(g) >= 1 {
			if id, ok := ParseUserIDFromSubject(g[0]); ok {
				ids = append(ids, id)
			}
		}
	}
	return ids, nil
}

func (e *Enforcer) AddPolicy(roleCode, domain, resource, action string) (bool, error) {
	return e.enforcer.AddPolicy(roleCode, domain, resource, action)
}

func (e *Enforcer) RemovePolicy(roleCode, domain, resource, action string) (bool, error) {
	return e.enforcer.RemovePolicy(roleCode, domain, resource, action)
}

func (e *Enforcer) RemovePoliciesForRoleInDomain(roleCode, domain string) (bool, error) {
	return e.enforcer.RemoveFilteredPolicy(0, roleCode, domain)
}

func (e *Enforcer) RemoveGroupingForUser(userID uint64) (bool, error) {
	return e.enforcer.RemoveFilteredGroupingPolicy(0, SubjectForUser(userID))
}

func (e *Enforcer) RemoveGroupingForRoleInDomain(roleCode, domain string) (bool, error) {
	return e.enforcer.RemoveFilteredGroupingPolicy(1, roleCode, domain)
}

// GetPolicies 查询 Casbin 策略（可按域和角色过滤）。
func (e *Enforcer) GetPolicies(domain, roleCode string) ([]PolicyRule, error) {
	var raw [][]string
	var err error
	switch {
	case roleCode != "" && domain != "":
		raw, err = e.enforcer.GetFilteredPolicy(0, roleCode, domain)
	case roleCode != "":
		raw, err = e.enforcer.GetFilteredPolicy(0, roleCode)
	case domain != "":
		raw, err = e.enforcer.GetFilteredPolicy(1, domain)
	default:
		raw, err = e.enforcer.GetPolicy()
	}
	if err != nil {
		return nil, err
	}
	rules := make([]PolicyRule, 0, len(raw))
	for _, r := range raw {
		if len(r) >= 4 {
			rules = append(rules, PolicyRule{
				Role:     r[0],
				Domain:   r[1],
				Resource: r[2],
				Action:   r[3],
			})
		}
	}
	return rules, nil
}

// GetGroupingsForDomain 返回某域内的全部角色绑定分组规则 g(user, role, domain)。
func (e *Enforcer) GetGroupingsForDomain(domain string) ([][]string, error) {
	return e.enforcer.GetFilteredGroupingPolicy(2, domain)
}

// CountPoliciesForDomain 统计某域内的 p 策略条数（服务端判定，不依赖请求头）。
func (e *Enforcer) CountPoliciesForDomain(domain string) (int64, error) {
	rules, err := e.enforcer.GetFilteredPolicy(1, domain)
	if err != nil {
		return 0, err
	}
	return int64(len(rules)), nil
}

// RemovePoliciesForDomain 删除某域内的全部 p 策略；适配器写入失败时内存不会被改动。
func (e *Enforcer) RemovePoliciesForDomain(domain string) (bool, error) {
	return e.enforcer.RemoveFilteredPolicy(1, domain)
}

// RemoveGroupingForDomain 删除某域内的全部角色绑定 g 规则。
func (e *Enforcer) RemoveGroupingForDomain(domain string) (bool, error) {
	return e.enforcer.RemoveFilteredGroupingPolicy(2, domain)
}

// ReloadPolicy 从存储重新加载全部策略，用于确认内存判定与持久化一致（无残留）。
func (e *Enforcer) ReloadPolicy() error {
	return e.enforcer.LoadPolicy()
}

// RoleChange 描述策略变更预演中的单条用户-角色变更。
type RoleChange struct {
	UserID uint64 `json:"user_id"`
	Role   string `json:"role"`
	Domain string `json:"domain"`
}

// SimulationDraft 描述权限模拟器的假设策略/角色变更草稿（仅在内存中运行，不落库）。
type SimulationDraft struct {
	AddPolicies    []PolicyRule `json:"add_policies"`
	RemovePolicies []PolicyRule `json:"remove_policies"`
	AddRoles       []RoleChange `json:"add_roles"`
	RemoveRoles    []RoleChange `json:"remove_roles"`
}

// SimulationResult 为权限模拟器输出的当前判定与预演变更对比结果。
type SimulationResult struct {
	Current               bool         `json:"current"`
	Simulated             bool         `json:"simulated"`
	Effect                string       `json:"effect"` // unchanged | granted | revoked
	RolesBefore           []string     `json:"roles_before"`
	RolesAfter            []string     `json:"roles_after"`
	MatchedPoliciesBefore []PolicyRule `json:"matched_policies_before"`
	MatchedPoliciesAfter  []PolicyRule `json:"matched_policies_after"`
}

// Simulate 在内存隔离副本中应用假设策略变更并执行与 Enforce 完全一致的两道平台闸门判定，绝不触碰真实策略库。
func (e *Enforcer) Simulate(userID uint64, domain, resource, action string, draft SimulationDraft) (*SimulationResult, error) {
	currentAllowed, err := e.Enforce(userID, domain, resource, action)
	if err != nil {
		return nil, err
	}
	rolesBefore := e.GetRolesForUserInDomain(userID, domain)
	matchedBefore := e.matchedPoliciesForUser(rolesBefore, domain, resource, action)

	// 构建独立内存 Enforcer（无适配器，仅拷贝 p 与 g）
	m, err := model.NewModelFromString(modelConf)
	if err != nil {
		return nil, err
	}
	simEnf, err := casbin.NewEnforcer(m)
	if err != nil {
		return nil, err
	}
	allP, _ := e.enforcer.GetPolicy()
	for _, row := range allP {
		if len(row) >= 4 {
			_, _ = simEnf.AddPolicy(row[0], row[1], row[2], row[3])
		}
	}
	allG, _ := e.enforcer.GetGroupingPolicy()
	for _, row := range allG {
		if len(row) >= 3 {
			_, _ = simEnf.AddGroupingPolicy(row[0], row[1], row[2])
		}
	}

	for _, r := range draft.RemovePolicies {
		_, _ = simEnf.RemovePolicy(strings.TrimSpace(r.Role), strings.TrimSpace(r.Domain), strings.TrimSpace(r.Resource), strings.TrimSpace(r.Action))
	}
	for _, r := range draft.AddPolicies {
		_, _ = simEnf.AddPolicy(strings.TrimSpace(r.Role), strings.TrimSpace(r.Domain), strings.TrimSpace(r.Resource), strings.TrimSpace(r.Action))
	}
	for _, g := range draft.RemoveRoles {
		uid := g.UserID
		if uid == 0 {
			uid = userID
		}
		dom := strings.TrimSpace(g.Domain)
		if dom == "" {
			dom = domain
		}
		_, _ = simEnf.RemoveGroupingPolicy(SubjectForUser(uid), strings.TrimSpace(g.Role), dom)
	}
	for _, g := range draft.AddRoles {
		uid := g.UserID
		if uid == 0 {
			uid = userID
		}
		dom := strings.TrimSpace(g.Domain)
		if dom == "" {
			dom = domain
		}
		_, _ = simEnf.AddGroupingPolicy(SubjectForUser(uid), strings.TrimSpace(g.Role), dom)
	}

	simWrapper := &Enforcer{enforcer: &casbin.SyncedEnforcer{Enforcer: simEnf}}
	simAllowed, err := simWrapper.Enforce(userID, domain, resource, action)
	if err != nil {
		return nil, err
	}
	rolesAfter := simWrapper.GetRolesForUserInDomain(userID, domain)
	matchedAfter := simWrapper.matchedPoliciesForUser(rolesAfter, domain, resource, action)

	effect := "unchanged"
	if !currentAllowed && simAllowed {
		effect = "granted"
	} else if currentAllowed && !simAllowed {
		effect = "revoked"
	}
	return &SimulationResult{
		Current:               currentAllowed,
		Simulated:             simAllowed,
		Effect:                effect,
		RolesBefore:           rolesBefore,
		RolesAfter:            rolesAfter,
		MatchedPoliciesBefore: matchedBefore,
		MatchedPoliciesAfter:  matchedAfter,
	}, nil
}

func (e *Enforcer) matchedPoliciesForUser(roles []string, domain, resource, action string) []PolicyRule {
	out := make([]PolicyRule, 0)
	for _, role := range roles {
		rules, err := e.GetPolicies(domain, role)
		if err != nil {
			continue
		}
		for _, r := range rules {
			if (r.Resource == resource || r.Resource == "*") && (r.Action == action || r.Action == "*") {
				out = append(out, r)
			}
		}
	}
	return out
}
