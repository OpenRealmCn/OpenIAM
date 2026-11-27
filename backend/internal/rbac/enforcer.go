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
)

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
	return e.enforcer.Enforce(SubjectForUser(userID), domain, resource, action)
}

func (e *Enforcer) EnforceSubject(subject, domain, resource, action string) (bool, error) {
	return e.enforcer.Enforce(subject, domain, resource, action)
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
