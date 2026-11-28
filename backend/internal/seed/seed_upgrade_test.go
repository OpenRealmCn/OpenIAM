package seed

import (
	"fmt"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/openrealm/openiam/internal/config"
	"github.com/openrealm/openiam/internal/models"
	"github.com/openrealm/openiam/internal/rbac"
	"github.com/openrealm/openiam/internal/version"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func newUpgradeDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared", strings.ReplaceAll(t.Name(), "/", "_"))
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(t, err)
	require.NoError(t, version.AutoMigrateForTesting(db))
	return db
}

// policySet 把某域某角色的策略读成 "resource:action" 集合。
func policySet(t *testing.T, e *rbac.Enforcer, domain, roleCode string) map[string]bool {
	t.Helper()
	rules, err := e.GetPolicies(domain, roleCode)
	require.NoError(t, err)
	out := make(map[string]bool, len(rules))
	for _, r := range rules {
		out[strings.TrimSpace(r.Resource)+":"+strings.TrimSpace(r.Action)] = true
	}
	return out
}

// 复审 485cf582「必须改」：升级清理必须限定在有明确历史来源的内置角色与旧策略上。
// 旧实现按 code = domain_admin 匹配所有域，并删掉一切「不可委派」的策略，
// 会把平台超管给别的域里自建的同名角色配的合法业务权限一起删掉。
func TestSeedUpgradeCleanupIsScopedToBuiltinRoleAndLegacyGrants(t *testing.T) {
	db := newUpgradeDB(t)
	enforcer, err := rbac.NewEnforcer(db)
	require.NoError(t, err)

	// 先按基线 seed 的样子种下历史残留：内置 domain_admin 拿到三个平台只读权限。
	for _, legacy := range legacyDomainAdminPlatformGrants {
		_, err := enforcer.AddPolicy("domain_admin", rbac.DefaultDomain, legacy.Resource, legacy.Action)
		require.NoError(t, err)
	}
	// 平台超管事后给内置角色另加的业务权限：不属于历史残留，不能被清掉。
	_, err = enforcer.AddPolicy("domain_admin", rbac.DefaultDomain, "orders", "approve")
	require.NoError(t, err)

	// 另一个域里用户自建的同名角色（IsSystem=false）：它的策略是合法配置，不能被删。
	require.NoError(t, db.Create(&models.Role{
		DomainCode: "beta",
		Code:       "domain_admin",
		Name:       "beta 自己的域管理员",
		IsSystem:   false,
	}).Error)
	for _, p := range [][2]string{{"settings", "read"}, {"orders", "approve"}, {"orders", "refund"}} {
		_, err := enforcer.AddPolicy("domain_admin", "beta", p[0], p[1])
		require.NoError(t, err)
	}

	// 执行升级（重复两次，验证幂等）。
	cfg := config.SeedConfig{Enabled: false}
	for i := 0; i < 2; i++ {
		require.NoError(t, EnsureDefaults(db, enforcer, cfg, nil))
	}

	builtin := policySet(t, enforcer, rbac.DefaultDomain, "domain_admin")

	// 1. 三条历史平台只读策略必须被清掉——否则域管理员连内置角色都分配不出去。
	for _, legacy := range legacyDomainAdminPlatformGrants {
		require.False(t, builtin[legacy.Resource+":"+legacy.Action],
			"历史残留 %s:%s 应被清理", legacy.Resource, legacy.Action)
	}
	// 2. 超管后来给内置角色加的业务权限必须保留。
	require.True(t, builtin["orders:approve"], "超管给内置角色配置的业务权限不应被删除")
	// 3. 内置角色仍持有全部可委派权限。
	for _, p := range rbac.DelegablePermissions() {
		require.True(t, builtin[p.Resource+":"+p.Action],
			"内置 domain_admin 应保有可委派权限 %s:%s", p.Resource, p.Action)
	}

	// 4. 其他域的自建同名角色：一条都不能被动。
	custom := policySet(t, enforcer, "beta", "domain_admin")
	require.True(t, custom["settings:read"], "其他域自建同名角色的策略不应被清理")
	require.True(t, custom["orders:approve"])
	require.True(t, custom["orders:refund"])

	// 5. 清理后内置角色只剩可委派权限 + 超管显式追加的业务权限，
	//    即「能否分配内置角色」不再被历史平台策略挡住。
	for _, legacy := range legacyDomainAdminPlatformGrants {
		require.False(t, rbac.IsDelegable(legacy.Resource, legacy.Action))
	}

	// 6. 重启后从存储重载，结果一致（证明清理已落库，不是只改了内存）。
	reloaded, err := rbac.NewEnforcer(db)
	require.NoError(t, err)
	afterRestart := policySet(t, reloaded, rbac.DefaultDomain, "domain_admin")
	for _, legacy := range legacyDomainAdminPlatformGrants {
		require.False(t, afterRestart[legacy.Resource+":"+legacy.Action], "重启后残留不得复活")
	}
	require.True(t, policySet(t, reloaded, "beta", "domain_admin")["settings:read"])
}
