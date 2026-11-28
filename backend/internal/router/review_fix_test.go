package router_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/openrealm/openiam/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func reviewCreateUser(t *testing.T, env *testEnv, token string, body map[string]any) {
	t.Helper()
	w := doJSON(t, env.engine, http.MethodPost, "/api/v1/users", body, token)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
}

func reviewUserID(t *testing.T, env *testEnv, username string) uint64 {
	t.Helper()
	var u models.User
	require.NoError(t, env.db.Where("username = ?", username).First(&u).Error)
	return u.ID
}

// 域管理员不能通过自行配置策略，把自己没有的权限（尤其是系统设置、身份源、域的写权限）授予任何角色。
func TestDomainAdminCannotGrantPermissionsTheyDoNotHold(t *testing.T) {
	env := setupTestEnv(t, "")
	adminToken, _ := loginAs(t, env.engine, "admin", testSeedAdminPassword)
	reviewCreateUser(t, env, adminToken, map[string]any{
		"username": "da3", "email": "da3@openrealm.local", "password": "Da3User@123456",
		"domain_code": "openiam", "role_codes": []string{"domain_admin"},
	})
	daToken, _ := loginAs(t, env.engine, "da3", "Da3User@123456")

	w := doJSON(t, env.engine, http.MethodPost, "/api/v1/policies", map[string]string{
		"role": "viewer", "domain": "openiam", "resource": "settings", "action": "write",
	}, daToken)
	assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	w = doJSON(t, env.engine, http.MethodPost, "/api/v1/roles", map[string]string{
		"domain_code": "openiam", "code": "custom_x", "name": "Custom X",
	}, daToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var role models.Role
	require.NoError(t, env.db.Where("code = ?", "custom_x").First(&role).Error)
	path := fmt.Sprintf("/api/v1/roles/%d/permissions", role.ID)

	w = doJSON(t, env.engine, http.MethodPut, path, map[string]any{
		"policies": []map[string]string{{"resource": "oauth_providers", "action": "write"}},
	}, daToken)
	assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	// 授予自己已持有的权限仍然允许
	w = doJSON(t, env.engine, http.MethodPut, path, map[string]any{
		"policies": []map[string]string{{"resource": "users", "action": "read"}},
	}, daToken)
	assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

// 域管理员只能管理仅属于本域的用户，不能重置、禁用或删除其他域的用户。
func TestDomainAdminCannotManageUsersOutsideTheirDomain(t *testing.T) {
	env := setupTestEnv(t, "")
	adminToken, _ := loginAs(t, env.engine, "admin", testSeedAdminPassword)

	w := doJSON(t, env.engine, http.MethodPost, "/api/v1/domains", map[string]string{"code": "billing", "name": "Billing"}, adminToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	w = doJSON(t, env.engine, http.MethodPost, "/api/v1/roles", map[string]string{
		"domain_code": "billing", "code": "billing_admin", "name": "Billing Admin",
	}, adminToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var role models.Role
	require.NoError(t, env.db.Where("code = ?", "billing_admin").First(&role).Error)
	w = doJSON(t, env.engine, http.MethodPut, fmt.Sprintf("/api/v1/roles/%d/permissions", role.ID), map[string]any{
		"policies": []map[string]string{{"resource": "users", "action": "read"}, {"resource": "users", "action": "write"}},
	}, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	reviewCreateUser(t, env, adminToken, map[string]any{
		"username": "bill_admin", "email": "bill_admin@openrealm.local", "password": "Ba@123456789",
		"domain_code": "billing", "role_codes": []string{"billing_admin"},
	})
	reviewCreateUser(t, env, adminToken, map[string]any{
		"username": "bill_member", "email": "bill_member@openrealm.local", "password": "Bm@123456789",
		"domain_code": "billing", "role_codes": []string{"billing_admin"},
	})
	reviewCreateUser(t, env, adminToken, map[string]any{
		"username": "victim", "email": "victim@openrealm.local", "password": "Victim@123456",
		"domain_code": "openiam", "role_codes": []string{"viewer"},
	})
	baToken, _ := loginAs(t, env.engine, "bill_admin", "Ba@123456789")
	hdr := map[string]string{"X-OpenIAM-Domain": "billing"}
	victim := reviewUserID(t, env, "victim")
	member := reviewUserID(t, env, "bill_member")

	w = doJSON(t, env.engine, http.MethodPost, fmt.Sprintf("/api/v1/users/%d/reset-password", victim), map[string]string{"new_password": "Reset@123456"}, baToken, hdr)
	assert.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
	w = doJSON(t, env.engine, http.MethodPut, fmt.Sprintf("/api/v1/users/%d", victim), map[string]string{"status": "disabled"}, baToken, hdr)
	assert.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
	w = doJSON(t, env.engine, http.MethodDelete, fmt.Sprintf("/api/v1/users/%d", victim), nil, baToken, hdr)
	assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	// 本域成员仍可正常管理
	w = doJSON(t, env.engine, http.MethodPost, fmt.Sprintf("/api/v1/users/%d/reset-password", member), map[string]string{"new_password": "Reset@123456"}, baToken, hdr)
	assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

func reviewCreateClient(t *testing.T, env *testEnv, adminToken, name string) (string, string) {
	t.Helper()
	w := doJSON(t, env.engine, http.MethodPost, "/api/v1/oauth-clients", map[string]any{
		"name": name, "domain_code": "openiam",
		"redirect_uris": []string{"https://" + name + ".example.com/cb"},
		"grant_types":   []string{"client_credentials"},
		"scopes":        []string{"openid"},
		"require_pkce":  true, "is_confidential": true,
	}, adminToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var resp struct {
		Data struct {
			Client       models.OAuthClient `json:"client"`
			ClientSecret string             `json:"client_secret"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	return resp.Data.Client.ClientID, resp.Data.ClientSecret
}

func reviewClientToken(t *testing.T, env *testEnv, id, secret string) string {
	t.Helper()
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", id)
	form.Set("client_secret", secret)
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "192.0.2.10:12345"
	w := httptest.NewRecorder()
	env.engine.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var resp struct {
		AccessToken string `json:"access_token"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.NotEmpty(t, resp.AccessToken)
	return resp.AccessToken
}

func reviewBasic(id, secret string) map[string]string {
	return map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(id+":"+secret))}
}

// introspect 与 revoke 只能作用于调用方自己的令牌：客户端 A 不能探测或撤销客户端 B 的令牌。
func TestIntrospectAndRevokeAreBoundToTheOwningClient(t *testing.T) {
	env := setupTestEnv(t, "")
	adminToken, _ := loginAs(t, env.engine, "admin", testSeedAdminPassword)
	idA, secA := reviewCreateClient(t, env, adminToken, "appa")
	idB, secB := reviewCreateClient(t, env, adminToken, "appb")
	tokB := reviewClientToken(t, env, idB, secB)
	body := map[string]string{"token": tokB}

	w := doJSON(t, env.engine, http.MethodPost, "/oauth2/introspect", body, "", reviewBasic(idA, secA))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), `"active":false`)

	w = doJSON(t, env.engine, http.MethodPost, "/oauth2/introspect", body, "", reviewBasic(idB, secB))
	assert.Contains(t, w.Body.String(), `"active":true`)

	// A 撤销 B 的令牌：静默成功，但令牌仍然有效
	w = doJSON(t, env.engine, http.MethodPost, "/oauth2/revoke", body, "", reviewBasic(idA, secA))
	assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
	w = doJSON(t, env.engine, http.MethodPost, "/oauth2/introspect", body, "", reviewBasic(idB, secB))
	assert.Contains(t, w.Body.String(), `"active":true`)

	// B 撤销自己的令牌后失效
	w = doJSON(t, env.engine, http.MethodPost, "/oauth2/revoke", body, "", reviewBasic(idB, secB))
	assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
	w = doJSON(t, env.engine, http.MethodPost, "/oauth2/introspect", body, "", reviewBasic(idB, secB))
	assert.Contains(t, w.Body.String(), `"active":false`)

	// 没有客户端凭据一律拒绝
	w = doJSON(t, env.engine, http.MethodPost, "/oauth2/introspect", body, "")
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// 仅对白名单内的具体来源返回 Allow-Credentials，预检允许 X-Token-Delivery 头。
func TestCORSAllowsCredentialsOnlyForRegisteredOrigins(t *testing.T) {
	env := setupTestEnv(t, "")

	w := doJSON(t, env.engine, http.MethodGet, "/api/v1/health", nil, "", map[string]string{"Origin": "http://localhost:5173"})
	assert.Equal(t, "http://localhost:5173", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "true", w.Header().Get("Access-Control-Allow-Credentials"))

	w = doJSON(t, env.engine, http.MethodGet, "/api/v1/health", nil, "", map[string]string{"Origin": "https://evil.example.com"})
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Credentials"))

	w = doJSON(t, env.engine, http.MethodOptions, "/api/v1/auth/login", nil, "", map[string]string{"Origin": "http://localhost:5173"})
	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Contains(t, w.Header().Get("Access-Control-Allow-Headers"), "X-Token-Delivery")
}

// bcrypt 上限是 72 字节而不是 72 个字符：30 个汉字（90 字节）的口令必须被明确拒绝为 400。
func TestPasswordLengthIsCountedInBytes(t *testing.T) {
	env := setupTestEnv(t, "")
	w := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/register", map[string]string{
		"username": "cnuser", "email": "cn@openrealm.local", "password": strings.Repeat("密", 30),
	}, "")
	assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
}
