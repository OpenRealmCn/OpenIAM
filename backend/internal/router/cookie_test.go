package router_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func findCookie(w *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, ck := range w.Result().Cookies() {
		if ck.Name == name {
			return ck
		}
	}
	return nil
}

func cookieRequest(t *testing.T, env *testEnv, path, bearer string, ck *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, nil)
	req.RemoteAddr = "192.0.2.10:12345"
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if ck != nil {
		req.AddCookie(ck)
	}
	w := httptest.NewRecorder()
	env.engine.ServeHTTP(w, req)
	return w
}

// 浏览器默认通过 HttpOnly Cookie 获取 Refresh Token：响应体不含令牌，刷新轮换后旧 Cookie 失效，登出后 Cookie 作废。
func TestRefreshTokenIsDeliveredViaHttpOnlyCookie(t *testing.T) {
	env := setupTestEnv(t, "")

	w := doJSON(t, env.engine, http.MethodPost, "/api/v1/auth/login", map[string]string{
		"username": "admin",
		"password": "Admin@123456",
	}, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var resp struct {
		Data struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp.Data.AccessToken)
	assert.Empty(t, resp.Data.RefreshToken, "默认不应在响应体中返回 Refresh Token")

	ck := findCookie(w, "openiam_refresh")
	require.NotNil(t, ck)
	assert.True(t, ck.HttpOnly)
	assert.Equal(t, http.SameSiteStrictMode, ck.SameSite)
	assert.Equal(t, "/api/v1/auth", ck.Path)
	assert.NotEmpty(t, ck.Value)

	// 仅凭 Cookie 即可刷新，并轮换出新的 Cookie
	r1 := cookieRequest(t, env, "/api/v1/auth/refresh", "", ck)
	require.Equal(t, http.StatusOK, r1.Code, r1.Body.String())
	ck2 := findCookie(r1, "openiam_refresh")
	require.NotNil(t, ck2)
	assert.NotEqual(t, ck.Value, ck2.Value)

	// 旧 Cookie 不能重放
	r2 := cookieRequest(t, env, "/api/v1/auth/refresh", "", ck)
	assert.Equal(t, http.StatusUnauthorized, r2.Code)

	// 登出会清除 Cookie 并使对应 Refresh Token 失效
	logout := cookieRequest(t, env, "/api/v1/auth/logout", resp.Data.AccessToken, ck2)
	require.Equal(t, http.StatusOK, logout.Code, logout.Body.String())
	cleared := findCookie(logout, "openiam_refresh")
	require.NotNil(t, cleared)
	assert.Less(t, cleared.MaxAge, 0)

	r3 := cookieRequest(t, env, "/api/v1/auth/refresh", "", ck2)
	assert.Equal(t, http.StatusUnauthorized, r3.Code)

	// 没有 Cookie 也没有请求体时应明确拒绝
	r4 := cookieRequest(t, env, "/api/v1/auth/refresh", "", nil)
	assert.Equal(t, http.StatusBadRequest, r4.Code)
}
