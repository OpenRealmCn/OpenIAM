package feishu

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func newFakeFeishu(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/auth/v3/app_access_token/internal", func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]string
		_ = json.Unmarshal(raw, &body)
		if body["app_id"] != "cli_test" || body["app_secret"] != "secret_test" {
			_ = json.NewEncoder(w).Encode(map[string]any{"code": 10003, "msg": "invalid app credentials"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"code": 0, "msg": "ok", "app_access_token": "app-token"})
	})

	mux.HandleFunc("/authen/v1/oidc/access_token", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer app-token" {
			_ = json.NewEncoder(w).Encode(map[string]any{"code": 99991663, "msg": "bad app token"})
			return
		}
		raw, _ := io.ReadAll(r.Body)
		var body map[string]string
		_ = json.Unmarshal(raw, &body)
		if body["code"] != "auth-code" || body["grant_type"] != "authorization_code" {
			_ = json.NewEncoder(w).Encode(map[string]any{"code": 10012, "msg": "bad code"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code": 0,
			"msg":  "success",
			"data": map[string]any{"access_token": "user-token", "token_type": "Bearer"},
		})
	})

	mux.HandleFunc("/authen/v1/user_info", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer user-token" {
			_ = json.NewEncoder(w).Encode(map[string]any{"code": 99991668, "msg": "bad user token"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code": 0,
			"msg":  "success",
			"data": map[string]any{
				"open_id":    "ou_123",
				"union_id":   "on_456",
				"name":       "张三",
				"email":      "zhang.san@openrealm.io",
				"avatar_url": "https://avatar.example/zhang.png",
			},
		})
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func TestHTTPProviderExchange(t *testing.T) {
	server := newFakeFeishu(t)
	provider := NewHTTPProvider(Config{
		AppID:       "cli_test",
		AppSecret:   "secret_test",
		RedirectURI: "http://localhost:8080/api/v1/auth/feishu/callback",
		BaseURL:     server.URL,
	}, server.Client())

	info, err := provider.Exchange(context.Background(), "auth-code")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if info.OpenID != "ou_123" || info.Email != "zhang.san@openrealm.io" || info.Name != "张三" {
		t.Fatalf("unexpected user info %+v", info)
	}
}

func TestHTTPProviderExchangeRejectsBadCode(t *testing.T) {
	server := newFakeFeishu(t)
	provider := NewHTTPProvider(Config{
		AppID:     "cli_test",
		AppSecret: "secret_test",
		BaseURL:   server.URL,
	}, server.Client())

	if _, err := provider.Exchange(context.Background(), "wrong-code"); err == nil {
		t.Fatal("expected exchange to fail for an invalid code")
	}
}

func TestAuthorizeURL(t *testing.T) {
	provider := NewHTTPProvider(Config{
		AppID:       "cli_test",
		AppSecret:   "secret_test",
		RedirectURI: "http://localhost:8080/cb",
		BaseURL:     "https://open.feishu.cn/open-apis",
	}, nil)

	parsed, err := url.Parse(provider.AuthorizeURL("state-abc"))
	if err != nil {
		t.Fatalf("parse authorize url: %v", err)
	}
	if !strings.HasSuffix(parsed.Path, "/authen/v1/authorize") {
		t.Fatalf("unexpected path %q", parsed.Path)
	}
	query := parsed.Query()
	if query.Get("app_id") != "cli_test" || query.Get("state") != "state-abc" ||
		query.Get("response_type") != "code" || query.Get("redirect_uri") != "http://localhost:8080/cb" {
		t.Fatalf("unexpected query %v", query)
	}
}
