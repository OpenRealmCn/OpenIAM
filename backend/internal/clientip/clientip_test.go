package clientip

import (
	"net/http/httptest"
	"testing"
)

func TestResolveAllMethods(t *testing.T) {
	defer SetPolicy(MethodXForwardedFor, "", DefaultTrustedProxies)

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set("X-Forwarded-For", "198.51.100.10, 10.0.0.8")
	req.Header.Set("X-Real-IP", "203.0.113.11")
	req.Header.Set("CF-Connecting-IP", "203.0.113.22")
	req.Header.Set("True-Client-IP", "203.0.113.33")
	req.Header.Set("EO-Client-IP", "203.0.113.44")

	cases := []struct {
		method       string
		customHeader string
		want         string
	}{
		{MethodRemoteAddr, "", "127.0.0.1"},
		{MethodXForwardedFor, "", "198.51.100.10"},
		{MethodXRealIP, "", "203.0.113.11"},
		{MethodCFConnectingIP, "", "203.0.113.22"},
		{MethodTrueClientIP, "", "203.0.113.33"},
		{MethodCustomHeader, "EO-Client-IP", "203.0.113.44"},
	}

	for _, tc := range cases {
		SetPolicy(tc.method, tc.customHeader, DefaultTrustedProxies)
		got := Resolve(req)
		if got != tc.want {
			t.Errorf("method=%s got=%q want=%q", tc.method, got, tc.want)
		}
	}
}

func TestResolveXFFStripsSpoofedLeftmostFromRight(t *testing.T) {
	p := buildPolicy(MethodXForwardedFor, "", []string{"10.0.0.0/8", "172.16.0.0/12"})
	req := httptest.NewRequest("GET", "/login", nil)
	req.RemoteAddr = "10.1.2.3:40000"
	// 最左侧 1.2.3.4 为客户端伪造，真实出口 198.51.100.77 由右侧可信反代追加
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 198.51.100.77, 172.16.0.5")

	got := ResolveWithPolicy(req, p)
	if got != "198.51.100.77" {
		t.Fatalf("expected 198.51.100.77, got %q", got)
	}
}

func TestRejectUntrustedDirectClientSpoofingHeaders(t *testing.T) {
	p := buildPolicy(MethodCFConnectingIP, "", DefaultTrustedProxies)
	req := httptest.NewRequest("GET", "/login", nil)
	// 来自公网直连，不在可信代理内，必须拒绝所有代理请求头
	req.RemoteAddr = "203.0.113.9:51111"
	req.Header.Set("CF-Connecting-IP", "8.8.8.8")
	req.Header.Set("X-Forwarded-For", "1.1.1.1")

	if got := ResolveWithPolicy(req, p); got != "203.0.113.9" {
		t.Fatalf("expected direct remote ip 203.0.113.9 when untrusted, got %q", got)
	}

	preview := Preview(req, MethodCFConnectingIP, "", DefaultTrustedProxies, "EO-Client-IP", nil)
	if preview.TrustedProxyMatched {
		t.Fatalf("expected TrustedProxyMatched=false for public remote addr")
	}
	for _, opt := range preview.Options {
		if opt.Method == MethodCFConnectingIP && opt.Status != "fallback_untrusted" {
			t.Fatalf("expected fallback_untrusted for cf_connecting_ip, got %s", opt.Status)
		}
	}
}

func TestPreviewReturnsAllOptionsAndPublicClassification(t *testing.T) {
	req := httptest.NewRequest("GET", "/preview", nil)
	req.RemoteAddr = "192.168.1.2:443"
	req.Header.Set("X-Forwarded-For", "114.114.114.114")
	req.Header.Set("CF-Connecting-IP", "invalid-ip")

	res := Preview(req, MethodXForwardedFor, "", DefaultTrustedProxies, "X-Test-IP", nil)
	if !res.TrustedProxyMatched {
		t.Fatalf("expected TrustedProxyMatched=true")
	}
	if res.ActiveIP != "114.114.114.114" || !res.ActiveIsPublic {
		t.Fatalf("unexpected active preview: ip=%s public=%v", res.ActiveIP, res.ActiveIsPublic)
	}
	if len(res.Options) != 6 {
		t.Fatalf("expected 6 options, got %d", len(res.Options))
	}

	statusByMethod := map[string]MethodPreview{}
	for _, o := range res.Options {
		statusByMethod[o.Method] = o
	}
	if statusByMethod[MethodXForwardedFor].Status != "matched" || !statusByMethod[MethodXForwardedFor].IsPublic {
		t.Fatalf("unexpected xff option: %+v", statusByMethod[MethodXForwardedFor])
	}
	if statusByMethod[MethodCFConnectingIP].Status != "fallback_invalid" || statusByMethod[MethodCFConnectingIP].ResolvedIP != "192.168.1.2" {
		t.Fatalf("unexpected cf option: %+v", statusByMethod[MethodCFConnectingIP])
	}
	if statusByMethod[MethodRemoteAddr].IsPublic {
		t.Fatalf("192.168.1.2 should not be public")
	}
}

func TestValidateCustomHeaderAndTrustedProxy(t *testing.T) {
	if err := ValidateCustomHeader("Authorization"); err == nil {
		t.Fatalf("expected Authorization header to be rejected")
	}
	if err := ValidateCustomHeader("Bad Header!"); err == nil {
		t.Fatalf("expected invalid characters to be rejected")
	}
	if err := ValidateCustomHeader("EO-Client-IP"); err != nil {
		t.Fatalf("expected EO-Client-IP to be valid, got %v", err)
	}
	if err := ValidateTrustedProxyEntry("10.0.0.0/8"); err != nil {
		t.Fatalf("expected CIDR to be valid, got %v", err)
	}
	if err := ValidateTrustedProxyEntry("not-an-ip"); err == nil {
		t.Fatalf("expected invalid proxy entry to fail")
	}
}
