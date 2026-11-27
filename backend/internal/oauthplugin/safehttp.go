package oauthplugin

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/oauth2"
)

// allowPrivateUpstream 为 true 时允许联合登录插件访问内网或回环地址的身份源。
// 默认禁止，防止通过身份源地址发起 SSRF 访问内网服务与云元数据接口。
var allowPrivateUpstream atomic.Bool

// SetAllowPrivateUpstream 设置是否允许访问内网地址的身份源（仅企业自建内网 IdP 时才应开启）。
func SetAllowPrivateUpstream(v bool) { allowPrivateUpstream.Store(v) }

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

var cgnatNet = mustCIDR("100.64.0.0/10")

func isBlockedIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() || cgnatNet.Contains(ip)
}

// guardDial 在真正建立连接前检查「已解析的目标 IP」，因此同时覆盖 DNS 重绑定与重定向跳转。
func guardDial(_, address string, _ syscall.RawConn) error {
	if allowPrivateUpstream.Load() {
		return nil
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("拒绝连接非 IP 目标: %s", host)
	}
	if isBlockedIP(ip) {
		return fmt.Errorf("出于安全考虑，禁止访问内网或保留地址: %s", host)
	}
	return nil
}

// upstreamClient 是访问外部身份源使用的受限 HTTP 客户端：带超时、限制重定向次数，并在拨号阶段拦截内网地址。
var upstreamClient = &http.Client{
	Timeout: 20 * time.Second,
	Transport: &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, Control: guardDial}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		MaxIdleConns:          20,
		IdleConnTimeout:       60 * time.Second,
		ForceAttemptHTTP2:     true,
	},
	CheckRedirect: func(_ *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return errors.New("重定向次数过多")
		}
		return nil
	},
}

// withUpstreamClient 把受限客户端放入 context，使 oauth2 与 go-oidc 的所有出站请求都走受限客户端。
func withUpstreamClient(ctx context.Context) context.Context {
	return context.WithValue(ctx, oauth2.HTTPClient, upstreamClient)
}

var upstreamURLKeys = []string{"issuer_url", "auth_url", "token_url", "userinfo_url", "api_base_url", "auth_base_url"}

// ValidateExtraConfig 校验身份源配置中的外部地址：必须是 https（允许内网时才可用 http），不得含用户信息，且不得指向内网或保留地址。
func ValidateExtraConfig(cfg map[string]any) error {
	for _, k := range upstreamURLKeys {
		v, ok := cfg[k]
		if !ok {
			continue
		}
		s, ok := v.(string)
		if !ok {
			return fmt.Errorf("配置项 %s 必须是字符串", k)
		}
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if err := validateUpstreamURL(s); err != nil {
			return fmt.Errorf("配置项 %s 无效: %w", k, err)
		}
	}
	return nil
}

func validateUpstreamURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil {
		return errors.New("不是有效的地址（不得包含用户信息）")
	}
	allowPrivate := allowPrivateUpstream.Load()
	switch u.Scheme {
	case "https":
	case "http":
		if !allowPrivate {
			return errors.New("必须使用 https")
		}
	default:
		return errors.New("仅支持 http(s) 协议")
	}
	if !allowPrivate {
		host := u.Hostname()
		if strings.EqualFold(host, "localhost") {
			return errors.New("禁止使用 localhost")
		}
		if ip := net.ParseIP(host); ip != nil && isBlockedIP(ip) {
			return errors.New("禁止使用内网或保留地址")
		}
	}
	return nil
}
