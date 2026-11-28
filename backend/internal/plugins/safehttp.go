package plugins

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var allowPrivateUpstreamFlag atomic.Bool

// SetAllowPrivateUpstream 设置插件出站 HTTP 客户端是否允许访问内网或回环地址（由系统设置热更新驱动）。
func SetAllowPrivateUpstream(v bool) { allowPrivateUpstreamFlag.Store(v) }

func allowPrivateUpstream() bool {
	return allowPrivateUpstreamFlag.Load()
}

// isBlockedHost 判断主机名或 IP 是否属于回环、内网、链路本地或保留地址，防 SSRF。
func isBlockedHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" || h == "localhost" || strings.HasSuffix(h, ".localhost") || strings.HasSuffix(h, ".local") || strings.HasSuffix(h, ".internal") {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return isPrivateOrReservedIP(ip)
	}
	return false
}

func isPrivateOrReservedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified() ||
		isReservedRange(ip)
}

// ValidateExternalURL 校验外部插件接口地址：必须为 https（允许私网开关打开时放行内网地址）。
func ValidateExternalURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return errors.New("接口地址不能为空")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return errors.New("接口地址格式无效")
	}
	if allowPrivateUpstream() {
		if u.Scheme != "http" && u.Scheme != "https" {
			return errors.New("接口地址必须使用 http 或 https 协议")
		}
		return nil
	}
	if u.Scheme != "https" {
		return errors.New("生产安全策略要求外部接口必须使用 https 协议")
	}
	if isBlockedHost(u.Hostname()) {
		return fmt.Errorf("禁止访问内网或回环地址 (%s)", u.Hostname())
	}
	return nil
}

var (
	safeClientOnce sync.Once
	safeClient     *http.Client
)

// NewSafeHTTPClient 返回进程内共享的、带 SSRF 防护与 10 秒超时的受限 HTTP 客户端。
// 共享同一个 Transport 以复用连接；私网开关在每次拨号时读取，热更新仍然生效。
func NewSafeHTTPClient() *http.Client {
	safeClientOnce.Do(func() { safeClient = buildSafeHTTPClient() })
	return safeClient
}

func buildSafeHTTPClient() *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	tr := &http.Transport{
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		MaxIdleConns:          32,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 8 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if allowPrivateUpstream() {
				return dialer.DialContext(ctx, network, addr)
			}
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			for _, ip := range ips {
				if isPrivateOrReservedIP(ip.IP) {
					return nil, fmt.Errorf("blocked private or reserved ip: %s", ip.IP.String())
				}
			}
			for _, ip := range ips {
				conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.IP.String(), port))
				if err == nil {
					return conn, nil
				}
			}
			return nil, fmt.Errorf("unable to connect to %s", addr)
		},
	}
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many redirects")
			}
			if !allowPrivateUpstream() && (req.URL.Scheme != "https" || isBlockedHost(req.URL.Hostname())) {
				return errors.New("blocked redirect target")
			}
			return nil
		},
	}
}
