package clientip

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"sync/atomic"

	"github.com/gin-gonic/gin"
)

const (
	MethodRemoteAddr     = "remote_addr"
	MethodXForwardedFor  = "x_forwarded_for"
	MethodXRealIP        = "x_real_ip"
	MethodCFConnectingIP = "cf_connecting_ip"
	MethodTrueClientIP   = "true_client_ip"
	MethodCustomHeader   = "custom_header"
)

var DefaultTrustedProxies = []string{
	"127.0.0.1",
	"::1",
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
}

var cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")
var customHeaderPattern = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

var reservedCustomHeaders = map[string]bool{
	"authorization":       true,
	"cookie":              true,
	"set-cookie":          true,
	"host":                true,
	"content-length":      true,
	"content-type":        true,
	"transfer-encoding":   true,
	"connection":          true,
	"upgrade":             true,
	"proxy-authorization": true,
	"x-forwarded-proto":   true,
	"x-forwarded-host":    true,
}

// Policy 描述当前生效的真实客户端 IP 解析策略。
type Policy struct {
	Method          string
	CustomHeader    string
	TrustedRaw      []string
	TrustedPrefixes []netip.Prefix
}

// MethodPreview 表示某一种 IP 获取方式针对当前请求的实时预览结果。
type MethodPreview struct {
	Method      string `json:"method"`
	Label       string `json:"label"`
	Description string `json:"description"`
	Source      string `json:"source"`
	RawHeader   string `json:"raw_header"`
	ResolvedIP  string `json:"resolved_ip"`
	IsPublic    bool   `json:"is_public"`
	FromHeader  bool   `json:"from_header"`
	Status      string `json:"status"`
	Note        string `json:"note"`
	IsActive    bool   `json:"is_active"`
}

// PreviewResult 返回全部可选方式针对当前请求的真实 IP 预览诊断结果。
type PreviewResult struct {
	ActiveMethod        string          `json:"active_method"`
	ActiveIP            string          `json:"active_ip"`
	ActiveIsPublic      bool            `json:"active_is_public"`
	RemoteAddr          string          `json:"remote_addr"`
	RemoteIsPublic      bool            `json:"remote_is_public"`
	TrustedProxyMatched bool            `json:"trusted_proxy_matched"`
	TrustedProxies      []string        `json:"trusted_proxies"`
	CustomHeader        string          `json:"custom_header"`
	Options             []MethodPreview `json:"options"`
}

var currentPolicy atomic.Pointer[Policy]

func init() {
	SetPolicy(MethodXForwardedFor, "", DefaultTrustedProxies)
}

// IsValidMethod 判断获取方式是否为平台支持的枚举值。
func IsValidMethod(method string) bool {
	switch strings.TrimSpace(method) {
	case MethodRemoteAddr, MethodXForwardedFor, MethodXRealIP, MethodCFConnectingIP, MethodTrueClientIP, MethodCustomHeader:
		return true
	default:
		return false
	}
}

// NormalizeMethod 将未知或空的策略名称归一化为默认 X-Forwarded-For。
func NormalizeMethod(method string) string {
	m := strings.TrimSpace(method)
	if IsValidMethod(m) {
		return m
	}
	return MethodXForwardedFor
}

// ValidateTrustedProxyEntry 校验单个可信代理 IP 或 CIDR 网段格式是否合法。
func ValidateTrustedProxyEntry(raw string) error {
	s := strings.TrimSpace(raw)
	if s == "" {
		return fmt.Errorf("可信代理条目不能为空")
	}
	if _, err := netip.ParsePrefix(s); err == nil {
		return nil
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return nil
	}
	return fmt.Errorf("可信代理地址 %q 格式无效，请输入合法的 IP 或 CIDR 网段（如 10.0.0.0/8）", s)
}

// ValidateCustomHeader 校验自定义真实 IP 请求头名称是否合法且非保留头。
func ValidateCustomHeader(name string) error {
	s := strings.TrimSpace(name)
	if s == "" {
		return nil
	}
	if !customHeaderPattern.MatchString(s) {
		return fmt.Errorf("自定义请求头 %q 格式无效，仅允许字母、数字与连字符（1~64 位）", s)
	}
	if reservedCustomHeaders[strings.ToLower(s)] {
		return fmt.Errorf("处于安全考虑，不允许使用保留请求头 %q 作为客户端 IP 来源", s)
	}
	return nil
}

func buildPolicy(method, customHeader string, trustedProxies []string) *Policy {
	prefixes := make([]netip.Prefix, 0, len(trustedProxies))
	cleanedRaw := make([]string, 0, len(trustedProxies))
	for _, item := range trustedProxies {
		s := strings.TrimSpace(item)
		if s == "" {
			continue
		}
		if p, err := netip.ParsePrefix(s); err == nil {
			masked := netip.PrefixFrom(p.Addr().Unmap(), p.Bits())
			if p.Addr().Is4In6() && p.Bits() >= 96 {
				masked = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
			}
			prefixes = append(prefixes, masked)
			cleanedRaw = append(cleanedRaw, s)
			continue
		}
		if a, err := netip.ParseAddr(s); err == nil {
			unmapped := a.Unmap()
			prefixes = append(prefixes, netip.PrefixFrom(unmapped, unmapped.BitLen()))
			cleanedRaw = append(cleanedRaw, s)
		}
	}
	return &Policy{
		Method:          NormalizeMethod(method),
		CustomHeader:    strings.TrimSpace(customHeader),
		TrustedRaw:      cleanedRaw,
		TrustedPrefixes: prefixes,
	}
}

// SetPolicy 原子更新全局真实客户端 IP 解析策略。
func SetPolicy(method, customHeader string, trustedProxies []string) {
	currentPolicy.Store(buildPolicy(method, customHeader, trustedProxies))
}

// CurrentPolicy 返回当前生效的只读策略快照。
func CurrentPolicy() *Policy {
	p := currentPolicy.Load()
	if p == nil {
		return buildPolicy(MethodXForwardedFor, "", DefaultTrustedProxies)
	}
	return p
}

// FromGin 从 Gin 请求上下文按当前全局策略提取真实客户端 IP。
func FromGin(c *gin.Context) string {
	if c == nil || c.Request == nil {
		return ""
	}
	return Resolve(c.Request)
}

// Resolve 根据当前全局策略从 HTTP 请求中提取真实客户端 IP。
func Resolve(r *http.Request) string {
	if r == nil {
		return ""
	}
	return ResolveWithPolicy(r, CurrentPolicy())
}

// ResolveWithPolicy 按指定策略解析真实客户端 IP（未命中可信代理时自动拒绝代理头以防伪造）。
func ResolveWithPolicy(r *http.Request, p *Policy) string {
	if r == nil {
		return ""
	}
	if p == nil {
		p = CurrentPolicy()
	}
	resolved, _, _, _ := resolveMethod(r, p.Method, p.CustomHeader, p.TrustedPrefixes)
	return resolved
}

// IsPublicIP 判断字符串是否为公网可路由 IP（排除回环、私网、链路本地、CGNAT、未指定地址等）。
func IsPublicIP(ipStr string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(ipStr))
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	if !addr.IsValid() || addr.IsLoopback() || addr.IsPrivate() ||
		addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() ||
		addr.IsMulticast() || addr.IsUnspecified() {
		return false
	}
	if addr.Is4() && cgnatPrefix.Contains(addr) {
		return false
	}
	return true
}

func parseRemoteAddr(raw string) (addr netip.Addr, ipStr string) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return netip.Addr{}, ""
	}
	host := s
	if h, _, err := net.SplitHostPort(s); err == nil {
		host = h
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if parsed, err := netip.ParseAddr(host); err == nil {
		unmapped := parsed.Unmap()
		return unmapped, unmapped.String()
	}
	return netip.Addr{}, host
}

func isTrustedAddr(addr netip.Addr, prefixes []netip.Prefix) bool {
	if !addr.IsValid() {
		return false
	}
	unmapped := addr.Unmap()
	for _, p := range prefixes {
		if p.Contains(unmapped) {
			return true
		}
	}
	return false
}

func joinHeaderValues(r *http.Request, headerName string) string {
	vals := r.Header.Values(headerName)
	if len(vals) == 0 {
		return ""
	}
	parts := make([]string, 0, len(vals))
	for _, v := range vals {
		if t := strings.TrimSpace(v); t != "" {
			parts = append(parts, t)
		}
	}
	return strings.Join(parts, ", ")
}

func parseIPToken(token string) (netip.Addr, bool) {
	s := strings.TrimSpace(token)
	s = strings.Trim(s, `"'[]`)
	if s == "" {
		return netip.Addr{}, false
	}
	// 处理带端口的 IPv4/IPv6 token（仅当存在 host:port 形式）
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = strings.Trim(h, "[]")
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

// extractFromForwardedChain 按逗号拆分并从右向左跳过可信代理，防止客户端伪造最左侧头部。
func extractFromForwardedChain(raw string, trusted []netip.Prefix) (ip string, ok bool) {
	tokens := strings.Split(raw, ",")
	var parsed []netip.Addr
	for _, tok := range tokens {
		if addr, valid := parseIPToken(tok); valid {
			parsed = append(parsed, addr)
		}
	}
	if len(parsed) == 0 {
		return "", false
	}
	for i := len(parsed) - 1; i >= 0; i-- {
		if !isTrustedAddr(parsed[i], trusted) {
			return parsed[i].String(), true
		}
	}
	return parsed[0].String(), true
}

func extractSingleOrChain(raw string, trusted []netip.Prefix) (ip string, ok bool) {
	if strings.Contains(raw, ",") {
		return extractFromForwardedChain(raw, trusted)
	}
	if addr, valid := parseIPToken(raw); valid {
		return addr.String(), true
	}
	return "", false
}

func resolveMethod(r *http.Request, method, customHeader string, trusted []netip.Prefix) (resolvedIP, rawHeader, status string, fromHeader bool) {
	remoteAddr, remoteIP := parseRemoteAddr(r.RemoteAddr)
	if method == MethodRemoteAddr {
		return remoteIP, remoteIP, "direct", false
	}

	var headerName string
	switch method {
	case MethodXForwardedFor:
		headerName = "X-Forwarded-For"
	case MethodXRealIP:
		headerName = "X-Real-IP"
	case MethodCFConnectingIP:
		headerName = "CF-Connecting-IP"
	case MethodTrueClientIP:
		headerName = "True-Client-IP"
	case MethodCustomHeader:
		headerName = strings.TrimSpace(customHeader)
		if headerName == "" {
			return remoteIP, "", "not_configured", false
		}
	default:
		headerName = "X-Forwarded-For"
	}

	rawHeader = joinHeaderValues(r, headerName)
	if rawHeader == "" {
		return remoteIP, "", "fallback_no_header", false
	}

	if !isTrustedAddr(remoteAddr, trusted) {
		return remoteIP, rawHeader, "fallback_untrusted", false
	}

	var extracted string
	var valid bool
	switch method {
	case MethodXForwardedFor:
		extracted, valid = extractFromForwardedChain(rawHeader, trusted)
	case MethodXRealIP, MethodCustomHeader:
		extracted, valid = extractSingleOrChain(rawHeader, trusted)
	case MethodCFConnectingIP, MethodTrueClientIP:
		if addr, ok := parseIPToken(rawHeader); ok {
			extracted, valid = addr.String(), true
		}
	default:
		extracted, valid = extractFromForwardedChain(rawHeader, trusted)
	}

	if !valid {
		return remoteIP, rawHeader, "fallback_invalid", false
	}
	return extracted, rawHeader, "matched", true
}

type methodDescriptor struct {
	Method      string
	Label       string
	Description string
	Source      string
}

var orderedDescriptors = []methodDescriptor{
	{
		Method:      MethodRemoteAddr,
		Label:       "直连来源 IP（TCP RemoteAddr）",
		Description: "适用于服务直接暴露在公网、前端没有反向代理或 CDN 的部署架构。",
		Source:      "TCP 连接来源地址",
	},
	{
		Method:      MethodXForwardedFor,
		Label:       "反向代理链（X-Forwarded-For）",
		Description: "适用于 Nginx、Caddy、Traefik、ALB 等反向代理或负载均衡，自动从右向左剥离可信代理。",
		Source:      "X-Forwarded-For",
	},
	{
		Method:      MethodXRealIP,
		Label:       "单层反代头（X-Real-IP）",
		Description: "适用于单层 Nginx 等直接通过 proxy_set_header X-Real-IP $remote_addr 透传的场景。",
		Source:      "X-Real-IP",
	},
	{
		Method:      MethodCFConnectingIP,
		Label:       "Cloudflare CDN（CF-Connecting-IP）",
		Description: "适用于流量经过 Cloudflare CDN 代理并由 Cloudflare 注入真实访客 IP 的场景。",
		Source:      "CF-Connecting-IP",
	},
	{
		Method:      MethodTrueClientIP,
		Label:       "通用 CDN / WAF（True-Client-IP）",
		Description: "适用于 Akamai、Cloudflare Enterprise 或云 WAF 透传 True-Client-IP 的场景。",
		Source:      "True-Client-IP",
	},
	{
		Method:      MethodCustomHeader,
		Label:       "自定义请求头（Custom Header）",
		Description: "适用于阿里云 SLB、腾讯云 CLB、自建网关注入自定义 IP 请求头的场景。",
		Source:      "自定义请求头",
	},
}

func buildNote(method, headerSource, status, resolvedIP, remoteIP string) string {
	switch status {
	case "direct":
		if IsPublicIP(resolvedIP) {
			return "直接使用当前连接来源地址，未经过可信代理透传。"
		}
		return "当前直连来源为内网或本地地址；若前面存在 Nginx / CDN，建议改用代理请求头方式。"
	case "matched":
		if IsPublicIP(resolvedIP) {
			return fmt.Sprintf("已通过可信代理校验并成功从 %s 提取公网真实 IP，可核对是否与您本机出口 IP 一致。", headerSource)
		}
		return fmt.Sprintf("已从 %s 提取到 IP（%s），当前显示为内网或本地地址。", headerSource, resolvedIP)
	case "fallback_no_header":
		return fmt.Sprintf("当前请求未携带 %s 请求头，已自动回退为直连地址 %s。", headerSource, remoteIP)
	case "fallback_untrusted":
		return fmt.Sprintf("检测到 %s，但直连节点 %s 不在「可信代理网段」中，为防止伪造 IP 已拒绝采信。", headerSource, remoteIP)
	case "fallback_invalid":
		return fmt.Sprintf("请求头 %s 内容无法解析为合法 IP，已回退为直连地址 %s。", headerSource, remoteIP)
	case "not_configured":
		return fmt.Sprintf("尚未填写自定义请求头名称，暂回退为直连地址 %s。", remoteIP)
	default:
		return ""
	}
}

// Preview 基于当前 HTTP 请求及可选草稿配置，试算全部 6 种方式的预览 IP 与可信校验诊断信息。
func Preview(r *http.Request, activeMethod, activeCustomHeader string, activeTrusted []string, draftCustomHeader string, draftTrusted []string) PreviewResult {
	effectiveCustom := strings.TrimSpace(draftCustomHeader)
	if effectiveCustom == "" {
		effectiveCustom = strings.TrimSpace(activeCustomHeader)
	}
	effectiveTrustedRaw := draftTrusted
	if len(effectiveTrustedRaw) == 0 {
		effectiveTrustedRaw = activeTrusted
	}
	if len(effectiveTrustedRaw) == 0 {
		effectiveTrustedRaw = DefaultTrustedProxies
	}

	previewPolicy := buildPolicy(activeMethod, effectiveCustom, effectiveTrustedRaw)
	remoteAddr, remoteIP := parseRemoteAddr(r.RemoteAddr)
	trustedMatched := isTrustedAddr(remoteAddr, previewPolicy.TrustedPrefixes)

	activePolicy := buildPolicy(activeMethod, activeCustomHeader, activeTrusted)
	activeIP := ResolveWithPolicy(r, activePolicy)

	options := make([]MethodPreview, 0, len(orderedDescriptors))
	for _, desc := range orderedDescriptors {
		resolvedIP, rawHeader, status, fromHeader := resolveMethod(
			r,
			desc.Method,
			previewPolicy.CustomHeader,
			previewPolicy.TrustedPrefixes,
		)
		source := desc.Source
		if desc.Method == MethodCustomHeader && previewPolicy.CustomHeader != "" {
			source = previewPolicy.CustomHeader
		}
		options = append(options, MethodPreview{
			Method:      desc.Method,
			Label:       desc.Label,
			Description: desc.Description,
			Source:      source,
			RawHeader:   rawHeader,
			ResolvedIP:  resolvedIP,
			IsPublic:    IsPublicIP(resolvedIP),
			FromHeader:  fromHeader,
			Status:      status,
			Note:        buildNote(desc.Method, source, status, resolvedIP, remoteIP),
			IsActive:    desc.Method == activePolicy.Method,
		})
	}

	return PreviewResult{
		ActiveMethod:        activePolicy.Method,
		ActiveIP:            activeIP,
		ActiveIsPublic:      IsPublicIP(activeIP),
		RemoteAddr:          remoteIP,
		RemoteIsPublic:      IsPublicIP(remoteIP),
		TrustedProxyMatched: trustedMatched,
		TrustedProxies:      previewPolicy.TrustedRaw,
		CustomHeader:        previewPolicy.CustomHeader,
		Options:             options,
	}
}
