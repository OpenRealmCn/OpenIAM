package risk

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/openrealm/openiam/internal/audit"
	"github.com/openrealm/openiam/internal/models"
	"github.com/openrealm/openiam/internal/notify"
	"github.com/openrealm/openiam/internal/rbac"
	"github.com/openrealm/openiam/internal/security"
	"github.com/openrealm/openiam/internal/settings"
	"gorm.io/gorm"
)

type Engine struct {
	db          *gorm.DB
	stateStore  *security.StateStore
	settingsSvc *settings.Service
	notifySvc   *notify.Service
	auditSvc    *audit.Service
}

func NewEngine(
	db *gorm.DB,
	stateStore *security.StateStore,
	settingsSvc *settings.Service,
	notifySvc *notify.Service,
	auditSvc *audit.Service,
) *Engine {
	return &Engine{
		db:          db,
		stateStore:  stateStore,
		settingsSvc: settingsSvc,
		notifySvc:   notifySvc,
		auditSvc:    auditSvc,
	}
}

type Evaluation struct {
	Score      int      `json:"score"`
	Level      string   `json:"level"` // low | medium | high
	Reasons    []string `json:"reasons"`
	Action     string   `json:"action"` // allow | notify | challenge_mfa | block
	Location   string   `json:"location"`
	DeviceName string   `json:"device_name"`
}

// ParseDeviceName 根据 User-Agent 提炼人类可读的设备与浏览器名称。
func ParseDeviceName(ua string) string {
	u := strings.ToLower(ua)
	osName := "未知系统"
	switch {
	case strings.Contains(u, "windows"):
		osName = "Windows"
	case strings.Contains(u, "iphone") || strings.Contains(u, "ipad"):
		osName = "iOS"
	case strings.Contains(u, "mac os x") || strings.Contains(u, "macintosh"):
		osName = "macOS"
	case strings.Contains(u, "android"):
		osName = "Android"
	case strings.Contains(u, "linux"):
		osName = "Linux"
	}
	browser := "浏览器"
	switch {
	case strings.Contains(u, "edg/"):
		browser = "Edge"
	case strings.Contains(u, "chrome/") && !strings.Contains(u, "edg/"):
		browser = "Chrome"
	case strings.Contains(u, "firefox/"):
		browser = "Firefox"
	case strings.Contains(u, "safari/") && !strings.Contains(u, "chrome/"):
		browser = "Safari"
	case strings.Contains(u, "curl/"):
		browser = "CLI/cURL"
	}
	return fmt.Sprintf("%s · %s", osName, browser)
}

// ResolveLocation 解析客户端 IP 所属位置（优先受信任网关注入的 X-Geo-Location）。
func ResolveLocation(ipStr, geoHeader string) string {
	if strings.TrimSpace(geoHeader) != "" {
		return strings.TrimSpace(geoHeader)
	}
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return "未知地区"
	}
	if ip.IsLoopback() {
		return "本机"
	}
	if ip.IsPrivate() {
		return "局域网"
	}
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("公网 %d.%d.*.*", v4[0], v4[1])
	}
	return "公网 IPv6"
}

// isKnownDevice 判断本次上报的设备指纹是否出现在历史会话中。
// 指纹由客户端上报：缺省时只有当历史会话也都没有指纹才视为已知设备，
// 否则攻击者省略指纹即可绕过「新设备」评分。
func isKnownDevice(sessions []models.UserSession, deviceFP string) bool {
	allPriorEmpty := true
	for _, s := range sessions {
		if s.DeviceFingerprint != "" {
			allPriorEmpty = false
		}
		if deviceFP != "" && s.DeviceFingerprint == deviceFP {
			return true
		}
	}
	return deviceFP == "" && allPriorEmpty
}

// EvaluateLogin 按 IP 信誉、异地、设备指纹变化、非常用登录时段评估登录风险，写入风控日志与审计并发送系统消息通知用户。
func (e *Engine) EvaluateLogin(
	ctx context.Context,
	user models.User,
	ip, ua, deviceFP, geoHeader string,
	now time.Time,
) *Evaluation {
	snap := e.settingsSvc.Snapshot()
	location := ResolveLocation(ip, geoHeader)
	deviceName := ParseDeviceName(ua)
	ev := &Evaluation{
		Level:      "low",
		Action:     "allow",
		Reasons:    []string{},
		Location:   location,
		DeviceName: deviceName,
	}
	if !snap.RiskEnabled {
		return ev
	}

	score := 0

	// 1. IP 信誉检查（黑名单 + 近期频繁失败）
	blocked := false
	for _, b := range snap.RiskBlockedIPs {
		if strings.TrimSpace(b) == strings.TrimSpace(ip) && ip != "" {
			blocked = true
			break
		}
	}
	if blocked {
		score += 80
		ev.Reasons = append(ev.Reasons, "来源 IP 在平台拦截名单中")
	} else if e.stateStore != nil && e.stateStore.GetIPFailureCount(ctx, ip) >= 5 {
		score += 35
		ev.Reasons = append(ev.Reasons, "该 IP 近期多次登录失败")
	}

	// 2. 历史活跃会话对比（异地 & 设备指纹变化）
	var recentSessions []models.UserSession
	_ = e.db.WithContext(ctx).
		Where("user_id = ?", user.ID).
		Order("id DESC").
		Limit(10).
		Find(&recentSessions).Error

	if len(recentSessions) > 0 {
		knownLocation := false
		for _, s := range recentSessions {
			if location != "" && s.Location != "" {
				if s.Location == location {
					knownLocation = true
				}
			} else if s.IPAddress != "" && s.IPAddress == ip {
				knownLocation = true
			}
		}
		knownFP := isKnownDevice(recentSessions, deviceFP)
		if !knownLocation {
			score += 30
			ev.Reasons = append(ev.Reasons, fmt.Sprintf("在不常用的地点或网络登录（%s）", location))
		}
		if !knownFP {
			score += 20
			ev.Reasons = append(ev.Reasons, fmt.Sprintf("在新设备上登录（%s）", deviceName))
		}
	} else if user.LastLoginIP != "" && user.LastLoginIP != ip {
		score += 30
		ev.Reasons = append(ev.Reasons, fmt.Sprintf("登录 IP 与上次不同（%s）", ip))
	}

	// 3. 非常用登录时段检测（深夜 00:00 ~ 05:59）
	hr := now.Hour()
	if hr >= 0 && hr < 6 {
		score += 15
		ev.Reasons = append(ev.Reasons, "在凌晨时段登录")
	}

	ev.Score = score
	switch {
	case score >= snap.RiskHighThreshold:
		ev.Level = "high"
		ev.Action = snap.RiskHighAction
	case score >= snap.RiskMediumThreshold:
		ev.Level = "medium"
		ev.Action = "notify"
	default:
		ev.Level = "low"
		ev.Action = "allow"
	}

	if ev.Level != "low" {
		// 写入风险事件表
		_ = e.db.WithContext(ctx).Create(&models.RiskEvent{
			UserID:            user.ID,
			Username:          user.Username,
			IPAddress:         ip,
			Location:          location,
			DeviceFingerprint: deviceFP,
			UserAgent:         ua,
			RiskScore:         ev.Score,
			RiskLevel:         ev.Level,
			Reasons:           models.StringSlice(ev.Reasons),
			ActionTaken:       ev.Action,
		}).Error

		// 写入审计日志
		if e.auditSvc != nil {
			e.auditSvc.Record(audit.Entry{
				ActorID:       user.ID,
				ActorUsername: user.Username,
				DomainCode:    rbac.DefaultDomain,
				Action:        "auth.risk_detected",
				ResourceType:  "risk_event",
				ResourceID:    fmt.Sprintf("%d", user.ID),
				After: map[string]interface{}{
					"score":   ev.Score,
					"level":   ev.Level,
					"action":  ev.Action,
					"reasons": ev.Reasons,
				},
				IPAddress: ip,
				UserAgent: ua,
				Status:    "success",
			})
		}

		// 发送系统消息给用户本人
		if e.notifySvc != nil {
			title := "发现一次异常登录"
			if ev.Level == "high" {
				title = "发现一次高风险登录"
			}
			_, _ = e.notifySvc.SendInApp(
				ctx,
				user.ID,
				notify.CategorySystemMessage,
				"security",
				title,
				fmt.Sprintf("你的账号于 %s 有一次登录尝试。\n地点：%s\nIP 地址：%s\n设备：%s\n异常原因：%s。\n\n如果是你本人操作，可以忽略这条提醒；如果不是，请立即修改密码并开启两步验证。",
					now.Format("2006-01-02 15:04"), location, ip, deviceName, strings.Join(ev.Reasons, "；")),
				models.JSONMap{
					"risk_score": ev.Score,
					"risk_level": ev.Level,
					"ip":         ip,
					"location":   location,
					"reasons":    ev.Reasons,
				},
				0,
				nil,
			)
		}
	}

	return ev
}
