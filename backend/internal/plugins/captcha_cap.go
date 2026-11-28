package plugins

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/openrealm/openiam/internal/models"
	"github.com/openrealm/openiam/internal/security"
)

// CapCaptchaDriver 实现与 trycap.dev 协议兼容的人机验证插件驱动：
// 支持 "local"（本机签发并核销 SHA-256 PoW 挑战）和 "remote"（对接独立部署的 Cap / siteverify 服务）。
type CapCaptchaDriver struct{}

func NewCapCaptchaDriver() *CapCaptchaDriver { return &CapCaptchaDriver{} }

func (d *CapCaptchaDriver) Slot() string { return SlotCaptcha }
func (d *CapCaptchaDriver) Type() string { return "cap_captcha" }

func (d *CapCaptchaDriver) Metadata() DriverMetadata {
	return DriverMetadata{
		Slot:        SlotCaptcha,
		Type:        d.Type(),
		DisplayName: "Cap 人机验证（trycap.dev）",
		Description: "基于工作量证明（PoW）的轻量级无追踪人机验证，支持本地自运行模式与远端 Cap 服务模式。",
		Fields: []ConfigField{
			{
				Key:      "mode",
				Label:    "运行模式",
				Type:     "select",
				Required: true,
				Default:  "local",
				Options: []ConfigFieldOption{
					{Value: "local", Label: "本地自运行（无需外部服务）"},
					{Value: "remote", Label: "远端 Cap 部署模式（siteverify）"},
				},
				Description: "本地模式由 OpenIAM 后端直接签发并验证 PoW 挑战；远端模式对接独立的 Cap 服务器。",
			},
			{
				Key:         "challenge_count",
				Label:       "挑战次数（本地模式）",
				Type:        "number",
				Default:     "16",
				Placeholder: "16",
				Description: "客户端需计算的 PoW 任务数量（建议 8~32，越高越防刷）。",
			},
			{
				Key:         "difficulty",
				Label:       "计算难度（本地模式）",
				Type:        "number",
				Default:     "4",
				Placeholder: "4",
				Description: "SHA-256 十六进制前导零位数（建议 3~5；4 位约耗时 0.5~1.5 秒）。",
			},
			{
				Key:         "remote_endpoint",
				Label:       "远端 Cap API 地址",
				Type:        "url",
				Placeholder: "https://cap.example.com/your-site-key/",
				Description: "远端部署模式必填，包含 Site Key 的 Cap 服务基础地址。",
			},
			{
				Key:         "remote_secret",
				Label:       "远端 Siteverify 密钥",
				Type:        "password",
				Placeholder: "输入远端密钥（留空保持不变）",
				Description: "远端部署模式必填，用于服务端调用 /siteverify 校验客户端令牌。",
			},
		},
	}
}

func (d *CapCaptchaDriver) ValidateConfig(cfg models.JSONMap) error {
	mode := cfgStr(cfg, "mode", "local")
	if mode != "local" && mode != "remote" {
		return errors.New("Cap 运行模式必须为 local 或 remote")
	}
	if mode == "local" {
		cnt, err := strconv.Atoi(cfgStr(cfg, "challenge_count", "16"))
		if err != nil || cnt < 1 || cnt > 64 {
			return errors.New("本地模式挑战次数范围需在 1 ~ 64 之间")
		}
		diff, err := strconv.Atoi(cfgStr(cfg, "difficulty", "4"))
		if err != nil || diff < 1 || diff > 6 {
			return errors.New("本地模式难度范围需在 1 ~ 6 之间")
		}
		return nil
	}
	endpoint := cfgStr(cfg, "remote_endpoint", "")
	if err := ValidateExternalURL(endpoint); err != nil {
		return fmt.Errorf("远端 Cap API 地址无效: %w", err)
	}
	if cfgStr(cfg, "remote_secret", "") == "" {
		return errors.New("远端模式必须配置 remote_secret")
	}
	return nil
}

func (d *CapCaptchaDriver) HealthCheck(ctx context.Context, cfg models.JSONMap) error {
	if err := d.ValidateConfig(cfg); err != nil {
		return err
	}
	mode := cfgStr(cfg, "mode", "local")
	if mode == "local" {
		return nil
	}
	endpoint := strings.TrimRight(cfgStr(cfg, "remote_endpoint", ""), "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/challenge", bytes.NewReader([]byte(`{}`)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := NewSafeHTTPClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("远端 Cap 服务返回异常状态码 %d", resp.StatusCode)
	}
	return nil
}

type CapChallengeBundle struct {
	Challenge struct {
		C int    `json:"c"`
		S string `json:"s"`
		D int    `json:"d"`
	} `json:"challenge"`
	Token   string `json:"token"`
	Expires int64  `json:"expires"`
}

type capChallengeState struct {
	Salt       string `json:"salt"`
	Count      int    `json:"count"`
	Difficulty int    `json:"difficulty"`
	Expires    int64  `json:"expires"`
}

// CapPublicConfig 返回给前端渲染 CapWidget 所需的公开配置。
type CapPublicConfig struct {
	Enabled        bool   `json:"enabled"`
	Mode           string `json:"mode"` // local | remote
	RemoteEndpoint string `json:"remote_endpoint,omitempty"`
	ProtectLogin   bool   `json:"protect_login"`
	ProtectReg     bool   `json:"protect_register"`
	ProtectOTP     bool   `json:"protect_otp"`
}

func (m *Manager) GetCaptchaPublicConfig() CapPublicConfig {
	snap := m.settingsSvc.Snapshot()
	cfg := CapPublicConfig{
		ProtectLogin: snap.CaptchaProtectLogin,
		ProtectReg:   snap.CaptchaProtectRegister,
		ProtectOTP:   snap.CaptchaProtectOTP,
	}
	list, err := m.ActiveBySlot(SlotCaptcha)
	if err != nil || len(list) == 0 {
		return cfg
	}
	active := list[0]
	cfg.Enabled = true
	cfg.Mode = cfgStr(active.Config, "mode", "local")
	if cfg.Mode == "remote" {
		cfg.RemoteEndpoint = strings.TrimRight(cfgStr(active.Config, "remote_endpoint", ""), "/") + "/"
	}
	return cfg
}

// CreateCapChallenge 为本地模式生成一组 Cap PoW 挑战参数。
func (m *Manager) CreateCapChallenge(ctx context.Context) (*CapChallengeBundle, error) {
	list, err := m.ActiveBySlot(SlotCaptcha)
	if err != nil || len(list) == 0 {
		return nil, errors.New("未启用人机验证插件")
	}
	inst := list[0]
	if cfgStr(inst.Config, "mode", "local") != "local" {
		return nil, errors.New("当前人机验证为远端部署模式，请直连远端站点端点")
	}

	cnt, _ := strconv.Atoi(cfgStr(inst.Config, "challenge_count", "16"))
	if cnt < 1 || cnt > 64 {
		cnt = 16
	}
	diff, _ := strconv.Atoi(cfgStr(inst.Config, "difficulty", "4"))
	if diff < 1 || diff > 6 {
		diff = 4
	}

	saltBytes := make([]byte, 16)
	_, _ = rand.Read(saltBytes)
	salt := hex.EncodeToString(saltBytes)
	token := "cap_" + uuid.NewString()
	expiresAt := time.Now().Add(3 * time.Minute)

	stateBytes, _ := json.Marshal(capChallengeState{
		Salt:       salt,
		Count:      cnt,
		Difficulty: diff,
		Expires:    expiresAt.UnixMilli(),
	})
	if err := m.stateStore.SaveCapChallenge(ctx, token, stateBytes, 3*time.Minute); err != nil {
		return nil, err
	}

	out := &CapChallengeBundle{
		Token:   token,
		Expires: expiresAt.UnixMilli(),
	}
	out.Challenge.C = cnt
	out.Challenge.S = salt
	out.Challenge.D = diff
	return out, nil
}

// RedeemCapChallenge 校验客户端提交的 PoW 解集合，通过后签发一次性验证令牌。
func (m *Manager) RedeemCapChallenge(ctx context.Context, token string, solutions []int64) (verifiedToken string, expires int64, err error) {
	raw, err := m.stateStore.ConsumeCapChallenge(ctx, strings.TrimSpace(token))
	if err != nil {
		return "", 0, errors.New("人机验证挑战已过期或不存在，请重试")
	}
	var st capChallengeState
	if err := json.Unmarshal(raw, &st); err != nil {
		return "", 0, errors.New("挑战数据无效")
	}
	if time.Now().UnixMilli() > st.Expires {
		return "", 0, errors.New("人机验证挑战已超时，请刷新后重试")
	}
	if len(solutions) != st.Count {
		return "", 0, fmt.Errorf("提交的 PoW 解答数量不匹配（期望 %d，实际 %d）", st.Count, len(solutions))
	}

	prefix := strings.Repeat("0", st.Difficulty)
	for i, nonce := range solutions {
		input := fmt.Sprintf("%s:%d:%d", st.Salt, i, nonce)
		sum := sha256.Sum256([]byte(input))
		hexSum := hex.EncodeToString(sum[:])
		if !strings.HasPrefix(hexSum, prefix) {
			return "", 0, fmt.Errorf("第 %d 项工作量证明校验失败", i+1)
		}
	}

	verifiedToken = "cap_ok_" + uuid.NewString()
	exp := time.Now().Add(2 * time.Minute)
	if err := m.stateStore.SaveCapVerifiedToken(ctx, verifiedToken, 2*time.Minute); err != nil {
		return "", 0, err
	}
	return verifiedToken, exp.UnixMilli(), nil
}

// VerifyCaptchaForScene 按业务场景检查人机验证是否开启并核销客户端传来的 token。
func (m *Manager) VerifyCaptchaForScene(ctx context.Context, scene, token string) error {
	snap := m.settingsSvc.Snapshot()
	required := false
	switch scene {
	case "login":
		required = snap.CaptchaProtectLogin
	case "register":
		required = snap.CaptchaProtectRegister
	case "otp":
		required = snap.CaptchaProtectOTP
	}
	if !required {
		return nil
	}

	list, err := m.ActiveBySlot(SlotCaptcha)
	if err != nil || len(list) == 0 {
		// 开启场景保护但管理员未启用任何 captcha 插件时不阻塞合法用户；可在测试中显式启用插件验证
		return nil
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return errors.New("请先完成人机安全验证")
	}
	inst := list[0]
	mode := cfgStr(inst.Config, "mode", "local")
	if mode == "local" {
		ok, err := m.stateStore.ConsumeCapVerifiedToken(ctx, token)
		if err != nil || !ok {
			return errors.New("人机验证令牌无效或已过期，请重新验证")
		}
		return nil
	}

	// 远端部署模式：调用 Cap /siteverify
	endpoint := strings.TrimRight(cfgStr(inst.Config, "remote_endpoint", ""), "/")
	secret := cfgStr(inst.Config, "remote_secret", "")
	payload, _ := json.Marshal(map[string]string{
		"secret":   secret,
		"response": token,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/siteverify", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := NewSafeHTTPClient().Do(req)
	if err != nil {
		return fmt.Errorf("远端人机验证校验失败: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Success bool   `json:"success"`
		Error   string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil || !result.Success {
		if errors.Is(err, security.ErrStateNotFound) || result.Error != "" {
			return fmt.Errorf("人机验证未通过: %s", result.Error)
		}
		return errors.New("远端人机验证未通过")
	}
	return nil
}
