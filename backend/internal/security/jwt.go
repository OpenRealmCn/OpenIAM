package security

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// AccessClaims 为 OpenIAM 颁发的标准 Access Token 声明。
type AccessClaims struct {
	UserID     uint64 `json:"uid"`
	Username   string `json:"username"`
	Email      string `json:"email"`
	Scope      string `json:"scope,omitempty"`
	ClientID   string `json:"client_id,omitempty"`
	SessionID  string `json:"sid,omitempty"`
	IssuedAtMs int64  `json:"iat_ms,omitempty"`
	jwt.RegisteredClaims
}

// IDTokenClaims 为 OIDC 标准 ID Token 声明。
type IDTokenClaims struct {
	Username        string `json:"preferred_username,omitempty"`
	Email           string `json:"email,omitempty"`
	EmailVerified   *bool  `json:"email_verified,omitempty"`
	Name            string `json:"name,omitempty"`
	Picture         string `json:"picture,omitempty"`
	AuthorizedParty string `json:"azp,omitempty"`
	Nonce           string `json:"nonce,omitempty"`
	jwt.RegisteredClaims
}

// IDTokenOptions 描述一次 ID Token 签发。Profile/Email 字段只在对应 scope 被授予时填写。
type IDTokenOptions struct {
	UserID        uint64
	ClientID      string
	Nonce         string
	TTL           time.Duration
	Username      string
	DisplayName   string
	AvatarURL     string
	Email         string
	EmailVerified *bool
}

const (
	// accessTokenType 写入 Access Token 的 typ 头（RFC 9068），用于和同一密钥签发的 ID Token 区分，
	// 防止把 ID Token 当作 Access Token 使用。
	accessTokenType = "at+jwt"
	idTokenType     = "JWT"
)

type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWTManager 管理 RS256 密钥对、Access/ID Token 签发、验签与 JWKS 导出。
type JWTManager struct {
	mu         sync.RWMutex
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	kid        string
	issuer     string
	accessTTL  time.Duration
}

func NewJWTManager(issuer, privateKeyPath string, accessTTL time.Duration) (*JWTManager, error) {
	var priv *rsa.PrivateKey
	var err error

	if privateKeyPath != "" {
		priv, err = loadPrivateKeyFromFile(privateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("load rsa private key: %w", err)
		}
	} else {
		priv, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("generate rsa key: %w", err)
		}
	}

	if accessTTL <= 0 {
		accessTTL = 30 * time.Minute
	}

	kid := computeKeyID(&priv.PublicKey)
	return &JWTManager{
		privateKey: priv,
		publicKey:  &priv.PublicKey,
		kid:        kid,
		issuer:     issuer,
		accessTTL:  accessTTL,
	}, nil
}

// EnsurePrivateKeyFile 确保 path 处存在 RSA 私钥：已存在则校验可解析，否则生成 2048 位密钥并以 0600 权限写入。
func EnsurePrivateKeyFile(path string) error {
	if _, err := os.Stat(path); err == nil {
		_, lErr := loadPrivateKeyFromFile(path)
		return lErr
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate rsa key: %w", err)
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	return f.Close()
}

func loadPrivateKeyFromFile(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("invalid PEM block")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an RSA private key")
	}
	return rsaKey, nil
}

func computeKeyID(pub *rsa.PublicKey) string {
	der, _ := x509.MarshalPKIXPublicKey(pub)
	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(sum[:8])
}

func (m *JWTManager) PrivateKey() *rsa.PrivateKey {
	return m.privateKey
}

func (m *JWTManager) KeyID() string {
	return m.kid
}

// UpdateSettings 支持在控制台修改系统设置后热更新 Issuer 与 AccessToken TTL。
func (m *JWTManager) UpdateSettings(issuer string, accessTTL time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if issuer != "" {
		m.issuer = issuer
	}
	if accessTTL > 0 {
		m.accessTTL = accessTTL
	}
}

func (m *JWTManager) Issuer() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.issuer
}

func (m *JWTManager) AccessTTL() time.Duration {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.accessTTL
}

// GenerateAccessToken 签发 RS256 Access Token，同时返回 JTI 和过期时间。
func (m *JWTManager) GenerateAccessToken(userID uint64, username, email, scope, clientID string, customTTL ...time.Duration) (tokenStr string, jti string, expiresAt time.Time, err error) {
	return m.GenerateAccessTokenWithSession(userID, username, email, scope, clientID, "", customTTL...)
}

// GenerateAccessTokenWithSession 签发携带指定会话 ID（sid）的 RS256 Access Token。
func (m *JWTManager) GenerateAccessTokenWithSession(userID uint64, username, email, scope, clientID, sessionID string, customTTL ...time.Duration) (tokenStr string, jti string, expiresAt time.Time, err error) {
	m.mu.RLock()
	ttl := m.accessTTL
	issuer := m.issuer
	m.mu.RUnlock()
	if len(customTTL) > 0 && customTTL[0] > 0 {
		ttl = customTTL[0]
	}
	now := time.Now()
	expiresAt = now.Add(ttl)
	jti = uuid.NewString()

	claims := AccessClaims{
		UserID:     userID,
		Username:   username,
		Email:      email,
		Scope:      scope,
		ClientID:   clientID,
		SessionID:  sessionID,
		IssuedAtMs: now.UnixMilli(),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   fmt.Sprintf("%d", userID),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			ID:        jti,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = m.kid
	token.Header["typ"] = accessTokenType
	tokenStr, err = token.SignedString(m.privateKey)
	return tokenStr, jti, expiresAt, err
}

// GenerateIDToken 签发 OIDC ID Token（包含全部资料声明，供内部兼容调用）。
func (m *JWTManager) GenerateIDToken(userID uint64, username, email, displayName, avatarURL, clientID string, ttl time.Duration) (string, error) {
	return m.GenerateIDTokenWithOptions(IDTokenOptions{
		UserID:      userID,
		ClientID:    clientID,
		TTL:         ttl,
		Username:    username,
		DisplayName: displayName,
		AvatarURL:   avatarURL,
		Email:       email,
	})
}

// GenerateIDTokenWithOptions 按授予的 scope 与请求 nonce 签发 OIDC ID Token。
func (m *JWTManager) GenerateIDTokenWithOptions(opts IDTokenOptions) (string, error) {
	m.mu.RLock()
	defaultTTL := m.accessTTL
	issuer := m.issuer
	m.mu.RUnlock()
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = defaultTTL
	}
	now := time.Now()
	claims := IDTokenClaims{
		Username:        opts.Username,
		Email:           opts.Email,
		EmailVerified:   opts.EmailVerified,
		Name:            opts.DisplayName,
		Picture:         opts.AvatarURL,
		AuthorizedParty: opts.ClientID,
		Nonce:           opts.Nonce,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   fmt.Sprintf("%d", opts.UserID),
			Audience:  jwt.ClaimStrings{opts.ClientID},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			ID:        uuid.NewString(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = m.kid
	token.Header["typ"] = idTokenType
	return token.SignedString(m.privateKey)
}

// ParseAccessToken 验证并解析 Access Token：只接受 RS256、typ=at+jwt 且签发者为本系统的令牌。
func (m *JWTManager) ParseAccessToken(tokenStr string) (*AccessClaims, error) {
	issuer := m.Issuer()
	opts := []jwt.ParserOption{jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()})}
	if issuer != "" {
		opts = append(opts, jwt.WithIssuer(issuer))
	}
	token, err := jwt.ParseWithClaims(tokenStr, &AccessClaims{}, func(t *jwt.Token) (interface{}, error) {
		if typ, _ := t.Header["typ"].(string); typ != accessTokenType {
			return nil, errors.New("not an access token")
		}
		return m.publicKey, nil
	}, opts...)
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*AccessClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid access token")
	}
	return claims, nil
}

// JWKS 导出标准 RSA 公钥集合（供 OIDC / 第三方应用验签）。
func (m *JWTManager) JWKS() JWKS {
	n := base64.RawURLEncoding.EncodeToString(m.publicKey.N.Bytes())
	eBytes := big.NewInt(int64(m.publicKey.E)).Bytes()
	e := base64.RawURLEncoding.EncodeToString(eBytes)
	return JWKS{
		Keys: []JWK{
			{
				Kty: "RSA",
				Use: "sig",
				Alg: "RS256",
				Kid: m.kid,
				N:   n,
				E:   e,
			},
		},
	}
}
