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
	IssuedAtMs int64  `json:"iat_ms,omitempty"`
	jwt.RegisteredClaims
}

// IDTokenClaims 为 OIDC 标准 ID Token 声明。
type IDTokenClaims struct {
	Username        string `json:"preferred_username"`
	Email           string `json:"email"`
	Name            string `json:"name,omitempty"`
	Picture         string `json:"picture,omitempty"`
	AuthorizedParty string `json:"azp,omitempty"`
	jwt.RegisteredClaims
}

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
	tokenStr, err = token.SignedString(m.privateKey)
	return tokenStr, jti, expiresAt, err
}

// GenerateIDToken 签发 OIDC ID Token。
func (m *JWTManager) GenerateIDToken(userID uint64, username, email, displayName, avatarURL, clientID string, ttl time.Duration) (string, error) {
	m.mu.RLock()
	defaultTTL := m.accessTTL
	issuer := m.issuer
	m.mu.RUnlock()
	if ttl <= 0 {
		ttl = defaultTTL
	}
	now := time.Now()
	claims := IDTokenClaims{
		Username:        username,
		Email:           email,
		Name:            displayName,
		Picture:         avatarURL,
		AuthorizedParty: clientID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   fmt.Sprintf("%d", userID),
			Audience:  jwt.ClaimStrings{clientID},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			ID:        uuid.NewString(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = m.kid
	return token.SignedString(m.privateKey)
}

// ParseAccessToken 验证并解析 Access Token。
func (m *JWTManager) ParseAccessToken(tokenStr string) (*AccessClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &AccessClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return m.publicKey, nil
	})
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
