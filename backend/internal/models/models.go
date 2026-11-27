package models

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"
)

// StringSlice 用于在 MySQL JSON 列和 SQLite 测试库之间无缝存储字符串切片。
type StringSlice []string

func (s StringSlice) Value() (driver.Value, error) {
	if s == nil {
		return "[]", nil
	}
	b, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	return string(b), nil
}

func (s *StringSlice) Scan(value interface{}) error {
	if value == nil {
		*s = []string{}
		return nil
	}
	var bytes []byte
	switch v := value.(type) {
	case []byte:
		bytes = v
	case string:
		bytes = []byte(v)
	default:
		return fmt.Errorf("unsupported StringSlice type: %T", value)
	}
	if len(bytes) == 0 {
		*s = []string{}
		return nil
	}
	return json.Unmarshal(bytes, s)
}

// JSONMap 用于存储结构化 JSON 对象（extra_config, before_state, after_state, raw_profile 等）。
type JSONMap map[string]interface{}

func (m JSONMap) Value() (driver.Value, error) {
	if m == nil {
		return nil, nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return string(b), nil
}

func (m *JSONMap) Scan(value interface{}) error {
	if value == nil {
		*m = nil
		return nil
	}
	var bytes []byte
	switch v := value.(type) {
	case []byte:
		bytes = v
	case string:
		bytes = []byte(v)
	default:
		return fmt.Errorf("unsupported JSONMap type: %T", value)
	}
	if len(bytes) == 0 || string(bytes) == "null" {
		*m = nil
		return nil
	}
	return json.Unmarshal(bytes, m)
}

// Domain 代表 OpenRealm 平台中的业务域或子应用租户。
type Domain struct {
	ID          uint64    `gorm:"primaryKey" json:"id"`
	Code        string    `gorm:"size:64;uniqueIndex;not null" json:"code"`
	Name        string    `gorm:"size:128;not null" json:"name"`
	Description string    `gorm:"size:512;not null;default:''" json:"description"`
	Status      string    `gorm:"size:32;not null;default:'active'" json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// User 代表平台身份主体。
type User struct {
	ID           uint64     `gorm:"primaryKey" json:"id"`
	Username     string     `gorm:"size:64;uniqueIndex;not null" json:"username"`
	Email        string     `gorm:"size:128;uniqueIndex;not null" json:"email"`
	DisplayName  string     `gorm:"size:128;not null;default:''" json:"display_name"`
	PasswordHash string     `gorm:"size:255;not null;default:''" json:"-"`
	AvatarURL    string     `gorm:"size:512;not null;default:''" json:"avatar_url"`
	Status       string     `gorm:"size:32;not null;default:'active'" json:"status"` // active | disabled
	LastLoginAt  *time.Time `json:"last_login_at"`
	LastLoginIP  string     `gorm:"size:64;not null;default:''" json:"last_login_ip"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

// Role 代表域内角色，权限关系由 Casbin 管理。
type Role struct {
	ID          uint64    `gorm:"primaryKey" json:"id"`
	DomainCode  string    `gorm:"size:64;not null;uniqueIndex:uk_roles_domain_code" json:"domain_code"`
	Code        string    `gorm:"size:64;not null;uniqueIndex:uk_roles_domain_code" json:"code"`
	Name        string    `gorm:"size:128;not null" json:"name"`
	Description string    `gorm:"size:512;not null;default:''" json:"description"`
	IsSystem    bool      `gorm:"not null;default:false" json:"is_system"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Permission 代表域内资源权限点元数据，与 Casbin 策略 p(role, domain, resource, action) 对应。
type Permission struct {
	ID          uint64    `gorm:"primaryKey" json:"id"`
	DomainCode  string    `gorm:"size:64;not null;uniqueIndex:uk_permissions_domain_code" json:"domain_code"`
	Code        string    `gorm:"size:128;not null;uniqueIndex:uk_permissions_domain_code" json:"code"`
	Name        string    `gorm:"size:128;not null" json:"name"`
	Resource    string    `gorm:"size:255;not null" json:"resource"`
	Action      string    `gorm:"size:64;not null" json:"action"`
	Description string    `gorm:"size:512;not null;default:''" json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// OAuthClient 代表接入 OpenIAM 的第三方或 OpenRealm 内部 OAuth 2.0 / OIDC 应用。
type OAuthClient struct {
	ID               uint64      `gorm:"primaryKey" json:"id"`
	ClientID         string      `gorm:"size:128;uniqueIndex;not null" json:"client_id"`
	ClientSecretHash string      `gorm:"size:255;not null;default:''" json:"-"`
	Name             string      `gorm:"size:128;not null" json:"name"`
	Description      string      `gorm:"size:512;not null;default:''" json:"description"`
	DomainCode       string      `gorm:"size:64;not null;default:'openiam'" json:"domain_code"`
	RedirectURIs     StringSlice `gorm:"type:json;not null" json:"redirect_uris"`
	GrantTypes       StringSlice `gorm:"type:json;not null" json:"grant_types"`
	Scopes           StringSlice `gorm:"type:json;not null" json:"scopes"`
	RequirePKCE      bool        `gorm:"not null;default:true" json:"require_pkce"`
	IsConfidential   bool        `gorm:"not null;default:true" json:"is_confidential"`
	Status           string      `gorm:"size:32;not null;default:'active'" json:"status"`
	CreatedBy        uint64      `gorm:"not null;default:0" json:"created_by"`
	CreatedAt        time.Time   `json:"created_at"`
	UpdatedAt        time.Time   `json:"updated_at"`
}

// OAuthProvider 代表一个配置好的外部 OAuth2/OIDC 联合登录提供方实例。
type OAuthProvider struct {
	ID           uint64    `gorm:"primaryKey" json:"id"`
	Name         string    `gorm:"size:64;uniqueIndex;not null" json:"name"`
	PluginType   string    `gorm:"size:64;not null" json:"plugin_type"`
	DisplayName  string    `gorm:"size:128;not null" json:"display_name"`
	ClientID     string    `gorm:"size:255;not null;default:''" json:"client_id"`
	ClientSecret string    `gorm:"size:512;not null;default:''" json:"-"`
	Scopes       string    `gorm:"size:512;not null;default:''" json:"scopes"`
	ExtraConfig  JSONMap   `gorm:"type:json" json:"extra_config"`
	AutoRegister bool      `gorm:"not null;default:true" json:"auto_register"`
	Enabled      bool      `gorm:"not null;default:false" json:"enabled"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// UserIdentity 将 OpenIAM 本地用户与外部 OAuth 联合登录身份绑定。
type UserIdentity struct {
	ID               uint64    `gorm:"primaryKey" json:"id"`
	UserID           uint64    `gorm:"index;not null" json:"user_id"`
	ProviderName     string    `gorm:"size:64;not null;uniqueIndex:uk_user_identities_provider_ext" json:"provider_name"`
	ExternalUserID   string    `gorm:"size:255;not null;uniqueIndex:uk_user_identities_provider_ext" json:"external_user_id"`
	ExternalUsername string    `gorm:"size:255;not null;default:''" json:"external_username"`
	ExternalEmail    string    `gorm:"size:255;not null;default:''" json:"external_email"`
	RawProfile       JSONMap   `gorm:"type:json" json:"raw_profile"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// AuditLog 记录认证事件及所有用户/域/角色/权限/OAuth 管理操作前后快照。
type AuditLog struct {
	ID            uint64    `gorm:"primaryKey" json:"id"`
	ActorID       uint64    `gorm:"index;not null;default:0" json:"actor_id"`
	ActorUsername string    `gorm:"size:64;not null;default:''" json:"actor_username"`
	DomainCode    string    `gorm:"size:64;index;not null;default:'openiam'" json:"domain_code"`
	Action        string    `gorm:"size:128;index;not null" json:"action"`
	ResourceType  string    `gorm:"size:64;index;not null" json:"resource_type"`
	ResourceID    string    `gorm:"size:128;index;not null;default:''" json:"resource_id"`
	BeforeState   JSONMap   `gorm:"type:json" json:"before_state"`
	AfterState    JSONMap   `gorm:"type:json" json:"after_state"`
	IPAddress     string    `gorm:"size:64;not null;default:''" json:"ip_address"`
	UserAgent     string    `gorm:"size:512;not null;default:''" json:"user_agent"`
	Status        string    `gorm:"size:32;not null;default:'success'" json:"status"`
	ErrorMessage  string    `gorm:"size:512;not null;default:''" json:"error_message"`
	CreatedAt     time.Time `gorm:"index" json:"created_at"`
}

// SystemVersionHistory 记录应用启动检查与数据库迁移历史。
type SystemVersionHistory struct {
	ID            uint64    `gorm:"primaryKey" json:"id"`
	AppVersion    string    `gorm:"size:32;not null" json:"app_version"`
	SchemaVersion uint64    `gorm:"not null" json:"schema_version"`
	Action        string    `gorm:"size:64;not null" json:"action"`
	Status        string    `gorm:"size:32;not null" json:"status"`
	Details       string    `gorm:"size:1024;not null;default:''" json:"details"`
	CreatedAt     time.Time `json:"created_at"`
}

func (SystemVersionHistory) TableName() string {
	return "system_version_history"
}
