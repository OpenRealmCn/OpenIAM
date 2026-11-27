package audit

import (
	"encoding/json"

	"github.com/gin-gonic/gin"
	"github.com/openrealm/openiam/internal/models"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// Entry 描述一条审计事件。
type Entry struct {
	ActorID       uint64
	ActorUsername string
	DomainCode    string
	Action        string
	ResourceType  string
	ResourceID    string
	Before        interface{}
	After         interface{}
	IPAddress     string
	UserAgent     string
	Status        string
	ErrorMessage  string
}

// Service 负责持久化认证事件与用户/域/角色/权限/OAuth 管理操作审计快照。
type Service struct {
	db     *gorm.DB
	logger *zap.Logger
}

func NewService(db *gorm.DB, logger *zap.Logger) *Service {
	return &Service{db: db, logger: logger}
}

// RecordFromContext 从 Gin 请求上下文提取操作者与 IP/UA 并记录审计日志。
func (s *Service) RecordFromContext(c *gin.Context, entry Entry) {
	if c != nil {
		if entry.IPAddress == "" {
			entry.IPAddress = c.ClientIP()
		}
		if entry.UserAgent == "" {
			entry.UserAgent = c.Request.UserAgent()
		}
		if entry.ActorID == 0 {
			if uid, ok := c.Get("user_id"); ok {
				if id, ok2 := uid.(uint64); ok2 {
					entry.ActorID = id
				}
			}
		}
		if entry.ActorUsername == "" {
			if uname, ok := c.Get("username"); ok {
				if str, ok2 := uname.(string); ok2 {
					entry.ActorUsername = str
				}
			}
		}
		if entry.DomainCode == "" {
			if dom, ok := c.Get("domain"); ok {
				if str, ok2 := dom.(string); ok2 {
					entry.DomainCode = str
				}
			}
		}
	}
	s.Record(entry)
}

// Record 直接写入审计日志，自动序列化并脱敏敏感字段。
func (s *Service) Record(entry Entry) {
	if s == nil || s.db == nil {
		return
	}
	if entry.DomainCode == "" {
		entry.DomainCode = "openiam"
	}
	if entry.Status == "" {
		entry.Status = "success"
	}

	logRow := models.AuditLog{
		ActorID:       entry.ActorID,
		ActorUsername: entry.ActorUsername,
		DomainCode:    entry.DomainCode,
		Action:        entry.Action,
		ResourceType:  entry.ResourceType,
		ResourceID:    entry.ResourceID,
		BeforeState:   toSanitizedJSONMap(entry.Before),
		AfterState:    toSanitizedJSONMap(entry.After),
		IPAddress:     truncate(entry.IPAddress, 64),
		UserAgent:     truncate(entry.UserAgent, 512),
		Status:        entry.Status,
		ErrorMessage:  truncate(entry.ErrorMessage, 512),
	}

	if err := s.db.Create(&logRow).Error; err != nil && s.logger != nil {
		s.logger.Error("failed to persist audit log", zap.Error(err), zap.String("action", entry.Action))
	}
}

func toSanitizedJSONMap(v interface{}) models.JSONMap {
	if v == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return models.JSONMap{"_raw_error": err.Error()}
	}
	var m models.JSONMap
	if err := json.Unmarshal(b, &m); err != nil {
		// 如果原始值不是 JSON 对象（如切片），包装为 items
		var anyVal interface{}
		if err2 := json.Unmarshal(b, &anyVal); err2 == nil {
			return models.JSONMap{"value": anyVal}
		}
		return nil
	}
	sanitizeMap(m)
	return m
}

func sanitizeMap(m map[string]interface{}) {
	for k, val := range m {
		if isSensitiveKey(k) {
			m[k] = "***REDACTED***"
			continue
		}
		sanitizeValue(val)
		if sub, ok := val.(map[string]interface{}); ok {
			sanitizeMap(sub)
		}
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}
