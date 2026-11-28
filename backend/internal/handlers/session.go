package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/openrealm/openiam/internal/audit"
	"github.com/openrealm/openiam/internal/clientip"
	"github.com/openrealm/openiam/internal/middleware"
	"github.com/openrealm/openiam/internal/models"
	"github.com/openrealm/openiam/internal/rbac"
	"github.com/openrealm/openiam/internal/risk"
	"github.com/openrealm/openiam/internal/security"
	"github.com/openrealm/openiam/internal/settings"
	"gorm.io/gorm"
)

func hashRefreshToken(rt string) string {
	sum := sha256.Sum256([]byte(rt))
	return hex.EncodeToString(sum[:])
}

// createSessionAndTokens 统一为用户签发在线设备会话、带 sid 的 Access Token 以及单次轮换 Refresh Token。
func createSessionAndTokens(
	c *gin.Context,
	db *gorm.DB,
	jwtMgr *security.JWTManager,
	stateStore *security.StateStore,
	settingsSvc *settings.Service,
	user models.User,
) (accessToken, refreshToken, sessionID string, expiresIn int64, err error) {
	snap := settingsSvc.Snapshot()
	sessionID = uuid.NewString()

	accessToken, _, _, err = jwtMgr.GenerateAccessTokenWithSession(
		user.ID, user.Username, user.Email, "openid profile email", "", sessionID,
	)
	if err != nil {
		return "", "", "", 0, err
	}

	refreshToken = uuid.NewString()
	if err := stateStore.SaveRefreshToken(c.Request.Context(), refreshToken, security.RefreshTokenRecord{
		UserID:    user.ID,
		Username:  user.Username,
		SessionID: sessionID,
	}, snap.JWTRefreshTTL); err != nil {
		return "", "", "", 0, err
	}

	now := time.Now()
	ua := truncateStr(c.GetHeader("User-Agent"), 512)
	fp := headerFingerprint(c)
	geo := headerGeo(c, settingsSvc)
	ip := clientip.FromGin(c)

	_ = db.Create(&models.UserSession{
		SessionID:         sessionID,
		UserID:            user.ID,
		RefreshTokenHash:  hashRefreshToken(refreshToken),
		DeviceName:        risk.ParseDeviceName(ua),
		DeviceFingerprint: fp,
		UserAgent:         ua,
		IPAddress:         ip,
		Location:          risk.ResolveLocation(ip, geo),
		LastActiveAt:      now,
		ExpiresAt:         now.Add(snap.JWTRefreshTTL),
	}).Error

	return accessToken, refreshToken, sessionID, int64(jwtMgr.AccessTTL().Seconds()), nil
}

type SessionHandler struct {
	db          *gorm.DB
	stateStore  *security.StateStore
	enforcer    *rbac.Enforcer
	auditSvc    *audit.Service
	settingsSvc *settings.Service
}

func NewSessionHandler(
	db *gorm.DB,
	stateStore *security.StateStore,
	enforcer *rbac.Enforcer,
	auditSvc *audit.Service,
	settingsSvc *settings.Service,
) *SessionHandler {
	return &SessionHandler{
		db:          db,
		stateStore:  stateStore,
		enforcer:    enforcer,
		auditSvc:    auditSvc,
		settingsSvc: settingsSvc,
	}
}

// revokeTTL 返回会话下线标记的保留时长：不短于完整的刷新令牌有效期，避免标记先于仍可轮换的刷新令牌过期。
func (h *SessionHandler) revokeTTL(expiresAt time.Time) time.Duration {
	ttl := time.Until(expiresAt)
	if full := h.settingsSvc.Snapshot().JWTRefreshTTL; full > ttl {
		ttl = full
	}
	return ttl
}

type sessionView struct {
	models.UserSession
	Username  string `json:"username,omitempty"`
	Email     string `json:"email,omitempty"`
	IsCurrent bool   `json:"is_current"`
}

func (h *SessionHandler) ListMySessions(c *gin.Context) {
	uid := CurrentUserID(c)
	curSID := c.GetString("session_id")
	var rows []models.UserSession
	if err := h.db.Where("user_id = ? AND revoked_at IS NULL AND expires_at > ?", uid, time.Now()).
		Order("last_active_at DESC").Find(&rows).Error; err != nil {
		Fail(c, http.StatusInternalServerError, "查询在线会话失败")
		return
	}
	out := make([]sessionView, 0, len(rows))
	for _, r := range rows {
		out = append(out, sessionView{
			UserSession: r,
			IsCurrent:   curSID != "" && r.SessionID == curSID,
		})
	}
	OK(c, out)
}

func (h *SessionHandler) RevokeMySession(c *gin.Context) {
	sid := strings.TrimSpace(c.Param("sid"))
	uid := CurrentUserID(c)
	var row models.UserSession
	if err := h.db.Where("session_id = ? AND user_id = ?", sid, uid).First(&row).Error; err != nil {
		Fail(c, http.StatusNotFound, "会话不存在")
		return
	}
	now := time.Now()
	_ = h.db.Model(&row).Update("revoked_at", &now).Error
	_ = h.stateStore.RevokeSession(c.Request.Context(), sid, h.revokeTTL(row.ExpiresAt))
	h.auditSvc.RecordFromContext(c, audit.Entry{
		DomainCode:   rbac.DefaultDomain,
		Action:       "auth.session.revoke",
		ResourceType: "user_session",
		ResourceID:   sid,
		Status:       "success",
	})
	OK(c, gin.H{"revoked": true})
}

type revokeAllReq struct {
	KeepCurrent bool `json:"keep_current"`
}

func (h *SessionHandler) RevokeAllMySessions(c *gin.Context) {
	var req revokeAllReq
	_ = c.ShouldBindJSON(&req)
	uid := CurrentUserID(c)
	curSID := c.GetString("session_id")

	var rows []models.UserSession
	q := h.db.Where("user_id = ? AND revoked_at IS NULL", uid)
	if req.KeepCurrent && curSID != "" {
		q = q.Where("session_id <> ?", curSID)
	}
	_ = q.Find(&rows).Error

	now := time.Now()
	for _, r := range rows {
		_ = h.db.Model(&r).Update("revoked_at", &now).Error
		_ = h.stateStore.RevokeSession(c.Request.Context(), r.SessionID, h.revokeTTL(r.ExpiresAt))
	}
	if !req.KeepCurrent {
		_ = h.stateStore.RevokeUserTokens(c.Request.Context(), uid)
	}
	h.auditSvc.RecordFromContext(c, audit.Entry{
		DomainCode:   rbac.DefaultDomain,
		Action:       "auth.session.revoke_all",
		ResourceType: "user",
		ResourceID:   fmt.Sprintf("%d", uid),
		After:        map[string]interface{}{"count": len(rows), "keep_current": req.KeepCurrent},
		Status:       "success",
	})
	OK(c, gin.H{"revoked_count": len(rows)})
}

// ListAllSessions 管理员查看全部在线会话（超管看全平台，域管理员限定查看本域用户会话）。
func (h *SessionHandler) ListAllSessions(c *gin.Context) {
	domain, all := scopedDomain(c, h.enforcer)
	q := h.db.Where("revoked_at IS NULL AND expires_at > ?", time.Now())
	if !all {
		ids := domainUserIDs(h.enforcer, domain)
		if len(ids) == 0 {
			OK(c, []sessionView{})
			return
		}
		q = q.Where("user_id IN ?", ids)
	}
	var rows []models.UserSession
	if err := q.Order("last_active_at DESC").Limit(200).Find(&rows).Error; err != nil {
		Fail(c, http.StatusInternalServerError, "查询在线会话失败")
		return
	}

	userIDSet := make([]uint64, 0, len(rows))
	seen := make(map[uint64]bool)
	for _, r := range rows {
		if !seen[r.UserID] {
			seen[r.UserID] = true
			userIDSet = append(userIDSet, r.UserID)
		}
	}
	userMap := make(map[uint64]models.User)
	if len(userIDSet) > 0 {
		var users []models.User
		_ = h.db.Where("id IN ?", userIDSet).Find(&users).Error
		for _, u := range users {
			userMap[u.ID] = u
		}
	}

	curSID := c.GetString("session_id")
	out := make([]sessionView, 0, len(rows))
	for _, r := range rows {
		u := userMap[r.UserID]
		out = append(out, sessionView{
			UserSession: r,
			Username:    u.Username,
			Email:       u.Email,
			IsCurrent:   curSID != "" && r.SessionID == curSID,
		})
	}
	OK(c, out)
}

func (h *SessionHandler) AdminRevokeSession(c *gin.Context) {
	sid := strings.TrimSpace(c.Param("sid"))
	var row models.UserSession
	if err := h.db.Where("session_id = ?", sid).First(&row).Error; err != nil {
		Fail(c, http.StatusNotFound, "会话不存在")
		return
	}
	if protectSuperAdminTarget(c, h.enforcer, row.UserID) || !requireTargetInDomain(c, h.enforcer, row.UserID) {
		return
	}
	now := time.Now()
	_ = h.db.Model(&row).Update("revoked_at", &now).Error
	_ = h.stateStore.RevokeSession(c.Request.Context(), sid, h.revokeTTL(row.ExpiresAt))
	h.auditSvc.RecordFromContext(c, audit.Entry{
		DomainCode:   middleware.ResolveDomain(c),
		Action:       "admin.session.revoke",
		ResourceType: "user_session",
		ResourceID:   sid,
		After:        map[string]interface{}{"target_user_id": row.UserID},
		Status:       "success",
	})
	OK(c, gin.H{"revoked": true})
}

func (h *SessionHandler) AdminRevokeUserSessions(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		Fail(c, http.StatusBadRequest, "无效的用户 ID")
		return
	}
	if protectSuperAdminTarget(c, h.enforcer, id) || !requireTargetInDomain(c, h.enforcer, id) {
		return
	}
	var rows []models.UserSession
	_ = h.db.Where("user_id = ? AND revoked_at IS NULL", id).Find(&rows).Error
	now := time.Now()
	for _, r := range rows {
		_ = h.db.Model(&r).Update("revoked_at", &now).Error
		_ = h.stateStore.RevokeSession(c.Request.Context(), r.SessionID, h.revokeTTL(r.ExpiresAt))
	}
	_ = h.stateStore.RevokeUserTokens(c.Request.Context(), id)
	h.auditSvc.RecordFromContext(c, audit.Entry{
		DomainCode:   middleware.ResolveDomain(c),
		Action:       "admin.session.revoke_all",
		ResourceType: "user",
		ResourceID:   fmt.Sprintf("%d", id),
		After:        map[string]interface{}{"count": len(rows)},
		Status:       "success",
	})
	OK(c, gin.H{"revoked_count": len(rows)})
}
