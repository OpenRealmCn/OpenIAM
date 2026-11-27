package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/openrealm/openiam/internal/audit"
	"github.com/openrealm/openiam/internal/middleware"
	"github.com/openrealm/openiam/internal/models"
	"github.com/openrealm/openiam/internal/security"
	"gorm.io/gorm"
)

type OAuthClientHandler struct {
	db       *gorm.DB
	auditSvc *audit.Service
}

func NewOAuthClientHandler(db *gorm.DB, auditSvc *audit.Service) *OAuthClientHandler {
	return &OAuthClientHandler{db: db, auditSvc: auditSvc}
}

func generateClientCredential(prefix string, byteLen int) string {
	b := make([]byte, byteLen)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

func (h *OAuthClientHandler) List(c *gin.Context) {
	domain := strings.TrimSpace(c.Query("domain"))
	q := h.db.Model(&models.OAuthClient{})
	if domain != "" && domain != "*" {
		q = q.Where("domain_code = ?", domain)
	}
	var clients []models.OAuthClient
	if err := q.Order("id DESC").Find(&clients).Error; err != nil {
		Fail(c, http.StatusInternalServerError, "查询 OAuth 应用失败")
		return
	}
	OK(c, clients)
}

type createOAuthClientReq struct {
	Name           string   `json:"name" binding:"required"`
	Description    string   `json:"description"`
	DomainCode     string   `json:"domain_code"`
	RedirectURIs   []string `json:"redirect_uris" binding:"required,min=1"`
	GrantTypes     []string `json:"grant_types"`
	Scopes         []string `json:"scopes"`
	RequirePKCE    *bool    `json:"require_pkce"`
	IsConfidential *bool    `json:"is_confidential"`
}

func (h *OAuthClientHandler) Create(c *gin.Context) {
	var req createOAuthClientReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, http.StatusBadRequest, "参数错误: "+err.Error())
		return
	}

	domain := strings.TrimSpace(req.DomainCode)
	if domain == "" {
		domain = middleware.ResolveDomain(c)
	}
	grantTypes := req.GrantTypes
	if len(grantTypes) == 0 {
		grantTypes = []string{"authorization_code", "refresh_token"}
	}
	scopes := req.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}
	requirePKCE := true
	if req.RequirePKCE != nil {
		requirePKCE = *req.RequirePKCE
	}
	isConfidential := true
	if req.IsConfidential != nil {
		isConfidential = *req.IsConfidential
	}

	clientID := generateClientCredential("oiam_cli_", 12)
	plainSecret := ""
	secretHash := ""
	if isConfidential {
		plainSecret = generateClientCredential("oiam_sec_", 24)
		var err error
		secretHash, err = security.HashPassword(plainSecret)
		if err != nil {
			Fail(c, http.StatusInternalServerError, "生成应用密钥失败")
			return
		}
	}

	client := models.OAuthClient{
		ClientID:         clientID,
		ClientSecretHash: secretHash,
		Name:             strings.TrimSpace(req.Name),
		Description:      strings.TrimSpace(req.Description),
		DomainCode:       domain,
		RedirectURIs:     models.StringSlice(req.RedirectURIs),
		GrantTypes:       models.StringSlice(grantTypes),
		Scopes:           models.StringSlice(scopes),
		RequirePKCE:      requirePKCE,
		IsConfidential:   isConfidential,
		Status:           "active",
		CreatedBy:        CurrentUserID(c),
	}
	if err := h.db.Create(&client).Error; err != nil {
		Fail(c, http.StatusInternalServerError, "创建 OAuth 应用失败: "+err.Error())
		return
	}

	h.auditSvc.RecordFromContext(c, audit.Entry{
		DomainCode:   domain,
		Action:       "oauth_client.create",
		ResourceType: "oauth_client",
		ResourceID:   client.ClientID,
		After:        client,
		Status:       "success",
	})

	Created(c, gin.H{
		"client":        client,
		"client_secret": plainSecret, // 仅在创建或轮换时明文返回一次
	})
}

type updateOAuthClientReq struct {
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	RedirectURIs   []string `json:"redirect_uris"`
	GrantTypes     []string `json:"grant_types"`
	Scopes         []string `json:"scopes"`
	RequirePKCE    *bool    `json:"require_pkce"`
	IsConfidential *bool    `json:"is_confidential"`
	Status         string   `json:"status"`
}

func (h *OAuthClientHandler) Update(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		Fail(c, http.StatusBadRequest, "无效的应用 ID")
		return
	}
	var client models.OAuthClient
	if err := h.db.First(&client, id).Error; err != nil {
		Fail(c, http.StatusNotFound, "OAuth 应用不存在")
		return
	}
	before := client

	var req updateOAuthClientReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, http.StatusBadRequest, "参数错误")
		return
	}
	if req.Name != "" {
		client.Name = strings.TrimSpace(req.Name)
	}
	if req.Description != "" {
		client.Description = strings.TrimSpace(req.Description)
	}
	if len(req.RedirectURIs) > 0 {
		client.RedirectURIs = models.StringSlice(req.RedirectURIs)
	}
	if len(req.GrantTypes) > 0 {
		client.GrantTypes = models.StringSlice(req.GrantTypes)
	}
	if len(req.Scopes) > 0 {
		client.Scopes = models.StringSlice(req.Scopes)
	}
	if req.RequirePKCE != nil {
		client.RequirePKCE = *req.RequirePKCE
	}
	if req.IsConfidential != nil {
		client.IsConfidential = *req.IsConfidential
	}
	if req.Status != "" {
		client.Status = req.Status
	}

	if err := h.db.Save(&client).Error; err != nil {
		Fail(c, http.StatusInternalServerError, "更新 OAuth 应用失败")
		return
	}

	h.auditSvc.RecordFromContext(c, audit.Entry{
		DomainCode:   client.DomainCode,
		Action:       "oauth_client.update",
		ResourceType: "oauth_client",
		ResourceID:   client.ClientID,
		Before:       before,
		After:        client,
		Status:       "success",
	})
	OK(c, client)
}

func (h *OAuthClientHandler) RotateSecret(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		Fail(c, http.StatusBadRequest, "无效的应用 ID")
		return
	}
	var client models.OAuthClient
	if err := h.db.First(&client, id).Error; err != nil {
		Fail(c, http.StatusNotFound, "OAuth 应用不存在")
		return
	}
	if !client.IsConfidential {
		Fail(c, http.StatusBadRequest, "Public 客户端无需密钥")
		return
	}

	newSecret := generateClientCredential("oiam_sec_", 24)
	hash, err := security.HashPassword(newSecret)
	if err != nil {
		Fail(c, http.StatusInternalServerError, "密钥生成失败")
		return
	}
	if err := h.db.Model(&client).Update("client_secret_hash", hash).Error; err != nil {
		Fail(c, http.StatusInternalServerError, "轮换密钥失败")
		return
	}

	h.auditSvc.RecordFromContext(c, audit.Entry{
		DomainCode:   client.DomainCode,
		Action:       "oauth_client.rotate_secret",
		ResourceType: "oauth_client",
		ResourceID:   client.ClientID,
		Status:       "success",
	})
	OK(c, gin.H{
		"client_id":     client.ClientID,
		"client_secret": newSecret,
	})
}

func (h *OAuthClientHandler) Delete(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		Fail(c, http.StatusBadRequest, "无效的应用 ID")
		return
	}
	var client models.OAuthClient
	if err := h.db.First(&client, id).Error; err != nil {
		Fail(c, http.StatusNotFound, "OAuth 应用不存在")
		return
	}
	if err := h.db.Delete(&client).Error; err != nil {
		Fail(c, http.StatusInternalServerError, "删除 OAuth 应用失败")
		return
	}

	h.auditSvc.RecordFromContext(c, audit.Entry{
		DomainCode:   client.DomainCode,
		Action:       "oauth_client.delete",
		ResourceType: "oauth_client",
		ResourceID:   client.ClientID,
		Before:       client,
		Status:       "success",
	})
	OK(c, gin.H{"deleted": true})
}

// ListMine 返回当前登录用户自己创建的 OAuth 应用列表。
func (h *OAuthClientHandler) ListMine(c *gin.Context) {
	uid := CurrentUserID(c)
	var clients []models.OAuthClient
	if err := h.db.Where("created_by = ?", uid).Order("id DESC").Find(&clients).Error; err != nil {
		Fail(c, http.StatusInternalServerError, "查询个人 OAuth 应用失败")
		return
	}
	OK(c, clients)
}

// CreateMine 允许拥有 oauth_clients:create_own 权限的普通用户创建自己的 OAuth 应用。
func (h *OAuthClientHandler) CreateMine(c *gin.Context) {
	h.Create(c)
}

// UpdateMine 允许用户更新自己创建的 OAuth 应用。
func (h *OAuthClientHandler) UpdateMine(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		Fail(c, http.StatusBadRequest, "无效的应用 ID")
		return
	}
	var client models.OAuthClient
	if err := h.db.Where("id = ? AND created_by = ?", id, CurrentUserID(c)).First(&client).Error; err != nil {
		Fail(c, http.StatusNotFound, "应用不存在或无权操作")
		return
	}
	h.Update(c)
}

// RotateSecretMine 允许用户轮换自己创建的 OAuth 应用密钥。
func (h *OAuthClientHandler) RotateSecretMine(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		Fail(c, http.StatusBadRequest, "无效的应用 ID")
		return
	}
	var client models.OAuthClient
	if err := h.db.Where("id = ? AND created_by = ?", id, CurrentUserID(c)).First(&client).Error; err != nil {
		Fail(c, http.StatusNotFound, "应用不存在或无权操作")
		return
	}
	h.RotateSecret(c)
}

// DeleteMine 允许用户删除自己创建的 OAuth 应用。
func (h *OAuthClientHandler) DeleteMine(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		Fail(c, http.StatusBadRequest, "无效的应用 ID")
		return
	}
	var client models.OAuthClient
	if err := h.db.Where("id = ? AND created_by = ?", id, CurrentUserID(c)).First(&client).Error; err != nil {
		Fail(c, http.StatusNotFound, "应用不存在或无权操作")
		return
	}
	h.Delete(c)
}
