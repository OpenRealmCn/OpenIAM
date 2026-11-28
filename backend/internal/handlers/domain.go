package handlers

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/openrealm/openiam/internal/audit"
	"github.com/openrealm/openiam/internal/models"
	"github.com/openrealm/openiam/internal/rbac"
	"gorm.io/gorm"
)

type DomainHandler struct {
	enforcer *rbac.Enforcer
	db       *gorm.DB
	auditSvc *audit.Service
}

func NewDomainHandler(db *gorm.DB, auditSvc *audit.Service, enforcer *rbac.Enforcer) *DomainHandler {
	return &DomainHandler{db: db, auditSvc: auditSvc, enforcer: enforcer}
}

func (h *DomainHandler) List(c *gin.Context) {
	var domains []models.Domain
	q := h.db.Order("id ASC")
	if uid := CurrentUserID(c); !isSuperAdmin(h.enforcer, uid) {
		// 非超级管理员只能看到自己持有角色的域
		roles, _ := h.enforcer.GetAllUserRoles(uid)
		codes := make([]string, 0, len(roles))
		for code := range roles {
			codes = append(codes, code)
		}
		if len(codes) == 0 {
			OK(c, []models.Domain{})
			return
		}
		q = q.Where("code IN ?", codes)
	}
	if err := q.Find(&domains).Error; err != nil {
		Fail(c, http.StatusInternalServerError, "查询域列表失败")
		return
	}
	OK(c, domains)
}

type createDomainReq struct {
	Code        string `json:"code" binding:"required,min=2,max=64"`
	Name        string `json:"name" binding:"required"`
	Description string `json:"description"`
	Status      string `json:"status"`
}

func (h *DomainHandler) Create(c *gin.Context) {
	var req createDomainReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, http.StatusBadRequest, bindError(err))
		return
	}
	code := strings.TrimSpace(req.Code)
	var dup int64
	h.db.Model(&models.Domain{}).Where("code = ?", code).Count(&dup)
	if dup > 0 {
		Fail(c, http.StatusConflict, "域标识已存在")
		return
	}

	status := req.Status
	if status == "" {
		status = "active"
	}
	dom := models.Domain{
		Code:        code,
		Name:        strings.TrimSpace(req.Name),
		Description: strings.TrimSpace(req.Description),
		Status:      status,
	}
	if err := h.db.Create(&dom).Error; err != nil {
		failWrite(c, err, "域编码已存在", "创建域失败")
		return
	}

	h.auditSvc.RecordFromContext(c, audit.Entry{
		DomainCode:   dom.Code,
		Action:       "domain.create",
		ResourceType: "domain",
		ResourceID:   dom.Code,
		After:        dom,
		Status:       "success",
	})
	Created(c, dom)
}

type updateDomainReq struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Status      string `json:"status"`
}

func (h *DomainHandler) Update(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		Fail(c, http.StatusBadRequest, "无效的域 ID")
		return
	}
	// 域是授权边界的根：本批收紧为超级管理员专属，域级 domains:write 不足以授权。
	if !isSuperAdmin(h.enforcer, CurrentUserID(c)) {
		Fail(c, http.StatusForbidden, "仅超级管理员可修改域")
		return
	}
	var dom models.Domain
	if err := h.db.First(&dom, id).Error; err != nil {
		Fail(c, http.StatusNotFound, "域不存在")
		return
	}
	before := dom

	// 严格解析：域标识 code 不可通过 body 修改（防止改标识绕开归属与审计）。
	var req updateDomainReq
	if !decodeStrictJSON(c, &req) {
		return
	}
	if req.Status != "" && req.Status != "active" && req.Status != "disabled" {
		Fail(c, http.StatusBadRequest, "无效的域状态")
		return
	}
	// 保护管理路径：主域 openiam 不可停用。
	if dom.Code == rbac.DefaultDomain && req.Status == "disabled" {
		Fail(c, http.StatusForbidden, "默认管理域 openiam 不可停用")
		return
	}
	if req.Name != "" {
		dom.Name = strings.TrimSpace(req.Name)
	}
	if req.Description != "" {
		dom.Description = strings.TrimSpace(req.Description)
	}
	if req.Status != "" {
		dom.Status = req.Status
	}

	if err := h.db.Save(&dom).Error; err != nil {
		Fail(c, http.StatusInternalServerError, "更新域失败")
		return
	}

	h.auditSvc.RecordFromContext(c, audit.Entry{
		DomainCode:   dom.Code,
		Action:       "domain.update",
		ResourceType: "domain",
		ResourceID:   dom.Code,
		Before:       before,
		After:        dom,
		Status:       "success",
	})
	OK(c, dom)
}

// domainDependencies 描述一个域在删除前仍被哪些数据引用。
type domainDependencies struct {
	Roles        int64 `json:"roles"`
	RoleBindings int64 `json:"role_bindings"`
	Users        int64 `json:"users"`
	OAuthClients int64 `json:"oauth_clients"`
	Policies     int64 `json:"policies"`
}

// blocking 返回必须由人先清理的依赖描述；p 策略不算阻塞项，会在删除时一并清理。
func (d domainDependencies) blocking() []string {
	out := make([]string, 0, 4)
	if d.Roles > 0 {
		out = append(out, fmt.Sprintf("角色 %d 个", d.Roles))
	}
	if d.RoleBindings > 0 {
		out = append(out, fmt.Sprintf("角色绑定 %d 条", d.RoleBindings))
	}
	if d.Users > 0 {
		out = append(out, fmt.Sprintf("用户 %d 个", d.Users))
	}
	if d.OAuthClients > 0 {
		out = append(out, fmt.Sprintf("OAuth 客户端 %d 个", d.OAuthClients))
	}
	return out
}

// inspectDomainDependencies 从服务端数据统计该域的依赖（不信任请求头里的域）。
func (h *DomainHandler) inspectDomainDependencies(code string) (domainDependencies, error) {
	var deps domainDependencies
	if err := h.db.Model(&models.Role{}).Where("domain_code = ?", code).Count(&deps.Roles).Error; err != nil {
		return deps, err
	}
	if err := h.db.Model(&models.OAuthClient{}).Where("domain_code = ?", code).Count(&deps.OAuthClients).Error; err != nil {
		return deps, err
	}
	groupings, err := h.enforcer.GetGroupingsForDomain(code)
	if err != nil {
		return deps, err
	}
	deps.RoleBindings = int64(len(groupings))
	seen := make(map[uint64]struct{}, len(groupings))
	for _, g := range groupings {
		if len(g) == 0 {
			continue
		}
		if uid, ok := rbac.ParseUserIDFromSubject(g[0]); ok {
			seen[uid] = struct{}{}
		}
	}
	deps.Users = int64(len(seen))
	deps.Policies, err = h.enforcer.CountPoliciesForDomain(code)
	return deps, err
}

func (h *DomainHandler) Delete(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		Fail(c, http.StatusBadRequest, "无效的域 ID")
		return
	}
	// 删除域会连带清掉该域全部授权，本批收紧为超级管理员专属。
	if !isSuperAdmin(h.enforcer, CurrentUserID(c)) {
		Fail(c, http.StatusForbidden, "仅超级管理员可删除域")
		return
	}
	var dom models.Domain
	if err := h.db.First(&dom, id).Error; err != nil {
		Fail(c, http.StatusNotFound, "域不存在")
		return
	}
	if dom.Code == rbac.DefaultDomain {
		Fail(c, http.StatusBadRequest, "默认系统域 openiam 不可删除")
		return
	}

	// 先查依赖：有依赖返回 409 并说明该清什么，绝不静默级联删除用户或客户端。
	deps, err := h.inspectDomainDependencies(dom.Code)
	if err != nil {
		Fail(c, http.StatusInternalServerError, "检查域依赖失败")
		return
	}
	if blocking := deps.blocking(); len(blocking) > 0 {
		Fail(c, http.StatusConflict, "该域仍有关联数据，请先清理后再删除: "+strings.Join(blocking, "、"))
		return
	}

	// 清理顺序很重要：先清 Casbin 授权，再删数据表行。
	// 这样失败时只会是"授权已清、域还在"（fail-closed），不会出现"域已删、授权仍生效"。
	if _, err := h.enforcer.RemovePoliciesForDomain(dom.Code); err != nil {
		Fail(c, http.StatusInternalServerError, "清理该域授权策略失败，域未被删除")
		return
	}
	if _, err := h.enforcer.RemoveGroupingForDomain(dom.Code); err != nil {
		Fail(c, http.StatusInternalServerError, "清理该域角色绑定失败，域未被删除")
		return
	}
	// 从持久化重新加载后再核对残留：确认清掉的不只是内存，存储里也没有，
	// 否则重启后策略会复活，出现"域已删、授权仍生效"。
	if err := h.enforcer.ReloadPolicy(); err != nil {
		Fail(c, http.StatusInternalServerError, "重新加载授权策略失败，域未被删除")
		return
	}
	if left, err := h.enforcer.CountPoliciesForDomain(dom.Code); err != nil || left != 0 {
		Fail(c, http.StatusInternalServerError, "该域授权策略仍有残留，域未被删除")
		return
	}
	if groups, err := h.enforcer.GetGroupingsForDomain(dom.Code); err != nil || len(groups) != 0 {
		Fail(c, http.StatusInternalServerError, "该域角色绑定仍有残留，域未被删除")
		return
	}

	// 表数据放在一个事务里删；失败则整体回滚（授权已清，属于 fail-closed）。
	if err := h.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("domain_code = ?", dom.Code).Delete(&models.Role{}).Error; err != nil {
			return err
		}
		return tx.Delete(&models.Domain{}, id).Error
	}); err != nil {
		Fail(c, http.StatusInternalServerError, "删除域数据失败（该域授权已清除，请重试）")
		return
	}

	h.auditSvc.RecordFromContext(c, audit.Entry{
		DomainCode:   dom.Code,
		Action:       "domain.delete",
		ResourceType: "domain",
		ResourceID:   dom.Code,
		Before:       dom,
		Status:       "success",
	})
	OK(c, gin.H{"deleted": true})
}
