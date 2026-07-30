package http

import (
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	identityrepo "github.com/openrealm/openiam/backend/internal/modules/identity/repository"
	"github.com/openrealm/openiam/backend/internal/modules/rbac/service"
	"github.com/openrealm/openiam/backend/internal/platform/middleware"
	"github.com/openrealm/openiam/backend/internal/platform/response"
)

type Handler struct {
	roles  *service.RoleService
	grants *service.GrantService
	users  *identityrepo.Repository
}

func NewHandler(roles *service.RoleService, grants *service.GrantService, users *identityrepo.Repository) *Handler {
	return &Handler{roles: roles, grants: grants, users: users}
}

func (h *Handler) ListRoles(c *gin.Context) {
	roles, err := h.roles.ListRoles(c.Request.Context())
	if err != nil {
		response.Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Unable to list roles")
		return
	}
	items := make([]RoleResponse, 0, len(roles))
	for i := range roles {
		items = append(items, ToRoleResponse(&roles[i]))
	}
	response.Data(c, http.StatusOK, gin.H{"items": items, "total": len(items)})
}

func (h *Handler) CreateRole(c *gin.Context) {
	var req CreateRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, "VALIDATION_FAILED", "Code and name are required")
		return
	}

	actorUserID, ok := middleware.UserIDFrom(c)
	if !ok {
		response.Error(c, http.StatusUnauthorized, "AUTH_REQUIRED", "Authentication required")
		return
	}

	role, err := h.roles.CreateRole(c.Request.Context(), actorUserID, service.CreateRoleInput{
		Code:        req.Code,
		Name:        req.Name,
		Description: req.Description,
	})
	if err != nil {
		if errors.Is(err, service.ErrRoleExists) {
			response.Error(c, http.StatusConflict, "ROLE_EXISTS", "Role code already exists")
			return
		}
		response.Error(c, http.StatusBadRequest, "VALIDATION_FAILED", "Unable to create role")
		return
	}

	response.Data(c, http.StatusCreated, ToRoleResponse(role))
}

func (h *Handler) DeleteRole(c *gin.Context) {
	code := c.Param("code")
	err := h.roles.DeleteRole(c.Request.Context(), code)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrRoleNotFound):
			response.Error(c, http.StatusNotFound, "ROLE_NOT_FOUND", "Role not found")
		case errors.Is(err, service.ErrSystemRole):
			response.Error(c, http.StatusForbidden, "SYSTEM_ROLE_PROTECTED", "System roles cannot be deleted")
		default:
			response.Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Unable to delete role")
		}
		return
	}
	response.Data(c, http.StatusOK, gin.H{"deleted": code})
}

func (h *Handler) GetRole(c *gin.Context) {
	code := c.Param("code")
	permissions, err := h.roles.RolePermissions(c.Request.Context(), code)
	if err != nil {
		if errors.Is(err, service.ErrRoleNotFound) {
			response.Error(c, http.StatusNotFound, "ROLE_NOT_FOUND", "Role not found")
			return
		}
		response.Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Unable to load role")
		return
	}

	roles, _ := h.roles.ListRoles(c.Request.Context())
	var matched *RoleResponse
	for i := range roles {
		if roles[i].Code == code {
			r := ToRoleResponse(&roles[i])
			matched = &r
			break
		}
	}
	if matched == nil {
		response.Error(c, http.StatusNotFound, "ROLE_NOT_FOUND", "Role not found")
		return
	}

	response.Data(c, http.StatusOK, RoleDetailResponse{Role: *matched, Permissions: permissions})
}

func (h *Handler) ReplaceRolePermissions(c *gin.Context) {
	var req ReplacePermissionsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, "VALIDATION_FAILED", "Invalid request body")
		return
	}

	actorUserID, ok := middleware.UserIDFrom(c)
	if !ok {
		response.Error(c, http.StatusUnauthorized, "AUTH_REQUIRED", "Authentication required")
		return
	}

	err := h.roles.ReplaceRolePermissions(c.Request.Context(), actorUserID, c.Param("code"), req.Permissions)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrRoleNotFound):
			response.Error(c, http.StatusNotFound, "ROLE_NOT_FOUND", "Role not found")
		case errors.Is(err, service.ErrUnknownCodes):
			response.Error(c, http.StatusBadRequest, "UNKNOWN_PERMISSION", "One or more permissions do not exist")
		default:
			response.Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Unable to update role permissions")
		}
		return
	}

	permissions, _ := h.roles.RolePermissions(c.Request.Context(), c.Param("code"))
	response.Data(c, http.StatusOK, gin.H{"permissions": permissions})
}

func (h *Handler) ListPermissions(c *gin.Context) {
	permissions, err := h.roles.ListPermissions(c.Request.Context())
	if err != nil {
		response.Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Unable to list permissions")
		return
	}
	items := make([]PermissionResponse, 0, len(permissions))
	for i := range permissions {
		items = append(items, ToPermissionResponse(&permissions[i]))
	}
	response.Data(c, http.StatusOK, gin.H{"items": items, "total": len(items)})
}

func (h *Handler) GetUserRoles(c *gin.Context) {
	user, err := h.users.FindByPublicID(c.Request.Context(), c.Param("id"))
	if err != nil {
		response.Error(c, http.StatusNotFound, "USER_NOT_FOUND", "User not found")
		return
	}

	roles, err := h.grants.UserRoles(c.Request.Context(), user.ID)
	if err != nil {
		response.Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Unable to load user roles")
		return
	}

	response.Data(c, http.StatusOK, UserRolesResponse{
		UserID:    user.PublicID,
		Roles:     roles,
		UpdatedAt: time.Now().UTC(),
	})
}

func (h *Handler) ReplaceUserRoles(c *gin.Context) {
	user, err := h.users.FindByPublicID(c.Request.Context(), c.Param("id"))
	if err != nil {
		response.Error(c, http.StatusNotFound, "USER_NOT_FOUND", "User not found")
		return
	}

	var req ReplaceRolesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, "VALIDATION_FAILED", "Invalid request body")
		return
	}

	var grantedBy *uint64
	if actorID, ok := middleware.UserIDFrom(c); ok {
		grantedBy = &actorID
	}

	if err := h.grants.ReplaceUserRoles(c.Request.Context(), user.ID, user.PublicID, req.Roles, grantedBy); err != nil {
		if errors.Is(err, service.ErrUnknownCodes) {
			response.Error(c, http.StatusBadRequest, "UNKNOWN_ROLE", "One or more roles do not exist")
			return
		}
		response.Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Unable to update user roles")
		return
	}

	roles, _ := h.grants.UserRoles(c.Request.Context(), user.ID)
	response.Data(c, http.StatusOK, gin.H{"roles": roles})
}
