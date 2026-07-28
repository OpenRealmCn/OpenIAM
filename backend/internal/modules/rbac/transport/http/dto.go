package http

import (
	"time"

	"github.com/openrealm/openiam/backend/internal/modules/rbac/domain"
)

type RoleResponse struct {
	Code        string  `json:"code"`
	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`
	IsSystem    bool    `json:"isSystem"`
	Status      string  `json:"status"`
}

func ToRoleResponse(role *domain.Role) RoleResponse {
	return RoleResponse{
		Code:        role.Code,
		Name:        role.Name,
		Description: role.Description,
		IsSystem:    role.IsSystem,
		Status:      role.Status,
	}
}

type PermissionResponse struct {
	Code        string  `json:"code"`
	Resource    string  `json:"resource"`
	Action      string  `json:"action"`
	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`
}

func ToPermissionResponse(p *domain.Permission) PermissionResponse {
	return PermissionResponse{
		Code:        p.Code,
		Resource:    p.Resource,
		Action:      p.Action,
		Name:        p.Name,
		Description: p.Description,
	}
}

type CreateRoleRequest struct {
	Code        string `json:"code" binding:"required"`
	Name        string `json:"name" binding:"required"`
	Description string `json:"description"`
}

type ReplacePermissionsRequest struct {
	Permissions []string `json:"permissions"`
}

type ReplaceRolesRequest struct {
	Roles []string `json:"roles"`
}

type RoleDetailResponse struct {
	Role        RoleResponse `json:"role"`
	Permissions []string     `json:"permissions"`
}

type UserRolesResponse struct {
	UserID    string    `json:"userId"`
	Roles     []string  `json:"roles"`
	UpdatedAt time.Time `json:"updatedAt"`
}
