package http

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/openrealm/openiam/backend/internal/modules/identity/domain"
	"github.com/openrealm/openiam/backend/internal/modules/identity/service"
	"github.com/openrealm/openiam/backend/internal/platform/middleware"
	"github.com/openrealm/openiam/backend/internal/platform/response"
)

type UserHandler struct {
	users *service.UserService
	perms middleware.PermissionChecker
}

func NewUserHandler(users *service.UserService, perms middleware.PermissionChecker) *UserHandler {
	return &UserHandler{users: users, perms: perms}
}

func (h *UserHandler) List(c *gin.Context) {
	limit := queryInt(c, "limit", 20, 100)
	page := queryInt(c, "page", 1, 100000)
	offset := (page - 1) * limit

	users, total, err := h.users.List(c.Request.Context(), limit, offset)
	if err != nil {
		response.Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Unable to list users")
		return
	}

	items := make([]UserResponse, 0, len(users))
	for i := range users {
		items = append(items, ToUserResponse(&users[i]))
	}

	response.Data(c, http.StatusOK, ListUsersResponse{
		Items: items,
		Total: total,
		Limit: limit,
		Page:  page,
	})
}

func (h *UserHandler) Get(c *gin.Context) {
	user, err := h.users.GetByPublicID(c.Request.Context(), c.Param("id"))
	if err != nil {
		if errors.Is(err, service.ErrNotFound) {
			response.Error(c, http.StatusNotFound, "USER_NOT_FOUND", "User not found")
			return
		}
		response.Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Unable to load user")
		return
	}
	response.Data(c, http.StatusOK, ToUserResponse(user))
}

func (h *UserHandler) Create(c *gin.Context) {
	var req CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, "VALIDATION_FAILED", "Username, email and password are required")
		return
	}

	user, err := h.users.Create(c.Request.Context(), service.CreateUserInput{
		Username:    req.Username,
		Email:       req.Email,
		Password:    req.Password,
		DisplayName: req.DisplayName,
	})
	if err != nil {
		switch {
		case errors.Is(err, service.ErrUserExists):
			response.Error(c, http.StatusConflict, "USER_EXISTS", "Username or email already exists")
		case errors.Is(err, service.ErrWeakPassword):
			response.Error(c, http.StatusBadRequest, "WEAK_PASSWORD", "Password does not meet policy")
		default:
			response.Error(c, http.StatusBadRequest, "VALIDATION_FAILED", "Unable to create user")
		}
		return
	}

	response.Data(c, http.StatusCreated, ToUserResponse(user))
}

func (h *UserHandler) Update(c *gin.Context) {
	user, err := h.users.GetByPublicID(c.Request.Context(), c.Param("id"))
	if err != nil {
		if errors.Is(err, service.ErrNotFound) {
			response.Error(c, http.StatusNotFound, "USER_NOT_FOUND", "User not found")
			return
		}
		response.Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Unable to load user")
		return
	}

	var req UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, "VALIDATION_FAILED", "Invalid request body")
		return
	}

	if req.Status != nil && (*req.Status == domain.StatusDisabled || *req.Status == domain.StatusLocked) {
		if !h.authorizedToDisable(c) {
			response.Error(c, http.StatusForbidden, "RBAC_FORBIDDEN", "Disabling users requires the users:disable permission")
			return
		}
	}

	updated, err := h.users.Update(c.Request.Context(), user.ID, service.UpdateUserInput{
		DisplayName: req.DisplayName,
		Status:      req.Status,
	})
	if err != nil {
		response.Error(c, http.StatusBadRequest, "VALIDATION_FAILED", "Unable to update user")
		return
	}

	response.Data(c, http.StatusOK, ToUserResponse(updated))
}

func queryInt(c *gin.Context, key string, fallback, max int) int {
	raw := c.Query(key)
	if raw == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil || parsed < 1 {
		return fallback
	}
	if parsed > max {
		return max
	}
	return parsed
}

func (h *UserHandler) authorizedToDisable(c *gin.Context) bool {
	if h.perms == nil {
		return false
	}
	userID, ok := middleware.UserIDFrom(c)
	if !ok {
		return false
	}
	allowed, err := h.perms.HasPermission(c.Request.Context(), userID, "users:disable")
	return err == nil && allowed
}
