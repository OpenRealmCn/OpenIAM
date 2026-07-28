package http

import (
	"time"

	"github.com/openrealm/openiam/backend/internal/modules/identity/domain"
)

type UserResponse struct {
	ID          string     `json:"id"`
	Username    string     `json:"username"`
	Email       string     `json:"email"`
	DisplayName string     `json:"displayName"`
	Status      string     `json:"status"`
	LastLoginAt *time.Time `json:"lastLoginAt,omitempty"`
	CreatedAt   time.Time  `json:"createdAt"`
}

func ToUserResponse(user *domain.User) UserResponse {
	return UserResponse{
		ID:          user.PublicID,
		Username:    user.Username,
		Email:       user.Email,
		DisplayName: user.DisplayName,
		Status:      user.Status,
		LastLoginAt: user.LastLoginAt,
		CreatedAt:   user.CreatedAt,
	}
}

type LoginRequest struct {
	Login    string `json:"login" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type LoginResponse struct {
	User      UserResponse `json:"user"`
	CSRFToken string       `json:"csrfToken"`
}

type MeResponse struct {
	User        UserResponse `json:"user"`
	Permissions []string     `json:"permissions"`
	CSRFToken   string       `json:"csrfToken"`
}

type CreateUserRequest struct {
	Username    string `json:"username" binding:"required"`
	Email       string `json:"email" binding:"required"`
	Password    string `json:"password" binding:"required"`
	DisplayName string `json:"displayName"`
}

type UpdateUserRequest struct {
	DisplayName *string `json:"displayName"`
	Status      *string `json:"status"`
}

type ListUsersResponse struct {
	Items []UserResponse `json:"items"`
	Total int64          `json:"total"`
	Limit int            `json:"limit"`
	Page  int            `json:"page"`
}
