package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/openrealm/openiam/backend/internal/modules/identity/domain"
	"github.com/openrealm/openiam/backend/internal/modules/identity/repository"
	"github.com/openrealm/openiam/backend/internal/platform/config"
	"github.com/openrealm/openiam/backend/internal/platform/crypto"
)

var (
	ErrUserExists   = errors.New("user already exists")
	ErrWeakPassword = errors.New("password does not meet policy")
	ErrNotFound     = repository.ErrUserNotFound
)

type UserService struct {
	users    *repository.Repository
	security config.SecurityConfig
	notifier Notifier
}

func NewUserService(users *repository.Repository, security config.SecurityConfig, notifier Notifier) *UserService {
	return &UserService{users: users, security: security, notifier: notifier}
}

type CreateUserInput struct {
	Username    string
	Email       string
	Password    string
	DisplayName string
}

func (s *UserService) Create(ctx context.Context, in CreateUserInput) (*domain.User, error) {
	in.Username = strings.TrimSpace(in.Username)
	in.Email = strings.TrimSpace(in.Email)

	if in.Username == "" || in.Email == "" {
		return nil, errors.New("username and email are required")
	}
	if len(in.Password) < s.security.PasswordMinLength {
		return nil, ErrWeakPassword
	}

	hash, err := crypto.HashPassword(in.Password)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	user := &domain.User{
		PublicID:          crypto.NewID(),
		Username:          in.Username,
		Email:             in.Email,
		PasswordHash:      &hash,
		DisplayName:       in.DisplayName,
		Status:            domain.StatusActive,
		PasswordChangedAt: &now,
	}

	if err := s.users.Create(ctx, user); err != nil {
		if isDuplicateKey(err) {
			return nil, ErrUserExists
		}
		return nil, err
	}

	if s.notifier != nil {
		s.notifier.NotifyUserCreated(ctx, user)
	}
	return user, nil
}

func (s *UserService) Get(ctx context.Context, id uint64) (*domain.User, error) {
	return s.users.FindByID(ctx, id)
}

func (s *UserService) GetByPublicID(ctx context.Context, publicID string) (*domain.User, error) {
	return s.users.FindByPublicID(ctx, publicID)
}

func (s *UserService) List(ctx context.Context, limit, offset int) ([]domain.User, int64, error) {
	return s.users.List(ctx, limit, offset)
}

type UpdateUserInput struct {
	DisplayName *string
	Status      *string
}

func (s *UserService) Update(ctx context.Context, id uint64, in UpdateUserInput) (*domain.User, error) {
	user, err := s.users.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if in.DisplayName != nil {
		user.DisplayName = *in.DisplayName
	}
	if in.Status != nil {
		switch *in.Status {
		case domain.StatusActive, domain.StatusDisabled, domain.StatusLocked, domain.StatusPending:
			user.Status = *in.Status
			if *in.Status != domain.StatusLocked {
				user.LockedUntil = nil
			}
		default:
			return nil, errors.New("invalid status")
		}
	}

	if err := s.users.Save(ctx, user); err != nil {
		return nil, err
	}
	return user, nil
}

func isDuplicateKey(err error) bool {
	return strings.Contains(err.Error(), "Duplicate entry") || strings.Contains(err.Error(), "1062")
}
