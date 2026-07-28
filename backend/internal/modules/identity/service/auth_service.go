package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/openrealm/openiam/backend/internal/modules/identity/domain"
	"github.com/openrealm/openiam/backend/internal/modules/identity/repository"
	"github.com/openrealm/openiam/backend/internal/modules/session"
	"github.com/openrealm/openiam/backend/internal/platform/config"
	"github.com/openrealm/openiam/backend/internal/platform/crypto"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrAccountDisabled    = errors.New("account disabled")
)

type AuditRecorder interface {
	RecordLogin(ctx context.Context, user *domain.User, success bool, ip, userAgent string)
}

type AuthService struct {
	users    *repository.Repository
	sessions *session.Manager
	security config.SecurityConfig
	audit    AuditRecorder
}

func NewAuthService(
	users *repository.Repository,
	sessions *session.Manager,
	security config.SecurityConfig,
	audit AuditRecorder,
) *AuthService {
	return &AuthService{users: users, sessions: sessions, security: security, audit: audit}
}

func (s *AuthService) Login(ctx context.Context, login, password, ip, userAgent string) (*session.Data, error) {
	user, err := s.users.FindByLogin(ctx, login)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			crypto.VerifyPassword(dummyHash, password)
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}

	now := time.Now().UTC()

	if user.Status == domain.StatusDisabled {
		s.recordLogin(ctx, user, false, ip, userAgent)
		return nil, ErrInvalidCredentials
	}

	if user.IsLocked(now) {
		s.recordLogin(ctx, user, false, ip, userAgent)
		return nil, ErrInvalidCredentials
	}

	if user.PasswordHash == nil || !crypto.VerifyPassword(*user.PasswordHash, password) {
		s.handleFailedAttempt(ctx, user, now, ip, userAgent)
		return nil, ErrInvalidCredentials
	}

	if err := s.users.RecordLoginSuccess(ctx, user.ID, now); err != nil {
		return nil, err
	}

	sess, err := s.sessions.Create(ctx, user.ID, user.PublicID)
	if err != nil {
		return nil, err
	}

	s.recordLogin(ctx, user, true, ip, userAgent)
	return sess, nil
}

func (s *AuthService) Logout(ctx context.Context, sessionID string) error {
	return s.sessions.Revoke(ctx, sessionID)
}

func (s *AuthService) UserByID(ctx context.Context, id uint64) (*domain.User, error) {
	return s.users.FindByID(ctx, id)
}

func (s *AuthService) ProvisionFederated(ctx context.Context, email, displayName string) (uint64, string, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return 0, "", errors.New("federated identity has no email")
	}

	if existing, err := s.users.FindByEmail(ctx, email); err == nil {
		return existing.ID, existing.PublicID, nil
	} else if !errors.Is(err, repository.ErrUserNotFound) {
		return 0, "", err
	}

	localPart := email
	if idx := strings.Index(email, "@"); idx > 0 {
		localPart = email[:idx]
	}

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		username := localPart
		if attempt > 0 {
			username = localPart + "-" + crypto.Token(2)
		}
		user := &domain.User{
			PublicID:    crypto.NewID(),
			Username:    username,
			Email:       email,
			DisplayName: displayName,
			Status:      domain.StatusActive,
		}
		if err := s.users.Create(ctx, user); err != nil {
			lastErr = err
			continue
		}
		return user.ID, user.PublicID, nil
	}

	if existing, err := s.users.FindByEmail(ctx, email); err == nil {
		return existing.ID, existing.PublicID, nil
	}
	return 0, "", lastErr
}

func (s *AuthService) handleFailedAttempt(ctx context.Context, user *domain.User, now time.Time, ip, userAgent string) {
	attempts := user.FailedLoginCount + 1
	var lockUntil *time.Time
	if s.security.LoginAttemptLimit > 0 && int(attempts) >= s.security.LoginAttemptLimit {
		until := now.Add(s.security.LoginLockDuration)
		lockUntil = &until
	}
	_ = s.users.RecordLoginFailure(ctx, user.ID, lockUntil)
	s.recordLogin(ctx, user, false, ip, userAgent)
}

func (s *AuthService) recordLogin(ctx context.Context, user *domain.User, success bool, ip, userAgent string) {
	if s.audit == nil {
		return
	}
	s.audit.RecordLogin(ctx, user, success, ip, userAgent)
}

const dummyHash = "$argon2id$v=19$m=65536,t=3,p=2$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
