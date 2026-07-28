package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openrealm/openiam/backend/internal/modules/identity/domain"
	"github.com/openrealm/openiam/backend/internal/modules/identity/repository"
	"github.com/openrealm/openiam/backend/internal/modules/session"
	"github.com/openrealm/openiam/backend/internal/platform/config"
	"github.com/openrealm/openiam/backend/internal/platform/crypto"
)

// Mock implementations for testing

type mockUserRepository struct {
	findByLoginFunc        func(ctx context.Context, login string) (*domain.User, error)
	findByEmailFunc        func(ctx context.Context, email string) (*domain.User, error)
	findByIDFunc           func(ctx context.Context, id uint64) (*domain.User, error)
	createFunc             func(ctx context.Context, user *domain.User) error
	recordLoginFailureFunc func(ctx context.Context, id uint64, lockUntil *time.Time) error
	recordLoginSuccessFunc func(ctx context.Context, id uint64, at time.Time) error
}

func (m *mockUserRepository) FindByLogin(ctx context.Context, login string) (*domain.User, error) {
	if m.findByLoginFunc != nil {
		return m.findByLoginFunc(ctx, login)
	}
	return nil, repository.ErrUserNotFound
}

func (m *mockUserRepository) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	if m.findByEmailFunc != nil {
		return m.findByEmailFunc(ctx, email)
	}
	return nil, repository.ErrUserNotFound
}

func (m *mockUserRepository) FindByID(ctx context.Context, id uint64) (*domain.User, error) {
	if m.findByIDFunc != nil {
		return m.findByIDFunc(ctx, id)
	}
	return nil, repository.ErrUserNotFound
}

func (m *mockUserRepository) Create(ctx context.Context, user *domain.User) error {
	if m.createFunc != nil {
		return m.createFunc(ctx, user)
	}
	return nil
}

func (m *mockUserRepository) RecordLoginFailure(ctx context.Context, id uint64, lockUntil *time.Time) error {
	if m.recordLoginFailureFunc != nil {
		return m.recordLoginFailureFunc(ctx, id, lockUntil)
	}
	return nil
}

func (m *mockUserRepository) RecordLoginSuccess(ctx context.Context, id uint64, at time.Time) error {
	if m.recordLoginSuccessFunc != nil {
		return m.recordLoginSuccessFunc(ctx, id, at)
	}
	return nil
}

type mockSessionManager struct {
	createFunc func(ctx context.Context, userID uint64, publicID string) (*session.Data, error)
	revokeFunc func(ctx context.Context, sessionID string) error
}

func (m *mockSessionManager) Create(ctx context.Context, userID uint64, publicID string) (*session.Data, error) {
	if m.createFunc != nil {
		return m.createFunc(ctx, userID, publicID)
	}
	return session.NewData("test-session-id", userID, publicID, "test-csrf", time.Now().UTC()), nil
}

func (m *mockSessionManager) Revoke(ctx context.Context, sessionID string) error {
	if m.revokeFunc != nil {
		return m.revokeFunc(ctx, sessionID)
	}
	return nil
}

type mockAuditRecorder struct {
	recorded []auditEntry
}

type auditEntry struct {
	user      *domain.User
	success   bool
	ip        string
	userAgent string
}

func (m *mockAuditRecorder) RecordLogin(ctx context.Context, user *domain.User, success bool, ip, userAgent string) {
	m.recorded = append(m.recorded, auditEntry{user, success, ip, userAgent})
}

// Test cases

func TestAuthService_Login_Success(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	passwordHash, _ := crypto.HashPassword("correct-password")

	user := &domain.User{
		ID:                1,
		PublicID:          "user-pub-123",
		Username:          "testuser",
		Email:             "test@example.com",
		PasswordHash:      &passwordHash,
		Status:            domain.StatusActive,
		FailedLoginCount:  0,
		LockedUntil:       nil,
		PasswordChangedAt: &now,
	}

	var loginSuccessRecorded bool
	userRepo := &mockUserRepository{
		findByLoginFunc: func(ctx context.Context, login string) (*domain.User, error) {
			if login == "testuser" {
				return user, nil
			}
			return nil, repository.ErrUserNotFound
		},
		recordLoginSuccessFunc: func(ctx context.Context, id uint64, at time.Time) error {
			if id == 1 {
				loginSuccessRecorded = true
			}
			return nil
		},
	}

	sessionMgr := &mockSessionManager{}
	audit := &mockAuditRecorder{}
	cfg := config.SecurityConfig{
		PasswordMinLength:  12,
		LoginAttemptLimit:  5,
		LoginLockDuration:  15 * time.Minute,
	}

	svc := NewAuthService(userRepo, sessionMgr, cfg, audit)
	sess, err := svc.Login(ctx, "testuser", "correct-password", "192.168.1.1", "TestAgent/1.0")

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if sess == nil {
		t.Fatal("expected session, got nil")
	}
	if sess.UserID() != 1 {
		t.Errorf("expected user ID 1, got %d", sess.UserID())
	}
	if !loginSuccessRecorded {
		t.Error("expected login success to be recorded")
	}
	if len(audit.recorded) != 1 {
		t.Fatalf("expected 1 audit entry, got %d", len(audit.recorded))
	}
	if !audit.recorded[0].success {
		t.Error("expected audit entry to mark success")
	}
}

func TestAuthService_Login_WrongPassword(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	passwordHash, _ := crypto.HashPassword("correct-password")

	user := &domain.User{
		ID:                1,
		PublicID:          "user-pub-123",
		Username:          "testuser",
		PasswordHash:      &passwordHash,
		Status:            domain.StatusActive,
		FailedLoginCount:  0,
		PasswordChangedAt: &now,
	}

	var failureRecorded bool
	userRepo := &mockUserRepository{
		findByLoginFunc: func(ctx context.Context, login string) (*domain.User, error) {
			return user, nil
		},
		recordLoginFailureFunc: func(ctx context.Context, id uint64, lockUntil *time.Time) error {
			if id == 1 {
				failureRecorded = true
			}
			return nil
		},
	}

	sessionMgr := &mockSessionManager{}
	audit := &mockAuditRecorder{}
	cfg := config.SecurityConfig{
		PasswordMinLength:  12,
		LoginAttemptLimit:  5,
		LoginLockDuration:  15 * time.Minute,
	}

	svc := NewAuthService(userRepo, sessionMgr, cfg, audit)
	sess, err := svc.Login(ctx, "testuser", "wrong-password", "192.168.1.1", "TestAgent/1.0")

	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
	if sess != nil {
		t.Error("expected nil session")
	}
	if !failureRecorded {
		t.Error("expected login failure to be recorded")
	}
	if len(audit.recorded) != 1 {
		t.Fatalf("expected 1 audit entry, got %d", len(audit.recorded))
	}
	if audit.recorded[0].success {
		t.Error("expected audit entry to mark failure")
	}
}

func TestAuthService_Login_UserNotFound_TimingAttackMitigation(t *testing.T) {
	ctx := context.Background()

	userRepo := &mockUserRepository{
		findByLoginFunc: func(ctx context.Context, login string) (*domain.User, error) {
			return nil, repository.ErrUserNotFound
		},
	}

	sessionMgr := &mockSessionManager{}
	audit := &mockAuditRecorder{}
	cfg := config.SecurityConfig{
		PasswordMinLength:  12,
		LoginAttemptLimit:  5,
		LoginLockDuration:  15 * time.Minute,
	}

	svc := NewAuthService(userRepo, sessionMgr, cfg, audit)

	// Measure time taken for non-existent user
	start := time.Now()
	sess, err := svc.Login(ctx, "nonexistent", "any-password", "192.168.1.1", "TestAgent/1.0")
	elapsed := time.Since(start)

	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
	if sess != nil {
		t.Error("expected nil session")
	}

	// The dummy hash verification should take at least 10ms (Argon2id is intentionally slow)
	// This ensures timing attacks can't distinguish "user not found" from "wrong password"
	if elapsed < 10*time.Millisecond {
		t.Errorf("timing attack mitigation insufficient: operation took only %v", elapsed)
	}

	// No audit record should be created for non-existent users
	if len(audit.recorded) != 0 {
		t.Errorf("expected no audit entries for non-existent user, got %d", len(audit.recorded))
	}
}

func TestAuthService_Login_AccountLockout(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	passwordHash, _ := crypto.HashPassword("correct-password")

	user := &domain.User{
		ID:               1,
		PublicID:         "user-pub-123",
		Username:         "testuser",
		PasswordHash:     &passwordHash,
		Status:           domain.StatusActive,
		FailedLoginCount: 4, // One more failure will trigger lockout
	}

	var lockUntilRecorded *time.Time
	userRepo := &mockUserRepository{
		findByLoginFunc: func(ctx context.Context, login string) (*domain.User, error) {
			return user, nil
		},
		recordLoginFailureFunc: func(ctx context.Context, id uint64, lockUntil *time.Time) error {
			if id == 1 {
				lockUntilRecorded = lockUntil
			}
			return nil
		},
	}

	sessionMgr := &mockSessionManager{}
	audit := &mockAuditRecorder{}
	cfg := config.SecurityConfig{
		PasswordMinLength:  12,
		LoginAttemptLimit:  5,
		LoginLockDuration:  15 * time.Minute,
	}

	svc := NewAuthService(userRepo, sessionMgr, cfg, audit)
	_, err := svc.Login(ctx, "testuser", "wrong-password", "192.168.1.1", "TestAgent/1.0")

	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
	if lockUntilRecorded == nil {
		t.Fatal("expected account to be locked")
	}
	if lockUntilRecorded.Before(now.Add(14 * time.Minute)) {
		t.Error("lock duration is too short")
	}
	if lockUntilRecorded.After(now.Add(16 * time.Minute)) {
		t.Error("lock duration is too long")
	}
}

func TestAuthService_Login_AlreadyLocked(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	lockUntil := now.Add(10 * time.Minute)
	passwordHash, _ := crypto.HashPassword("correct-password")

	user := &domain.User{
		ID:               1,
		PublicID:         "user-pub-123",
		Username:         "testuser",
		PasswordHash:     &passwordHash,
		Status:           domain.StatusLocked,
		FailedLoginCount: 5,
		LockedUntil:      &lockUntil,
	}

	userRepo := &mockUserRepository{
		findByLoginFunc: func(ctx context.Context, login string) (*domain.User, error) {
			return user, nil
		},
	}

	sessionMgr := &mockSessionManager{}
	audit := &mockAuditRecorder{}
	cfg := config.SecurityConfig{
		PasswordMinLength:  12,
		LoginAttemptLimit:  5,
		LoginLockDuration:  15 * time.Minute,
	}

	svc := NewAuthService(userRepo, sessionMgr, cfg, audit)
	sess, err := svc.Login(ctx, "testuser", "correct-password", "192.168.1.1", "TestAgent/1.0")

	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
	if sess != nil {
		t.Error("expected nil session")
	}
	if len(audit.recorded) != 1 {
		t.Fatalf("expected 1 audit entry, got %d", len(audit.recorded))
	}
	if audit.recorded[0].success {
		t.Error("expected audit entry to mark failure")
	}
}

func TestAuthService_Login_DisabledAccount(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	passwordHash, _ := crypto.HashPassword("correct-password")

	user := &domain.User{
		ID:                1,
		PublicID:          "user-pub-123",
		Username:          "testuser",
		PasswordHash:      &passwordHash,
		Status:            domain.StatusDisabled,
		PasswordChangedAt: &now,
	}

	userRepo := &mockUserRepository{
		findByLoginFunc: func(ctx context.Context, login string) (*domain.User, error) {
			return user, nil
		},
	}

	sessionMgr := &mockSessionManager{}
	audit := &mockAuditRecorder{}
	cfg := config.SecurityConfig{
		PasswordMinLength:  12,
		LoginAttemptLimit:  5,
		LoginLockDuration:  15 * time.Minute,
	}

	svc := NewAuthService(userRepo, sessionMgr, cfg, audit)
	sess, err := svc.Login(ctx, "testuser", "correct-password", "192.168.1.1", "TestAgent/1.0")

	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
	if sess != nil {
		t.Error("expected nil session")
	}
}

func TestAuthService_ProvisionFederated_NewUser(t *testing.T) {
	ctx := context.Background()

	var createdUser *domain.User
	userRepo := &mockUserRepository{
		findByEmailFunc: func(ctx context.Context, email string) (*domain.User, error) {
			return nil, repository.ErrUserNotFound
		},
		createFunc: func(ctx context.Context, user *domain.User) error {
			createdUser = user
			user.ID = 42 // Simulate DB auto-increment
			return nil
		},
	}

	sessionMgr := &mockSessionManager{}
	audit := &mockAuditRecorder{}
	cfg := config.SecurityConfig{}

	svc := NewAuthService(userRepo, sessionMgr, cfg, audit)
	userID, publicID, err := svc.ProvisionFederated(ctx, "  NewUser@Example.COM  ", "New User")

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if userID != 42 {
		t.Errorf("expected user ID 42, got %d", userID)
	}
	if publicID == "" {
		t.Error("expected non-empty public ID")
	}
	if createdUser == nil {
		t.Fatal("expected user to be created")
	}
	if createdUser.Email != "newuser@example.com" {
		t.Errorf("expected lowercase normalized email, got %s", createdUser.Email)
	}
	if createdUser.Username != "newuser" {
		t.Errorf("expected username 'newuser', got %s", createdUser.Username)
	}
	if createdUser.DisplayName != "New User" {
		t.Errorf("expected display name 'New User', got %s", createdUser.DisplayName)
	}
	if createdUser.Status != domain.StatusActive {
		t.Errorf("expected status Active, got %s", createdUser.Status)
	}
	if createdUser.PasswordHash != nil {
		t.Error("expected nil password hash for federated user")
	}
}

func TestAuthService_ProvisionFederated_ExistingUser(t *testing.T) {
	ctx := context.Background()

	existingUser := &domain.User{
		ID:       99,
		PublicID: "existing-pub-id",
		Email:    "existing@example.com",
		Username: "existing",
	}

	userRepo := &mockUserRepository{
		findByEmailFunc: func(ctx context.Context, email string) (*domain.User, error) {
			if email == "existing@example.com" {
				return existingUser, nil
			}
			return nil, repository.ErrUserNotFound
		},
	}

	sessionMgr := &mockSessionManager{}
	audit := &mockAuditRecorder{}
	cfg := config.SecurityConfig{}

	svc := NewAuthService(userRepo, sessionMgr, cfg, audit)
	userID, publicID, err := svc.ProvisionFederated(ctx, "EXISTING@example.com", "Display Name")

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if userID != 99 {
		t.Errorf("expected user ID 99, got %d", userID)
	}
	if publicID != "existing-pub-id" {
		t.Errorf("expected existing public ID, got %s", publicID)
	}
}

func TestAuthService_ProvisionFederated_EmptyEmail(t *testing.T) {
	ctx := context.Background()

	userRepo := &mockUserRepository{}
	sessionMgr := &mockSessionManager{}
	audit := &mockAuditRecorder{}
	cfg := config.SecurityConfig{}

	svc := NewAuthService(userRepo, sessionMgr, cfg, audit)
	_, _, err := svc.ProvisionFederated(ctx, "", "Display Name")

	if err == nil {
		t.Fatal("expected error for empty email")
	}
	if err.Error() != "federated identity has no email" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestAuthService_ProvisionFederated_UsernameConflictRetry(t *testing.T) {
	ctx := context.Background()

	attempts := 0
	userRepo := &mockUserRepository{
		findByEmailFunc: func(ctx context.Context, email string) (*domain.User, error) {
			return nil, repository.ErrUserNotFound
		},
		createFunc: func(ctx context.Context, user *domain.User) error {
			attempts++
			if attempts < 3 {
				// Simulate username conflict on first two attempts
				return errors.New("Duplicate entry 'testuser' for key 'uk_users_username'")
			}
			user.ID = 123
			return nil
		},
	}

	sessionMgr := &mockSessionManager{}
	audit := &mockAuditRecorder{}
	cfg := config.SecurityConfig{}

	svc := NewAuthService(userRepo, sessionMgr, cfg, audit)
	userID, publicID, err := svc.ProvisionFederated(ctx, "testuser@example.com", "Test User")

	if err != nil {
		t.Fatalf("expected no error after retry, got %v", err)
	}
	if userID != 123 {
		t.Errorf("expected user ID 123, got %d", userID)
	}
	if publicID == "" {
		t.Error("expected non-empty public ID")
	}
	if attempts != 3 {
		t.Errorf("expected 3 attempts (2 failures + 1 success), got %d", attempts)
	}
}

func TestAuthService_Logout(t *testing.T) {
	ctx := context.Background()

	var revokedSessionID string
	sessionMgr := &mockSessionManager{
		revokeFunc: func(ctx context.Context, sessionID string) error {
			revokedSessionID = sessionID
			return nil
		},
	}

	userRepo := &mockUserRepository{}
	audit := &mockAuditRecorder{}
	cfg := config.SecurityConfig{}

	svc := NewAuthService(userRepo, sessionMgr, cfg, audit)
	err := svc.Logout(ctx, "session-abc-123")

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if revokedSessionID != "session-abc-123" {
		t.Errorf("expected session 'session-abc-123' to be revoked, got %s", revokedSessionID)
	}
}
