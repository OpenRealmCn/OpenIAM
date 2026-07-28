package repository

import (
	"context"
	"errors"
	"time"

	"github.com/openrealm/openiam/backend/internal/modules/identity/domain"
	"gorm.io/gorm"
)

var ErrUserNotFound = errors.New("user not found")

type Repository struct {
	db *gorm.DB
}

func New(db *gorm.DB) *Repository {
	return &Repository{db: db}
}

func (r *Repository) FindByLogin(ctx context.Context, login string) (*domain.User, error) {
	var user domain.User
	err := r.db.WithContext(ctx).
		Where("username = ? OR email = ?", login, login).
		First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *Repository) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	var user domain.User
	err := r.db.WithContext(ctx).Where("email = ?", email).First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *Repository) FindByID(ctx context.Context, id uint64) (*domain.User, error) {
	var user domain.User
	err := r.db.WithContext(ctx).First(&user, id).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *Repository) FindByPublicID(ctx context.Context, publicID string) (*domain.User, error) {
	var user domain.User
	err := r.db.WithContext(ctx).Where("public_id = ?", publicID).First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *Repository) List(ctx context.Context, limit, offset int) ([]domain.User, int64, error) {
	var users []domain.User
	var total int64

	if err := r.db.WithContext(ctx).Model(&domain.User{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}
	err := r.db.WithContext(ctx).
		Order("id ASC").
		Limit(limit).
		Offset(offset).
		Find(&users).Error
	if err != nil {
		return nil, 0, err
	}
	return users, total, nil
}

func (r *Repository) Create(ctx context.Context, user *domain.User) error {
	return r.db.WithContext(ctx).Create(user).Error
}

func (r *Repository) Save(ctx context.Context, user *domain.User) error {
	return r.db.WithContext(ctx).Save(user).Error
}

func (r *Repository) RecordLoginFailure(ctx context.Context, id uint64, lockUntil *time.Time) error {
	updates := map[string]any{
		"failed_login_count": gorm.Expr("failed_login_count + 1"),
	}
	if lockUntil != nil {
		updates["locked_until"] = lockUntil
		updates["status"] = domain.StatusLocked
	}
	return r.db.WithContext(ctx).Model(&domain.User{}).Where("id = ?", id).Updates(updates).Error
}

func (r *Repository) RecordLoginSuccess(ctx context.Context, id uint64, at time.Time) error {
	return r.db.WithContext(ctx).Model(&domain.User{}).Where("id = ?", id).Updates(map[string]any{
		"failed_login_count": 0,
		"locked_until":       nil,
		"last_login_at":      at,
		"status":             domain.StatusActive,
	}).Error
}
