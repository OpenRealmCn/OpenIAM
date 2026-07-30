package repository

import (
	"context"
	"errors"
	"time"

	"github.com/openrealm/openiam/backend/internal/modules/rbac/domain"
	"gorm.io/gorm"
)

var ErrRoleNotFound = errors.New("role not found")

type Repository struct {
	db *gorm.DB
}

func New(db *gorm.DB) *Repository {
	return &Repository{db: db}
}

func (r *Repository) UserPermissionCodes(ctx context.Context, userID uint64) ([]string, error) {
	var codes []string
	err := r.db.WithContext(ctx).
		Table("permissions AS p").
		Select("DISTINCT p.code").
		Joins("JOIN role_permissions AS rp ON rp.permission_id = p.id").
		Joins("JOIN roles AS r ON r.id = rp.role_id AND r.deleted_at IS NULL AND r.status = ?", domain.RoleStatusActive).
		Joins("JOIN user_roles AS ur ON ur.role_id = r.id AND (ur.expires_at IS NULL OR ur.expires_at > ?)", time.Now().UTC()).
		Where("ur.user_id = ?", userID).
		Pluck("p.code", &codes).Error
	if err != nil {
		return nil, err
	}
	return codes, nil
}

func (r *Repository) ListRoles(ctx context.Context) ([]domain.Role, error) {
	var roles []domain.Role
	err := r.db.WithContext(ctx).Order("id ASC").Find(&roles).Error
	return roles, err
}

func (r *Repository) GetRoleByCode(ctx context.Context, code string) (*domain.Role, error) {
	var role domain.Role
	err := r.db.WithContext(ctx).Where("code = ?", code).First(&role).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrRoleNotFound
	}
	if err != nil {
		return nil, err
	}
	return &role, nil
}

func (r *Repository) CreateRole(ctx context.Context, role *domain.Role) error {
	return r.db.WithContext(ctx).Create(role).Error
}

func (r *Repository) DeleteRole(ctx context.Context, roleID uint64) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("role_id = ?", roleID).Delete(&domain.RolePermission{}).Error; err != nil {
			return err
		}
		if err := tx.Where("role_id = ?", roleID).Delete(&domain.UserRole{}).Error; err != nil {
			return err
		}
		return tx.Unscoped().Delete(&domain.Role{}, roleID).Error
	})
}

func (r *Repository) ListPermissions(ctx context.Context) ([]domain.Permission, error) {
	var permissions []domain.Permission
	err := r.db.WithContext(ctx).Order("resource ASC, action ASC").Find(&permissions).Error
	return permissions, err
}

func (r *Repository) PermissionIDsByCodes(ctx context.Context, codes []string) (map[string]uint64, error) {
	if len(codes) == 0 {
		return map[string]uint64{}, nil
	}
	var permissions []domain.Permission
	if err := r.db.WithContext(ctx).Where("code IN ?", codes).Find(&permissions).Error; err != nil {
		return nil, err
	}
	ids := make(map[string]uint64, len(permissions))
	for _, p := range permissions {
		ids[p.Code] = p.ID
	}
	return ids, nil
}

func (r *Repository) RolePermissionCodes(ctx context.Context, roleID uint64) ([]string, error) {
	var codes []string
	err := r.db.WithContext(ctx).
		Table("permissions AS p").
		Select("p.code").
		Joins("JOIN role_permissions AS rp ON rp.permission_id = p.id").
		Where("rp.role_id = ?", roleID).
		Pluck("p.code", &codes).Error
	return codes, err
}

func (r *Repository) ReplaceRolePermissions(ctx context.Context, roleID uint64, permissionIDs []uint64) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("role_id = ?", roleID).Delete(&domain.RolePermission{}).Error; err != nil {
			return err
		}
		if len(permissionIDs) == 0 {
			return nil
		}
		now := time.Now().UTC()
		records := make([]domain.RolePermission, 0, len(permissionIDs))
		for _, pid := range permissionIDs {
			records = append(records, domain.RolePermission{RoleID: roleID, PermissionID: pid, GrantedAt: now})
		}
		return tx.Create(&records).Error
	})
}

func (r *Repository) UserRoleCodes(ctx context.Context, userID uint64) ([]string, error) {
	var codes []string
	err := r.db.WithContext(ctx).
		Table("roles AS r").
		Select("r.code").
		Joins("JOIN user_roles AS ur ON ur.role_id = r.id AND (ur.expires_at IS NULL OR ur.expires_at > ?)", time.Now().UTC()).
		Where("ur.user_id = ? AND r.deleted_at IS NULL", userID).
		Pluck("r.code", &codes).Error
	return codes, err
}

func (r *Repository) ReplaceUserRoles(ctx context.Context, userID uint64, roleIDs []uint64, grantedBy *uint64) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("user_id = ?", userID).Delete(&domain.UserRole{}).Error; err != nil {
			return err
		}
		if len(roleIDs) == 0 {
			return nil
		}
		now := time.Now().UTC()
		records := make([]domain.UserRole, 0, len(roleIDs))
		for _, rid := range roleIDs {
			records = append(records, domain.UserRole{UserID: userID, RoleID: rid, GrantedBy: grantedBy, GrantedAt: now})
		}
		return tx.Create(&records).Error
	})
}

func (r *Repository) RoleIDsByCodes(ctx context.Context, codes []string) (map[string]uint64, error) {
	if len(codes) == 0 {
		return map[string]uint64{}, nil
	}
	var roles []domain.Role
	if err := r.db.WithContext(ctx).Where("code IN ?", codes).Find(&roles).Error; err != nil {
		return nil, err
	}
	ids := make(map[string]uint64, len(roles))
	for _, role := range roles {
		ids[role.Code] = role.ID
	}
	return ids, nil
}

// UserIDsWithRole returns all user IDs currently assigned the given role.
// Expired grants are excluded.
func (r *Repository) UserIDsWithRole(ctx context.Context, roleID uint64) ([]uint64, error) {
	var userIDs []uint64
	err := r.db.WithContext(ctx).
		Table("user_roles").
		Select("DISTINCT user_id").
		Where("role_id = ? AND (expires_at IS NULL OR expires_at > ?)", roleID, time.Now().UTC()).
		Pluck("user_id", &userIDs).Error
	return userIDs, err
}
