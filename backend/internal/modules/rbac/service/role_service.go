package service

import (
	"context"
	"errors"
	"strings"

	"github.com/openrealm/openiam/backend/internal/modules/rbac/domain"
	"github.com/openrealm/openiam/backend/internal/modules/rbac/repository"
)

var (
	ErrRoleExists   = errors.New("role already exists")
	ErrRoleNotFound = repository.ErrRoleNotFound
	ErrUnknownCodes = errors.New("one or more codes do not exist")
)

type RBACRecorder interface {
	RecordRoleCreated(ctx context.Context, actorUserID uint64, roleCode string)
	RecordRolePermissionsChanged(ctx context.Context, actorUserID uint64, roleCode string)
	RecordUserRolesChanged(ctx context.Context, actorUserID, targetUserID uint64, targetPublicID string)
}

type RoleService struct {
	repo    *repository.Repository
	checker *Checker
	audit   RBACRecorder
}

func NewRoleService(repo *repository.Repository, checker *Checker, audit RBACRecorder) *RoleService {
	return &RoleService{repo: repo, checker: checker, audit: audit}
}

func (s *RoleService) ListRoles(ctx context.Context) ([]domain.Role, error) {
	return s.repo.ListRoles(ctx)
}

func (s *RoleService) ListPermissions(ctx context.Context) ([]domain.Permission, error) {
	return s.repo.ListPermissions(ctx)
}

type CreateRoleInput struct {
	Code        string
	Name        string
	Description string
}

func (s *RoleService) CreateRole(ctx context.Context, actorUserID uint64, in CreateRoleInput) (*domain.Role, error) {
	in.Code = strings.TrimSpace(in.Code)
	in.Name = strings.TrimSpace(in.Name)
	if in.Code == "" || in.Name == "" {
		return nil, errors.New("code and name are required")
	}

	role := &domain.Role{
		Code:   in.Code,
		Name:   in.Name,
		Status: domain.RoleStatusActive,
	}
	if in.Description != "" {
		role.Description = &in.Description
	}

	if err := s.repo.CreateRole(ctx, role); err != nil {
		if strings.Contains(err.Error(), "Duplicate entry") {
			return nil, ErrRoleExists
		}
		return nil, err
	}

	if s.audit != nil {
		s.audit.RecordRoleCreated(ctx, actorUserID, role.Code)
	}

	return role, nil
}

func (s *RoleService) RolePermissions(ctx context.Context, code string) ([]string, error) {
	role, err := s.repo.GetRoleByCode(ctx, code)
	if err != nil {
		return nil, err
	}
	return s.repo.RolePermissionCodes(ctx, role.ID)
}

func (s *RoleService) ReplaceRolePermissions(ctx context.Context, actorUserID uint64, code string, permissionCodes []string) error {
	role, err := s.repo.GetRoleByCode(ctx, code)
	if err != nil {
		return err
	}

	ids, err := s.repo.PermissionIDsByCodes(ctx, permissionCodes)
	if err != nil {
		return err
	}

	permissionIDs := make([]uint64, 0, len(permissionCodes))
	for _, c := range permissionCodes {
		id, ok := ids[c]
		if !ok {
			return ErrUnknownCodes
		}
		permissionIDs = append(permissionIDs, id)
	}

	if err := s.repo.ReplaceRolePermissions(ctx, role.ID, permissionIDs); err != nil {
		return err
	}

	// Invalidate permission cache for all users holding this role, since their
	// effective permissions have changed. Without this, users retain old permissions
	// until the cache TTL expires (10 minutes).
	if s.checker != nil {
		userIDs, err := s.repo.UserIDsWithRole(ctx, role.ID)
		if err != nil {
			// Log but don't fail the operation; cache will expire naturally
			return nil
		}
		for _, userID := range userIDs {
			s.checker.Invalidate(ctx, userID)
		}
	}

	if s.audit != nil {
		s.audit.RecordRolePermissionsChanged(ctx, actorUserID, code)
	}

	return nil
}

type GrantService struct {
	repo    *repository.Repository
	checker *Checker
	audit   RBACRecorder
}

func NewGrantService(repo *repository.Repository, checker *Checker, audit RBACRecorder) *GrantService {
	return &GrantService{repo: repo, checker: checker, audit: audit}
}

func (s *GrantService) UserRoles(ctx context.Context, userID uint64) ([]string, error) {
	return s.repo.UserRoleCodes(ctx, userID)
}

func (s *GrantService) ReplaceUserRoles(ctx context.Context, userID uint64, userPublicID string, roleCodes []string, grantedBy *uint64) error {
	ids, err := s.repo.RoleIDsByCodes(ctx, roleCodes)
	if err != nil {
		return err
	}

	roleIDs := make([]uint64, 0, len(roleCodes))
	for _, code := range roleCodes {
		id, ok := ids[code]
		if !ok {
			return ErrUnknownCodes
		}
		roleIDs = append(roleIDs, id)
	}

	if err := s.repo.ReplaceUserRoles(ctx, userID, roleIDs, grantedBy); err != nil {
		return err
	}

	s.checker.Invalidate(ctx, userID)

	if s.audit != nil && grantedBy != nil {
		s.audit.RecordUserRolesChanged(ctx, *grantedBy, userID, userPublicID)
	}

	return nil
}
