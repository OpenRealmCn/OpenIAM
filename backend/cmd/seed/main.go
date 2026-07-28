package main

import (
	"context"
	"errors"
	"log"
	"os"
	"strings"
	"time"

	"github.com/openrealm/openiam/backend/internal/modules/identity/domain"
	identityrepo "github.com/openrealm/openiam/backend/internal/modules/identity/repository"
	"github.com/openrealm/openiam/backend/internal/modules/rbac/catalog"
	rbacdomain "github.com/openrealm/openiam/backend/internal/modules/rbac/domain"
	rbacrepo "github.com/openrealm/openiam/backend/internal/modules/rbac/repository"
	"github.com/openrealm/openiam/backend/internal/platform/config"
	"github.com/openrealm/openiam/backend/internal/platform/crypto"
	"github.com/openrealm/openiam/backend/internal/platform/database"
	"gorm.io/gorm"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	db, err := database.Open(cfg.Database)
	if err != nil {
		log.Fatalf("connect to MySQL: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := seedPermissions(ctx, db); err != nil {
		log.Fatalf("seed permissions: %v", err)
	}
	if err := seedRoles(ctx, db); err != nil {
		log.Fatalf("seed roles: %v", err)
	}
	if err := seedAdmin(ctx, db, cfg); err != nil {
		log.Fatalf("seed admin: %v", err)
	}

	log.Println("seed completed")
}

func seedPermissions(ctx context.Context, db *gorm.DB) error {
	for _, p := range catalog.Permissions {
		var count int64
		if err := db.WithContext(ctx).Model(&rbacdomain.Permission{}).Where("code = ?", p.Code).Count(&count).Error; err != nil {
			return err
		}
		if count > 0 {
			continue
		}
		permission := rbacdomain.Permission{
			Code:        p.Code,
			Resource:    p.Resource,
			Action:      p.Action,
			Name:        p.Name,
			Description: &p.Description,
		}
		if err := db.WithContext(ctx).Create(&permission).Error; err != nil {
			return err
		}
		log.Printf("permission seeded: %s", p.Code)
	}
	return nil
}

func seedRoles(ctx context.Context, db *gorm.DB) error {
	repo := rbacrepo.New(db)

	for _, r := range catalog.Roles {
		role, err := repo.GetRoleByCode(ctx, r.Code)
		if err != nil && !errors.Is(err, rbacrepo.ErrRoleNotFound) {
			return err
		}
		if role == nil {
			description := r.Description
			created := &rbacdomain.Role{
				Code:        r.Code,
				Name:        r.Name,
				Description: &description,
				IsSystem:    r.IsSystem,
				Status:      rbacdomain.RoleStatusActive,
			}
			if err := repo.CreateRole(ctx, created); err != nil {
				return err
			}
			role = created
			log.Printf("role seeded: %s", r.Code)
		}

		ids, err := repo.PermissionIDsByCodes(ctx, r.Permissions)
		if err != nil {
			return err
		}
		permissionIDs := make([]uint64, 0, len(r.Permissions))
		for _, code := range r.Permissions {
			if code == catalog.WildcardPermission {
				continue
			}
			if id, ok := ids[code]; ok {
				permissionIDs = append(permissionIDs, id)
			}
		}
		if err := repo.ReplaceRolePermissions(ctx, role.ID, permissionIDs); err != nil {
			return err
		}
	}
	return nil
}

func seedAdmin(ctx context.Context, db *gorm.DB, cfg config.Config) error {
	users := identityrepo.New(db)
	repo := rbacrepo.New(db)

	const username = "admin"
	existing, err := users.FindByLogin(ctx, username)
	if err != nil && !errors.Is(err, identityrepo.ErrUserNotFound) {
		return err
	}

	password := os.Getenv("OPENIAM_ADMIN_PASSWORD")
	generated := false
	if password == "" {
		if cfg.Environment == "production" {
			return errors.New("OPENIAM_ADMIN_PASSWORD is required when OPENIAM_ENV=production")
		}
		// Outside production, generate a single-use random password rather than
		// falling back to a well-known constant. It is printed once below.
		password = crypto.Token(24)
		generated = true
	}
	if len(password) < cfg.Security.PasswordMinLength {
		return errors.New("OPENIAM_ADMIN_PASSWORD does not meet the password policy")
	}

	var admin *domain.User
	if existing != nil {
		admin = existing
	} else {
		hash, err := crypto.HashPassword(password)
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		admin = &domain.User{
			PublicID:          crypto.NewID(),
			Username:          username,
			Email:             "admin@openrealm.io",
			PasswordHash:      &hash,
			DisplayName:       "Platform Administrator",
			Status:            domain.StatusActive,
			PasswordChangedAt: &now,
		}
		if err := users.Create(ctx, admin); err != nil {
			if strings.Contains(err.Error(), "Duplicate entry") {
				admin, err = users.FindByLogin(ctx, username)
				if err != nil {
					return err
				}
			} else {
				return err
			}
		} else {
			log.Printf("admin user seeded: %s", username)
			if generated {
				log.Printf("generated admin password (shown once, store it now): %s", password)
			}
		}
	}

	roleIDs, err := repo.RoleIDsByCodes(ctx, []string{"super-admin"})
	if err != nil {
		return err
	}
	ids := make([]uint64, 0, len(roleIDs))
	for _, id := range roleIDs {
		ids = append(ids, id)
	}
	if err := repo.ReplaceUserRoles(ctx, admin.ID, ids, nil); err != nil {
		return err
	}

	log.Printf("admin granted role: super-admin")
	return nil
}
