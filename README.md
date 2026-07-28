# OpenIAM

OpenIAM is OpenRealm's private identity and access management platform. The repository contains a modular Go control plane and a separate Next.js management interface, with MySQL for durable identity data and Redis for ephemeral security state.

The backend implements real authentication (Argon2id credentials with account lockout and IP-based rate limiting), opaque Redis sessions with CSRF protection, RBAC enforcement middleware, and administrative APIs for users, roles, permissions, and grants. Feishu OAuth federation is implemented. OAuth 2.1 / OpenID Connect protocol endpoints are the next milestone and build on the existing schema and module boundaries.

## Stack

- Frontend: Next.js 16, React 19, Tailwind CSS 4, Shadcn-compatible components
- Backend: Go 1.24, Gin, GORM
- Storage: MySQL 8.4
- Cache: Redis 7.4
- Architecture: frontend/backend separation in a modular monorepo

## Repository

```text
OpenIAM/
├── backend/
│   ├── cmd/server/              # Service entry point
│   ├── internal/bootstrap/      # Explicit dependency composition
│   ├── internal/modules/        # Identity, RBAC, session, OAuth, audit
│   ├── internal/platform/       # Config, HTTP, MySQL, Redis, responses
│   └── migrations/              # Reversible MySQL schema migrations
├── frontend/
│   └── src/
│       ├── app/                 # Next.js App Router routes
│       ├── components/          # Product and Shadcn-style UI
│       ├── lib/                 # API and shared utilities
│       └── proxy.ts             # Early session-aware route redirects
├── docs/                        # Architecture, API, data, ADRs, setup
├── compose.yaml
└── package.json                 # npm workspace entry point
```

## Local Development

Requirements: Go 1.24+, Node.js 22+, npm 10+, and Docker Compose.

Create local environment settings:

```bash
cp .env.example .env
```

Start MySQL and Redis:

```bash
docker compose up -d mysql redis
```

Apply the schema and seed the initial administrator, permission catalog, and roles:

```bash
cd backend
go run ./cmd/migrate
go run ./cmd/seed
```

The seed creates an `admin` account. Set its password explicitly:

```bash
OPENIAM_ADMIN_PASSWORD='your-strong-password' go run ./cmd/seed
```

If `OPENIAM_ADMIN_PASSWORD` is unset outside production, the seed generates a
random password and prints it once. When `OPENIAM_ENV=production` the variable
is required and the seed fails without it.

Start the backend in a second terminal:

```bash
cd backend
go run ./cmd/server
```

Start the frontend from the repository root:

```bash
npm install
npm run dev
```

Default endpoints:

- Frontend: `http://localhost:3000`
- Backend liveness: `http://localhost:8080/health/live`
- Backend readiness: `http://localhost:8080/health/ready`

## Validation

```bash
cd backend
go test ./...
go build ./cmd/server

cd ../frontend
npm run lint
npm run typecheck
npm run build
```

Production dependency audit:

```bash
npm audit --omit=dev
```

## Security Baseline

- Browser authentication uses an opaque `HttpOnly` session cookie stored in Redis.
- Passwords are hashed with Argon2id; repeated failures trigger timed account lockout.
- Login attempts are rate-limited by IP (20/min) and per-account (10/15min).
- State-changing requests require a CSRF token bound to the session.
- Feishu OAuth federation provisions federated users automatically.
- OAuth applications will use Authorization Code with PKCE S256.
- OpenID Connect will provide login and SSO semantics.
- The Go API is the final enforcement point for every RBAC decision.
- Client secrets, tokens, passwords, and signing keys are never stored in plaintext.

See [`docs/architecture/overview.md`](docs/architecture/overview.md), [`docs/architecture/authentication-flow.md`](docs/architecture/authentication-flow.md), [`docs/api/management.md`](docs/api/management.md), and [`docs/database/redis-keys.md`](docs/database/redis-keys.md) for the detailed decisions.

## Next Milestone

1. Implement OAuth 2.1 Authorization Code with PKCE and OIDC discovery/JWKS.
2. Wire the Next.js console to the real backend APIs (replacing the dev-only session preview).
3. Add audit log querying API and refresh-token rotation for OAuth clients.
4. Invalidate cached permissions for all holders when a role's permissions change.
5. Add audit records for role and permission administration, not just logins.

## License

GNU Lesser General Public License v2.1. See [`LICENSE`](LICENSE).
