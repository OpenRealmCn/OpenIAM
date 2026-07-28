# OpenIAM

OpenIAM is OpenRealm's private identity and access management platform. The repository contains a modular Go control plane and a separate Next.js management interface, with MySQL for durable identity data and Redis for ephemeral security state.

The current milestone is a verified project foundation. It intentionally does not accept credentials yet; authentication, RBAC enforcement, and OAuth/OIDC protocol endpoints will be implemented on top of the established module boundaries.

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

- Browser authentication will use an opaque `HttpOnly` session cookie.
- OAuth applications will use Authorization Code with PKCE S256.
- OpenID Connect will provide login and SSO semantics.
- The Go API is the final enforcement point for every RBAC decision.
- Client secrets, tokens, passwords, and signing keys are never stored in plaintext.
- Login controls remain disabled until the credential and session services are complete.

See [`docs/architecture/overview.md`](docs/architecture/overview.md), [`docs/architecture/authentication-flow.md`](docs/architecture/authentication-flow.md), and [`docs/database/redis-keys.md`](docs/database/redis-keys.md) for the detailed decisions.

## Next Milestone

1. Add migration execution and seed the initial administrator and permission catalog.
2. Implement Argon2id credential verification and account lockout.
3. Implement opaque Redis sessions, CSRF protection, and logout.
4. Add RBAC repositories, permission middleware, and administrative APIs.
5. Implement OAuth 2.1 Authorization Code with PKCE and OIDC discovery/JWKS.

## License

GNU Lesser General Public License v2.1. See [`LICENSE`](LICENSE).
