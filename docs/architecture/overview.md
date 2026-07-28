# Architecture Overview

OpenIAM starts as a modular monolith with a separate Next.js frontend and Go API. The backend owns all authentication and authorization decisions. MySQL stores durable identity data and Redis stores ephemeral sessions, one-time authorization codes, revocation markers, rate limits, and caches.

## Modules

| Module | Responsibility |
| --- | --- |
| Identity | Users, credentials, profile, and account state |
| RBAC | Roles, permissions, grants, and permission checks |
| Session | Browser sessions and refresh-token families |
| OAuth | OAuth 2.1 and OpenID Connect protocol endpoints |
| Audit | Security and administrative event records |

Modules expose narrow interfaces to each other. A module must not import another module's persistence implementation.

## Trust Boundaries

- The browser is untrusted.
- Next.js route checks improve navigation but are not authorization controls.
- The Go API is the enforcement point for authentication and RBAC.
- Secrets and signing keys are never exposed through `NEXT_PUBLIC_*` variables.
- Production traffic must terminate TLS before reaching either application.
