# Management API

Base path: `/api/v1`. All responses wrap payloads in `data` and errors in `error`, each with a `requestId`.

## Authentication

| Method | Path | Auth | CSRF | Description |
| --- | --- | --- | --- | --- |
| POST | `/auth/login` | public | no | Verify credentials, issue session cookie, return CSRF token |
| GET | `/auth/me` | session | no | Current user, permissions, and CSRF token |
| POST | `/auth/logout` | session | yes | Revoke session and clear cookie |
| GET | `/auth/feishu` | public | no | Start Feishu OAuth login (redirects to Feishu) |
| GET | `/auth/feishu/callback` | public | no | Feishu callback: exchange code, provision user, issue session |

Login accepts `{ "login": "username-or-email", "password": "..." }`. Failures return a single generic `AUTH_INVALID_CREDENTIALS` error to avoid account enumeration. Repeated failures lock the account for `OPENIAM_LOGIN_LOCK_DURATION`.

The session cookie is `HttpOnly`, `SameSite=Lax`, `Secure` in production. The CSRF token returned by `/auth/login` and `/auth/me` must be sent as the `X-CSRF-Token` header on every state-changing request.

### Feishu OAuth Login

`/auth/feishu` generates a single-use `state` (stored in Redis for 5 minutes) and redirects to Feishu's authorization page. Feishu redirects back to `/auth/feishu/callback` with `code` and `state`; the callback atomically consumes the state (`GETDEL`), exchanges the code for the user profile, then finds or provisions a local user by email (SSO users have no password) and issues a session cookie before redirecting to the frontend. Failures redirect to `/login?error=<reason>`.

## System

| Method | Path | Permission | CSRF | Description |
| --- | --- | --- | --- | --- |
| POST | `/system/mail/test` | `system:mail-test` | yes | Send an SMTP test email to `{ "to": "..." }` |

When `OPENIAM_SMTP_HOST` is empty, all outbound mail is logged instead of sent, so user creation and the test endpoint remain functional in development.

## Users

| Method | Path | Permission | CSRF | Description |
| --- | --- | --- | --- | --- |
| GET | `/users` | `users:read` | no | Paginated list (`?limit=&page=`) |
| POST | `/users` | `users:create` | yes | Create a user |
| GET | `/users/:id` | `users:read` | no | Fetch by public id |
| PATCH | `/users/:id` | `users:update` | yes | Update display name or status |
| GET | `/users/:id/roles` | `roles:read` | no | List assigned role codes |
| PUT | `/users/:id/roles` | `roles:assign` | yes | Replace assigned roles |

## Roles

| Method | Path | Permission | CSRF | Description |
| --- | --- | --- | --- | --- |
| GET | `/roles` | `roles:read` | no | List roles |
| POST | `/roles` | `roles:create` | yes | Create a role |
| GET | `/roles/:code` | `roles:read` | no | Role with its permission codes |
| PUT | `/roles/:code/permissions` | `roles:update` | yes | Replace role permissions |

## Permissions

| Method | Path | Permission | CSRF | Description |
| --- | --- | --- | --- | --- |
| GET | `/permissions` | `permissions:read` | no | Permission catalog |

## Authorization Model

Permissions use `resource:action` codes. A user's effective permissions are the union of permissions bound to their active, non-expired roles. The `*:*` wildcard grants every permission and is reserved for the system `super-admin` role. Effective permissions are cached in Redis (`user-permissions:{userId}`, 10 minute TTL) and invalidated on role reassignment.

### Super-Admin vs Admin

Two system roles define the privilege tiers:

- **super-admin** holds `*:*` and can manage roles, permissions, role assignment, user disabling, OAuth client secrets, and system configuration (`system:mail-test`, `system:settings`).
- **admin** holds an operational subset: `users:read/create/update`, `roles:read`, `permissions:read`, `oauth-clients:read`, `audit-logs:read`, `sessions:revoke`. It cannot create or modify roles, assign roles, disable users, rotate client secrets, or touch system settings.

Disabling or locking a user through `PATCH /users/:id` additionally requires `users:disable`, so an `admin` can edit profiles but cannot deactivate accounts. The full permission catalog and role definitions live in `backend/internal/modules/rbac/catalog`, and a test enforces that `admin` never contains a privileged permission.
