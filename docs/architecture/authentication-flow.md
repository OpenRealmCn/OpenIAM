# Authentication Flow

The management console uses an opaque session cookie named `openiam_session`. The cookie is `HttpOnly`, `Secure` in production, `SameSite=Lax`, and scoped to `/`.

1. The browser submits credentials and a CSRF token to the Go API.
2. The API verifies credentials and account state.
3. The API rotates the session identifier and stores session metadata in Redis.
4. The browser receives only the opaque session cookie.
5. Protected API requests resolve the session and enforce RBAC in Go.

OAuth clients use Authorization Code with PKCE S256. OpenID Connect supplies identity and SSO semantics. Implicit and password grants are not supported.
