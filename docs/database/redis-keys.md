# Redis Key Conventions

All keys use `openiam:{environment}:v1:{domain}:{identifier}`. Sensitive values are hashed before being placed in a key.

| Pattern | TTL | Purpose |
| --- | --- | --- |
| `session:{sid}` | 12 hours | Browser SSO session |
| `oauth:code:{sha256}` | 5 minutes | Atomic one-time authorization code |
| `refresh:{sha256}` | 30 days | Refresh token metadata |
| `refresh-family:{id}` | 30 days | Rotation and reuse detection |
| `revoked-jti:{jti}` | Token remainder | Access-token revocation |
| `user-permissions:{userId}` | 10 minutes | RBAC cache |
| `rate-limit:login:ip:{ipHash}` | 1 minute | Login throttling |
| `rate-limit:login:user:{userHash}` | 15 minutes | Brute-force defense |

Authorization-code exchange and refresh-token rotation must use a transaction or Lua script so consumption is atomic.
