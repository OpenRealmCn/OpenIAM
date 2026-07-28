# API Conventions

Management endpoints use `/api/v1`. Protocol endpoints use `/oauth2` and `/.well-known` paths required by OAuth and OpenID Connect.

Successful responses wrap resources in `data`. Errors return a stable machine code, a safe message, and the request ID.

```json
{
  "error": {
    "code": "AUTH_UNAUTHENTICATED",
    "message": "Authentication is required"
  },
  "requestId": "01JEXAMPLE"
}
```

The API never returns stack traces, SQL errors, credential existence, token contents, or password policy details in authentication failures.
