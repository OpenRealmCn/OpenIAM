# OpenIAM — OpenRealm 私有身份与访问管理平台

OpenIAM 是为 **OpenRealm** 打造的私有身份与访问管理（IAM）平台，采用模块化 **Go** 后端与 **React + MUI / MUI X** 前端控制台，使用 **MySQL** 进行身份与策略持久化存储，**Redis** 存储临时安全状态。

---

## 核心特性

1. **完整身份认证与安全状态管理（MySQL + Redis）**
   - RS256 非对称签名 JWT Access Token 与单次轮换（Rotation）Refresh Token。
   - Redis 管理 Refresh Token 会话、JWT 注销黑名单（JTI）、连续登录失败计数与临时锁定、OAuth 临时 State。
   - 基于 `github.com/ulule/limiter/v3` 的 IP 速率限制中间件（支持分布式 Redis 存储，区分认证严格限流与通用 API 限流）。
2. **多域 RBAC 权限控制（Casbin）**
   - 基于 `github.com/casbin/casbin/v3` + `gorm-adapter/v3` 实现 **RBAC with Domains** 模型，按 OpenRealm 业务域/租户隔离角色与权限。
   - 提供 `RequirePermission` 中间件（通过 `X-OpenIAM-Domain` 请求头自动识别域上下文）以及 `/api/v1/policies/check` 实时权限校验接口。
3. **数据库动态系统设置（无需维护 `config.yaml`）**
   - 本地仅需配置 **MySQL** 与 **Redis** 连接地址（环境变量或 `.env`），所有安全策略、JWT、IP 速率限制、CORS、OAuth 服务端与联合登录回调设置均存储在 MySQL `system_settings` 表中。
   - 管理员可在控制台「系统设置」面板在线修改并立即热生效，所有变更记入审计日志。
3. **全面安全审计（覆盖认证与 RBAC 变更）**
   - 不仅记录登录、注册、登出、联合登录、OAuth 授权同意等认证行为，还完整记录**角色创建/修改/删除、角色权限绑定、用户域角色分配/撤销、权限点与 Casbin 策略增删**的变更前后 JSON 快照（`before_state` / `after_state`），自动对密钥/密码脱敏。
4. **可插拔 OAuth 2.0 / OIDC 联合登录插件体系**
   - 定义标准 `oauthplugin.OAuthProviderPlugin` 接口与动态前端表单描述 `ConfigField`。
   - 内置 5 套适配器插件：
     - `generic_oidc`：通用 OIDC（支持 `.well-known/openid-configuration` 自动发现）或自定义 OAuth2 端点
     - `github`：GitHub OAuth App
     - `google`：Google OAuth 2.0 / OIDC
     - `feishu`：飞书 (Feishu / Lark)
     - `wecom`：企业微信 (WeCom)
5. **OpenIAM 作为 OAuth 2.0 / OIDC 授权服务端（IdP）**
   - 基于 `github.com/go-oauth2/oauth2/v4` 构建标准 OAuth 2.0 授权服务端，结合 MySQL `ClientStore` 与 Redis `TokenStore`。
   - 支持 `authorization_code`（含 PKCE S256）、`refresh_token`、`client_credentials`、OIDC `id_token` 签发，提供 Discovery (`/.well-known/openid-configuration`)、JWKS (`/.well-known/jwks.json`)、`/oauth2/authorize`、`/oauth2/token`、`/oauth2/userinfo`、`/oauth2/introspect`、`/oauth2/revoke` 及前端授权同意页。
6. **数据库迁移与版本检查**
   - 基于 `github.com/golang-migrate/migrate/v4` + `iofs` 内嵌 SQL 迁移脚本。
   - 支持启动时自动校验 `AppVersion` 与 `ExpectedSchemaVersion`，支持 `--migrate-only` 与 `--check-version` CLI 模式，并将检查与升级历史写入 `system_version_history` 表。

---

## 快速启动

### 方式一：Docker Compose 编排（MySQL 与 Redis 均支持外部接入或按需启用）

`docker-compose.yml` 默认仅启动 `backend` 和 `frontend`，通过环境变量连接已有 MySQL 和 Redis；如需一并拉起内置 MySQL / Redis 容器，使用 Docker Compose `profiles`：

```bash
# 1. 连接外部已有的 MySQL 和 Redis（参考 .env.example 设置 OPENIAM_MYSQL_DSN / OPENIAM_REDIS_ADDR）
docker compose up -d --build

# 2. 同时启动内置 MySQL + Redis（全套容器化）
docker compose --profile full up -d --build

# 3. 仅额外启动内置 Redis（使用外部 MySQL）
docker compose --profile redis up -d --build

# 4. 仅额外启动内置 MySQL（使用外部 Redis）
docker compose --profile mysql up -d --build
```

- 唯一对外主入口（控制台 + API + OIDC 反代）: `http://localhost:5173`（可通过 `OPENIAM_PORT` 修改，例如设为 `80`）
- 后端服务仅在 Docker 内网监听，不对外暴露端口；前端 Nginx 通过 `OPENIAM_BACKEND_UPSTREAM` 动态转发至后端
- 超级管理员账号: 用户名 `admin`，初始口令必须通过环境变量 `OPENIAM_SEED_ADMIN_PASSWORD` 显式设置（docker compose 未设置时会拒绝启动；后端也会在空库初始化时校验，未设置、长度/复杂度不达标或仍使用历史默认口令都会直接启动失败），初始化出来的账号带强制改密标记：登录后只能改密或退出，改密成功才解除限制；可信代理列表通过 `OPENIAM_TRUSTED_PROXIES` 配置
- 浏览器端 Refresh Token 通过 HttpOnly Cookie 下发，Access Token 仅保存在内存；非浏览器客户端可在请求头加 `X-Token-Delivery: body` 从响应体获取 Refresh Token
- 联合登录身份源与插件出站请求默认禁止指向内网地址（防 SSRF），自建内网服务可在管理员控制台「系统设置 -> 登录与安全」中开启 `security.allow_private_upstream`
- 完整安全审查结论见 `SECURITY_AUDIT.md`

### 方式二：本地开发启动

1. **配置本地 MySQL 8 与 Redis 7 连接**（可选复制 `.env.example` 为 `.env`）：
   ```bash
   cp .env.example .env
   ```
2. **启动后端服务**：
   ```bash
   cd backend
   go run ./cmd/server --check-version   # 可选：仅执行版本检查
   go run ./cmd/server --migrate-only    # 可选：仅执行数据库迁移
   go run ./cmd/server                   # 启动服务（默认开启 auto_migrate）
   ```
3. **启动前端控制台**：
   ```bash
   cd frontend
   npm install
   npm run dev
   ```

---

## 如何编写自定义 OAuth 联合登录插件

1. 在 `backend/internal/oauthplugin/` 下新建适配器结构体，实现 `OAuthProviderPlugin` 接口：
   ```go
   type OAuthProviderPlugin interface {
       Type() string
       Metadata() PluginMetadata
       AuthCodeURL(ctx context.Context, params AuthURLParams) (string, error)
       ExchangeAndFetchUser(ctx context.Context, params ExchangeParams) (*ExternalUserInfo, error)
   }
   ```
2. 在 `NewDefaultRegistry()` 中调用 `r.Register(NewMyCustomPlugin())`。
3. 前端管理页面会自动读取 `/api/v1/oauth-providers/plugins` 返回的 `config_fields` 元数据，自动渲染配置表单与登录按钮，无需修改前端代码。

---

## 如何让 OpenRealm 子应用接入 OpenIAM OAuth2 / OIDC

1. 在 OpenIAM 控制台进入 **OAuth 应用接入**，创建新应用并填写回调地址（如 `https://app.openrealm.local/callback`），保存一次性展示的 `Client ID` 和 `Client Secret`。
2. 在子应用的 OIDC 客户端库中配置（统一通过 OpenIAM 主入口访问）：
   - **Issuer / Discovery URL**: `http://localhost:5173/.well-known/openid-configuration`
   - **Authorization Endpoint**: `http://localhost:5173/oauth2/authorize`
   - **Token Endpoint**: `http://localhost:5173/oauth2/token`
   - **UserInfo Endpoint**: `http://localhost:5173/oauth2/userinfo`
   - **JWKS URI**: `http://localhost:5173/.well-known/jwks.json`
3. 业务服务如需校验用户在特定 OpenRealm 域下的细粒度权限，可直接调用 `POST /api/v1/policies/check`（传 `user_id`, `domain`, `resource`, `action`）或使用 JWKS 本地验证 JWT 后在网关层集成。
