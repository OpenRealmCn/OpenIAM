# OpenIAM 代码安全审查报告

审查范围：`backend/`（Go）、`frontend/`（React）、`docker-compose.yml`、两个 Dockerfile、nginx 配置与迁移脚本，共 89 个已跟踪文件。

## 验证情况

- 后端：`go build`、`go vet`、`go test ./...` 全部通过。新增回归测试：`privilege_test.go`（域管理员提权）、`session_test.go`（改密或重置密码后会话失效、列表接口域收敛、`/policies/check` 限制）、`cookie_test.go`（HttpOnly Cookie 刷新令牌）、`ssrf_test.go`（身份源地址与回调地址校验）。
- 前端：`npm run build`（`tsc -b && vite build`）通过。
- 未验证：Docker 镜像构建；nginx 新增响应头与 CSP 在浏览器中的实际表现；Cookie 刷新流程在真实浏览器与 HTTPS 反代下的端到端表现；SSRF 拨号拦截只验证了地址校验逻辑，没有对真实内网目标做连通性测试。
- 没有专门自动化测试的改动：OAuth scope 与 PKCE 限制、联合登录拒绝邮箱关联、自助应用限制、审计脱敏、CORS、可信代理、系统设置范围校验。

## 已修复

### 严重 / 高危

1. 域管理员可自我提权为超级管理员：角色分配、策略增删、角色权限设置原先使用请求体中的域，未校验该域的权限。现已新增 `handlers/authz.go`，按目标域校验，禁止非超级管理员授予 `super_admin`、配置通配符策略、操作超级管理员账号。
2. 第三方 OAuth 令牌可当作管理令牌：`AuthMiddleware` 现拒绝带 `client_id` 或 `uid=0` 的令牌。
3. 注销黑名单在 Redis 出错时放行：改为 fail-closed。
4. 修改或重置密码、禁用或删除用户后，旧令牌不失效：新增按用户的「令牌失效时间点」，此前签发的 Access Token 与 Refresh Token 全部失效；改密接口返回 `relogin_required`。
5. OAuth 服务端：redirect_uri 校验限定到发起请求的客户端；PKCE 仅允许 S256；scope 限定在客户端登记范围内；授权同意请求改为原子消费，防止重放；`introspect` 和 `revoke` 要求客户端认证；`userinfo` 拒绝已禁用用户；授权类型列表为空时不再默认放行。
6. 联合登录账号接管：外部邮箱未必经过验证，邮箱与本地账号冲突时直接拒绝，不再自动关联。
7. 联合登录身份源 SSRF：身份源地址必须是 https 且不得指向内网或保留地址；出站请求使用受限客户端，在拨号阶段拦截内网 IP（覆盖 DNS 重绑定与重定向），带超时并限制重定向次数。确需接入内网 IdP 时，可在管理员面板「系统设置」开启 `security.allow_private_upstream`。
8. 联合登录回调 `redirect_uri` 可被请求方任意覆盖：现在只允许系统配置的回调地址，或已登记 CORS 来源下的 `/oauth/callback/{provider}`。
9. 域管理员默认权限过大：默认不再授予 `settings`、`oauth_providers`、`domains` 的写权限。
10. 普通用户自助创建 OAuth 应用：限制授权类型、scope、回调地址（https，或本机回环 http），并强制归属默认域。
11. 前端令牌存放在 `localStorage`：现在 Access Token 只保存在内存中，Refresh Token 由服务端以 `HttpOnly`、`SameSite=Strict`、`Path=/api/v1/auth` 的 Cookie 下发，页面加载时静默刷新，并清理旧版本遗留在 `localStorage` 的令牌。非浏览器客户端可在请求头加 `X-Token-Delivery: body`，继续从响应体获取 Refresh Token。

### 中危

- 列表接口跨域读取：角色、权限点、OAuth 应用、审计日志、策略列表的 `domain` 参数对非超级管理员不再生效，固定为已通过权限校验的请求域；`GET /domains` 只返回调用者持有角色的域；用户列表与用户角色查询只暴露请求域内的角色；OAuth 应用的创建、修改、轮换密钥、删除按目标应用所属域校验权限。
- `/policies/check`：查询他人权限需要在目标域拥有 `permissions:read`，查询自己不受限。
- 系统设置：整数项增加取值范围，URL 类设置必须是有效的 http(s) 地址，CORS 来源必须形如 `scheme://host[:port]` 且不允许通配符。
- 分页 `page` 上限 10000；审计统计改为数据库聚合计数，不再把记录读入内存。
- 限流与审计 IP 可伪造：新增 `OPENIAM_TRUSTED_PROXIES`，仅采信可信代理的 `X-Forwarded-For`。
- 服务器无超时、无请求体限制：改用 `http.Server` 设置超时，请求体上限 1 MiB。
- CORS：来源列表为空时不再放行所有来源，不再带 `Allow-Credentials`。
- 访问日志不再记录完整 query，避免带出 `code`、`state`、token。
- 登录：失败计数与锁定统一按规范用户名，邮箱登录无法绕过；禁用账号与密码错误返回相同提示；密码长度 8~72；用户名禁止包含 `@`。
- 不再向客户端返回数据库和内部错误文本。
- `/auth/me` 只返回当前用户所持角色的策略。
- 审计脱敏：补全敏感键、忽略大小写、处理数组内嵌套对象。
- 部署：MySQL、Redis 端口仅绑定 `127.0.0.1`；compose 必须显式设置管理员口令；默认口令启动时告警；后端容器非 root 运行；前端使用 `npm ci`；nginx 增加安全响应头、CSP、`server_tokens off`、请求体限制。
- 依赖：`go mod tidy` 已执行，`go-sql-driver/mysql` 调整为直接依赖。

## 复审修复（/code-review 发现的问题）

1. 域管理员自行授权提权：非超级管理员配置策略或角色权限时，只能授予自己在目标域已持有的权限；`settings`、`oauth_providers`、`domains`、`system` 的写权限仅超级管理员可授予。移除策略不受「已持有」限制。
2. 跨域操作用户：非超级管理员重置密码、禁用、修改、删除用户时，目标用户必须在请求域内持有角色，且不得同时属于其他域，否则返回 403。
3. OAuth 回调地址校验：校验函数只在发起请求的客户端自己登记的回调地址内匹配，不再遍历其他客户端。
4. `introspect` 与 `revoke`：令牌必须属于已认证的客户端，不属于时 `introspect` 返回 `active:false`，`revoke` 静默成功且不撤销；公共客户端可凭 `client_id` 撤销自己的令牌（RFC 7009）。
5. 令牌失效范围扩大到 OAuth2 服务端：`userinfo` 与 `introspect` 同样检查用户级失效时间点，Redis 异常时按已失效处理；禁用或删除用户时撤销失败会返回错误，不再被忽略。
6. CORS：仅对白名单内的具体来源返回 `Access-Control-Allow-Credentials`，预检允许 `X-Token-Delivery`，前端请求带 `withCredentials`。控制台与 API 不同源时 Refresh Cookie 才能工作；`SameSite=Strict` 在跨站部署下仍可能被浏览器拦截，推荐同源反代部署。
7. 口令长度按 UTF-8 字节数校验（新增 `maxbytes` 规则，覆盖注册、改密、管理员创建与重置、个人资料改密），含中文或 emoji 的口令超过 72 字节时返回 400。
8. 默认口令：`.env.example` 中该项留空；release 模式下口令为空或为公开默认值时后端拒绝启动，非 release 模式只告警；compose 不再用 `:?` 强制变量，`docker compose down` 等命令不受影响。
9. 联合登录邮箱冲突：被拒绝的尝试写入审计日志，提示用户先登录再在个人中心绑定；已删除不再使用的邮箱关联分支。

新增回归测试集中在 `review_fix_test.go`，覆盖第 1、2、4、6、7 项。第 3 项（跨客户端回调地址）、第 5 项（OAuth2 令牌失效）、第 8 项（启动拒绝）没有专门测试。

## 企业版功能复审（TOTP、OTP、风控、JIT、会话、插件）

1. 二步验证暴力破解：`/auth/mfa/verify` 现按 mfa_token（5 次）与用户（10 次）双重计数，超限后销毁挑战并返回 429，Redis 异常时按已锁定处理。
2. 验证码并发绕过：OTP 与密码重置验证码的错误计数改为原子自增，验证码以 DEL 返回值原子消费；密码重置验证码连续输错 5 次作废。
3. 公开 OTP 发送接口：仅允许 login 场景，账号不存在时返回统一成功响应而不真正发送；降级提示中的邮箱已脱敏；邮件正文做 HTML 转义。
4. OTP 登录绕过二步验证：已启用 TOTP 的账号不能仅凭邮箱或短信验证码登录。
5. JIT 临时授权：用户已持有的角色不得再临时授权（否则到期回收会误删永久角色），有效期与生效时间均不得超过 30 天。
6. 风控输入可伪造：`X-Geo-Location` 默认不再采信，仅在「系统设置」开启 `risk.trust_geo_header=true`（前置网关覆盖该头）时生效；设备指纹与 User-Agent 按字节截断，避免超长值导致会话写入失败。
7. 手机号：校验格式并要求唯一。
8. 密码重置：按邮箱与 IP 限频，邮件发送失败不再向客户端泄露细节，禁止使用历史默认口令，撤销旧会话失败时返回错误。
9. SSRF 黑名单补充 100.64.0.0/10（含部分云厂商元数据地址）。

新增回归测试在 `security_review_test.go`；原有企业功能测试因依赖旧行为已调整（OTP 测试改用带手机号的已注册账号，风控测试显式开启地理头信任）。

## 第三轮全量复审修复

这一轮从头复查了全部代码，发现 6 个高危问题，另有若干上一轮声称已修复、但实际没修好的条目。以下问题已全部修复。

### 高危

1. 二步验证可被邮箱或短信验证码绕过：登录流程统一收口到 `login_flow.go`。已启用 TOTP 的账号只接受 TOTP 或恢复码，`/auth/mfa/verify` 只接受挑战里列出的方式。风控要求二次验证、但账号没有可用方式时，直接阻断登录，不再放行。
2. 联合登录绕过 TOTP、强制改密和风控：联合登录改走统一登录出口，会写入会话表，也能在「我的会话」中踢下线。前端回调页能处理 MFA 挑战（转到登录页继续验证）和强制改密。
3. OAuth2 scope 越权：注册 `ClientScopeHandler` 和 `RefreshingScopeHandler`。`client_credentials` 只能申请应用登记的 scope，刷新令牌时 scope 只能缩小、不能扩大。
4. 禁用或改密后，OAuth2 refresh_token 仍能续期：签发和刷新时都会检查用户状态和用户级令牌失效时间点。
5. 管理员登记 `javascript:` 回调地址导致同意页 XSS：所有应用（含管理员创建的）都校验回调地址协议，只允许 https、本机回环 http 和含点号的自定义 scheme。前端同意页在跳转前再校验一次。
6. 改手机号无需验证：新手机号要通过短信验证码证明持有，并且需要近 5 分钟内重新验证身份。

### 敏感操作二次认证

新增 `POST /auth/reauth`，用密码或 TOTP 动态码确认身份，有效期 5 分钟。改手机号、启用 TOTP、新增 Passkey、绑定第三方账号都要求先完成这一步，否则返回 `403 reauth_required`。前端新增全局 `ReauthDialog`：收到 `reauth_required` 时弹窗验证，通过后自动重试原请求。关闭 TOTP 需要同时提供动态码（或恢复码）和登录密码（账号有密码时）。

### 中危

- 用户列表和详情跨域读取：非超级管理员只能看到请求域内持有角色的用户。创建用户、创建 JIT 临时授权时，目标域必须等于已鉴权的请求域。
- 被吊销的会话复活：刷新令牌轮换时同步更新会话过期时间，吊销标记的 TTL 不会早于会话本身。
- 注册验证缺口：任一模式下，提交的每个可验证联系方式都必须通过验证码；`email` / `sms` 模式要求对应联系方式必填。邮箱和手机号恢复唯一索引（迁移 `000008`），并发注册返回 409。ID Token 和 userinfo 新增 `email_verified`，只有验证过的邮箱才为 true；管理员修改邮箱后该标记重置为未验证。
- 公共客户端关闭 PKCE：公共客户端强制使用 PKCE，`/oauth2/codes` 同样检查。
- 账号枚举和信息泄露：OTP 发送、OTP 登录、重置密码对账号存在与否返回一致的结果，验证失败统一提示，只有「尝试次数过多」原样返回。SMTP 和上游报错不再透传给客户端。联合登录出站请求出错时，错误里不再带 URL（企业微信的 `corpsecret` 位于查询参数）。管理接口的数据库错误统一由 `failInternal` / `failWrite` 处理，唯一约束冲突返回 409。
- 人机验证在数据库出错时放行：改为拒绝。
- 联合登录和绑定的 `state` 未绑定浏览器（登录 CSRF）：`state` 绑定发起请求的浏览器，回调时校验。
- 并发计数：OTP、重置码、MFA 的尝试次数改为原子自增，MFA 挑战按原子消费结果判断。OAuth2 授权码改为原子消费，重复兑换返回 400。
- Passkey 的 RP ID 和 Origin 只从系统配置的 Issuer 与 CORS 来源中选取，不再信任请求头。

### 低危与部署

- 敏感字段落库加密：TOTP 种子、联合登录 Client Secret、插件密钥字段、密钥类系统设置使用 AES-GCM 加密（前缀 `enc:v1:`）。密钥来自 `OPENIAM_DATA_ENCRYPTION_KEY`；未配置时以明文存储并告警。已有的明文数据仍可读取，下次保存时会自动加密。
- JWT 签名密钥：未指定私钥路径时，自动生成并持久化到 `data/jwt_private.pem`（权限 0600），重启不再使全部令牌失效。compose 为此挂载 `openiam_backend_data` 卷。
- OIDC 支持 `nonce`。ID Token 不能当作 Access Token 调用 API。
- 全员公告的已读状态改为按用户记录（`notification_reads` 表）。
- Webhook 配置 `secret` 后，请求带签名：`X-OpenIAM-Signature: sha256=hex(HMAC(secret, timestamp + "." + body))`。
- SSRF 黑名单补充 `0.0.0.0/8`、`192.0.0.0/24`、文档与基准测试地址段、`240.0.0.0/4`、NAT64、`100::/64`、`2001:db8::/32`、`2002::/16`、接口本地组播。插件出站共用一个带连接池和超时的受限客户端。
- 风控：省略设备指纹不能再冒充已知设备。只有当历史会话也都没有指纹时，空指纹才视为已知。
- 登录锁定判断在 Redis 出错时按已锁定处理。限流器在存储出错时返回 503（fail-closed），触发限流时返回 `Retry-After`。
- SMTP 在 `starttls` 模式下，服务器不支持 STARTTLS 时直接拒绝发送，不再降级为明文。
- 审计脱敏改为按归一化后的子串匹配（如 `client_secret`、`apiKey`、`recovery-codes`），顶层数组也会脱敏。
- `/health` 不再返回版本号。业务连接强制关闭 `multiStatements`，只有迁移连接开启。
- 默认运行模式为 `release`。可信代理默认只有 `127.0.0.1,::1`。
- 前端：`?redirect=` 和联合登录回跳地址只接受同源路径；重置密码的发码接受人机验证令牌；`react-router-dom` 升级到 7.18，修复 GHSA-wrjc-x8rr-h8h6 与 GHSA-337j-9hxr-rhxg，`npm audit --omit=dev` 为 0。
- 部署：
  - compose 中 MySQL 健康检查通过环境变量读取口令，不再硬编码。
  - 内置 Redis 用 `OPENIAM_REDIS_PASSWORD` 启用认证。
  - compose 使用固定内部网段 `OPENIAM_DOCKER_SUBNET`，后端只信任该网段转发的 `X-Forwarded-*`。
  - 前端镜像只用 `npm ci`，去掉了 `npm install` 回退；nginx 改为非 root 镜像，监听 8080，并沿用上游代理声明的 https。
  - 容器开启 `no-new-privileges`，镜像版本固定到次版本号。
  - CI 中的 Actions 固定到 commit SHA，新增 `go vet`、前端完整构建和 `npm audit`。
  - `.gitignore` 增加私钥、本地数据库与 `data/` 目录。

### 验证

- 后端：`go build`、`go vet`、`go test ./...` 全部通过。
  - 新增 `security_regression_test.go`，覆盖注册时每个联系方式都要验证、用户列表和详情的域隔离、TOTP 种子加密落库、公告已读状态按用户隔离。
  - 新增 `fieldcrypt_test.go`、`sanitize_test.go`、`webhook_sign_test.go`、`risk/engine_test.go`。
  - 集成测试补充了 nonce、ID Token 不能调用 API、授权码不能重复兑换、刷新时不能扩大 scope。
- 前端：`npm run build` 通过。
- 未验证：
  - Docker 镜像构建与 compose 启动（本机没有 Docker），包括非 root nginx 的模板渲染和 Redis 口令认证。
  - 前端重新认证弹窗、改手机号、联合登录 MFA 跳转在真实浏览器中的交互。
  - SMTP STARTTLS 的严格模式。

## 尚未修复

1. 修改密码等操作的审计、令牌撤销依赖 Redis；Redis 不可用时，登录与刷新会失败。这是有意的 fail-closed 设计。
2. 联合登录插件仍然信任管理员配置的外部 https 站点本身。开启系统设置 `security.allow_private_upstream` 会放宽 SSRF 防护。
3. 未配置 `OPENIAM_DATA_ENCRYPTION_KEY` 时，敏感字段仍以明文落库（启动时会告警）。
4. compose 中内置 MySQL 的默认口令仍是公开值（端口只绑定本机回环），生产环境需要在 `.env` 中修改。

## 升级注意

- release 模式下，`OPENIAM_SEED_ADMIN_PASSWORD` 为空或为公开默认值时后端会拒绝启动，这是有意为之；管理员账号已存在的旧部署，可设置 `OPENIAM_SEED_ENABLED=false` 跳过初始化。
- 非超级管理员原先能管理的跨域用户、以及为角色授予自己未持有的权限，升级后都会被拒绝，需要由超级管理员操作。
- `introspect` 与 `revoke` 现在要求携带客户端凭据，且只能作用于调用方自己的令牌，依赖旧行为的资源服务需要改用自己的客户端凭据。
- 库里已有的 `domain_admin` 旧策略不会被自动收回，需要管理员手动核对。
- 升级后浏览器里旧的 `localStorage` 令牌会被清除，用户需要重新登录一次。
- 前端必须经由 HTTPS 反代访问生产环境，Cookie 才会带 `Secure` 属性；nginx 已传递 `X-Forwarded-Proto`，上游代理需保证该头正确。
- 已有身份源配置中若使用 http 或内网地址，保存时会被拒绝，需要改用 https 或显式开启内网开关。
- 联合登录的回调地址需要在「系统设置」的 CORS 来源或回调前缀中登记。
- 第三轮修复的升级影响：
  - 迁移 `000008` 会恢复邮箱和手机号的唯一索引。如果库里已有重复的邮箱或手机号，迁移会失败，需要先清理重复数据。
  - 令牌的 `typ` 与签发方校验变严格，升级前签发的令牌会失效，用户需要重新登录。
  - 公共 OAuth 客户端必须使用 PKCE。`client_credentials` 和刷新令牌不能再申请超出登记范围的 scope。
  - 改手机号、启用 TOTP、新增 Passkey、绑定第三方账号前需要重新验证身份。直接调用 API 的客户端要先调用 `POST /auth/reauth`。
  - SMTP 服务器不支持 STARTTLS 时会拒绝发送。确实是内网明文中继的，需要把加密方式设为 `none`。
  - 限流存储（Redis）异常时返回 503，不再放行。
  - 可信代理默认只信任回环地址。自建反向代理的部署需要设置 `OPENIAM_TRUSTED_PROXIES`，或在系统设置中配置。
  - 启用 `OPENIAM_DATA_ENCRYPTION_KEY` 后请妥善备份该密钥，丢失后已加密的字段无法恢复。
  - compose 部署：前端容器端口从 80 改为 8080（宿主机端口仍由 `OPENIAM_PORT` 控制）；使用内置 Redis 时必须在 `.env` 设置 `OPENIAM_REDIS_PASSWORD`，后端使用同一个变量连接。
