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
8. 默认口令：`.env.example` 中该项留空；release 模式下口令为空或为公开默认值时后端拒绝启动，非 release 模式只告警；compose 不再用 `:?` 强制变量，`docker compose down` 等命令不受影响。注意：该检查在第三轮才真正接进启动流程——此前 `isWeakSeedPassword` 只是定义、从未被调用，现已由 `backend/cmd/server/main.go` 在初始化管理员之前强制调用。
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

## 尚未修复

1. Redis 默认无密码（仅绑定本机回环，但仍建议在生产环境设置 `OPENIAM_REDIS_PASSWORD`）。
2. 缺省运行模式为 `debug`，GORM 会打印 SQL；生产环境请设置 `OPENIAM_MODE=release`（compose 默认已是 release）。
3. DSN 强制开启 `multiStatements=true`，这是迁移所需；建议后续把迁移与业务连接拆开。
4. 修改密码等操作的审计、令牌撤销依赖 Redis；Redis 不可用时登录与刷新会失败（有意的 fail-closed）。
5. 联合登录插件仍信任管理员配置的外部 https 站点本身；开启系统设置 `security.allow_private_upstream` 会放宽 SSRF 防护。

## 升级注意

- release 模式下，`OPENIAM_SEED_ADMIN_PASSWORD` 为空或为公开默认值时后端会拒绝启动，这是有意为之；管理员账号已存在的旧部署，可设置 `OPENIAM_SEED_ENABLED=false` 跳过初始化。
- 非超级管理员原先能管理的跨域用户、以及为角色授予自己未持有的权限，升级后都会被拒绝，需要由超级管理员操作。
- `introspect` 与 `revoke` 现在要求携带客户端凭据，且只能作用于调用方自己的令牌，依赖旧行为的资源服务需要改用自己的客户端凭据。
- 库里已有的 `domain_admin` 旧策略不会被自动收回，需要管理员手动核对。
- 升级后浏览器里旧的 `localStorage` 令牌会被清除，用户需要重新登录一次。
- 前端必须经由 HTTPS 反代访问生产环境，Cookie 才会带 `Secure` 属性；nginx 已传递 `X-Forwarded-Proto`，上游代理需保证该头正确。
- 已有身份源配置中若使用 http 或内网地址，保存时会被拒绝，需要改用 https 或显式开启内网开关。
- 联合登录的回调地址需要在「系统设置」的 CORS 来源或回调前缀中登记。

## 第三轮修复（2026-11-28）

本轮改动集中在「凭据生命周期」与「配置可信来源」两条主线，改动文件与验证方式如下。

1. 旧刷新令牌绕过改密：`users` 新增 `tokens_valid_after`（迁移 `000006_user_tokens_valid_after`），改密 / 重置密码 / 禁用账号时与口令哈希同事务写入；`/oauth2/token` 的 refresh grant 与 `/api/v1/auth/refresh` 都按「签发时间 ≤ 凭据有效起点」拒绝，返回 `invalid_grant`。Redis 里的失效时间点丢失时，库里的时间戳仍然生效。
2. 找回密码验证码：改为 `INCR` 计数 + `GETDEL` 单次原子消费，同一验证码并发提交只有一个能成功；同账号连续 5 次输错立即作废验证码并清空计数；任何 Redis 写失败都会让流程失败，不再吞错误。
3. 通行密钥可信来源：RP ID 与允许来源改由 `webauthn.rp_id` / `webauthn.allowed_origins` 配置（支持环境变量），请求 `Origin` 必须在白名单内，否则返回 400 并记录 `auth.passkey.origin_rejected` 安全事件；删除「拿 Host 兜底」与「把请求 Origin 加进白名单」的逻辑。
4. 通行密钥必须用户验证：注册与登录的 WebAuthn 选项均设 `userVerification=required`，服务端在注册与登录阶段复核 UV 标志位，缺失即拒绝。
5. 外部身份绑定：state 中新增发起绑定的会话 JTI、会话签发时间与用户凭据有效起点快照，回调阶段逐项复核，不匹配即拒绝并作废本次绑定。
6. 重置密码：撤销旧会话失败即整体失败，口令哈希与凭据有效起点同事务落库；验证码记录里保存发码时的邮箱，确认阶段与账号当前邮箱比对，邮箱换绑后旧验证码失效。
7. SMTP：声明 `starttls`（含默认值）必须真正升级成功，服务器不支持时中止发送；明文发送仅在显式 `smtp.allow_insecure_plaintext=true` 且环境不是 `production` 时允许，并打警告日志。
8. 登录方式兜底：删除通行密钥与解绑外部身份前统计剩余登录方式（密码 / 其余通行密钥 / 其余外部身份），结果为 0 时返回 400；超级管理员可带 `force=true` 强制删除并写审计。
9. 通行密钥签名计数器：新值不大于已存值（疑似克隆）时拒绝登录并记安全事件。
10. SMTP 授权码改为 AES-256-GCM 加密存储（`enc:v1:` 前缀，密钥取 `OPENIAM_ENCRYPTION_KEY`，缺省回退 `OPENIAM_JWT_SECRET`），读取时解密，历史明文可平滑升级；接口层仍然脱敏。

对应回归测试：`backend/internal/router/review2_security_test.go`（第 1、3、4、6 项）、`backend/internal/security/state_store_pwdreset_test.go`（第 2 项）、`backend/internal/oauthplugin/bind_state_internal_test.go`（第 5 项）、`backend/internal/mailer/starttls_test.go`（第 7 项）、`backend/internal/handlers/tokens_test.go`（第 1、8 项的判定函数）、`backend/internal/security/crypto_test.go`（第 10 项）。

仍未覆盖：通行密钥 UV 缺失与签名计数器异常这两条只有服务端判定逻辑，没有构造真实认证器的端到端测试，需要后续用手工构造的 attestation/assertion 夹具补齐。
