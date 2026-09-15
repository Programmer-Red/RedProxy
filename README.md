# RedProxy

RedProxy 是一个 **TOTP 验证后动态生成一次性 CRX3 浏览器扩展** 的自托管工具。

用户完成 TOTP 登录后，选择代理节点和会话有效期，服务端会为该会话动态生成一个专属 CRX3（以及 ZIP fallback）。用户手动安装扩展后，扩展会保存 Chrome 原先的代理配置、临时把浏览器流量切到指定 HTTP/HTTPS/SOCKS5 节点，并定时向服务端发送心跳。页面关闭、用户主动关闭、服务端撤销、TTL/空闲超时或心跳连续失败后，扩展会恢复原代理设置、清理本地状态并调用 `chrome.management.uninstallSelf({ showConfirmDialog: false })` 自我卸载。

> RedProxy 不创建本地 TCP 端口，也不是普通网页中继。代理流量由 Chrome 扩展通过 `chrome.proxy.settings` 转发到远程 HTTP/HTTPS/SOCKS5 节点。

## 功能

- TOTP 单管理员登录，支持前后 1 个时间片验证。
- HttpOnly + SameSite Cookie；生产环境通过 `COOKIE_SECURE=true` 支持 Secure Cookie。
- 节点管理：添加、删除、启用/禁用、查看名称/协议/地址；长期密码只保存在服务端。
- HTTP、HTTPS、SOCKS5 三种代理协议；不支持 VLESS、VMess、Shadowsocks 等协议。
- 一次性动态 CRX3，扩展令牌只保存 SHA-256 哈希，绑定当前会话和节点。
- 会话 TTL、空闲超时、并发设备上限、同设备旧会话自动撤销。
- 管理员查看活跃设备并主动撤销。
- 页面 `pagehide + navigator.sendBeacon()` 尽力撤销。
- 扩展自我卸载、恢复原代理配置、清理本地存储。
- 审计日志记录会话创建、心跳、撤销和过期事件。
- Docker Compose 一键部署。

## 快速启动

### 本地开发

要求 Node.js 22+ 和 npm。

```bash
cp .env.example .env
# 编辑 .env，至少确认 PUBLIC_BASE_URL、ADMIN_TOTP_SECRET、COOKIE_SECURE
npm install
npm run dev
```

打开 `http://localhost:3000`。首次启动时若未配置 `ADMIN_TOTP_SECRET`，服务端会生成：

- `data/totp-secret.txt`
- 控制台中的 `otpauth://...` 绑定 URI

登录后可在管理区点“查看 TOTP 绑定 URI”获得与认证器绑定的 URI。

### Docker Compose

```bash
cp .env.example .env
# 推荐：PUBLIC_BASE_URL 设置为浏览器实际访问的地址
# 如果本机只做临时验收且没有 HTTPS，可设置 ALLOW_INSECURE_HTTP=true、COOKIE_SECURE=false
docker compose up -d --build
docker compose logs -f redproxy
```

默认映射 `3000:3000`，数据持久化在命名卷 `redproxy-data`。

## 环境变量

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `PORT` | `3000` | 服务端监听端口。 |
| `PUBLIC_BASE_URL` | `http://localhost:3000` | 写入扩展的服务端基础 URL，必须在浏览器中可访问。 |
| `ADMIN_TOTP_SECRET` | 空 | Base32 TOTP Secret；为空时首次启动自动生成到 `DATA_DIR/totp-secret.txt`。 |
| `SESSION_TTL_SECONDS` | `3600` | 临时会话最大 TTL。 |
| `SESSION_IDLE_SECONDS` | `90` | 无心跳后的空闲失效时间。 |
| `MAX_CONCURRENT_DEVICES` | `2` | 最大并发设备/会话数。 |
| `COOKIE_SECURE` | 生产环境 `true` | 是否给登录 Cookie 加 `Secure`。 |
| `DATA_DIR` | `./data` | 数据目录，TOTP Secret、CRX 私钥、运行数据默认存放在这里。 |
| `CRX_PRIVATE_KEY_PATH` | `./data/redproxy.pem` | 固定 CRX3 私钥路径。 |
| `NODE_ENV` | `development` | `production` 时默认启用 Secure Cookie。 |
| `AUTH_SESSION_TTL_SECONDS` | `43200` | 管理员登录 Cookie 有效期。 |
| `LOGIN_MAX_ATTEMPTS` | `5` | 登录窗口内允许的失败次数。 |
| `LOGIN_WINDOW_SECONDS` | `300` | 登录限速窗口。 |
| `CRX_KEY_BITS` | `2048` | CRX RSA 私钥位数，最小 2048。 |
| `TRUST_PROXY` | `false` | 是否信任反向代理的 `X-Forwarded-For`。 |
| `ALLOW_INSECURE_HTTP` | `false` | 仅在本地验收时允许通过 HTTP 传输扩展令牌；生产环境应保持 `false` 并使用 HTTPS。 |

**不要提交 `.env`、`data/totp-secret.txt`、`data/redproxy.pem`。** `.gitignore` 已排除这些文件。

## 节点管理

节点结构：

```json
{
  "id": "tokyo-1",
  "name": "Tokyo",
  "scheme": "http",
  "host": "127.0.0.1",
  "port": 10809,
  "username": null,
  "password": null,
  "enabled": true
}
```

说明：

- 支持 `http`、`https`、`socks5`。
- 暂不支持 VLESS、VMess、Shadowsocks 等协议。若要使用这些协议，需要先在服务器上暴露对应的 HTTP 或 SOCKS5 入站，再在 RedProxy 中添加节点。
- 普通前端接口只返回 `hasAuth` 布尔值，不返回长期密码。
- 节点密码只保存在服务端内存/配置中，并会写入对应会话的 CRX 扩展包。

## API

```text
POST   /api/auth/totp
POST   /api/auth/logout
GET    /api/me

GET    /api/config
GET    /api/admin/totp
GET    /api/admin/nodes
POST   /api/admin/nodes
PATCH  /api/admin/nodes/:id
DELETE /api/admin/nodes/:id

GET    /api/admin/sessions
DELETE /api/admin/sessions/:id
GET    /api/admin/events

POST   /api/session
GET    /api/session
POST   /api/session/heartbeat
POST   /api/session/revoke

GET    /api/session/extension.crx
GET    /api/session/extension.zip

POST   /api/extension/heartbeat
POST   /api/extension/revoke

GET    /healthz
```

扩展接口使用：

```http
Authorization: Bearer <extensionToken>
```

扩展令牌约束：

- 随机/派生生成，服务端只保存 SHA-256 哈希。
- 绑定当前会话、设备和节点。
- 仅在会话有效期内有效。
- 页面撤销、管理员撤销、TTL/空闲超时后立即失效。
- 不能用于创建其他会话。

## 动态 CRX3 与 ZIP fallback

访问 `GET /api/session/extension.crx` 时服务端会：

1. 校验管理员登录状态；
2. 校验当前存在有效临时会话；
3. 生成/刷新一次性 `extensionToken`；
4. 把服务端地址、节点信息、token、到期时间写入临时扩展文件；
5. 使用 `CRX_PRIVATE_KEY_PATH` 指向的固定私钥生成 CRX3；
6. 返回 `application/x-chrome-extension`、附件下载和 `no-store` 缓存头。

同时提供 `GET /api/session/extension.zip` 作为 ZIP fallback。

### 安装说明与平台限制

- **Windows/macOS 普通 Chrome 可能禁止自托管 CRX**，并可能报 `CRX_REQUIRED_PROOF_MISSING` 或其他安装错误。
- 可以开启开发者模式后，下载 ZIP、解压，再使用“加载已解压的扩展程序”。解压目录方式下扩展仍可正常调用 `chrome.proxy.settings`。
- **Linux 对本地 CRX 支持更好**，但不同发行版和 Chrome 版本仍可能有策略限制。
- **Chrome Web Store 是跨平台正式分发方案**；RedProxy 这种一次性自托管 CRX 更适合受控环境、测试环境或 Linux 客户端。
- 企业环境可以通过策略安装自托管扩展。

## 扩展行为

扩展为 Manifest V3，核心权限：

```json
["proxy", "storage", "alarms"]
```

当节点配置了用户名/密码时，动态生成的 manifest 会额外加入：

```json
["webRequest", "webRequestAuthProvider"]
```

启动流程：

1. 读取注入的运行时配置；
2. 使用 `chrome.proxy.settings.get()` 保存原始配置到 `chrome.storage.local`；
3. 使用 `chrome.proxy.settings.set()` 设置临时代理；
4. 每 15 秒发送一次心跳；
5. 监听 `chrome.alarms` 和 service worker 唤醒。

清理触发条件：

- 服务端返回 401/403；
- token 过期或服务端返回 revoked；
- 心跳连续失败；
- 本地 `expiresAt` 到期；
- 用户点击扩展/页面“立即关闭”。

清理流程是幂等的：

1. 停止心跳；
2. 请求服务端撤销；
3. 恢复原代理设置，失败时重试；
4. 清理本地存储；
5. 调用 `chrome.management.uninstallSelf({ showConfirmDialog: false })`。

## 安全说明

RedProxy 实现了：

- TOTP 登录失败按 IP 限速。
- 登录 Cookie 使用 `HttpOnly`、`SameSite=Lax`，生产环境建议 `COOKIE_SECURE=true`。
- 所有 CRX/ZIP 响应禁止缓存。
- 生产环境默认拒绝通过纯 HTTP 下发扩展令牌；仅在设置 `ALLOW_INSECURE_HTTP=true` 时允许本地验收。
- 不向普通前端返回长期节点密码。
- 对管理 API 做认证。
- 对用户输入使用 Zod 校验。
- 限制节点协议为 `http`、`https`、`socks5`，端口限制在 `1..65535`。
- 审计日志记录会话创建、心跳、撤销和过期事件。
- `.env`、TOTP Secret、CRX 私钥、`data/` 均已加入 `.gitignore`。

### 必须了解的限制

1. **CRX 下载文件可能留在下载目录。** 扩展自我卸载不会自动删除浏览器下载目录中的 CRX/ZIP 文件。
2. **扩展自卸载不能保证删除下载文件。** 用户需要自行清理下载目录。
3. **扩展包中的短期节点凭据理论上可以被本地用户查看。** CRX/ZIP 中的节点密码或令牌不是对本地用户的安全边界；请使用短期、可撤销的节点凭据。
4. **Chrome 代理设置是浏览器级别的，不等于系统所有程序都走代理。** 只有 Chrome/Chromium 浏览器流量会遵循扩展代理设置。
5. **页面关闭撤销属于尽力而为。** `pagehide`/`sendBeacon` 可能因为权限、网络、浏览器策略失败；服务端 TTL 和空闲超时才是最终兜底。
6. 服务端重启后，所有临时会话默认失效；正在安装的扩展会在下一次心跳失败后清理并自我卸载。

## 开发与测试

```bash
npm install
npm run lint
npm run typecheck
npm test
docker compose config
```

测试覆盖：

- TOTP 正确/错误验证、登录限速；
- 会话 TTL 过期与空闲过期；
- 心跳续活；
- 并发设备限制；
- 同设备旧会话撤销；
- 管理员/扩展撤销会话；
- extension token 失效；
- 动态 CRX3 生成；
- 从 CRX3 内嵌 ZIP 校验 `manifest.json` 与 `background.js`；
- 扩展保存/恢复原代理配置、重试恢复和幂等清理。

## 技术栈

- Node.js 22+
- TypeScript
- Express
- `otpauth`
- `crx3`
- 原生 HTML/CSS/JavaScript
- Docker Compose

## 许可证

AGPL-3.0-only。详见 [LICENSE](./LICENSE)。
