# RedProxy

RedProxy 是一个 **TOTP 验证后动态生成一次性 CRX3 浏览器扩展** 的自托管工具。

它由**两个互相独立的站点**组成：

| 站点 | 默认地址 | 默认绑定 | 作用 |
| --- | --- | --- | --- |
| **用户站** | `http://<host>:3000/` | `0.0.0.0:3000` | 终端用户登录、选节点、选有效期、生成一次性 CRX/ZIP |
| **管理站** | `http://<host>:3001/` | `127.0.0.1:3001` | 管理员配置节点、Xray、会话、认证方式、导入导出、日志 |

两个站点使用**不同的 Cookie**（`redproxy_user` / `redproxy_admin`）和**不同的服务端登录会话**：登录其中一个不会获得另一个的权限。用户站始终只要求 TOTP；管理站按 `AUTH_MODE` 决定是「仅 TOTP」还是「TOTP + 管理员密码」。

安装扩展后，扩展会保存 Chrome 原有代理配置、临时代理浏览器流量、每 15 秒发送心跳。页面关闭、用户主动关闭、管理员撤销、TTL / 空闲超时或心跳连续失败后，扩展会恢复原代理设置、清理本地状态并调用 `chrome.management.uninstallSelf({ showConfirmDialog: false })` 自我卸载。

> RedProxy 不创建本地 TCP 端口，也不是普通网页中继。浏览器流量由 Chrome 扩展通过 `chrome.proxy.settings` 转发到 HTTP / HTTPS / SOCKS4 / SOCKS5 节点。

## 目录

- [两个站点的区别](#两个站点的区别)
- [运行方式一：Docker](#运行方式一docker)
- [运行方式二：单个可执行文件](#运行方式二单个可执行文件)
- [首次启动与 TOTP 绑定](#首次启动与-totp-绑定)
- [认证方式与登录封禁](#认证方式与登录封禁)
- [管理站功能](#管理站功能)
- [节点管理](#节点管理)
- [Xray 节点与分享链接](#xray-节点与分享链接)
- [一次性扩展机制](#一次性扩展机制)
- [API](#api)
- [安全设计](#安全设计)
- [已知限制](#已知限制)
- [开发与测试](#开发与测试)
- [许可证](#许可证)

## 两个站点的区别

| | 用户站 `/` | 管理站 `/` |
| --- | --- | --- |
| 端口 | `PORT`（默认 3000） | `ADMIN_PORT`（默认 3001） |
| 绑定 | `HOST`（默认 `0.0.0.0`） | `ADMIN_HOST`（默认 `127.0.0.1`） |
| Cookie | `redproxy_user` | `redproxy_admin` |
| 登录方式 | 始终 TOTP | `AUTH_MODE`：`totp` 或 `totp_password` |
| 能做什么 | 选节点、建会话、下载 CRX/ZIP、关闭自己的会话 | 节点/Xray/会话/安全/导入导出/日志 |
| 节点密码 | 不可见 | 可管理（仍不会回显到普通列表） |

**建议**：管理站默认只监听 `127.0.0.1`，通过 SSH 隧道或反向代理访问；用户站可以开放到公网并配置 HTTPS。

## 运行方式一：Docker

不需要 `docker-compose`，直接构建 / 运行：

```bash
# 构建镜像
docker build -t redproxy .

# 启动：用户站 3000 对外，管理站 3001 只绑本机
docker run -d --name redproxy \
  -p 3000:3000 \
  -p 127.0.0.1:3001:3001 \
  -e PUBLIC_BASE_URL=https://proxy.example.com \
  -e COOKIE_SECURE=true \
  -v redproxy-data:/app/data \
  --restart unless-stopped \
  redproxy
```

本地验收且暂时没有 HTTPS 时：

```bash
docker run -d --name redproxy \
  -p 3000:3000 -p 127.0.0.1:3001:3001 \
  -e PUBLIC_BASE_URL=http://127.0.0.1:3000 \
  -e COOKIE_SECURE=false \
  -e ALLOW_INSECURE_HTTP=true \
  -v redproxy-data:/app/data \
  redproxy
```

只跑用户站、不要管理站：

```bash
docker run -d --name redproxy -p 3000:3000 \
  -e ADMIN_ENABLED=false \
  -e PUBLIC_BASE_URL=https://proxy.example.com \
  -v redproxy-data:/app/data \
  redproxy
```

数据（TOTP 密钥、管理员密码哈希、CRX 私钥）都在 `/app/data`，请务必挂载持久卷。

## 运行方式二：单个可执行文件

`npm run build:binary`（需要 Bun）会生成一个内嵌 Web UI 和扩展模板的单文件，例如 `dist/redproxy`。不需要携带 `public/` 或 `extension-template/`。

```bash
./redproxy --help
./redproxy serve \
  --host 0.0.0.0 --port 3000 \
  --admin-host 127.0.0.1 --admin-port 3001 \
  --data-dir ./data \
  --public-url https://proxy.example.com
```

常用命令：

```bash
redproxy serve [options]           # 启动用户站 + 管理站（默认命令）
redproxy generate-key [--path f]   # 生成 CRX 私钥
redproxy generate-secret           # 打印新的随机 TOTP 密钥和 otpauth URI
redproxy show-uri                  # 打印当前 TOTP 密钥和 URI
redproxy reset-password --password <pw>
redproxy version
redproxy help
```

服务端参数：

| 参数 | 环境变量 | 说明 |
| --- | --- | --- |
| `--host` | `HOST` | 用户站监听地址，默认 `0.0.0.0` |
| `--port` | `PORT` | 用户站端口，默认 `3000` |
| `--admin-host` | `ADMIN_HOST` | 管理站监听地址，默认 `127.0.0.1` |
| `--admin-port` | `ADMIN_PORT` | 管理站端口，默认用户站端口 + 1 |
| `--no-admin` | `ADMIN_ENABLED=false` | 关闭管理站 |
| `--data-dir` | `DATA_DIR` | 数据目录，默认 `./data` |
| `--public-url` | `PUBLIC_BASE_URL` | 写入扩展的对外地址 |
| `--session-ttl` | `SESSION_TTL_SECONDS` | 会话最大有效期，默认 3600 |
| `--idle` | `SESSION_IDLE_SECONDS` | 空闲超时，默认 90 |
| `--enrollment-ttl` | `ENROLLMENT_TTL_SECONDS` | CRX 内嵌一次性 token 的有效期，默认 120 |
| `--max-devices` | `MAX_CONCURRENT_DEVICES` | 最大并发设备，默认 2 |
| `--auth-mode` | `AUTH_MODE` | 管理站登录方式：`totp` 或 `totp_password` |
| `--cookie-secure` / `--no-cookie-secure` | `COOKIE_SECURE` | 登录 Cookie 是否加 `Secure` |
| `--allow-insecure-http` | `ALLOW_INSECURE_HTTP` | 仅本地验收时允许 HTTP 下发扩展 |
| `--trust-proxy` | `TRUST_PROXY` | 是否信任反向代理的 `X-Forwarded-For` |

## 首次启动与 TOTP 绑定

首次启动时，如果 `DATA_DIR/settings.json` 不存在，RedProxy 会：

1. **随机生成**一个 TOTP 密钥并写入 `settings.json`（权限 0600）；
2. 使用 `DATA_DIR/redproxy.pem` 作为固定 CRX 签名私钥（不存在时自动生成）。

用管理员身份进入**管理站**的「安全」页即可看到：

- TOTP 绑定二维码；
- `otpauth://` URI 和 Base32 密钥；
- 「随机生成新密钥」按钮（需要输入当前 6 位动态码确认）。

用户站和管理站共用同一个 TOTP 密钥。

也可以直接用 CLI 查看：

```bash
./redproxy show-uri --data-dir ./data
```

**不要把 `settings.json`、`data/`、`*.pem` 提交到 Git。**

## 认证方式与登录封禁

**用户站**：始终只要求 TOTP（终端用户不需要管理员密码）。

**管理站**：由 `AUTH_MODE` 控制：

- `totp`：仅 TOTP（默认）；
- `totp_password`：TOTP + 管理员密码。密码用 scrypt 加盐哈希保存在 `settings.json`。

登录封禁（两个站点共享同一个按 IP 的限速器）：

- IP 来源：`TRUST_PROXY=false` 时使用 socket 地址；`true` 时使用 `X-Forwarded-For`；
- 在 `LOGIN_WINDOW_SECONDS`（默认 300 秒）内失败 `LOGIN_MAX_ATTEMPTS`（默认 5）次后，封禁该 IP `LOGIN_BAN_SECONDS`（默认 900 秒）；
- 封禁期间即使 TOTP 正确也返回 `429 ip_banned`；
- 管理员可在管理站「安全 → 登录封禁」查看并手动解封。

> 注意：NAT、公司出口或反向代理后面的多个用户可能共享同一个 IP。开启 `TRUST_PROXY` 时请确保只有可信反向代理能访问服务端。

## 管理站功能

- **节点**：添加 / 删除 / 启停传统代理（`http`/`https`/`socks4`/`socks5`）与 Xray 节点。
- **Xray**：导入 `vless://`、`vmess://`、`trojan://`、`ss://` 分享链接；导出可直接运行的 Xray `config.json`。
- **会话**：查看所有会话（设备、来源 IP、节点、状态、是否已绑定、剩余时间）并撤销。
- **安全**：管理站认证方式、管理员密码、TOTP 二维码、随机重新生成密钥、登录封禁管理。
- **导入导出**：粘贴 JSON 或分享链接导入；导出节点 JSON（可选是否包含凭据）或分享链接。
- **日志**：审计事件。

## 节点管理

传统代理节点：

```json
{
  "id": "tokyo-1",
  "name": "Tokyo",
  "kind": "proxy",
  "scheme": "http",
  "host": "127.0.0.1",
  "port": 10809,
  "username": null,
  "password": null,
  "enabled": true
}
```

支持的 `scheme`：`http`、`https`、`socks4`、`socks5`。

安全约束：

- 节点协议只允许上述四种，端口范围 `1..65535`；
- 用户站节点列表只返回名称/协议/地址，不返回密码；
- 节点密码只保存在服务端，并会写入使用该节点的会话扩展包（请使用短期、可撤销的节点凭据）。

## Xray 节点与分享链接

RedProxy 扩展只能连接 `http` / `https` / `socks4` / `socks5`。Xray 节点通过“远端 Xray 出站 + 本地 Inbound”的方式接入：

1. 在管理站「Xray」页导入分享链接；
2. 每个 Xray 节点保存远端协议、UUID / 密码、传输与 TLS 参数，以及一个本地 Inbound（默认 `socks5 127.0.0.1:1080x`）；
3. 点「导出配置」得到可直接运行的 Xray `config.json`；
4. 在服务器上启动 Xray：`xray run -c <node>-xray.json`；
5. 用户在用户站选择该节点时，扩展连接本地 Inbound，由 Xray 转发到远端。

支持的导入格式：

- `vless://uuid@host:port?...#name`
- `trojan://password@host:port?...#name`
- `ss://base64(method:password)@host:port#name`（SIP002 及旧版 base64）
- `vmess://base64(json)`
- `http(s)://user:pass@host:port`、`socks4://...`、`socks5://...`

支持的传输/安全：`tcp`、`ws`、`grpc`、`http`、`xhttp`、`kcp`、`quic`，以及 `tls`、`reality`。

## 代理模式（单端口）

RedProxy 有两种代理模式，通过 `PROXY_MODE` 选择，默认 `server`。

### `server`（默认，推荐）

```
Chrome ──HTTPS 代理 / CONNECT──> RedProxy 同一端口（3000/443）
        ──服务端转发──> 内网 socks5/http 或 Xray 节点
```

- **复用前台同一个端口**，不需要额外开代理端口
- 节点地址、节点账号密码**只保存在服务端**，CRX 里不含任何节点信息
- 浏览器只用一个一次性 token 向 RedProxy 认证（`Proxy-Authorization: Basic <token>`）
- 内网地址（如 `192.168.0.2:8080`）由服务端代连，外网客户端也能用
- 会话撤销 / 过期后 token 立即失效，代理请求返回 407

配置：

```env
PROXY_MODE=server
PROXY_ENABLED=true
PROXY_CONNECT_TIMEOUT_MS=10000
```

### `direct`

扩展直接把 Chrome 代理指向节点地址，客户端必须能直达该节点。适合节点本身有公网入口的场景。

```env
PROXY_MODE=direct
```

### HTTPS 与 CDN

要让浏览器走 **HTTPS 代理**（`scheme: https`），需要给用户端口启用 TLS：

```env
TLS_ENABLED=true
TLS_CERT_PATH=/app/data/fullchain.pem
TLS_KEY_PATH=/app/data/privkey.pem
PUBLIC_BASE_URL=https://proxy.example.com
```

> ⚠️ **Cloudflare 等 CDN 不能承载代理流量。** CDN 只代理 HTTP/HTTPS/WebSocket，**不转发 HTTP CONNECT**。所以套 CDN 后：
> - 网页控制台可以正常访问
> - **代理功能会失效**
>
> 如果要隐藏源站端口，请用 **Cloudflare Spectrum（企业版）**、独立 IP 的 TCP 转发，或直接在源站使用 443。CDN 适合保护控制台，不适合承载代理。

## 一次性扩展机制

1. 用户下载 `extension.crx` / `extension.zip` 时，服务端生成一个**一次性 enrollment token**写入扩展包，有效期为 `ENROLLMENT_TTL_SECONDS`（默认 120 秒）；
2. 扩展第一次调用 `POST /api/extension/heartbeat` 时，服务端**消费**该 token 并返回新的 access token；
3. 扩展把 access token 保存到 `chrome.storage.local`，之后只用它；
4. 原 CRX 中的 enrollment token 立即删除，**重放永久 401**；
5. 后续心跳继续轮换 access token，旧 token 只在 `TOKEN_GRACE_SECONDS`（默认 30 秒）恢复窗口内接受一次；
6. 会话撤销 / TTL 到期 / 空闲超时后，服务端清除该会话所有 token；
7. 同一会话重新下载 CRX 会作废之前未使用的 enrollment token。

因此即使扩展自我卸载失败、用户重装旧 CRX、或把 CRX 拷到另一台机器，服务端都已不再接受这些 token。

## API

用户站（`PORT`）：

```text
GET    /healthz
GET    /api/config
GET    /api/auth/mode
POST   /api/auth/totp
POST   /api/auth/logout
GET    /api/me
GET    /api/nodes
POST   /api/session
GET    /api/session
POST   /api/session/heartbeat
POST   /api/session/revoke
GET    /api/session/extension.crx
GET    /api/session/extension.zip
POST   /api/extension/heartbeat
POST   /api/extension/revoke
```

管理站（`ADMIN_PORT`）：

```text
GET    /healthz
GET    /api/auth/mode
POST   /api/auth/totp
POST   /api/auth/logout
GET    /api/me

GET    /api/settings
PATCH  /api/settings
POST   /api/settings/password
DELETE /api/settings/password
POST   /api/settings/totp/regenerate
GET    /api/login-bans
DELETE /api/login-bans/:ip

GET    /api/nodes
POST   /api/nodes
PATCH  /api/nodes/:id
DELETE /api/nodes/:id
POST   /api/nodes/import
GET    /api/nodes/export
GET    /api/nodes/export/links
GET    /api/xray/config/:id
POST   /api/xray/preview

GET    /api/sessions
DELETE /api/sessions/:id
GET    /api/events
```

扩展接口使用：

```http
Authorization: Bearer <extensionToken>
```

## 安全设计

- 用户站 / 管理站完全分离：不同端口、不同 Cookie、不同服务端会话。
- 用户站只暴露使用功能，管理 API 不在用户站注册。
- 管理站默认只监听 `127.0.0.1`。
- TOTP 失败按 IP 限速并封禁，可配置、可查看、可解封。
- 登录 Cookie 使用 `HttpOnly`、`SameSite=Lax`；生产建议 `COOKIE_SECURE=true`。
- 管理员密码使用 scrypt + 随机盐。
- 所有 CRX / ZIP 响应禁止缓存。
- 生产环境默认拒绝通过纯 HTTP 下发扩展 token。
- 扩展 token 只保存 SHA-256 哈希，一次性 + 短 TTL + 轮换 + 恢复窗口。
- 节点协议白名单、端口范围校验、主机名校验、Zod 输入校验。
- 审计日志覆盖登录、密码变更、密钥重生成、节点变更、会话创建 / 心跳 / 撤销 / 过期、IP 解封。

## 已知限制

1. **CRX 下载文件可能留在下载目录。** 扩展自我卸载不会删除浏览器下载目录里的 CRX / ZIP。
2. **扩展包中的短期节点凭据理论上可以被本地用户查看。** 请使用短期、可撤销的节点凭据。
3. **Chrome 代理设置是浏览器级别的，不等于系统所有程序都走代理。**
4. **页面关闭撤销属于尽力而为。** 服务端 TTL 和空闲超时才是最终兜底。
5. Windows / macOS 普通 Chrome 可能禁止自托管 CRX，需开启开发者模式加载解压目录，或使用企业策略 / Chrome Web Store。Linux 对本地 CRX 支持更好。
6. 会话和节点默认保存在服务端内存中，进程重启后临时会话全部失效；TOTP 设置和 CRX 私钥会持久化在 `data/`。
7. Xray 配置导出覆盖常见协议 / 传输组合；复杂配置请自行调整。

## 开发与测试

要求 Node.js 22+。

```bash
npm install
npm run embed         # 把 public/ 与 extension-template/ 内嵌到 server/src/generated/assets.ts
npm run lint
npm run typecheck
npm test
npm run build
npm run dev           # 开发模式：用户站 + 管理站
```

构建单文件可执行程序（需要 Bun）：

```bash
npm run build:binary
```

测试覆盖：

- 用户站 / 管理站分离与独立登录态；
- TOTP 正确 / 错误验证、登录限速与封禁、解封；
- 管理站 TOTP + 密码模式；
- 随机 TOTP 密钥与二维码接口；
- 会话 TTL 过期、空闲过期、心跳续活、并发设备限制；
- 管理员 / 扩展撤销会话；
- 一次性 enrollment token 消费、重放拒绝、轮换与恢复窗口；
- 动态 CRX3 生成与 CRX 内嵌 ZIP 校验；
- 扩展保存 / 恢复原代理配置、重试恢复、幂等清理、token 轮换持久化；
- 节点 JSON / 分享链接导入导出、Xray 配置生成。

## 许可证

AGPL-3.0-only。详见 [LICENSE](./LICENSE)。
