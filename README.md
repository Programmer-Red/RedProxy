# RedProxy

RedProxy 是一个 **TOTP 验证后动态生成一次性 CRX3 浏览器扩展** 的自托管工具。

管理员完成 TOTP（可选再加一层密码）登录后，在 Web 控制台选择代理节点和会话有效期，服务端为该会话动态生成专属 CRX3（以及 ZIP fallback）。用户手动安装扩展后，扩展会保存 Chrome 原有代理配置、临时代理浏览器流量、每 15 秒发送心跳。页面关闭、用户主动关闭、管理员撤销、TTL / 空闲超时或心跳连续失败后，扩展会恢复原代理设置、清理本地状态并调用 `chrome.management.uninstallSelf({ showConfirmDialog: false })` 自我卸载。

> RedProxy 不创建本地 TCP 端口，也不是普通网页中继。浏览器流量由 Chrome 扩展通过 `chrome.proxy.settings` 转发到 HTTP / HTTPS / SOCKS4 / SOCKS5 节点。

## 目录

- [功能总览](#功能总览)
- [运行方式一：单个可执行文件（推荐）](#运行方式一单个可执行文件推荐)
- [运行方式二：Docker](#运行方式二docker)
- [首次启动与 TOTP 绑定](#首次启动与-totp-绑定)
- [认证方式与登录封禁](#认证方式与登录封禁)
- [管理后台](#管理后台)
- [节点管理](#节点管理)
- [Xray 节点与分享链接](#xray-节点与分享链接)
- [一次性扩展机制](#一次性扩展机制)
- [API](#api)
- [安全设计](#安全设计)
- [已知限制](#已知限制)
- [开发与测试](#开发与测试)
- [许可证](#许可证)

## 功能总览

- 一次性管理员登录：**TOTP 必须**，可选叠加管理员密码（`totp` / `totp_password`）。
- TOTP 密钥**随机生成**，不要求用户输入；控制台提供**二维码**、`otpauth://` URI，并支持重新随机生成。
- 登录按客户端 IP 限速 + 封禁，可在后台查看并解封。
- 节点管理：`http`、`https`、`socks4`、`socks5`；长期密码只保存在服务端。
- Xray 节点管理：导入 `vless://`、`vmess://`、`trojan://`、`ss://` 分享链接，导出可直接运行的 Xray `config.json`。
- 节点 JSON 导入 / 导出、分享链接导入 / 导出。
- 会话 TTL、空闲超时、并发设备上限、同设备旧会话自动撤销。
- 管理员查看活跃会话、来源 IP、扩展是否已绑定，并主动撤销。
- 页面 `pagehide + navigator.sendBeacon()` 尽力撤销。
- 扩展 Token **一次性**：首次心跳即被服务端轮换，CRX 内嵌 token 之后永久失效。
- 扩展自我卸载、恢复原代理配置、清理本地存储。
- 审计日志记录登录、会话创建、心跳、撤销、过期、节点变更等事件。
- 两种交付：GitHub Release 单文件可执行程序；Docker 镜像 / `docker run`。

## 运行方式一：单个可执行文件（推荐）

从 GitHub Releases 下载对应平台的文件（例如 `redproxy-linux-x64`），赋予执行权限后直接运行：

```bash
chmod +x redproxy-linux-x64
./redproxy-linux-x64 --help
./redproxy-linux-x64 serve \
  --host 0.0.0.0 \
  --port 3000 \
  --data-dir ./data \
  --public-url https://proxy.example.com \
  --max-devices 2
```

常用命令：

```bash
redproxy serve [options]           # 启动 HTTP 服务（默认命令）
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
| `--host` | `HOST` | 监听地址，默认 `0.0.0.0` |
| `--port` | `PORT` | 监听端口，默认 `3000` |
| `--data-dir` | `DATA_DIR` | 数据目录，默认 `./data` |
| `--public-url` | `PUBLIC_BASE_URL` | 写入扩展的对外地址，必须是浏览器可访问的 HTTPS 地址 |
| `--session-ttl` | `SESSION_TTL_SECONDS` | 会话最大有效期，默认 3600 |
| `--idle` | `SESSION_IDLE_SECONDS` | 空闲超时，默认 90 |
| `--enrollment-ttl` | `ENROLLMENT_TTL_SECONDS` | CRX 内嵌一次性 token 的有效期，默认 120 |
| `--max-devices` | `MAX_CONCURRENT_DEVICES` | 最大并发设备，默认 2 |
| `--auth-mode` | `AUTH_MODE` | `totp` 或 `totp_password` |
| `--cookie-secure` / `--no-cookie-secure` | `COOKIE_SECURE` | 登录 Cookie 是否加 `Secure` |
| `--allow-insecure-http` | `ALLOW_INSECURE_HTTP` | 仅本地验收时允许 HTTP 下发扩展；生产保持 false |
| `--trust-proxy` | `TRUST_PROXY` | 是否信任反向代理的 `X-Forwarded-For` |
| `--static-dir` | `STATIC_DIR` | 覆盖 Web UI 目录（一般不需要） |
| `--template-dir` | `EXTENSION_TEMPLATE_DIR` | 覆盖扩展模板目录（一般不需要） |

编译好的二进制已经内嵌 Web 控制台和扩展模板，因此**不需要携带 public / extension-template 目录**。只有一个文件。

## 运行方式二：Docker

不需要 `docker-compose`，直接构建 / 运行：

```bash
# 构建镜像
docker build -t redproxy .

# 启动
docker run -d --name redproxy \
  -p 3000:3000 \
  -e PUBLIC_BASE_URL=https://proxy.example.com \
  -e COOKIE_SECURE=true \
  -v redproxy-data:/app/data \
  --restart unless-stopped \
  redproxy
```

本地验收且暂时没有 HTTPS 时：

```bash
docker run -d --name redproxy \
  -p 3000:3000 \
  -e PUBLIC_BASE_URL=http://127.0.0.1:3000 \
  -e COOKIE_SECURE=false \
  -e ALLOW_INSECURE_HTTP=true \
  -e NODE_ENV=production \
  -v redproxy-data:/app/data \
  redproxy
```

也可以直接使用 GitHub Container Registry 镜像（发布后由 Release workflow 推送）：

```bash
docker run -d --name redproxy -p 3000:3000 \
  -e PUBLIC_BASE_URL=https://proxy.example.com \
  -v redproxy-data:/app/data \
  ghcr.io/programmer-red/redproxy:latest
```

数据（TOTP 密钥、管理员密码哈希、CRX 私钥）都在 `/app/data`，请务必挂载持久卷。

## 首次启动与 TOTP 绑定

首次启动时，如果 `DATA_DIR/settings.json` 不存在，RedProxy 会：

1. **随机生成**一个 TOTP 密钥并写入 `settings.json`（权限 0600）；
2. 使用 `DATA_DIR/redproxy.pem` 作为固定 CRX 签名私钥（不存在时自动生成）；

登录控制台后进入「安全」页即可看到：

- TOTP 绑定二维码；
- `otpauth://` URI 和 Base32 密钥；
- 「随机生成新密钥」按钮（需要输入当前 6 位动态码确认）。

也可以完全不进后台，直接用 CLI 查看：

```bash
./redproxy show-uri --data-dir ./data
```

**不要把 `settings.json`、`data/`、`*.pem` 提交到 Git。** 仓库的 `.gitignore` 已经排除它们。

## 认证方式与登录封禁

`AUTH_MODE` 支持两种：

- `totp`：只校验 TOTP（默认，推荐）；
- `totp_password`：TOTP + 管理员密码。密码用 scrypt 加盐哈希后保存在 `settings.json`，不会以明文存储。

登录封禁规则（按**客户端 IP**）：

- IP 来源：`TRUST_PROXY=false` 时使用 socket 地址；`TRUST_PROXY=true` 时使用 `X-Forwarded-For`；
- 在 `LOGIN_WINDOW_SECONDS`（默认 300 秒）内失败 `LOGIN_MAX_ATTEMPTS`（默认 5）次后，封禁该 IP `LOGIN_BAN_SECONDS`（默认 900 秒）；
- 封禁期间即使 TOTP 正确也返回 `429 ip_banned`；
- 管理员可在「安全 → 登录封禁」查看并手动解封。

> 注意：NAT、公司出口或反向代理后面的多个用户可能共享同一个 IP。开启 `TRUST_PROXY` 时请确保只有可信反向代理能访问服务端，否则客户端可以伪造 `X-Forwarded-For`。

## 管理后台

打开 `http://<host>:<port>/`，用 TOTP（以及密码，若启用）登录后即可看到标签页：

- **使用**：选择节点、有效期，生成 CRX / 下载 ZIP，查看会话状态，主动关闭会话。
- **节点**：添加 / 删除 / 启停传统代理或 Xray 节点。
- **Xray**：导入分享链接、导出 Xray `config.json`。
- **会话**：查看活跃会话（设备、来源 IP、节点、状态、是否已绑定、剩余时间）并撤销。
- **安全**：认证方式、管理员密码、TOTP 二维码、随机重新生成密钥、登录封禁管理。
- **导入导出**：粘贴 JSON 或分享链接导入；导出节点 JSON（可选择是否包含凭据）或分享链接。
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
- 普通前端接口只返回 `hasAuth` 布尔值，不返回长期密码；
- 节点密码只保存在服务端，并会写入使用该节点的会话扩展包（因此扩展包中的凭据理论上可被本机用户查看，请使用短期、可撤销的节点凭据）。

## Xray 节点与分享链接

RedProxy 扩展只能连接 `http` / `https` / `socks4` / `socks5`。Xray 节点通过“远端 Xray 出站 + 本地 Inbound”的方式接入：

1. 在「Xray」页导入 `vless://`、`vmess://`、`trojan://`、`ss://` 分享链接；
2. 每个 Xray 节点保存远端协议、UUID / 密码、传输与 TLS 参数，以及一个本地 Inbound（默认 `socks5 127.0.0.1:10808` 等）；
3. 在节点列表中点击「导出配置」，得到可直接运行的 Xray `config.json`；
4. 在服务器上启动 Xray：`xray run -c <node>-xray.json`；
5. RedProxy 会话选择该节点时，扩展连接的是本地 Inbound，由 Xray 负责转发到远端。

支持的导入格式：

- `vless://uuid@host:port?...#name`
- `trojan://password@host:port?...#name`
- `ss://base64(method:password)@host:port#name`（SIP002 及旧版 base64）
- `vmess://base64(json)`
- `http(s)://user:pass@host:port`、`socks4://...`、`socks5://...` 传统代理链接

支持的 Xray 传输/安全：`tcp`、`ws`、`grpc`、`http`、`xhttp`、`kcp`、`quic`，以及 `tls`、`reality`。导出配置覆盖常见参数，但复杂场景（多出站路由、负载均衡等）建议导出后自行调整。

## 一次性扩展机制

这是 RedProxy 的核心安全设计：

1. 会话创建后，下载 `extension.crx` / `extension.zip` 时服务端生成一个**一次性 enrollment token**，写入扩展包，有效期为 `ENROLLMENT_TTL_SECONDS`（默认 120 秒）；
2. 扩展第一次调用 `POST /api/extension/heartbeat` 时，服务端**消费**该 enrollment token，并返回一个新的 access token；
3. 扩展把 access token 保存到 `chrome.storage.local`，之后只用它心跳；
4. 原 CRX 中的 enrollment token 立即从服务端索引中删除，**无法重放**；
5. 后续心跳会继续轮换 access token，旧 token 只在 `TOKEN_GRACE_SECONDS`（默认 30 秒）的恢复窗口内被接受一次，用于 service worker 崩溃恢复；
6. 会话撤销 / TTL 到期 / 空闲超时后，服务端清除该会话所有 token；
7. 同一会话重新下载 CRX 会作废之前未使用的 enrollment token；
8. 因此：**即使扩展自我卸载失败、用户重新安装旧 CRX、或把 CRX 复制到另一台机器，服务端已经不再接受这些 token**。旧安装包在会话结束后只是一段无用的 ZIP 数据。

> 严格意义上，任何“已下载到本地的可执行代码”都无法保证在本地被彻底销毁；RedProxy 保证的是**服务端授权不可再次使用**。这是浏览器扩展模型下能做到的最强一次性语义。

## API

```text
POST   /api/auth/totp
POST   /api/auth/logout
GET    /api/me
GET    /api/auth/mode
GET    /api/config

GET    /api/admin/settings
GET    /api/admin/settings/totp
PATCH  /api/admin/settings
POST   /api/admin/settings/password
DELETE /api/admin/settings/password
POST   /api/admin/settings/totp/regenerate
GET    /api/admin/login-bans
DELETE /api/admin/login-bans/:ip

GET    /api/admin/nodes
POST   /api/admin/nodes
PATCH  /api/admin/nodes/:id
DELETE /api/admin/nodes/:id
POST   /api/admin/nodes/import
GET    /api/admin/nodes/export
GET    /api/admin/nodes/export/links
GET    /api/admin/xray/config/:id
POST   /api/admin/xray/preview

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

心跳响应会在首次绑定或轮换时返回新 token：

```json
{
  "ok": true,
  "revoked": false,
  "expiresAt": 1789500000000,
  "token": "<rotated access token>",
  "rotated": true
}
```

## 安全设计

- TOTP 失败按 IP 限速并封禁，封禁可配置、可查看、可解封。
- 登录 Cookie 使用 `HttpOnly`、`SameSite=Lax`；生产建议 `COOKIE_SECURE=true`。
- 管理员密码使用 scrypt + 随机盐，不存明文。
- 所有 CRX / ZIP 响应禁止缓存。
- 生产环境默认拒绝通过纯 HTTP 下发扩展 token；仅 `ALLOW_INSECURE_HTTP=true` 时允许本地验收。
- 扩展 token 只保存 SHA-256 哈希，一次性 + 短 TTL + 轮换 + 恢复窗口。
- 节点协议白名单、端口范围校验、主机名校验、Zod 输入校验。
- 不向普通前端返回长期节点密码。
- 管理 API 全部需要登录态。
- 审计日志覆盖登录、密码变更、密钥重生成、节点变更、会话创建 / 心跳 / 撤销 / 过期、IP 解封。
- `.gitignore` 排除 `.env`、`data/`、`*.pem`、`*.crx`、`*.zip`。

## 已知限制

1. **CRX 下载文件可能留在下载目录。** 扩展自我卸载不会删除浏览器下载目录里的 CRX / ZIP。
2. **扩展自卸载不能保证删除下载文件。** 需要用户自行清理。
3. **扩展包中的短期节点凭据理论上可以被本地用户查看。** 请使用短期、可撤销的节点凭据。
4. **Chrome 代理设置是浏览器级别的，不等于系统所有程序都走代理。**
5. **页面关闭撤销属于尽力而为。** `pagehide` / `sendBeacon` 可能失败；服务端 TTL 和空闲超时才 是最终兜底。
6. Windows / macOS 普通 Chrome 可能禁止自托管 CRX，需开启开发者模式加载解压目录，或使用企业策略 / Chrome Web Store。Linux 对本地 CRX 支持更好。
7. 会话和节点默认保存在服务端内存中，进程重启后临时会话全部失效，需要重新生成 CRX；TOTP 设置和 CRX 私钥会持久化在 `data/`。
8. Xray 配置导出覆盖常见协议 / 传输组合；复杂配置请自行调整。

## 开发与测试

要求 Node.js 22+。

```bash
npm install
npm run embed         # 把 public/ 与 extension-template/ 内嵌到 server/src/generated/assets.ts
npm run lint
npm run typecheck
npm test
npm run build
npm run dev           # 开发模式启动
```

构建单文件可执行程序（需要 Bun）：

```bash
npm run build:binary
```

测试覆盖：

- TOTP 正确 / 错误验证、登录限速与封禁、解封；
- TOTP + 密码模式；
- 随机 TOTP 密钥与二维码接口；
- 会话 TTL 过期、空闲过期、心跳续活；
- 并发设备限制、同设备旧会话撤销；
- 管理员 / 扩展撤销会话；
- 一次性 enrollment token 消费、重放拒绝、轮换与恢复窗口；
- 动态 CRX3 生成、CRX 内嵌 ZIP 中的 manifest / background 校验；
- 扩展保存 / 恢复原代理配置、重试恢复、幂等清理、token 轮换持久化；
- 节点 JSON / 分享链接导入导出、Xray 配置生成。

## 许可证

AGPL-3.0-only。详见 [LICENSE](./LICENSE)。
