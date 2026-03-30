# 🛠️ 管理 API

**注意：以下内容适用于有一定技术能力的用户，否则请跳过此页面！！！**

本文档说明如何直接调用 Metapi 管理后台的 `/api/*` 接口，用脚本完成站点与账号管理。

[返回文档维护页](./README.md)

[返回文档首页](/)

---

## 适用范围

这组接口适合以下场景：

- 初始化新实例，批量导入站点和账号
- 用 Shell / Python / CI 脚本维护现有管理数据
- 在外部系统里接入 Metapi 后台能力，而不是手工点页面

> [!IMPORTANT]
> 本页介绍的是 **管理 API**，不是下游客户端调用的 `/v1/*` 代理接口。
> - 管理 API 使用 `AUTH_TOKEN`
> - 代理接口使用 `PROXY_TOKEN`

## 认证方式

所有受保护的管理接口都需要携带：

```http
Authorization: Bearer <AUTH_TOKEN>
```

其中：

- `AUTH_TOKEN` 就是你启动 Metapi 时配置的管理员令牌
- 如果你后来在「设置」里修改过管理员令牌，脚本里也要同步改成新值
- 管理端如果启用了 `ADMIN_IP_ALLOWLIST`，脚本调用方的来源 IP 也必须命中白名单

管理 API 不需要额外先调用“登录接口”；脚本直接带 `AUTH_TOKEN` 即可。

推荐先准备两个环境变量：

```bash
export METAPI_ADMIN_BASE_URL="http://127.0.0.1:4000"
# 或者
# export METAPI_ADMIN_BASE_URL="https://your-domain.com"
export METAPI_AUTH_TOKEN="your-admin-token"
```

之后所有请求都可以复用：

```bash
curl -sS "${METAPI_ADMIN_BASE_URL}/api/sites" \
  -H "Authorization: Bearer ${METAPI_AUTH_TOKEN}"
```

## 通用约定

| 项目 | 说明 |
|------|------|
| 接口前缀 | 管理接口统一在 `/api/*` |
| 请求体 | 默认使用 `application/json` |
| 认证方式 | `Authorization: Bearer <AUTH_TOKEN>` |
| 成功判定 | 除了看 HTTP 状态码，也要看响应体里的 `success` / `error` / `message` |
| 业务失败返回 | 有些接口会返回 `200`，但响应体里是 `success: false` |
| 常见错误码 | `400` 参数错误、`401/403` 认证失败、`409` 资源冲突、`429` 触发限流 |

> [!TIP]
> 对脚本来说，最稳妥的做法是：
> 1. 先检查 HTTP 状态码
> 2. 再检查返回 JSON 里的 `success`、`error`、`message`
> 3. 不要只靠 `200` 判断调用成功

## 常用脚本流程

脚本化添加一个新站点并绑定账号，通常按下面顺序：

1. `POST /api/sites/detect` 自动识别平台
2. `POST /api/sites` 创建站点
3. `POST /api/accounts/verify-token` 验证凭证
4. `POST /api/accounts` 保存账号

最小流程示例：

```bash
# 1. 自动识别站点类型
curl -sS "${METAPI_ADMIN_BASE_URL}/api/sites/detect" \
  -H "Authorization: Bearer ${METAPI_AUTH_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://api.example.com"
  }'

# 2. 创建站点
curl -sS "${METAPI_ADMIN_BASE_URL}/api/sites" \
  -H "Authorization: Bearer ${METAPI_AUTH_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My New API",
    "url": "https://api.example.com",
    "platform": "new-api"
  }'

# 3. 验证 API Key 或 Session Token
curl -sS "${METAPI_ADMIN_BASE_URL}/api/accounts/verify-token" \
  -H "Authorization: Bearer ${METAPI_AUTH_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "siteId": 1,
    "accessToken": "sk-or-session-token",
    "credentialMode": "apikey"
  }'

# 4. 保存账号
curl -sS "${METAPI_ADMIN_BASE_URL}/api/accounts" \
  -H "Authorization: Bearer ${METAPI_AUTH_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "siteId": 1,
    "accessToken": "sk-or-session-token",
    "credentialMode": "apikey"
  }'
```

## 站点接口

### 1. 获取站点列表

`GET /api/sites`

返回当前全部站点。响应除了站点自身字段，还会带上聚合出来的 `totalBalance` 和 `subscriptionSummary`。

示例：

```bash
curl -sS "${METAPI_ADMIN_BASE_URL}/api/sites" \
  -H "Authorization: Bearer ${METAPI_AUTH_TOKEN}"
```

示例响应：

```json
[
  {
    "id": 1,
    "name": "My New API",
    "url": "https://api.example.com",
    "platform": "new-api",
    "status": "active",
    "useSystemProxy": false,
    "totalBalance": 42.5,
    "subscriptionSummary": null
  }
]
```

### 2. 自动识别站点类型

`POST /api/sites/detect`

用于在真正创建站点前，先根据 URL 探测平台类型。

请求体：

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `url` | `string` | 是 | 站点根地址，**不要**带 `/v1` |

示例：

```bash
curl -sS "${METAPI_ADMIN_BASE_URL}/api/sites/detect" \
  -H "Authorization: Bearer ${METAPI_AUTH_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://api.example.com"
  }'
```

成功响应：

```json
{
  "url": "https://api.example.com",
  "platform": "new-api"
}
```

失败响应：

```json
{
  "error": "Could not detect platform"
}
```

### 3. 创建站点

`POST /api/sites`

请求体字段：

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `name` | `string` | 是 | 站点名称 |
| `url` | `string` | 是 | 站点根地址，**不要**带 `/v1` |
| `platform` | `string` | 否 | 平台类型；留空时服务端会再次尝试自动识别 |
| `proxyUrl` | `string \| null` | 否 | 站点专用代理地址，支持 `http(s)` / `socks` |
| `useSystemProxy` | `boolean` | 否 | 是否使用全局 `SYSTEM_PROXY_URL` |
| `customHeaders` | `string \| null` | 否 | 自定义请求头，注意这里传的是 **JSON 字符串** |
| `externalCheckinUrl` | `string \| null` | 否 | 外部签到地址，需为 `http(s)` |
| `status` | `string` | 否 | `active` 或 `disabled` |
| `isPinned` | `boolean` | 否 | 是否置顶 |
| `sortOrder` | `number` | 否 | 排序值，非负整数 |
| `globalWeight` | `number` | 否 | 站点全局权重，必须为正数 |

示例：

```bash
curl -sS "${METAPI_ADMIN_BASE_URL}/api/sites" \
  -H "Authorization: Bearer ${METAPI_AUTH_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Proxy Site",
    "url": "https://proxy-site.example.com",
    "platform": "new-api",
    "proxyUrl": "socks5://127.0.0.1:1080",
    "useSystemProxy": true,
    "customHeaders": "{\"cf-access-client-id\":\"site-client-id\",\"x-site-scope\":\"internal\"}",
    "externalCheckinUrl": "https://checkin.example.com/welfare",
    "globalWeight": 1.5
  }'
```

成功响应示例：

```json
{
  "id": 1,
  "name": "Proxy Site",
  "url": "https://proxy-site.example.com",
  "platform": "new-api",
  "proxyUrl": "socks5://127.0.0.1:1080",
  "useSystemProxy": true,
  "customHeaders": "{\"cf-access-client-id\":\"site-client-id\",\"x-site-scope\":\"internal\"}",
  "externalCheckinUrl": "https://checkin.example.com/welfare",
  "status": "active",
  "globalWeight": 1.5
}
```

常见失败：

- `409`：同一个 `(platform, url)` 已存在
- `400`：`proxyUrl`、`externalCheckinUrl`、`customHeaders`、`globalWeight` 等字段格式不合法

> [!TIP]
> `customHeaders` 不是对象，而是 JSON 字符串；并且 value 必须是字符串。

## 账号接口

### 1. 获取账号列表

`GET /api/accounts`

返回当前全部账号，以及关联站点、凭证模式、能力信息、今日花费、运行健康状态等聚合字段。

示例：

```bash
curl -sS "${METAPI_ADMIN_BASE_URL}/api/accounts" \
  -H "Authorization: Bearer ${METAPI_AUTH_TOKEN}"
```

示例响应：

```json
[
  {
    "id": 1,
    "siteId": 1,
    "username": "alice",
    "status": "active",
    "credentialMode": "apikey",
    "capabilities": {
      "canCheckin": false,
      "canRefreshBalance": false,
      "proxyOnly": true
    },
    "site": {
      "id": 1,
      "name": "My New API",
      "url": "https://api.example.com",
      "platform": "new-api"
    }
  }
]
```

### 2. 验证凭证

`POST /api/accounts/verify-token`

建议在真正保存账号前先调用一次。这样脚本可以在入库前拿到更明确的错误信息。

请求体字段：

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `siteId` | `number` | 是 | 目标站点 ID |
| `accessToken` | `string` | 是 | Session Token / Session Cookie / API Key |
| `platformUserId` | `number` | 否 | 某些 `new-api` / `anyrouter` 站点需要手动传 |
| `credentialMode` | `string` | 否 | `auto` / `session` / `apikey`，脚本里推荐显式传 |

#### 验证 API Key

```bash
curl -sS "${METAPI_ADMIN_BASE_URL}/api/accounts/verify-token" \
  -H "Authorization: Bearer ${METAPI_AUTH_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "siteId": 1,
    "accessToken": "sk-fast-verify",
    "credentialMode": "apikey"
  }'
```

成功响应：

```json
{
  "success": true,
  "tokenType": "apikey",
  "modelCount": 2,
  "models": ["gpt-5-mini", "gpt-4o-mini"]
}
```

#### 验证 Session Token

```bash
curl -sS "${METAPI_ADMIN_BASE_URL}/api/accounts/verify-token" \
  -H "Authorization: Bearer ${METAPI_AUTH_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "siteId": 1,
    "accessToken": "session=xxxx",
    "credentialMode": "session"
  }'
```

成功响应：

```json
{
  "success": true,
  "tokenType": "session",
  "userInfo": {
    "username": "alice"
  },
  "balance": 12.34,
  "apiToken": "sk-generated-by-upstream"
}
```

> [!TIP]
> 对 `new-api` / `anyrouter` 一类站点，如果返回 `needsUserId: true`，说明脚本里要补上 `platformUserId` 再重试。

### 3. 保存账号

`POST /api/accounts`

请求体字段：

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `siteId` | `number` | 是 | 目标站点 ID |
| `accessToken` | `string` | 是 | 输入凭证；即使是 API Key 模式，也先放这里 |
| `username` | `string` | 否 | 用户名；Session 模式下通常可由服务端自动识别 |
| `apiToken` | `string` | 否 | 可显式指定要保存的 API Key；留空时服务端会自动推断 |
| `platformUserId` | `number` | 否 | 平台用户 ID，New API 系站点常用 |
| `checkinEnabled` | `boolean` | 否 | Session 模式下是否开启签到 |
| `credentialMode` | `string` | 否 | `auto` / `session` / `apikey` |
| `refreshToken` | `string` | 否 | `sub2api` 会话可附带刷新令牌 |
| `tokenExpiresAt` | `number \| string` | 否 | `sub2api` 会话过期时间戳 |
| `skipModelFetch` | `boolean` | 否 | 为 `true` 时可跳过即时模型拉取 |

#### 保存 API Key 账号

```bash
curl -sS "${METAPI_ADMIN_BASE_URL}/api/accounts" \
  -H "Authorization: Bearer ${METAPI_AUTH_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "siteId": 1,
    "accessToken": "sk-proxy-only",
    "credentialMode": "apikey"
  }'
```

成功响应示例：

```json
{
  "id": 1,
  "siteId": 1,
  "tokenType": "apikey",
  "credentialMode": "apikey",
  "capabilities": {
    "canCheckin": false,
    "canRefreshBalance": false,
    "proxyOnly": true
  },
  "modelCount": 1,
  "apiTokenFound": true,
  "queued": true,
  "jobId": "task_xxx",
  "message": "已添加为 API Key 账号，后台正在同步模型和路由信息。"
}
```

#### 保存 Session 账号

```bash
curl -sS "${METAPI_ADMIN_BASE_URL}/api/accounts" \
  -H "Authorization: Bearer ${METAPI_AUTH_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "siteId": 1,
    "accessToken": "session=xxxx",
    "credentialMode": "session",
    "platformUserId": 1001,
    "checkinEnabled": true
  }'
```

常见失败：

- `400` + `requiresVerification: true`：凭证还没有通过验证，建议先调用 `/api/accounts/verify-token`
- `400`：`siteId` 不存在、Token 为空、凭证类型与 `credentialMode` 不匹配

> [!TIP]
> 对纯脚本导入场景，建议始终显式传 `credentialMode`，不要依赖 `auto` 推断。

### 4. 重新绑定 Session Token

`POST /api/accounts/:id/rebind-session`

用于账号 Session 过期后，脚本直接把新 Session Token 重新写回账号。

请求体字段：

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `accessToken` | `string` | 是 | 新的 Session Token |
| `platformUserId` | `number` | 否 | 覆盖或补充平台用户 ID |
| `refreshToken` | `string` | 否 | `sub2api` 会话可附带 |
| `tokenExpiresAt` | `number \| string` | 否 | `sub2api` 会话过期时间戳 |

示例：

```bash
curl -sS "${METAPI_ADMIN_BASE_URL}/api/accounts/1/rebind-session" \
  -H "Authorization: Bearer ${METAPI_AUTH_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "accessToken": "session=new-token",
    "platformUserId": 1001
  }'
```

成功响应示例：

```json
{
  "success": true,
  "tokenType": "session",
  "credentialMode": "session",
  "apiTokenFound": true
}
```

## 常见失败返回

### 站点创建冲突

当同一个 `(platform, url)` 已存在时，会返回：

```json
{
  "error": "A new-api site with URL https://api.example.com already exists."
}
```

### 需要补平台用户 ID

某些 `new-api` / `anyrouter` 站点会返回：

```json
{
  "success": false,
  "needsUserId": true,
  "message": "This site requires a user ID. Please fill in your site user ID."
}
```

这时请在 `/api/accounts/verify-token` 或 `/api/accounts` 里补上 `platformUserId`。

### 平台用户 ID 不匹配

```json
{
  "success": false,
  "invalidUserId": true,
  "message": "The provided user ID does not match this token. Please check your site user ID."
}
```

### 命中防护盾

```json
{
  "success": false,
  "shieldBlocked": true,
  "message": "This site is shielded by anti-bot challenge. Create an API key on the target site and import that key."
}
```

这通常意味着账号密码或 Session 流程被防护页拦住了，更适合改用 API Key 模式。

### 验证过于频繁

`POST /api/accounts/verify-token` 对同一来源 IP 有速率限制。超过限制后会返回：

```json
{
  "success": false,
  "message": "请求过于频繁，请稍后再试"
}
```

建议脚本在这类错误上做退避重试。

## 下一步

- [上游接入](./upstream-integration.md) — 查看不同站点类型应该怎么填 URL、凭证和 User ID
- [配置说明](./configuration.md) — 查看 `AUTH_TOKEN`、`ADMIN_IP_ALLOWLIST`、系统代理等配置项
- [客户端接入](./client-integration.md) — 如果你要接的是 `/v1/*` 代理接口而不是后台管理接口，请看这里
