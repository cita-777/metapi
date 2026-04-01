# ⚙️ 配置说明

本文档列出 Metapi 的环境变量，并单独说明管理后台中的运行时设置。

[返回文档中心](./README.md)

---

## 配置来源

| 配置类型 | 入口 | 生效方式 | 适用场景 |
|----------|------|----------|----------|
| 环境变量 | `.env` / 容器环境变量 | 服务启动时读取，作为启动配置或默认值 | 部署、容器编排、首次初始化 |
| 运行时设置 | 管理后台「设置」 | 持久化到当前运行数据库；大部分即时生效，数据库运行配置保存后需重启 | 在线调整、运维排障 |

## 必填配置

> ⚠️ 以下变量**必须修改**，不要使用默认值。

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `AUTH_TOKEN` | 管理后台登录令牌 | `change-me-admin-token` |
| `PROXY_TOKEN` | 代理接口 Bearer Token（下游客户端使用此值作为 API Key） | `change-me-proxy-sk-token` |

## 基础配置

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `PORT` | 服务监听端口 | `4000` |
| `DATA_DIR` | 数据目录（SQLite 数据库存储位置） | `./data` |
| `TZ` | 时区 | `Asia/Shanghai` |
| `SYSTEM_PROXY_URL` | 系统代理 URL（留空表示不使用） | 空 |
| `ACCOUNT_CREDENTIAL_SECRET` | 账号凭证加密密钥（用于加密存储的上游账号密码） | 默认使用 `AUTH_TOKEN` |

## 更新中心与 Deploy Helper

如果你现在只是一个普通 Docker / Docker Compose 部署，没有 K3s / Kubernetes、没有 Helm release、也没有 Deploy Helper，那么这一节可以先跳过。

这一节只写给已经准备使用“K3s 更新中心”的用户。除了设置页里的运行时字段，还需要补齐主服务和 helper 的环境变量。

如果你是老用户，正在从 Docker Compose 迁到 K3s / Helm，这一节可以提前看，先把迁移后的环境变量和组件关系理解清楚。

### 主 Metapi 服务

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `DEPLOY_HELPER_TOKEN` | 主服务访问 Deploy Helper 的 Bearer Token | 空 |
| `UPDATE_CENTER_HELPER_TOKEN` | `DEPLOY_HELPER_TOKEN` 的兼容别名，二选一即可 | 空 |

> [!IMPORTANT]
> 主 Metapi 和 Deploy Helper 必须使用同一个 token，否则更新中心可以显示页面但无法完成 helper 状态查询或部署。

### Deploy Helper 服务

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `DEPLOY_HELPER_HOST` | helper 监听地址 | `0.0.0.0` |
| `DEPLOY_HELPER_PORT` | helper 监听端口 | `9850` |
| `DEPLOY_HELPER_TOKEN` | helper Bearer Token，必须和主服务一致 | 空 |

### 设置页里的持久化字段

更新中心页面本身还会把下面这些字段持久化到运行数据库：

- `helperBaseUrl`
- `namespace`
- `releaseName`
- `chartRef`
- `imageRepository`
- `githubReleasesEnabled`
- `dockerHubTagsEnabled`
- `defaultDeploySource`

完整接入步骤见：

- [K3s 更新中心](./k3s-update-center.md)

## 数据库配置

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `DB_TYPE` | 运行数据库类型：`sqlite` / `mysql` / `postgres` | `sqlite` |
| `DB_URL` | 数据库连接串；使用 `mysql` / `postgres` 时必填 | 空 |
| `DB_SSL` | 连接 MySQL / Postgres 时启用 SSL | `false` |

`DB_TYPE=sqlite` 时，`DB_URL` 留空即可，服务会使用默认 SQLite 路径。

## 定时任务

| 变量名 | 说明 | 默认值 | 示例 |
|--------|------|--------|------|
| `CHECKIN_CRON` | 自动签到计划 | `0 8 * * *` | 每天 8:00 |
| `BALANCE_REFRESH_CRON` | 余额刷新计划 | `0 * * * *` | 每小时整点 |

Cron 表达式格式：`分 时 日 月 周`（标准五段式）

常用示例：
- `0 8 * * *` — 每天 08:00
- `0 */2 * * *` — 每 2 小时
- `30 7,12,20 * * *` — 每天 07:30、12:30、20:30

## 智能路由

Metapi 的路由引擎按多因子加权选择最优通道。

### 成本信号优先级

```
实测成本（代理日志） → 账号配置成本 → 目录参考价 → 兜底默认值
```

### 路由权重参数

| 变量名 | 说明 | 默认值 | 范围 |
|--------|------|--------|------|
| `ROUTING_FALLBACK_UNIT_COST` | 无成本信号时的默认单价 | `1` | > 0 |
| `BASE_WEIGHT_FACTOR` | 基础权重因子 | `0.5` | 0~1 |
| `VALUE_SCORE_FACTOR` | 性价比评分因子 | `0.5` | 0~1 |
| `COST_WEIGHT` | 成本权重（越大越偏向低成本通道） | `0.4` | 0~1 |
| `BALANCE_WEIGHT` | 余额权重（越大越偏向余额充足的通道） | `0.3` | 0~1 |
| `USAGE_WEIGHT` | 使用率权重（越大越偏向使用较少的通道） | `0.3` | 0~1 |

> 三个权重之和建议为 1.0，但不强制。

### 路由缓存

| 变量名 | 说明 | 默认值 | 范围 |
|--------|------|--------|------|
| `TOKEN_ROUTER_CACHE_TTL_MS` | Token 路由缓存 TTL（毫秒） | `1500` | >= 100 |

### 路由预设建议

| 场景 | COST_WEIGHT | BALANCE_WEIGHT | USAGE_WEIGHT | 说明 |
|------|:-----------:|:--------------:|:------------:|------|
| **成本优先** | 0.7 | 0.2 | 0.1 | 适合预算敏感场景，总是选最便宜的通道 |
| **均衡（默认）** | 0.4 | 0.3 | 0.3 | 兼顾成本、余额和负载均衡，推荐大多数用户 |
| **稳定优先** | 0.2 | 0.5 | 0.3 | 适合生产环境，优先选余额充足的通道避免中断 |
| **轮转均匀** | 0.1 | 0.1 | 0.8 | 适合测试场景，尽量让每个通道都被使用到 |

**调参建议：**

- 如果某个站点总是被选中导致余额很快耗尽 → 调高 `BALANCE_WEIGHT`
- 如果你有几个很便宜的站点想优先用 → 调高 `COST_WEIGHT`
- 如果你想让请求均匀分散到所有站点 → 调高 `USAGE_WEIGHT`
- 如果你需要对特定项目偏好某个站点 → 使用[下游 API Key 的 `siteWeightMultipliers`](#下游-api-key-策略) 而非调全局权重

## 代理日志保留

| 变量名 | 说明 | 默认值 | 范围 |
|--------|------|--------|------|
| `PROXY_LOG_RETENTION_DAYS` | 代理日志保留天数 | `30` | >= 0 |
| `PROXY_LOG_RETENTION_PRUNE_INTERVAL_MINUTES` | 代理日志清理任务执行间隔（分钟） | `30` | >= 1 |

## 安全配置

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `ADMIN_IP_ALLOWLIST` | 管理端 IP 白名单（逗号分隔，支持单个 IP 与 IPv4 CIDR） | 空（不限制） |

示例：`ADMIN_IP_ALLOWLIST=192.168.1.10,192.168.1.0/24,10.0.0.0/8`

## 下游 API Key 策略

除了全局 `PROXY_TOKEN`，Metapi 支持在管理后台「设置 → 下游 API Key」中创建多个项目级下游 Key。

每个 Key 可独立配置以下约束：

| 字段 | 说明 | 示例 |
|------|------|------|
| `name` | Key 名称（仅供标识） | `team-backend` |
| `expiresAt` | 过期时间 | `2026-12-31T23:59:59Z` |
| `maxCost` | 累计费用上限 | `100`（超限后拒绝请求） |
| `maxRequests` | 累计请求数上限 | `10000` |
| `supportedModels` | 模型白名单（JSON 数组） | `["gpt-4o", "claude-*", "re:deepseek.*"]` |
| `allowedRouteIds` | 可走的路由 ID 白名单 | `[1, 3, 5]` |
| `siteWeightMultipliers` | 站点权重倍率 | `{"1": 2.0, "3": 0.5}` |

模型白名单支持三种匹配模式：

- **精确匹配**：`gpt-4o`
- **通配符**：`claude-*`（glob 风格）
- **正则表达式**：`re:deepseek.*`（`re:` 前缀）

## 通知渠道

### Webhook

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `WEBHOOK_ENABLED` | 启用 Webhook 通知 | `true` |
| `WEBHOOK_URL` | Webhook 推送地址 | 空 |

### Bark（iOS 推送）

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `BARK_ENABLED` | 启用 Bark 推送 | `true` |
| `BARK_URL` | Bark 推送地址 | 空 |

### Server酱

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `SERVERCHAN_ENABLED` | 启用 Server酱 通知 | `true` |
| `SERVERCHAN_KEY` | Server酱 SendKey | 空 |

### Telegram Bot

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `TELEGRAM_ENABLED` | 启用 Telegram 通知 | `false` |
| `TELEGRAM_BOT_TOKEN` | Telegram Bot Token（形如 `123456:abc`） | 空 |
| `TELEGRAM_CHAT_ID` | 接收消息的 Chat ID（如 `-100xxxx` 或 `@channel`） | 空 |

**配置步骤：**

1. **创建 Bot**：在 Telegram 中搜索 [@BotFather](https://t.me/BotFather)，发送 `/newbot`，按提示设置名称后获取 Bot Token（格式如 `123456789:ABCdefGHIjklMNOpqrsTUVwxyz`）
2. **获取 Chat ID**：
   - **个人聊天**：向你的 Bot 发送任意消息，然后访问 `https://api.telegram.org/bot<你的Token>/getUpdates`，在返回的 JSON 中找到 `chat.id`，或者在 Telegram 搜索 @userinfobot 或是 @getmyid_bot。点击 Start，它会立刻回复一串数字（通常是 9 到 10 位）。
   - **群组**：将 Bot 邀请进群组，在群内发送消息后同样通过 `getUpdates` 接口获取群组 Chat ID（通常为负数，如 `-1001234567890`）
   - **频道**：使用频道用户名，如 `@your_channel`（需先将 Bot 添加为频道管理员）
3. **填入配置**：将获取的 Token 和 Chat ID 填入管理后台「通知设置」页面
4. **大陆服务器反代**：如果服务器无法直连 Telegram，可在「通知设置」里填写 `Telegram API Base URL`，例如 `https://your-proxy.example.com`，Metapi 将请求 `https://your-proxy.example.com/bot<token>/sendMessage`
5. **测试**：保存后点击页面上的「测试通知」按钮验证是否收到消息

### SMTP 邮件

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `SMTP_ENABLED` | 启用邮件通知 | `false` |
| `SMTP_HOST` | SMTP 服务器地址 | 空 |
| `SMTP_PORT` | SMTP 端口 | `587` |
| `SMTP_SECURE` | 使用 SSL/TLS | `false` |
| `SMTP_USER` | SMTP 用户名 | 空 |
| `SMTP_PASS` | SMTP 密码 | 空 |
| `SMTP_FROM` | 发件人地址 | 空 |
| `SMTP_TO` | 收件人地址 | 空 |

### 告警控制

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `NOTIFY_COOLDOWN_SEC` | 相同告警冷却时间（秒），防止同一事件重复通知 | `300` |

## 运行时设置

管理后台「设置」中的运行时设置与环境变量分开管理：环境变量负责启动默认值；保存后的运行时设置会持久化到当前运行数据库，并覆盖对应默认值。

| 分类 | 对应项 | 生效方式 |
|------|--------|----------|
| 代理访问与网络 | `PROXY_TOKEN`、`SYSTEM_PROXY_URL`、`ADMIN_IP_ALLOWLIST` | 保存后即时生效 |
| 定时任务 | `CHECKIN_CRON`、`BALANCE_REFRESH_CRON` | 保存后即时生效 |
| 智能路由 | `ROUTING_FALLBACK_UNIT_COST`、各路由权重 | 保存后即时生效 |
| 通知渠道 | Webhook / Bark / Telegram / Server酱 / SMTP / `NOTIFY_COOLDOWN_SEC` | 保存后即时生效 |
| 数据库运行配置 | `DB_TYPE`、`DB_URL`、`DB_SSL` | 保存后在下次 Metapi 后端启动时生效 |

> `TOKEN_ROUTER_CACHE_TTL_MS`、`PROXY_LOG_RETENTION_DAYS`、`PROXY_LOG_RETENTION_PRUNE_INTERVAL_MINUTES` 当前仍属于部署级环境变量，不在后台运行时设置里单独维护。

## 站点公告

管理后台新增了「站点公告」页面，用于保存和浏览 Metapi 已同步到本地的上游公告记录。

- 首次发现的上游公告会写入站内通知，并按现有通知渠道外发一次
- 后续重复同步只更新本地公告记录，不会重复外发同一条公告
- 当前支持的上游公告来源包括 `new-api`、`done-hub` 与 `sub2api`
- 「清空公告」只删除 Metapi 本地保存的公告记录，不会修改上游站点数据

## 更新提醒

更新中心现在会在后台定时检查 GitHub Releases / Docker Hub 的可部署候选，并把结果保存为本地运行时状态。

- 首次发现新的版本候选或新的 Docker digest 时，会写入站内通知，并按现有通知渠道外发一次
- 相同候选后续重复检查只更新本地运行时状态，不会重复外发同一条提醒
- 这类提醒不会自动触发部署，只是把用户带到「设置 → 更新中心」继续手动确认和执行
- K3s 用户可以在收到提醒后直接去更新中心部署；Compose 用户也可以收到提醒，但仍按自己的升级方式处理

## 下一步

- [部署指南](./deployment.md) — Docker Compose 与反向代理
- [客户端接入](./client-integration.md) — 对接下游应用
- [上游接入](./upstream-integration.md) — 添加和管理上游平台
- [运维手册](./operations.md) — 备份、日志与健康检查
