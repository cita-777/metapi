# ❓ 常见问题（FAQ）

[返回文档中心](./README.md)

---

<a id="account-auth-guide"></a>

## 账号认证方式与兼容性（Session / API Key / OAuth）

### Q: Access Token、Cookie、API Key、OAuth 应该选哪个？

**A:** 现在最稳妥的判断方式不是只看“有没有 Token”，而是先看你接的是哪一类上游：

| 方式 | 特点 | 适用场景 |
|------|------|----------|
| **Access Token（系统访问令牌）** | 稳定、适合长期使用、适合多账号 | 标准 New API / One API / OneHub / DoneHub / Veloera 等面板站 |
| **Cookie（浏览器登录态）** | 兼容性强，但更容易过期 | Access Token 不可用、AnyRouter 一类魔改站点、特殊兜底场景 |
| **API Key** | 最简单，适合代理调用 | OpenAI / Claude / Gemini 兼容入口、CPA、各类官方预设 |
| **OAuth** | 不手填普通凭证，走浏览器授权 | Codex、Claude、Gemini CLI、Antigravity |

结论：

1. 面板型站点优先 **Access Token**
2. Access Token 拿不到时再考虑 **Cookie**
3. 兼容接口、CPA、官方预设优先 **API Key**
4. Provider 原生授权优先 **OAuth**

### Q: 在 Metapi 里怎么切换认证方式？

**A:** 入口已经分成两条：

1. **普通站点**：在「账号管理 / API Key 管理」里选择 Session 或 API Key
2. **OAuth provider**：在左侧「OAuth 管理」里完成授权

如果你不确定该去哪一页，先看 [上游接入](/upstream-integration)。

### Q: 以 NewAPI 为例，Access Token 在哪里生成？

**A:** 通常路径是：**控制台 → 个人设置 → 安全设置 → 系统访问令牌**。  
如果你确实需要 Cookie 兜底，可在浏览器 `F12 → Application → Cookie` 获取对应登录态。

### Q: 什么情况下应该直接走 OAuth？

**A:** 当你接的不是一个普通面板站，而是 provider 自己的账号授权时：

- Codex
- Claude
- Gemini CLI
- Antigravity

这时不要再把它当成“账号管理里的一条普通 Session”去处理，直接看 [OAuth 管理](/oauth)。

### Q: AnyRouter 这类魔改站点为什么更容易报错？

**A:** AnyRouter 在 Metapi 中按 NewAPI 兼容站点处理，但不少实例会隐藏 Access Token 入口，或额外加登录盾。建议：

1. 如果站点后台能生成系统访问令牌，优先用 Session 模式 + Access Token
2. 如果没有 Access Token 入口，或验证时被盾/认证页拦截，再改用 Cookie 导入
3. 若返回 HTML 盾页错误，先在浏览器完成验证后再重新绑定

### Q: CPA / CLIProxyAPI 应该怎么接？

**A:** 这类站点现在走 `cliproxyapi` 平台类型，推荐直接加 API Key，不建议把它当成可签到、可登录的面板站。详细步骤见 [上游接入](/upstream-integration)。

### Q: Sub2API 站点怎么处理？

**A:** Sub2API 常见 JWT 短期会话机制，和传统 NewAPI 站点差异较大。当前建议：

1. 在「凭证模式」里选择 Session 模式，分别粘贴 F12 界面中的 `auth_token`、`refresh_token`、`token_expires_at` 字段进行验证，无需配置用户 ID
2. 不要使用账号密码登录，Metapi 不支持代替 Sub2API 做登录
3. Sub2API 通常为订阅制使用，不支持签到；如果你只关心代理调用，也可以直接改用 API Key 模式
4. 若 `GET /v1/models` 为空，先确认该账号下已有可用用户 API Key，Metapi 会再尝试用它发现模型

详细操作说明见 [上游接入](/upstream-integration)。

## 部署相关

### Q: 启动后无法访问管理后台

**A:** 排查步骤：

1. 确认容器正常运行：`docker compose ps`
2. 确认端口映射正确：`docker compose logs | grep listening`
3. 检查防火墙是否放行了端口（默认 4000）
4. 如果使用反向代理，确认代理配置正确

### Q: 登录失败，提示令牌无效

**A:** 先确认你输入的是管理员令牌，而不是代理令牌。登录后台使用的是 `AUTH_TOKEN`，注意：

- 初始管理员令牌 = 启动时设置的 `AUTH_TOKEN`
- 如果你在非 Compose 场景未显式设置 `AUTH_TOKEN`，默认值是 `change-me-admin-token`（仅建议本地调试）
- 若复用旧 SQLite `data/` 目录，或当前实例已切到 MySQL / Postgres，系统会优先读取当前运行数据库中的 `auth_token` 设置（可能覆盖当前环境变量）
- 使用 `.env` 文件时，确认文件路径正确，且值不需要加引号

### Q: Docker Compose 启动报错 `AUTH_TOKEN is required`

**A:** 使用了 `${AUTH_TOKEN:?}` 语法，需要先设置环境变量：

```bash
export AUTH_TOKEN=your-token
export PROXY_TOKEN=your-proxy-token
docker compose up -d
```

或使用 `.env` 文件。

### Q: 桌面版启动失败

**A:** 排查步骤：

1. 确认下载的是与你系统匹配的桌面安装包
2. Windows 首次运行若出现未知发布者提示，先确认安装包来自官方 Releases
3. 如果桌面版提示后端启动失败，优先查看托盘菜单中的日志目录
4. 如需部署到服务器，请改用 Docker / Docker Compose，而不是桌面安装包

---

## 代理相关

### Q: 下游客户端提示 401 / 403

**A:** 排查：

- 确认使用的是 `PROXY_TOKEN`（代理令牌），而非 `AUTH_TOKEN`（管理令牌）
- 确认反向代理正确透传了 `Authorization` 请求头
- 检查是否设置了 `ADMIN_IP_ALLOWLIST` 限制了访问

### Q: `GET /v1/models` 返回空列表

**A:** 可能原因：

1. 未添加任何站点或账号
2. 账号处于 `unhealthy` 状态 — 在账号管理页面检查并刷新
3. 未同步 Token — 在 Token 管理页面点击「同步」
4. 模型未发现 — 手动触发模型刷新；若近期改过站点/账号/路由，可到「设置 → 清除缓存并重建路由」或「TokenRoutes → 重建路由」后再试

### Q: 非流式正常，但流式输出异常（卡住、乱码、截断）

**A:** 几乎都是反向代理配置问题。请确认：

1. Nginx：添加 `proxy_buffering off;`
2. 未改写 `text/event-stream` Content-Type
3. 无 CDN 或中间层缓存 SSE 响应

完整 Nginx 配置参考 [部署指南](./deployment.md#nginx)。

### Q: 某模型显示可用，但实际调用失败

**A:** 在管理后台的「模型测试器」中直测该模型，查看具体失败原因：

- **上游账号状态异常**：账号凭证过期或被禁用
- **通道处于冷却期**：近期该通道请求失败，系统自动冷却（默认 10 分钟）
- **上游模型下线**：上游站点已移除该模型
- **余额不足**：对应账号余额已耗尽

### Q: 请求延迟很高

**A:** 排查方向：

- 在代理日志中查看具体延迟分布
- 检查是否因冷却导致使用了较远/较慢的上游
- 调整路由权重，降低 `COST_WEIGHT`、提高成功率高的通道优先级

---

## 下游 API Key 相关

### Q: 如何限制不同项目/团队的用量

**A:** 在管理后台 **设置 → 下游 API Key** 中为每个项目创建独立的 Key，可单独配置：

- 费用上限（MaxCost）和请求上限（MaxRequests）
- 模型白名单（限制可用模型，支持通配符和正则）
- 路由白名单（限制可走的路由规则）
- 站点倍率（控制不同项目的上游偏好）

### Q: 下游 Key 和 PROXY_TOKEN 有什么区别

**A:** `PROXY_TOKEN` 是全局代理令牌，拥有完整权限。下游 Key 是项目级的细粒度控制，可设置过期时间、用量上限和模型限制，适合多团队共用的场景。

---

## 签到相关

### Q: 签到一直失败

**A:** 可能原因：

- 上游站点不支持签到功能
- 账号凭证已过期（系统会尝试自动重登录）
- 站点接口变更 — 检查 Metapi 是否为最新版本

### Q: 签到成功但奖励显示为 0

**A:** 部分站点的签到接口不返回奖励金额。Metapi 会尝试从收入日志推算奖励，但可能存在延迟。

---

## 数据相关

### Q: 数据迁移怎么做

**A:** 两种方式：

1. **应用内导入导出**（推荐）：在管理后台 → 导入/导出 页面操作，适合 SQLite / MySQL / Postgres / Desktop 之间迁移
2. **目录迁移**：仅适用于当前运行在 SQLite 的实例（包括桌面版本地数据目录）
3. **数据库原生迁移**：如果当前运行库是 MySQL / Postgres，请使用数据库自己的备份/恢复工具，而不是只拷贝 `data/`

### Q: 如何清理历史数据

**A:** 代理日志和签到日志会持续增长。在管理后台对应页面可以清理历史记录；如果还需要把路由占用统计一并归零，可到「设置 → 清除占用与使用日志」。

### Q: 开源发布时如何避免泄露敏感信息

**A:**

- 确认 `.gitignore` 包含 `.env`、`data/`、`tmp/`
- 发布前执行一次密钥轮换（上游账号密码、通知 SMTP、Webhook 地址）
- 使用全新仓库或清理 Git 历史后再公开
- 检查备份 JSON 文件中是否包含凭证

---

## 更多帮助

如果以上内容未能解决你的问题：

- [搜索已有 Issue](https://github.com/cita-777/metapi/issues?q=is%3Aissue) — 看看是否有人遇到过相同问题
- [提交新 Issue](https://github.com/cita-777/metapi/issues/new) — 报告 Bug 或提出功能建议
- [参与讨论](https://github.com/cita-777/metapi/discussions) — 使用疑问、经验分享
- [文档中心](./README.md) — 查看所有文档
