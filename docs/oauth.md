# 🔐 OAuth 管理

本文档介绍 Metapi 里的「OAuth 管理」页面，适合需要直接授权 provider 账号的场景。

[返回文档中心](/)

---

## 这页解决什么问题

不是所有上游都适合手填 API Key、Access Token 或 Cookie。

对下面这类 provider 账号，更推荐直接走 OAuth：

- Codex
- Claude
- Gemini CLI
- Antigravity

这类接法的特点是：

- 使用浏览器授权，而不是手填用户名密码
- 授权成功后，Metapi 会自动创建或复用对应 provider 的站点
- 账号会按 OAuth 连接保存，后续刷新和重绑也走同一套流程

如果你接的是 New API、One API、Sub2API、CPA、OpenAI-compatible、Claude-compatible 这类**普通站点或网关**，请看 [上游接入](/upstream-integration)。

---

## 入口在哪里

管理后台左侧菜单已经有独立入口：

```text
OAuth 管理
```

这不是站点编辑器里的一个隐藏选项，而是和「站点管理」「账号管理」并列的一页。

---

## 当前支持的 provider

| Provider | 对应平台 | 自动创建的站点名 | 典型用途 |
|------|------|------|------|
| Codex | `codex` | `ChatGPT Codex OAuth` | 直接用 Codex 账号授权 |
| Claude | `claude` | `Anthropic Claude OAuth` | 直接用 Claude / Anthropic 账号授权 |
| Gemini CLI | `gemini-cli` | `Google Gemini CLI OAuth` | 复用 Gemini CLI / Google Cloud 账号授权，可选输入 Project ID |
| Antigravity | `antigravity` | `Google Antigravity OAuth` | 复用 Antigravity 账号授权 |

授权完成后，这些站点会出现在「站点管理」里，但通常**不建议你手动创建**它们。

---

## 授权前的准备

### 1. 确保 Metapi 能访问 provider 的 OAuth 端点

如果你的部署环境访问外网受限，可以：

- 先配置全局 `SYSTEM_PROXY_URL`
- 或在 OAuth 启动 / 重绑时使用单次代理参数

相关环境变量见 [配置说明](/configuration) 里的「OAuth 与 Provider 登录」一节。

### 2. 远程部署要提前考虑回调方式

OAuth 默认使用 Metapi 本机上的 loopback 回调地址，例如本机 `127.0.0.1` 端口。

如果你的 Metapi 跑在远程服务器上，而浏览器跑在本地电脑上，常见做法有两个：

1. **SSH 隧道**：按页面给出的命令，把回调端口转发到远端
2. **手动回填 callback URL**：如果浏览器已经完成授权，但自动回调没打通，可把最终回调地址手动贴回管理页

### 3. 了解它和普通站点接入的边界

OAuth 连接更适合“provider 原生账号授权”，而不是：

- 面板站点账号密码登录
- New API / One API 后台管理
- CPA / OpenAI-compatible 的普通 API Key 托管

---

## 标准流程

### 步骤 1：打开 OAuth 管理

进入左侧菜单「OAuth 管理」，等待页面加载 provider 列表和已有连接。

### 步骤 2：点击要连接的 provider

页面会为 provider 发起一个 OAuth 会话，并弹出授权窗口。

Metapi 会同时给出：

- 授权链接
- 本机回调端口
- 手动回填等待时间
- 如果当前是远程访问，还会给出 SSH 隧道命令模板

### 步骤 3：在 provider 页面完成授权

完成授权后，Metapi 会轮询当前会话状态：

- `pending`：等待回调
- `success`：授权成功
- `error`：授权失败，需要重新检查浏览器回调或网络

### 步骤 4：必要时手动回填 callback URL

如果弹窗里已经能看到类似 `...?code=...&state=...` 的回调地址，但 Metapi 页面还没成功：

1. 复制浏览器最终回调 URL
2. 回到「OAuth 管理」
3. 粘贴到手动回填区域提交

### 步骤 5：确认站点与连接都已出现

成功后通常会看到两层结果：

- 「OAuth 管理」页里出现新的连接记录
- 「站点管理」页里出现对应 provider 的站点行

---

## 和普通站点 / API Key 的区别

| 方式 | 入口 | 适合什么 | 典型例子 |
|------|------|------|------|
| 普通站点 + Session | 站点管理 / 账号管理 | 有后台面板，需要签到、余额、账号令牌管理 | New API、One API、DoneHub、AnyRouter、Sub2API |
| 普通站点 + API Key | 站点管理 / API Key 管理 | 只关心代理调用和模型列表 | OpenAI-compatible、Claude-compatible、CPA |
| OAuth 连接 | OAuth 管理 | 需要 provider 官方授权、刷新、重绑 | Codex、Claude、Gemini CLI、Antigravity |

简单判断：

- 你拿到的是 **站点后台地址**，优先看 [上游接入](/upstream-integration)
- 你拿到的是 **provider 登录授权**，优先看这页

---

## 自动生成的站点有什么用

OAuth 成功后，Metapi 会确保对应 provider 的站点存在。这样做是为了让 OAuth 连接也能融入现有的：

- 站点列表
- 路由通道
- 账号归属
- 代理与重绑逻辑

但这类站点和普通面板站点仍然不同：

- 它们通常不是拿来手动登录的
- 不要把它理解成“我又多了一个可签到的面板站”
- 更准确地说，它是 OAuth 账号在 Metapi 里的宿主站点

---

## 管理 API 里怎么自动化

如果你想脚本化处理 OAuth，可以用这些接口：

| 接口 | 作用 |
|------|------|
| `GET /api/oauth/providers` | 获取当前可用 provider 列表 |
| `POST /api/oauth/providers/:provider/start` | 启动 OAuth 流程 |
| `GET /api/oauth/sessions/:state` | 轮询会话状态 |
| `POST /api/oauth/sessions/:state/manual-callback` | 手动回填 callback URL |
| `GET /api/oauth/connections` | 列出现有连接 |
| `POST /api/oauth/connections/:accountId/rebind` | 重绑已有 OAuth 连接 |
| `DELETE /api/oauth/connections/:accountId` | 删除 OAuth 连接 |

脚本示例见 [管理 API](/management-api)。

---

## 常见问题

### provider 显示“当前不可用”

通常说明回调监听器不可用，或当前 provider 的启动条件不满足。优先检查：

1. 服务是否刚启动但回调监听失败
2. 端口是否被占用
3. 当前环境是否缺少必要的 OAuth 配置

### 浏览器授权成功了，但页面一直停在“等待授权完成”

优先怀疑回调链路没通：

1. 如果是远程服务器，先按页面提示建 SSH 隧道
2. 如果不方便建隧道，直接用手动 callback 回填
3. 如果 provider 页面最终没有 `code` / `state` 参数，说明授权本身还没成功

### OAuth 连接需要系统代理吗

有可能需要，尤其是：

- 国内服务器访问 OpenAI / Anthropic / Google OAuth 端点
- 服务器本身不能直连 provider

优先使用：

1. 全局 `SYSTEM_PROXY_URL`
2. OAuth 启动 / 重绑时指定单次代理

### OAuth 成功后为什么还会在站点管理看到一行站点

这是预期行为。Metapi 需要一个明确的站点记录来承载：

- 账号所属平台
- 路由与通道归属
- 后续重绑 / 刷新逻辑

它不代表你又新增了一个普通面板站点。

---

## 相关文档

- [上游接入](/upstream-integration)
- [管理 API](/management-api)
- [配置说明](/configuration)
- [常见问题 FAQ](/faq)
