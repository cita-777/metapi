# 🔌 客户端接入

本文档说明如何将下游客户端连接到 Metapi 代理网关。

[返回文档中心](./README.md)

---

## 通用配置

Metapi 暴露标准 OpenAI / Claude 兼容接口，下游客户端通常只需配置两项：

| 配置项 | 值 |
|--------|-----|
| **Base URL** | 按客户端字段行为填写：会自动补 `/v1` 的字段填 `https://your-domain.com`；要求完整 API URL 的字段填 `https://your-domain.com/v1` |
| **API Key** | 你设置的 `PROXY_TOKEN` 值，或创建的[下游 API Key](./configuration.md#下游-api-key-策略) |

模型列表自动从 `GET /v1/models` 获取，无需手动配置。

> [!TIP]
> 如果不确定客户端是否自动补 `/v1`，先试根域名，报 404 再改成带 `/v1` 的完整路径。

## 支持的接口

| 接口 | 方法 | 说明 |
|------|------|------|
| `/v1/responses` | POST | OpenAI Responses |
| `/v1/chat/completions` | POST | OpenAI Chat Completions |
| `/v1/messages` | POST | Claude Messages |
| `/v1/completions` | POST | OpenAI Completions（Legacy） |
| `/v1/embeddings` | POST | 向量嵌入 |
| `/v1/files` | POST / GET | OpenAI Files 上传与列举 |
| `/v1/files/:fileId` | GET / DELETE | OpenAI Files 读取元信息与删除 |
| `/v1/files/:fileId/content` | GET | OpenAI Files 原始内容读取 |
| `/v1/images/generations` | POST | 图像生成 |
| `/v1/models` | GET | 模型列表 |

### 图像生成

`POST /v1/images/generations` 遵循 OpenAI Images API 的 JSON 请求格式。`prompt` 为必填字段，`model` 未填写时使用 `gpt-image-1`；其余图像参数（例如 `size`、`quality`、`background` 和 `output_format`）会随请求透传到实际选中的上游模型。

```bash
curl https://your-domain.com/v1/images/generations \
  -H "Authorization: Bearer $PROXY_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-image-1","prompt":"一只戴着太空头盔的橘猫","size":"1024x1024"}'
```

响应保持标准 `{ "created": ..., "data": [...] }` 结构，其中 `data` 项至少包含 `url` 或 `b64_json`。如果上游返回成功状态但没有图像数据，网关会将其视为异常并按渠道策略重试，避免客户端收到无法使用的空结果。

## 已验证兼容的客户端

### ChatGPT-Next-Web

| 配置项 | 值 |
|--------|-----|
| Settings → Custom Endpoint | `https://your-domain.com`（该字段会自动访问 `/v1/*`） |
| API Key | `PROXY_TOKEN` |

### Open WebUI

| 配置项 | 值 |
|--------|-----|
| Settings → Connections → OpenAI API URL | `https://your-domain.com/v1` |
| API Key | `PROXY_TOKEN` |

### Cherry Studio

| 配置项 | 值 |
|--------|-----|
| 模型提供商 → OpenAI → API 地址 | `https://your-domain.com/v1` |
| API Key | `PROXY_TOKEN` |

> 说明：Metapi 现在支持标准 OpenAI `/v1/files` 文件链路。  
> Cherry Studio、Open WebUI 等客户端如果通过标准 OpenAI Files + `Responses` / Chat 文件块发送 PDF、Markdown、JSON、图片、音频附件，即可经由 Metapi 转发。  
> 如果某个客户端版本仍使用私有附件协议而不是标准 `/v1/files`，则仍需单独适配。

### Cursor

| 配置项 | 值 |
|--------|-----|
| Settings → Models → OpenAI API Key | `PROXY_TOKEN` |
| Override OpenAI Base URL | `https://your-domain.com/v1` |

### Claude Code

在 `~/.claude/settings.json` 中配置：

```json
{
  "env": {
    "ANTHROPIC_BASE_URL": "https://your-domain.com",
    "ANTHROPIC_API_KEY": "your-proxy-sk-token",
    "ANTHROPIC_AUTH_TOKEN": "your-proxy-sk-token",
    "CLAUDE_CODE_ATTRIBUTION_HEADER": "0",
    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1"
  }
}
```

**环境变量说明：**

| 变量 | 作用 |
|------|------|
| `ANTHROPIC_BASE_URL` | 指向 Metapi 的根域名，Claude Code 会自动拼接 `/v1/messages` |
| `ANTHROPIC_API_KEY` | 认证令牌，填 `PROXY_TOKEN` 值 |
| `ANTHROPIC_AUTH_TOKEN` | 部分版本读取此变量而非 `ANTHROPIC_API_KEY`，建议两个都设 |
| `CLAUDE_CODE_ATTRIBUTION_HEADER` | 设为 `0` 禁用 Attribution 头，避免部分上游不支持该头导致报错 |
| `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC` | 设为 `1` 减少非必要请求（遥测等），降低 Token 消耗 |

> [!IMPORTANT]
> `ANTHROPIC_BASE_URL` 填根域名即可，**不要**手动拼接 `/v1`。
> 上述变量由 Claude Code 客户端读取，属于客户端行为开关；Metapi 服务端只能处理已经发来的请求。

### Codex CLI

`~/.codex/config.toml`

```toml
model = "gpt-5"
model_provider = "metapi"

[model_providers.metapi]
name = "metapi"
base_url = "https://your-domain.com/v1"
```

`~/.codex/auth.json`

```json
{
  "OPENAI_API_KEY": "your-proxy-sk-token"
}
```

> 提示：`model` 需要是你在 Metapi `GET /v1/models` 可见的模型名。

### Roo Code / Kilo Code

配置方式与 Cursor 类似，在设置中填入 `https://your-domain.com/v1` 和 API Key。

### 其他客户端

所有支持 OpenAI API 格式的客户端均可接入，只需找到 Base URL 和 API Key 的配置位置即可：

| 你的客户端... | 填法 |
|--------------|------|
| 有 "Base URL" 字段，会自动补 `/v1` | 填 `https://your-domain.com` |
| 有 "OpenAI API URL" 字段，要求完整路径 | 填 `https://your-domain.com/v1` |
| 有 "Anthropic" 选项 | 填 `https://your-domain.com`，Metapi 自动处理 `/v1/messages` |
| 只能填 API Key | 填 `PROXY_TOKEN` 值即可 |

> [!TIP]
> 不确定选哪种？先用 `/v1/models` 测试连通性，再配置模型。

## 下游 API Key 策略

除了全局 `PROXY_TOKEN`，你还可以创建多个项目级下游 Key，每个 Key 可独立配置过期时间、费用/请求上限、模型白名单、路由白名单和站点倍率，适用于多团队/多项目共用一个 Metapi 实例的场景。

详细字段说明见 [配置说明 → 下游 API Key 策略](./configuration.md#下游-api-key-策略)。

---

## 快速自检

部署完成后，用以下命令验证链路：

```bash
# 1. 检查模型列表
curl -sS https://your-domain.com/v1/models \
  -H "Authorization: Bearer <PROXY_TOKEN>" | head -50

# 2. 测试对话（非流式）
curl -sS https://your-domain.com/v1/chat/completions \
  -H "Authorization: Bearer <PROXY_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}'

# 3. 测试文件上传
curl -sS https://your-domain.com/v1/files \
  -H "Authorization: Bearer <PROXY_TOKEN>" \
  -F "purpose=assistants" \
  -F "file=@./sample.pdf"

# 4. 测试流式
curl -sS https://your-domain.com/v1/chat/completions \
  -H "Authorization: Bearer <PROXY_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}],"stream":true}'
```

## 常见问题

遇到流式响应异常、模型列表为空、客户端提示 401/403 等问题，请参阅 [常见问题 FAQ](./faq.md)。

## 下一步

- [配置说明](./configuration.md) — 环境变量详解与下游 API Key 策略
- [上游接入](./upstream-integration.md) — 添加和管理上游平台
- [运维手册](./operations.md) — 日志排查与健康检查
- [常见问题](./faq.md) — 更多故障排查
