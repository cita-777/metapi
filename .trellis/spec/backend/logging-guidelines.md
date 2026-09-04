# 后端日志规范

## 日志面

`src/server/config.ts` 中的 `buildFastifyOptions()` 启用 Fastify 内置 logger（`logger: true`）和 `trustProxy`。请求范围的路由失败应优先使用带结构化字段的 `request.log`，OAuth 路由中的下例可作为参考：

```ts
request.log.error({ err: error }, 'oauth import failed');
```

长时间运行的 scheduler、启动、兼容修复和 best-effort service 工作目前使用仓库统一的 `console` 约定，并带稳定前缀，例如 `[Scheduler]`、`[db]`、`[proxy-log-retention]` 或 `[channel-recovery-probe]`。应保持这种区分：如果 request handler 可以使用 `request.log`，不要在其中另造 logger 或打印临时诊断。

## 日志级别

- `info`/`console.log`：成功启动、定时任务边界和简短完成汇总（`checkinScheduler.ts`、`src/server/index.ts`）。
- `warn`：非致命恢复、兼容 fallback、跳过的 cleanup 或 best-effort telemetry 失败。包含 subsystem 前缀和安全标识符。
- `error`：无法恢复的请求失败、失败的 scheduler pass 或需要运维介入的数据库/启动错误。请求范围使用 `request.log.error({ err }, message)`，后台代码使用带前缀的 `console.error`。
- debug 级输出不是常规生产约定。请求需要详细且 opt-in 的诊断时，使用持久化的 proxy-debug trace 能力（`proxyDebugTraceRuntime.ts`）。

## 消息形状与上下文

优先使用简短、稳定的 subsystem 前缀，以及有助于关联失败的事实：account/site/channel ID、在安全情况下的 model 名、HTTP status、retry 次数、latency 和 operation 名。代理可观测性应通过 `proxyLogStore.ts` 与 `proxyDebugTraceRuntime.ts` 写入结构化的 `proxy_logs`/`proxy_debug_traces` store，不要倾倒巨型 console dump。

使用 `proxyLogMessage.ts` 中的 `composeProxyLogMessage()`，保留下游 client/session/trace metadata 和 usage source。复用现有 trace/session 字段，不要另造一次性的 correlation 格式。

## 应记录什么

日志应足以回答：

- 哪个 subsystem 和 operation 执行了；
- 执行是成功、跳过、retry 还是 fallback；
- 安全的资源标识符和上游 status/error 摘要是什么；以及
- 如果会影响操作，cleanup/rebuild 的数量或耗时是多少。

示例包括 `checkinScheduler.ts` 的 scheduler count、`siteApiEndpointService.ts` 的 endpoint health warning，以及 `proxyFileRetentionService.ts`/`proxyLogRetentionService.ts` 的 retention count。

## 不应记录什么

绝不要记录原始 admin/proxy/API token、OAuth access/refresh token、SMTP password、cookie、authorization header、包含凭据的完整 database URL，或无界的 request/response body。不要把 `proxyDebug` body/header capture 设置复制到普通日志；这些 capture 是显式 opt-in 的，并且受运行时大小限制。

运维人员需要查看凭据相关值时，使用掩码或布尔/状态汇总。`src/server/routes/api/auth.ts` 只返回供显示的四加四掩码 token，settings route 使用 `maskSecret()`/`maskConnectionString()` 模式。

## 错误上下文与脱敏

如果任意 error object 可能携带请求 metadata，不要直接把它 stringify 到 response 或 log。将其作为结构化 `err` 字段传给 Pino/Fastify，让框架格式化 stack；另外单独为客户端选择安全 message。对于上游 body，使用 `summarizeUpstreamError()`，使 HTML/JSON 紧凑化并截断长文本。

后台任务可以在 warning 后继续运行；warning 不能用来掩盖失败的主操作。当 UI 需要展示重要 warning 时，配合持久化 event 或 status 字段。
