# 后端错误处理规范

## 边界校验

在路由边界将 Fastify request body 和 query value 视为 `unknown`。使用 `src/server/contracts/` 中匹配的 Zod helper 解析；解析失败时立即返回 400。parser 会把缺失 body 归一化为 `{}`，并返回稳定、可读的错误信息，`parseSiteCreatePayload()` 和 `parseRuntimeSettingsPayload()` 展示了这种模式。

```ts
const parsedBody = parseSiteCreatePayload(request.body);
if (!parsedBody.success) {
  return reply.code(400).send({ success: false, message: parsedBody.error });
}
const body = parsedBody.data;
```

解析后再执行领域校验（例如 `src/server/routes/api/sites.ts` 中的 URL 归一化或重复检测），并显式设置响应状态。

## 错误类型与传播

当 service 需要跨边界携带 HTTP 语义时，使用具名错误类。`src/server/services/proxyInputFileResolver.ts` 中的 `ProxyInputFileResolutionError` 携带 `statusCode` 和协议形态的 `payload`；`accountManualModelService.ts` 中的 `AccountManualModelServiceError` 为账号不存在携带 `statusCode`。路由应识别这些字段/类，并发送预期的 status 和 payload，不能把客户端错误变成通用 500。

对于上游代理失败，保留共享失败词汇和流程：

- `proxy-core/orchestration/endpointFlow.ts` 中的 `executeEndpointFlow()` 拥有 endpoint 尝试、恢复、降级和最终状态选择。
- `proxy-core/orchestration/upstreamRequest.ts` 中的 `summarizeUpstreamError()` 提取有用的 JSON/HTML 文本，并截断任意 body。
- 对整包上游读取（包括压缩响应），必须使用 `proxy-core/executors/types.ts` 中的 `readRuntimeResponseText()`。
- `sharedSurface.ts` 记录 channel health、retry/failure 状态、usage 和 proxy log；endpoint route 文件不得重复这套记账。

账号验证诊断的失败分类（`needs-user-id`、`invalid-user-id`、`shield-blocked`、network/no-response）应由 `src/server/services/accountVerificationDiagnostics.ts` 的纯 parser/service 统一拥有；route 可以选择 `requireSiteApiBaseUrl()` 的 endpoint pool 并映射既有 HTTP response，但不得恢复第二套 Bearer/Cookie probe 或把 timeout 静默变成 unknown。

## Catch 与尽力而为工作

在能够补充上下文或选择恢复动作的层捕获错误。返回或重新抛出主失败；非关键 telemetry、event、cleanup 或 route-rebuild 工作放进 best-effort helper。现有示例包括 proxy route 中的 `recordTokenRouterEventBestEffort()` 调用，以及 `proxyLogStore.ts` 调用方受保护的 proxy-log 写入。不要为了让请求看起来成功而静默吞掉主数据库或上游操作的失败。

批量操作可能部分成功时，返回逐项结果和汇总。`src/server/services/accountMutationWorkflow.ts` 中的 `refreshAccountCoverageBatch()` 使用 `Promise.allSettled()`，把 refresh 失败与 route-rebuild 失败分开报告。

## HTTP 响应约定

历史 endpoint 并不存在一个统一 envelope；应保持各 endpoint family 的本地形状：

| 情况 | 当前响应形状 |
| --- | --- |
| 管理员凭据缺失/无效 | 来自 `middleware/auth.ts` 的 `401`/`403`，body 为 `{ error: string }` |
| 管理 payload 无效 | `400`，body 为 `{ success: false, message }` 或 `{ message }` |
| 资源不存在 | `404`，使用资源专属 message；参见 `tasks.ts` 和 `downstreamApiKeys.ts` |
| 唯一性/业务冲突 | `409`；sites 使用 `sendSiteBindingConflict()` |
| 限流 | `429`、`Retry-After` 和来自 `requestRateLimit.ts` 的 message |
| 已接受的后台任务 | `202`，body 为 job/status object；参见 `checkin.ts`、`test.ts` 和 `updateCenter.ts` |
| 代理/上游失败 | `{ error: { message, type: 'upstream_error' } }`，使用选定 status |

代理路由应保持协议 error type（`invalid_request_error`、`not_found_error`、`upstream_error`）不变，以便 OpenAI/Claude 兼容客户端正确解释。

## 日志与安全

记录归一化后的错误和相关标识符，不记录原始凭据、cookie、authorization header 或 request body。遵循 `logging-guidelines.md`。返回给客户端的错误应可行动，但不得暴露连接字符串、access token 或内部 stack trace。

## 常见失败模式

- 捕获上游请求失败后仍返回 HTTP 200。
- 路由自行 retry，却没有更新 channel health 或 proxy log。
- 在 proxy-core 中直接读取 `response.text()`，导致丢失解压处理。
- parser/domain 错误本应返回 400/404/409，却被转换为通用 500。
- 每层重复记录同一个错误，却没有增加上下文。

## 场景：账号验证诊断与中性 helper owner

### 1. 适用范围与触发条件（Scope / Trigger）

- Trigger：账号 verify/rebind 需要解释上游失败，或 proxy-core 需要复用
  downstream policy/multipart helper 时适用。
- Scope：route 负责 Fastify 输入、endpoint pool 选择和 HTTP response mapping；
  `services/**` 负责纯分类、请求候选和可复用适配；proxy-core 不依赖
  `routes/proxy/**`。

### 2. 接口签名（Signatures）

```ts
type AccountVerificationDiagnosticOptions = {
  baseUrl: string;
  accessToken: string;
  platformUserId?: number;
  skipRawShieldDetection?: boolean;
  timeoutMs?: number;
  requestInit?: (headers: Record<string, string>, signal: AbortSignal) => RequestInit;
};

type AccountVerificationDiagnosticResult = {
  reason: 'needs-user-id' | 'invalid-user-id' | 'shield-blocked' | null;
  sawResponse: boolean;
  sawNetworkError: boolean;
  status: number | null;
  endpoint: string | null;
  timedOut: boolean;
  retryable: boolean;
};
```

实现位于 `src/server/services/accountVerificationDiagnostics.ts`；
`getDownstreamRoutingPolicy`、`ensureModelAllowedForDownstreamKey`、
`recordDownstreamCostUsage` 和 multipart parser 位于 services owner，旧
`routes/proxy/*` 只能保留兼容 re-export。

### 3. 契约（Contracts）

- 诊断按 Bearer-first、Cookie candidate 顺序请求 `${baseUrl}/api/user/self`；
  `New-Api-User`、shield 检测、timeout 和 request proxy override 的语义必须
  与现有 verify route 一致。
- 诊断结果可以表达所有候选均无响应的 `sawNetworkError && !sawResponse`，
  但 route 仍映射原有业务 envelope，不把网络 timeout 伪装成新的 HTTP contract。
- `needs-user-id`、`invalid-user-id`、`shield-blocked` 只能由 service parser
  产生；route 不得恢复第二套 JSON/HTML 文本匹配。
- policy helper 保留无 auth context 时的 empty policy/allow 语义，拒绝时仍返回
  `403` 和 `permission_error`；multipart parser 保留 buffer、FormData、文件
  override 行为。
- service 不直接写数据库、发送 Fastify response 或改变 proxy 协议；共享
  helper 的 import 方向只能是 route → service 或 proxy-core → service。

### 4. 校验与错误矩阵（Validation & Error Matrix）

| 条件 | service 行为 | route 行为 |
| --- | --- | --- |
| HTML challenge 且未跳过 shield 检测 | `shield-blocked` | 现有 shield payload |
| message 指示缺失 user id | `needs-user-id` | `needsUserId=true` |
| message 指示 mismatch/invalid user id | `invalid-user-id` | `invalidUserId=true` |
| 所有候选网络失败且无 response | `timedOut=true,retryable=true` | 保留原 generic verification failure/hint |
| 至少一次有 response 但无法分类 | `reason=null,timedOut=false` | 保留原 generic failure |
| endpoint pool 选择失败 | route best-effort 回 generic | 不发起第二套 probe |
| managed key 模型被拒 | service helper 返回 false | `403 permission_error` |

### 5. 正例、基线与反例（Good / Base / Bad Cases）

- Good：route 先用 `requireSiteApiBaseUrl(site)` 选 base URL，再把 token、user id
  和 `withSiteRecordProxyRequestInit` 传给 service，最后只映射 `reason`。
- Base：保留 `routes/proxy/downstreamPolicy.ts` 和 `multipart.ts` 的 re-export，
  让旧 route import 平滑迁移，同时 drift guard 禁止 proxy-core 新增旧路径。
- Bad：在 route 中复制 `undici.fetch`、header variants 或 shield regex，或让
  service 直接调用 `reply.send`；这会造成错误词汇和 owner 漂移。

### 6. 必需测试（Tests Required）

- parser table tests：shield HTML/JSON、needs/invalid user id、skip shield、
  malformed/unknown body。
- service tests：header 顺序、endpoint normalization、all-network timeout、
  mixed response/network、status 和 retryable flags。
- route tests：现有 verify/rebind 的 400/成功/generic/shield/user-id envelope
  不变；policy 403 和 multipart file/override 行为不变。
- architecture tests：service 不 import route/db/Fastify response；proxy-core 不
  import `routes/proxy`; facade 只做 re-export。

### 7. 错误与正确对照（Wrong vs Correct）

#### 错误示例（Wrong）

```ts
// route adapter 再次拥有 probe、文本分类和 timeout
const response = await fetch(`${site.url}/api/user/self`, { headers });
if (responseText.includes('captcha')) return reply.send(...);
```

#### 正确示例（Correct）

```ts
const diagnostic = await diagnoseAccountVerificationFailure({
  baseUrl: diagnosticBaseUrl,
  accessToken,
  platformUserId: parsedPlatformUserId,
  requestInit: (headers, signal) => withSiteRecordProxyRequestInit(site, { headers, signal }),
});
return buildVerificationFailureResponse(diagnostic.reason) ?? genericFailure;
```
