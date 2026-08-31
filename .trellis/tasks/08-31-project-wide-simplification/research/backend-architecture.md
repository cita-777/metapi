# Metapi 后端架构调查

## 查询元数据

- **查询**：调查 Fastify route、proxy-core、service、transformer、contract、database 和 platform adapter 的真实所有权，核对重复诊断、proxy log 及 drift debt。
- **范围**：`src/server/index.ts`、`src/server/routes/**`、`src/server/proxy-core/**`、`src/server/services/**`、`src/server/transformers/**`、`src/server/contracts/**`、`src/server/db/**`、相关测试与 `scripts/dev/repo-drift-check.ts`。
- **日期**：2026-08-31。

## 可复现命令

```bash
find src/server -maxdepth 2 -type d | sort
rg -n 'executeEndpointFlow|sharedSurface|readRuntimeResponseText' src/server/routes src/server/proxy-core
rg -n 'class .*Adapter|extends StandardApiProviderAdapterBase|extends BasePlatformAdapter' src/server/services/platforms
rg -n '500000|1000000|Veloera-User|New-API-User|User-id|available_model' src/server/services src/server/routes
rg -n 'diagnoseVerificationFailure|detectVerifyFailureReason|accountVerificationDiagnostics' src/server/routes/api/accounts.ts src/server/services
rg -n 'writeSurfaceProxyLog|logProxy|insertProxyLog|composeProxyLogMessage' src/server/routes/proxy src/server/proxy-core/surfaces
rg -n 'sqliteTable\\(|switchRuntimeDatabase|RuntimeDbDialect' src/server/db src/server/index.ts
npm run repo:drift-check
```

## 真实层次和启动编排

```text
src/server/routes/api/**       管理 API Fastify adapter
src/server/routes/proxy/**     /v1 与供应商兼容 endpoint adapter/facade
src/server/proxy-core/**       endpoint flow、surface、executor、provider、runtime
src/server/services/**         业务 workflow、平台 adapter、OAuth、日志、路由
src/server/transformers/**     协议纯净转换
src/server/contracts/**        Zod 外部 payload parser
src/server/db/**               schema、连接、迁移、runtime dialect、兼容处理
```

`src/server/index.ts:135-260` 在创建 Fastify 前确保 runtime DB、读取 settings、切换 dialect、执行 compatibility columns、backfill、route rebuild 和 OAuth registry；随后注册 auth hook、管理 API、proxy routes、静态 web 与 SPA fallback。它是启动/生命周期 owner，不是把 scheduler 或业务流程塞进 route 的理由。

## Route、core、service 和 transformer 规则

- route 文件可以注册 Fastify endpoint、读取 request context、调用 service/surface 和组装 HTTP response；不能拥有 retry policy、stream lifecycle、billing 或 persistence。
- endpoint fallback 必须通过 `src/server/proxy-core/orchestration/endpointFlow.ts` 的 `executeEndpointFlow()`；`src/server/routes/proxy/endpointFlow.ts` 只是兼容 re-export。
- `src/server/proxy-core/surfaces/sharedSurface.ts:239-300` 拥有共享 channel/session 记账、usage、billing、proxy log 和 failure toolkit；整包上游 body 读取通过 `src/server/proxy-core/executors/types.ts` 的 `readRuntimeResponseText()`。
- `src/server/transformers/` 不得导入 route、Fastify、OAuth service、token router 或 runtime dispatch；协议转换应可独立测试。
- 外部 request body 在 `src/server/contracts/` 用 Zod parser 归一化，route 只处理 parser 的结果和 HTTP status。

## Platform adapter 继承与差异（纠正旧任务文档）

真实继承关系：

```text
StandardApiProviderAdapterBase（standardApiProvider.ts）
  ├─ ClaudeAdapter
  ├─ GeminiAdapter
  ├─ OpenAiAdapter
  ├─ OrcaRouterAdapter
  └─ CliProxyApiAdapter

BasePlatformAdapter（base.ts）
  ├─ OneApiAdapter（oneApi.ts）
  │    └─ OneHubAdapter
  │         └─ DoneHubAdapter
  ├─ VeloeraAdapter（veloera.ts）
  ├─ NewApiAdapter
  ├─ Sub2ApiAdapter
  └─ 其他平台
```

`OneApiAdapter` 与 `VeloeraAdapter` 都直接继承 `BasePlatformAdapter`（分别见 `oneApi.ts:1,19`、`veloera.ts:1,8`），不是 `StandardApiProviderAdapterBase` 的子类。因此不能在设计或 PRD 中写“通过 StandardApiProviderAdapterBase 合并 OneApi/Veloera”，除非先完成独立的中性策略抽取并证明兼容。

已经由源码和测试锁定的差异：

| 平台 | 代码证据 | 语义 |
| --- | --- | --- |
| OneApi | `oneApi.ts:57-81` | check-in `/api/user/checkin`；quota/used/today 字段除以 `500000`；models 从 `/v1/models` 读取并写入 context-length cache |
| Veloera | `veloera.ts:23-58` | headers 可能同时带 `Veloera-User`、`New-API-User`、`User-id`；quota/used/today 除以 `1000000`；models 流程相似但 header contract 不同 |
| OneHub | `oneHub.ts:12-39` | 先 `/v1/models`，失败后 `/api/available_model`；user group 从 `/api/user_group_map` 读取 |
| DoneHub | `doneHub.ts:12-33`、测试 `doneHub.test.ts:78-105` | check-in 明确不支持；`quota` 是 remaining，`used_quota` 是 spent，total 为两者之和；继承 OneHub 的 model fallback |

可行方向是中性策略/config/helper + 参数化测试，不是强行改继承树。`StandardApiProviderAdapterBase` 当前只拥有 standard models URL、unsupported login/check-in/zero-balance defaults（`standardApiProvider.ts:37-97`）。

## 账号验证诊断

HEAD `accounts.ts` 同时有 `diagnoseVerificationFailure` 和 `detectVerifyFailureReason` 两套局部实现（`git show HEAD:src/server/routes/api/accounts.ts` 可复现，约 721-861、966-1055 行）：两者都生成 Bearer/Cookie variants，访问 `/api/user/self`，解析 shield、`needs-user-id`/`invalid-user-id`，并使用 2,500ms 诊断 timeout；差异在 endpoint pool 和网络错误可见性。

当前工作树新增候选 `src/server/services/accountVerificationDiagnostics.ts`：

- `parseAccountVerificationFailureReason()` 负责纯文本/JSON/shield/user-id 分类（约 105-147 行）；
- `buildAccountVerificationHeaderVariants()` 固定 Bearer/Cookie 顺序（约 153-190 行）；
- `diagnoseAccountVerificationFailure()` 返回 `reason`、`sawResponse`、`sawNetworkError`、`status`、`endpoint`、`timedOut`、`retryable`（约 215-278 行）。

当前 route 已通过 `requireSiteApiBaseUrl(site)` 选择 endpoint，再注入 `withSiteRecordProxyRequestInit`；这是未提交 WIP，必须经过 accounts verify/rebind focused tests 和 architecture test 才能写成完成。

## Proxy log 所有权和剩余重复

- 共享 owner `writeSurfaceProxyLog()` 位于 `sharedSurface.ts:239-300`，统一 UTC 时间、`composeProxyLogMessage()`、`insertProxyLog()`、usageSource、billing、stream timing、client/session/trace metadata 和 best-effort warning。
- `sharedSurface.ts` 已被 chat、rerank 等 surface 使用，但 `routes/proxy/completions.ts`、`embeddings.ts`、`images.ts`、`search.ts` 以及 `proxy-core/surfaces/geminiSurface.ts` 仍有 local `logProxy`。迁移前必须逐个对照 `downstreamPath`、`upstreamPath`、`usageSource`、billing 默认值、stream timing、token 默认值、warning scope、status/retry 语义；不能只做名称替换。
- 当前候选中性 service/facade 为 `downstreamPolicyService.ts`、`multipart.ts`，并有 `shared-helper-boundaries.architecture.test.ts`；它们已让当前 drift checker 结果为 0/0，但仍未提交、未完成完整产品回归。

## Drift 与 page boundary

当前 checker 的 `HEAD` 归档有五条违规：四条 `proxy-core -> routes/proxy`（downstreamPolicy/multipart）和一条 `src/web/pages/Accounts.tsx -> ./Tokens.js`。当前工作树通过中性 service/facade 与 `pages/tokens/` 候选迁移暂时消除这些路径；历史 checker 曾把它们记成 tracked debt。任务材料必须同时写清 checker 版本和扫描对象。

## 数据库与测试边界

- `src/server/db/schema.ts` 有 27 个 `sqliteTable`，`drizzle/` 有 29 个 SQL 文件；`src/server/db/index.ts` 支持 SQLite/MySQL/PostgreSQL runtime switch。
- 本轮不改 schema/migration/generated artifacts；schema 需求必须单独建任务并同步 Drizzle schema、migration history、generated contract/parity 测试。
- 相关验证应覆盖 `src/server/routes/api/accounts*`、`src/server/services/platforms`、`src/server/proxy-core/surfaces`、`src/server/routes/proxy` 的 focused tests、`npm run typecheck:server`、`npm run build:server`、`npm run repo:drift-check` 和 `git diff --check`。Node/native ABI 不匹配时必须精确记录，不能隐藏失败。

## 反模式

- 不把 route 变成 workflow owner，不在 transformer 中引入 runtime/service，不在 proxy-core 中直接从 routes/proxy 取 helper。
- 不复制平台 quota/header/check-in 逻辑，也不把不兼容平台伪装成统一 capability。
- 不在 log migration 中丢失 path/usage/billing/trace 字段，不把 best-effort telemetry 失败变成主请求成功。
