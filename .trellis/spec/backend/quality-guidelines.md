# 后端质量规范

## TypeScript 与边界

仓库级 TypeScript 配置是严格模式（`tsconfig.json`）。服务端配置当前对遗留代码设置 `noImplicitAny: false`，因此新代码不得扩大 `any` 的使用；在不可信边界使用 `unknown`、显式的输入/输出类型和 type guard。路由、proxy-core、transformer、service 和数据库的所有权必须与 `AGENTS.md` 及架构测试保持一致。

## 必须遵循的模式

- 通过 `src/server/contracts/` 中的 Zod helper 解析外部 body。
- 通过 `executeEndpointFlow()` 和共享 proxy surface 处理 route endpoint fallback；surface/orchestration 收到 runtime `Response` 时，整包上游读取使用 `readRuntimeResponseText()`。
- 将平台 capability/discovery 行为放在声明式 registry/profile 层，不要散落 `if (platform === ...)` 分支。
- 不要假设所有 platform adapter 共享同一继承树：`OneApiAdapter` 与 `VeloeraAdapter` 当前直接继承 `BasePlatformAdapter`，`StandardApiProviderAdapterBase` 只覆盖其 provider 子类的 standard endpoint/default 行为。跨平台抽象必须用 header、quota、check-in、models/context cache 的参数化测试证明。
- 使用共享 insert/upsert/query helper，以及 `database-guidelines.md` 描述的 transaction 边界。
- 行为或所有权边界变化时，添加聚焦的回归测试或架构测试。架构测试是契约的一部分，不是可选的文档。

## 禁止或高风险模式

- 在 route adapter 中放业务逻辑、持久化、计费、retry 策略或 stream 生命周期。
- transformer 从 routes、Fastify、OAuth/token-router/runtime-dispatch module 导入。
- 在 db 层之外直接使用 `.returning()`/`lastInsertRowid`。
- 在 proxy-core surface 中直接使用 `.text()` 读取整包 runtime body（`responsesSseFinal.ts` 为无 `headers` 的最小测试 double 保留兼容分支；真实 `Response` 仍走 `readRuntimeResponseText()`）。
- 已有 helper 由 `routeRefreshWorkflow.ts`、`sharedSurface.ts`、`insertHelpers.ts` 或 transformer facade 拥有时，再实现一套平行版本。
- proxy log 从 local `logProxy` 迁移到共享 owner 时，必须保留 `downstreamPath`、`upstreamPath`、`usageSource`、billing/token 默认值、stream timing、warning scope 和 status/retry 语义。
- 记录 secret、cookie、authorization header 或完整 proxy body。
- 禁用失败测试、增加无界 retry，或在未更新对应 route contract 测试时更改 status code。

## 测试要求

使用 Vitest（`npm test`），测试与 source 相邻。当前可信的测试风格包括：

- Fastify `app.inject()` route test，使用隔离的临时 data directory；
- 重置/填充 Drizzle table 并断言状态转换的 service test；
- pure transformer/helper unit test；以及
- source-inspection 架构测试，例如 `src/server/routes/proxy/architecture-boundaries.test.ts` 和 `src/server/db/returning.architecture.test.ts`。

新增 route 至少覆盖 invalid payload、认证/授权、资源不存在、成功，以及相关的 conflict/rate-limit/background-job path。代理变更覆盖成功、失败/retry 和 stream closeout 路径。schema 变更运行 schema unit/parity/upgrade/runtime suite。

## 命令与门禁

包声明 Node `>=25.0.0`；即使旧贡献文档仍写 Node 20+，权威 build/typecheck 结果也应使用匹配运行时。

```bash
npm run typecheck:server
npm test
npm run repo:drift-check
npm run build:server
git diff --check
```

如果检查需要不可用的实时 MySQL/PostgreSQL 服务或不同 Node 版本，记录确切限制，不要称该门禁已通过。

## 评审清单

- 变更行为是否由正确层拥有？
- 是否复用了已有 contract、workflow 和失败词汇？
- 是否测试了所有输入/响应形状，包括错误 status code？
- retry、stream、cancellation 和 best-effort 副作用是否可观测？
- schema、migration、生成产物和 parity 测试是否同步？
- 是否保留 secret 脱敏，并避免新增 any/cast？
- 是否运行 `npm run repo:drift-check`、typecheck、tests 和 `git diff --check`？

## 场景：服务端边界简化的质量门

### 1. 适用范围与触发条件（Scope / Trigger）

- Trigger：把 route-local helper 移到 service、改变 proxy-core import 方向、或
  为跨层请求增加 cancellation/diagnostic contract 时适用。
- Scope：审查 route/service/proxy-core/transformer 的真实 owner、协议字段、
  HTTP status、best-effort side effect 和架构守卫；数据库 schema/migration
  不在没有单独批准时扩展。

### 2. 接口签名（Signatures）

- route：解析 `unknown` body/query，调用 service，映射既有 HTTP envelope。
- service：接受显式 typed options，返回 typed result 或具名错误；不依赖
  `FastifyReply` 来决定领域流程。
- proxy-core：从 `services/**`/`proxy-core/**` 导入共享策略、multipart、log
  owner；整包 upstream body 继续使用 `readRuntimeResponseText()`。
- 架构检查：`npm run repo:drift-check` 必须报告 zero violations，且已迁移
  debt 不得通过 allowlist 复活。

### 3. 契约（Contracts）

- 抽取前后保留 path、header、quota divisor、usageSource、billing/token 默认值、
  warning scope、stream timing、retry/health 和 status 语义。
- 失败分类沿用共享 vocabulary；network timeout、no-response、upstream error、
  业务 400/403/404/409 不得被 catch-all 改成 500 或 200。
- transformer 保持协议纯净，不能导入 route、Fastify、OAuth、token-router 或
  runtime dispatch；service 不能偷偷写 schema/migration。
- 兼容 facade 可以保留旧 import，但实现只能有一个中性 owner，并配套
  architecture test 防止新调用方继续依赖 facade。

### 4. 校验与错误矩阵（Validation & Error Matrix）

| 维度 | 必须验证 | 失败处理 |
| --- | --- | --- |
| 输入 parser | invalid/empty/unknown body 的 status/envelope | route 立即 400 |
| service result | success、resource missing、业务 conflict、network/timeout | 使用具名结果/错误映射，不猜字符串 |
| proxy stream | first byte、abort、reader close、retry、final status | 保留 stream closeout 和 health/log |
| proxy log | 一次写入、字段完整、insert failure best-effort | 不吞主请求失败，不重复记录 |
| import direction | proxy-core/transformer 无 route 依赖 | 修 owner，不加 debt allowlist |
| schema surface | 无 schema/migration/generated 变化 | 发现需求时另建任务并暂停 |

### 5. 正例、基线与反例（Good / Base / Bad Cases）

- Good：先用参数化 tests 证明 helper 抽取前后字段和错误等价，再删除旧实现；
  route 只留下 endpoint 选择与 response mapping。
- Base：OneApi/Veloera 与 proxy log 大规模统一若存在 header、quota、文案或
  时序差异，记录为暂缓并保留各自 owner，不为达到“零重复”强行合并。
- Bad：把所有平台或 endpoint 塞进一个 `any`/if-chain service，或仅凭 typecheck
  通过就宣称协议无回归。

### 6. 必需测试（Tests Required）

- service unit/table tests、route `app.inject()` status/envelope tests、proxy
  surface stream/whole-body/log tests、transformer purity tests。
- 每个新 boundary-heavy module 同目录 architecture test；运行 server
  typecheck、focused/full server tests、build、drift 和 diff check。
- 跨 web/server 变更还需运行 web tests/typecheck/build，报告 Node/native
  dependency 限制（例如 better-sqlite3 ABI）而不是隐藏失败。

### 7. 错误与正确对照（Wrong vs Correct）

#### 错误示例（Wrong）

```text
为消除重复，直接让 proxy-core import routes/proxy helper，并在 route/service
各记录一次 proxy log；测试只检查 HTTP 200。
```

#### 正确示例（Correct）

```text
把纯策略/解析移到 services，保留 route facade；由 shared owner 一次记录 log，
用 architecture + 参数化行为测试证明 import 方向、字段和 status 未漂移。
```
