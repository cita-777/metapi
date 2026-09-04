# 代码复用思考指南

> **用途**：在创建新函数、组件、常量、解析器或任务文档之前，先确认现有 owner 和重复模式，避免行为在不同层逐渐分叉。

## 核心原则

Metapi 的重复代码通常不是纯粹的行数问题，而是同一契约被多个位置重新解释。复制一段逻辑会让修复、错误分类、默认值和测试覆盖无法同步。复用的目标是让一个 owner 负责一个不变量，而不是为了减少文件数强行抽象。

## 编写前的搜索顺序

先在最窄的目录搜索，再扩大到整个仓库：

```bash
rg -n "函数名|字段名|错误词汇" src/server src/web
rg -n "formatUtcSqlDateTime|insertProxyLog|composeProxyLogMessage" src/server
rg -n "CenteredModal|MobileDrawer|ResponsiveFilterPanel|ResponsiveBatchActionBar" src/web
rg -n "fetch\\(|AbortController|setInterval|setTimeout" src/web
```

搜索后回答：

| 问题 | 处理方式 |
| --- | --- |
| 已经存在相同的 contract、parser 或 helper 吗？ | 扩展现有 owner，并让调用方共享其类型和测试。 |
| 相似实现是否有不同默认值或错误语义？ | 先记录差异，再决定参数化；不要把差异藏在一个模糊的 `boolean`。 |
| 逻辑是否跨越了当前层边界？ | 把 owner 移到中性目录，再由 route/page 保留薄适配器。 |
| 只使用一次且非常短吗？ | 可以保留局部实现，避免制造没有复用价值的 utility。 |
| 是否准备复制无类型 payload 的字段读取？ | 先建立 type guard、normalizer 或 projection，禁止第三个局部 cast。 |

## Metapi 中的 owner 选择

| 行为 | 首选 owner | 不应放置 |
| --- | --- | --- |
| 管理 API payload 解析 | `src/server/contracts/` 的 Zod parser | 每个 route 的局部 `as`/重复校验 |
| endpoint fallback、retry、响应体读取 | `src/server/proxy-core/orchestration/`、`executors/types.ts` | `src/server/routes/proxy/**` 的第二套流程 |
| channel/session、usage、billing 和 proxy log | `src/server/proxy-core/surfaces/sharedSurface.ts`、`src/server/services/proxyLogStore.ts` | 每个 endpoint 的 `logProxy` 副本 |
| 业务 workflow、平台差异、路由刷新 | `src/server/services/` | route adapter 或 transformer |
| 协议转换 | `src/server/transformers/` | Fastify、OAuth、token router 或 runtime dispatch |
| schema、migration、dialect 兼容 | `src/server/db/` 及生成器 | feature route 手写 DDL |
| 共享 UI 行为 | `src/web/components/`、`src/web/components/ui/` | 顶层 page 之间互相 import |
| 页面领域纯逻辑 | `src/web/pages/helpers/` 或 `pages/<domain>/` | 无主的全局 `utils/` 垃圾场 |
| 已认证 web 请求 | `src/web/api.ts` | 没有 owner 的页面级 HTTP client |
| Trellis 任务/会话/状态 | `.trellis/scripts/common/` 与 `.trellis/workflow.md` | 在 hook 里另造 status 字典 |

## 已调查的重复模式和正确处理

### 账号验证诊断

历史 `src/server/routes/api/accounts.ts` 同时存在 `diagnoseVerificationFailure` 和 `detectVerifyFailureReason`，都处理 Bearer/Cookie、`/api/user/self`、shield、`needs-user-id` 和 `invalid-user-id`。正确做法是让 `src/server/services/accountVerificationDiagnostics.ts` 拥有纯解析器、header variants 和网络结果 contract，route 只选择 `requireSiteApiBaseUrl()` 并映射既有 response。不要在 route 中保留第二个 parser，也不要因为两个调用点的 endpoint pool 不同就复制整段流程。

### Proxy log

`sharedSurface.ts` 的 `writeSurfaceProxyLog()` 已拥有 UTC 时间、`composeProxyLogMessage()`、`insertProxyLog()`、usageSource、billing、stream timing 和 best-effort warning。迁移 `completions`、`embeddings`、`images`、`search` 或 Gemini 前，逐字段比较 `downstreamPath`、`upstreamPath`、`usageSource`、token 默认值、warning scope 和 status/retry 语义；不能只把函数名改成 `recordProxyLog`。

### Downstream policy 与 multipart

若 helper 被 `proxy-core` 和多个 route 使用，它不应继续位于 `src/server/routes/proxy/`。将 request/auth 适配与纯策略计算拆开，放入 `src/server/services/` 或 `proxy-core` 的中性模块；route 下可以暂时保留兼容 facade，但 facade 不得重新拥有业务规则。

### UI 与异步请求

`CenteredModal`、`MobileDrawer`、`ModernSelect`、`ResponsiveFilterPanel` 和 `ResponsiveBatchActionBar` 是现有共享词汇。创建相似 modal、drawer、body-scroll lock 或 mobile action bar 前，先扩展它们或 `components/ui/` wrapper。请求生命周期可以由 `useAsyncResource` 这类窄 hook 统一，但页面仍拥有领域数据、partial failure 和 mutation invalidation。

## 何时参数化，何时拆分

适合参数化：

- 同一流程的输入/输出 contract 相同，只是平台 header、quota divisor、路径或文案不同；
- 差异可以用命名策略或配置表达，并能用 table-driven test 锁定；
- 抽象不会把不支持的 capability 伪装成支持。

适合拆分：

- 一个函数同时负责 request adapter、业务 workflow、持久化和用户响应；
- 两个调用点虽然名字相同，但失败词汇、状态码或生命周期不同；
- 页面出现第二个复杂 modal/drawer/panel family；
- helper 需要导入它不应依赖的层。

不要为了“统一”把 `OneApiAdapter`、`VeloeraAdapter` 强行改成同一继承树：当前二者都直接继承 `BasePlatformAdapter`，而 `StandardApiProviderAdapterBase` 只覆盖 standard models/unsupported defaults。先抽取中性策略，再以参数化测试证明差异没有被吞掉。

## Payload、事件和 reducer

当两个以上消费者读取同一个 `unknown` JSON、SSE、JSONL 或配置字段时：

1. 在边界定义 variant/type guard；
2. 在 owner 处完成归一化和默认值；
3. 导出 typed projection 给 UI、command 或统计；
4. 让 replay/reducer 只接受已判别的 event，不在展示层重新 cast。

例如 proxy event 的 `seq`、`id`、`version` 必须由 writer 分配，filter/reducer 使用同一字段；不能让每个 consumer 自己维护 cursor。

## 批量修改后的复核

- 再次用 `rg` 搜索旧函数名、旧 import 和旧字段读取，确认没有漏迁移。
- 比较迁移前后默认值、错误 status、日志字段、取消和 cleanup；“编译通过”不等于语义相同。
- 为新的边界增加相邻的 `*.architecture.test.ts` 或参数化测试。
- 运行 `npm run repo:drift-check`，并把仍保留的兼容 facade/allowlist 写进任务研究记录，而不是隐式放过。

## Trellis 文档和 manifest 也遵循单一来源

- `.trellis/workflow.md` 的 `[workflow-state:STATUS]` body 是 breadcrumb 的唯一自然语言来源；hook 只解析，不复制另一套 status 文案。
- `implement.jsonl`/`check.jsonl` 只登记 spec/research 文件；代码由 agent 按任务 diff 自行读取。
- `_example` seed 行不算真实 manifest entry；新增理由使用简体中文，JSON key、路径和 status 值保持原文。

## 提交前清单

- [ ] 已搜索相似函数、常量、字段、组件和错误词汇。
- [ ] 已确认一个明确的 owner，或记录为什么局部实现更安全。
- [ ] 没有复制 route/proxy、page/page、transformer 或 UI primitive 的业务逻辑。
- [ ] 无类型 payload 的读取集中在 shared decoder/type guard 外，没有新增 local cast。
- [ ] 平台差异通过显式策略和参数化测试表达，没有默认 capability fallthrough。
- [ ] timer、listener、stream、body lock 和异步 request 的 cleanup 仍由一个 owner 负责。
- [ ] 已运行相关 focused tests、typecheck、`npm run repo:drift-check` 和 `git diff --check`。
