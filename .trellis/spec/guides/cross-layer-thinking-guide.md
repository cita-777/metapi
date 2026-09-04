# 跨层思考指南

> **用途**：在修改 API、代理、页面、数据库或 Trellis runtime 之前，画出真实数据流，明确每一条边界的输入、输出、错误和生命周期 owner。

## 先画数据流，再改代码

最小模板：

```text
外部输入 → adapter/parser → service/workflow → store/runtime → response/stream → consumer
```

对每条箭头记录四件事：

1. 输入的实际类型和可信度；
2. 是否发生格式、单位、默认值或身份转换；
3. 失败如何分类、谁负责重试、谁负责记录；
4. 请求、stream、timer、transaction 或 body 的结束条件。

## Metapi 边界矩阵

| 边界 | 真实 owner | 必须确认 |
| --- | --- | --- |
| 管理 route ↔ service | `src/server/routes/api/**` ↔ `src/server/services/**` | route 只适配；service 返回具名错误/结构化结果；HTTP status 由 route 映射 |
| proxy route ↔ proxy-core | `routes/proxy/**` ↔ `proxy-core/orchestration/**` | endpoint fallback 经过 `executeEndpointFlow()`；流式和整包路径都保留 |
| proxy-core ↔ upstream runtime | `executors/types.ts`、`runtimeDispatch.ts` | 整包 body 用 `readRuntimeResponseText()`；首字节、abort、retry 和 status 不被吞掉 |
| proxy surface ↔ log/store | `sharedSurface.ts` ↔ `proxyLogStore.ts` | path、usageSource、billing、client/session/trace、stream timing 字段一致 |
| transformer ↔ protocol | `transformers/**` | 只处理协议形状；不导入 Fastify、route、OAuth、token router 或 runtime dispatch |
| service ↔ database | `services/**` ↔ `db/**` | schema/migration/generated contract 同步；transaction 提交后再做外部副作用 |
| web page ↔ API | `pages/**` ↔ `src/web/api.ts` | auth、timeout、error extraction、AbortSignal 和 body 生命周期清晰 |
| web page ↔ browser-only API | `App.tsx`/`Sites.tsx`/`api.ts` | raw `fetch()` 必须有 owner、原因、认证/超时/取消/测试边界 |
| Trellis writer ↔ hook parser | `workflow.md`、`task.py`、`.codex/hooks/**` | machine key/status/path 不变；自然语言可本地化；缺失输入 fail closed |

## 典型管理 API 流程

```text
Fastify request.body/query (unknown)
  → src/server/contracts/*.ts 的 Zod parser
  → route 的边界归一化与 service 调用
  → service/workflow 读取 db/schema
  → 具名错误或 typed result
  → route 映射既有 HTTP envelope
```

不要让每个层重复解析同一 payload。parser 失败通常是 400；资源不存在、冲突、限流和后台任务沿用各 endpoint family 的现有 status/envelope。service 若要跨边界携带 status，使用具名错误类或结构化结果，不要让 route 依赖字符串猜测。

## 代理和流式流程

```text
下游请求
  → route adapter / auth context
  → proxy-core surface
  → executeEndpointFlow()（endpoint、retry、fallback）
  → runtime dispatch / transformer
  → upstream Response 或 SSE reader
  → sharedSurface 记账、usage、log、channel health
  → 下游协议 response
```

每次改代理都同时检查：

- `/v1` 下游路径与 upstream path 是否仍可追踪；
- stream close、abort、首字节 timeout 和整包读取是否一致；
- retry 是否更新 channel health，并使用共享 failure vocabulary；
- usage 来源（`upstream`、`self-log`、`unknown`）、billing 默认值、token 默认值和 warning scope 是否保留；
- `readRuntimeResponseText()` 是否替代了 proxy-core surface/orchestration 中对真实 runtime `Response` 的直接 `.text()`；`responsesSseFinal.ts` 的无 `headers` 测试 double 兼容分支除外。

## Web 请求边界：默认规则和有意例外

已认证管理 API 默认经过 `src/web/api.ts`。以下 raw `fetch()` 是源码确认的例外，不得用全面禁止规则破坏功能：

| 位置 | 原因 | 验收 |
| --- | --- | --- |
| `src/web/App.tsx:155` | 登录 bootstrap 尚未持久化 token | Authorization、错误提取、失败翻译和不泄露 token |
| `src/web/pages/Sites.tsx:634` | `probe-stream` 需要直接控制 `ReadableStream` 和 `AbortController` | 每站 timeout/abort、reader close、逐项结果和 unmount cleanup |
| `src/web/api.ts:487` | API boundary 自身调用浏览器 `fetch()` | 统一 auth/session expiry、timeout、body lifecycle |
| `src/web/api.ts:1978` | `testChatStream` 有意返回原始 `Response` | 调用方明确拥有 stream body，避免重复消费 |

新增例外必须在相邻注释或研究文件说明 owner、浏览器/跨域/stream 原因、auth、timeout、cancellation、测试和迁移计划。

## 数据库跨层契约

一次 schema 变更必须沿着以下链路同步：

```text
src/server/db/schema.ts
  → drizzle/*.sql migration history
  → generated schema contract/bootstrap/upgrade artifacts
  → schema unit/parity/upgrade/runtime tests
  → service/route 行为
```

不要在 feature route 手写 MySQL/PostgreSQL DDL，也不要在 transaction 提交前触发 route rebuild、通知或外部请求。当前仓库支持 SQLite/MySQL/PostgreSQL runtime switch；dialect 差异属于 db owner。

## Platform adapter 边界

平台名称、探测顺序、endpoint preference、header、quota unit 和 capability 必须形成一个声明式故事。当前 `OneApiAdapter`、`VeloeraAdapter` 直接继承 `BasePlatformAdapter`，OneHub/DoneHub 另有 models fallback、quota 解释和 check-in 差异；不要把它们误写成 `StandardApiProviderAdapterBase` 的统一子类。跨平台抽象必须用参数化测试证明：

- header 是否按平台发送；
- quota divisor/remaining 与 total 的单位是否正确；
- 不支持的 check-in 是否返回 skipped/unsupported 语义；
- models/context cache 和错误分类是否保持。

## JSON、事件和 JSONL 边界

对于 append-only event、SSE 或 Trellis JSONL：

```text
writer → JSONL/stream → 单一 decoder/type guard → projection/reducer → UI/command
```

writer 是唯一 `seq`/`id` 分配者；decoder 负责 `unknown` 归一化；projection 负责供 consumer 使用的 metadata；reducer 负责从事实来源 replay。UI、command 和 hook 不得各自 local cast 同一个字段。`implement.jsonl`/`check.jsonl` 的 `_example` seed 没有 `file` 字段，应被 reader 跳过；真实条目只能引用 spec/research。

## Trellis workflow 跨层契约

```text
task.json.status / session pointer
  → resolve breadcrumb key
  → workflow.md [workflow-state:STATUS] body
  → hook additionalContext
  → AI 当前轮动作
```

不变量：

- `STATUS` 只允许 `[A-Za-z0-9_-]+`；开闭标签必须同名；
- `no_task`、`stale_<source_type>` 是 runtime 伪状态，不写入普通 task status；
- Codex `dispatch_mode`（`auto`、`inline`、旧别名 `sub-agent`）与 workflow status 是两个独立字段；
- active task 指针按 session 存放在 `.trellis/.runtime/sessions/`，不能回退到全局 `.current-task`；
- 缺失/损坏 workflow 或 malformed hook input 应产生可修复的中文提示或 fail closed，不得静默选择别的 task；
- `task.py finish` 只清除 session pointer，`task.py archive` 才写 `status=completed` 并移动目录。

修改 workflow tag、task writer 或 hook 时，必须同时查看 parser、writer、session resolver 和输出 schema，不能只改一端的文案。

## 跨层检查清单

实现前：

- [ ] 已画出 source → transform → store/runtime → consumer 的完整数据流。
- [ ] 每条边界都有输入、输出、错误、单位和生命周期 owner。
- [ ] 已搜索已有 parser、workflow、failure vocabulary、UI primitive 和 API method。
- [ ] 已区分 HEAD 事实、当前工作树 WIP 和最终验收证据。

实现后：

- [ ] 用 null、empty、invalid、timeout、abort、partial failure 和 stale response 测试边界。
- [ ] 验证 round-trip 没有丢字段，HTTP status/protocol payload 没有改变。
- [ ] 验证 consumer 使用 shared decoder/projection，而不是 local cast。
- [ ] 验证 timer/listener/reader/body lock/transaction cleanup。
- [ ] 跨越 server/web/db/Trellis 时运行对应 architecture tests、typecheck、`npm run repo:drift-check` 和 `git diff --check`。

## 需要建立 flow 记录的时机

满足任一条件就把数据流写进任务 `research/` 或 `design.md`：

- 功能触及三个以上层；
- 同一字段在 API、数据库和页面之间转换；
- 涉及流式、重试、并发、取消或 session pointer；
- 过去已经因为边界误解产生过 bug；
- 需要保留兼容 facade 或 drift allowlist。
