# Metapi 前端架构约定

这份约定把管理端的技术入口收敛成一条可检查的路径，作为新增页面和重构时
的维护者参考。它不改变现有页面能力、路由、协议或主题。

## Canonical stack

```text
pages/** → pages/<domain>/** → components/ui/** → Radix behavior primitives
                                      └──────────→ index.css design tokens/classes
```

- 生产页面使用 React 18 + TypeScript + Vite，并通过 `src/web/api.ts` 发起
  认证 HTTP/SSE 请求。
- `src/web/components/ui/**` 是项目拥有的 UI 边界。只有这一层可以直接
  import `@radix-ui/*`（以及其他交互原语库）；页面和领域组件只接收
  Metapi 的语义 props。
- `CenteredModal`、`MobileDrawer`、`ModernSelect` 是兼容 facade。新代码优先
  使用 `components/ui` 的 wrapper；旧导出在迁移完成前继续有效。
- 浏览器 renderer 的 Radix modal overlay 已负责 `RemoveScroll`；`components/ui`
  只在 SSR/test/不完整 DOM fallback 使用引用计数 body lock，避免多个 owner
  在卸载顺序不同步时留下页面滚动锁。
- 视觉来源是 `src/web/index.css` 的 CSS variables 和语义 class。不要为单个
  页面引入 CSS module、styled-components 或另一套 UI framework；复用布局时
  先扩展已有 class/primitive。
- `@import "tailwindcss"` 只允许出现在 `src/web/index.css`。当前它作为
  Vite 的单一 utility/preflight 入口保留；页面不得再创建第二个样式 runtime。

## 异步与状态边界

- `src/web/api.ts` 负责认证、超时、错误提取、取消和 SSE 解析；页面只拥有
  自己的 server state、URL intent 和领域 mutation。
- 请求 effect 必须在 target 改变和卸载时 abort 或 stale-guard，并清理 timer、
  listener、animation frame、portal 和 body-scroll lock。
- loading、empty、error、cancel 状态使用共享窄职责 primitive 或既有语义
  class；用户可见文本通过 `t()`/`tr()` 翻译。

## 维护检查

提交前运行：

```bash
npm run typecheck:web
npm run typecheck:web:test
npm run repo:drift-check
npm run build:web
git diff --check
```

`repo:drift-check` 会报告以下架构漂移：

- 页面/领域组件直接 import 第三方 UI 原语；
- 顶层 page 互相 import；以及
- `proxy-core`、transformer 和整包响应读取等既有边界债务。

新的 wrapper 只能放入 `src/web/components/ui/**`，不能通过新增 allowlist
隐藏违规。若确有浏览器能力例外，应在拥有该能力的 helper 中记录原因、测试
和后续迁移边界。

## 迁移策略

优先迁移低耦合的 modal/drawer、异步按钮和反馈状态，再处理大型领域页面。
每个切片都应保留旧 props/class、桌面与移动断点、键盘行为和翻译，并以聚焦
测试证明 focus return、Escape/backdrop、body-scroll 多实例清理和 stale 请求
语义没有回归。不要为了“统一”机械替换所有历史 `<button>` 或业务卡片。

## 当前交付证据（2026-08-31）

本轮简化已经把以下高频路径接入同一套生命周期 owner：

- `Dashboard`、`ProxyLogs`、`Models` 和 `SearchModal` 使用
  `src/web/components/useAsyncResource.ts`；该 helper 负责 `AbortController`、
  stale identity、single-flight、silent refresh、timeout/abort 分类和卸载清理。
- `Dashboard` 的跨域测速集中在 `pages/helpers/siteSpeedProbe.ts`，固定 worker
  pool（目标并发不超过 4）、逐站 timeout 和 `done/timeout/error/aborted` 结果。
  这是有意保留的 browser-only `fetch(..., { mode: 'no-cors' })` 能力，不属于
  认证管理 API。
- `ModelTester` 的 SSE delta/raw event 通过 24ms batcher 提交；停止、完成、
  abort 和卸载都会先 flush，再取消 reader/controller。批处理只改变 React
  commit 频率，不改变 cumulative delta 去重或 raw event 顺序。
- `TokensPanel` 位于 `pages/tokens/`，`pages/Tokens.tsx` 只保留 legacy route
  redirect 和兼容导出；页面之间不再通过顶层 page 互引。

验证记录（本地 Node `v22.23.1`，包声明 Node `>=25.0.0`）：

- `npm run build:web`：`2614 modules transformed`；CSS `136.83 kB`（gzip
  `22.01 kB`），构建通过；
- `npm test -- --run src/web`：157 个文件、539 个测试通过，2 个跳过；
- `npm test -- --run src/server`：301 个文件、2,155 个测试通过，6 个跳过；
- `npm test`：480 个文件、2,777 个测试通过，1 个文件/8 个测试跳过；
- `npm run typecheck`、`npm run build`、`npm run repo:drift-check` 和
  `git diff --check` 通过；drift 结果为 0 violations / 0 tracked debt；
- build 仍显示 `vchart-vendor` 约 2.15 MB（gzip 约 587 kB）的 large-chunk
  warning。当前没有真实浏览器 below-fold/network trace 来证明拆分收益，故把
  它记录为后续独立性能任务，不宣称本轮已经解决。

## 服务端对应边界

管理 route 只做输入解析、endpoint 选择和 HTTP 响应映射；账号验证诊断由
`src/server/services/accountVerificationDiagnostics.ts` 单一拥有，
`downstreamPolicy` 与 multipart helper 由 `src/server/services/` 拥有，旧
`routes/proxy/*` 文件只保留兼容 re-export。proxy-core surface 不得重新引入
`routes/proxy`，transformer 继续保持协议纯净。

OneApi/Veloera 的整套继承统一、以及 completions/embeddings/images/search/
Gemini 的所有 proxy-log 写入迁移暂缓：真实差异包括 header、quota divisor、
check-in 文案、model error propagation、usage/billing 默认值和 await 时序。
只有补齐参数化协议回归后，才允许另建任务继续合并；“减少文件数”不是跳过这些
契约的理由。

## 维护者工作流

新增 UI 交互时按以下顺序检查：

1. 先搜索 `components/ui`、现有 responsive primitive 和 `api.ts` owner；
2. 在 wrapper/helper 层补行为测试，再迁移一个页面；
3. 运行 `npm run repo:drift-check`，确认没有第三方 UI/style runtime 直引；
4. 记录请求并发、stale、timer/reader cleanup 和 chunk 证据；没有实测的收益
   写成“待验证瓶颈”，不要用构建成功替代性能结论。

`ModernSelect` 是兼容 facade，当前仍使用项目自己的 listbox 实现；它不是
“所有交互都已迁移到 Radix Select”的信号。未来若替换内部行为，必须保持现有
`options/value/onChange/placeholder` 契约并新增键盘/controlled 回归测试。
