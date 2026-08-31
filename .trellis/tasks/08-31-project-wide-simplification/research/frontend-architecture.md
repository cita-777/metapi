# Metapi 前端架构调查

## 查询元数据

- **查询**：确认 React/Vite 入口、页面边界、认证请求 owner、raw `fetch()` 例外、状态管理、样式入口、性能热点和当前候选 helper。
- **范围**：`src/web/main.tsx`、`src/web/App.tsx`、`src/web/api.ts`、`src/web/components/**`、`src/web/pages/**`、`src/web/index.css`、`vite.config.ts`、前端测试与 `package.json`。
- **日期**：2026-08-31。

## 可复现命令

```bash
nl -ba src/web/main.tsx
nl -ba src/web/App.tsx
rg -n '\\bfetch\\(' src/web --glob '*.ts' --glob '*.tsx'
rg -n 'useAsyncResource|siteSpeedProbe|streamBatcher' src/web --glob '*.ts' --glob '*.tsx'
rg -l 'style=\\{\\{' src/web/pages/*.tsx
wc -l src/web/index.css src/web/pages/*.tsx
npm run typecheck:web
npm run typecheck:web:test
npm run build:web
```

## 已确认的生产入口

- `src/web/main.tsx:1-13` 使用 `React.StrictMode` + `BrowserRouter` 挂载 `<App />`，并加载 `index.css`。
- `src/web/App.tsx:22-39` 通过 `lazy(() => import(...))` 注册 Dashboard、Sites、Accounts、Tokens、TokenRoutes、ProxyLogs、Settings、DownstreamKeys、Models、ModelTester 等路由；`App.tsx` 还拥有 shell、`I18nProvider`、`ToastProvider`、登录状态和导航。
- `package.json` 当前为 React `18.3.1`、Vite `6.4.2`、TypeScript `6.0.3`；UI 依赖包含 `@radix-ui/react-dialog` 和 `@visactor/react-vchart`。仓库没有 React Query、SWR、Redux 或 Zustand 依赖，server state 主要由 React state/Context + 手写 API method 管理。

## API 边界与 raw `fetch()` 分类

`src/web/api.ts` 是已认证管理 API 的默认 owner，负责 auth token、401/403 session 清理、timeout、外部 `AbortSignal`、body 生命周期、HTTP error extraction、JSON/SSE/binary response，以及 proxy-test alias（见 `api.ts:10-34`、`200-240`、`447-500`、`1912-1990`）。但“所有请求都经过 `api.ts`”不符合当前源码，必须保留以下有 owner 的例外：

| 文件/行 | 例外 | 为什么不能机械归入普通 wrapper | 必须保留的契约 |
| --- | --- | --- | --- |
| `src/web/App.tsx:150-181` | 登录 bootstrap | 此时 token 尚未持久化，登录页需要用用户输入的 token 探测公开 auth info | Authorization header、错误文本提取、登录失败翻译；后续管理请求才进入 `api.ts` |
| `src/web/pages/Sites.tsx:634-690` | `probe-stream` | 页面需要自己的 `AbortController` 和 `ReadableStream` 增量读取 | 每站取消、stream close、超时和逐项结果；不能把 no-cors/stream 误当普通 JSON |
| `src/web/api.ts:447-500` | client 内部 `fetch` | 这是 API boundary 的实现，不是页面绕过 | 统一 auth、timeout、错误和 body cleanup |
| `src/web/api.ts:1912-1990` | `testChatStream` 返回原始 `Response` | 调用方有意拥有 stream body 生命周期 | 明确 `wrapBody`/reader 责任，不能重复消费 body |

因此规范应写成“已认证管理 API 默认经过 `api.ts`；raw `fetch()` 仅在列出 owner、浏览器/跨域/stream 原因、auth、timeout、cancellation、测试和迁移边界时允许”，而不是禁止全部 raw `fetch()`。

## 状态与生命周期模式

- 当前 canonical state 仍是页面本地 `useState`、`useMemo`、`useRef` 和两个 Context；URL intent 由 React Router location/search 管理，安装级状态由 `authSession.ts`、`appLocalState.ts` 等小模块管理。
- `useIsMobile.ts`、`useAnimatedVisibility.ts`、`CenteredModal.tsx`、`MobileDrawer.tsx` 展示 listener/timer/animation/body-scroll cleanup 模式。
- `TokenRoutes.tsx` 已有 progressive chunk + `IntersectionObserver`；这是评估大列表优化的样例，不是所有列表都应机械窗口化。
- 过期请求必须由 cancelled flag、sequence ref 或 `AbortController` 保护；mutation 后刷新权威 snapshot，不能把派生 filter/sort 复制成第二份可变 server state。

## 样式与 bundle 事实

- `src/web/index.css` 当前实测 6,908 行、62 个 CSS variables，约 943 个以行首 `.` 统计的 class selector；页面大量组合语义 class 和少量 inline style。
- `vite.config.ts` 同时配置 React plugin 与 Tailwind Vite plugin，`index.css:1` 有 `@import "tailwindcss"`。
- 生产源码明确可见的 utility 至少有 `Settings.tsx` 与 `DownstreamKeys.tsx` 的 `h-4 w-4`；因此不能只凭“看起来很少”删除 Tailwind。应先完成 utility 使用率、生成 CSS 和 chunk 的可重复审计，再决定保留/清理。
- 规划阶段构建采样为 `2613 modules`、`5.35s`、`vchart-vendor 2,154.02 kB`（gzip `586.81 kB`）；最终交付复核为 `2614 modules`、CSS `136.83 kB`（gzip `22.01 kB`）。图表 below-fold gate 必须以网络请求、布局稳定和图表出现后的功能测试为准。

## 当前工作树候选实现（未提交）

以下文件属于当前工作树 WIP，不等于 HEAD 或最终验收：

- `src/web/components/useAsyncResource.ts`：单活动请求、abort、递增 request id、mounted guard、silent refresh、dedupe、`AsyncErrorKind` 分类。当前工作树生产引用为 `Dashboard.tsx`、`Models.tsx`、`ProxyLogs.tsx`、`SearchModal.tsx` 四条路径；HEAD 没有该 helper。必须完成 focused test、typecheck、review 后才能计入验收。
- `src/web/pages/helpers/siteSpeedProbe.ts`：保留 `mode: "no-cors"`，每站 timeout/abort，默认并发 4，`probeSiteSpeeds()` 逐项回调。该模块是有意的跨域 browser-only 例外，不应伪装成 `api.ts` 管理请求。
- `src/web/pages/model-tester/streamBatcher.ts`：24ms 窗口，分别保留 delta/raw event 顺序，支持 `flush()`/`dispose()`；ModelTester 在停止、abort、完成和卸载路径显式 flush。必须用内容等价和 render/flush 计数验证，而不是只看编译。
- `SearchModal.tsx` 当前 WIP 已使用 `useAsyncResource`，通过 query ref + debounce timer 保护 q1→q2 stale 竞态；这覆盖了旧调查中“尚未迁移”的结论。

## 反模式与维护规则

- 顶层 page 不得互相 import；领域 modal/drawer/panel 放入 `pages/<domain>/`，共享 UI 放入 `components/` 或 `components/ui/`。
- 不新增第二套 CSS module/styled-components/runtime，不把业务规则搬入 UI wrapper，不为单页 server state 引入 global store。
- 新 effect 必须列出依赖并清理 timer/listener/reader/body lock；后台轮询要有单飞或 abort previous 与 `visibilitychange` 语义。
- 新 UI 使用真实 button/link、label、dialog role/aria 和 `t()`/`tr()`；测试应断言可见行为、键盘和 cleanup，不只断言 mock 调用。

## HEAD、工作树与限制

- HEAD 的 `SearchModal`、Dashboard、Models、ProxyLogs 使用各自的局部请求/状态逻辑；当前工作树已出现候选抽取，但产品改动还未完成全量回归。
- 本轮未运行真实浏览器 performance trace、生产网络或用户端 LCP/TTI；build 数字只作为本机可复现基线。
- Node 当前为 `v22.23.1`，而 package engine 为 `>=25.0.0`；完整前端/产品验收要在匹配运行时复核。
