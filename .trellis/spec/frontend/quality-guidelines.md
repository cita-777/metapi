# 前端质量规范

## 必须遵循的实践

- 顶层 route page 之间不得互相 import；架构变更后运行 `npm run repo:drift-check`。
- 已认证管理 HTTP/SSE 调用默认通过 `src/web/api.ts`，以保持 auth expiry、timeout、error extraction 和 cancellation 一致；登录 bootstrap、`probe-stream` 和 `api.ts` 内部 raw `fetch()` 是有记录的例外。
- 新增异步 UI 时提供 loading、empty、error 和 success state。
- 防止 effect 发生 stale response，并清理 timer、listener、stream、portal 和 body-scroll lock。
- mobile 行为复用 `ResponsiveFilterPanel`、`ResponsiveBatchActionBar`、`MobileCard`、`MobileDrawer`、`useIsMobile` 和 `mobileLayout.ts`。
- 用户可见字符串使用 `t()`/`tr()`，并保留现有 language Context 行为。
- 行为变化添加或更新聚焦的 Vitest 测试；边界或导入规则变化时再添加架构测试。

## 测试风格

测试使用 Vitest、`react-test-renderer` 和 `act()`；`MemoryRouter` 提供 route state，`vi.mock()`/`vi.stubGlobal()` 隔离 API、storage、browser 和 portal 依赖。可信示例包括：

- `src/web/api.test.ts`：auth header、timeout tier、SSE/file 行为和 alias identity；
- `src/web/App.mobile-layout.test.tsx`：768px breakpoint；
- `src/web/components/centered-modal.test.tsx` 和 `mobile-drawer.test.tsx`：无障碍/cleanup primitive；以及
- `pages/sites.detect-race.test.tsx`、`pages/accounts.edit-panel.test.tsx` 和 `pages/ProxyLogs.server-driven.test.tsx` 等页面测试：stale request 和 server data。

新增 modal/drawer 时，按适用范围测试 close button、Escape/backdrop policy、portal fallback、body overflow 恢复和卸载 cleanup。新增 mobile layout 时，测试 768 以及其上下相邻宽度。

## 命令与门禁

```bash
npm run typecheck:web
npm run typecheck:web:test
npm test
npm run build:web
npm run repo:drift-check
git diff --check
```

面向完整发布的变更还要运行 `npm run build`，它会检查 server 和 desktop 编译。包声明 Node `>=25.0.0`；即使旧贡献文本写 Node 20+，也应使用该运行时取得权威结果。

## 无障碍与评审清单

- 控件是否可通过键盘到达并有名称？
- label、dialog role、`aria-modal` 和 close affordance 是否正确？
- 在共享 mobile breakpoint 和支持 reduced motion 的动画组件中，UI 是否仍可用？
- 用户可见错误是否已翻译、可操作，且没有泄露 secret？
- server response field 是否在渲染前收窄？
- effect 和异步操作是否取消或 stale-guard？
- 是否保留共享 component/API/state 约定并添加对应测试？

## 高风险模式

避免没有说明的 raw per-page `fetch()`、为页面本地数据新增 global store、无界 `any`/assertion、可点击的非语义容器、重复 modal 实现，以及只断言 mock 实现细节而没有验证可见行为的测试。

## 场景：前端简化与性能交付门

### 1. 适用范围与触发条件（Scope / Trigger）

- Trigger：跨页面抽取 UI/request helper、修改轮询或流式渲染、增加架构守卫，
  或改变 route/page/domain 文件边界时适用。
- Scope：验收同时覆盖行为、生命周期、无障碍、构建 chunk 和维护边界；只有
  “编译成功”不能作为性能或 UX 完成证据。

### 2. 接口签名（Signatures）

- 认证管理 API：`src/web/api.ts` 的 typed method，可选 `{ signal, timeoutMs }`。
- browser-only 站点测速：`probeSiteSpeed(url, options)` 与
  `probeSiteSpeeds(sites, { concurrency, timeoutMs, signal, onResult })`，固定
  `GET ${site}/v1/models`、`mode: 'no-cors'` 语义。
- 架构门：`npm run repo:drift-check` 输出 `violations` 与 `tracked debt`；
  新 wrapper/exception 必须有源码 owner、原因和测试。

### 3. 契约（Contracts）

- 新页面沿用 React 18 + Vite + TypeScript、`components/ui/**`、全局
  `index.css` token/class 和 `api.ts`；不得引入第二套 UI framework、CSS
  module、style runtime 或 per-page HTTP client。
- 页面级列表/图表/搜索/轮询优化要记录 before/after 的 chunk、请求在途数、
  stale response 和关键交互证据。没有真实浏览器 trace 时，必须标为静态或
  测试夹具证据。
- 跨域 `no-cors` 测速是明确例外：opaque response 只判断可达性，逐站结果
  区分 `done`、`timeout`、`error`、`aborted`，并限制并发不超过 4。
- `vchart-vendor` 若仍是最大 chunk，应记录为后续独立瓶颈，不能在未测量
  below-fold 门控收益时声称已解决。

### 4. 校验与错误矩阵（Validation & Error Matrix）

| 检查 | 通过条件 | 失败处理 |
| --- | --- | --- |
| UI architecture/drift | 第三方 primitive 只在 `components/ui`，style/Tailwind 入口唯一 | 修复 import/owner，不新增隐式 allowlist |
| async lifecycle | abort、stale、timer、reader、body-scroll 均有 cleanup | 加 regression test 后再继续 |
| mobile/keyboard/a11y | 768px 断点、focus、Escape/backdrop、label/role 有可见行为证据 | 回退 wrapper 迁移或补测试 |
| performance | 请求不叠加，route chunk 不回归，批处理内容等价 | 保留基线并把未证实优化列为后续 |
| build/type/test | web/server typecheck、focused/full tests、build、diff check 全部通过 | 精确记录环境限制，不隐藏失败 |

### 5. 正例、基线与反例（Good / Base / Bad Cases）

- Good：先在 helper/unit 层证明取消和结果映射，再迁移四个页面；保留旧
  facade，逐步减少页面编排复杂度。
- Base：本地 build 显示 `vchart-vendor` 约 2.15MB 时，记录测量与局限，暂不
  做没有收益证据的动态拆分。
- Bad：看到 HTTP 200 或 mock fetch 就宣称测速/性能完成，或为某页面加入
  独立 CSS/UI 包以绕过共享边界。

### 6. 必需测试（Tests Required）

- `src/web/components/ui/**` behavior/architecture tests；`useAsyncResource`、
  `siteSpeedProbe`、ModelTester batcher 和 API body lifecycle tests。
- Dashboard/ProxyLogs/Search/Models 的 stale、single-flight、visibility、
  partial failure、移动和键盘回归。
- 交付命令：`npm run typecheck:web`、`npm run typecheck:web:test`、
  `npm test -- --run src/web`、`npm run build:web`、`npm run repo:drift-check`、
  `git diff --check`；跨层改动再运行 server tests/typecheck/build 与完整 `npm run build`。

### 7. 错误与正确对照（Wrong vs Correct）

#### 错误示例（Wrong）

```text
“build 通过，所以首屏性能已经优化；vchart chunk 的 warning 忽略即可。”
```

#### 正确示例（Correct）

```text
记录 chunk/request/stale/interaction 的实测或夹具证据；若 vchart 尚未拆分，
明确写成已测量瓶颈和后续任务，不把它混入本次已完成项。
```
