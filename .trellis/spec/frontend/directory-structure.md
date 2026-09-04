# 前端目录结构

## 运行时布局

React/Vite 应用位于 `src/web/`：

```text
src/web/
├── main.tsx                 # StrictMode + BrowserRouter 入口
├── App.tsx                  # lazy route table 和应用 shell
├── api.ts                   # 认证 HTTP/SSE client 与响应类型
├── authSession.ts           # 会过期的本地 admin session
├── appLocalState.ts         # 安装级 localStorage cleanup/常量
├── i18n.tsx                 # language Context 与翻译桥接
├── i18n.supplement.ts       # 补充翻译条目
├── index.css                # 全局 CSS、Tailwind import、design token
├── components/              # 可复用 UI、dialog、响应式 primitive、图表
├── pages/                   # 顶层路由页和页面自有 helper
│   ├── helpers/             # 多个页面文件共享的纯页面领域逻辑
│   ├── accounts/            # 账号专属 modal/panel family
│   ├── downstream-keys/     # downstream-key drawer/editor family
│   ├── model-tester/        # playground 子组件
│   ├── oauth/               # OAuth modal family
│   ├── settings/            # settings modal/section family
│   └── token-routes/        # route card、filter 和排序 helper
└── public/                  # web 提供的静态图片和图标
```

`src/web/main.tsx` 在 `React.StrictMode` 和 `BrowserRouter` 中挂载 `<App />`；`App.tsx` 负责 shell 和 lazy route 组装。

## 放置规则

- 顶层路由 screen 放在 `pages/<Name>.tsx`，并在 `App.tsx` 中 lazy 注册。
- 多页面使用的组件放在 `components/`。只属于一个领域的 modal/drawer family 放在 page 子目录，例如 `pages/settings/` 和 `pages/token-routes/`。
- 仅页面使用的纯逻辑放在 `pages/helpers/` 或相应领域子目录。若 helper 变为跨页面共享，只有在它是 UI 导向时才放到 `components/`；否则使用合适的共享模块。
- API 调用和响应 contract 默认放在 `api.ts`；不要创建绕过 auth/timeout/error handling 的页面级 `fetch()` wrapper。当前允许的 raw `fetch()` 例外是 `App.tsx:155` 的登录 bootstrap、`Sites.tsx:634` 的 `probe-stream`，以及 `api.ts` 自身的 boundary/原始 stream 返回；新增例外必须有 owner、原因、取消/超时和测试说明。
- 浏览器 asset 放在 `public/`，全局样式放在 `index.css`；不要把运行时 asset 或生成文件散落在页面目录。
- 测试与被测文件或 feature 相邻（`*.test.ts`/`*.test.tsx`）。

## 页面边界

页面是编排 surface：组合组件、调用 `api`、拥有页面本地 state，并把 server data 翻译成 display model。顶层 page 不得 import 另一个顶层 page。仓库 drift check 强制此规则；`src/web/pages/Accounts.tsx` 是现有 tracked exception，不得扩大。

页面出现第二个复杂 modal、drawer 或 panel family 时，应先抽取，再增加更多 inline state。现有示例包括 `pages/downstream-keys/DownstreamKeyDrawer.tsx`、`pages/settings/FactoryResetModal.tsx` 和 `pages/model-tester/ConversationComposer.tsx`。

## 命名与示例

- React component 文件使用 PascalCase（`Dashboard.tsx`、`MobileCard.tsx`），helper/hook 使用 camelCase（`numberFormat.ts`、`useIsMobile.ts`）。
- 行为或架构测试使用描述性后缀（`mobile.test.tsx`、`drawer.architecture.test.ts`）。
- 共享示例：`components/CenteredModal.tsx`、`components/ResponsiveBatchActionBar.tsx` 和 `components/Toast.tsx`。
- 页面/领域示例：`pages/Models.tsx` 配套 `pages/helpers/`，`pages/Dashboard.tsx` 的 browser-only `siteSpeedProbe`，以及 `pages/TokenRoutes.tsx` 配套 `pages/token-routes/`。
