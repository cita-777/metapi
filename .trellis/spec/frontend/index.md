# 前端开发规范

本规范描述 `src/web/` 下的 React/Vite 管理端 UI。内容反映当前代码、测试、`AGENTS.md`、`CONTRIBUTING.md` 和 `docs/project-structure.md`。已认证管理 API 默认经过 `src/web/api.ts`；raw `fetch()` 只允许有明确 owner 的登录 bootstrap、跨域/stream 能力或 API boundary 内部实现，具体契约见目录结构和 Hook 规范。

## 规范索引

| 规范 | 用途 | 维护中的示例 |
| --- | --- | --- |
| [目录结构](./directory-structure.md) | 决定页面、组件、helper 和 asset 的放置位置 | `src/web/App.tsx`、`src/web/pages/`、`src/web/components/` |
| [组件规范](./component-guidelines.md) | props、组合、样式、modal、drawer 和无障碍 | `CenteredModal.tsx`、`MobileDrawer.tsx`、`ResponsiveFilterPanel.tsx` |
| [Hook 规范](./hook-guidelines.md) | effect、取消、数据获取和可复用有状态逻辑 | `useIsMobile.ts`、`useAnimatedVisibility.ts`、`pages/TokenRoutes.tsx` |
| [状态管理](./state-management.md) | local、URL、持久化、context 和 server state | `App.tsx`、`authSession.ts`、`i18n.tsx`、`pages/ProxyLogs.tsx` |
| [类型安全](./type-safety.md) | API 类型、unknown 边界、运行时归一化和遗留 cast | `api.ts`、`pages/helpers/`、`tsconfig*.json` |
| [质量规范](./quality-guidelines.md) | 测试、响应式行为、无障碍和构建门禁 | `src/web/**/*.test.tsx`、`package.json` |

## 开发前检查

修改 web 代码之前：

1. 阅读相关规范和 `AGENTS.md` 中的仓库级规则。
2. 判断行为是共享的（`components/`）还是页面专属的（`pages/<domain>/` 或 `pages/helpers/`）。不要让一个顶层 page import 另一个顶层 page。
3. 新增 fetch wrapper、formatter、modal 或 responsive 分支前，先搜索 `api.ts`、已有 helper 和共享 mobile primitive。
4. 服务端通信默认保持在 `src/web/api.ts`；若必须使用 raw `fetch()`，在代码或 research 中记录 owner、浏览器/跨域/stream 原因、auth、timeout、cancellation、测试和迁移边界。
5. 对执行 fetch 或 polling 的 effect，先规划 cancellation/stale-result protection 和 cleanup，再写 render path。
6. 新增 UI state 前，先把它归类为 local、derived、URL、persistent 或 server state，再选择 `useState`、`useMemo`、ref 或 Context。

## 质量检查

迭代时运行聚焦的 test/typecheck，交付前运行完整 web 和仓库门禁：

```bash
npm run typecheck:web
npm run typecheck:web:test
npm test
npm run build:web
npm run repo:drift-check
git diff --check
```

页面变更应在相关时包含 loading/error/success 行为测试，以及 mobile 或 keyboard 行为测试。共享组件变更必须保留其 architecture test 和 portal/cleanup 语义。

## 事实来源

现有组件和测试才是权威来源。应用当前使用 React state 和 Context 加手写 API 调用；没有可扩展的 React Query、Redux 或 Zustand store。旧文件仍有部分 `any` cast，但新代码应使用此处描述的 typed API contract 和 `unknown` guard。
