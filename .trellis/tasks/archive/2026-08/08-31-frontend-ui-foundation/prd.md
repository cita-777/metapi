# 前端 UI 基础与 Radix 封装层

## 目标

采用 Iris 使用的组件边界：Radix 负责交互/无障碍原语，Metapi 自己的
`components/ui` 负责稳定 props、主题和兼容性，页面只使用项目封装。降低
重复弹窗、抽屉、选择器、按钮和反馈状态的维护成本，同时不改变现有页面能力。

## 已确认事实

- 当前没有 Radix 或完整 UI 套件依赖；`CenteredModal`、`MobileDrawer`、
  `ModernSelect` 是已有共享原语，但多个页面仍复制外壳。
- `ChangeKeyModal`、`SearchModal`、多个 settings modal、下游/OAuth drawer
  绕过或复制共享壳；`TokenRoutes` 还有 imperative `innerHTML` dialog。
- 生产代码约有 430 个原生 `<button>`，没有统一 `Button` 组件；异步按钮的
  spinner、disabled、文案组合在页面中大量重复。
- `ModernSelect` 的 props 和组件类型被很多测试直接断言，必须保留 facade
  兼容性，不能直接把 Radix 节点暴露给页面。

## 需求

1. 新增 `components/ui` 的项目封装边界，只有该边界可以直接 import
   `@radix-ui/*`；页面和领域组件不得直接依赖第三方 UI 原语。
2. 提供兼容现有行为的 Dialog/Drawer wrapper：具备明确 role/aria、焦点返回、
   Escape/backdrop 策略、body-scroll 引用计数和退出动画；保留现有 CSS class
   与 `CenteredModal`/`MobileDrawer` 导出。
3. 将复制的 modal/drawer 和 imperative confirm 按低风险顺序迁移，保留
   remember-dismiss、URL intent、portal fallback 和现有关闭策略。
4. 通过 facade 逐步让 `ModernSelect` 使用 Radix 行为，保留
   `options/onChange/value/placeholder` 等当前测试和调用方契约。
5. 提供 `Button`/`AsyncButton`、`LoadingState`、`EmptyState`、`ErrorState` 或
   等价的窄职责 primitive，至少迁移三个高频页面/组件；不强行抽取领域卡片。
6. 为 Toast 增加 `aria-live` 和 timer cleanup，但保持 `useToast` API 不变。
7. 增加 drift/architecture 守卫，阻止未来页面直接导入第三方 UI，并记录
   暂时保留的兼容债务。
8. 根据实际 utility 使用率清理或明确保留 Tailwind 入口；不得新增第三种
   样式运行时。

## 验收标准

- [ ] Dialog/Drawer/Select/Button/feedback wrapper 有行为或 architecture 测试，
      覆盖关闭、焦点、body lock、键盘、loading/disabled 和 portal cleanup。
- [ ] 复制的 Search/ChangeKey/settings/downstream/OAuth modal/drawer 中至少
      三个家族改为 wrapper，TokenRoutes 的 imperative dialog 不再新增；
      现有功能和测试语义保持不变。
- [ ] 页面和领域组件没有新增第三方 UI 直引；drift check 对直接 import 可
      报 violation，对 wrapper 目录可通过。
- [ ] `ModernSelect` 的现有调用方和测试无需改写为 Radix 原语，键盘/鼠标/受
      控值行为有回归证据。
- [ ] 选定页面的重复 inline style/按钮/反馈 markup 明显减少，未改变主题、
      移动断点和翻译；样式入口选择有构建证据。
- [ ] `npm run typecheck:web`、相关 Vitest、`npm run repo:drift-check`、
      `git diff --check` 和 `npm run build:web` 通过。

## 范围外

- 全量重写所有页面、改变视觉品牌、引入 Arco/Ant Design 等完整视觉套件；
- 迁移业务表格/图表的领域渲染逻辑；
- 改变公开 API、协议、权限或数据库语义。
