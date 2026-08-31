# 前端 UI 基础与 Radix 封装层：执行清单

## 实施步骤

1. 核对 package manager 和 React 18 peer 兼容性，只加入实际需要的 Radix
   包，保持 npm/pnpm lockfile 一致。
2. 建立 `src/web/components/ui/` 目录和第三方 import architecture test。
3. 提取共享 dialog/drawer 生命周期辅助逻辑，补多实例 body-lock、焦点返回、
   Escape/backdrop、portal fallback 测试。
4. 让 `CenteredModal`、`MobileDrawer` 委托或复用新 wrapper，先确保旧测试通过。
5. 迁移 SearchModal、ChangeKeyModal、settings modal、downstream/OAuth drawer
   和 TokenRoutes confirm/imperative dialog，逐个运行局部测试。
6. 增加 `Button`/`AsyncButton`、统一 loading/empty/error primitive，迁移至少
   Accounts、Settings、Tokens 中的高频异步动作。
7. 让 Toast 提供 aria-live 和 timer cleanup，保持 `useToast` 合约。
8. 按 utility 搜索和 `build:web` 结果决定 Tailwind cleanup，并更新文档/guard。

## 重点验证

```bash
npm test -- src/web/components/centered-modal.test.tsx src/web/components/mobile-drawer.test.tsx src/web/components/ModernSelect.test.tsx
npm test -- src/web/pages/DownstreamKeys.test.tsx src/web/pages/settings.factory-reset.test.tsx src/web/pages/tokenRoutes.mobile-layout.test.tsx
npm run typecheck:web
npm run typecheck:web:test
npm run repo:drift-check
npm run build:web
git diff --check
```

## 停止条件

- Radix 改变 test renderer、focus、z-index、portal 或 controlled Select 语义且
  无法通过 facade 兼容时，停止迁移并保留现有内部实现；
- 发现需要改协议/数据库或删除用户能力时，回到父任务评审；
- 不使用批量替换破坏用户已有 dirty/untracked 文件。
