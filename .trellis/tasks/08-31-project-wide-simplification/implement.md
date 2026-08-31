# 全项目简化与前端一致性：执行计划

## 执行前检查

- [x] 已读取根 `AGENTS.md`、frontend/backend Trellis specs、代码复用和跨层
      思考指南。
- [x] 已检索历史 single-source consolidation，避免重复已交付工作。
- [x] 已建立 web typecheck、web build、drift check 和 chunk 基线。
- [x] 已确认用户选择 Iris-like：Radix 原语 + 项目封装层。
- [ ] 在 `task.py start` 前完成最终规划评审；未获评审批准不得改产品代码。

## 子任务顺序

### 1. `08-31-frontend-ui-foundation`

目标：建立唯一的 `components/ui` 边界，修复共享弹窗/抽屉/选择器的可访问
性和生命周期问题，并建立防止第三方 UI 直引的 architecture guard。

建议顺序：

1. 确认 Radix 最小依赖集合，更新 npm/pnpm lockfile 并验证 React 18 兼容；
2. 新增 Dialog/Drawer wrapper，保留 `CenteredModal`/`MobileDrawer` facade；
3. 为多个 portal 的 body lock、focus return、Escape/backdrop 写回归测试；
4. 迁移 SearchModal、ChangeKeyModal、settings modal、下游/OAuth drawer；
5. 迁移 `window.confirm` 和 TokenRoutes imperative dialog，覆盖 remember/
   dismiss 语义；
6. 以 facade 改造 `ModernSelect`，再增量加入 `Button`/`AsyncButton` 与反馈
   primitive；
7. 清理已确认未使用的 Tailwind 入口（或记录保留理由），建立 wrapper import
   architecture test 和 drift rule；
8. 运行组件及页面焦点、移动布局、类型和构建测试。

风险文件：`src/web/components/CenteredModal.tsx`、`MobileDrawer.tsx`、
`ModernSelect.tsx`、`Toast.tsx`、`src/web/App.tsx`、
`src/web/pages/TokenRoutes.tsx`、settings/downstream/oauth 子目录。

### 2. `08-31-frontend-performance-ux`

依赖阶段 1 的 wrapper/API 边界，但不要求等待所有页面 UI 迁移完成。

建议顺序：

1. 新增并测试窄职责 `useAsyncResource`/`useCancellableLoad`（最终命名按
   代码搜索结果决定），覆盖 abort、stale、silent refresh、unmount；
2. 迁移 SearchModal、Dashboard、ProxyLogs 和一个普通管理页；
3. 抽取 `probeSiteSpeed` 并将 Dashboard 站点测速限制并发、统一 timeout/result；
4. 修复 Dashboard/ProxyLogs 自动刷新 single-flight 和 visibility 行为；
5. 修复 Models hydrate timer，给 ModelTester 流式更新加批处理并验证内容
   完整性；
6. 仅在测量证明必要时复用 TokenRoutes progressive list 或图表可见性门控；
7. 迁移选定页面的共享 loading/error/empty/inline style，并做桌面/移动
   回归；
8. 生成前后性能报告（chunk、请求并发、render/long-task 近似指标）。

风险文件：`src/web/api.ts`、`SearchModal.tsx`、`Dashboard.tsx`、
`ProxyLogs.tsx`、`ModelTester.tsx`、`Models.tsx`、相关页面测试。

### 3. `08-31-server-boundary-simplification`

依赖阶段 1 的架构守卫定义，但可独立实现和验证。

建议顺序：

1. 抽取 `accountVerificationDiagnostics`，以参数化测试锁定 shield、user-id、
   bearer/cookie、endpoint pool、网络超时和失败 reason；
2. 先核对 `OneApiAdapter`/`VeloeraAdapter` 都直接继承 `BasePlatformAdapter` 的
   事实；在中性策略 owner 和参数化测试证明兼容前，不改成
   `StandardApiProviderAdapterBase` 子类。显式保留 quota divisor、header、
   models fallback、check-in capability 和文案差异；
3. 将各 proxy path 的 `logProxy` 改为结构化 `recordProxyLog` owner；
4. 迁移 downstream policy、multipart helper 和 Accounts TokensPanel，删除
   drift allowlist 中已解决的 tracked debt；
5. 运行 API/proxy/service/transformer architecture tests、server typecheck、
   drift check 和相关构建。

风险文件：`src/server/routes/api/accounts.ts`、
`src/server/services/platforms/oneApi.ts`、`veloera.ts`、
`standardApiProvider.ts`、`src/server/proxy-core/surfaces/*`、
`src/server/routes/proxy/{completions,embeddings,images,search}.ts`、
`src/web/pages/Accounts.tsx` 和 `Tokens.tsx`。

## 共同验证门

每个子任务完成前按变更范围运行：

```bash
npm run typecheck:web
npm run typecheck:web:test
npm run typecheck:server
npm test -- <focused tests>
npm run repo:drift-check
git diff --check
npm run build:web
```

父任务最终再运行：

```bash
npm test
npm run typecheck
npm run repo:drift-check
npm run build
```

若全量测试遇到既有失败，保留完整命令、失败文件、退出码和是否与本任务
相关的判断，不通过删测试、放宽断言或隐藏 warning 来“修复”。

## 回滚点与停止条件

- 每个 wrapper、hook、服务抽取和页面迁移保持单一职责、独立 commit；
- 出现 API 响应变化、协议转换差异、焦点/滚动锁回归或跨域测速能力丢失时，
  立即停止该子任务，保留失败证据并回到对应 facade，而不是继续扩大重构；
- 发现数据库 schema/migration 需求、外部实时服务缺失或需要删除用户能力时，
  暂停并回到 PRD 评审，不自行扩大范围；
- 不使用 destructive git 命令，不覆盖用户已有 untracked/dirty 文件。

## 完成定义

- 三个子任务的验收标准均有测试或可重复的测量证据；
- 页面不直接 import 第三方 UI 原语，新增页面不绕过 `api.ts`（显式跨域/登录
  例外有 owner 和 tracked debt）；
- 已解决的 proxy-core/page boundary debt 从 drift allowlist 中删除；
- 目标页面的重复样式/状态/编排明显下降且没有能力回归；
- 全量检查、构建和文档/规范更新完成后，才可执行 Trellis finish/archive。
