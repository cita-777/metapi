# 全项目简化与前端一致性

## 目标

在保留现有用户能力以及协议/数据库语义的前提下，降低 Metapi 全项目的维护
成本和行为漂移。项目应拥有一条容易理解的前端路径、一套可复用的视觉语言，
以及明确负责重复请求、状态和业务编排的 owner。所有管理页面的响应式行为、
加载/错误反馈、键盘行为和交互质量应保持一致。

## 已确认的仓库事实

- 项目是 TypeScript 单仓库，包含 Fastify 服务端、React 18/Vite 管理后台和
  Electron 桌面封装；Web 路由已在 `src/web/App.tsx:22-39` 使用 lazy load。
- Web 应用在 `src/web/index.css` 中已有全局 token/class 体系（当前约 6,908
  行、62 个 CSS variables），但多个页面仍携带大量 inline style。热点包括 `Settings.tsx`、
  `ProxyLogs.tsx`、`Sites.tsx`、`Accounts.tsx`、`Models.tsx` 和 `ModelTester.tsx`。
- `vite.config.ts` 同时启用 React plugin 和 Tailwind Vite plugin，而生产界面
  主要使用 `index.css` class 与 inline style；必须通过明确决策解决入口不一致，
  不能让页面各自选择。
- `src/web/api.ts` 是认证请求/SSE 边界，拥有 timeout、session expiry、错误
  提取和 proxy-test alias；少数页面仍直接调用浏览器 `fetch()`，需要先审计。
- 大型编排页面包括 `Settings.tsx`（2,647 行）、`ProxyLogs.tsx`（3,832 行）、
  `Accounts.tsx`（3,499 行）和 `ModelTester.tsx`（3,401 行）；`Sites.tsx` 为
  2,426 行，`Dashboard.tsx` 为 1,710 行。现有领域子目录和响应式 primitive
  证明增量抽取是项目接受的模式。
- 历史 single-source consolidation（`docs/plans/2026-03-23-single-source-consolidation-mega-plan.md`）
  已覆盖协议归一化、route refresh、platform discovery、schema metadata、
  responsive filter/action shell 以及部分 modal/drawer。新工作必须复用这些
  owner，不得重建并行 helper。
- 当前工作树含用户拥有的未跟踪 Trellis/IDE/生成文件；它们不属于本任务范围，
  必须原样保留。
- 兄弟项目 Iris 没有使用 Arco 或 Ant Design 全套视觉组件，而是项目组件 +
  Radix Dialog/Tabs 原语、Tailwind token/utility、TanStack React Query、Zustand、
  Lucide、Motion 和 dnd-kit；其 `OverlayDialog` 展示了“第三方行为隐藏在本地
  wrapper 后面”的模式。
- 用户已选择 Iris-like 组件架构：Radix 原语只负责交互/无障碍，Metapi 保留
  自己的靛蓝/灰色 token 和领域组件，路由页不得暴露或直接使用第三方组件 API。
  Tailwind 是否保留由实际使用率和构建证据决定，不能因此混用多套页面体系。
- 规划阶段构建采样为 `2613 modules transformed`、约 `5.35s`，`vchart-vendor` 为
  `2,154.02 kB`（gzip `586.81 kB`）；最终复核为 `2614 modules`，这些数字来自
  本机 dirty worktree，不能直接当作发布基线。
- `useAsyncResource`、`siteSpeedProbe`、`streamBatcher`、`components/ui/**` 和
  中性 server helper 目前属于未提交工作树候选/WIP；是否纳入最终交付必须以
  focused tests、typecheck、build、drift 和 review 证据为准。

## 需求

### R1. 建立可执行的简化契约

建立重复样式、页面 raw request、页面互引、异步状态转移和超大编排文件的基线
清单与 architecture check。新代码必须沿用 React、Vite、TypeScript、
`src/web/api.ts` 和全局 design token 路径；页面不得引入新的 UI framework、
CSS module 约定、样式 runtime 或本地 HTTP client，除非有明确记录的例外。

### R2. 统一前端视觉体系

把现有 CSS variable 和语义 class 作为唯一视觉语言，抽取通用的 page header、
section、field、loading/error/empty、action group 和 list/table state primitive。
优先迁移重复频率最高的 inline style，保留现有响应式断点和主题行为。新生产
UI 不得在已有 shared class/variant 可用时新增 one-off style object。

### R3. 收敛异步状态与请求 owner

提供小而类型安全的可取消加载 helper，负责 stale-result protection、loading/
error/empty 转移和 refresh invalidation；至少迁移一组高频页面。领域状态仍由
页面拥有，认证 HTTP/SSE 仍由 `src/web/api.ts` 负责，取消、timeout 和 partial
failure 的用户语义必须保持可区分。

### R4. 按职责拆分大型编排文件

把应用 shell 和最大页面热点拆成领域 hook、section 与 component，保持页面作为
编排面；modal/panel 家族放回现有领域目录，纯计算放入 helper。不得创建无主的
通用 `utils/` 垃圾场，也不得把业务规则搬入 route/page adapter。

### R5. 以证据驱动前端性能优化

保留路由级 code splitting，并针对列表、图表、搜索、轮询和 model tester 做
可测量优化：避免重复请求、取消过期工作、延迟非关键数据、稳定昂贵派生值，
减少无关 parent 更新导致的重渲染。记录前后 chunk/request/render 基线，目标
路径不得回归，并应有可重复的改善或明确的瓶颈转移证据。

### R6. 提升跨页面 UX 与可访问性一致性

用共享 primitive 统一 focus、keyboard、dialog/drawer 语义、移动 action/filter、
loading skeleton、empty state、可操作错误和翻译文本；保留 URL intent 与历史
行为。每个交互家族增加聚焦测试，并覆盖 stale request 和 cleanup。

### R7. 只合并有证据的服务端重复

审计 services、proxy-core、routes、transformers、contracts 和 platform adapter。
只有在存在清晰重复和 owner 时才合并，复用既有 workflow/failure vocabulary；
routes 保持 adapter、transformers 保持 protocol-pure。数据库变更不在本任务内，
除非单独发现并获批 schema 需求。

### R8. 留下可重复的维护守卫

记录选定的前端 stack 和抽取模式，在必要位置添加 architecture test，并纳入
repository drift gate，防止后续页面悄悄重新引入第二套技术或样式体系。

## 验收标准

- [ ] 检入一份 baseline/audit，记录重复样式、请求、状态和大文件热点，并把每个
      选定改动链接到明确 owner。
- [ ] 前端有一条文档化的生产样式路径；新改页面不得引入独立 CSS/UI 技术或绕过
      shared API boundary。未使用的 build plugin/dependency 必须删除，或有测试和
      文档说明其保留理由。
- [ ] shared primitive 与 async request/state helper 有 unit 或 architecture test，
      至少三个高频页面实际使用。
- [ ] 选定大型页面的编排边界变薄，路由、action、URL intent、响应式行为、翻译及
      modal/drawer 无障碍保证均无损失。
- [ ] 性能测量证明 initial/route bundle、重复请求数和 stale 行为不回归；目标的
      list/chart/model-test 路径有改善，或有可复现测量证明瓶颈在别处。
- [ ] 改过的异步路径会取消或 stale-guard 过期工作，恢复 timer/listener/body-scroll，
      并提供可操作的 loading、empty 和 error feedback。
- [ ] 相关 focused tests、web/server type checks、`npm run repo:drift-check`、
      `git diff --check` 和生产构建通过；既有无关失败必须带精确证据记录，不能隐藏。
- [ ] 维护者文档说明 canonical frontend stack、shared styles/hooks/components 的放置
      位置，以及 architecture check 如何阻止页面自行发明实现。

## 范围内

- 一个带独立验收前端基础、前端性能/UX、服务端简化切片的 parent task；
- 在现有 React/Vite/Fastify 架构内的代码、测试、狭义文档和 architecture check 改动。

## 范围外

- 删除或重设计用户能力、改变 proxy protocol semantics、database schema/migrations，
  或未经单独批准改变 public API contract；
- 替换 React/Vite、增加全局 state library，或一次重写所有历史页面；
- 清理无关的 untracked 文件、生成物、IDE 状态或既有用户改动。

## 关键决策

- **组件架构**：采用 Iris-like 的 Radix behavior primitives + 单一项目封装层；保留
  并扩展已有 Metapi component，不为使用库而替换仍然正确的领域组件。
- **视觉兼容**：保留现有 Metapi CSS variables、主题、响应式断点和用户可见样式。
- **第三方 import 边界**：只有 `src/web/components/ui/**` 可以直接 import Radix；
  routed pages/domain components 只能依赖项目 wrapper。
- **样式入口**：先依据 utility 使用率和 production build 证据决定 Tailwind 是否清理；
  无论结果如何，不允许页面增加另一种 CSS runtime 或 convention。

当前没有待用户决策的产品问题；Tailwind 的处理结果属于实现前可验证的技术判断，
并会在 `design.md` 中记录证据。

## Trellis 文档语言

本任务后续新增或修改的 Trellis 文档默认使用简体中文。命令、路径、代码符号、
配置字段、协议名和第三方名称保持规范原文；已有英文历史内容不因该约定批量回译。
