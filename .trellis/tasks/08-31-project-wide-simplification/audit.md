# 全项目简化基线审计（2026-08-31）

## 执行环境与命令

- Node `v22.23.1`、npm `10.9.8`。
- `npm run typecheck:web`：通过。
- `npm run build:web`：当前工作树最终复核通过，`2614 modules transformed`，约 `4.77s`。
- web CSS：`136.83 kB`（gzip `22.01 kB`）；`vchart-vendor`：`2,154.02 kB`
  （gzip `586.81 kB`）。
- `npm run repo:drift-check`：当前工作树为 `0 violations / 0 tracked debt`；同一
  checker 只读扫描 `HEAD` 为 `5 violations / 0 tracked debt`。这里的两种口径必须
  分开记录，不能把当前未提交 WIP 的结果写成历史基线。
- 本审计只读，不修改产品源码；当前工作树的 `.agents/`、`.codex/`、
  `.trellis/`、`graphify-out/`、`output/` 等无关文件保持原状。

## 前端结构与样式

| 观察 | 证据 | 影响 |
| --- | --- | --- |
| 路由已经 lazy load | `src/web/App.tsx:22-39` | 不应重复引入第二套路由/页面技术栈 |
| 全局 CSS token/class 是主样式来源 | `src/web/index.css:1-70`、6,908 行、62 个 CSS variables | 适合继续作为 Metapi 视觉 owner |
| Tailwind 入口存在但 utility 实际使用很少 | `vite.config.ts:1-18`、`index.css:1`；生产扫描仅命中极少工具类 | 存在冗余构建入口，应在阶段 A 以 build 证据决定清理 |
| 共享 modal/drawer/select 已存在 | `components/CenteredModal.tsx`、`MobileDrawer.tsx`、`ModernSelect.tsx` | 应保留 API 做 facade，而非一次性重写 |
| 约 430 个原生 button、无统一 Button | 高频集中于 Accounts/Sites/Settings/OAuth/Tokens | 重复 disabled/spinner/aria 组合，易产生视觉和行为漂移 |
| inline style 热点 | Settings 192、ProxyLogs 185、Sites 134、Models 119、Accounts 109、ModelTester 108 | 先抽高频布局/反馈 primitive，避免机械全量替换 |
| 超大页面 | ProxyLogs 3,832、Accounts 3,499、ModelTester 3,401、Settings 2,647、Sites 2,426 | 状态、编排、渲染混在单文件，适合按领域拆分 |

## UI/无障碍重复

- `ChangeKeyModal`、`SearchModal`、settings 多个 modal、下游/OAuth drawer 各自
  复制 portal/backdrop/动画/滚动锁；部分缺 `role`、`aria`、focus return。
- `TokenRoutes.tsx` 有 `document.createElement + innerHTML` imperative dialog；
  `window.confirm` 分散在 ImportExport、OAuthManagement、Settings、TokenRoutes。
- `ModernSelect` 的 `options/onChange` 和组件类型被测试直接断言，必须先做
  facade，再考虑内部 Radix Select。
- Toast 已有集中 provider，但缺 `aria-live` 和完整 timer cleanup。

## 请求与性能热点

- `Dashboard.tsx:250-319` 首屏三组请求；可见性轮询没有在途锁。
- `ProxyLogs.tsx:975-1020,1084-1090` 有 sequence guard 但 2 秒刷新可能堆积
  慢请求。
- `SearchModal.tsx:78-121` debounce 没有 abort/sequence，旧结果可能覆盖新查询。
- `Models.tsx:189-240` 的延迟 metadata hydrate timer 需要卸载清理。
- `ModelTester.tsx:1740+` 每个 SSE chunk 都 setState，适合批处理但必须验证
  文本顺序、工具调用和 debug 字节不变。
- `Dashboard.tsx:1347-1443` 对每个站点用 `Promise.all` 做跨域 `no-cors` 测速；
  该能力不能伪装成认证 API，应抽成有限并发 helper 并保留明确例外。
- `vchart-vendor` 2,154.02 kB（gzip 586.81 kB）是唯一超过 500 kB 的 chunk；
  先做 below-fold 可见性测量，再决定是否拆入口。

## 服务端重复与边界债务

- `src/server/routes/api/accounts.ts:721-830,966-1055` 两套验证诊断同构，
  需统一 shield、user-id、Bearer/Cookie、endpoint pool 和网络错误语义。
- `src/server/services/platforms/oneApi.ts:57-98` 与 `veloera.ts:34-75` 重复
  check-in、balance、models/context cache，差异可配置化。
- `geminiSurface.ts:247-299`、`routes/proxy/completions.ts:372-425`、
  `embeddings.ts:217-270`、`images.ts:461-514`、`search.ts:217-268` 重复
  proxy log 编排，应统一结构化 owner 并保留 path/usageSource/billing 默认值。
- `HEAD` 的 drift report 有 5 条违规：4 条 proxy-core → routes/proxy import、
  1 条 Accounts → Tokens page import；当前工作树 checker 已暂时消除这些路径，
  但只有迁移真实完成并经 review 后才可把它当作稳定结论。

## 已确定方向与限制

- 采用 Iris-like 的 Radix 原语 + 项目封装层，不引入 Arco/Ant Design 全套视觉
  组件；页面和领域组件不直接 import 第三方 UI。
- 保留 Metapi 现有靛蓝/灰色视觉 token 和业务组件，不复制 Iris 暖色主题。
- 不新增 React Query/SWR/Zustand 全局 server-state 层，不改数据库 schema、
  代理协议、公开 API 或用户能力。
- 跨域测速、登录 bootstrap 等 raw fetch 只能作为有 owner、有注释的例外，不能
  变成新页面的默认模式。

## 审计局限

- 未在本机运行真实浏览器性能 trace 或生产网络；chunk/request 指标是本地构建
  和静态/测试夹具基线。
- live MySQL/PostgreSQL 服务未作为本任务前置条件；服务端阶段不改 schema。
- 现有工作树的用户 dirty/untracked 内容不属于本审计，不能据此推断其意图。

## 当前工作树候选核验与 owner 映射（2026-08-31）

下表描述当前 dirty worktree 中已出现的候选切片，不表示已提交、已发布或父/子
任务全部完成；未提交的产品代码仍由各自任务负责，必须在任务级 quality gate
完成后才能升级为交付结论。这里仍然坚持有明确 owner 和回归证据，未把“文件变少”
当成协议统一的充分理由：

| 交付物 | 唯一 owner | 证据与边界 |
| --- | --- | --- |
| Dialog/Drawer/Button/feedback | `src/web/components/ui/**` | role/aria、focus return、Escape/backdrop、body-lock 多实例和 loading 行为测试；`CenteredModal`/`MobileDrawer` 保留 facade |
| ModernSelect | `src/web/components/ui/Select.tsx` | 保留 `options/value/onChange/placeholder` 与 listbox 键盘语义；仍是项目兼容 facade，尚未声称迁移 Radix Select |
| 异步请求生命周期 | `src/web/components/useAsyncResource.ts` + `src/web/api.ts` | abort、stale、silent refresh、single-flight、timeout/body/SSE cleanup 测试；页面继续拥有领域 state |
| Dashboard 测速 | `src/web/pages/helpers/siteSpeedProbe.ts` | 固定并发上限 4、逐站 timeout/result、`no-cors` browser-only 例外和可见按钮状态测试 |
| ModelTester 流式更新 | `src/web/pages/model-tester/streamBatcher.ts` | 24ms 批处理；done/stop/abort/unmount flush，cumulative delta 与 raw event 顺序等价测试 |
| Tokens 页面边界 | `src/web/pages/tokens/TokensPanel.tsx` | `Tokens.tsx` 仅 legacy redirect/兼容导出；解除 top-level page-to-page import |
| 账号验证诊断 | `src/server/services/accountVerificationDiagnostics.ts` | Bearer/Cookie、shield、user-id、endpoint/timeout/no-response 结构化诊断与 route envelope 回归 |
| proxy-core helper | `src/server/services/downstreamPolicyService.ts`、`multipart.ts` | proxy-core 不再依赖 `routes/proxy/**`；旧路径仅 re-export facade，并有 architecture test |

候选切片此前记录的门禁结果（仅作为当前工作树证据，需在最终任务检查时重跑）：

- Web：157 个测试文件、539 个测试通过，2 个跳过；
- Server：301 个测试文件、2,155 个测试通过，6 个跳过；
- 全仓库 `npm test`：480 个测试文件通过、2,777 个测试通过，1 个文件/8 个测试跳过；
- `npm run typecheck`、`npm run build`、`npm run repo:drift-check`、
  `git diff --check` 曾通过；当前 checker 的 drift 为 `0 violations / 0 tracked debt`；
- `better-sqlite3` 首次受 Node ABI 不匹配影响，执行 `npm rebuild better-sqlite3`
  后再运行 server suite；该操作只改 `node_modules`，没有改仓库产物。

仍明确保留的后续项和未决风险：

1. `vchart-vendor` 约 2.15 MB（gzip 约 587 kB）仍是最大 chunk。当前没有真实
   浏览器 below-fold/network trace，因此不实施未经测量的图表拆分；后续任务须
   提供首屏请求、LCP/TTI 和布局稳定性证据。
2. OneApi/Veloera 全面继承统一与全部 proxy-log owner 迁移暂缓。header、quota
   divisor、check-in 文案、model error propagation、usage/billing 默认值和
   await 时序存在真实差异；继续合并前必须先补参数化协议回归。
3. `testChatStream()` 保留 raw `fetch()`，因为它有意返回原始 `Response` 并由
   调用方拥有 body；跨域测速和登录 bootstrap 同样是已记录的 browser-only/API
   boundary 例外，不应被全面禁止规则破坏。
