# Metapi 变更日志

> 这是当前项目的持续变更记录。后续每次新增功能、修复缺陷、调整接口或修改文档，都要在本文件追加一条记录，不能只修改代码而不记录。

## 记录规则

- 每条记录使用日期、变更类型、需求来源、Issue 链接、实现范围、验证结果和交付物几个字段。
- 有 GitHub Issue 时必须附上完整链接；没有 Issue 时标记为“本会话需求”，不要虚构编号。
- 代码完成后再补充实际文件路径和测试结果，未验证的内容必须明确标记为“未验证”。
- 采用追加方式维护历史记录，不覆盖已完成记录；如果后续修复同一问题，新增一条记录并链接到原记录。
- PDF、截图、需求说明等交付物也要记录，但不能把交付物当成代码实现本身。

## 2026-08-03

### 1. 每个站点独立最大并发

- **类型**：功能实现
- **需求来源**：本会话需求，未提供 GitHub Issue 链接
- **目标**：允许每个站点单独设置最大并发；`0` 表示不限制；不同站点的请求不能共享同一个并发计数器。
- **实现范围**：
  - 数据库 `sites.max_concurrency` 字段，默认值为 `0`，同步更新 schema contract 和各数据库启动产物。
  - 站点创建、更新 API 支持 `maxConcurrency`，接受 `0-100000` 的整数，并拒绝越界或非整数值。
  - 站点管理页面增加最大并发输入框和表格列，保存后可以看到每个站点自己的限制值。
  - 代理请求通过站点级 lease/队列控制并发；达到上限时只等待当前站点，不阻塞其他站点。
- **主要文件**：
  - `src/server/db/schema.ts`
  - `src/server/routes/api/sites.ts`
  - `src/server/services/proxyChannelCoordinator.ts`
  - `src/server/services/siteApiEndpointService.ts`
  - `src/server/proxy-core/surfaces/sharedSurface.ts`
  - `src/server/proxy-core/surfaces/geminiSurface.ts`
  - `src/web/pages/Sites.tsx`
  - `src/web/pages/helpers/sitesEditor.ts`
- **验证**：
  - `src/server/routes/api/sites.api-endpoints.test.ts` 覆盖创建、更新和越界校验。
  - `src/server/services/proxyChannelCoordinator.test.ts` 覆盖同站点排队、不同站点隔离和 `0` 不限流。
  - 本地页面实际显示 `concurrency-site` 的最大并发为 `1`，其他站点显示“不限制”。
- **状态**：已完成并在当前本地服务中运行。

### 2. Rerank 代理接口

- **类型**：功能实现
- **需求来源**：[GitHub Issue #591](https://github.com/cita-777/metapi/issues/591)
- **目标**：新增 `POST /v1/rerank`，复用现有的鉴权、模型路由、站点 API 地址池、重试、用量解析、计费和代理日志链路。
- **实现范围**：
  - 增加 Rerank 路由，校验 `model`，将请求转发到选中的上游 `/v1/rerank`。
  - 支持站点 API 地址池、首字节超时、通道重试和失败切换。
  - 成功路径解析用量并记录计费；失败路径只记录通道失败和代理失败日志，不虚构用量或费用。
  - 路由已在 proxy router 中注册。
- **主要文件**：
  - `src/server/routes/proxy/rerank.ts`
  - `src/server/routes/proxy/rerank.test.ts`
  - `src/server/routes/proxy/router.ts`
- **验证**：
  - 缺少 `model` 返回 HTTP 400。
  - 未携带下游鉴权调用实际本地接口返回 HTTP 401，鉴权边界生效。
  - Rerank 路由单元测试覆盖上游 URL、请求体转发和成功日志。
- **状态**：已完成。要得到真实排序结果，还需要在本地配置支持 Rerank 的上游站点和下游 API Key。

### 3. 路由优先级与 P0/P1/P2

- **类型**：缺陷修复
- **需求来源**：[GitHub Issue #590](https://github.com/cita-777/metapi/issues/590)
- **目标**：新建通道进入当前路由的下一优先级；拖拽或批量更新后优先级保持连续并和页面展示一致。
- **实现范围**：
  - 创建通道时按当前路由已有最大优先级计算默认值，不再把所有新通道固定为 `P0`。
  - 批量保存时按路由压缩为连续的 `P0`、`P1`、`P2` 等层级。
  - 返回通道列表时按 `priority`、`id` 排序，确保 API 和页面顺序一致。
  - 保留优先级拖拽后的保存和路由决策刷新行为。
- **主要文件**：
  - `src/server/routes/api/tokens.ts`
  - `src/web/pages/TokenRoutes.tsx`
  - `src/web/pages/token-routes/priorityRail.ts`
  - `src/web/pages/token-routes/RouteCard.tsx`
- **验证**：
  - 前端优先级 helper 和拖拽相关测试通过。
  - 本地路由页面实际展开 `deepseek-v4-pro`，通道显示在 `P0` 优先级桶中。
  - API 返回顺序使用 `priority`、`id` 排序。
- **状态**：已完成并在当前本地服务中运行。

### 4. Coding Plan v3 URL 拼接

- **类型**：缺陷修复
- **需求来源**：[GitHub Issue #586](https://github.com/cita-777/metapi/issues/586)
- **目标**：当上游 Base URL 已经以 `/v3` 等版本段结尾时，不要把下游请求的 `/v1` 重复拼接到 URL 中。
- **实现范围**：
  - URL 拼接逻辑识别末尾 `/vN` 版本段。
  - `.../api/coding/v3` 加 `/v1/chat/completions` 后得到 `.../api/coding/v3/chat/completions`。
  - 保持已有 `/v1`、无版本后缀和其他平台路径行为不回归。
- **主要文件**：
  - `src/server/proxy-core/orchestration/upstreamRequest.ts`
- **验证**：
  - Coding Plan v3 URL 拼接单元测试覆盖 v3、v1、无版本后缀和现有特殊路径。
  - Rerank 测试中的 Coding Plan v3 上游地址实际拼接为 `https://ark.cn-beijing.volces.com/api/coding/v3/rerank`。
- **状态**：已完成。

### 5. 渠道失败隔离

- **类型**：缺陷修复
- **需求来源**：[GitHub Issue #585](https://github.com/cita-777/metapi/issues/585)
- **目标**：一个渠道失败时，只更新实际失败渠道的冷却和失败状态，不影响同凭据的其他渠道，也不误触发站点级运行时熔断。
- **实现范围**：
  - 429 用量限流只冷却本次实际失败的 channel。
  - 不再按同一凭据扩散 `cooldownUntil` 或失败状态。
  - 429 不再写入站点级运行时熔断；其他健康渠道仍可参与选择。
  - 成功恢复时只清理当前通道自身的失败状态。
- **主要文件**：
  - `src/server/services/tokenRouter.ts`
  - 相关 token router、proxy retry 和路由健康状态测试文件
- **验证**：
  - 单线程 Vitest 覆盖限流失败、普通失败、成功恢复和站点熔断边界。
  - 验证结论：失败通道进入冷却，同凭据其他通道不扩散，429 不写入站点级熔断。
- **状态**：已完成。

### 6. 需求文档和演示交付物

- **类型**：文档与交付物
- **需求来源**：本会话中提供的四个 GitHub Issue
- **实现范围**：
  - 需求说明：[docs/plans/github-issues-591-590-586-585.md](plans/github-issues-591-590-586-585.md)
  - 网页演示 PDF：`output/pdf/metapi-issues-demo-2026-08-03.pdf`
  - PDF 包含当前 run 页面截图、站点独立并发、路由 P0、Rerank 请求示例、Coding Plan v3 和渠道失败隔离说明。
- **验证**：
  - 前端 `http://127.0.0.1:5174/` 返回 HTTP 200。
  - 后端 `http://127.0.0.1:4000/health` 返回 HTTP 200。
  - PDF 已渲染检查，共 6 页，中文正文和接口示例可读。
- **状态**：已完成。

### 7. 汇总验证

- `npm run typecheck:server`：通过
- `npm run typecheck:web`：通过
- `npm run typecheck:web:test`：通过
- `npm run test:schema:unit`：通过
- `npm run repo:drift-check`：通过
- 相关 Rerank、endpoint flow、路由优先级、tokenRouter、站点并发测试：使用单线程 Vitest 通过
- 说明：本机并行 Vitest worker 曾出现 OOM/UNKNOWN，后续复测优先使用：

```powershell
npx vitest run --pool=threads --poolOptions.threads.singleThread=true <test-file>
```

### 8. 建立持续变更日志

- **类型**：文档维护
- **需求来源**：本会话需求
- **目标**：把功能、修复、测试和交付物集中记录，作为后续改动的唯一开发日志。
- **实现范围**：新增本文件 `docs/change-log.md`，并提供 Issue 链接、文件路径、验证结果和后续追加模板。
- **状态**：已完成；后续每次代码或文档变更都追加到本文件。

## 2026-08-21

### 9. 提交到上游仓库的独立分支

- **类型**：版本交付
- **需求来源**：本会话需求：[Metapi 仓库](https://github.com/cita-777/metapi)
- **目标**：将本地已完成的站点独立并发、Rerank 和四个 Issue 修复提交到上游仓库的独立分支，不直接修改 `main`。
- **实现范围**：以远程 `main` 为基线创建 `codex/metapi-issues-591-590-586-585`，迁移代码、测试、数据库迁移产物、需求文档、持续日志和演示 PDF。
- **主要文件**：
  - `src/server/routes/proxy/rerank.ts`
  - `src/server/services/proxyChannelCoordinator.ts`
  - `src/server/services/tokenRouter.ts`
  - `src/server/db/schema.ts`
  - `docs/change-log.md`
- **验证**：`npm run typecheck:server`、`npm run typecheck:web`、`npm run typecheck:web:test`、`npm run test:schema:unit`、`npm run repo:drift-check` 均通过；相关聚焦测试通过，`tokenRouter.selection.test.ts` 单独运行 26/26 通过。
- **提交**：本地提交 `02e2308`（`feat: add proxy fixes and per-site concurrency`）。
- **推送结果**：未推送；GitHub 返回 `403 Permission to cita-777/metapi.git denied to lengxiaouser`，当前凭据对该仓库没有写权限；远程分支尚未创建。
- **状态**：代码已验证并在本地分支就绪，等待具备该仓库写权限的凭据后重试。

### 10. 创建 Fork 并准备 Pull Request

- **类型**：版本交付
- **需求来源**：本会话需求
- **目标**：通过个人 Fork 提交变更，避免直接写入上游仓库。
- **实现范围**：已创建 [lengxiaouser/metapi](https://github.com/lengxiaouser/metapi) Fork，目标分支为 `codex/metapi-issues-591-590-586-585`，PR 基线为上游 `main`。
- **验证**：Fork 的 `main` 已通过 Git 远程读取确认，功能分支已成功推送。
- **状态**：已完成。

### 11. 创建上游 Pull Request

- **类型**：版本交付
- **需求来源**：本会话需求
- **目标**：请求上游仓库审核本次站点并发控制、Rerank 及四个 Issue 修复。
- **实现范围**：创建 [PR #609](https://github.com/cita-777/metapi/pull/609)，源分支为 `lengxiaouser:codex/metapi-issues-591-590-586-585`，目标为 `cita-777:main`。
- **验证**：GitHub API 返回 PR 编号 `609`，状态为 `open`；PR 描述已包含 Issue 链接、验证命令和变更范围。
- **状态**：已提交，等待上游审核。

## 2026-08-22

### 12. 修复 CodeRabbit PR 审查问题

- **类型**：缺陷修复与架构重构
- **需求来源**：CodeRabbit 对 [PR #609](https://github.com/cita-777/metapi/pull/609) 的审查；对应 Issue：[ #591](https://github.com/cita-777/metapi/issues/591)、[#590](https://github.com/cita-777/metapi/issues/590)、[#586](https://github.com/cita-777/metapi/issues/586)、[#585](https://github.com/cita-777/metapi/issues/585)
- **目标**：修复站点并发租约释放、并发超时误判、路由通道优先级竞态、Rerank 路由职责过重和变更日志字段不完整等问题。
- **实现范围**：
  - 流式响应交接后暂停后台续租，按真实读取进度续租；读取失败先取消 reader，再释放站点租约。
  - 为本地站点排队超时增加显式 `siteConcurrencyTimeout` 标记，统一由 `sharedSurface.ts` 分类，避免把真实上游 503 当成站点排队超时。
  - 新增 `routeChannelService.ts`，用进程内串行锁和数据库事务统一处理自动通道、批量通道、单通道和批量优先级写入，并统一清理路由决策缓存。
  - 新增 `rerankSurface.ts`，通过 `executeEndpointFlow()` 承担 Rerank 的站点地址池、首字节超时、上游请求、用量计费、日志和失败重试；路由文件只保留校验与委托。
  - 修正 Rerank 记录：只有成功响应解析用量并计费，失败只写失败状态日志，费用和用量为零/未知不代表已发生计费。
- **主要文件**：
  - `src/server/services/proxyChannelCoordinator.ts`
  - `src/server/services/siteApiEndpointService.ts`
  - `src/server/proxy-core/surfaces/sharedSurface.ts`
  - `src/server/proxy-core/surfaces/chatSurface.ts`
  - `src/server/proxy-core/surfaces/openAiResponsesSurface.ts`
  - `src/server/proxy-core/surfaces/geminiSurface.ts`
  - `src/server/proxy-core/surfaces/rerankSurface.ts`
  - `src/server/routes/proxy/rerank.ts`
  - `src/server/services/routeChannelService.ts`
  - `src/server/routes/api/tokens.ts`
  - `docs/change-log.md`
- **验证**：
  - `npm run typecheck:server`：通过。
  - `npx vitest run --pool=threads --poolOptions.threads.singleThread=true src/server/routes/proxy/rerank.test.ts src/server/services/siteApiEndpointService.test.ts src/server/services/proxyChannelCoordinator.test.ts`：通过，26 个测试通过。
  - 路由优先级与共享 surface 回归测试：通过，`tokens.batch.test.ts`、`tokens.route-update-rebuild.test.ts` 共 21 个测试，`sharedSurface.test.ts` 与 `sharedSurface.usage-source.test.ts` 共 24 个测试。
  - Rerank 测试实际验证上游 URL 为 `https://ark.cn-beijing.volces.com/api/coding/v3/rerank`、请求体转发和成功日志；测试环境的 quota best-effort 查询因未创建 `accounts` 表输出告警，但不影响请求结果。
  - `npm run typecheck:web`：通过。
  - `npm run typecheck:web:test`：通过。
  - `npm run test:schema:unit`：通过，15 个测试通过。
  - `npm run repo:drift-check`：通过，新增违规 0 个；报告中的 5 项为既有 tracked debt。
- **交付物**：本地 checkout 中的修复代码和本变更日志；无新增 PDF 或截图。
- **状态**：已完成，等待提交并更新 PR。

## 后续记录模板

复制下面模板追加到对应日期下，先记录需求来源，再补充实际实现和验证结果：

```md
### YYYY-MM-DD - 简短标题

- **类型**：功能实现 / 缺陷修复 / 重构 / 文档
- **需求来源**：[Issue #N](https://github.com/cita-777/metapi/issues/N) 或本会话需求
- **目标**：
- **实现范围**：
- **主要文件**：
  - `path/to/file`
- **验证**：
- **交付物**：代码、文档、PDF、截图等；没有交付物时填写“无”。
- **状态**：进行中 / 已完成 / 阻塞
```
