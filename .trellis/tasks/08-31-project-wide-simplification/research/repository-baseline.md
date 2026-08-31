# Metapi 仓库基线调查

## 查询元数据

- **查询**：调查当前仓库的规模、运行时入口、依赖、测试门禁、数据库形态、Git 基线和 Trellis 任务状态。
- **范围**：`src/`、`drizzle/`、`scripts/`、`package.json`、`.trellis/`、`.codex/`；不修改产品代码，不把未提交产品 WIP 当作已验收结果。
- **日期**：2026-08-31（Asia/Shanghai）。
- **调查者**：`cita-777` session；当前分支为 `dev`。

## 可复现命令

以下命令在仓库根目录 `/Users/apple/code/metapi` 执行：

```bash
python3 ./.trellis/scripts/get_context.py
python3 ./.trellis/scripts/get_context.py --mode phase
python3 ./.trellis/scripts/get_context.py --mode packages
git status --short
git log --oneline -5
npm run repo:drift-check
npm run typecheck:web
npm run build:web
git diff --check
```

规模统计使用 `Path.rglob('*.ts'/'*.tsx')` 计算文件数和物理行数；CSS、页面热点和 `sqliteTable(` 使用 `rg`/`wc` 复核。构建数字来自本轮实际的 `vite build` 输出，不沿用旧任务文档中的估算。

## Git 与 Trellis 状态

- `HEAD`：`f4114ada6d797e668c83c1b3f68ca80f8c897863`，提交说明为 `fix: tolerate corrupted site announcement cache rows`。
- 当前工作树有约 71 个未提交路径，包含用户产品 WIP、`.agents/`、`.codex/`、`.trellis/`、IDE 状态和生成文件。它们均视为用户已有内容；本调查不清理、不覆盖、不提交。
- `.trellis/scripts/get_context.py` 报告为 single-repo，spec layers 为 `backend`、`frontend`；当前 session 没有自己的 `CURRENT TASK` 指针，但存在四个活动任务：一个 parent planning、两个 child in_progress、一个 child planning。
- 不要在本 session 为了制造指针运行 `task.py start`；其他 session 正在处理两个 child task，活动任务指针是 session-specific 的。

## 规模快照

本轮工作树实测如下（生成文件是否存在会影响少量行数）：

| 路径 | TypeScript/TSX 文件 | 行数 |
| --- | ---: | ---: |
| `src/server` | 648 | 187,574 |
| `src/web` | 280 | 77,035 |
| `src/desktop` | 7 | 912 |
| `src/shared` | 17 | 796 |
| `src/server/routes/api` | 79 | 34,230 |
| `src/server/routes/proxy` | 53 | 23,647 |
| `src/server/proxy-core` | 70 | 15,159 |
| `src/server/services` | 251 | 66,102 |
| `src/server/transformers` | 119 | 34,441 |
| `src/server/contracts` | 7 | 1,325 |
| `src/server/db` | 38 | 8,401 |
| `src/web/components` | 62 | 6,621 |
| `src/web/pages` | 193 | 64,697 |

页面热点（`wc -l`）为：`ProxyLogs.tsx` 3,832、`Accounts.tsx` 3,499、`ModelTester.tsx` 3,401、`Settings.tsx` 2,647、`Sites.tsx` 2,426、`TokenRoutes.tsx` 2,041、`Dashboard.tsx` 1,710、`DownstreamKeys.tsx` 1,415、`Models.tsx` 1,124、`OAuthManagement.tsx` 2,601。`style={{` 的文件级热点为 `Settings.tsx` 192、`ProxyLogs.tsx` 185、`Sites.tsx` 134、`Models.tsx` 119、`Accounts.tsx` 109、`ModelTester.tsx` 108、`DownstreamKeys.tsx` 82、`Dashboard.tsx` 64。

## 依赖和构建基线

- `package.json` 声明 Node `>=25.0.0`；本次本地命令使用 Node `v22.23.1`，因此完整产品验收不能只凭本地通过推断。
- 关键版本：React `18.3.1`、Vite `6.4.2`、Fastify `5.8.4`、Drizzle ORM `0.45.2`、`@radix-ui/react-dialog` `1.1.23`、`@visactor/react-vchart` `2.0.22`、Tailwind CSS `4.0.0`。
- 规划阶段的 `npm run build:web` 采样为：`2613 modules transformed`，约 `5.35s` 完成；CSS 为 `136.78 kB`（gzip `22.00 kB`），`vchart-vendor` 为 `2,154.02 kB`（gzip `586.81 kB`）。较大的路由 chunk 为 `TokenRoutes` `176.61 kB`、`Settings` `105.96 kB`、`ModelTester` `88.98 kB`、`DownstreamKeys` `65.48 kB`、`Accounts` `60.73 kB`、`Sites` `59.67 kB`、`ProxyLogs` `58.56 kB`；最终交付复核见 `docs/frontend-architecture.md` 与任务审计。
- 旧 `design.md` 记录的 `2548 modules/5.30s/2,145.97 kB` 已过时；后续报告应标明采样时间和工作树状态。
- `npm run repo:drift-check` 当前工作树实测为 `Violations: 0`、`Tracked debt: 0`。这只证明当前 checker 对当前文件集的结果，不证明未提交 WIP 已通过产品回归。

## Drift 基线口径

为避免把两个时期混为一谈，保留三种口径：

1. **当前工作树 + 当前 checker**：`0 violations / 0 tracked debt`。
2. **当前 checker 扫描 `HEAD` 归档**：`5 violations / 0 tracked debt`，路径为 `chatSurface.ts -> routes/proxy/downstreamPolicy.js`、`filesSurface.ts -> routes/proxy/multipart.js`、`geminiSurface.ts -> routes/proxy/downstreamPolicy.js`、`openAiResponsesSurface.ts -> routes/proxy/downstreamPolicy.js`、`Accounts.tsx -> ./Tokens.js`。
3. **历史 HEAD checker + 历史 allowlist**：早期任务材料把这五项记成 tracked debt。若要复现历史数字，必须使用 `HEAD` 版本的 `scripts/dev/repo-drift-check.ts`；不能用当前已删除 allowlist 的 checker 反推历史 debt 数字。

临时 HEAD 归档位于 `/tmp/metapi-head-JBtZz7`，仅用于本轮只读比较，不能写入任务 manifest，也不能视为发布产物。

## 数据库快照

- `src/server/db/schema.ts` 当前有 27 个 `sqliteTable` 声明；`drizzle/` 有 29 个 SQL migration 文件。
- migration 文件名存在两个 `0027`：`0027_site_custom_headers_override_request_headers.sql` 与 `0027_site_max_concurrency.sql`。这属于需要在 schema 任务中专门处理的事实，本轮不改名、不重排。
- `src/server/db/index.ts` 暴露 `RuntimeDbDialect = 'sqlite' | 'mysql' | 'postgres'`、`switchRuntimeDatabase()`、transaction wrapper 和 compatibility-column bootstrap；`src/server/index.ts:135-193` 在读取设置后执行 runtime DB 切换、兼容列、默认数据、OAuth backfill 和 route rebuild。
- 本轮没有修改 schema、migration 或 `src/server/db/generated/`；任何必须改 schema 的发现都应另建任务。

## 质量证据与限制

- `npm run typecheck:web` 和 `npm run build:web` 已在当前工作树执行并通过；构建前自动运行了 `desktop:icons`。
- `npm run repo:drift-check` 与 `git diff --check` 是文档/边界工作的最低门禁。
- 完整 `npm test` 不能在 Node 22 + 当前本机 native dependency 组合下直接当作产品验收；历史记录显示 `better-sqlite3` 可能出现 `NODE_MODULE_VERSION` 不匹配。需要在声明的 Node 版本下重建 native module 后再判断全量结果。
- 本轮没有真实生产网络、浏览器性能 trace、MySQL/PostgreSQL live service 或部署证据；chunk 数字是本地构建测量，不能替代线上 LCP/TTI 或服务健康证明。

## 对后续规范的约束

- 研究文档必须区分 `HEAD` 已确认事实、当前工作树事实、未提交候选实现和最终验收状态。
- 任何“已完成迁移”“debt 已清零”“性能已改善”的表述都必须附带对应测试、构建、drift 或运行时证据；仅有 source diff 不足以升级状态。
- 文档中的命令、路径、函数名、配置字段、协议名和 `status` 值保持原文；解释性正文使用简体中文。
