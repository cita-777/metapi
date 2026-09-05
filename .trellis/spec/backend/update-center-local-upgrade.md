# 更新中心本地升级规范

本规范约束 Metapi 在 Docker/Compose 中使用持久化 runtime 卷完成服务器
Release Bundle 的检查、安装、重启确认和回滚。它是跨服务端、Runner、发布制品
和前端状态的代码契约；不适用于桌面 Electron 更新，也不允许恢复 K3s、Helm、
Kubectl 或 Deploy Helper 路径。

## 1. Scope / Trigger

- Trigger：修改更新中心 API、`updateCenter*Service`、`scripts/runtime/docker-runner.mjs`、
  Release Bundle 构建、`docker/Dockerfile`、Compose runtime 卷或对应前端状态时，必须
  同步遵守本规范。
- Scope：官方 GitHub Release 发现、Linux `amd64`/`arm64` Bundle、Node 25 运行时、
  `runtime/current` 与 `runtime/previous` 指针、持久化事务状态、健康确认和一次性
  自动回滚。
- Non-scope：任意用户提供的下载源、Docker Socket/CLI、特权容器、Bun/Node SEA、
  Windows/macOS 服务器 Bundle、多节点滚动发布和数据库自动降级。
- Owner：路由只负责 Zod 解析、授权和 HTTP 映射；下载、解包、校验、锁、切换和
  回滚由 `src/server/services/updateCenterLocalUpdateService.ts` 负责；跨重启状态由
  `updateCenterRuntimeStateService.ts` 负责；PID 1 生命周期由稳定 Runner 负责。

## 2. Signatures

### Service

```ts
getUpdateCenterRuntimeCapability(input?): Promise<UpdateCenterRuntimeCapability>
getUpdateCenterLocalStatus(runtimeDir?): Promise<{
  capability: UpdateCenterRuntimeCapability;
  state: UpdateCenterRuntimeState;
  pending: UpdateCenterPendingState | null;
  installedVersions: UpdateCenterInstalledVersion[];
}>
installUpdateCenterRelease(input: UpdateCenterInstallInput): Promise<UpdateCenterInstallResult>
rollbackUpdateCenter(input?: UpdateCenterRollbackInput): Promise<UpdateCenterRollbackResult>
markUpdateCenterHealthy(runtimeDir?): Promise<UpdateCenterRuntimeState>
markUpdateCenterFailed(error, runtimeDir?): Promise<UpdateCenterRuntimeState>
rollbackPendingUpdateCenter(error?, runtimeDir?): Promise<UpdateCenterRuntimeState>
```

`installUpdateCenterRelease` 和 `rollbackUpdateCenter` 成功时都返回
`restartRequired: true`；服务不得在当前进程仍运行时把候选版本标记为最终健康。
`withUpdateCenterLock(runtimeDir, taskId, callback)` 是所有 runtime 写操作的互斥边界。

### HTTP API

| 方法与路径 | 请求 | 成功响应 |
| --- | --- | --- |
| `GET /healthz` | 无 | `{ status: "ok", ready: true, version }` |
| `GET /api/update-center/status` | 无 | `UpdateCenterStatusResult` |
| `POST /api/update-center/check` | 无或 `{}` | 最新 `UpdateCenterStatusResult` |
| `PUT /api/update-center/config` | `{ enabled?, channel?, autoCheck? }` | `{ success: true, config }` |
| `POST /api/update-center/deploy` | `{ targetVersion? }`，兼容 `targetTag` | `202 { success: true, reused, task }` |
| `POST /api/update-center/rollback` | `{ targetVersion? }`，兼容 `targetRevision` | `202 { success: true, reused, task }` |
| `GET /api/update-center/tasks/:id/stream` | 无 | SSE `log` 与终止 `done` 事件 |

`source`、`targetDigest` 等已移除字段必须由 contract 以 `400` 拒绝。更新和回滚
分别使用各自的后台任务 dedupe key，避免回滚请求错误复用正在执行的升级任务；
runtime 文件锁仍是跨操作的最终互斥边界。SSE 在进程重启时可以断开，客户端应根据
持久化 status 继续轮询。

### Runner

```text
node scripts/runtime/docker-runner.mjs
```

Runner 是容器 PID 1，使用 `UPDATE_CENTER_RUNTIME_DIR`（默认 `/app/runtime`）、
`METAPI_BOOTSTRAP_DIR`（默认 `/app/bootstrap`）和 `PORT`。它把
`METAPI_RELEASE_ROOT`、`METAPI_RELEASE_VERSION` 和 runtime 路径传给子进程，转发
`SIGTERM`/`SIGINT`，先运行 `migrationEntrypoint`，再运行 `entrypoint`。

## 3. Contracts

### Runtime layout

```text
<runtime>/
├── releases/<stable-version>/release.json + payload
├── staging/<task-id>/
├── current -> releases/<stable-version>
├── previous -> releases/<stable-version>
├── pending.json
├── state.json
├── .persistent
└── .update.lock
```

- runtime 根目录、`releases` 和 `staging` 必须是真实目录，不能是符号链接。
- `current`/`previous` 必须是相对链接，目标只能是 `releases/<normalized-version>`；
  目标 release 目录和 `release.json` 必须是普通文件/目录，realpath 必须仍位于
  runtime 的 `releases` 下。
- 指针通过同一文件系统的临时链接加 `rename` 原子替换；下载、解包或校验失败
  不得改变 `current`。
- `.persistent` 标记或 `UPDATE_CENTER_RUNTIME_PERSISTENT=true` 才能声明持久化；
  官方 Compose/Dockerfile 必须挂载 `/app/runtime` 并写入该标记。

### Release Bundle and manifest

正式资产固定为：

- `metapi-server-v<version>-linux-amd64.tar.gz`
- `metapi-server-v<version>-linux-arm64.tar.gz`
- `checksums.txt`

归档应包含 `dist/server/index.js`、`dist/server/db/migrate.js`、`dist/web/**`、
`drizzle/**`、运行时 `node_modules/**`、`package.json` 和 `release.json`。Manifest
至少包含：

```json
{
  "schemaVersion": 1,
  "version": "1.2.3",
  "channel": "stable",
  "platform": "linux",
  "arch": "amd64",
  "nodeMajor": 25,
  "entrypoint": "dist/server/index.js",
  "migrationEntrypoint": "dist/server/db/migrate.js",
  "artifactName": "metapi-server-v1.2.3-linux-amd64.tar.gz",
  "artifactSha256": "<sha256>",
  "gitSha": "<optional>"
}
```

Bundle 由 esbuild 以 `platform=node`、ESM、`target=node25` 构建；动态运行依赖和
`better-sqlite3` 保留在生产依赖树中，并必须在目标 Linux 架构的原生 Node 25 runner
上构建。`artifactSha256` 是 Bundle payload hash；归档 hash 仍由外部
`checksums.txt` 校验，不能混用。

入口合并后不得假设原始 TypeScript 模块层级仍存在。Runner 必须向迁移和服务器进程
传递 `METAPI_RELEASE_ROOT`；数据库迁移、`drizzle` 文件和 generated schema artifact
统一从该根目录解析，并保留源码布局作为开发环境 fallback。

### State and transaction

`pending.json` 使用 `schemaVersion: 1`，必须有纯三段稳定 SemVer 的 `targetVersion`、
可空的 `previousVersion`、合法 `taskId`、阶段 `downloading | staging | switching |
restarting | health-check`、时间戳和安全整数 `rollbackBudget`（只允许 `0` 或 `1`）。
应用侧与 Runner 必须使用相同的解析规则；明确损坏的 JSON、目录或符号链接应清理，
瞬时读取错误不得误删文件。安装默认预算为 `1`，手动回滚为 `0`；Runner 消耗预算后
不得再次自动回滚。

`state.json` 是跨重启唯一事实来源，`updateState` 使用
`idle/checking/downloading/staging/switching/restarting/healthy/failed/rolled_back/
unsupported`；同时保存当前/上一版本、安装列表、`restartPending`、任务编号、最后
错误和最近 Release 快照。异步 Release 检查与通知只能 patch 自己拥有的字段，禁止把
早先读取的完整 state snapshot 写回，以免覆盖同时进行的升级阶段。数据库仅保存
`{ enabled, channel: "stable", autoCheck }` 配置与通知偏好。

### Discovery and security

- Release 源固定为 `cita-777/metapi` 的 GitHub API；只接受非 draft、非 prerelease 的
  稳定 SemVer。
- 下载必须是 HTTPS、无凭据/自定义端口，且每一跳重定向 host 都在
  `github.com`、`api.github.com`、`objects.githubusercontent.com`、
  `release-assets.githubusercontent.com` 或 `github-releases.githubusercontent.com`。
- 归档下载上限为 512 MiB；解包前后限制条目数和展开大小，并拒绝绝对路径、父级
  跳转、反斜杠路径、符号链接、硬链接、设备文件等危险项。
- 安装前校验 checksum、资产名、manifest 版本/架构/Node 主版本、入口文件和原生
  addon；未通过时保留旧指针。

## 4. Validation & Error Matrix

| 条件 | 必须结果 | 允许的领域错误/HTTP |
| --- | --- | --- |
| 非 Linux、非 `amd64`/`arm64`、Node 非 25 | capability `supported=false`，不下载 | `UNSUPPORTED_PLATFORM`、`UNSUPPORTED_ARCHITECTURE`、`NODE_VERSION_MISMATCH`；API `409` |
| runtime 未持久化、不可写或布局含危险链接 | 不创建更新事务、不改指针 | `RUNTIME_NOT_PERSISTENT`、`RUNTIME_NOT_WRITABLE`、`RUNTIME_PATH_UNSAFE`；API `409` |
| body 缺失/未知字段/移除字段 | route 立即拒绝 | `400`，稳定 `message` |
| target 不是稳定 SemVer | 不启动后台任务 | `400`、`INVALID_VERSION` |
| 官方 Release/架构资产/checksum 不存在 | 保持 `current` | `RELEASE_NOT_FOUND`、`ASSET_NOT_FOUND`、`CHECKSUM_MISSING` |
| URL 非 HTTPS、host 不在 allowlist、重定向越界 | 不写入归档 | `INVALID_DOWNLOAD_URL`、`INSECURE_DOWNLOAD_URL`、`UNTRUSTED_DOWNLOAD_HOST`、`DOWNLOAD_REDIRECT` |
| 超过 512 MiB、展开上限或危险 tar entry | 删除 staging，不改指针 | `DOWNLOAD_TOO_LARGE`、`ARCHIVE_TOO_LARGE`、`UNSAFE_ARCHIVE`、`ARCHIVE_INVALID` |
| hash、资产名、manifest、native addon 不匹配 | 删除候选 release，不改指针 | `CHECKSUM_MISMATCH`、`ASSET_MISMATCH`、`VERSION_MISMATCH`、`ARCHITECTURE_MISMATCH`、`INVALID_MANIFEST` |
| 已有锁或 restart pending | 不并发写 runtime | `UPDATE_IN_PROGRESS` 或 API `409`；同类后台任务可复用，升级与回滚不得互相复用 |
| 指针切换失败 | 清理未切换 staging/release，旧版本继续服务 | `POINTER_SWITCH_FAILED`、`UPDATE_FAILED` |
| 候选迁移失败、退出或 60 秒内 `/healthz` 版本不匹配 | Runner 原子切回 previous，预算减为 0 | `failed` → `rolled_back`；不得自动恢复数据库 |
| 无 previous 或预算已耗尽 | 停止重试，保留诊断 | `failed`，Runner 退出，避免循环 |
| SSE 客户端断开或 response 已关闭 | 只清理订阅/定时器，`write`/`end` 不再冒泡 | 不改变后台任务结果；客户端读取 `state.json` 映射的 status |

## 5. Good / Base / Bad Cases

- Good：runtime 有持久卷且标记为持久化；服务下载官方匹配架构资产，流式校验后在
  `staging/<task-id>` 安全解包，写入 pending，再原子切换；Runner 迁移并确认
  `/healthz` 的 `version` 后清 pending、标记 `healthy`，保留 current/previous。
- Base：首次启动 runtime 为空时，Runner 从镜像内置 bootstrap Bundle 初始化；容器
  重建仍从卷恢复更高版本，旧版本只在未受保护时按保留策略清理。
- Bad：把 GitHub URL 交给 UI 任意配置、直接覆盖 current 目录、在容器内调用 Docker
  CLI、把候选进程健康当作原进程已升级，或让旧 K3s 配置的 `enabled=true` 自动继承。

## 6. Tests Required

- `updateCenterLocalUpdateService.test.ts`：下载上限、HTTPS/allowlist/重定向、checksum、
  tar 路径安全、manifest/架构/Node/native addon、锁、原子指针、重复安装、回滚和
  保留策略；断言失败时 `current` 未改变。
- `updateCenterLocalUpdateService.architecture.test.ts`：service 所有权、旧 Helper/K3s
  文件不存在和禁止的依赖方向。
- `updateCenterRuntimeStateService.test.ts`：JSON 原子写入、state/pending 归一化、
  pointer realpath 边界、损坏状态清理和持久化标记。
- `scripts/runtime/docker-runner.test.ts`：bootstrap、manifest 校验、信号/健康轮询、
  pending reconcile、一次性回滚和危险 releases 链接。
- `build-server-bundle.test.ts`：资产命名、Node 25 manifest、amd64/arm64 目标、无
  `.d.ts`/stale Helper/K3s 产物，并在目标 runner 验证 `better-sqlite3` 加载。
- API route 测试：config、invalid/兼容 payload、能力不支持、同类/跨类后台 dedupe、
  202/409、`/healthz` 和 response close 后的 SSE `log/done`；前端测试覆盖 unsupported
  禁用、重复 check single-flight、SSE unmount abort 和重启后状态轮询。
- 交付门禁：`npm run typecheck`、`npm run build`、`npm run repo:drift-check`、
  `npm test`、`npm run docs:build`、`git diff --check`。本机 Darwin/Node 22 只能作为
  代码检查证据，不能替代 Linux/Node 25 原生 Bundle 验收。

## 7. Wrong vs Correct

### Wrong

```text
路由读取 targetTag 后直接执行 Helm/Kubectl，或下载 UI 提供的 URL 并覆盖
runtime/current；子进程返回 200 就把更新标记为成功，未保存 pending/previous。
```

### Correct

```text
route -> Zod parser -> background task -> local update service
      -> official Release/HTTPS+checksum -> staging -> manifest/native checks
      -> pending.json -> atomic current/previous switch -> SIGTERM
      -> stable Runner migration + /healthz(version) -> healthy 或一次 rollback
```

路由不拥有下载、重试、解包或持久化；Runner 不调用 Docker API；所有跨重启结论都
从 `state.json`/`pending.json` 和真实指针重新读取。
