# 后端开发规范

本规范描述仓库中当前维护的 Fastify 服务端、代理运行时、数据库层和后端测试。内容来源于 `AGENTS.md`、`CONTRIBUTING.md`、`docs/project-structure.md` 以及当前源码树；如果任务涉及 Trellis 脚本或 hook，另读 [Trellis 运行时契约](../guides/trellis-runtime-contract.md)。

## 规范索引

| 规范 | 用途 | 维护中的示例 |
| --- | --- | --- |
| [目录结构](./directory-structure.md) | 选择逻辑所有权边界和文件位置 | `src/server/index.ts`、`src/server/routes/`、`src/server/proxy-core/` |
| [数据库规范](./database-guidelines.md) | Drizzle 查询、迁移、兼容处理和生成 SQL | `src/server/db/schema.ts`、`src/server/db/migrate.ts` |
| [错误处理](./error-handling.md) | 校验、领域错误、代理失败和 HTTP 响应 | `src/server/contracts/`、`src/server/proxy-core/orchestration/`、`src/server/routes/api/` |
| [日志规范](./logging-guidelines.md) | 请求日志、后台日志、代理可观测性和脱敏 | `src/server/config.ts`、`src/server/services/proxyLogStore.ts` |
| [质量规范](./quality-guidelines.md) | 类型检查、测试、架构检查和评审门禁 | `package.json`、`src/server/**/*.architecture.test.ts` |

平台 adapter 的继承关系和差异以 `src/server/services/platforms/base.ts`、`standardApiProvider.ts`、`oneApi.ts`、`veloera.ts`、`oneHub.ts`、`doneHub.ts` 为准。`OneApiAdapter` 与 `VeloeraAdapter` 都直接继承 `BasePlatformAdapter`，不能在任务设计中把它们写成 `StandardApiProviderAdapterBase` 的子类。

## 开发前检查

修改后端代码之前：

1. 阅读上方相关规范，以及 `AGENTS.md` 中的仓库级规则。
2. 确认逻辑所属层。路由是适配器；编排属于 `proxy-core`，业务逻辑属于 `services`，协议转换属于 `transformers`，持久化属于 `db`。
3. 新增实现前，先搜索已有 helper、contract、workflow 或失败词汇。
4. 对请求 payload，在使用 `request.body` 前先检查或扩展 `src/server/contracts/` 中对应的 Zod parser。
5. 对 schema 变更，将 Drizzle schema、迁移历史、生成产物和 parity 测试作为一个整体规划。
6. 对代理变更，同时追踪流式与整包响应路径，并在编辑路由前检查 endpoint/retry 所有权测试。

## 质量检查

迭代时运行最小相关检查，交付前再运行完整门禁：

```bash
npm run typecheck:server
npm test
npm run repo:drift-check
git diff --check
```

数据库变更还必须运行 schema unit/parity 测试，并重新生成 `src/server/db/generated/`。跨越 web 或 desktop 边界的变更，必须运行前端质量规范中列出的对应 typecheck/build 命令。

## 事实来源

各规范列出的代码和测试才是权威来源。本规范记录当前约定，也包含仍然存在的兼容 shim 和旧有 `any` 用法；这不表示遗留代码已经完成重构。
