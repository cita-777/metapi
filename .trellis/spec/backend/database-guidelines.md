# 后端数据库规范

## 数据库模型

Metapi 使用 Drizzle ORM，`src/server/db/schema.ts` 中以 SQLite 形态为规范 schema。运行时通过 `src/server/db/index.ts` 中的 adapter 支持 SQLite（`better-sqlite3`）、MySQL 和 PostgreSQL。SQLite 是默认数据库（`DATA_DIR`/`DB_URL`），运行时设置可在启动后切换当前 dialect。TypeScript 字段名保持 camelCase，数据库 table/column/index 名保持 snake_case，例如 `sites.createdAt` 映射到 `created_at`，索引名为 `sites_platform_url_unique`。

## 查询模式

使用共享的 `db`/`schema` 导出和 Drizzle builder：

```ts
const row = await db
  .select()
  .from(schema.accounts)
  .where(eq(schema.accounts.id, accountId))
  .get();

const rows = await db
  .select()
  .from(schema.sites)
  .where(eq(schema.sites.status, 'active'))
  .all();
```

单个可选记录使用 `.get()`，集合使用 `.all()`，写操作使用 `.run()`。复用 `src/server/db/insertHelpers.ts` 中的 `insertAndGetById()`/`getInsertedRowId()`；生产服务端代码不得调用 Drizzle `.returning()`，也不得在 db 层以外读取 `lastInsertRowid`。可执行守卫是 `src/server/db/returning.architecture.test.ts`。

多次写入必须原子收敛时使用 `db.transaction()`。例如 `src/server/services/accountManualModelService.ts` 中的 `removeManualModelsFromAccount()` 会在一个 transaction 内验证账号并删除其记录，待 transaction 成功后再执行路由重建。

重复操作使用共享跨 dialect helper。`src/server/db/upsertSetting.ts` 中的 `upsertSetting()` 只在 Drizzle MySQL builder 不同时才分支；不要把 dialect 特定 upsert 复制进路由。

## Schema 变更与迁移

一次 schema 变更必须同步产生三类输出：

1. 更新 `src/server/db/schema.ts`。
2. 使用 `npm run db:generate` 生成并审查 `drizzle/` 下一个 SQL 文件。
3. 使用 `npm run schema:generate` 重新生成纳入版本控制的 contract 和非 SQLite 产物，包括 `src/server/db/generated/schemaContract.json`、`mysql.bootstrap.sql`、`mysql.upgrade.sql`、`postgres.bootstrap.sql` 和 `postgres.upgrade.sql`。

使用 `npm run db:migrate` 执行迁移；`src/server/db/migrate.ts` 中的实现还处理旧版 SQLite journal 和严格限定的重复列恢复。不要在 feature route 中手写第二套完整 schema。

规范 contract 由 `src/server/db/schemaContract.ts` 从 migration SQL 构建。外部数据库的运行时升级是 additive，并由 `schemaArtifactGenerator.ts` 生成；`siteSchemaCompatibility.ts`、`routeGroupingSchemaCompatibility.ts`、`proxyFileSchemaCompatibility.ts` 等兼容模块可以添加范围严格受限的遗留列或索引。它们造成的 mutation 必须反映在 contract 中，并由 parity 测试覆盖。

## 关系约定

- 在 `schema.ts` 中声明 foreign key 和删除行为；当前 table 会在适当位置显式使用 `ON DELETE CASCADE` 或 `SET NULL`。
- 为常用过滤和时序查询添加命名索引，沿用 `accounts_site_status_idx`、`proxy_logs_created_at_idx` 等命名方式。
- JSON 类型的设置/metadata 以序列化文本存储（或在生成 dialect 中使用 schema 声明的 JSON 类型），并在 service 边界解析。
- 时间戳使用仓库统一的 UTC SQL 字符串格式；写入需要显式时间值时使用 `formatUtcSqlDateTime()`。

## 应避免的常见错误

- 只更新 `schema.ts`，忘记 `drizzle/` 或生成产物。
- 在 feature code 中直接加入 MySQL/PostgreSQL DDL，而不是修改 contract generator 或 feature 自有的兼容规范。
- 使用 `.returning()`，或假设 `lastInsertRowid` 在所有 dialect 上都可用。
- 绕开 `src/server/db/index.ts` 再打开一个数据库连接。
- 在 transaction 尚未提交时执行路由重建或其他外部副作用。

## 验证

涉及 schema 时至少运行：

```bash
npm run test:schema:unit
npm run test:schema:parity
npm run test:schema:upgrade
npm run test:schema:runtime
npm run repo:drift-check
```

实时 MySQL/PostgreSQL 测试需要已配置的外部服务；如果服务不可用，应记录为 blocked，不能把跳过的 live test 当作 parity 已证实。
