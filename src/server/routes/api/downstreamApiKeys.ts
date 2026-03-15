import { FastifyInstance } from 'fastify';
import { and, eq, inArray, sql, type SQL } from 'drizzle-orm';
import { db, hasProxyLogDownstreamApiKeyIdColumn, runtimeDbDialect, schema } from '../../db/index.js';
import {
  getDownstreamApiKeyById,
  listDownstreamApiKeys,
  normalizeDownstreamApiKeyPayload,
  toDownstreamApiKeyPolicyView,
  toPersistenceJson,
} from '../../services/downstreamApiKeyService.js';
import { formatUtcSqlDateTime } from '../../services/localTimeService.js';

function parseRouteId(raw: string): number | null {
  const id = Number.parseInt(raw, 10);
  if (!Number.isFinite(id) || id <= 0) return null;
  return id;
}

function validateKeyShape(key: string): boolean {
  return key.startsWith('sk-') && key.length >= 6;
}

function looksLikeUniqueViolation(error: unknown): boolean {
  const message = (error as Error | undefined)?.message || '';
  return message.includes('UNIQUE constraint failed') && message.includes('downstream_api_keys.key');
}

function normalizeBatchIds(raw: unknown): number[] {
  const values = Array.isArray(raw) ? raw : [];
  const ids: number[] = [];
  for (const item of values) {
    const parsed = Number(item);
    if (!Number.isFinite(parsed)) continue;
    const id = Math.trunc(parsed);
    if (id <= 0 || ids.includes(id)) continue;
    ids.push(id);
    if (ids.length >= 500) break;
  }
  return ids;
}

type DownstreamKeyRange = '24h' | '7d' | 'all';
type DownstreamKeyStatus = 'all' | 'enabled' | 'disabled';

function normalizeDownstreamKeyRange(raw: unknown): DownstreamKeyRange {
  const value = typeof raw === 'string' ? raw.trim().toLowerCase() : '';
  if (value === '24h') return '24h';
  if (value === '7d') return '7d';
  if (value === 'all') return 'all';
  return '24h';
}

function normalizeDownstreamKeyStatus(raw: unknown): DownstreamKeyStatus {
  const value = typeof raw === 'string' ? raw.trim().toLowerCase() : '';
  if (value === 'enabled') return 'enabled';
  if (value === 'disabled') return 'disabled';
  return 'all';
}

function normalizeSearchQuery(raw: unknown): string {
  const value = typeof raw === 'string' ? raw.trim() : '';
  if (!value) return '';
  return value.slice(0, 80);
}

function resolveRangeSinceUtc(range: DownstreamKeyRange): string | null {
  const nowTs = Date.now();
  if (range === '24h') return formatUtcSqlDateTime(new Date(nowTs - 24 * 60 * 60 * 1000));
  if (range === '7d') return formatUtcSqlDateTime(new Date(nowTs - 7 * 24 * 60 * 60 * 1000));
  return null;
}

function resolveBucketSeconds(range: DownstreamKeyRange): number {
  return range === 'all' ? 86400 : 3600;
}

function resolveBucketTsExpression(bucketSeconds: number) {
  if (runtimeDbDialect === 'mysql') {
    return sql<number>`floor(unix_timestamp(${schema.proxyLogs.createdAt}) / ${bucketSeconds}) * ${bucketSeconds}`;
  }
  if (runtimeDbDialect === 'postgres') {
    if (bucketSeconds === 86400) {
      return sql<number>`extract(epoch from date_trunc('day', ${schema.proxyLogs.createdAt}))::bigint`;
    }
    return sql<number>`extract(epoch from date_trunc('hour', ${schema.proxyLogs.createdAt}))::bigint`;
  }
  // sqlite
  return sql<number>`cast(cast(strftime('%s', ${schema.proxyLogs.createdAt}) as integer) / ${bucketSeconds} as integer) * ${bucketSeconds}`;
}

async function validatePolicyReferences(input: {
  allowedRouteIds: number[];
  siteWeightMultipliers: Record<number, number>;
}): Promise<string | null> {
  const routeIds = input.allowedRouteIds || [];
  if (routeIds.length > 0) {
    const rows = await db.select({ id: schema.tokenRoutes.id })
      .from(schema.tokenRoutes)
      .where(inArray(schema.tokenRoutes.id, routeIds))
      .all();
    const existingIds = new Set(rows.map((row) => Number(row.id)));
    const missingIds = routeIds.filter((id) => !existingIds.has(id));
    if (missingIds.length > 0) {
      return `allowedRouteIds 包含不存在的路由: ${missingIds.join(', ')}`;
    }
  }

  const siteIds = Object.keys(input.siteWeightMultipliers || {})
    .map((key) => Number(key))
    .filter((value) => Number.isFinite(value) && value > 0)
    .map((value) => Math.trunc(value));
  if (siteIds.length > 0) {
    const rows = await db.select({ id: schema.sites.id })
      .from(schema.sites)
      .where(inArray(schema.sites.id, siteIds))
      .all();
    const existingIds = new Set(rows.map((row) => Number(row.id)));
    const missingIds = siteIds.filter((id) => !existingIds.has(id));
    if (missingIds.length > 0) {
      return `siteWeightMultipliers 包含不存在的站点: ${missingIds.join(', ')}`;
    }
  }

  return null;
}

export async function downstreamApiKeysRoutes(app: FastifyInstance) {
  app.get<{ Querystring: { range?: string; status?: string; search?: string } }>('/api/downstream-keys/summary', async (request) => {
    const range = normalizeDownstreamKeyRange(request.query?.range);
    const status = normalizeDownstreamKeyStatus(request.query?.status);
    const search = normalizeSearchQuery(request.query?.search);

    const whereClauses: SQL[] = [];
    if (status === 'enabled') {
      whereClauses.push(eq(schema.downstreamApiKeys.enabled, true));
    } else if (status === 'disabled') {
      whereClauses.push(eq(schema.downstreamApiKeys.enabled, false));
    }
    if (search) {
      const pattern = `%${search.toLowerCase()}%`;
      whereClauses.push(sql`(lower(${schema.downstreamApiKeys.name}) like ${pattern} or lower(coalesce(${schema.downstreamApiKeys.description}, '')) like ${pattern})`);
    }

    let keysQuery = db.select().from(schema.downstreamApiKeys);
    if (whereClauses.length > 0) {
      keysQuery = keysQuery.where(and(...whereClauses));
    }
    const keys = (await keysQuery.all())
      .map((row) => toDownstreamApiKeyPolicyView(row))
      .sort((a, b) => b.id - a.id);

    if (keys.length === 0) {
      return { success: true, range, status, search, items: [] };
    }

    const columnReady = await hasProxyLogDownstreamApiKeyIdColumn();
    const sinceUtc = resolveRangeSinceUtc(range);
    const ids = keys.map((k) => k.id);

    const usageRows = columnReady
      ? await db.select({
        keyId: schema.proxyLogs.downstreamApiKeyId,
        totalRequests: sql<number>`count(*)`,
        successRequests: sql<number>`coalesce(sum(case when ${schema.proxyLogs.status} = 'success' then 1 else 0 end), 0)`,
        failedRequests: sql<number>`coalesce(sum(case when ${schema.proxyLogs.status} = 'success' then 0 else 1 end), 0)`,
        totalTokens: sql<number>`coalesce(sum(coalesce(${schema.proxyLogs.totalTokens}, 0)), 0)`,
        totalCost: sql<number>`coalesce(sum(coalesce(${schema.proxyLogs.estimatedCost}, 0)), 0)`,
      })
        .from(schema.proxyLogs)
        .where(and(
          inArray(schema.proxyLogs.downstreamApiKeyId, ids),
          ...(sinceUtc ? [sql`${schema.proxyLogs.createdAt} >= ${sinceUtc}`] : []),
        ))
        .groupBy(schema.proxyLogs.downstreamApiKeyId)
        .all()
      : [];

    const usageByKey = new Map<number, {
      totalRequests: number;
      successRequests: number;
      failedRequests: number;
      totalTokens: number;
      totalCost: number;
    }>();

    for (const row of usageRows) {
      const keyId = Number((row as any).keyId ?? 0);
      if (!Number.isFinite(keyId) || keyId <= 0) continue;
      usageByKey.set(keyId, {
        totalRequests: Number((row as any).totalRequests || 0),
        successRequests: Number((row as any).successRequests || 0),
        failedRequests: Number((row as any).failedRequests || 0),
        totalTokens: Number((row as any).totalTokens || 0),
        totalCost: Number((row as any).totalCost || 0),
      });
    }

    return {
      success: true,
      range,
      status,
      search,
      items: keys.map((key) => {
        const usage = usageByKey.get(key.id) || {
          totalRequests: 0,
          successRequests: 0,
          failedRequests: 0,
          totalTokens: 0,
          totalCost: 0,
        };
        const successRate = usage.totalRequests > 0
          ? Math.round((usage.successRequests / usage.totalRequests) * 1000) / 10
          : null;
        return {
          ...key,
          rangeUsage: {
            totalRequests: usage.totalRequests,
            successRequests: usage.successRequests,
            failedRequests: usage.failedRequests,
            successRate,
            totalTokens: usage.totalTokens,
            totalCost: Math.round(usage.totalCost * 1_000_000) / 1_000_000,
          },
        };
      }),
    };
  });

  app.get<{ Params: { id: string } }>('/api/downstream-keys/:id/overview', async (request, reply) => {
    const id = parseRouteId(request.params.id);
    if (!id) {
      return reply.code(400).send({ success: false, message: 'id 无效' });
    }

    const item = await getDownstreamApiKeyById(id);
    if (!item) {
      return reply.code(404).send({ success: false, message: 'API key 不存在' });
    }

    const columnReady = await hasProxyLogDownstreamApiKeyIdColumn();
    if (!columnReady) {
      return { success: true, item, usage: { last24h: null, last7d: null, all: null } };
    }

    const readAggregate = async (range: DownstreamKeyRange) => {
      const sinceUtc = resolveRangeSinceUtc(range);
      const row = await db.select({
        totalRequests: sql<number>`count(*)`,
        successRequests: sql<number>`coalesce(sum(case when ${schema.proxyLogs.status} = 'success' then 1 else 0 end), 0)`,
        failedRequests: sql<number>`coalesce(sum(case when ${schema.proxyLogs.status} = 'success' then 0 else 1 end), 0)`,
        totalTokens: sql<number>`coalesce(sum(coalesce(${schema.proxyLogs.totalTokens}, 0)), 0)`,
        totalCost: sql<number>`coalesce(sum(coalesce(${schema.proxyLogs.estimatedCost}, 0)), 0)`,
      })
        .from(schema.proxyLogs)
        .where(and(
          eq(schema.proxyLogs.downstreamApiKeyId, id),
          ...(sinceUtc ? [sql`${schema.proxyLogs.createdAt} >= ${sinceUtc}`] : []),
        ))
        .get();

      const totalRequests = Number((row as any)?.totalRequests || 0);
      const successRequests = Number((row as any)?.successRequests || 0);
      const totalCost = Number((row as any)?.totalCost || 0);
      return {
        totalRequests,
        successRequests,
        failedRequests: Number((row as any)?.failedRequests || 0),
        successRate: totalRequests > 0 ? Math.round((successRequests / totalRequests) * 1000) / 10 : null,
        totalTokens: Number((row as any)?.totalTokens || 0),
        totalCost: Math.round(totalCost * 1_000_000) / 1_000_000,
      };
    };

    const [last24h, last7d, all] = await Promise.all([
      readAggregate('24h'),
      readAggregate('7d'),
      readAggregate('all'),
    ]);

    return { success: true, item, usage: { last24h, last7d, all } };
  });

  app.get<{ Params: { id: string }; Querystring: { range?: string } }>('/api/downstream-keys/:id/trend', async (request, reply) => {
    const id = parseRouteId(request.params.id);
    if (!id) {
      return reply.code(400).send({ success: false, message: 'id 无效' });
    }

    const range = normalizeDownstreamKeyRange(request.query?.range);
    const item = await getDownstreamApiKeyById(id);
    if (!item) {
      return reply.code(404).send({ success: false, message: 'API key 不存在' });
    }

    const columnReady = await hasProxyLogDownstreamApiKeyIdColumn();
    if (!columnReady) {
      return { success: true, range, item: { id: item.id, name: item.name }, buckets: [] };
    }

    const bucketSeconds = resolveBucketSeconds(range);
    const bucketTs = resolveBucketTsExpression(bucketSeconds);
    const sinceUtc = resolveRangeSinceUtc(range);

    const rows = await db.select({
      bucketTs,
      totalRequests: sql<number>`count(*)`,
      successRequests: sql<number>`coalesce(sum(case when ${schema.proxyLogs.status} = 'success' then 1 else 0 end), 0)`,
      failedRequests: sql<number>`coalesce(sum(case when ${schema.proxyLogs.status} = 'success' then 0 else 1 end), 0)`,
      totalTokens: sql<number>`coalesce(sum(coalesce(${schema.proxyLogs.totalTokens}, 0)), 0)`,
      totalCost: sql<number>`coalesce(sum(coalesce(${schema.proxyLogs.estimatedCost}, 0)), 0)`,
    })
      .from(schema.proxyLogs)
      .where(and(
        eq(schema.proxyLogs.downstreamApiKeyId, id),
        ...(sinceUtc ? [sql`${schema.proxyLogs.createdAt} >= ${sinceUtc}`] : []),
      ))
      .groupBy(bucketTs)
      .orderBy(bucketTs)
      .all();

    return {
      success: true,
      range,
      item: { id: item.id, name: item.name },
      bucketSeconds,
      buckets: rows.map((row: any) => {
        const tsSeconds = Number(row.bucketTs || 0);
        const totalRequests = Number(row.totalRequests || 0);
        const successRequests = Number(row.successRequests || 0);
        return {
          startUtc: tsSeconds > 0 ? new Date(tsSeconds * 1000).toISOString() : null,
          totalRequests,
          successRequests,
          failedRequests: Number(row.failedRequests || 0),
          successRate: totalRequests > 0 ? Math.round((successRequests / totalRequests) * 1000) / 10 : null,
          totalTokens: Number(row.totalTokens || 0),
          totalCost: Math.round(Number(row.totalCost || 0) * 1_000_000) / 1_000_000,
        };
      }),
    };
  });

  app.get('/api/downstream-keys', async () => {
    return {
      success: true,
      items: await listDownstreamApiKeys(),
    };
  });

  app.post<{
    Body: {
      name?: unknown;
      key?: unknown;
      description?: unknown;
      enabled?: unknown;
      expiresAt?: unknown;
      maxCost?: unknown;
      maxRequests?: unknown;
      supportedModels?: unknown;
      allowedRouteIds?: unknown;
      siteWeightMultipliers?: unknown;
    };
  }>('/api/downstream-keys', async (request, reply) => {
    let normalized: ReturnType<typeof normalizeDownstreamApiKeyPayload>;
    try {
      normalized = normalizeDownstreamApiKeyPayload(request.body || {});
    } catch (error: unknown) {
      return reply.code(400).send({ success: false, message: (error as Error)?.message || '参数无效' });
    }

    if (!normalized.name) {
      return reply.code(400).send({ success: false, message: 'name 不能为空' });
    }
    if (!normalized.key) {
      return reply.code(400).send({ success: false, message: 'key 不能为空' });
    }
    if (!validateKeyShape(normalized.key)) {
      return reply.code(400).send({ success: false, message: 'key 必须以 sk- 开头且长度至少 6' });
    }
    const policyRefError = await validatePolicyReferences({
      allowedRouteIds: normalized.allowedRouteIds,
      siteWeightMultipliers: normalized.siteWeightMultipliers,
    });
    if (policyRefError) {
      return reply.code(400).send({ success: false, message: policyRefError });
    }

    const nowIso = new Date().toISOString();

    try {
      const insertedResult = await db.insert(schema.downstreamApiKeys).values({
        name: normalized.name,
        key: normalized.key,
        description: normalized.description,
        enabled: normalized.enabled,
        expiresAt: normalized.expiresAt,
        maxCost: normalized.maxCost,
        usedCost: 0,
        maxRequests: normalized.maxRequests,
        usedRequests: 0,
        supportedModels: toPersistenceJson(normalized.supportedModels),
        allowedRouteIds: toPersistenceJson(normalized.allowedRouteIds),
        siteWeightMultipliers: toPersistenceJson(normalized.siteWeightMultipliers),
        createdAt: nowIso,
        updatedAt: nowIso,
      }).run();
      const insertedId = Number(insertedResult.lastInsertRowid || 0);
      if (insertedId <= 0) {
        return reply.code(500).send({ success: false, message: '创建失败' });
      }
      const inserted = await db.select().from(schema.downstreamApiKeys)
        .where(eq(schema.downstreamApiKeys.id, insertedId))
        .get();
      if (!inserted) {
        return reply.code(500).send({ success: false, message: '创建失败' });
      }

      return {
        success: true,
        item: toDownstreamApiKeyPolicyView(inserted),
      };
    } catch (error: unknown) {
      if (looksLikeUniqueViolation(error)) {
        return reply.code(409).send({ success: false, message: 'API key 已存在' });
      }
      return reply.code(500).send({ success: false, message: (error as Error)?.message || '创建失败' });
    }
  });

  app.put<{
    Params: { id: string };
    Body: {
      name?: unknown;
      key?: unknown;
      description?: unknown;
      enabled?: unknown;
      expiresAt?: unknown;
      maxCost?: unknown;
      maxRequests?: unknown;
      supportedModels?: unknown;
      allowedRouteIds?: unknown;
      siteWeightMultipliers?: unknown;
    };
  }>('/api/downstream-keys/:id', async (request, reply) => {
    const id = parseRouteId(request.params.id);
    if (!id) {
      return reply.code(400).send({ success: false, message: 'id 无效' });
    }

    const existing = await db.select().from(schema.downstreamApiKeys)
      .where(eq(schema.downstreamApiKeys.id, id))
      .get();

    if (!existing) {
      return reply.code(404).send({ success: false, message: 'API key 不存在' });
    }

    const existingView = toDownstreamApiKeyPolicyView(existing);
    let normalized: ReturnType<typeof normalizeDownstreamApiKeyPayload>;
    try {
      normalized = normalizeDownstreamApiKeyPayload({
        name: request.body?.name ?? existing.name,
        key: request.body?.key ?? existing.key,
        description: request.body?.description ?? existing.description,
        enabled: request.body?.enabled ?? existing.enabled,
        expiresAt: request.body?.expiresAt ?? existing.expiresAt,
        maxCost: request.body?.maxCost ?? existing.maxCost,
        maxRequests: request.body?.maxRequests ?? existing.maxRequests,
        supportedModels: request.body?.supportedModels ?? existingView.supportedModels,
        allowedRouteIds: request.body?.allowedRouteIds ?? existingView.allowedRouteIds,
        siteWeightMultipliers: request.body?.siteWeightMultipliers ?? existingView.siteWeightMultipliers,
      });
    } catch (error: unknown) {
      return reply.code(400).send({ success: false, message: (error as Error)?.message || '参数无效' });
    }

    if (!normalized.name) {
      return reply.code(400).send({ success: false, message: 'name 不能为空' });
    }
    if (!normalized.key) {
      return reply.code(400).send({ success: false, message: 'key 不能为空' });
    }
    if (!validateKeyShape(normalized.key)) {
      return reply.code(400).send({ success: false, message: 'key 必须以 sk- 开头且长度至少 6' });
    }
    const policyRefError = await validatePolicyReferences({
      allowedRouteIds: normalized.allowedRouteIds,
      siteWeightMultipliers: normalized.siteWeightMultipliers,
    });
    if (policyRefError) {
      return reply.code(400).send({ success: false, message: policyRefError });
    }

    const nowIso = new Date().toISOString();
    try {
      await db.update(schema.downstreamApiKeys).set({
        name: normalized.name,
        key: normalized.key,
        description: normalized.description,
        enabled: normalized.enabled,
        expiresAt: normalized.expiresAt,
        maxCost: normalized.maxCost,
        maxRequests: normalized.maxRequests,
        supportedModels: toPersistenceJson(normalized.supportedModels),
        allowedRouteIds: toPersistenceJson(normalized.allowedRouteIds),
        siteWeightMultipliers: toPersistenceJson(normalized.siteWeightMultipliers),
        updatedAt: nowIso,
      }).where(eq(schema.downstreamApiKeys.id, id)).run();

      const updated = await getDownstreamApiKeyById(id);
      return {
        success: true,
        item: updated,
      };
    } catch (error: unknown) {
      if (looksLikeUniqueViolation(error)) {
        return reply.code(409).send({ success: false, message: 'API key 已存在' });
      }
      return reply.code(500).send({ success: false, message: (error as Error)?.message || '更新失败' });
    }
  });

  app.post<{ Params: { id: string } }>('/api/downstream-keys/:id/reset-usage', async (request, reply) => {
    const id = parseRouteId(request.params.id);
    if (!id) {
      return reply.code(400).send({ success: false, message: 'id 无效' });
    }

    const existing = await getDownstreamApiKeyById(id);
    if (!existing) {
      return reply.code(404).send({ success: false, message: 'API key 不存在' });
    }

    await db.update(schema.downstreamApiKeys).set({
      usedCost: 0,
      usedRequests: 0,
      updatedAt: new Date().toISOString(),
    }).where(eq(schema.downstreamApiKeys.id, id)).run();

    return {
      success: true,
      item: await getDownstreamApiKeyById(id),
    };
  });

  app.delete<{ Params: { id: string } }>('/api/downstream-keys/:id', async (request, reply) => {
    const id = parseRouteId(request.params.id);
    if (!id) {
      return reply.code(400).send({ success: false, message: 'id 无效' });
    }

    const existing = await getDownstreamApiKeyById(id);
    if (!existing) {
      return reply.code(404).send({ success: false, message: 'API key 不存在' });
    }

    await db.delete(schema.downstreamApiKeys)
      .where(eq(schema.downstreamApiKeys.id, id))
      .run();

    return { success: true };
  });

  app.post<{ Body?: { ids?: number[]; action?: string } }>('/api/downstream-keys/batch', async (request, reply) => {
    const ids = normalizeBatchIds(request.body?.ids);
    const action = String(request.body?.action || '').trim();
    if (ids.length === 0) {
      return reply.code(400).send({ success: false, message: 'ids is required' });
    }
    if (!['enable', 'disable', 'delete', 'resetUsage'].includes(action)) {
      return reply.code(400).send({ success: false, message: 'Invalid action' });
    }

    const successIds: number[] = [];
    const failedItems: Array<{ id: number; message: string }> = [];

    for (const id of ids) {
      try {
        const existing = await getDownstreamApiKeyById(id);
        if (!existing) {
          failedItems.push({ id, message: 'API key 不存在' });
          continue;
        }

        if (action === 'delete') {
          await db.delete(schema.downstreamApiKeys)
            .where(eq(schema.downstreamApiKeys.id, id))
            .run();
        } else if (action === 'resetUsage') {
          await db.update(schema.downstreamApiKeys).set({
            usedCost: 0,
            usedRequests: 0,
            updatedAt: new Date().toISOString(),
          }).where(eq(schema.downstreamApiKeys.id, id)).run();
        } else {
          await db.update(schema.downstreamApiKeys).set({
            enabled: action === 'enable',
            updatedAt: new Date().toISOString(),
          }).where(eq(schema.downstreamApiKeys.id, id)).run();
        }

        successIds.push(id);
      } catch (error: any) {
        failedItems.push({ id, message: error?.message || 'Batch operation failed' });
      }
    }

    return {
      success: true,
      successIds,
      failedItems,
    };
  });
}
