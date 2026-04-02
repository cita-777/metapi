import Fastify, { type FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { eq } from 'drizzle-orm';
import { PgDialect } from 'drizzle-orm/pg-core';

type DbModule = typeof import('../../db/index.js');

describe('downstream api keys routes', () => {
  let app: FastifyInstance;
  let db: DbModule['db'];
  let schema: DbModule['schema'];
  let dataDir = '';

  beforeAll(async () => {
    dataDir = mkdtempSync(join(tmpdir(), 'metapi-downstream-routes-'));
    process.env.DATA_DIR = dataDir;

    await import('../../db/migrate.js');
    const dbModule = await import('../../db/index.js');
    const routesModule = await import('./downstreamApiKeys.js');
    db = dbModule.db;
    schema = dbModule.schema;

    app = Fastify();
    await app.register(routesModule.downstreamApiKeysRoutes);
  });

  beforeEach(async () => {
    await db.delete(schema.proxyLogs).run();
    await db.delete(schema.downstreamApiKeys).run();
    await db.delete(schema.tokenRoutes).run();
    await db.delete(schema.sites).run();
  });

  afterAll(async () => {
    await app.close();
    delete process.env.DATA_DIR;
  });

  it('builds postgres trend buckets by casting text timestamps before date_trunc', async () => {
    const routesModule = await import('./downstreamApiKeys.js') as Record<string, any>;

    expect(typeof routesModule.buildBucketTsExpressionForDialect).toBe('function');

    const expression = routesModule.buildBucketTsExpressionForDialect('postgres', schema.proxyLogs.createdAt, 3600);
    const rendered = new PgDialect().sqlToQuery(expression).sql;

    expect(rendered).toContain('date_trunc');
    expect(rendered).toContain('cast');
    expect(rendered).toContain('timestamp');
  });

  it('creates, updates, resets and deletes downstream api keys', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'portal-site',
      url: 'https://portal.example.com',
      status: 'active',
      platform: 'openai',
    }).returning().get();
    const route = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-5.2',
      displayName: 'portal-route',
      enabled: true,
    }).returning().get();

    const createRes = await app.inject({
      method: 'POST',
      url: '/api/downstream-keys',
      payload: {
        name: 'portal-key',
        key: 'sk-portal-key-001',
        description: 'portal consumer',
        groupName: '项目A',
        tags: ['移动端', 'VIP'],
        enabled: true,
        maxCost: 12.5,
        maxRequests: 500,
        supportedModels: ['gpt-5.2', 'claude-sonnet-4-5'],
        allowedRouteIds: [route.id],
        siteWeightMultipliers: { [site.id]: 1.2 },
      },
    });

    expect(createRes.statusCode).toBe(200);
    const createdBody = createRes.json();
    expect(createdBody.success).toBe(true);
    expect(createdBody.item).toMatchObject({
      name: 'portal-key',
      keyMasked: expect.any(String),
      groupName: '项目A',
      tags: ['移动端', 'VIP'],
      maxCost: 12.5,
      maxRequests: 500,
      supportedModels: ['gpt-5.2', 'claude-sonnet-4-5'],
      allowedRouteIds: [route.id],
    });

    const keyId = createdBody.item.id as number;

    const updateRes = await app.inject({
      method: 'PUT',
      url: `/api/downstream-keys/${keyId}`,
      payload: {
        name: 'portal-key-updated',
        key: 'sk-portal-key-001',
        groupName: '项目B',
        tags: ['批量候选', 'VIP'],
        enabled: false,
        maxCost: 20,
        maxRequests: 900,
      },
    });

    expect(updateRes.statusCode).toBe(200);
    expect(updateRes.json()).toMatchObject({
      success: true,
      item: {
        id: keyId,
        name: 'portal-key-updated',
        groupName: '项目B',
        tags: ['批量候选', 'VIP'],
        enabled: false,
        maxCost: 20,
        maxRequests: 900,
      },
    });

    await db.update(schema.downstreamApiKeys).set({
      usedCost: 5.5,
      usedRequests: 123,
    }).where(eq(schema.downstreamApiKeys.id, keyId)).run();

    const resetRes = await app.inject({
      method: 'POST',
      url: `/api/downstream-keys/${keyId}/reset-usage`,
    });

    expect(resetRes.statusCode).toBe(200);
    expect(resetRes.json()).toMatchObject({ success: true });

    const resetRow = await db.select().from(schema.downstreamApiKeys)
      .where(eq(schema.downstreamApiKeys.id, keyId))
      .get();
    expect(resetRow?.usedCost).toBe(0);
    expect(resetRow?.usedRequests).toBe(0);

    const deleteRes = await app.inject({
      method: 'DELETE',
      url: `/api/downstream-keys/${keyId}`,
    });

    expect(deleteRes.statusCode).toBe(200);
    expect(deleteRes.json()).toMatchObject({ success: true });

    const listRes = await app.inject({
      method: 'GET',
      url: '/api/downstream-keys',
    });
    expect(listRes.statusCode).toBe(200);
    expect(listRes.json()).toMatchObject({ success: true, items: [] });
  });

  it('clears nullable editor fields when updating a downstream api key', async () => {
    const createRes = await app.inject({
      method: 'POST',
      url: '/api/downstream-keys',
      payload: {
        name: 'editor-key',
        key: 'sk-editor-key-001',
        description: 'editor consumer',
        groupName: '项目A',
        enabled: true,
        expiresAt: '2026-12-31T00:00:00.000Z',
        maxCost: 12.5,
        maxRequests: 500,
      },
    });

    expect(createRes.statusCode).toBe(200);
    const keyId = (createRes.json() as { item: { id: number } }).item.id;

    const updateRes = await app.inject({
      method: 'PUT',
      url: `/api/downstream-keys/${keyId}`,
      payload: {
        name: 'editor-key-updated',
        key: 'sk-editor-key-001',
        description: '',
        groupName: null,
        enabled: true,
        expiresAt: null,
        maxCost: null,
        maxRequests: null,
      },
    });

    expect(updateRes.statusCode).toBe(200);
    expect(updateRes.json()).toMatchObject({
      success: true,
      item: {
        id: keyId,
        name: 'editor-key-updated',
        description: null,
        groupName: null,
        expiresAt: null,
        maxCost: null,
        maxRequests: null,
      },
    });

    const row = await db.select().from(schema.downstreamApiKeys)
      .where(eq(schema.downstreamApiKeys.id, keyId))
      .get();
    expect(row).toMatchObject({
      name: 'editor-key-updated',
      description: null,
      groupName: null,
      expiresAt: null,
      maxCost: null,
      maxRequests: null,
    });
  });

  it('supports batch enable/disable/reset/delete operations', async () => {
    const inserted = await db.insert(schema.downstreamApiKeys).values([
      {
        name: 'batch-a',
        key: 'sk-batch-a-001',
        enabled: true,
        usedCost: 1.2,
        usedRequests: 12,
      },
      {
        name: 'batch-b',
        key: 'sk-batch-b-001',
        enabled: false,
        usedCost: 2.4,
        usedRequests: 24,
      },
    ]).returning().all();

    const disableRes = await app.inject({
      method: 'POST',
      url: '/api/downstream-keys/batch',
      payload: {
        ids: [inserted[0].id, inserted[1].id],
        action: 'disable',
      },
    });
    expect(disableRes.statusCode).toBe(200);
    expect(disableRes.json()).toMatchObject({
      success: true,
      successIds: [inserted[0].id, inserted[1].id],
      failedItems: [],
    });

    const disabledRows = await db.select().from(schema.downstreamApiKeys).all();
    expect(disabledRows.every((row) => row.enabled === false)).toBe(true);

    const resetRes = await app.inject({
      method: 'POST',
      url: '/api/downstream-keys/batch',
      payload: {
        ids: [inserted[0].id, inserted[1].id],
        action: 'resetUsage',
      },
    });
    expect(resetRes.statusCode).toBe(200);
    const resetRows = await db.select().from(schema.downstreamApiKeys).all();
    expect(resetRows.every((row) => Number(row.usedCost) === 0 && Number(row.usedRequests) === 0)).toBe(true);

    const deleteRes = await app.inject({
      method: 'POST',
      url: '/api/downstream-keys/batch',
      payload: {
        ids: [inserted[0].id, inserted[1].id],
        action: 'delete',
      },
    });
    expect(deleteRes.statusCode).toBe(200);
    expect(await db.select().from(schema.downstreamApiKeys).all()).toHaveLength(0);
  });

  it('supports batch metadata update for group and tags', async () => {
    const inserted = await db.insert(schema.downstreamApiKeys).values([
      {
        name: 'meta-a',
        key: 'sk-meta-a-001',
        groupName: '旧分组',
        tags: JSON.stringify(['旧标签']),
        enabled: true,
      },
      {
        name: 'meta-b',
        key: 'sk-meta-b-001',
        tags: JSON.stringify(['旧标签', '公共']),
        enabled: true,
      },
    ]).returning().all();

    const res = await app.inject({
      method: 'POST',
      url: '/api/downstream-keys/batch',
      payload: {
        ids: inserted.map((item) => item.id),
        action: 'updateMetadata',
        groupOperation: 'set',
        groupName: '新分组',
        tagOperation: 'append',
        tags: ['项目A', '公共'],
      },
    });

    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({
      success: true,
      successIds: inserted.map((item) => item.id),
      failedItems: [],
    });

    const rows = await db.select().from(schema.downstreamApiKeys).all();
    expect(rows).toHaveLength(2);
    for (const row of rows) {
      expect(row.groupName).toBe('新分组');
    }
    const views = rows.map((row) => ({
      id: row.id,
      groupName: row.groupName,
      tags: JSON.parse(String(row.tags || '[]')),
    }));
    expect(views).toContainEqual(expect.objectContaining({ tags: ['旧标签', '项目A', '公共'] }));
    expect(views).toContainEqual(expect.objectContaining({ tags: ['旧标签', '公共', '项目A'] }));
  });

  it('rejects duplicate key creation and invalid batch action', async () => {
    const firstRes = await app.inject({
      method: 'POST',
      url: '/api/downstream-keys',
      payload: {
        name: 'dup-a',
        key: 'sk-dup-key-001',
      },
    });
    expect(firstRes.statusCode).toBe(200);

    const duplicateRes = await app.inject({
      method: 'POST',
      url: '/api/downstream-keys',
      payload: {
        name: 'dup-b',
        key: 'sk-dup-key-001',
      },
    });
    expect(duplicateRes.statusCode).toBe(409);
    expect(duplicateRes.json()).toMatchObject({
      success: false,
      message: 'API key 已存在',
    });

    const invalidBatchRes = await app.inject({
      method: 'POST',
      url: '/api/downstream-keys/batch',
      payload: {
        ids: [999],
        action: 'archive',
      },
    });
    expect(invalidBatchRes.statusCode).toBe(400);
    expect(invalidBatchRes.json()).toMatchObject({
      success: false,
      message: 'Invalid action',
    });
  });

  it('rejects duplicate key update with conflict status', async () => {
    const firstRes = await app.inject({
      method: 'POST',
      url: '/api/downstream-keys',
      payload: {
        name: 'dup-a',
        key: 'sk-dup-key-001',
      },
    });
    expect(firstRes.statusCode).toBe(200);

    const secondRes = await app.inject({
      method: 'POST',
      url: '/api/downstream-keys',
      payload: {
        name: 'dup-b',
        key: 'sk-dup-key-002',
      },
    });
    expect(secondRes.statusCode).toBe(200);

    const secondId = secondRes.json().item.id as number;
    const duplicateUpdateRes = await app.inject({
      method: 'PUT',
      url: `/api/downstream-keys/${secondId}`,
      payload: {
        name: 'dup-b-updated',
        key: 'sk-dup-key-001',
      },
    });

    expect(duplicateUpdateRes.statusCode).toBe(409);
    expect(duplicateUpdateRes.json()).toMatchObject({
      success: false,
      message: 'API key 已存在',
    });
  });

  it('rejects malformed create, update, and batch payloads at the route boundary', async () => {
    const invalidCreateRes = await app.inject({
      method: 'POST',
      url: '/api/downstream-keys',
      payload: {
        name: 'bad-create',
        key: 'sk-bad-create-001',
        enabled: 'false',
      },
    });
    expect(invalidCreateRes.statusCode).toBe(400);
    expect(invalidCreateRes.json()).toMatchObject({
      success: false,
      message: 'Invalid enabled. Expected boolean.',
    });

    const createRes = await app.inject({
      method: 'POST',
      url: '/api/downstream-keys',
      payload: {
        name: 'shape-ok',
        key: 'sk-shape-ok-001',
      },
    });
    expect(createRes.statusCode).toBe(200);
    const keyId = createRes.json().item.id as number;

    const invalidUpdateRes = await app.inject({
      method: 'PUT',
      url: `/api/downstream-keys/${keyId}`,
      payload: {
        tags: ['valid', 123],
      },
    });
    expect(invalidUpdateRes.statusCode).toBe(400);
    expect(invalidUpdateRes.json()).toMatchObject({
      success: false,
      message: 'Invalid tags. Expected string or string[].',
    });

    const invalidBatchRes = await app.inject({
      method: 'POST',
      url: '/api/downstream-keys/batch',
      payload: {
        ids: [String(keyId)],
        action: 'disable',
      },
    });
    expect(invalidBatchRes.statusCode).toBe(400);
    expect(invalidBatchRes.json()).toMatchObject({
      success: false,
      message: 'Invalid ids. Expected number[].',
    });
  });

  it('returns summary, overview and trend aggregated from proxy logs', async () => {
    const inserted = await db.insert(schema.downstreamApiKeys).values({
      name: 'analytics-key',
      key: 'sk-analytics-key-001',
      enabled: true,
      description: 'analytics',
      usedCost: 0,
      usedRequests: 0,
    }).returning().get();

    const now = Date.now();
    const within24h = new Date(now - 2 * 60 * 60 * 1000).toISOString();
    const within7d = new Date(now - 2 * 24 * 60 * 60 * 1000).toISOString();
    const outside7d = new Date(now - 10 * 24 * 60 * 60 * 1000).toISOString();

    await db.insert(schema.proxyLogs).values([
      {
        downstreamApiKeyId: inserted.id,
        status: 'success',
        totalTokens: 1200,
        estimatedCost: 0.12,
        createdAt: within24h,
      },
      {
        downstreamApiKeyId: inserted.id,
        status: 'failed',
        totalTokens: 300,
        estimatedCost: 0.03,
        createdAt: within24h,
      },
      {
        downstreamApiKeyId: inserted.id,
        status: 'success',
        totalTokens: 600,
        estimatedCost: 0.06,
        createdAt: within7d,
      },
      {
        downstreamApiKeyId: inserted.id,
        status: 'success',
        totalTokens: 900,
        estimatedCost: 0.09,
        createdAt: outside7d,
      },
    ]).run();

    const summaryRes = await app.inject({
      method: 'GET',
      url: '/api/downstream-keys/summary?range=24h&status=enabled&search=analytics',
    });

    expect(summaryRes.statusCode).toBe(200);
    expect(summaryRes.json()).toMatchObject({
      success: true,
      range: '24h',
      status: 'enabled',
      search: 'analytics',
      group: '',
      tags: [],
      tagMatch: 'any',
      items: [
        {
          id: inserted.id,
          name: 'analytics-key',
          rangeUsage: {
            totalRequests: 2,
            successRequests: 1,
            failedRequests: 1,
            successRate: 50,
            totalTokens: 1500,
            totalCost: 0.15,
          },
        },
      ],
    });

    const overviewRes = await app.inject({
      method: 'GET',
      url: `/api/downstream-keys/${inserted.id}/overview`,
    });

    expect(overviewRes.statusCode).toBe(200);
    expect(overviewRes.json()).toMatchObject({
      success: true,
      item: { id: inserted.id, name: 'analytics-key' },
      usage: {
        last24h: {
          totalRequests: 2,
          successRequests: 1,
          failedRequests: 1,
          totalTokens: 1500,
          totalCost: 0.15,
        },
        last7d: {
          totalRequests: 3,
          successRequests: 2,
          failedRequests: 1,
          totalTokens: 2100,
          totalCost: 0.21,
        },
        all: {
          totalRequests: 4,
          successRequests: 3,
          failedRequests: 1,
          totalTokens: 3000,
          totalCost: 0.3,
        },
      },
    });

    const trendRes = await app.inject({
      method: 'GET',
      url: `/api/downstream-keys/${inserted.id}/trend?range=all`,
    });

    expect(trendRes.statusCode).toBe(200);
    const trendBody = trendRes.json();
    expect(trendBody.success).toBe(true);
    expect(trendBody.range).toBe('all');
    expect(trendBody.item).toMatchObject({ id: inserted.id, name: 'analytics-key' });
    expect(Array.isArray(trendBody.buckets)).toBe(true);
    expect(trendBody.buckets.length).toBeGreaterThanOrEqual(3);
    expect(trendBody.buckets.some((bucket: any) => bucket.totalTokens === 1500)).toBe(true);
    expect(trendBody.buckets.some((bucket: any) => bucket.totalTokens === 600)).toBe(true);
    expect(trendBody.buckets.some((bucket: any) => bucket.totalTokens === 900)).toBe(true);
  });

  it('rejects unknown route ids and site ids in downstream policy payloads', async () => {
    const createRes = await app.inject({
      method: 'POST',
      url: '/api/downstream-keys',
      payload: {
        name: 'invalid-policy',
        key: 'sk-invalid-policy-001',
        allowedRouteIds: [999],
      },
    });
    expect(createRes.statusCode).toBe(400);
    expect(createRes.json()).toMatchObject({
      success: false,
      message: 'allowedRouteIds 包含不存在的路由: 999',
    });

    const site = await db.insert(schema.sites).values({
      name: 'site-a',
      url: 'https://example.com',
      status: 'active',
      platform: 'openai',
    }).returning().get();
    const route = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-5.2',
      enabled: true,
    }).returning().get();
    const created = await app.inject({
      method: 'POST',
      url: '/api/downstream-keys',
      payload: {
        name: 'valid-policy',
        key: 'sk-valid-policy-001',
        allowedRouteIds: [route.id],
        siteWeightMultipliers: { [site.id]: 1.2 },
      },
    });
    expect(created.statusCode).toBe(200);
    const keyId = created.json().item.id as number;

    const updateRes = await app.inject({
      method: 'PUT',
      url: `/api/downstream-keys/${keyId}`,
      payload: {
        siteWeightMultipliers: { 999: 1.5 },
      },
    });
    expect(updateRes.statusCode).toBe(400);
    expect(updateRes.json()).toMatchObject({
      success: false,
      message: 'siteWeightMultipliers 包含不存在的站点: 999',
    });

    const filteredSummaryRes = await app.inject({
      method: 'GET',
      url: '/api/downstream-keys/summary?range=all&group=__ungrouped__&tags=foo,bar&tagMatch=all',
    });
    expect(filteredSummaryRes.statusCode).toBe(200);
    expect(filteredSummaryRes.json()).toMatchObject({
      success: true,
      range: 'all',
      group: '__ungrouped__',
      tags: ['foo', 'bar'],
      tagMatch: 'all',
      items: [],
    });
  });
});
