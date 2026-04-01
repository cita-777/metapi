import Fastify, { type FastifyInstance } from 'fastify';
import { describe, expect, it, beforeAll, beforeEach, afterAll } from 'vitest';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { mkdtempSync } from 'node:fs';
import { formatUtcSqlDateTime } from '../../services/localTimeService.js';

type DbModule = typeof import('../../db/index.js');

describe('stats proxy logs routes', () => {
  let app: FastifyInstance;
  let db: DbModule['db'];
  let schema: DbModule['schema'];
  let dataDir = '';

  beforeAll(async () => {
    dataDir = mkdtempSync(join(tmpdir(), 'metapi-stats-proxy-logs-'));
    process.env.DATA_DIR = dataDir;

    await import('../../db/migrate.js');
    const dbModule = await import('../../db/index.js');
    const routesModule = await import('./stats.js');
    db = dbModule.db;
    schema = dbModule.schema;

    app = Fastify();
    await app.register(routesModule.statsRoutes);
  });

  beforeEach(async () => {
    await db.delete(schema.proxyLogs).run();
    await db.delete(schema.downstreamApiKeys).run();
    await db.delete(schema.accounts).run();
    await db.delete(schema.sites).run();
  });

  afterAll(async () => {
    await app.close();
    delete process.env.DATA_DIR;
  });

  it('returns paginated proxy logs with server-side filters and summary metadata', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'proxy-site',
      url: 'https://proxy-site.example.com',
      platform: 'new-api',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'proxy-user',
      accessToken: 'proxy-token',
      status: 'active',
    }).returning().get();

    const downstreamKey = await db.insert(schema.downstreamApiKeys).values({
      name: '项目A-Key',
      key: 'sk-project-a-001',
      groupName: '项目A',
      tags: JSON.stringify(['VIP', '灰度']),
      enabled: true,
    }).returning().get();

    const timestamps = [
      formatUtcSqlDateTime(new Date('2026-03-09T08:00:00.000Z')),
      formatUtcSqlDateTime(new Date('2026-03-09T08:01:00.000Z')),
      formatUtcSqlDateTime(new Date('2026-03-09T08:02:00.000Z')),
      formatUtcSqlDateTime(new Date('2026-03-09T08:03:00.000Z')),
    ];

    await db.insert(schema.proxyLogs).values([
      {
        accountId: account.id,
        downstreamApiKeyId: downstreamKey.id,
        modelRequested: 'gpt-4o',
        modelActual: 'gpt-4o',
        status: 'success',
        clientFamily: 'generic',
        clientAppId: 'cherry_studio',
        clientAppName: 'Cherry Studio',
        clientConfidence: 'exact',
        promptTokens: 10,
        completionTokens: 5,
        totalTokens: 15,
        estimatedCost: 0.1,
        createdAt: timestamps[0],
        billingDetails: JSON.stringify({ id: 'success-gpt' }),
      },
      {
        accountId: account.id,
        downstreamApiKeyId: downstreamKey.id,
        modelRequested: 'gpt-4o-mini',
        modelActual: 'gpt-4o-mini',
        status: 'failed',
        clientFamily: 'codex',
        promptTokens: 8,
        completionTokens: 2,
        totalTokens: 10,
        estimatedCost: 0.2,
        createdAt: timestamps[1],
        billingDetails: JSON.stringify({ id: 'failed-gpt' }),
      },
      {
        accountId: account.id,
        modelRequested: 'gpt-4.1',
        modelActual: 'gpt-4.1',
        status: 'retried',
        promptTokens: 20,
        completionTokens: 4,
        totalTokens: 24,
        estimatedCost: 0.3,
        createdAt: timestamps[2],
        billingDetails: JSON.stringify({ id: 'retried-gpt' }),
      },
      {
        accountId: account.id,
        modelRequested: 'claude-3-7-sonnet',
        modelActual: 'claude-3-7-sonnet',
        status: 'success',
        promptTokens: 40,
        completionTokens: 10,
        totalTokens: 50,
        estimatedCost: 0.4,
        createdAt: timestamps[3],
        billingDetails: JSON.stringify({ id: 'success-claude' }),
      },
    ]).run();

    const response = await app.inject({
      method: 'GET',
      url: '/api/stats/proxy-logs?limit=1&offset=1&status=failed&search=gpt',
    });

    expect(response.statusCode).toBe(200);
    const body = response.json() as {
      items: Array<Record<string, unknown>>;
      total: number;
      page: number;
      pageSize: number;
      summary: {
        totalCount: number;
        successCount: number;
        failedCount: number;
        totalCost: number;
        totalTokensAll: number;
      };
      clientOptions: Array<{
        value: string;
        label: string;
      }>;
    };

    expect(body.page).toBe(2);
    expect(body.pageSize).toBe(1);
    expect(body.total).toBe(2);
    expect(body.items).toHaveLength(1);
    expect(body.items[0]?.modelRequested).toBe('gpt-4o-mini');
    expect(body.items[0]?.status).toBe('failed');
    expect(body.items[0]?.downstreamKeyName).toBe('项目A-Key');
    expect(body.items[0]?.downstreamKeyGroupName).toBe('项目A');
    expect(body.items[0]?.downstreamKeyTags).toEqual(['VIP', '灰度']);
    expect(body.items[0]?.clientFamily).toBe('codex');
    expect(body.items[0]?.clientAppId).toBe(null);
    expect(body.items[0]?.clientAppName).toBe(null);
    expect(body.items[0]?.clientConfidence).toBe(null);
    expect(body.items[0]).not.toHaveProperty('billingDetails');
    expect(body.clientOptions).toEqual([
      { value: 'family:codex', label: '协议 · Codex' },
    ]);
    expect(body.summary).toEqual({
      totalCount: 3,
      successCount: 1,
      failedCount: 2,
      totalCost: 0.6,
      totalTokensAll: 49,
    });
  });

  it('returns a single proxy log detail with parsed billing details', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'detail-site',
      url: 'https://detail-site.example.com',
      platform: 'new-api',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'detail-user',
      accessToken: 'detail-token',
      status: 'active',
    }).returning().get();

    const downstreamKey = await db.insert(schema.downstreamApiKeys).values({
      name: 'detail-key',
      key: 'sk-detail-key-001',
      groupName: '测试项目',
      tags: JSON.stringify(['回归', '日志']),
      enabled: true,
    }).returning().get();

    const inserted = await db.insert(schema.proxyLogs).values({
      accountId: account.id,
      downstreamApiKeyId: downstreamKey.id,
      modelRequested: 'gpt-5',
      modelActual: 'gpt-5',
      status: 'success',
      clientFamily: 'codex',
      clientAppId: 'cherry_studio',
      clientAppName: 'Cherry Studio',
      clientConfidence: 'exact',
      promptTokens: 100,
      completionTokens: 20,
      totalTokens: 120,
      estimatedCost: 0.12,
      errorMessage: 'downstream: /v1/chat upstream: /api/chat',
      createdAt: formatUtcSqlDateTime(new Date('2026-03-09T08:05:00.000Z')),
      billingDetails: JSON.stringify({
        breakdown: { totalCost: 0.12 },
        usage: { promptTokens: 100, completionTokens: 20 },
      }),
    }).run();

    const logId = Number(inserted.lastInsertRowid || 0);
    const response = await app.inject({
      method: 'GET',
      url: `/api/stats/proxy-logs/${logId}`,
    });

    expect(response.statusCode).toBe(200);
    const body = response.json() as {
      id: number;
      siteName: string | null;
      username: string | null;
      downstreamKeyName: string | null;
      downstreamKeyGroupName: string | null;
      downstreamKeyTags: string[];
      clientFamily: string | null;
      clientAppId: string | null;
      clientAppName: string | null;
      clientConfidence: string | null;
      billingDetails: Record<string, unknown> | null;
    };

    expect(body.id).toBe(logId);
    expect(body.siteName).toBe('detail-site');
    expect(body.username).toBe('detail-user');
    expect(body.downstreamKeyName).toBe('detail-key');
    expect(body.downstreamKeyGroupName).toBe('测试项目');
    expect(body.downstreamKeyTags).toEqual(['回归', '日志']);
    expect(body.clientFamily).toBe('codex');
    expect(body.clientAppId).toBe('cherry_studio');
    expect(body.clientAppName).toBe('Cherry Studio');
    expect(body.clientConfidence).toBe('exact');
    expect(body.billingDetails).toMatchObject({
      breakdown: { totalCost: 0.12 },
      usage: { promptTokens: 100, completionTokens: 20 },
    });
  });

  it('supports searching proxy logs by downstream key metadata', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'meta-site',
      url: 'https://meta.example.com',
      platform: 'new-api',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'meta-user',
      accessToken: 'meta-token',
      status: 'active',
    }).returning().get();

    const alphaKey = await db.insert(schema.downstreamApiKeys).values({
      name: '渠道-A',
      key: 'sk-channel-a',
      groupName: '项目甲',
      tags: JSON.stringify(['商务', 'VIP']),
      enabled: true,
    }).returning().get();

    const betaKey = await db.insert(schema.downstreamApiKeys).values({
      name: '渠道-B',
      key: 'sk-channel-b',
      groupName: '项目乙',
      tags: JSON.stringify(['灰度']),
      enabled: true,
    }).returning().get();

    await db.insert(schema.proxyLogs).values([
      {
        accountId: account.id,
        downstreamApiKeyId: alphaKey.id,
        modelRequested: 'gpt-4o',
        modelActual: 'gpt-4o',
        status: 'success',
        totalTokens: 12,
        estimatedCost: 0.12,
        createdAt: formatUtcSqlDateTime(new Date('2026-03-09T10:00:00.000Z')),
      },
      {
        accountId: account.id,
        downstreamApiKeyId: betaKey.id,
        modelRequested: 'gpt-4.1-mini',
        modelActual: 'gpt-4.1-mini',
        status: 'success',
        totalTokens: 22,
        estimatedCost: 0.22,
        createdAt: formatUtcSqlDateTime(new Date('2026-03-09T10:05:00.000Z')),
      },
    ]).run();

    const response = await app.inject({
      method: 'GET',
      url: '/api/stats/proxy-logs?search=%E9%A1%B9%E7%9B%AE%E7%94%B2',
    });

    expect(response.statusCode).toBe(200);
    const body = response.json() as {
      total: number;
      items: Array<Record<string, unknown>>;
    };

    expect(body.total).toBe(1);
    expect(body.items[0]?.downstreamKeyName).toBe('渠道-A');
    expect(body.items[0]?.downstreamKeyGroupName).toBe('项目甲');
  });

  it('filters proxy logs by site and time range', async () => {
    const alphaSite = await db.insert(schema.sites).values({
      name: 'alpha-site',
      url: 'https://alpha.example.com',
      platform: 'new-api',
    }).returning().get();
    const betaSite = await db.insert(schema.sites).values({
      name: 'beta-site',
      url: 'https://beta.example.com',
      platform: 'new-api',
    }).returning().get();

    const alphaAccount = await db.insert(schema.accounts).values({
      siteId: alphaSite.id,
      username: 'alpha-user',
      accessToken: 'alpha-token',
      status: 'active',
    }).returning().get();
    const betaAccount = await db.insert(schema.accounts).values({
      siteId: betaSite.id,
      username: 'beta-user',
      accessToken: 'beta-token',
      status: 'active',
    }).returning().get();

    await db.insert(schema.proxyLogs).values([
      {
        accountId: alphaAccount.id,
        modelRequested: 'gpt-4o',
        modelActual: 'gpt-4o',
        status: 'success',
        totalTokens: 10,
        estimatedCost: 0.11,
        createdAt: formatUtcSqlDateTime(new Date('2026-03-09T08:15:00.000Z')),
      },
      {
        accountId: alphaAccount.id,
        modelRequested: 'gpt-4.1-mini',
        modelActual: 'gpt-4.1-mini',
        status: 'failed',
        totalTokens: 20,
        estimatedCost: 0.22,
        createdAt: formatUtcSqlDateTime(new Date('2026-03-09T08:45:00.000Z')),
      },
      {
        accountId: alphaAccount.id,
        modelRequested: 'gpt-4.1',
        modelActual: 'gpt-4.1',
        status: 'success',
        totalTokens: 30,
        estimatedCost: 0.33,
        createdAt: formatUtcSqlDateTime(new Date('2026-03-09T09:15:00.000Z')),
      },
      {
        accountId: betaAccount.id,
        modelRequested: 'claude-3-7-sonnet',
        modelActual: 'claude-3-7-sonnet',
        status: 'success',
        totalTokens: 40,
        estimatedCost: 0.44,
        createdAt: formatUtcSqlDateTime(new Date('2026-03-09T08:30:00.000Z')),
      },
    ]).run();

    const response = await app.inject({
      method: 'GET',
      url: `/api/stats/proxy-logs?siteId=${alphaSite.id}&from=${encodeURIComponent('2026-03-09T08:00:00.000Z')}&to=${encodeURIComponent('2026-03-09T09:00:00.000Z')}`,
    });

    expect(response.statusCode).toBe(200);
    const body = response.json() as {
      items: Array<Record<string, unknown>>;
      total: number;
      summary: {
        totalCount: number;
        successCount: number;
        failedCount: number;
        totalCost: number;
        totalTokensAll: number;
      };
    };

    expect(body.total).toBe(2);
    expect(body.items).toHaveLength(2);
    expect(body.items.map((item) => item.siteId)).toEqual([alphaSite.id, alphaSite.id]);
    expect(body.items.map((item) => item.siteName)).toEqual(['alpha-site', 'alpha-site']);
    expect(body.summary).toEqual({
      totalCount: 2,
      successCount: 1,
      failedCount: 1,
      totalCost: 0.33,
      totalTokensAll: 30,
    });
  });

  it('filters proxy logs by app id while keeping client options scoped only by the other filters', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'client-filter-site',
      url: 'https://client-filter.example.com',
      platform: 'new-api',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'client-filter-user',
      accessToken: 'client-filter-token',
      status: 'active',
    }).returning().get();

    await db.insert(schema.proxyLogs).values([
      {
        accountId: account.id,
        modelRequested: 'gpt-4o',
        modelActual: 'gpt-4o',
        status: 'success',
        clientFamily: 'generic',
        clientAppId: 'cherry_studio',
        clientAppName: 'Cherry Studio',
        clientConfidence: 'exact',
        totalTokens: 12,
        estimatedCost: 0.12,
        createdAt: formatUtcSqlDateTime(new Date('2026-03-09T11:00:00.000Z')),
      },
      {
        accountId: account.id,
        modelRequested: 'gpt-4.1',
        modelActual: 'gpt-4.1',
        status: 'failed',
        clientFamily: 'codex',
        totalTokens: 22,
        estimatedCost: 0.22,
        createdAt: formatUtcSqlDateTime(new Date('2026-03-09T11:05:00.000Z')),
      },
    ]).run();

    const response = await app.inject({
      method: 'GET',
      url: '/api/stats/proxy-logs?client=app%3Acherry_studio',
    });

    expect(response.statusCode).toBe(200);
    const body = response.json() as {
      total: number;
      items: Array<Record<string, unknown>>;
      clientOptions: Array<{
        value: string;
        label: string;
      }>;
    };

    expect(body.total).toBe(1);
    expect(body.items[0]?.clientAppId).toBe('cherry_studio');
    expect(body.clientOptions).toEqual([
      { value: 'app:cherry_studio', label: '应用 · Cherry Studio' },
      { value: 'family:codex', label: '协议 · Codex' },
    ]);
  });

  it('falls back to legacy client prefixes for old logs without inferring an app fingerprint', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'legacy-site',
      url: 'https://legacy.example.com',
      platform: 'new-api',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'legacy-user',
      accessToken: 'legacy-token',
      status: 'active',
    }).returning().get();

    const inserted = await db.insert(schema.proxyLogs).values({
      accountId: account.id,
      modelRequested: 'gpt-4o',
      modelActual: 'gpt-4o',
      status: 'failed',
      errorMessage: '[client:codex] [session:turn-123] [downstream:/v1/responses] upstream error',
      totalTokens: 9,
      estimatedCost: 0.09,
      createdAt: formatUtcSqlDateTime(new Date('2026-03-09T12:00:00.000Z')),
    }).run();

    const logId = Number(inserted.lastInsertRowid || 0);
    const listResponse = await app.inject({
      method: 'GET',
      url: '/api/stats/proxy-logs',
    });
    const detailResponse = await app.inject({
      method: 'GET',
      url: `/api/stats/proxy-logs/${logId}`,
    });

    expect(listResponse.statusCode).toBe(200);
    expect(detailResponse.statusCode).toBe(200);

    const listBody = listResponse.json() as {
      items: Array<Record<string, unknown>>;
    };
    const detailBody = detailResponse.json() as Record<string, unknown>;

    expect(listBody.items[0]?.clientFamily).toBe('codex');
    expect(listBody.items[0]?.clientAppId).toBe(null);
    expect(listBody.items[0]?.clientAppName).toBe(null);
    expect(detailBody.clientFamily).toBe('codex');
    expect(detailBody.clientAppId).toBe(null);
    expect(detailBody.clientAppName).toBe(null);
  });

  it('returns unknown usage source and nullable token fields for logs without recovered usage', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'unknown-usage-site',
      url: 'https://unknown-usage.example.com',
      platform: 'new-api',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'unknown-usage-user',
      accessToken: 'unknown-usage-token',
      status: 'active',
    }).returning().get();

    await db.insert(schema.proxyLogs).values({
      accountId: account.id,
      modelRequested: 'gpt-5',
      modelActual: 'gpt-5',
      status: 'success',
      promptTokens: null,
      completionTokens: null,
      totalTokens: null,
      estimatedCost: 0,
      errorMessage: '[downstream:/v1/chat/completions] [upstream:/v1/chat/completions] [usage:unknown]',
      createdAt: formatUtcSqlDateTime(new Date('2026-03-09T12:30:00.000Z')),
    }).run();

    const response = await app.inject({
      method: 'GET',
      url: '/api/stats/proxy-logs',
    });

    expect(response.statusCode).toBe(200);
    const body = response.json() as {
      items: Array<{
        usageSource: string | null;
        promptTokens: number | null;
        completionTokens: number | null;
        totalTokens: number | null;
      }>;
    };

    expect(body.items[0]).toMatchObject({
      usageSource: 'unknown',
      promptTokens: null,
      completionTokens: null,
      totalTokens: null,
    });
  });
});
