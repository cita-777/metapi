import Fastify, { type FastifyInstance } from 'fastify';
import { describe, expect, it, beforeAll, beforeEach, afterAll } from 'vitest';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { mkdtempSync } from 'node:fs';
import { sql } from 'drizzle-orm';
import { formatLocalDate, formatUtcSqlDateTime } from '../../services/localTimeService.js';

type DbModule = typeof import('../../db/index.js');

describe('stats dashboard filters disabled sites', () => {
  let app: FastifyInstance;
  let db: DbModule['db'];
  let schema: DbModule['schema'];
  let dataDir = '';

  beforeAll(async () => {
    dataDir = mkdtempSync(join(tmpdir(), 'metapi-stats-site-status-'));
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
    await db.delete(schema.checkinLogs).run();
    await db.delete(schema.routeChannels).run();
    await db.delete(schema.tokenRoutes).run();
    await db.delete(schema.tokenModelAvailability).run();
    await db.delete(schema.modelAvailability).run();
    await db.delete(schema.accountTokens).run();
    await db.delete(schema.accounts).run();
    await db.delete(schema.sites).run();
  });

  afterAll(async () => {
    await app.close();
    delete process.env.DATA_DIR;
  });

  it('excludes disabled-site balances from dashboard totals', async () => {
    const activeSite = await db.insert(schema.sites).values({
      name: 'active-site',
      url: 'https://active-site.example.com',
      platform: 'new-api',
    }).returning().get();

    const disabledSite = await db.insert(schema.sites).values({
      name: 'disabled-site',
      url: 'https://disabled-site.example.com',
      platform: 'new-api',
    }).returning().get();

    await db.run(sql`update sites set status = 'disabled' where id = ${disabledSite.id}`);

    await db.insert(schema.accounts).values({
      siteId: activeSite.id,
      username: 'active-user',
      accessToken: 'active-token',
      balance: 100,
      status: 'active',
    }).run();

    await db.insert(schema.accounts).values({
      siteId: disabledSite.id,
      username: 'disabled-user',
      accessToken: 'disabled-token',
      balance: 900,
      status: 'active',
    }).run();

    const response = await app.inject({
      method: 'GET',
      url: '/api/stats/dashboard',
    });

    expect(response.statusCode).toBe(200);
    const body = response.json() as {
      totalBalance: number;
      activeAccounts: number;
      totalAccounts: number;
    };

    expect(body.totalBalance).toBe(100);
    expect(body.activeAccounts).toBe(1);
    expect(body.totalAccounts).toBe(1);
  });

  it('treats skipped checkins as successful in dashboard stats', async () => {
    const today = formatLocalDate(new Date());
    const site = await db.insert(schema.sites).values({
      name: 'checkin-site',
      url: 'https://checkin-site.example.com',
      platform: 'new-api',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'checkin-user',
      accessToken: 'token',
      balance: 10,
      status: 'active',
    }).returning().get();

    await db.insert(schema.checkinLogs).values([
      {
        accountId: account.id,
        status: 'success',
        message: 'checked in',
        reward: '1',
        createdAt: `${today} 09:00:00`,
      },
      {
        accountId: account.id,
        status: 'skipped',
        message: 'today already checked in',
        reward: '',
        createdAt: `${today} 09:10:00`,
      },
      {
        accountId: account.id,
        status: 'failed',
        message: 'checkin failed',
        reward: '',
        createdAt: `${today} 09:20:00`,
      },
    ]).run();

    const response = await app.inject({
      method: 'GET',
      url: '/api/stats/dashboard',
    });

    expect(response.statusCode).toBe(200);
    const body = response.json() as {
      todayCheckin: {
        success: number;
        failed: number;
        total: number;
      };
    };

    expect(body.todayCheckin).toEqual({
      success: 2,
      failed: 1,
      total: 3,
    });
  });

  it('returns recent RPM and TPM stats using only active-site proxy logs', async () => {
    const activeSite = await db.insert(schema.sites).values({
      name: 'active-performance-site',
      url: 'https://active-performance.example.com',
      platform: 'new-api',
    }).returning().get();

    const disabledSite = await db.insert(schema.sites).values({
      name: 'disabled-performance-site',
      url: 'https://disabled-performance.example.com',
      platform: 'new-api',
    }).returning().get();

    await db.run(sql`update sites set status = 'disabled' where id = ${disabledSite.id}`);

    const activeAccount = await db.insert(schema.accounts).values({
      siteId: activeSite.id,
      username: 'active-performance-user',
      accessToken: 'active-performance-token',
      balance: 100,
      status: 'active',
    }).returning().get();

    const disabledAccount = await db.insert(schema.accounts).values({
      siteId: disabledSite.id,
      username: 'disabled-performance-user',
      accessToken: 'disabled-performance-token',
      balance: 100,
      status: 'active',
    }).returning().get();

    const now = Date.now();
    const withinWindow = formatUtcSqlDateTime(new Date(now - 30_000));
    const outsideWindow = formatUtcSqlDateTime(new Date(now - 90_000));

    await db.insert(schema.proxyLogs).values([
      {
        accountId: activeAccount.id,
        status: 'success',
        totalTokens: 1200,
        createdAt: withinWindow,
      },
      {
        accountId: activeAccount.id,
        status: 'failed',
        totalTokens: 600,
        createdAt: withinWindow,
      },
      {
        accountId: activeAccount.id,
        status: 'success',
        totalTokens: null,
        createdAt: withinWindow,
      },
      {
        accountId: activeAccount.id,
        status: 'success',
        totalTokens: 9999,
        createdAt: outsideWindow,
      },
      {
        accountId: disabledAccount.id,
        status: 'success',
        totalTokens: 7777,
        createdAt: withinWindow,
      },
    ]).run();

    const response = await app.inject({
      method: 'GET',
      url: '/api/stats/dashboard',
    });

    expect(response.statusCode).toBe(200);
    const body = response.json() as {
      performance?: {
        windowSeconds: number;
        requestsPerMinute: number;
        tokensPerMinute: number;
      };
    };

    expect(body.performance).toEqual({
      windowSeconds: 60,
      requestsPerMinute: 3,
      tokensPerMinute: 1800,
    });
  });

  it('returns site availability buckets and average latency from per-request proxy logs', async () => {
    const activeSite = await db.insert(schema.sites).values({
      name: 'availability-site',
      url: 'https://availability.example.com',
      platform: 'new-api',
    }).returning().get();

    const disabledSite = await db.insert(schema.sites).values({
      name: 'disabled-availability-site',
      url: 'https://disabled-availability.example.com',
      platform: 'new-api',
    }).returning().get();

    await db.run(sql`update sites set status = 'disabled' where id = ${disabledSite.id}`);

    const activeAccount = await db.insert(schema.accounts).values({
      siteId: activeSite.id,
      username: 'availability-user',
      accessToken: 'availability-token',
      balance: 20,
      status: 'active',
    }).returning().get();

    const disabledAccount = await db.insert(schema.accounts).values({
      siteId: disabledSite.id,
      username: 'disabled-availability-user',
      accessToken: 'disabled-availability-token',
      balance: 20,
      status: 'active',
    }).returning().get();

    const now = Date.now();
    const recentSuccess = formatUtcSqlDateTime(new Date(now - 5 * 60_000));
    const recentFailure = formatUtcSqlDateTime(new Date(now - 65 * 60_000));

    await db.insert(schema.proxyLogs).values([
      {
        accountId: activeAccount.id,
        status: 'success',
        latencyMs: 120,
        createdAt: recentSuccess,
      },
      {
        accountId: activeAccount.id,
        status: 'failed',
        latencyMs: 280,
        createdAt: recentFailure,
      },
      {
        accountId: disabledAccount.id,
        status: 'success',
        latencyMs: 999,
        createdAt: recentSuccess,
      },
    ]).run();

    const response = await app.inject({
      method: 'GET',
      url: '/api/stats/dashboard',
    });

    expect(response.statusCode).toBe(200);
    const body = response.json() as {
      siteAvailability?: Array<{
        siteId: number;
        siteName: string;
        totalRequests: number;
        successCount: number;
        failedCount: number;
        availabilityPercent: number | null;
        averageLatencyMs: number | null;
        buckets: Array<{
          startUtc?: string;
          totalRequests: number;
          successCount: number;
          failedCount: number;
        }>;
      }>;
    };

    expect(Array.isArray(body.siteAvailability)).toBe(true);
    expect(body.siteAvailability).toHaveLength(1);
    expect(body.siteAvailability?.[0]).toMatchObject({
      siteId: activeSite.id,
      siteName: 'availability-site',
      totalRequests: 2,
      successCount: 1,
      failedCount: 1,
      availabilityPercent: 50,
      averageLatencyMs: 200,
    });
    expect(body.siteAvailability?.[0]?.buckets).toHaveLength(24);
    expect(
      body.siteAvailability?.[0]?.buckets.reduce((sum, bucket) => sum + bucket.totalRequests, 0),
    ).toBe(2);
    expect(
      body.siteAvailability?.[0]?.buckets.reduce((sum, bucket) => sum + bucket.successCount, 0),
    ).toBe(1);
    expect(
      body.siteAvailability?.[0]?.buckets.reduce((sum, bucket) => sum + bucket.failedCount, 0),
    ).toBe(1);
    expect(typeof body.siteAvailability?.[0]?.buckets[0]?.startUtc).toBe('string');
  });
});
