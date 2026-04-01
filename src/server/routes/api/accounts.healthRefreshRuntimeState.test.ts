import Fastify, { type FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const refreshBalanceMock = vi.fn();

vi.mock('../../services/balanceService.js', () => ({
  refreshBalance: (...args: unknown[]) => refreshBalanceMock(...args),
}));

type DbModule = typeof import('../../db/index.js');

describe('accounts health refresh runtime state', () => {
  let app: FastifyInstance;
  let db: DbModule['db'];
  let schema: DbModule['schema'];
  let dataDir = '';
  let resetBackgroundTasks: (() => void) | null = null;
  let getBackgroundTask: ((taskId: string) => { status: string; result: unknown; finishedAt: string | null } | null) | null = null;

  beforeAll(async () => {
    dataDir = mkdtempSync(join(tmpdir(), 'metapi-accounts-health-refresh-'));
    process.env.DATA_DIR = dataDir;

    await import('../../db/migrate.js');
    const dbModule = await import('../../db/index.js');
    const routesModule = await import('./accounts.js');
    const backgroundTaskModule = await import('../../services/backgroundTaskService.js');
    db = dbModule.db;
    schema = dbModule.schema;
    resetBackgroundTasks = backgroundTaskModule.__resetBackgroundTasksForTests;
    getBackgroundTask = backgroundTaskModule.getBackgroundTask;

    app = Fastify();
    await app.register(routesModule.accountsRoutes);
  });

  beforeEach(async () => {
    refreshBalanceMock.mockReset();
    resetBackgroundTasks?.();
    await db.delete(schema.proxyLogs).run();
    await db.delete(schema.checkinLogs).run();
    await db.delete(schema.routeChannels).run();
    await db.delete(schema.tokenRoutes).run();
    await db.delete(schema.tokenModelAvailability).run();
    await db.delete(schema.modelAvailability).run();
    await db.delete(schema.accountTokens).run();
    await db.delete(schema.events).run();
    await db.delete(schema.accounts).run();
    await db.delete(schema.sites).run();
  });

  afterAll(async () => {
    await app.close();
    delete process.env.DATA_DIR;
  });

  it('keeps degraded runtime state for unsupported checkin after health refresh', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'Wind Hub',
      url: 'https://windhub.cc',
      platform: 'done-hub',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'ld6jl3djexjf',
      accessToken: 'token',
      status: 'active',
      extraConfig: JSON.stringify({
        runtimeHealth: {
          state: 'degraded',
          reason: '站点不支持签到接口',
          source: 'checkin',
          checkedAt: '2026-02-25T18:00:00.000Z',
        },
      }),
    }).returning().get();

    refreshBalanceMock.mockResolvedValueOnce({ balance: 100, used: 0, quota: 100 });

    const response = await app.inject({
      method: 'POST',
      url: '/api/accounts/health/refresh',
      payload: { accountId: account.id, wait: true },
    });

    expect(response.statusCode).toBe(200);
    const body = response.json() as {
      success: boolean;
      summary: {
        healthy: number;
        degraded: number;
        failed: number;
      };
      results: Array<{ state: string; status: string; message: string }>;
    };

    expect(body.success).toBe(true);
    expect(body.summary.degraded).toBe(1);
    expect(body.summary.healthy).toBe(0);
    expect(body.summary.failed).toBe(0);
    expect(body.results[0]).toMatchObject({
      state: 'degraded',
      status: 'success',
      message: '站点不支持签到接口',
    });
  });

  it('rejects non-boolean wait payload when refreshing health', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/accounts/health/refresh',
      payload: { wait: 'true' },
    });

    expect(response.statusCode).toBe(400);
    expect((response.json() as { message?: string }).message).toContain('wait');
  });

  it('rejects non-number accountId payload when refreshing health', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/accounts/health/refresh',
      payload: { accountId: '1', wait: true },
    });

    expect(response.statusCode).toBe(400);
    expect((response.json() as { message?: string }).message).toContain('账号 ID');
  });

  it('returns readable task messages when starting a background refresh for all accounts', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'Wind Hub',
      url: 'https://windhub.cc',
      platform: 'done-hub',
    }).returning().get();

    await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'tester',
      accessToken: 'token',
      status: 'active',
    }).returning().get();

    refreshBalanceMock.mockImplementation(() => new Promise(() => {}));

    const response = await app.inject({
      method: 'POST',
      url: '/api/accounts/health/refresh',
      payload: {},
    });

    expect(response.statusCode).toBe(202);
    expect(response.json()).toMatchObject({
      success: true,
      message: '已开始刷新账号运行健康状态，请稍后查看账号列表',
    });

    for (let i = 0; i < 10; i += 1) {
      const events = await db.select().from(schema.events).all();
      if (events.length > 0) {
        expect(events[0]).toMatchObject({
          title: '刷新全部账号运行健康状态已开始',
          message: '刷新全部账号运行健康状态 已开始执行',
          level: 'info',
          type: 'status',
        });
        return;
      }
      await new Promise((resolve) => setTimeout(resolve, 10));
    }

    throw new Error('expected a background task event to be recorded');
  });

  it('fails a single-account health refresh after 10 seconds when the site never responds', async () => {
    vi.useFakeTimers();
    try {
      const site = await db.insert(schema.sites).values({
        name: 'Slow Site',
        url: 'https://slow.example.com',
        platform: 'done-hub',
      }).returning().get();

      const account = await db.insert(schema.accounts).values({
        siteId: site.id,
        username: 'slow-user',
        accessToken: 'token',
        status: 'active',
      }).returning().get();

      refreshBalanceMock.mockImplementation(() => new Promise(() => {}));

      const responsePromise = app.inject({
        method: 'POST',
        url: '/api/accounts/health/refresh',
        payload: { accountId: account.id, wait: true },
      });

      await vi.advanceTimersByTimeAsync(10_001);

      const response = await responsePromise;
      expect(response.statusCode).toBe(200);

      const body = response.json() as {
        success: boolean;
        summary: {
          total: number;
          failed: number;
        };
        results: Array<{ status: string; state: string; message: string }>;
      };

      expect(body.success).toBe(true);
      expect(body.summary).toMatchObject({
        total: 1,
        failed: 1,
      });
      expect(body.results[0]).toMatchObject({
        status: 'failed',
        state: 'unhealthy',
        message: '站点健康检查超时（10s）',
      });
    } finally {
      vi.useRealTimers();
    }
  }, 1000);

  it('skips runtime refresh for proxy-only accounts', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'Proxy Site',
      url: 'https://proxy.example.com',
      platform: 'new-api',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: null,
      accessToken: 'api-key-token',
      status: 'expired',
      extraConfig: JSON.stringify({
        credentialMode: 'apikey',
      }),
    }).returning().get();

    const response = await app.inject({
      method: 'POST',
      url: '/api/accounts/health/refresh',
      payload: { accountId: account.id, wait: true },
    });

    expect(response.statusCode).toBe(200);
    const body = response.json() as {
      success: boolean;
      summary: {
        total: number;
        skipped: number;
        failed: number;
      };
      results: Array<{ status: string; state: string; message: string }>;
    };

    expect(body.success).toBe(true);
    expect(body.summary).toMatchObject({
      total: 1,
      skipped: 1,
      failed: 0,
    });
    expect(body.results[0]).toMatchObject({
      status: 'skipped',
      state: 'unknown',
    });
    expect(refreshBalanceMock).not.toHaveBeenCalled();
  });

  it('finishes the background refresh-all task after the 10 second site timeout instead of staying in progress', async () => {
    vi.useFakeTimers();
    try {
      const site = await db.insert(schema.sites).values({
        name: 'Slow Site',
        url: 'https://slow.example.com',
        platform: 'done-hub',
      }).returning().get();

      await db.insert(schema.accounts).values({
        siteId: site.id,
        username: 'slow-user',
        accessToken: 'token',
        status: 'active',
      }).returning().get();

      refreshBalanceMock.mockImplementation(() => new Promise(() => {}));

      const responsePromise = app.inject({
        method: 'POST',
        url: '/api/accounts/health/refresh',
        payload: {},
      });
      await vi.advanceTimersByTimeAsync(0);
      const response = await responsePromise;

      expect(response.statusCode).toBe(202);
      const body = response.json() as { jobId: string };

      await vi.advanceTimersByTimeAsync(10_001);

      const task = getBackgroundTask?.(body.jobId);
      expect(task).toMatchObject({
        status: 'succeeded',
        result: {
          summary: {
            total: 1,
            failed: 1,
          },
        },
      });
      expect(task?.finishedAt).toBeTruthy();
    } finally {
      vi.useRealTimers();
    }
  }, 3000);
});
