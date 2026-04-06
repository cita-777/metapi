import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const refreshSub2ApiManagedSessionSingleflightMock = vi.fn();

vi.mock('./sub2apiRefreshSingleflight.js', () => ({
  refreshSub2ApiManagedSessionSingleflight: (...args: unknown[]) => refreshSub2ApiManagedSessionSingleflightMock(...args),
}));

vi.mock('./sub2apiManagedAuth.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./sub2apiManagedAuth.js')>();
  return {
    ...actual,
  };
});

type DbModule = typeof import('../db/index.js');
type SchedulerModule = typeof import('./sub2apiRefreshScheduler.js');

function buildSub2ApiExtraConfig(input: {
  refreshToken?: string;
  tokenExpiresAt?: number;
}): string {
  return JSON.stringify({
    credentialMode: 'session',
    ...(input.refreshToken || input.tokenExpiresAt
      ? {
          sub2apiAuth: {
            ...(input.refreshToken ? { refreshToken: input.refreshToken } : {}),
            ...(input.tokenExpiresAt ? { tokenExpiresAt: input.tokenExpiresAt } : {}),
          },
        }
      : {}),
  });
}

describe('sub2apiRefreshScheduler', () => {
  let db: DbModule['db'];
  let schema: DbModule['schema'];
  let executeSub2ApiManagedRefreshPass: SchedulerModule['executeSub2ApiManagedRefreshPass'];
  let sub2ApiRefreshSchedulerConcurrency: number;
  let startSub2ApiManagedRefreshScheduler: SchedulerModule['startSub2ApiManagedRefreshScheduler'];
  let stopSub2ApiManagedRefreshScheduler: SchedulerModule['stopSub2ApiManagedRefreshScheduler'];
  let resetSub2ApiManagedRefreshSchedulerForTests: SchedulerModule['__resetSub2ApiManagedRefreshSchedulerForTests'];
  let dataDir = '';
  let originalDataDir: string | undefined;

  beforeAll(async () => {
    dataDir = mkdtempSync(join(tmpdir(), 'metapi-sub2api-refresh-scheduler-'));
    originalDataDir = process.env.DATA_DIR;
    process.env.DATA_DIR = dataDir;

    await import('../db/migrate.js');
    const dbModule = await import('../db/index.js');
    const schedulerModule = await import('./sub2apiRefreshScheduler.js');

    db = dbModule.db;
    schema = dbModule.schema;
    executeSub2ApiManagedRefreshPass = schedulerModule.executeSub2ApiManagedRefreshPass;
    sub2ApiRefreshSchedulerConcurrency = schedulerModule.SUB2API_REFRESH_SCHEDULER_CONCURRENCY;
    startSub2ApiManagedRefreshScheduler = schedulerModule.startSub2ApiManagedRefreshScheduler;
    stopSub2ApiManagedRefreshScheduler = schedulerModule.stopSub2ApiManagedRefreshScheduler;
    resetSub2ApiManagedRefreshSchedulerForTests = schedulerModule.__resetSub2ApiManagedRefreshSchedulerForTests;
  });

  beforeEach(async () => {
    vi.useFakeTimers();
    refreshSub2ApiManagedSessionSingleflightMock.mockReset();
    await stopSub2ApiManagedRefreshScheduler();
    await resetSub2ApiManagedRefreshSchedulerForTests();

    await db.delete(schema.accounts).run();
    await db.delete(schema.sites).run();
  });

  afterEach(async () => {
    await stopSub2ApiManagedRefreshScheduler();
    await resetSub2ApiManagedRefreshSchedulerForTests();
    vi.useRealTimers();
  });

  afterAll(() => {
    if (originalDataDir === undefined) {
      delete process.env.DATA_DIR;
    } else {
      process.env.DATA_DIR = originalDataDir;
    }
  });

  it('refreshes only active sub2api session accounts whose managed token is within the refresh lead window', async () => {
    const nowMs = Date.parse('2026-04-06T02:00:00.000Z');
    vi.setSystemTime(nowMs);

    const activeSub2ApiSite = await db.insert(schema.sites).values({
      name: 'sub2-due-site',
      url: 'https://sub2-due.example.com',
      platform: 'sub2api',
      status: 'active',
    }).returning().get();

    const disabledSub2ApiSite = await db.insert(schema.sites).values({
      name: 'sub2-disabled-site',
      url: 'https://sub2-disabled.example.com',
      platform: 'sub2api',
      status: 'disabled',
    }).returning().get();

    const activeNonSub2ApiSite = await db.insert(schema.sites).values({
      name: 'other-site',
      url: 'https://other.example.com',
      platform: 'new-api',
      status: 'active',
    }).returning().get();

    const accountIds: Record<string, number> = {};
    for (const account of [
      {
        key: 'due',
        siteId: activeSub2ApiSite.id,
        status: 'active',
        refreshToken: 'sub2-refresh-due',
        tokenExpiresAt: nowMs + 60_000,
      },
      {
        key: 'expired',
        siteId: activeSub2ApiSite.id,
        status: 'active',
        refreshToken: 'sub2-refresh-expired',
        tokenExpiresAt: nowMs - 1_000,
      },
      {
        key: 'later',
        siteId: activeSub2ApiSite.id,
        status: 'active',
        refreshToken: 'sub2-refresh-later',
        tokenExpiresAt: nowMs + (10 * 60 * 1000),
      },
      {
        key: 'inactive',
        siteId: activeSub2ApiSite.id,
        status: 'disabled',
        refreshToken: 'sub2-refresh-inactive',
        tokenExpiresAt: nowMs + 60_000,
      },
      {
        key: 'disabled_site',
        siteId: disabledSub2ApiSite.id,
        status: 'active',
        refreshToken: 'sub2-refresh-disabled-site',
        tokenExpiresAt: nowMs + 60_000,
      },
      {
        key: 'missing_refresh_token',
        siteId: activeSub2ApiSite.id,
        status: 'active',
        refreshToken: '',
        tokenExpiresAt: nowMs + 60_000,
      },
      {
        key: 'missing_expiry',
        siteId: activeSub2ApiSite.id,
        status: 'active',
        refreshToken: 'sub2-refresh-missing-expiry',
      },
      {
        key: 'wrong_platform',
        siteId: activeNonSub2ApiSite.id,
        status: 'active',
        refreshToken: 'sub2-refresh-other-platform',
        tokenExpiresAt: nowMs + 60_000,
      },
    ]) {
      const inserted = await db.insert(schema.accounts).values({
        siteId: account.siteId,
        username: `${account.key}@example.com`,
        accessToken: `${account.key}-access-token`,
        apiToken: null,
        status: account.status,
        extraConfig: buildSub2ApiExtraConfig({
          refreshToken: account.refreshToken,
          tokenExpiresAt: account.tokenExpiresAt,
        }),
      }).returning().get();
      accountIds[account.key] = inserted.id;
    }

    refreshSub2ApiManagedSessionSingleflightMock.mockResolvedValue({
      accessToken: 'refreshed-access-token',
      extraConfig: buildSub2ApiExtraConfig({
        refreshToken: 'refreshed-refresh-token',
        tokenExpiresAt: nowMs + (60 * 60 * 1000),
      }),
    });

    const result = await executeSub2ApiManagedRefreshPass({ nowMs });

    expect(result).toMatchObject({
      scanned: 5,
      refreshed: 2,
      failed: 0,
      skipped: 3,
    });
    expect(result.refreshedAccountIds.sort((a, b) => a - b)).toEqual([
      accountIds.due,
      accountIds.expired,
    ].sort((a, b) => a - b));
    expect(result.failedAccountIds).toEqual([]);
    expect(
      refreshSub2ApiManagedSessionSingleflightMock.mock.calls
        .map((call) => call[0]?.account?.id)
        .sort((a, b) => a - b),
    ).toEqual([
      accountIds.due,
      accountIds.expired,
    ].sort((a, b) => a - b));
  });

  it('refreshes due sub2api accounts with bounded concurrency instead of serially', async () => {
    vi.useRealTimers();
    const nowMs = Date.parse('2026-04-06T02:00:00.000Z');
    vi.setSystemTime(nowMs);

    const activeSub2ApiSite = await db.insert(schema.sites).values({
      name: 'sub2-concurrency-site',
      url: 'https://sub2-concurrency.example.com',
      platform: 'sub2api',
      status: 'active',
    }).returning().get();

    for (const key of [
      ...Array.from({ length: sub2ApiRefreshSchedulerConcurrency + 2 }, (_value, index) => `due-${index + 1}`),
      'later',
    ]) {
      await db.insert(schema.accounts).values({
        siteId: activeSub2ApiSite.id,
        username: `${key}@example.com`,
        accessToken: `${key}-access-token`,
        apiToken: null,
        status: 'active',
        extraConfig: buildSub2ApiExtraConfig({
          refreshToken: `${key}-refresh-token`,
          tokenExpiresAt: key === 'later' ? nowMs + (10 * 60 * 1000) : nowMs + 60_000,
        }),
      }).run();
    }

    const resolvers: Array<() => void> = [];
    refreshSub2ApiManagedSessionSingleflightMock.mockImplementation(() => new Promise((resolve) => {
      resolvers.push(() => resolve({
        accessToken: 'refreshed-access-token',
        extraConfig: buildSub2ApiExtraConfig({
          refreshToken: 'refreshed-refresh-token',
          tokenExpiresAt: nowMs + (60 * 60 * 1000),
        }),
      }));
    }));

    const passPromise = executeSub2ApiManagedRefreshPass({ nowMs });
    await new Promise((resolve) => setImmediate(resolve));
    await new Promise((resolve) => setImmediate(resolve));

    expect(refreshSub2ApiManagedSessionSingleflightMock).toHaveBeenCalledTimes(sub2ApiRefreshSchedulerConcurrency);

    const firstBatchResolvers = [...resolvers];
    for (const resolve of firstBatchResolvers) {
      resolve();
    }
    await new Promise((resolve) => setImmediate(resolve));
    await new Promise((resolve) => setImmediate(resolve));

    expect(refreshSub2ApiManagedSessionSingleflightMock).toHaveBeenCalledTimes(
      sub2ApiRefreshSchedulerConcurrency + 2,
    );

    const secondBatchResolvers = resolvers.slice(firstBatchResolvers.length);
    for (const resolve of secondBatchResolvers) {
      resolve();
    }

    const result = await passPromise;
    expect(result).toMatchObject({
      scanned: sub2ApiRefreshSchedulerConcurrency + 3,
      refreshed: sub2ApiRefreshSchedulerConcurrency + 2,
      failed: 0,
      skipped: 1,
    });
  });
});
