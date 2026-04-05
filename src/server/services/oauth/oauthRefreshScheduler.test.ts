import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const refreshOauthAccessTokenSingleflightMock = vi.fn();

vi.mock('./refreshSingleflight.js', () => ({
  refreshOauthAccessTokenSingleflight: (...args: unknown[]) => refreshOauthAccessTokenSingleflightMock(...args),
}));

type DbModule = typeof import('../../db/index.js');
type SchedulerModule = typeof import('./oauthRefreshScheduler.js');

function buildOauthExtraConfig(input: {
  provider: string;
  refreshToken?: string;
  tokenExpiresAt?: number;
}): string {
  return JSON.stringify({
    credentialMode: 'session',
    oauth: {
      provider: input.provider,
      email: `${input.provider}-user@example.com`,
      accountKey: `${input.provider}-user@example.com`,
      ...(input.refreshToken ? { refreshToken: input.refreshToken } : {}),
      ...(input.tokenExpiresAt ? { tokenExpiresAt: input.tokenExpiresAt } : {}),
    },
  });
}

describe('oauthRefreshScheduler', () => {
  let db: DbModule['db'];
  let schema: DbModule['schema'];
  let executeOauthTokenAutoRefreshPass: SchedulerModule['executeOauthTokenAutoRefreshPass'];
  let startOauthTokenRefreshScheduler: SchedulerModule['startOauthTokenRefreshScheduler'];
  let stopOauthTokenRefreshScheduler: SchedulerModule['stopOauthTokenRefreshScheduler'];
  let resetOauthTokenRefreshSchedulerForTests: SchedulerModule['__resetOauthTokenRefreshSchedulerForTests'];
  let dataDir = '';
  let originalDataDir: string | undefined;

  beforeAll(async () => {
    dataDir = mkdtempSync(join(tmpdir(), 'metapi-oauth-refresh-scheduler-'));
    originalDataDir = process.env.DATA_DIR;
    process.env.DATA_DIR = dataDir;

    await import('../../db/migrate.js');
    const dbModule = await import('../../db/index.js');
    const schedulerModule = await import('./oauthRefreshScheduler.js');

    db = dbModule.db;
    schema = dbModule.schema;
    executeOauthTokenAutoRefreshPass = schedulerModule.executeOauthTokenAutoRefreshPass;
    startOauthTokenRefreshScheduler = schedulerModule.startOauthTokenRefreshScheduler;
    stopOauthTokenRefreshScheduler = schedulerModule.stopOauthTokenRefreshScheduler;
    resetOauthTokenRefreshSchedulerForTests = schedulerModule.__resetOauthTokenRefreshSchedulerForTests;
  });

  beforeEach(async () => {
    vi.useFakeTimers();
    refreshOauthAccessTokenSingleflightMock.mockReset();
    await stopOauthTokenRefreshScheduler();
    await resetOauthTokenRefreshSchedulerForTests();

    await db.delete(schema.accounts).run();
    await db.delete(schema.sites).run();
  });

  afterEach(() => {
    return (async () => {
      await stopOauthTokenRefreshScheduler();
      await resetOauthTokenRefreshSchedulerForTests();
      vi.useRealTimers();
    })();
  });

  afterAll(() => {
    if (originalDataDir === undefined) {
      delete process.env.DATA_DIR;
    } else {
      process.env.DATA_DIR = originalDataDir;
    }
  });

  it('refreshes only oauth accounts that are within the provider-specific lead window, including gemini-cli', async () => {
    const nowMs = Date.parse('2026-04-05T12:00:00.000Z');
    vi.setSystemTime(nowMs);

    const activeSite = await db.insert(schema.sites).values({
      name: 'oauth-refresh-site',
      url: 'https://oauth-refresh.example.com',
      platform: 'codex',
      status: 'active',
    }).returning().get();

    const disabledSite = await db.insert(schema.sites).values({
      name: 'oauth-disabled-site',
      url: 'https://oauth-disabled.example.com',
      platform: 'codex',
      status: 'disabled',
    }).returning().get();

    const accountIds: Record<string, number> = {};
    for (const account of [
      {
        key: 'codex_due',
        provider: 'codex',
        siteId: activeSite.id,
        status: 'active',
        refreshToken: 'codex-refresh',
        tokenExpiresAt: nowMs + (4 * 24 * 60 * 60 * 1000),
      },
      {
        key: 'codex_skip',
        provider: 'codex',
        siteId: activeSite.id,
        status: 'active',
        refreshToken: 'codex-refresh-later',
        tokenExpiresAt: nowMs + (6 * 24 * 60 * 60 * 1000),
      },
      {
        key: 'claude_due',
        provider: 'claude',
        siteId: activeSite.id,
        status: 'active',
        refreshToken: 'claude-refresh',
        tokenExpiresAt: nowMs + (3 * 60 * 60 * 1000),
      },
      {
        key: 'claude_skip',
        provider: 'claude',
        siteId: activeSite.id,
        status: 'active',
        refreshToken: 'claude-refresh-later',
        tokenExpiresAt: nowMs + (5 * 60 * 60 * 1000),
      },
      {
        key: 'antigravity_due',
        provider: 'antigravity',
        siteId: activeSite.id,
        status: 'active',
        refreshToken: 'antigravity-refresh',
        tokenExpiresAt: nowMs + (4 * 60 * 1000),
      },
      {
        key: 'antigravity_skip',
        provider: 'antigravity',
        siteId: activeSite.id,
        status: 'active',
        refreshToken: 'antigravity-refresh-later',
        tokenExpiresAt: nowMs + (6 * 60 * 1000),
      },
      {
        key: 'gemini_due',
        provider: 'gemini-cli',
        siteId: activeSite.id,
        status: 'active',
        refreshToken: 'gemini-refresh',
        tokenExpiresAt: nowMs + (4 * 60 * 1000),
      },
      {
        key: 'gemini_skip',
        provider: 'gemini-cli',
        siteId: activeSite.id,
        status: 'active',
        refreshToken: 'gemini-refresh-later',
        tokenExpiresAt: nowMs + (6 * 60 * 1000),
      },
      {
        key: 'inactive_due',
        provider: 'antigravity',
        siteId: activeSite.id,
        status: 'disabled',
        refreshToken: 'inactive-refresh',
        tokenExpiresAt: nowMs + (4 * 60 * 1000),
      },
      {
        key: 'disabled_site_due',
        provider: 'antigravity',
        siteId: disabledSite.id,
        status: 'active',
        refreshToken: 'site-disabled-refresh',
        tokenExpiresAt: nowMs + (4 * 60 * 1000),
      },
      {
        key: 'missing_refresh_token',
        provider: 'antigravity',
        siteId: activeSite.id,
        status: 'active',
        refreshToken: '',
        tokenExpiresAt: nowMs + (4 * 60 * 1000),
      },
      {
        key: 'missing_expiry',
        provider: 'antigravity',
        siteId: activeSite.id,
        status: 'active',
        refreshToken: 'missing-expiry-refresh',
      },
    ]) {
      const inserted = await db.insert(schema.accounts).values({
        siteId: account.siteId,
        username: `${account.key}@example.com`,
        accessToken: `${account.key}-access-token`,
        apiToken: null,
        status: account.status,
        oauthProvider: account.provider,
        oauthAccountKey: `${account.key}@example.com`,
        extraConfig: buildOauthExtraConfig({
          provider: account.provider,
          refreshToken: account.refreshToken,
          tokenExpiresAt: account.tokenExpiresAt,
        }),
      }).returning().get();
      accountIds[account.key] = inserted.id;
    }

    const result = await executeOauthTokenAutoRefreshPass({ nowMs });

    expect(result).toMatchObject({
      scanned: 12,
      refreshed: 4,
      failed: 0,
      skipped: 8,
    });
    expect(result.refreshedAccountIds.sort((a, b) => a - b)).toEqual([
      accountIds.codex_due,
      accountIds.claude_due,
      accountIds.antigravity_due,
      accountIds.gemini_due,
    ].sort((a, b) => a - b));
    expect(result.failedAccountIds).toEqual([]);
    expect(refreshOauthAccessTokenSingleflightMock.mock.calls.map((call) => call[0]).sort((a, b) => a - b)).toEqual([
      accountIds.codex_due,
      accountIds.claude_due,
      accountIds.antigravity_due,
      accountIds.gemini_due,
    ].sort((a, b) => a - b));
  });

  it('starts with an immediate pass and keeps polling until stopped', async () => {
    const nowMs = Date.parse('2026-04-05T12:00:00.000Z');
    vi.setSystemTime(nowMs);

    const site = await db.insert(schema.sites).values({
      name: 'oauth-refresh-site',
      url: 'https://oauth-refresh.example.com',
      platform: 'antigravity',
      status: 'active',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'scheduler-user@example.com',
      accessToken: 'scheduler-access-token',
      apiToken: null,
      status: 'active',
      oauthProvider: 'antigravity',
      oauthAccountKey: 'scheduler-user@example.com',
      extraConfig: buildOauthExtraConfig({
        provider: 'antigravity',
        refreshToken: 'scheduler-refresh-token',
        tokenExpiresAt: nowMs + (4 * 60 * 1000),
      }),
    }).returning().get();

    const started = startOauthTokenRefreshScheduler(60_000);
    expect(started).toMatchObject({
      enabled: true,
      intervalMs: 60_000,
    });

    await vi.advanceTimersByTimeAsync(0);
    expect(refreshOauthAccessTokenSingleflightMock).toHaveBeenCalledTimes(1);
    expect(refreshOauthAccessTokenSingleflightMock).toHaveBeenLastCalledWith(account.id);

    await vi.advanceTimersByTimeAsync(60_000);
    expect(refreshOauthAccessTokenSingleflightMock).toHaveBeenCalledTimes(2);

    await stopOauthTokenRefreshScheduler();
    await vi.advanceTimersByTimeAsync(60_000);
    expect(refreshOauthAccessTokenSingleflightMock).toHaveBeenCalledTimes(2);
  });

  it('waits for an in-flight refresh pass before stop resolves', async () => {
    const nowMs = Date.parse('2026-04-05T12:00:00.000Z');
    vi.setSystemTime(nowMs);

    let releaseRefresh: (() => void) | null = null;
    refreshOauthAccessTokenSingleflightMock.mockImplementation(() => new Promise<void>((resolve) => {
      releaseRefresh = resolve;
    }));

    const site = await db.insert(schema.sites).values({
      name: 'oauth-refresh-site',
      url: 'https://oauth-refresh.example.com',
      platform: 'antigravity',
      status: 'active',
    }).returning().get();

    await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'scheduler-user@example.com',
      accessToken: 'scheduler-access-token',
      apiToken: null,
      status: 'active',
      oauthProvider: 'antigravity',
      oauthAccountKey: 'scheduler-user@example.com',
      extraConfig: buildOauthExtraConfig({
        provider: 'antigravity',
        refreshToken: 'scheduler-refresh-token',
        tokenExpiresAt: nowMs + (4 * 60 * 1000),
      }),
    }).run();

    startOauthTokenRefreshScheduler(60_000);
    await vi.advanceTimersByTimeAsync(0);
    expect(refreshOauthAccessTokenSingleflightMock).toHaveBeenCalledTimes(1);

    let stopResolved = false;
    const stopPromise = Promise.resolve(stopOauthTokenRefreshScheduler()).then(() => {
      stopResolved = true;
    });
    await Promise.resolve();
    expect(stopResolved).toBe(false);

    releaseRefresh?.();
    await stopPromise;
    expect(stopResolved).toBe(true);
  });
});
