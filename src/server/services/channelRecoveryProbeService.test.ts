import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { eq } from 'drizzle-orm';

const probeRuntimeModelMock = vi.fn();

vi.mock('./runtimeModelProbe.js', () => ({
  probeRuntimeModel: (...args: unknown[]) => probeRuntimeModelMock(...args),
}));

type DbModule = typeof import('../db/index.js');
type RecoveryModule = typeof import('./channelRecoveryProbeService.js');
type CoordinatorModule = typeof import('./proxyChannelCoordinator.js');
type ConfigModule = typeof import('../config.js');
type TokenRouterModule = typeof import('./tokenRouter.js');

describe('channelRecoveryProbeService', () => {
  let db: DbModule['db'];
  let schema: DbModule['schema'];
  let runChannelRecoveryProbeSweep: RecoveryModule['runChannelRecoveryProbeSweep'];
  let resetChannelRecoveryProbeState: RecoveryModule['resetChannelRecoveryProbeState'];
  let proxyChannelCoordinator: CoordinatorModule['proxyChannelCoordinator'];
  let resetProxyChannelCoordinatorState: CoordinatorModule['resetProxyChannelCoordinatorState'];
  let invalidateTokenRouterCache: TokenRouterModule['invalidateTokenRouterCache'];
  let resetSiteRuntimeHealthState: TokenRouterModule['resetSiteRuntimeHealthState'];
  let config: ConfigModule['config'];
  let dataDir = '';
  let originalDataDir: string | undefined;
  let originalConcurrencyLimit = 0;

  beforeAll(async () => {
    dataDir = mkdtempSync(join(tmpdir(), 'metapi-channel-recovery-probe-'));
    originalDataDir = process.env.DATA_DIR;
    process.env.DATA_DIR = dataDir;

    await import('../db/migrate.js');
    const dbModule = await import('../db/index.js');
    const recoveryModule = await import('./channelRecoveryProbeService.js');
    const coordinatorModule = await import('./proxyChannelCoordinator.js');
    const configModule = await import('../config.js');
    const tokenRouterModule = await import('./tokenRouter.js');

    db = dbModule.db;
    schema = dbModule.schema;
    runChannelRecoveryProbeSweep = recoveryModule.runChannelRecoveryProbeSweep;
    resetChannelRecoveryProbeState = recoveryModule.resetChannelRecoveryProbeState;
    proxyChannelCoordinator = coordinatorModule.proxyChannelCoordinator;
    resetProxyChannelCoordinatorState = coordinatorModule.resetProxyChannelCoordinatorState;
    invalidateTokenRouterCache = tokenRouterModule.invalidateTokenRouterCache;
    resetSiteRuntimeHealthState = tokenRouterModule.resetSiteRuntimeHealthState;
    config = configModule.config;
    originalConcurrencyLimit = config.proxySessionChannelConcurrencyLimit;
  });

  beforeEach(async () => {
    probeRuntimeModelMock.mockReset();
    probeRuntimeModelMock.mockResolvedValue({
      status: 'supported',
      latencyMs: 320,
      reason: 'probe succeeded',
    });
    config.proxySessionChannelConcurrencyLimit = 1;
    resetChannelRecoveryProbeState();
    resetProxyChannelCoordinatorState();
    invalidateTokenRouterCache();
    resetSiteRuntimeHealthState();

    await db.delete(schema.routeChannels).run();
    await db.delete(schema.tokenRoutes).run();
    await db.delete(schema.settings).run();
    await db.delete(schema.accountTokens).run();
    await db.delete(schema.accounts).run();
    await db.delete(schema.sites).run();
  });

  afterAll(() => {
    config.proxySessionChannelConcurrencyLimit = originalConcurrencyLimit;
    resetChannelRecoveryProbeState();
    resetProxyChannelCoordinatorState();
    invalidateTokenRouterCache();
    resetSiteRuntimeHealthState();
    rmSync(dataDir, { recursive: true, force: true });
    if (originalDataDir === undefined) {
      delete process.env.DATA_DIR;
    } else {
      process.env.DATA_DIR = originalDataDir;
    }
  });

  it('clears cooldown markers when a background probe succeeds', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'recovery-site',
      url: 'https://recovery-site.example.com',
      platform: 'new-api',
      status: 'active',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'recovery-user',
      accessToken: 'access-recovery',
      apiToken: 'sk-recovery',
      status: 'active',
    }).returning().get();

    const token = await db.insert(schema.accountTokens).values({
      accountId: account.id,
      name: 'default',
      token: 'sk-recovery-token',
      enabled: true,
      isDefault: true,
    }).returning().get();

    const route = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-5.4',
      enabled: true,
    }).returning().get();

    const channel = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: account.id,
      tokenId: token.id,
      enabled: true,
      cooldownUntil: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
      lastFailAt: new Date().toISOString(),
      consecutiveFailCount: 2,
      cooldownLevel: 1,
    }).returning().get();

    await runChannelRecoveryProbeSweep();

    expect(probeRuntimeModelMock).toHaveBeenCalledTimes(1);
    expect(probeRuntimeModelMock.mock.calls[0]?.[0]).toMatchObject({
      modelName: 'gpt-5.4',
      tokenValue: 'sk-recovery-token',
    });

    const refreshed = await db.select().from(schema.routeChannels)
      .where(eq(schema.routeChannels.id, channel.id))
      .get();
    expect(refreshed?.cooldownUntil).toBeNull();
    expect(refreshed?.lastFailAt).toBeNull();
    expect(refreshed?.consecutiveFailCount).toBe(0);
    expect(refreshed?.cooldownLevel).toBe(0);
  });

  it('also probes active leased channels in the background', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'active-site',
      url: 'https://active-site.example.com',
      platform: 'new-api',
      status: 'active',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'active-user',
      accessToken: 'access-active',
      apiToken: 'sk-active',
      status: 'active',
      extraConfig: JSON.stringify({
        credentialMode: 'session',
      }),
    }).returning().get();

    const token = await db.insert(schema.accountTokens).values({
      accountId: account.id,
      name: 'default',
      token: 'sk-active-token',
      enabled: true,
      isDefault: true,
    }).returning().get();

    const route = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-5.2',
      enabled: true,
    }).returning().get();

    const channel = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: account.id,
      tokenId: token.id,
      enabled: true,
    }).returning().get();

    const lease = await proxyChannelCoordinator.acquireChannelLease({
      channelId: channel.id,
      accountExtraConfig: account.extraConfig,
    });
    expect(lease.status).toBe('acquired');
    if (lease.status !== 'acquired') return;

    await runChannelRecoveryProbeSweep();

    expect(probeRuntimeModelMock).toHaveBeenCalledTimes(1);
    expect(probeRuntimeModelMock.mock.calls[0]?.[0]).toMatchObject({
      modelName: 'gpt-5.2',
      tokenValue: 'sk-active-token',
    });

    lease.lease.release();
  });

  it('skips provider-directed quota cooldown channels during recovery sweeps', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'quota-site',
      url: 'https://quota-site.example.com',
      platform: 'codex',
      status: 'active',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'quota-user',
      accessToken: 'access-quota',
      apiToken: 'sk-quota',
      status: 'active',
    }).returning().get();

    const quotaToken = await db.insert(schema.accountTokens).values({
      accountId: account.id,
      name: 'quota-token',
      token: 'sk-quota-token',
      enabled: true,
      isDefault: false,
    }).returning().get();

    const retryToken = await db.insert(schema.accountTokens).values({
      accountId: account.id,
      name: 'retry-token',
      token: 'sk-retry-token',
      enabled: true,
      isDefault: false,
    }).returning().get();

    const route = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-5.4',
      enabled: true,
    }).returning().get();

    await db.insert(schema.routeChannels).values([
      {
        routeId: route.id,
        accountId: account.id,
        tokenId: quotaToken.id,
        enabled: true,
        cooldownUntil: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
        lastFailAt: new Date().toISOString(),
        failCount: 0,
        consecutiveFailCount: 0,
        cooldownLevel: 0,
      },
      {
        routeId: route.id,
        accountId: account.id,
        tokenId: retryToken.id,
        enabled: true,
        cooldownUntil: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
        lastFailAt: new Date().toISOString(),
        failCount: 2,
        consecutiveFailCount: 0,
        cooldownLevel: 0,
      },
    ]).run();

    await runChannelRecoveryProbeSweep();

    expect(probeRuntimeModelMock).toHaveBeenCalledTimes(1);
    expect(probeRuntimeModelMock.mock.calls[0]?.[0]).toMatchObject({
      tokenValue: 'sk-retry-token',
      modelName: 'gpt-5.4',
    });
  });

  it('prioritizes never-probed active channels before reprobing recently started ones', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'priority-site',
      url: 'https://priority-site.example.com',
      platform: 'new-api',
      status: 'active',
    }).returning().get();

    const leases: Array<{ release: () => void }> = [];
    try {
      for (let index = 1; index <= 5; index += 1) {
        const account = await db.insert(schema.accounts).values({
          siteId: site.id,
          username: `priority-user-${index}`,
          accessToken: `access-priority-${index}`,
          apiToken: `sk-priority-${index}`,
          status: 'active',
          extraConfig: JSON.stringify({
            credentialMode: 'session',
          }),
        }).returning().get();

        const token = await db.insert(schema.accountTokens).values({
          accountId: account.id,
          name: `token-${index}`,
          token: `sk-priority-token-${index}`,
          enabled: true,
          isDefault: true,
        }).returning().get();

        const route = await db.insert(schema.tokenRoutes).values({
          modelPattern: `gpt-5.4-${index}`,
          enabled: true,
        }).returning().get();

        const channel = await db.insert(schema.routeChannels).values({
          routeId: route.id,
          accountId: account.id,
          tokenId: token.id,
          enabled: true,
        }).returning().get();

        const lease = await proxyChannelCoordinator.acquireChannelLease({
          channelId: channel.id,
          accountExtraConfig: account.extraConfig,
        });
        expect(lease.status).toBe('acquired');
        if (lease.status === 'acquired') {
          leases.push(lease.lease);
        }
      }

      const startedAt = Date.UTC(2026, 3, 1, 0, 0, 0);
      await runChannelRecoveryProbeSweep(startedAt);

      expect(probeRuntimeModelMock).toHaveBeenCalledTimes(4);
      expect(probeRuntimeModelMock.mock.calls.map((call) => call[0]?.tokenValue)).not.toContain('sk-priority-token-5');

      probeRuntimeModelMock.mockClear();

      await runChannelRecoveryProbeSweep(startedAt + 5 * 60 * 1000);

      expect(probeRuntimeModelMock).toHaveBeenCalledTimes(4);
      const secondSweepTokens = probeRuntimeModelMock.mock.calls.map((call) => call[0]?.tokenValue);
      expect(secondSweepTokens).toContain('sk-priority-token-5');
    } finally {
      for (const lease of leases) {
        lease.release();
      }
    }
  });
});
