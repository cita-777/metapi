import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync } from 'node:fs';
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

describe('channelRecoveryProbeService', () => {
  let db: DbModule['db'];
  let schema: DbModule['schema'];
  let runChannelRecoveryProbeSweep: RecoveryModule['runChannelRecoveryProbeSweep'];
  let resetChannelRecoveryProbeState: RecoveryModule['resetChannelRecoveryProbeState'];
  let proxyChannelCoordinator: CoordinatorModule['proxyChannelCoordinator'];
  let resetProxyChannelCoordinatorState: CoordinatorModule['resetProxyChannelCoordinatorState'];
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

    db = dbModule.db;
    schema = dbModule.schema;
    runChannelRecoveryProbeSweep = recoveryModule.runChannelRecoveryProbeSweep;
    resetChannelRecoveryProbeState = recoveryModule.resetChannelRecoveryProbeState;
    proxyChannelCoordinator = coordinatorModule.proxyChannelCoordinator;
    resetProxyChannelCoordinatorState = coordinatorModule.resetProxyChannelCoordinatorState;
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
});
