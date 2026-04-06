import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { eq } from 'drizzle-orm';

type DbModule = typeof import('../db/index.js');
type TokenRouterModule = typeof import('./tokenRouter.js');
type ConfigModule = typeof import('../config.js');
type ProxyChannelCoordinatorModule = typeof import('./proxyChannelCoordinator.js');

const mockedCatalogRoutingCost = vi.fn<(
  input: { siteId: number; accountId: number; modelName: string }
) => number | null>(() => null);

vi.mock('./modelPricingService.js', async () => {
  const actual = await vi.importActual<typeof import('./modelPricingService.js')>('./modelPricingService.js');
  return {
    ...actual,
    getCachedModelRoutingReferenceCost: mockedCatalogRoutingCost,
  };
});

describe('TokenRouter selection scoring', () => {
  let db: DbModule['db'];
  let schema: DbModule['schema'];
  let TokenRouter: TokenRouterModule['TokenRouter'];
  let tokenRouterTestUtils: TokenRouterModule['__tokenRouterTestUtils'];
  let invalidateTokenRouterCache: TokenRouterModule['invalidateTokenRouterCache'];
  let resetSiteRuntimeHealthState: TokenRouterModule['resetSiteRuntimeHealthState'];
  let flushSiteRuntimeHealthPersistence: TokenRouterModule['flushSiteRuntimeHealthPersistence'];
  let filterRecentlyFailedCandidates: TokenRouterModule['filterRecentlyFailedCandidates'];
  let config: ConfigModule['config'];
  let proxyChannelCoordinator: ProxyChannelCoordinatorModule['proxyChannelCoordinator'];
  let resetProxyChannelCoordinatorState: ProxyChannelCoordinatorModule['resetProxyChannelCoordinatorState'];
  let dataDir = '';
  let idSeed = 0;
  let originalRoutingWeights: typeof config.routingWeights;
  let originalRoutingFallbackUnitCost: number;
  let originalProxySessionChannelConcurrencyLimit: number;
  let originalProxySessionChannelQueueWaitMs: number;

  const nextId = () => {
    idSeed += 1;
    return idSeed;
  };

  beforeAll(async () => {
    dataDir = mkdtempSync(join(tmpdir(), 'metapi-token-router-selection-'));
    process.env.DATA_DIR = dataDir;

    await import('../db/migrate.js');
    const dbModule = await import('../db/index.js');
    const tokenRouterModule = await import('./tokenRouter.js');
    const configModule = await import('../config.js');
    const coordinatorModule = await import('./proxyChannelCoordinator.js');
    db = dbModule.db;
    schema = dbModule.schema;
    TokenRouter = tokenRouterModule.TokenRouter;
    tokenRouterTestUtils = tokenRouterModule.__tokenRouterTestUtils;
    invalidateTokenRouterCache = tokenRouterModule.invalidateTokenRouterCache;
    resetSiteRuntimeHealthState = tokenRouterModule.resetSiteRuntimeHealthState;
    flushSiteRuntimeHealthPersistence = tokenRouterModule.flushSiteRuntimeHealthPersistence;
    filterRecentlyFailedCandidates = tokenRouterModule.filterRecentlyFailedCandidates;
    config = configModule.config;
    proxyChannelCoordinator = coordinatorModule.proxyChannelCoordinator;
    resetProxyChannelCoordinatorState = coordinatorModule.resetProxyChannelCoordinatorState;
    originalRoutingWeights = { ...config.routingWeights };
    originalRoutingFallbackUnitCost = config.routingFallbackUnitCost;
    originalProxySessionChannelConcurrencyLimit = config.proxySessionChannelConcurrencyLimit;
    originalProxySessionChannelQueueWaitMs = config.proxySessionChannelQueueWaitMs;
  });

  beforeEach(async () => {
    idSeed = 0;
    mockedCatalogRoutingCost.mockReset();
    mockedCatalogRoutingCost.mockReturnValue(null);
    config.proxySessionChannelConcurrencyLimit = originalProxySessionChannelConcurrencyLimit;
    config.proxySessionChannelQueueWaitMs = originalProxySessionChannelQueueWaitMs;
    await db.delete(schema.routeChannels).run();
    await db.delete(schema.tokenRoutes).run();
    await db.delete(schema.settings).run();
    await db.delete(schema.accountTokens).run();
    await db.delete(schema.accounts).run();
    await db.delete(schema.sites).run();
    invalidateTokenRouterCache();
    resetSiteRuntimeHealthState();
    resetProxyChannelCoordinatorState();
  });

  afterAll(() => {
    config.routingWeights = { ...originalRoutingWeights };
    config.routingFallbackUnitCost = originalRoutingFallbackUnitCost;
    config.proxySessionChannelConcurrencyLimit = originalProxySessionChannelConcurrencyLimit;
    config.proxySessionChannelQueueWaitMs = originalProxySessionChannelQueueWaitMs;
    invalidateTokenRouterCache();
    resetSiteRuntimeHealthState();
    resetProxyChannelCoordinatorState();
    delete process.env.DATA_DIR;
  });

  async function createRoute(modelPattern: string) {
    return await db.insert(schema.tokenRoutes).values({
      modelPattern,
      enabled: true,
    }).returning().get();
  }

  async function createSite(namePrefix: string) {
    const id = nextId();
    return await db.insert(schema.sites).values({
      name: `${namePrefix}-${id}`,
      url: `https://${namePrefix}-${id}.example.com`,
      platform: 'new-api',
      status: 'active',
    }).returning().get();
  }

  async function createAccount(siteId: number, usernamePrefix: string, options: { extraConfig?: string | null } = {}) {
    const id = nextId();
    return await db.insert(schema.accounts).values({
      siteId,
      username: `${usernamePrefix}-${id}`,
      accessToken: `access-${id}`,
      apiToken: `sk-${id}`,
      status: 'active',
      extraConfig: options.extraConfig ?? null,
    }).returning().get();
  }

  async function createToken(accountId: number, name: string) {
    return await db.insert(schema.accountTokens).values({
      accountId,
      name,
      token: `token-${name}-${nextId()}`,
      enabled: true,
      isDefault: false,
    }).returning().get();
  }

  it('reuses a preferred channel only while it remains healthy', async () => {
    config.routingWeights = {
      baseWeightFactor: 1,
      valueScoreFactor: 0,
      costWeight: 0,
      balanceWeight: 0,
      usageWeight: 0,
    };

    const route = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-5.2',
      routingStrategy: 'stable_first',
      enabled: true,
    }).returning().get();
    const site = await createSite('sticky-site');
    const account = await createAccount(site.id, 'sticky-user');
    const tokenA = await createToken(account.id, 'sticky-a');
    const tokenB = await createToken(account.id, 'sticky-b');

    const preferredChannel = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: account.id,
      tokenId: tokenA.id,
      priority: 0,
      weight: 10,
      enabled: true,
      failCount: 0,
    }).returning().get();

    await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: account.id,
      tokenId: tokenB.id,
      priority: 0,
      weight: 10,
      enabled: true,
      failCount: 0,
    }).run();

    const router = new TokenRouter();
    const selected = await router.selectPreferredChannel('gpt-5.2', preferredChannel.id);
    expect(selected?.channel.id).toBe(preferredChannel.id);

    await db.update(schema.routeChannels).set({
      failCount: 4,
      lastFailAt: new Date().toISOString(),
    }).where(eq(schema.routeChannels.id, preferredChannel.id)).run();
    invalidateTokenRouterCache();

    await expect(router.selectPreferredChannel('gpt-5.2', preferredChannel.id)).resolves.toBeNull();
  });

  it('round-robins inside an oauth route unit while keeping one outer channel', async () => {
    const route = await createRoute('gpt-5.4');
    const site = await db.insert(schema.sites).values({
      name: 'oauth-pool-site',
      url: 'https://oauth-pool-site.example.com',
      platform: 'codex',
      status: 'active',
    }).returning().get();
    const accountA = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'pool-a@example.com',
      accessToken: 'oauth-access-a',
      apiToken: null,
      status: 'active',
      oauthProvider: 'codex',
      oauthAccountKey: 'pool-a',
      extraConfig: JSON.stringify({
        credentialMode: 'session',
        oauth: {
          provider: 'codex',
          accountId: 'pool-a',
          accountKey: 'pool-a',
          email: 'pool-a@example.com',
        },
      }),
    }).returning().get();
    const accountB = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'pool-b@example.com',
      accessToken: 'oauth-access-b',
      apiToken: null,
      status: 'active',
      oauthProvider: 'codex',
      oauthAccountKey: 'pool-b',
      extraConfig: JSON.stringify({
        credentialMode: 'session',
        oauth: {
          provider: 'codex',
          accountId: 'pool-b',
          accountKey: 'pool-b',
          email: 'pool-b@example.com',
        },
      }),
    }).returning().get();
    const unit = await db.insert(schema.oauthRouteUnits).values({
      siteId: site.id,
      provider: 'codex',
      name: 'Codex Pool A',
      strategy: 'round_robin',
      enabled: true,
    }).returning().get();
    await db.insert(schema.oauthRouteUnitMembers).values([
      {
        unitId: unit.id,
        accountId: accountA.id,
        sortOrder: 0,
      },
      {
        unitId: unit.id,
        accountId: accountB.id,
        sortOrder: 1,
      },
    ]).run();
    const channel = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: accountA.id,
      oauthRouteUnitId: unit.id,
      tokenId: null,
      priority: 0,
      weight: 10,
      enabled: true,
      manualOverride: false,
    }).returning().get();

    const router = new TokenRouter();
    const first = await router.selectChannel('gpt-5.4');
    const second = await router.selectChannel('gpt-5.4');

    expect(first?.channel.id).toBe(channel.id);
    expect(second?.channel.id).toBe(channel.id);
    expect(first?.account.id).toBe(accountA.id);
    expect(second?.account.id).toBe(accountB.id);
  });

  it('sticks to one oauth route unit member until that member becomes unavailable', async () => {
    const route = await createRoute('gpt-5.4');
    const site = await db.insert(schema.sites).values({
      name: 'oauth-stick-site',
      url: 'https://oauth-stick-site.example.com',
      platform: 'codex',
      status: 'active',
    }).returning().get();
    const accountA = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'stick-a@example.com',
      accessToken: 'oauth-stick-a',
      apiToken: null,
      status: 'active',
      oauthProvider: 'codex',
      oauthAccountKey: 'stick-a',
      extraConfig: JSON.stringify({
        credentialMode: 'session',
        oauth: {
          provider: 'codex',
          accountId: 'stick-a',
          accountKey: 'stick-a',
          email: 'stick-a@example.com',
        },
      }),
    }).returning().get();
    const accountB = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'stick-b@example.com',
      accessToken: 'oauth-stick-b',
      apiToken: null,
      status: 'active',
      oauthProvider: 'codex',
      oauthAccountKey: 'stick-b',
      extraConfig: JSON.stringify({
        credentialMode: 'session',
        oauth: {
          provider: 'codex',
          accountId: 'stick-b',
          accountKey: 'stick-b',
          email: 'stick-b@example.com',
        },
      }),
    }).returning().get();
    const unit = await db.insert(schema.oauthRouteUnits).values({
      siteId: site.id,
      provider: 'codex',
      name: 'Codex Stick Pool',
      strategy: 'stick_until_unavailable',
      enabled: true,
    }).returning().get();
    await db.insert(schema.oauthRouteUnitMembers).values([
      {
        unitId: unit.id,
        accountId: accountA.id,
        sortOrder: 0,
      },
      {
        unitId: unit.id,
        accountId: accountB.id,
        sortOrder: 1,
      },
    ]).run();
    const channel = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: accountA.id,
      oauthRouteUnitId: unit.id,
      tokenId: null,
      priority: 0,
      weight: 10,
      enabled: true,
      manualOverride: false,
    }).returning().get();

    const router = new TokenRouter();
    const first = await router.selectChannel('gpt-5.4');
    const second = await router.selectChannel('gpt-5.4');

    expect(first?.account.id).toBe(accountA.id);
    expect(second?.account.id).toBe(accountA.id);

    await router.recordFailure(channel.id, {
      status: 429,
      errorText: 'rate_limit',
      modelName: 'gpt-5.4',
    }, accountA.id);

    const third = await router.selectChannel('gpt-5.4');
    expect(third?.account.id).toBe(accountB.id);
  });

  it('avoids recently failed candidates by default when healthy alternatives exist', () => {
    const nowMs = Date.now();
    const filtered = filterRecentlyFailedCandidates([
      {
        channel: {
          failCount: 3,
          lastFailAt: new Date(nowMs).toISOString(),
        },
      },
      {
        channel: {
          failCount: 0,
          lastFailAt: null,
        },
      },
    ], nowMs);

    expect(filtered).toHaveLength(1);
    expect(filtered[0]?.channel.failCount).toBe(0);
  });

  it('normalizes probability across channels on the same site', async () => {
    config.routingWeights = {
      baseWeightFactor: 1,
      valueScoreFactor: 0,
      costWeight: 0,
      balanceWeight: 0,
      usageWeight: 0,
    };

    const route = await createRoute('claude-haiku-4-5-20251001');

    const siteA = await createSite('site-a');
    const accountA = await createAccount(siteA.id, 'user-a');
    const tokenA1 = await createToken(accountA.id, 'a-1');
    const tokenA2 = await createToken(accountA.id, 'a-2');

    const siteB = await createSite('site-b');
    const accountB = await createAccount(siteB.id, 'user-b');
    const tokenB = await createToken(accountB.id, 'b-1');

    const channelA1 = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: accountA.id,
      tokenId: tokenA1.id,
      priority: 0,
      weight: 10,
      enabled: true,
    }).returning().get();

    const channelA2 = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: accountA.id,
      tokenId: tokenA2.id,
      priority: 0,
      weight: 10,
      enabled: true,
    }).returning().get();

    const channelB = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: accountB.id,
      tokenId: tokenB.id,
      priority: 0,
      weight: 10,
      enabled: true,
    }).returning().get();

    const decision = await new TokenRouter().explainSelection('claude-haiku-4-5-20251001');
    const probMap = new Map(decision.candidates.map((candidate) => [candidate.channelId, candidate.probability]));

    const probA1 = probMap.get(channelA1.id) ?? 0;
    const probA2 = probMap.get(channelA2.id) ?? 0;
    const probB = probMap.get(channelB.id) ?? 0;

    expect(probA1).toBeCloseTo(25, 1);
    expect(probA2).toBeCloseTo(25, 1);
    expect(probB).toBeCloseTo(50, 1);
    expect(probA1 + probA2).toBeCloseTo(probB, 1);
  });

  it('uses observed channel cost from real routing results when scoring cost priority', async () => {
    config.routingWeights = {
      baseWeightFactor: 0.35,
      valueScoreFactor: 0.65,
      costWeight: 1,
      balanceWeight: 0,
      usageWeight: 0,
    };

    const route = await createRoute('claude-opus-4-6');

    const siteCheap = await createSite('cheap-site');
    const accountCheap = await createAccount(siteCheap.id, 'cheap-user');
    const tokenCheap = await createToken(accountCheap.id, 'cheap-token');
    await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: accountCheap.id,
      tokenId: tokenCheap.id,
      priority: 0,
      weight: 10,
      enabled: true,
      successCount: 10,
      failCount: 0,
      totalCost: 0.01,
    }).run();

    const siteExpensive = await createSite('expensive-site');
    const accountExpensive = await createAccount(siteExpensive.id, 'expensive-user');
    const tokenExpensive = await createToken(accountExpensive.id, 'exp-token');
    await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: accountExpensive.id,
      tokenId: tokenExpensive.id,
      priority: 0,
      weight: 10,
      enabled: true,
      successCount: 10,
      failCount: 0,
      totalCost: 0.1,
    }).run();

    const decision = await new TokenRouter().explainSelection('claude-opus-4-6');
    const cheapCandidate = decision.candidates.find((candidate) => candidate.siteName.startsWith('cheap-site'));
    const expensiveCandidate = decision.candidates.find((candidate) => candidate.siteName.startsWith('expensive-site'));

    expect(cheapCandidate).toBeTruthy();
    expect(expensiveCandidate).toBeTruthy();
    expect((cheapCandidate?.probability || 0)).toBeGreaterThan(expensiveCandidate?.probability || 0);
    expect(cheapCandidate?.reason || '').toContain('成本=实测');
    expect(expensiveCandidate?.reason || '').toContain('成本=实测');
  });

  it('uses runtime-configured fallback unit cost when observed and configured costs are missing', async () => {
    config.routingWeights = {
      baseWeightFactor: 0.35,
      valueScoreFactor: 0.65,
      costWeight: 1,
      balanceWeight: 0,
      usageWeight: 0,
    };
    config.routingFallbackUnitCost = 0.02;

    const route = await createRoute('claude-sonnet-4-6');

    const siteFallback = await createSite('fallback-site');
    const accountFallback = await createAccount(siteFallback.id, 'fallback-user');
    const tokenFallback = await createToken(accountFallback.id, 'fallback-token');
    await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: accountFallback.id,
      tokenId: tokenFallback.id,
      priority: 0,
      weight: 10,
      enabled: true,
      successCount: 0,
      failCount: 0,
      totalCost: 0,
    }).run();

    const siteObserved = await createSite('observed-site');
    const accountObserved = await createAccount(siteObserved.id, 'observed-user');
    const tokenObserved = await createToken(accountObserved.id, 'observed-token');
    await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: accountObserved.id,
      tokenId: tokenObserved.id,
      priority: 0,
      weight: 10,
      enabled: true,
      successCount: 10,
      failCount: 0,
      totalCost: 2, // unit cost 0.2
    }).run();

    const decision = await new TokenRouter().explainSelection('claude-sonnet-4-6');
    const fallbackCandidate = decision.candidates.find((candidate) => candidate.siteName.startsWith('fallback-site'));
    const observedCandidate = decision.candidates.find((candidate) => candidate.siteName.startsWith('observed-site'));

    expect(fallbackCandidate).toBeTruthy();
    expect(observedCandidate).toBeTruthy();
    expect((fallbackCandidate?.probability || 0)).toBeGreaterThan(observedCandidate?.probability || 0);
    expect(fallbackCandidate?.reason || '').toContain('成本=默认:0.020000');
  });

  it('penalizes fallback-cost channels when fallback unit cost is set very high', async () => {
    config.routingWeights = {
      baseWeightFactor: 0.35,
      valueScoreFactor: 0.65,
      costWeight: 0.75,
      balanceWeight: 0.15,
      usageWeight: 0.1,
    };
    config.routingFallbackUnitCost = 1000;

    const route = await createRoute('gpt-5-nano');

    const siteFallback = await createSite('fallback-high-balance');
    const accountFallback = await db.insert(schema.accounts).values({
      siteId: siteFallback.id,
      username: `fallback-high-balance-${nextId()}`,
      accessToken: `access-${nextId()}`,
      apiToken: `sk-${nextId()}`,
      status: 'active',
      balance: 10_000,
    }).returning().get();
    const tokenFallback = await createToken(accountFallback.id, 'fallback-token');
    await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: accountFallback.id,
      tokenId: tokenFallback.id,
      priority: 0,
      weight: 10,
      enabled: true,
      successCount: 0,
      failCount: 0,
      totalCost: 0,
    }).run();

    const siteObserved = await createSite('observed-low-balance');
    const accountObserved = await db.insert(schema.accounts).values({
      siteId: siteObserved.id,
      username: `observed-low-balance-${nextId()}`,
      accessToken: `access-${nextId()}`,
      apiToken: `sk-${nextId()}`,
      status: 'active',
      balance: 0,
    }).returning().get();
    const tokenObserved = await createToken(accountObserved.id, 'observed-token');
    await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: accountObserved.id,
      tokenId: tokenObserved.id,
      priority: 0,
      weight: 10,
      enabled: true,
      successCount: 10,
      failCount: 0,
      totalCost: 10, // observed unit cost = 1
    }).run();

    const decision = await new TokenRouter().explainSelection('gpt-5-nano');
    const fallbackCandidate = decision.candidates.find((candidate) => candidate.siteName.startsWith('fallback-high-balance'));
    const observedCandidate = decision.candidates.find((candidate) => candidate.siteName.startsWith('observed-low-balance'));

    expect(fallbackCandidate).toBeTruthy();
    expect(observedCandidate).toBeTruthy();
    expect((fallbackCandidate?.probability || 0)).toBeLessThan(1);
    expect((observedCandidate?.probability || 0)).toBeGreaterThan(99);
    expect(fallbackCandidate?.reason || '').toContain('成本=默认:1000.000000');
  });

  it('uses cached catalog routing cost when observed and configured costs are missing', async () => {
    config.routingWeights = {
      baseWeightFactor: 0.35,
      valueScoreFactor: 0.65,
      costWeight: 1,
      balanceWeight: 0,
      usageWeight: 0,
    };
    config.routingFallbackUnitCost = 100;

    const route = await createRoute('claude-sonnet-4-5-20250929');

    const siteCatalog = await createSite('catalog-site');
    const accountCatalog = await createAccount(siteCatalog.id, 'catalog-user');
    const tokenCatalog = await createToken(accountCatalog.id, 'catalog-token');
    await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: accountCatalog.id,
      tokenId: tokenCatalog.id,
      priority: 0,
      weight: 10,
      enabled: true,
      successCount: 0,
      failCount: 0,
      totalCost: 0,
    }).run();

    const siteFallback = await createSite('fallback-site');
    const accountFallback = await createAccount(siteFallback.id, 'fallback-user');
    const tokenFallback = await createToken(accountFallback.id, 'fallback-token');
    await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: accountFallback.id,
      tokenId: tokenFallback.id,
      priority: 0,
      weight: 10,
      enabled: true,
      successCount: 0,
      failCount: 0,
      totalCost: 0,
    }).run();

    mockedCatalogRoutingCost.mockImplementation(({ accountId, modelName }) => {
      if (accountId !== accountCatalog.id) return null;
      if (modelName !== 'claude-sonnet-4-5-20250929') return null;
      return 0.2;
    });

    const decision = await new TokenRouter().explainSelection('claude-sonnet-4-5-20250929');
    const catalogCandidate = decision.candidates.find((candidate) => candidate.siteName.startsWith('catalog-site'));
    const fallbackCandidate = decision.candidates.find((candidate) => candidate.siteName.startsWith('fallback-site'));

    expect(catalogCandidate).toBeTruthy();
    expect(fallbackCandidate).toBeTruthy();
    expect((catalogCandidate?.probability || 0)).toBeGreaterThan(fallbackCandidate?.probability || 0);
    expect(catalogCandidate?.reason || '').toContain('成本=目录:0.200000');
    expect(fallbackCandidate?.reason || '').toContain('成本=默认:100.000000');
  });

  it('downweights a site after transient failures and restores it quickly after success', async () => {
    config.routingWeights = {
      baseWeightFactor: 1,
      valueScoreFactor: 0,
      costWeight: 0,
      balanceWeight: 0,
      usageWeight: 0,
    };

    const route = await createRoute('gpt-5.4');

    const siteA = await createSite('runtime-a');
    const accountA = await createAccount(siteA.id, 'runtime-user-a');
    const tokenA = await createToken(accountA.id, 'runtime-token-a');
    const channelA = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: accountA.id,
      tokenId: tokenA.id,
      priority: 0,
      weight: 10,
      enabled: true,
    }).returning().get();

    const siteB = await createSite('runtime-b');
    const accountB = await createAccount(siteB.id, 'runtime-user-b');
    const tokenB = await createToken(accountB.id, 'runtime-token-b');
    const channelB = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: accountB.id,
      tokenId: tokenB.id,
      priority: 0,
      weight: 10,
      enabled: true,
    }).returning().get();

    const router = new TokenRouter();
    let decision = await router.explainSelection('gpt-5.4');
    let candidateA = decision.candidates.find((candidate) => candidate.channelId === channelA.id);
    let candidateB = decision.candidates.find((candidate) => candidate.channelId === channelB.id);
    expect(candidateA?.probability).toBeCloseTo(50, 1);
    expect(candidateB?.probability).toBeCloseTo(50, 1);

    await router.recordFailure(channelA.id, {
      status: 502,
      errorText: 'Bad gateway',
    });
    await db.update(schema.routeChannels).set({
      cooldownUntil: null,
      lastFailAt: null,
      failCount: 0,
    }).where(eq(schema.routeChannels.id, channelA.id)).run();
    invalidateTokenRouterCache();

    decision = await router.explainSelection('gpt-5.4');
    candidateA = decision.candidates.find((candidate) => candidate.channelId === channelA.id);
    candidateB = decision.candidates.find((candidate) => candidate.channelId === channelB.id);
    expect(candidateA).toBeTruthy();
    expect(candidateB).toBeTruthy();
    expect((candidateA?.probability || 0)).toBeLessThan(30);
    expect(candidateA?.reason || '').toContain('运行时健康=');
    expect((candidateB?.probability || 0)).toBeGreaterThan(70);

    await router.recordSuccess(channelA.id, 800, 0);
    invalidateTokenRouterCache();

    decision = await router.explainSelection('gpt-5.4');
    candidateA = decision.candidates.find((candidate) => candidate.channelId === channelA.id);
    candidateB = decision.candidates.find((candidate) => candidate.channelId === channelB.id);
    expect((candidateA?.probability || 0)).toBeGreaterThan(40);
    expect((candidateB?.probability || 0)).toBeLessThan(60);
  });

  it('opens a site breaker after repeated transient failures and closes it after recovery', async () => {
    config.routingWeights = {
      baseWeightFactor: 1,
      valueScoreFactor: 0,
      costWeight: 0,
      balanceWeight: 0,
      usageWeight: 0,
    };

    const route = await createRoute('gpt-5.3');

    const siteA = await createSite('breaker-a');
    const accountA = await createAccount(siteA.id, 'breaker-user-a');
    const tokenA = await createToken(accountA.id, 'breaker-token-a');
    const channelA = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: accountA.id,
      tokenId: tokenA.id,
      priority: 0,
      weight: 10,
      enabled: true,
    }).returning().get();

    const siteB = await createSite('breaker-b');
    const accountB = await createAccount(siteB.id, 'breaker-user-b');
    const tokenB = await createToken(accountB.id, 'breaker-token-b');
    const channelB = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: accountB.id,
      tokenId: tokenB.id,
      priority: 0,
      weight: 10,
      enabled: true,
    }).returning().get();

    const router = new TokenRouter();
    for (let index = 0; index < 3; index += 1) {
      await router.recordFailure(channelA.id, {
        status: 502,
        errorText: 'Gateway timeout',
      });
    }
    await db.update(schema.routeChannels).set({
      cooldownUntil: null,
      lastFailAt: null,
      failCount: 0,
    }).where(eq(schema.routeChannels.id, channelA.id)).run();
    invalidateTokenRouterCache();

    let decision = await router.explainSelection('gpt-5.3');
    const breakerCandidateA = decision.candidates.find((candidate) => candidate.channelId === channelA.id);
    const breakerCandidateB = decision.candidates.find((candidate) => candidate.channelId === channelB.id);
    expect(breakerCandidateA?.reason || '').toContain('站点熔断');
    expect((breakerCandidateA?.probability || 0)).toBe(0);
    expect((breakerCandidateB?.probability || 0)).toBe(100);
    expect(decision.summary.join(' ')).toContain('站点熔断避让');

    await router.recordSuccess(channelA.id, 600, 0);
    invalidateTokenRouterCache();

    decision = await router.explainSelection('gpt-5.3');
    const recoveredCandidateA = decision.candidates.find((candidate) => candidate.channelId === channelA.id);
    const recoveredCandidateB = decision.candidates.find((candidate) => candidate.channelId === channelB.id);
    expect((recoveredCandidateA?.probability || 0)).toBeGreaterThan(30);
    expect((recoveredCandidateB?.probability || 0)).toBeLessThan(70);
  });

  it('clears persisted runtime breaker state when channel cooldown is manually cleared', async () => {
    config.routingWeights = {
      baseWeightFactor: 1,
      valueScoreFactor: 0,
      costWeight: 0,
      balanceWeight: 0,
      usageWeight: 0,
    };

    const route = await createRoute('gpt-5.4');

    const siteA = await createSite('clear-breaker-a');
    const accountA = await createAccount(siteA.id, 'clear-breaker-user-a');
    const tokenA = await createToken(accountA.id, 'clear-breaker-token-a');
    const channelA = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: accountA.id,
      tokenId: tokenA.id,
      priority: 0,
      weight: 10,
      enabled: true,
    }).returning().get();

    const siteB = await createSite('clear-breaker-b');
    const accountB = await createAccount(siteB.id, 'clear-breaker-user-b');
    const tokenB = await createToken(accountB.id, 'clear-breaker-token-b');
    const channelB = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: accountB.id,
      tokenId: tokenB.id,
      priority: 0,
      weight: 10,
      enabled: true,
    }).returning().get();

    const router = new TokenRouter();
    for (let index = 0; index < 3; index += 1) {
      await router.recordFailure(channelA.id, {
        status: 502,
        errorText: 'Bad gateway',
        modelName: 'gpt-5.4',
      });
    }
    await db.update(schema.routeChannels).set({
      cooldownUntil: null,
      lastFailAt: null,
      failCount: 0,
      consecutiveFailCount: 0,
      cooldownLevel: 0,
    }).where(eq(schema.routeChannels.id, channelA.id)).run();
    invalidateTokenRouterCache();

    let decision = await router.explainSelection('gpt-5.4');
    const breakerCandidateA = decision.candidates.find((candidate) => candidate.channelId === channelA.id);
    const breakerCandidateB = decision.candidates.find((candidate) => candidate.channelId === channelB.id);
    expect(breakerCandidateA?.reason || '').toContain('熔断');
    expect((breakerCandidateA?.probability || 0)).toBe(0);
    expect((breakerCandidateB?.probability || 0)).toBe(100);

    await router.clearChannelFailureState([channelA.id]);
    resetSiteRuntimeHealthState();
    invalidateTokenRouterCache();

    const refreshedChannel = await db.select().from(schema.routeChannels)
      .where(eq(schema.routeChannels.id, channelA.id))
      .get();
    expect(refreshedChannel).toMatchObject({
      failCount: 0,
      lastFailAt: null,
      consecutiveFailCount: 0,
      cooldownLevel: 0,
      cooldownUntil: null,
    });

    decision = await router.explainSelection('gpt-5.4');
    const recoveredCandidateA = decision.candidates.find((candidate) => candidate.channelId === channelA.id);
    const recoveredCandidateB = decision.candidates.find((candidate) => candidate.channelId === channelB.id);
    expect(recoveredCandidateA?.reason || '').not.toContain('熔断');
    expect((recoveredCandidateA?.probability || 0)).toBeGreaterThan(30);
    expect((recoveredCandidateB?.probability || 0)).toBeLessThan(70);
  });

  it('does not open a site breaker for repeated timeout validation errors', async () => {
    config.routingWeights = {
      baseWeightFactor: 1,
      valueScoreFactor: 0,
      costWeight: 0,
      balanceWeight: 0,
      usageWeight: 0,
    };

    const route = await createRoute('gpt-5.4');

    const siteA = await createSite('timeout-validation-a');
    const accountA = await createAccount(siteA.id, 'timeout-validation-user-a');
    const tokenA = await createToken(accountA.id, 'timeout-validation-token-a');
    const channelA = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: accountA.id,
      tokenId: tokenA.id,
      priority: 0,
      weight: 10,
      enabled: true,
    }).returning().get();

    const siteB = await createSite('timeout-validation-b');
    const accountB = await createAccount(siteB.id, 'timeout-validation-user-b');
    const tokenB = await createToken(accountB.id, 'timeout-validation-token-b');
    const channelB = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: accountB.id,
      tokenId: tokenB.id,
      priority: 0,
      weight: 10,
      enabled: true,
    }).returning().get();

    const router = new TokenRouter();
    for (let index = 0; index < 3; index += 1) {
      await router.recordFailure(channelA.id, {
        status: 400,
        errorText: 'invalid timeout parameter',
      });
    }
    await db.update(schema.routeChannels).set({
      cooldownUntil: null,
      lastFailAt: null,
      failCount: 0,
    }).where(eq(schema.routeChannels.id, channelA.id)).run();
    invalidateTokenRouterCache();

    const decision = await router.explainSelection('gpt-5.4');
    const candidateA = decision.candidates.find((candidate) => candidate.channelId === channelA.id);
    const candidateB = decision.candidates.find((candidate) => candidate.channelId === channelB.id);

    expect(candidateA).toBeTruthy();
    expect(candidateB).toBeTruthy();
    expect(candidateA?.reason || '').not.toContain('站点熔断');
    expect(candidateB?.reason || '').not.toContain('站点熔断');
    expect(decision.summary.join(' ')).not.toContain('站点熔断避让');
    expect((candidateA?.probability || 0)).toBeGreaterThan(0);
  });

  it('uses persisted site success and latency history to prefer historically healthier sites', async () => {
    config.routingWeights = {
      baseWeightFactor: 1,
      valueScoreFactor: 0,
      costWeight: 0,
      balanceWeight: 0,
      usageWeight: 0,
    };

    const route = await createRoute('claude-4-sonnet');

    const siteStable = await createSite('history-stable');
    const accountStable = await createAccount(siteStable.id, 'history-user-stable');
    const tokenStable = await createToken(accountStable.id, 'history-token-stable');
    await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: accountStable.id,
      tokenId: tokenStable.id,
      priority: 0,
      weight: 10,
      enabled: true,
      successCount: 90,
      failCount: 10,
      totalLatencyMs: 90 * 240,
    }).run();

    const siteWeak = await createSite('history-weak');
    const accountWeak = await createAccount(siteWeak.id, 'history-user-weak');
    const tokenWeak = await createToken(accountWeak.id, 'history-token-weak');
    await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: accountWeak.id,
      tokenId: tokenWeak.id,
      priority: 0,
      weight: 10,
      enabled: true,
      successCount: 20,
      failCount: 30,
      totalLatencyMs: 20 * 5200,
    }).run();

    const decision = await new TokenRouter().explainSelection('claude-4-sonnet');
    const stableCandidate = decision.candidates.find((candidate) => candidate.siteName.startsWith('history-stable'));
    const weakCandidate = decision.candidates.find((candidate) => candidate.siteName.startsWith('history-weak'));

    expect(stableCandidate).toBeTruthy();
    expect(weakCandidate).toBeTruthy();
    expect((stableCandidate?.probability || 0)).toBeGreaterThan(weakCandidate?.probability || 0);
    expect(stableCandidate?.reason || '').toContain('历史健康=');
    expect(stableCandidate?.reason || '').toContain('成功率=90.0%');
    expect(weakCandidate?.reason || '').toContain('成功率=40.0%');
  });

  it('stable_first ranks recent and fallback success rate ahead of balance-heavy weak sites', async () => {
    config.routingWeights = {
      baseWeightFactor: 0,
      valueScoreFactor: 1,
      costWeight: 0.1,
      balanceWeight: 10,
      usageWeight: 0,
    };

    const route = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-5.4',
      routingStrategy: 'stable_first',
      enabled: true,
    }).returning().get();

    const siteStable = await createSite('stable-rate-front');
    const accountStable = await createAccount(siteStable.id, 'stable-rate-user-front');
    const tokenStable = await createToken(accountStable.id, 'stable-rate-token-front');
    const stableChannel = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: accountStable.id,
      tokenId: tokenStable.id,
      priority: 0,
      weight: 10,
      enabled: true,
      successCount: 80,
      failCount: 4,
      totalLatencyMs: 80 * 380,
    }).returning().get();

    const siteWeak = await createSite('stable-rate-back');
    const accountWeak = await createAccount(siteWeak.id, 'stable-rate-user-back');
    await db.update(schema.accounts).set({
      balance: 999999,
    }).where(eq(schema.accounts.id, accountWeak.id)).run();
    const tokenWeak = await createToken(accountWeak.id, 'stable-rate-token-back');
    const weakChannel = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: accountWeak.id,
      tokenId: tokenWeak.id,
      priority: 0,
      weight: 10,
      enabled: true,
      successCount: 5,
      failCount: 21,
      totalLatencyMs: 5 * 1600,
    }).returning().get();

    const decision = await new TokenRouter().explainSelection('gpt-5.4');
    const stableCandidate = decision.candidates.find((candidate) => candidate.channelId === stableChannel.id);
    const weakCandidate = decision.candidates.find((candidate) => candidate.channelId === weakChannel.id);

    expect(stableCandidate).toBeTruthy();
    expect(weakCandidate).toBeTruthy();
    expect(decision.selectedChannelId).toBe(stableChannel.id);
    expect((stableCandidate?.probability || 0)).toBeGreaterThan(weakCandidate?.probability || 0);
    expect(stableCandidate?.reason || '').toContain('近期成功率=');
    expect(weakCandidate?.reason || '').toContain('综合近期成功率=');
  });

  it('reloads persisted runtime health after in-memory reset', async () => {
    config.routingWeights = {
      baseWeightFactor: 1,
      valueScoreFactor: 0,
      costWeight: 0,
      balanceWeight: 0,
      usageWeight: 0,
    };

    const route = await createRoute('gpt-4o-mini');

    const siteA = await createSite('persist-a');
    const accountA = await createAccount(siteA.id, 'persist-user-a');
    const tokenA = await createToken(accountA.id, 'persist-token-a');
    const channelA = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: accountA.id,
      tokenId: tokenA.id,
      priority: 0,
      weight: 10,
      enabled: true,
    }).returning().get();

    const siteB = await createSite('persist-b');
    const accountB = await createAccount(siteB.id, 'persist-user-b');
    const tokenB = await createToken(accountB.id, 'persist-token-b');
    const channelB = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: accountB.id,
      tokenId: tokenB.id,
      priority: 0,
      weight: 10,
      enabled: true,
    }).returning().get();

    const router = new TokenRouter();
    await router.recordFailure(channelA.id, {
      status: 502,
      errorText: 'Gateway timeout',
      modelName: 'gpt-4o-mini',
    });
    await db.update(schema.routeChannels).set({
      cooldownUntil: null,
      lastFailAt: null,
      failCount: 0,
    }).where(eq(schema.routeChannels.id, channelA.id)).run();
    await flushSiteRuntimeHealthPersistence();

    const persisted = await db.select().from(schema.settings)
      .where(eq(schema.settings.key, 'token_router_site_runtime_health_v1'))
      .get();
    expect(persisted?.value).toBeTruthy();

    resetSiteRuntimeHealthState();
    invalidateTokenRouterCache();

    const decision = await new TokenRouter().explainSelection('gpt-4o-mini');
    const candidateA = decision.candidates.find((candidate) => candidate.channelId === channelA.id);
    const candidateB = decision.candidates.find((candidate) => candidate.channelId === channelB.id);

    expect(candidateA).toBeTruthy();
    expect(candidateB).toBeTruthy();
    expect((candidateA?.probability || 0)).toBeLessThan((candidateB?.probability || 0));
    expect(candidateA?.reason || '').toContain('运行时健康=');
  });

  it('keeps a recovered stable_first site behind healthier peers until recent success rebuilds', async () => {
    config.routingWeights = {
      baseWeightFactor: 1,
      valueScoreFactor: 0,
      costWeight: 0,
      balanceWeight: 0,
      usageWeight: 0,
    };

    const route = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-5.3',
      routingStrategy: 'stable_first',
      enabled: true,
    }).returning().get();

    const siteRecovered = await createSite('stable-recovery-a');
    const accountRecovered = await createAccount(siteRecovered.id, 'stable-recovery-user-a');
    const tokenRecovered = await createToken(accountRecovered.id, 'stable-recovery-token-a');
    const recoveredChannel = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: accountRecovered.id,
      tokenId: tokenRecovered.id,
      priority: 0,
      weight: 10,
      enabled: true,
    }).returning().get();

    const siteHealthy = await createSite('stable-recovery-b');
    const accountHealthy = await createAccount(siteHealthy.id, 'stable-recovery-user-b');
    const tokenHealthy = await createToken(accountHealthy.id, 'stable-recovery-token-b');
    const healthyChannel = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: accountHealthy.id,
      tokenId: tokenHealthy.id,
      priority: 0,
      weight: 10,
      enabled: true,
    }).returning().get();

    const router = new TokenRouter();
    for (let index = 0; index < 3; index += 1) {
      await router.recordFailure(recoveredChannel.id, {
        status: 502,
        errorText: 'Gateway timeout',
        modelName: 'gpt-5.3',
      });
    }
    await db.update(schema.routeChannels).set({
      cooldownUntil: null,
      lastFailAt: null,
      failCount: 0,
      consecutiveFailCount: 0,
      cooldownLevel: 0,
    }).where(eq(schema.routeChannels.id, recoveredChannel.id)).run();

    await router.recordSuccess(recoveredChannel.id, 900, 0, 'gpt-5.3');
    for (let index = 0; index < 4; index += 1) {
      await router.recordSuccess(healthyChannel.id, 320, 0, 'gpt-5.3');
    }
    invalidateTokenRouterCache();

    const preview = await router.previewSelectedChannel('gpt-5.3');
    const decision = await router.explainSelection('gpt-5.3');
    const recoveredCandidate = decision.candidates.find((candidate) => candidate.channelId === recoveredChannel.id);
    const healthyCandidate = decision.candidates.find((candidate) => candidate.channelId === healthyChannel.id);

    expect(preview?.channel.id).toBe(healthyChannel.id);
    expect(decision.selectedChannelId).toBe(healthyChannel.id);
    expect((recoveredCandidate?.probability || 0)).toBeLessThan(healthyCandidate?.probability || 0);
    expect(recoveredCandidate?.reason || '').toContain('近期成功率=');
    expect(healthyCandidate?.reason || '').toContain('近期成功率=');
  });

  it('penalizes the failed model more than unrelated models on the same site', async () => {
    config.routingWeights = {
      baseWeightFactor: 1,
      valueScoreFactor: 0,
      costWeight: 0,
      balanceWeight: 0,
      usageWeight: 0,
    };

    const gptRoute = await createRoute('gpt-5.4');
    const claudeRoute = await createRoute('claude-sonnet-4-6');

    const siteA = await createSite('model-aware-a');
    const accountA = await createAccount(siteA.id, 'model-aware-user-a');
    const tokenA = await createToken(accountA.id, 'model-aware-token-a');
    const gptChannelA = await db.insert(schema.routeChannels).values({
      routeId: gptRoute.id,
      accountId: accountA.id,
      tokenId: tokenA.id,
      priority: 0,
      weight: 10,
      enabled: true,
    }).returning().get();
    await db.insert(schema.routeChannels).values({
      routeId: claudeRoute.id,
      accountId: accountA.id,
      tokenId: tokenA.id,
      priority: 0,
      weight: 10,
      enabled: true,
    }).run();

    const siteB = await createSite('model-aware-b');
    const accountB = await createAccount(siteB.id, 'model-aware-user-b');
    const tokenB = await createToken(accountB.id, 'model-aware-token-b');
    await db.insert(schema.routeChannels).values([
      {
        routeId: gptRoute.id,
        accountId: accountB.id,
        tokenId: tokenB.id,
        priority: 0,
        weight: 10,
        enabled: true,
      },
      {
        routeId: claudeRoute.id,
        accountId: accountB.id,
        tokenId: tokenB.id,
        priority: 0,
        weight: 10,
        enabled: true,
      },
    ]).run();

    const router = new TokenRouter();
    await router.recordFailure(gptChannelA.id, {
      status: 502,
      errorText: 'Bad gateway',
      modelName: 'gpt-5.4',
    });
    await db.update(schema.routeChannels).set({
      cooldownUntil: null,
      lastFailAt: null,
      failCount: 0,
    }).where(eq(schema.routeChannels.id, gptChannelA.id)).run();
    invalidateTokenRouterCache();

    const gptDecision = await router.explainSelection('gpt-5.4');
    const claudeDecision = await router.explainSelection('claude-sonnet-4-6');
    const gptCandidateA = gptDecision.candidates.find((candidate) => candidate.siteName.startsWith('model-aware-a'));
    const claudeCandidateA = claudeDecision.candidates.find((candidate) => candidate.siteName.startsWith('model-aware-a'));

    expect(gptCandidateA).toBeTruthy();
    expect(claudeCandidateA).toBeTruthy();
    expect((gptCandidateA?.probability || 0)).toBeLessThan((claudeCandidateA?.probability || 0));
    expect(gptCandidateA?.reason || '').toContain('模型=');
  });

  it('treats unknown provider for model as model-scoped degradation instead of opening a site breaker', async () => {
    config.routingWeights = {
      baseWeightFactor: 1,
      valueScoreFactor: 0,
      costWeight: 0,
      balanceWeight: 0,
      usageWeight: 0,
    };

    const gptRoute = await createRoute('gpt-5.4');
    const claudeRoute = await createRoute('claude-sonnet-4-6');

    const siteA = await createSite('unknown-provider-a');
    const accountA = await createAccount(siteA.id, 'unknown-provider-user-a');
    const tokenA = await createToken(accountA.id, 'unknown-provider-token-a');
    const gptChannelA = await db.insert(schema.routeChannels).values({
      routeId: gptRoute.id,
      accountId: accountA.id,
      tokenId: tokenA.id,
      priority: 0,
      weight: 10,
      enabled: true,
    }).returning().get();
    await db.insert(schema.routeChannels).values({
      routeId: claudeRoute.id,
      accountId: accountA.id,
      tokenId: tokenA.id,
      priority: 0,
      weight: 10,
      enabled: true,
    }).run();

    const siteB = await createSite('unknown-provider-b');
    const accountB = await createAccount(siteB.id, 'unknown-provider-user-b');
    const tokenB = await createToken(accountB.id, 'unknown-provider-token-b');
    await db.insert(schema.routeChannels).values([
      {
        routeId: gptRoute.id,
        accountId: accountB.id,
        tokenId: tokenB.id,
        priority: 0,
        weight: 10,
        enabled: true,
      },
      {
        routeId: claudeRoute.id,
        accountId: accountB.id,
        tokenId: tokenB.id,
        priority: 0,
        weight: 10,
        enabled: true,
      },
    ]).run();

    const router = new TokenRouter();
    for (let index = 0; index < 3; index += 1) {
      await router.recordFailure(gptChannelA.id, {
        status: 502,
        errorText: 'unknown provider for model gpt-5.4',
        modelName: 'gpt-5.4',
      });
    }
    await db.update(schema.routeChannels).set({
      cooldownUntil: null,
      lastFailAt: null,
      failCount: 0,
    }).where(eq(schema.routeChannels.id, gptChannelA.id)).run();
    invalidateTokenRouterCache();

    const gptDecision = await router.explainSelection('gpt-5.4');
    const claudeDecision = await router.explainSelection('claude-sonnet-4-6');
    const gptCandidateA = gptDecision.candidates.find((candidate) => candidate.siteName.startsWith('unknown-provider-a'));
    const claudeCandidateA = claudeDecision.candidates.find((candidate) => candidate.siteName.startsWith('unknown-provider-a'));

    expect(gptCandidateA).toBeTruthy();
    expect(claudeCandidateA).toBeTruthy();
    expect(gptDecision.summary.join(' ')).not.toContain('站点熔断避让');
    expect(claudeDecision.summary.join(' ')).not.toContain('站点熔断避让');
    expect(gptCandidateA?.reason || '').not.toContain('站点熔断');
    expect(claudeCandidateA?.reason || '').not.toContain('站点熔断');
    expect((gptCandidateA?.probability || 0)).toBeLessThan((claudeCandidateA?.probability || 0));
    expect(gptCandidateA?.reason || '').toContain('模型=');
  });

  it('stable_first deterministically chooses the healthiest candidate', async () => {
    config.routingWeights = {
      baseWeightFactor: 1,
      valueScoreFactor: 0,
      costWeight: 0,
      balanceWeight: 0,
      usageWeight: 0,
    };

    const route = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-5.1',
      routingStrategy: 'stable_first',
      enabled: true,
    }).returning().get();

    const siteA = await createSite('stable-first-a');
    const accountA = await createAccount(siteA.id, 'stable-first-user-a');
    const tokenA = await createToken(accountA.id, 'stable-first-token-a');
    const channelA = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: accountA.id,
      tokenId: tokenA.id,
      priority: 0,
      weight: 10,
      enabled: true,
    }).returning().get();

    const siteB = await createSite('stable-first-b');
    const accountB = await createAccount(siteB.id, 'stable-first-user-b');
    const tokenB = await createToken(accountB.id, 'stable-first-token-b');
    const channelB = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: accountB.id,
      tokenId: tokenB.id,
      priority: 0,
      weight: 10,
      enabled: true,
    }).returning().get();

    const router = new TokenRouter();
    await router.recordFailure(channelA.id, {
      status: 502,
      errorText: 'Gateway timeout',
      modelName: 'gpt-5.1',
    });
    await db.update(schema.routeChannels).set({
      cooldownUntil: null,
      lastFailAt: null,
      failCount: 0,
    }).where(eq(schema.routeChannels.id, channelA.id)).run();
    invalidateTokenRouterCache();

    const preview = await router.previewSelectedChannel('gpt-5.1');
    const decision = await router.explainSelection('gpt-5.1');

    expect(preview?.channel.id).toBe(channelB.id);
    expect(decision.summary.join(' ')).toContain('稳定优先');
    expect(decision.selectedChannelId).toBe(channelB.id);
  });

  it('stable_first rotates across sites that remain inside the stable pool', async () => {
    config.routingWeights = {
      baseWeightFactor: 1,
      valueScoreFactor: 0,
      costWeight: 0,
      balanceWeight: 0,
      usageWeight: 0,
    };

    const route = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-5.4',
      routingStrategy: 'stable_first',
      enabled: true,
    }).returning().get();

    const siteA = await createSite('stable-pool-a');
    const accountA = await createAccount(siteA.id, 'stable-pool-user-a');
    const tokenA = await createToken(accountA.id, 'stable-pool-token-a');
    const channelA = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: accountA.id,
      tokenId: tokenA.id,
      priority: 0,
      weight: 10,
      enabled: true,
    }).returning().get();

    const siteB = await createSite('stable-pool-b');
    const accountB = await createAccount(siteB.id, 'stable-pool-user-b');
    const tokenB = await createToken(accountB.id, 'stable-pool-token-b');
    const channelB = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: accountB.id,
      tokenId: tokenB.id,
      priority: 0,
      weight: 9,
      enabled: true,
    }).returning().get();

    const router = new TokenRouter();
    const first = await router.selectChannel('gpt-5.4');
    const second = await router.selectChannel('gpt-5.4');
    const third = await router.selectChannel('gpt-5.4');
    const decision = await router.explainSelection('gpt-5.4');

    expect(first?.channel.id).toBe(channelA.id);
    expect(second?.channel.id).toBe(channelB.id);
    expect(third?.channel.id).toBe(channelA.id);
    expect(decision.summary.join(' ')).toContain('主池站点 2');
  });

  it('stable_first rotates across healthy sites in configured priority order instead of stopping at the first layer', async () => {
    config.routingWeights = {
      baseWeightFactor: 1,
      valueScoreFactor: 0,
      costWeight: 0,
      balanceWeight: 0,
      usageWeight: 0,
    };

    const route = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-4.1',
      routingStrategy: 'stable_first',
      enabled: true,
    }).returning().get();

    const siteA = await createSite('ordered-stable-a');
    const accountA = await createAccount(siteA.id, 'ordered-stable-user-a');
    const tokenA = await createToken(accountA.id, 'ordered-stable-token-a');
    const channelA = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: accountA.id,
      tokenId: tokenA.id,
      priority: 0,
      weight: 10,
      enabled: true,
    }).returning().get();

    const siteB = await createSite('ordered-stable-b');
    const accountB = await createAccount(siteB.id, 'ordered-stable-user-b');
    const tokenB = await createToken(accountB.id, 'ordered-stable-token-b');
    const channelB = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: accountB.id,
      tokenId: tokenB.id,
      priority: 4,
      weight: 10,
      enabled: true,
    }).returning().get();

    const siteC = await createSite('ordered-stable-c');
    const accountC = await createAccount(siteC.id, 'ordered-stable-user-c');
    const tokenC = await createToken(accountC.id, 'ordered-stable-token-c');
    const channelC = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: accountC.id,
      tokenId: tokenC.id,
      priority: 8,
      weight: 10,
      enabled: true,
    }).returning().get();

    const router = new TokenRouter();
    const first = await router.selectChannel('gpt-4.1');
    const second = await router.selectChannel('gpt-4.1');
    const third = await router.selectChannel('gpt-4.1');
    const fourth = await router.selectChannel('gpt-4.1');
    const decision = await router.explainSelection('gpt-4.1');

    expect(first?.channel.id).toBe(channelA.id);
    expect(second?.channel.id).toBe(channelB.id);
    expect(third?.channel.id).toBe(channelC.id);
    expect(fourth?.channel.id).toBe(channelA.id);
    expect(decision.summary.join(' ')).toContain('按配置顺序轮询站点');
  });

  it('stable_first gives observation-pool sites occasional real traffic without background probing', async () => {
    config.routingWeights = {
      baseWeightFactor: 1,
      valueScoreFactor: 0,
      costWeight: 0,
      balanceWeight: 0,
      usageWeight: 0,
    };

    const route = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-5.4-probe-free',
      routingStrategy: 'stable_first',
      enabled: true,
    }).returning().get();

    const sitePrimary = await createSite('observation-primary');
    const accountPrimary = await createAccount(sitePrimary.id, 'observation-user-primary');
    const tokenPrimary = await createToken(accountPrimary.id, 'observation-token-primary');
    const primaryChannel = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: accountPrimary.id,
      tokenId: tokenPrimary.id,
      priority: 0,
      weight: 10,
      enabled: true,
      successCount: 48,
      failCount: 0,
      totalLatencyMs: 48 * 320,
    }).returning().get();

    const siteObservation = await createSite('observation-candidate');
    const accountObservation = await createAccount(siteObservation.id, 'observation-user-candidate');
    const tokenObservation = await createToken(accountObservation.id, 'observation-token-candidate');
    const observationChannel = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: accountObservation.id,
      tokenId: tokenObservation.id,
      priority: 1,
      weight: 10,
      enabled: true,
    }).returning().get();

    const router = new TokenRouter();
    const selectedChannelIds: number[] = [];
    for (let index = 0; index < 23; index += 1) {
      const selected = await router.selectChannel('gpt-5.4-probe-free');
      selectedChannelIds.push(selected?.channel.id ?? 0);
    }
    let decision = await router.explainSelection('gpt-5.4-probe-free');
    let observationCandidate = decision.candidates.find((candidate) => candidate.channelId === observationChannel.id);
    let primaryCandidate = decision.candidates.find((candidate) => candidate.channelId === primaryChannel.id);

    expect(observationCandidate?.probability).toBe(100);
    expect(primaryCandidate?.probability).toBe(0);
    expect(decision.summary.join(' ')).toContain('本次命中观察池灰度流量');

    const observationSelected = await router.selectChannel('gpt-5.4-probe-free');
    selectedChannelIds.push(observationSelected?.channel.id ?? 0);

    decision = await router.explainSelection('gpt-5.4-probe-free');
    observationCandidate = decision.candidates.find((candidate) => candidate.channelId === observationChannel.id);
    primaryCandidate = decision.candidates.find((candidate) => candidate.channelId === primaryChannel.id);

    expect(selectedChannelIds.filter((channelId) => channelId === observationChannel.id)).toHaveLength(1);
    expect(selectedChannelIds.filter((channelId) => channelId === primaryChannel.id).length).toBeGreaterThan(20);
    expect(decision.summary.join(' ')).toContain('观察池站点 1');
    expect(decision.summary.join(' ')).toContain('还需 23 次主池请求');
    expect(observationCandidate?.reason || '').toContain('观察池');
    expect(observationCandidate?.probability).toBe(0);
    expect(primaryCandidate?.reason || '').toContain('主池');
    expect((primaryCandidate?.probability || 0)).toBeGreaterThan(0);
  });

  it('caps the stable_first rotation cache size', () => {
    invalidateTokenRouterCache();

    for (let index = 0; index < 1200; index += 1) {
      tokenRouterTestUtils.rememberStableFirstSiteSelectionForKey(`route:${index}`, (index % 7) + 1);
    }

    expect(tokenRouterTestUtils.getStableFirstRotationCacheSize()).toBeLessThanOrEqual(1024);
  });

  it('penalizes saturated session-scoped channels using runtime load snapshots', async () => {
    config.routingWeights = {
      baseWeightFactor: 1,
      valueScoreFactor: 0,
      costWeight: 0,
      balanceWeight: 0,
      usageWeight: 0,
    };
    config.proxySessionChannelConcurrencyLimit = 1;
    config.proxySessionChannelQueueWaitMs = 5_000;

    const route = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-5.2',
      routingStrategy: 'stable_first',
      enabled: true,
    }).returning().get();
    const sessionExtraConfig = JSON.stringify({ credentialMode: 'session' });

    const siteBusy = await createSite('runtime-load-busy');
    const accountBusy = await createAccount(siteBusy.id, 'runtime-load-user-busy', {
      extraConfig: sessionExtraConfig,
    });
    const tokenBusy = await createToken(accountBusy.id, 'runtime-load-token-busy');
    const channelBusy = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: accountBusy.id,
      tokenId: tokenBusy.id,
      priority: 0,
      weight: 10,
      enabled: true,
    }).returning().get();

    const siteFree = await createSite('runtime-load-free');
    const accountFree = await createAccount(siteFree.id, 'runtime-load-user-free', {
      extraConfig: sessionExtraConfig,
    });
    const tokenFree = await createToken(accountFree.id, 'runtime-load-token-free');
    const channelFree = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: accountFree.id,
      tokenId: tokenFree.id,
      priority: 0,
      weight: 10,
      enabled: true,
    }).returning().get();

    const activeLease = await proxyChannelCoordinator.acquireChannelLease({
      channelId: channelBusy.id,
      accountExtraConfig: accountBusy.extraConfig,
    });
    expect(activeLease.status).toBe('acquired');
    if (activeLease.status !== 'acquired') return;

    const queuedLeasePromise = proxyChannelCoordinator.acquireChannelLease({
      channelId: channelBusy.id,
      accountExtraConfig: accountBusy.extraConfig,
    });
    await Promise.resolve();

    const router = new TokenRouter();
    const preview = await router.previewSelectedChannel('gpt-5.2');
    const decision = await router.explainSelection('gpt-5.2');
    const busyCandidate = decision.candidates.find((candidate) => candidate.channelId === channelBusy.id);
    const freeCandidate = decision.candidates.find((candidate) => candidate.channelId === channelFree.id);

    expect(preview?.channel.id).toBe(channelFree.id);
    expect(busyCandidate?.reason || '').toContain('会话负载=');
    expect(busyCandidate?.reason || '').toContain('活跃=1/1');
    expect(busyCandidate?.reason || '').toContain('等待=1');
    expect((busyCandidate?.probability || 0)).toBeLessThan((freeCandidate?.probability || 0));

    activeLease.lease.release();
    const queuedLease = await queuedLeasePromise;
    expect(queuedLease.status).toBe('acquired');
    if (queuedLease.status === 'acquired') {
      queuedLease.lease.release();
    }
  });
});
