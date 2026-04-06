import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

type DbModule = typeof import('../db/index.js');
type TokenRouterModule = typeof import('./tokenRouter.js');

describe('TokenRouter oauth route units', () => {
  let db: DbModule['db'];
  let schema: DbModule['schema'];
  let TokenRouter: TokenRouterModule['TokenRouter'];
  let invalidateTokenRouterCache: TokenRouterModule['invalidateTokenRouterCache'];
  let tokenRouterTestUtils: TokenRouterModule['__tokenRouterTestUtils'];
  let dataDir = '';

  beforeAll(async () => {
    dataDir = mkdtempSync(join(tmpdir(), 'metapi-token-router-oauth-route-units-'));
    process.env.DATA_DIR = dataDir;

    await import('../db/migrate.js');
    const dbModule = await import('../db/index.js');
    const tokenRouterModule = await import('./tokenRouter.js');
    db = dbModule.db;
    schema = dbModule.schema;
    TokenRouter = tokenRouterModule.TokenRouter;
    invalidateTokenRouterCache = tokenRouterModule.invalidateTokenRouterCache;
    tokenRouterTestUtils = tokenRouterModule.__tokenRouterTestUtils;
  });

  beforeEach(async () => {
    await db.delete(schema.routeChannels).run();
    await db.delete(schema.tokenRoutes).run();
    await db.delete(schema.modelAvailability).run();
    await db.delete(schema.accountTokens).run();
    await db.delete(schema.oauthRouteUnitMembers).run();
    await db.delete(schema.oauthRouteUnits).run();
    await db.delete(schema.accounts).run();
    await db.delete(schema.sites).run();
    invalidateTokenRouterCache();
  });

  afterAll(() => {
    invalidateTokenRouterCache();
    delete process.env.DATA_DIR;
  });

  it('round robins across healthy oauth route unit members while keeping a single outer channel', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'ChatGPT Codex OAuth',
      url: 'https://chatgpt.com/backend-api/codex',
      platform: 'codex',
      status: 'active',
    }).returning().get();

    const accountA = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'rr-a@example.com',
      accessToken: 'oauth-access-token-a',
      apiToken: null,
      status: 'active',
      oauthProvider: 'codex',
      oauthAccountKey: 'chatgpt-rr-a',
      extraConfig: JSON.stringify({
        credentialMode: 'session',
        oauth: { provider: 'codex', accountId: 'chatgpt-rr-a', email: 'rr-a@example.com' },
      }),
    }).returning().get();
    const accountB = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'rr-b@example.com',
      accessToken: 'oauth-access-token-b',
      apiToken: null,
      status: 'active',
      oauthProvider: 'codex',
      oauthAccountKey: 'chatgpt-rr-b',
      extraConfig: JSON.stringify({
        credentialMode: 'session',
        oauth: { provider: 'codex', accountId: 'chatgpt-rr-b', email: 'rr-b@example.com' },
      }),
    }).returning().get();

    const route = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-5.4',
      enabled: true,
    }).returning().get();
    const routeUnit = await db.insert(schema.oauthRouteUnits).values({
      siteId: site.id,
      provider: 'codex',
      name: 'Codex RR Pool',
      strategy: 'round_robin',
      enabled: true,
    }).returning().get();
    await db.insert(schema.oauthRouteUnitMembers).values([
      { unitId: routeUnit.id, accountId: accountA.id, sortOrder: 0 },
      { unitId: routeUnit.id, accountId: accountB.id, sortOrder: 1 },
    ]).run();
    await db.insert(schema.modelAvailability).values([
      { accountId: accountA.id, modelName: 'gpt-5.4', available: true },
      { accountId: accountB.id, modelName: 'gpt-5.4', available: true },
    ]).run();
    const channel = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: accountA.id,
      tokenId: null,
      oauthRouteUnitId: routeUnit.id,
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

  it('sticks to the same oauth route unit member until it becomes unavailable', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'ChatGPT Codex OAuth',
      url: 'https://chatgpt.com/backend-api/codex',
      platform: 'codex',
      status: 'active',
    }).returning().get();

    const accountA = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'sticky-a@example.com',
      accessToken: 'oauth-access-token-a',
      apiToken: null,
      status: 'active',
      oauthProvider: 'codex',
      oauthAccountKey: 'chatgpt-sticky-a',
      extraConfig: JSON.stringify({
        credentialMode: 'session',
        oauth: { provider: 'codex', accountId: 'chatgpt-sticky-a', email: 'sticky-a@example.com' },
      }),
    }).returning().get();
    const accountB = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'sticky-b@example.com',
      accessToken: 'oauth-access-token-b',
      apiToken: null,
      status: 'active',
      oauthProvider: 'codex',
      oauthAccountKey: 'chatgpt-sticky-b',
      extraConfig: JSON.stringify({
        credentialMode: 'session',
        oauth: { provider: 'codex', accountId: 'chatgpt-sticky-b', email: 'sticky-b@example.com' },
      }),
    }).returning().get();

    const route = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-5.4',
      routingStrategy: 'stable_first',
      enabled: true,
    }).returning().get();
    const routeUnit = await db.insert(schema.oauthRouteUnits).values({
      siteId: site.id,
      provider: 'codex',
      name: 'Codex Sticky Pool',
      strategy: 'stick_until_unavailable',
      enabled: true,
    }).returning().get();
    await db.insert(schema.oauthRouteUnitMembers).values([
      { unitId: routeUnit.id, accountId: accountA.id, sortOrder: 0 },
      { unitId: routeUnit.id, accountId: accountB.id, sortOrder: 1 },
    ]).run();
    await db.insert(schema.modelAvailability).values([
      { accountId: accountA.id, modelName: 'gpt-5.4', available: true },
      { accountId: accountB.id, modelName: 'gpt-5.4', available: true },
    ]).run();
    const channel = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: accountA.id,
      tokenId: null,
      oauthRouteUnitId: routeUnit.id,
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

    await router.recordFailure(channel.id, { status: 503, errorText: 'unavailable' }, accountA.id);
    const third = await router.selectChannel('gpt-5.4');
    expect(third?.channel.id).toBe(channel.id);
    expect(third?.account.id).toBe(accountB.id);
  });

  it('keeps unrelated stable-first cache entries when pooled member state updates', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'ChatGPT Codex OAuth',
      url: 'https://chatgpt.com/backend-api/codex',
      platform: 'codex',
      status: 'active',
    }).returning().get();

    const accountA = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'cache-a@example.com',
      accessToken: 'oauth-cache-access-a',
      apiToken: null,
      status: 'active',
      oauthProvider: 'codex',
      oauthAccountKey: 'chatgpt-cache-a',
      extraConfig: JSON.stringify({
        credentialMode: 'session',
        oauth: { provider: 'codex', accountId: 'chatgpt-cache-a', email: 'cache-a@example.com' },
      }),
    }).returning().get();
    const accountB = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'cache-b@example.com',
      accessToken: 'oauth-cache-access-b',
      apiToken: null,
      status: 'active',
      oauthProvider: 'codex',
      oauthAccountKey: 'chatgpt-cache-b',
      extraConfig: JSON.stringify({
        credentialMode: 'session',
        oauth: { provider: 'codex', accountId: 'chatgpt-cache-b', email: 'cache-b@example.com' },
      }),
    }).returning().get();

    const route = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-5.4',
      routingStrategy: 'weighted',
      enabled: true,
    }).returning().get();
    const routeUnit = await db.insert(schema.oauthRouteUnits).values({
      siteId: site.id,
      provider: 'codex',
      name: 'Cache Pool',
      strategy: 'round_robin',
      enabled: true,
    }).returning().get();
    await db.insert(schema.oauthRouteUnitMembers).values([
      { unitId: routeUnit.id, accountId: accountA.id, sortOrder: 0 },
      { unitId: routeUnit.id, accountId: accountB.id, sortOrder: 1 },
    ]).run();
    await db.insert(schema.modelAvailability).values([
      { accountId: accountA.id, modelName: 'gpt-5.4', available: true },
      { accountId: accountB.id, modelName: 'gpt-5.4', available: true },
    ]).run();
    const channel = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: accountA.id,
      tokenId: null,
      oauthRouteUnitId: routeUnit.id,
      priority: 0,
      weight: 10,
      enabled: true,
      manualOverride: false,
    }).returning().get();

    tokenRouterTestUtils.rememberStableFirstSiteSelectionForKey('999:other-model', 77);
    expect(tokenRouterTestUtils.getStableFirstRotationCacheSize()).toBe(1);

    const router = new TokenRouter();
    const selected = await router.selectChannel('gpt-5.4');
    expect(selected?.channel.id).toBe(channel.id);
    expect(tokenRouterTestUtils.getStableFirstRotationCacheSize()).toBe(1);

    await router.recordFailure(channel.id, { status: 503, errorText: 'pooled unavailable' }, accountA.id);
    expect(tokenRouterTestUtils.getStableFirstRotationCacheSize()).toBe(1);
  });

  it('fails closed when a pooled channel has no loaded members', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'ChatGPT Codex OAuth',
      url: 'https://chatgpt.com/backend-api/codex',
      platform: 'codex',
      status: 'active',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'missing-members@example.com',
      accessToken: 'oauth-access-token-missing-members',
      apiToken: null,
      status: 'active',
      oauthProvider: 'codex',
      oauthAccountKey: 'chatgpt-missing-members',
      extraConfig: JSON.stringify({
        credentialMode: 'session',
        oauth: { provider: 'codex', accountId: 'chatgpt-missing-members', email: 'missing-members@example.com' },
      }),
    }).returning().get();

    const route = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-5.4',
      enabled: true,
    }).returning().get();
    const routeUnit = await db.insert(schema.oauthRouteUnits).values({
      siteId: site.id,
      provider: 'codex',
      name: 'Broken Pool',
      strategy: 'round_robin',
      enabled: true,
    }).returning().get();
    await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: account.id,
      tokenId: null,
      oauthRouteUnitId: routeUnit.id,
      priority: 0,
      weight: 10,
      enabled: true,
      manualOverride: false,
    }).run();

    const router = new TokenRouter();
    const selected = await router.selectChannel('gpt-5.4');

    expect(selected).toBeNull();
  });

  it('uses the api token fallback for pooled oauth members when the access token is blank', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'ChatGPT Codex OAuth',
      url: 'https://chatgpt.com/backend-api/codex',
      platform: 'codex',
      status: 'active',
    }).returning().get();

    const accountA = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'fallback-a@example.com',
      accessToken: '   ',
      apiToken: 'oauth-api-token-a',
      status: 'active',
      oauthProvider: 'codex',
      oauthAccountKey: 'chatgpt-fallback-a',
      extraConfig: JSON.stringify({
        credentialMode: 'session',
        oauth: { provider: 'codex', accountId: 'chatgpt-fallback-a', email: 'fallback-a@example.com' },
      }),
    }).returning().get();
    const accountB = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'fallback-b@example.com',
      accessToken: 'oauth-access-token-b',
      apiToken: null,
      status: 'active',
      oauthProvider: 'codex',
      oauthAccountKey: 'chatgpt-fallback-b',
      extraConfig: JSON.stringify({
        credentialMode: 'session',
        oauth: { provider: 'codex', accountId: 'chatgpt-fallback-b', email: 'fallback-b@example.com' },
      }),
    }).returning().get();

    const route = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-5.4',
      enabled: true,
    }).returning().get();
    const routeUnit = await db.insert(schema.oauthRouteUnits).values({
      siteId: site.id,
      provider: 'codex',
      name: 'Fallback Pool',
      strategy: 'round_robin',
      enabled: true,
    }).returning().get();
    await db.insert(schema.oauthRouteUnitMembers).values([
      { unitId: routeUnit.id, accountId: accountA.id, sortOrder: 0 },
      { unitId: routeUnit.id, accountId: accountB.id, sortOrder: 1 },
    ]).run();
    await db.insert(schema.modelAvailability).values([
      { accountId: accountA.id, modelName: 'gpt-5.4', available: true },
      { accountId: accountB.id, modelName: 'gpt-5.4', available: true },
    ]).run();
    const channel = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: accountA.id,
      tokenId: null,
      oauthRouteUnitId: routeUnit.id,
      priority: 0,
      weight: 10,
      enabled: true,
      manualOverride: false,
    }).returning().get();

    const router = new TokenRouter();
    const selected = await router.selectChannel('gpt-5.4');

    expect(selected?.channel.id).toBe(channel.id);
    expect(selected?.account.id).toBe(accountA.id);
    expect(selected?.tokenValue).toBe('oauth-api-token-a');
  });

  it('does not immediately retry the same pooled member during failover when it just failed', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'ChatGPT Codex OAuth',
      url: 'https://chatgpt.com/backend-api/codex',
      platform: 'codex',
      status: 'active',
    }).returning().get();

    const accountA = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'failover-a@example.com',
      accessToken: 'oauth-access-token-a',
      apiToken: null,
      status: 'active',
      oauthProvider: 'codex',
      oauthAccountKey: 'chatgpt-failover-a',
      extraConfig: JSON.stringify({
        credentialMode: 'session',
        oauth: { provider: 'codex', accountId: 'chatgpt-failover-a', email: 'failover-a@example.com' },
      }),
    }).returning().get();
    const accountB = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'failover-b@example.com',
      accessToken: 'oauth-access-token-b',
      apiToken: null,
      status: 'disabled',
      oauthProvider: 'codex',
      oauthAccountKey: 'chatgpt-failover-b',
      extraConfig: JSON.stringify({
        credentialMode: 'session',
        oauth: { provider: 'codex', accountId: 'chatgpt-failover-b', email: 'failover-b@example.com' },
      }),
    }).returning().get();

    const route = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-5.4',
      enabled: true,
    }).returning().get();
    const routeUnit = await db.insert(schema.oauthRouteUnits).values({
      siteId: site.id,
      provider: 'codex',
      name: 'Failover Pool',
      strategy: 'round_robin',
      enabled: true,
    }).returning().get();
    await db.insert(schema.oauthRouteUnitMembers).values([
      { unitId: routeUnit.id, accountId: accountA.id, sortOrder: 0 },
      { unitId: routeUnit.id, accountId: accountB.id, sortOrder: 1 },
    ]).run();
    await db.insert(schema.modelAvailability).values([
      { accountId: accountA.id, modelName: 'gpt-5.4', available: true },
      { accountId: accountB.id, modelName: 'gpt-5.4', available: true },
    ]).run();
    const channel = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: accountA.id,
      tokenId: null,
      oauthRouteUnitId: routeUnit.id,
      priority: 0,
      weight: 10,
      enabled: true,
      manualOverride: false,
    }).returning().get();

    const router = new TokenRouter();
    const first = await router.selectChannel('gpt-5.4');
    expect(first?.account.id).toBe(accountA.id);

    await router.recordFailure(channel.id, { status: 503, errorText: 'upstream unavailable' }, accountA.id);
    const failover = await router.selectNextChannel('gpt-5.4', [channel.id]);

    expect(failover).toBeNull();
  });
});
