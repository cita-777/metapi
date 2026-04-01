import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { eq } from 'drizzle-orm';

type DbModule = typeof import('../db/index.js');
type TokenRouterModule = typeof import('./tokenRouter.js');
type ConfigModule = typeof import('../config.js');

describe('TokenRouter runtime cache', () => {
  let db: DbModule['db'];
  let schema: DbModule['schema'];
  let TokenRouter: TokenRouterModule['TokenRouter'];
  let invalidateTokenRouterCache: TokenRouterModule['invalidateTokenRouterCache'];
  let isChannelRecentlyFailed: TokenRouterModule['isChannelRecentlyFailed'];
  let resetSiteRuntimeHealthState: TokenRouterModule['resetSiteRuntimeHealthState'];
  let config: ConfigModule['config'];
  let dataDir = '';
  let originalCacheTtlMs = 0;
  let originalFailureCooldownMaxSec = 0;

  beforeAll(async () => {
    dataDir = mkdtempSync(join(tmpdir(), 'metapi-token-router-cache-'));
    process.env.DATA_DIR = dataDir;

    await import('../db/migrate.js');
    const dbModule = await import('../db/index.js');
    const tokenRouterModule = await import('./tokenRouter.js');
    const configModule = await import('../config.js');
    db = dbModule.db;
    schema = dbModule.schema;
    TokenRouter = tokenRouterModule.TokenRouter;
    invalidateTokenRouterCache = tokenRouterModule.invalidateTokenRouterCache;
    isChannelRecentlyFailed = tokenRouterModule.isChannelRecentlyFailed;
    resetSiteRuntimeHealthState = tokenRouterModule.resetSiteRuntimeHealthState;
    config = configModule.config;
    originalCacheTtlMs = config.tokenRouterCacheTtlMs;
    originalFailureCooldownMaxSec = config.tokenRouterFailureCooldownMaxSec;
  });

  beforeEach(async () => {
    await db.delete(schema.routeChannels).run();
    await db.delete(schema.tokenRoutes).run();
    await db.delete(schema.settings).run();
    await db.delete(schema.accountTokens).run();
    await db.delete(schema.accounts).run();
    await db.delete(schema.sites).run();
    config.tokenRouterCacheTtlMs = 60_000;
    config.tokenRouterFailureCooldownMaxSec = originalFailureCooldownMaxSec;
    invalidateTokenRouterCache();
    resetSiteRuntimeHealthState();
  });

  afterAll(() => {
    config.tokenRouterCacheTtlMs = originalCacheTtlMs;
    config.tokenRouterFailureCooldownMaxSec = originalFailureCooldownMaxSec;
    invalidateTokenRouterCache();
    resetSiteRuntimeHealthState();
    delete process.env.DATA_DIR;
  });

  it('keeps route snapshot inside TTL until explicit invalidation', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'cache-site',
      url: 'https://cache-site.example.com',
      platform: 'new-api',
      status: 'active',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'cache-user',
      accessToken: 'cache-access-token',
      apiToken: 'cache-api-token',
      status: 'active',
    }).returning().get();

    const token = await db.insert(schema.accountTokens).values({
      accountId: account.id,
      name: 'cache-token',
      token: 'sk-cache-token',
      enabled: true,
      isDefault: true,
    }).returning().get();

    const route = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-4o-mini',
      enabled: true,
    }).returning().get();

    await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: account.id,
      tokenId: token.id,
      priority: 0,
      weight: 10,
      enabled: true,
    }).run();

    const router = new TokenRouter();
    expect(await router.selectChannel('gpt-4o-mini')).toBeTruthy();

    await db.delete(schema.routeChannels).where(eq(schema.routeChannels.routeId, route.id)).run();
    await db.delete(schema.tokenRoutes).where(eq(schema.tokenRoutes.id, route.id)).run();

    const cachedSelection = await router.selectChannel('gpt-4o-mini');
    expect(cachedSelection).toBeTruthy();

    invalidateTokenRouterCache();
    const refreshedSelection = await router.selectChannel('gpt-4o-mini');
    expect(refreshedSelection).toBeNull();
  });

  it('uses fibonacci-style cooldown across repeated failures', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'cooldown-site',
      url: 'https://cooldown-site.example.com',
      platform: 'new-api',
      status: 'active',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'cooldown-user',
      accessToken: 'cooldown-access-token',
      apiToken: 'cooldown-api-token',
      status: 'active',
    }).returning().get();

    const token = await db.insert(schema.accountTokens).values({
      accountId: account.id,
      name: 'cooldown-token',
      token: 'sk-cooldown-token',
      enabled: true,
      isDefault: true,
    }).returning().get();

    const route = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-4o-mini',
      routingStrategy: 'weighted',
      enabled: true,
    }).returning().get();

    const channel = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: account.id,
      tokenId: token.id,
      priority: 0,
      weight: 10,
      enabled: true,
    }).returning().get();

    const router = new TokenRouter();

    const firstStartedAt = Date.now();
    await router.recordFailure(channel.id);
    const firstRecord = await db.select().from(schema.routeChannels)
      .where(eq(schema.routeChannels.id, channel.id))
      .get();
    const firstCooldownMs = Date.parse(String(firstRecord?.cooldownUntil || '')) - firstStartedAt;
    expect(firstCooldownMs).toBeGreaterThanOrEqual(10_000);
    expect(firstCooldownMs).toBeLessThanOrEqual(20_000);

    const secondStartedAt = Date.now();
    await router.recordFailure(channel.id);
    const secondRecord = await db.select().from(schema.routeChannels)
      .where(eq(schema.routeChannels.id, channel.id))
      .get();
    const secondCooldownMs = Date.parse(String(secondRecord?.cooldownUntil || '')) - secondStartedAt;
    expect(secondCooldownMs).toBeGreaterThanOrEqual(10_000);
    expect(secondCooldownMs).toBeLessThanOrEqual(20_000);

    const thirdStartedAt = Date.now();
    await router.recordFailure(channel.id);
    const thirdRecord = await db.select().from(schema.routeChannels)
      .where(eq(schema.routeChannels.id, channel.id))
      .get();
    const thirdCooldownMs = Date.parse(String(thirdRecord?.cooldownUntil || '')) - thirdStartedAt;
    expect(thirdCooldownMs).toBeGreaterThanOrEqual(25_000);
    expect(thirdCooldownMs).toBeLessThanOrEqual(35_000);
  });

  it('caps generic failure cooldowns at the configured maximum', async () => {
    config.tokenRouterFailureCooldownMaxSec = 20;

    const site = await db.insert(schema.sites).values({
      name: 'capped-cooldown-site',
      url: 'https://capped-cooldown.example.com',
      platform: 'new-api',
      status: 'active',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'capped-cooldown-user',
      accessToken: 'capped-cooldown-access-token',
      apiToken: 'capped-cooldown-api-token',
      status: 'active',
    }).returning().get();

    const token = await db.insert(schema.accountTokens).values({
      accountId: account.id,
      name: 'capped-cooldown-token',
      token: 'sk-capped-cooldown-token',
      enabled: true,
      isDefault: true,
    }).returning().get();

    const route = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-4o-mini',
      routingStrategy: 'weighted',
      enabled: true,
    }).returning().get();

    const channel = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: account.id,
      tokenId: token.id,
      priority: 0,
      weight: 10,
      enabled: true,
    }).returning().get();

    const router = new TokenRouter();

    await router.recordFailure(channel.id);
    await router.recordFailure(channel.id);

    const startedAt = Date.now();
    await router.recordFailure(channel.id);

    const record = await db.select().from(schema.routeChannels)
      .where(eq(schema.routeChannels.id, channel.id))
      .get();
    const cooldownMs = Date.parse(String(record?.cooldownUntil || '')) - startedAt;

    expect(cooldownMs).toBeGreaterThanOrEqual(17_000);
    expect(cooldownMs).toBeLessThanOrEqual(23_000);
    const recentFailureCheckAt = Date.now();
    expect(isChannelRecentlyFailed({
      failCount: 3,
      lastFailAt: new Date(recentFailureCheckAt - 19_000).toISOString(),
    }, recentFailureCheckAt)).toBe(true);
    expect(isChannelRecentlyFailed({
      failCount: 3,
      lastFailAt: new Date(recentFailureCheckAt - 21_000).toISOString(),
    }, recentFailureCheckAt)).toBe(false);
  });

  it('uses codex oauth reset hints for usage-limit cooldowns', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'codex-oauth-site',
      url: 'https://codex-oauth.example.com',
      platform: 'codex',
      status: 'active',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'codex-oauth-user',
      accessToken: 'codex-access-token',
      status: 'active',
      oauthProvider: 'codex',
      extraConfig: JSON.stringify({
        credentialMode: 'session',
        oauth: {
          provider: 'codex',
        },
      }),
    }).returning().get();

    const route = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-5.4',
      routingStrategy: 'weighted',
      enabled: true,
    }).returning().get();

    const channel = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: account.id,
      priority: 0,
      weight: 10,
      enabled: true,
    }).returning().get();

    const router = new TokenRouter();
    const startedAt = Date.now();
    await router.recordFailure(channel.id, {
      status: 429,
      errorText: JSON.stringify({
        error: {
          type: 'usage_limit_reached',
          resets_in_seconds: 600,
          message: 'quota exceeded',
        },
      }),
      modelName: 'gpt-5.4',
    });

    const record = await db.select().from(schema.routeChannels)
      .where(eq(schema.routeChannels.id, channel.id))
      .get();
    const cooldownMs = Date.parse(String(record?.cooldownUntil || '')) - startedAt;

    expect(cooldownMs).toBeGreaterThanOrEqual(9 * 60 * 1000);
    expect(cooldownMs).toBeLessThanOrEqual(11 * 60 * 1000);
  });

  it('falls back to a short cooldown for codex oauth usage-limit failures without reset hints', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'codex-oauth-fallback-site',
      url: 'https://codex-oauth-fallback.example.com',
      platform: 'codex',
      status: 'active',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'codex-oauth-fallback-user',
      accessToken: 'codex-fallback-access-token',
      status: 'active',
      oauthProvider: 'codex',
      extraConfig: JSON.stringify({
        credentialMode: 'session',
        oauth: {
          provider: 'codex',
        },
      }),
    }).returning().get();

    const route = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-5.4',
      routingStrategy: 'weighted',
      enabled: true,
    }).returning().get();

    const channel = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: account.id,
      priority: 0,
      weight: 10,
      enabled: true,
    }).returning().get();

    const router = new TokenRouter();
    const startedAt = Date.now();
    await router.recordFailure(channel.id, {
      status: 429,
      errorText: JSON.stringify({
        error: {
          type: 'usage_limit_reached',
          message: 'The usage limit has been reached',
        },
      }),
      modelName: 'gpt-5.4',
    });

    const record = await db.select().from(schema.routeChannels)
      .where(eq(schema.routeChannels.id, channel.id))
      .get();
    const cooldownMs = Date.parse(String(record?.cooldownUntil || '')) - startedAt;

    expect(cooldownMs).toBeGreaterThanOrEqual(4 * 60 * 1000);
    expect(cooldownMs).toBeLessThanOrEqual(6 * 60 * 1000);
  });

  it('reuses stored codex oauth reset hints when the latest 429 omits reset timing', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'codex-oauth-stored-reset-site',
      url: 'https://codex-oauth-stored-reset.example.com',
      platform: 'codex',
      status: 'active',
    }).returning().get();

    const resetAt = new Date(Date.now() + 8 * 60 * 1000).toISOString();
    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'codex-oauth-stored-reset-user',
      accessToken: 'codex-stored-reset-access-token',
      status: 'active',
      oauthProvider: 'codex',
      extraConfig: JSON.stringify({
        credentialMode: 'session',
        oauth: {
          provider: 'codex',
          quota: {
            status: 'supported',
            source: 'reverse_engineered',
            lastLimitResetAt: resetAt,
            providerMessage: 'current codex oauth signals do not expose stable 5h/7d remaining values',
            windows: {
              fiveHour: {
                supported: false,
                message: 'official 5h quota window is not exposed by current codex oauth artifacts',
              },
              sevenDay: {
                supported: false,
                message: 'official 7d quota window is not exposed by current codex oauth artifacts',
              },
            },
          },
        },
      }),
    }).returning().get();

    const route = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-5.4',
      routingStrategy: 'weighted',
      enabled: true,
    }).returning().get();

    const channel = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: account.id,
      priority: 0,
      weight: 10,
      enabled: true,
    }).returning().get();

    const router = new TokenRouter();
    await router.recordFailure(channel.id, {
      status: 429,
      errorText: JSON.stringify({
        error: {
          type: 'usage_limit_reached',
          message: 'The usage limit has been reached',
        },
      }),
      modelName: 'gpt-5.4',
    });

    const record = await db.select().from(schema.routeChannels)
      .where(eq(schema.routeChannels.id, channel.id))
      .get();

    expect(record?.cooldownUntil).toBe(resetAt);
  });

  it('treats non-oauth 429 limit failures as short-window cooldowns', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'limit-site',
      url: 'https://limit-site.example.com',
      platform: 'new-api',
      status: 'active',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'limit-user',
      accessToken: 'limit-access-token',
      apiToken: 'limit-api-token',
      status: 'active',
    }).returning().get();

    const route = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-4o-mini',
      routingStrategy: 'weighted',
      enabled: true,
    }).returning().get();

    const channel = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: account.id,
      priority: 0,
      weight: 10,
      enabled: true,
    }).returning().get();

    const router = new TokenRouter();
    const startedAt = Date.now();
    await router.recordFailure(channel.id, {
      status: 429,
      errorText: JSON.stringify({
        error: {
          message: 'rate limit exceeded',
        },
      }),
      modelName: 'gpt-4o-mini',
    });

    const record = await db.select().from(schema.routeChannels)
      .where(eq(schema.routeChannels.id, channel.id))
      .get();
    const cooldownMs = Date.parse(String(record?.cooldownUntil || '')) - startedAt;

    expect(cooldownMs).toBeGreaterThanOrEqual(4 * 60 * 1000);
    expect(cooldownMs).toBeLessThanOrEqual(6 * 60 * 1000);
    expect(record?.failCount).toBe(0);
  });

  it('keeps generic 429 backoff when the error is not limit-related', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'generic-429-site',
      url: 'https://generic-429.example.com',
      platform: 'new-api',
      status: 'active',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'generic-429-user',
      accessToken: 'generic-429-access-token',
      apiToken: 'generic-429-api-token',
      status: 'active',
    }).returning().get();

    const route = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-4o-mini',
      routingStrategy: 'weighted',
      enabled: true,
    }).returning().get();

    const channel = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: account.id,
      priority: 0,
      weight: 10,
      enabled: true,
    }).returning().get();

    const router = new TokenRouter();
    const startedAt = Date.now();
    await router.recordFailure(channel.id, {
      status: 429,
      errorText: JSON.stringify({
        error: {
          message: 'upstream overloaded',
        },
      }),
      modelName: 'gpt-4o-mini',
    });

    const record = await db.select().from(schema.routeChannels)
      .where(eq(schema.routeChannels.id, channel.id))
      .get();
    const cooldownMs = Date.parse(String(record?.cooldownUntil || '')) - startedAt;

    expect(cooldownMs).toBeGreaterThanOrEqual(10_000);
    expect(cooldownMs).toBeLessThanOrEqual(20_000);
    expect(record?.failCount).toBe(1);
  });

  it('applies short-window cooldown to sibling channels that share the same account-level credential', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'shared-credential-site',
      url: 'https://shared-credential.example.com',
      platform: 'codex',
      status: 'active',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'shared-credential-user',
      accessToken: 'shared-credential-access-token',
      status: 'active',
      oauthProvider: 'codex',
      extraConfig: JSON.stringify({
        credentialMode: 'session',
        oauth: {
          provider: 'codex',
        },
      }),
    }).returning().get();

    const primaryRoute = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-5.4',
      routingStrategy: 'weighted',
      enabled: true,
    }).returning().get();

    const siblingRoute = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-4o-mini',
      routingStrategy: 'weighted',
      enabled: true,
    }).returning().get();

    const primaryChannel = await db.insert(schema.routeChannels).values({
      routeId: primaryRoute.id,
      accountId: account.id,
      priority: 0,
      weight: 10,
      enabled: true,
    }).returning().get();

    const siblingChannel = await db.insert(schema.routeChannels).values({
      routeId: siblingRoute.id,
      accountId: account.id,
      priority: 0,
      weight: 10,
      enabled: true,
    }).returning().get();

    const router = new TokenRouter();
    const initialSiblingSelection = await router.selectChannel('gpt-4o-mini');
    expect(initialSiblingSelection?.channel.id).toBe(siblingChannel.id);

    await router.recordFailure(primaryChannel.id, {
      status: 429,
      errorText: JSON.stringify({
        error: {
          type: 'usage_limit_reached',
          message: 'The usage limit has been reached',
        },
      }),
      modelName: 'gpt-5.4',
    });

    const cooledSibling = await db.select().from(schema.routeChannels)
      .where(eq(schema.routeChannels.id, siblingChannel.id))
      .get();

    expect(cooledSibling?.cooldownUntil).toBeTruthy();
    expect(cooledSibling?.failCount).toBe(0);
    expect(await router.selectChannel('gpt-4o-mini')).toBeNull();
  });

  it('round robins across all available channels regardless of priority', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'round-robin-site',
      url: 'https://round-robin-site.example.com',
      platform: 'new-api',
      status: 'active',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'round-robin-user',
      accessToken: 'round-robin-access-token',
      apiToken: 'round-robin-api-token',
      status: 'active',
    }).returning().get();

    const token = await db.insert(schema.accountTokens).values({
      accountId: account.id,
      name: 'round-robin-token',
      token: 'sk-round-robin-token',
      enabled: true,
      isDefault: true,
    }).returning().get();

    const route = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-4o-mini',
      routingStrategy: 'round_robin',
      enabled: true,
    }).returning().get();

    const channels = await db.insert(schema.routeChannels).values([
      { routeId: route.id, accountId: account.id, tokenId: token.id, priority: 0, weight: 10, enabled: true },
      { routeId: route.id, accountId: account.id, tokenId: token.id, priority: 3, weight: 10, enabled: true },
      { routeId: route.id, accountId: account.id, tokenId: token.id, priority: 9, weight: 10, enabled: true },
    ]).returning().all();

    const router = new TokenRouter();

    const first = await router.selectChannel('gpt-4o-mini');
    const second = await router.selectChannel('gpt-4o-mini');
    const third = await router.selectChannel('gpt-4o-mini');
    const fourth = await router.selectChannel('gpt-4o-mini');

    expect(first?.channel.id).toBe(channels[0].id);
    expect(second?.channel.id).toBe(channels[1].id);
    expect(third?.channel.id).toBe(channels[2].id);
    expect(fourth?.channel.id).toBe(channels[0].id);
  });

  it('applies staged cooldowns for round robin after every three consecutive failures', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'round-robin-cooldown-site',
      url: 'https://round-robin-cooldown-site.example.com',
      platform: 'new-api',
      status: 'active',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'round-robin-cooldown-user',
      accessToken: 'round-robin-cooldown-access-token',
      apiToken: 'round-robin-cooldown-api-token',
      status: 'active',
    }).returning().get();

    const token = await db.insert(schema.accountTokens).values({
      accountId: account.id,
      name: 'round-robin-cooldown-token',
      token: 'sk-round-robin-cooldown-token',
      enabled: true,
      isDefault: true,
    }).returning().get();

    const route = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-4o-mini',
      routingStrategy: 'round_robin',
      enabled: true,
    }).returning().get();

    const channel = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: account.id,
      tokenId: token.id,
      priority: 0,
      weight: 10,
      enabled: true,
    }).returning().get();

    const router = new TokenRouter();

    for (let index = 0; index < 2; index += 1) {
      await router.recordFailure(channel.id);
    }
    let current = await db.select().from(schema.routeChannels)
      .where(eq(schema.routeChannels.id, channel.id))
      .get();
    expect(current?.cooldownUntil).toBeNull();
    expect(current?.consecutiveFailCount).toBe(2);
    expect(current?.cooldownLevel).toBe(0);

    let startedAt = Date.now();
    await router.recordFailure(channel.id);
    current = await db.select().from(schema.routeChannels)
      .where(eq(schema.routeChannels.id, channel.id))
      .get();
    let cooldownMs = Date.parse(String(current?.cooldownUntil || '')) - startedAt;
    expect(current?.consecutiveFailCount).toBe(0);
    expect(current?.cooldownLevel).toBe(1);
    expect(cooldownMs).toBeGreaterThanOrEqual(9 * 60 * 1000);
    expect(cooldownMs).toBeLessThanOrEqual(11 * 60 * 1000);

    await db.update(schema.routeChannels).set({ cooldownUntil: null }).where(eq(schema.routeChannels.id, channel.id)).run();

    for (let index = 0; index < 2; index += 1) {
      await router.recordFailure(channel.id);
    }
    startedAt = Date.now();
    await router.recordFailure(channel.id);
    current = await db.select().from(schema.routeChannels)
      .where(eq(schema.routeChannels.id, channel.id))
      .get();
    cooldownMs = Date.parse(String(current?.cooldownUntil || '')) - startedAt;
    expect(current?.cooldownLevel).toBe(2);
    expect(cooldownMs).toBeGreaterThanOrEqual(59 * 60 * 1000);
    expect(cooldownMs).toBeLessThanOrEqual(61 * 60 * 1000);

    await db.update(schema.routeChannels).set({ cooldownUntil: null }).where(eq(schema.routeChannels.id, channel.id)).run();

    for (let index = 0; index < 2; index += 1) {
      await router.recordFailure(channel.id);
    }
    startedAt = Date.now();
    await router.recordFailure(channel.id);
    current = await db.select().from(schema.routeChannels)
      .where(eq(schema.routeChannels.id, channel.id))
      .get();
    cooldownMs = Date.parse(String(current?.cooldownUntil || '')) - startedAt;
    expect(current?.cooldownLevel).toBe(3);
    expect(cooldownMs).toBeGreaterThanOrEqual(23 * 60 * 60 * 1000);
    expect(cooldownMs).toBeLessThanOrEqual(25 * 60 * 60 * 1000);

    await router.recordSuccess(channel.id, 320, 0.12);
    current = await db.select().from(schema.routeChannels)
      .where(eq(schema.routeChannels.id, channel.id))
      .get();
    expect(current?.consecutiveFailCount).toBe(0);
    expect(current?.cooldownLevel).toBe(0);
    expect(current?.cooldownUntil).toBeNull();
  });

  it('caps weighted cooldowns before Date overflow for heavily failed channels', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'weighted-cooldown-cap-site',
      url: 'https://weighted-cooldown-cap.example.com',
      platform: 'new-api',
      status: 'active',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'weighted-cooldown-cap-user',
      accessToken: 'weighted-cooldown-cap-access-token',
      apiToken: 'weighted-cooldown-cap-api-token',
      status: 'active',
    }).returning().get();

    const token = await db.insert(schema.accountTokens).values({
      accountId: account.id,
      name: 'weighted-cooldown-cap-token',
      token: 'sk-weighted-cooldown-cap-token',
      enabled: true,
      isDefault: true,
    }).returning().get();

    const route = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-5.4',
      routingStrategy: 'weighted',
      enabled: true,
    }).returning().get();

    const channel = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: account.id,
      tokenId: token.id,
      priority: 0,
      weight: 10,
      enabled: true,
      failCount: 57,
    }).returning().get();

    // Weighted routes previously let Fibonacci backoff grow beyond the Date range.
    const router = new TokenRouter();

    const startedAt = Date.now();
    await router.recordFailure(channel.id);
    const current = await db.select().from(schema.routeChannels)
      .where(eq(schema.routeChannels.id, channel.id))
      .get();
    const cooldownMs = Date.parse(String(current?.cooldownUntil || '')) - startedAt;

    expect(current?.failCount).toBe(58);
    expect(Number.isFinite(Date.parse(String(current?.cooldownUntil || '')))).toBe(true);
    expect(cooldownMs).toBeGreaterThanOrEqual((30 * 24 * 60 * 60 - 5) * 1000);
    expect(cooldownMs).toBeLessThanOrEqual((30 * 24 * 60 * 60 + 5) * 1000);
  });
});
