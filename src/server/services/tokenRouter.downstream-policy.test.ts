import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

type DbModule = typeof import('../db/index.js');
type TokenRouterModule = typeof import('./tokenRouter.js');

describe('TokenRouter downstream policy', () => {
  let db: DbModule['db'];
  let schema: DbModule['schema'];
  let TokenRouter: TokenRouterModule['TokenRouter'];
  let invalidateTokenRouterCache: TokenRouterModule['invalidateTokenRouterCache'];
  let dataDir = '';

  beforeAll(async () => {
    dataDir = mkdtempSync(join(tmpdir(), 'metapi-token-router-policy-'));
    process.env.DATA_DIR = dataDir;

    await import('../db/migrate.js');
    const dbModule = await import('../db/index.js');
    const tokenRouterModule = await import('./tokenRouter.js');
    db = dbModule.db;
    schema = dbModule.schema;
    TokenRouter = tokenRouterModule.TokenRouter;
    invalidateTokenRouterCache = tokenRouterModule.invalidateTokenRouterCache;
  });

  beforeEach(async () => {
    await db.delete(schema.routeChannels).run();
    await db.delete(schema.tokenRoutes).run();
    await db.delete(schema.accountTokens).run();
    await db.delete(schema.accounts).run();
    await db.delete(schema.sites).run();
    invalidateTokenRouterCache();
  });

  afterAll(() => {
    invalidateTokenRouterCache();
    delete process.env.DATA_DIR;
  });

  it('respects allowedRouteIds when selecting channels', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'site-a',
      url: 'https://a.example.com',
      platform: 'new-api',
      status: 'active',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'user-a',
      accessToken: 'access-a',
      apiToken: 'sk-a',
      status: 'active',
    }).returning().get();

    const routeAllowed = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'claude-opus-4-6',
      enabled: true,
    }).returning().get();

    const routeBlocked = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-4o-mini',
      enabled: true,
    }).returning().get();

    await db.insert(schema.routeChannels).values({
      routeId: routeAllowed.id,
      accountId: account.id,
      tokenId: null,
      priority: 0,
      weight: 10,
      enabled: true,
    }).run();

    await db.insert(schema.routeChannels).values({
      routeId: routeBlocked.id,
      accountId: account.id,
      tokenId: null,
      priority: 0,
      weight: 10,
      enabled: true,
    }).run();

    const router = new TokenRouter();

    const allowedPick = await router.selectChannel('claude-opus-4-6', {
      allowedRouteIds: [routeAllowed.id],
      supportedModels: [],
      siteWeightMultipliers: {},
    });
    const blockedPick = await router.selectChannel('gpt-4o-mini', {
      allowedRouteIds: [routeAllowed.id],
      supportedModels: [],
      siteWeightMultipliers: {},
    });

    expect(allowedPick).toBeTruthy();
    expect(allowedPick?.channel.routeId).toBe(routeAllowed.id);
    expect(blockedPick).toBeNull();
  });

  it('rejects route selection when both supportedModels and allowedRouteIds are empty', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'site-deny-all',
      url: 'https://deny-all.example.com',
      platform: 'new-api',
      status: 'active',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'user-deny-all',
      accessToken: 'access-deny-all',
      apiToken: 'sk-deny-all',
      status: 'active',
    }).returning().get();

    const route = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-4o-mini',
      enabled: true,
    }).returning().get();

    await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: account.id,
      tokenId: null,
      priority: 0,
      weight: 10,
      enabled: true,
    }).run();

    const router = new TokenRouter();
    const deniedPick = await router.selectChannel('gpt-4o-mini', {
      allowedRouteIds: [],
      supportedModels: [],
      siteWeightMultipliers: {},
      denyAllWhenEmpty: true,
    });

    expect(deniedPick).toBeNull();
  });

  it('applies site weight multipliers to probability explanation', async () => {
    const siteHigh = await db.insert(schema.sites).values({
      name: 'high-site',
      url: 'https://high.example.com',
      platform: 'new-api',
      status: 'active',
    }).returning().get();

    const siteLow = await db.insert(schema.sites).values({
      name: 'low-site',
      url: 'https://low.example.com',
      platform: 'new-api',
      status: 'active',
    }).returning().get();

    const accountHigh = await db.insert(schema.accounts).values({
      siteId: siteHigh.id,
      username: 'user-high',
      accessToken: 'access-high',
      apiToken: 'sk-high',
      status: 'active',
      unitCost: 1,
      balance: 100,
    }).returning().get();

    const accountLow = await db.insert(schema.accounts).values({
      siteId: siteLow.id,
      username: 'user-low',
      accessToken: 'access-low',
      apiToken: 'sk-low',
      status: 'active',
      unitCost: 1,
      balance: 100,
    }).returning().get();

    const route = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'claude-sonnet-4-6',
      enabled: true,
    }).returning().get();

    const channelHigh = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: accountHigh.id,
      tokenId: null,
      priority: 0,
      weight: 10,
      enabled: true,
    }).returning().get();

    const channelLow = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: accountLow.id,
      tokenId: null,
      priority: 0,
      weight: 10,
      enabled: true,
    }).returning().get();

    const router = new TokenRouter();
    const decision = await router.explainSelectionForRoute(
      route.id,
      'claude-sonnet-4-6',
      [],
      {
        allowedRouteIds: [route.id],
        supportedModels: [],
        siteWeightMultipliers: {
          [siteHigh.id]: 4,
          [siteLow.id]: 1,
        },
      },
    );

    const highCandidate = decision.candidates.find((candidate) => candidate.channelId === channelHigh.id);
    const lowCandidate = decision.candidates.find((candidate) => candidate.channelId === channelLow.id);

    expect(highCandidate).toBeTruthy();
    expect(lowCandidate).toBeTruthy();
    expect((highCandidate?.probability || 0)).toBeGreaterThan(lowCandidate?.probability || 0);
  });

  it('combines site global weight with downstream site multiplier', async () => {
    const siteGlobalHigh = await db.insert(schema.sites).values({
      name: 'global-high-site',
      url: 'https://global-high.example.com',
      platform: 'new-api',
      status: 'active',
      globalWeight: 3,
    }).returning().get();

    const siteGlobalLow = await db.insert(schema.sites).values({
      name: 'global-low-site',
      url: 'https://global-low.example.com',
      platform: 'new-api',
      status: 'active',
      globalWeight: 1,
    }).returning().get();

    const accountGlobalHigh = await db.insert(schema.accounts).values({
      siteId: siteGlobalHigh.id,
      username: 'user-global-high',
      accessToken: 'access-global-high',
      apiToken: 'sk-global-high',
      status: 'active',
      unitCost: 1,
      balance: 100,
    }).returning().get();

    const accountGlobalLow = await db.insert(schema.accounts).values({
      siteId: siteGlobalLow.id,
      username: 'user-global-low',
      accessToken: 'access-global-low',
      apiToken: 'sk-global-low',
      status: 'active',
      unitCost: 1,
      balance: 100,
    }).returning().get();

    const route = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-5-mini',
      enabled: true,
    }).returning().get();

    const highChannel = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: accountGlobalHigh.id,
      tokenId: null,
      priority: 0,
      weight: 10,
      enabled: true,
    }).returning().get();

    const lowChannel = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: accountGlobalLow.id,
      tokenId: null,
      priority: 0,
      weight: 10,
      enabled: true,
    }).returning().get();

    const router = new TokenRouter();
    const decision = await router.explainSelectionForRoute(
      route.id,
      'gpt-5-mini',
      [],
      {
        allowedRouteIds: [route.id],
        supportedModels: [],
        siteWeightMultipliers: {
          [siteGlobalHigh.id]: 0.5,
          [siteGlobalLow.id]: 1,
        },
      },
    );

    const highCandidate = decision.candidates.find((candidate) => candidate.channelId === highChannel.id);
    const lowCandidate = decision.candidates.find((candidate) => candidate.channelId === lowChannel.id);

    expect(highCandidate).toBeTruthy();
    expect(lowCandidate).toBeTruthy();
    // combined multiplier: high=3*0.5=1.5, low=1*1=1
    expect((highCandidate?.probability || 0)).toBeGreaterThan(lowCandidate?.probability || 0);
  });

  it('supports union semantics between supportedModels and allowedRouteIds', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'site-union',
      url: 'https://union.example.com',
      platform: 'new-api',
      status: 'active',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'user-union',
      accessToken: 'access-union',
      apiToken: 'sk-union',
      status: 'active',
    }).returning().get();

    const claudeGroupRoute = await db.insert(schema.tokenRoutes).values({
      modelPattern: 're:^claude-(opus|sonnet)-4-6$',
      enabled: true,
    }).returning().get();

    const gptExactRoute = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-4o-mini',
      enabled: true,
    }).returning().get();

    await db.insert(schema.routeChannels).values({
      routeId: claudeGroupRoute.id,
      accountId: account.id,
      tokenId: null,
      priority: 0,
      weight: 10,
      enabled: true,
    }).run();

    await db.insert(schema.routeChannels).values({
      routeId: gptExactRoute.id,
      accountId: account.id,
      tokenId: null,
      priority: 0,
      weight: 10,
      enabled: true,
    }).run();

    const router = new TokenRouter();
    const policy = {
      allowedRouteIds: [claudeGroupRoute.id],
      supportedModels: ['gpt-4o-mini'],
      siteWeightMultipliers: {},
    };

    const claudePick = await router.selectChannel('claude-opus-4-6', policy);
    const gptPick = await router.selectChannel('gpt-4o-mini', policy);

    expect(claudePick?.channel.routeId).toBe(claudeGroupRoute.id);
    expect(gptPick?.channel.routeId).toBe(gptExactRoute.id);
  });

  it('excludes candidates from excluded sites before route selection', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'site-excluded',
      url: 'https://excluded.example.com',
      platform: 'new-api',
      status: 'active',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'user-excluded',
      accessToken: 'access-excluded',
      apiToken: 'sk-excluded',
      status: 'active',
    }).returning().get();

    const route = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-4o-mini',
      enabled: true,
    }).returning().get();

    const channel = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: account.id,
      tokenId: null,
      priority: 0,
      weight: 10,
      enabled: true,
    }).returning().get();

    const router = new TokenRouter();
    const policy: any = {
      allowedRouteIds: [route.id],
      supportedModels: [],
      siteWeightMultipliers: {},
      excludedSiteIds: [site.id],
      excludedCredentialRefs: [],
    };

    const pick = await router.selectChannel('gpt-4o-mini', policy);
    const decision = await router.explainSelectionForRoute(route.id, 'gpt-4o-mini', [], policy);
    const candidate = decision.candidates.find((item) => item.channelId === channel.id);

    expect(pick).toBeNull();
    expect(candidate?.eligible).toBe(false);
    expect(candidate?.reason).toContain('站点已被下游密钥排除');
  });

  it('excludes explicitly bound tokens by downstream credential refs', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'site-token',
      url: 'https://token.example.com',
      platform: 'new-api',
      status: 'active',
    }).returning().get();

    const blockedAccount = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'user-blocked',
      accessToken: 'access-blocked',
      apiToken: 'sk-blocked-default',
      status: 'active',
    }).returning().get();
    const allowedAccount = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'user-allowed',
      accessToken: 'access-allowed',
      apiToken: 'sk-allowed-default',
      status: 'active',
    }).returning().get();

    const blockedToken = await db.insert(schema.accountTokens).values({
      accountId: blockedAccount.id,
      name: 'blocked-token',
      token: 'sk-blocked-token',
      enabled: true,
      isDefault: true,
      valueStatus: 'ready',
    }).returning().get();
    const allowedToken = await db.insert(schema.accountTokens).values({
      accountId: allowedAccount.id,
      name: 'allowed-token',
      token: 'sk-allowed-token',
      enabled: true,
      isDefault: true,
      valueStatus: 'ready',
    }).returning().get();

    const route = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'claude-sonnet-4-6',
      enabled: true,
    }).returning().get();

    const blockedChannel = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: blockedAccount.id,
      tokenId: blockedToken.id,
      priority: 0,
      weight: 10,
      enabled: true,
    }).returning().get();
    const allowedChannel = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: allowedAccount.id,
      tokenId: allowedToken.id,
      priority: 0,
      weight: 10,
      enabled: true,
    }).returning().get();

    const router = new TokenRouter();
    const policy: any = {
      allowedRouteIds: [route.id],
      supportedModels: [],
      siteWeightMultipliers: {},
      excludedSiteIds: [],
      excludedCredentialRefs: [
        { kind: 'account_token', siteId: site.id, accountId: blockedAccount.id, tokenId: blockedToken.id },
      ],
    };

    const pick = await router.selectChannel('claude-sonnet-4-6', policy);
    const decision = await router.explainSelectionForRoute(route.id, 'claude-sonnet-4-6', [], policy);
    const blockedCandidate = decision.candidates.find((item) => item.channelId === blockedChannel.id);
    const allowedCandidate = decision.candidates.find((item) => item.channelId === allowedChannel.id);

    expect(pick?.channel.id).toBe(allowedChannel.id);
    expect(blockedCandidate?.eligible).toBe(false);
    expect(blockedCandidate?.reason).toContain('API Key/令牌已被下游密钥排除');
    expect(allowedCandidate?.eligible).toBe(true);
  });

  it('excludes default api key channels by downstream credential refs', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'site-default',
      url: 'https://default.example.com',
      platform: 'new-api',
      status: 'active',
    }).returning().get();

    const blockedAccount = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'user-blocked',
      accessToken: 'access-blocked',
      apiToken: 'sk-blocked-default',
      status: 'active',
    }).returning().get();
    const allowedAccount = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'user-allowed',
      accessToken: 'access-allowed',
      apiToken: 'sk-allowed-default',
      status: 'active',
    }).returning().get();

    const route = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-5-mini',
      enabled: true,
    }).returning().get();

    const blockedChannel = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: blockedAccount.id,
      tokenId: null,
      priority: 0,
      weight: 10,
      enabled: true,
    }).returning().get();
    const allowedChannel = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: allowedAccount.id,
      tokenId: null,
      priority: 0,
      weight: 10,
      enabled: true,
    }).returning().get();

    const router = new TokenRouter();
    const policy: any = {
      allowedRouteIds: [route.id],
      supportedModels: [],
      siteWeightMultipliers: {},
      excludedSiteIds: [],
      excludedCredentialRefs: [
        { kind: 'default_api_key', siteId: site.id, accountId: blockedAccount.id },
      ],
    };

    const pick = await router.selectChannel('gpt-5-mini', policy);
    const decision = await router.explainSelectionForRoute(route.id, 'gpt-5-mini', [], policy);
    const blockedCandidate = decision.candidates.find((item) => item.channelId === blockedChannel.id);

    expect(pick?.channel.id).toBe(allowedChannel.id);
    expect(blockedCandidate?.eligible).toBe(false);
    expect(blockedCandidate?.reason).toContain('API Key/令牌已被下游密钥排除');
  });
});
