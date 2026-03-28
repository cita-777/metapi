import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

type DbModule = typeof import('../db/index.js');
type TokenRouterModule = typeof import('./tokenRouter.js');

describe('TokenRouter patterns and model mapping', () => {
  let db: DbModule['db'];
  let schema: DbModule['schema'];
  let TokenRouter: TokenRouterModule['TokenRouter'];
  let invalidateTokenRouterCache: TokenRouterModule['invalidateTokenRouterCache'];
  let tokenRouterTestUtils: TokenRouterModule['__tokenRouterTestUtils'];
  let dataDir = '';
  let idSeed = 0;

  const nextId = () => {
    idSeed += 1;
    return idSeed;
  };

  beforeAll(async () => {
    dataDir = mkdtempSync(join(tmpdir(), 'metapi-token-router-patterns-'));
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
    idSeed = 0;
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

  async function createSite(namePrefix: string) {
    const id = nextId();
    return await db.insert(schema.sites).values({
      name: `${namePrefix}-${id}`,
      url: `https://${namePrefix}-${id}.example.com`,
      platform: 'new-api',
      status: 'active',
    }).returning().get();
  }

  async function createAccount(siteId: number, usernamePrefix: string) {
    const id = nextId();
    return await db.insert(schema.accounts).values({
      siteId,
      username: `${usernamePrefix}-${id}`,
      accessToken: `access-${id}`,
      apiToken: `sk-${id}`,
      status: 'active',
    }).returning().get();
  }

  async function createRouteWithSingleChannel(
    modelPattern: string,
    modelMapping?: string,
    options?: { displayName?: string; sourceModel?: string | null },
  ) {
    const site = await createSite('pattern-site');
    const account = await createAccount(site.id, 'pattern-user');
    const route = await db.insert(schema.tokenRoutes).values({
      modelPattern,
      displayName: options?.displayName,
      modelMapping,
      enabled: true,
    }).returning().get();
    const channel = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: account.id,
      tokenId: null,
      sourceModel: options?.sourceModel ?? null,
      priority: 0,
      weight: 10,
      enabled: true,
    }).returning().get();
    return { route, channel };
  }

  async function createExplicitGroupRoute(
    displayName: string,
    sourceRouteIds: number[],
  ) {
    const route = await db.insert(schema.tokenRoutes).values({
      modelPattern: displayName,
      displayName,
      routeMode: 'explicit_group',
      enabled: true,
    }).returning().get();

    await db.insert(schema.routeGroupSources).values(
      sourceRouteIds.map((sourceRouteId) => ({
        groupRouteId: route.id,
        sourceRouteId,
      })),
    ).run();

    return route;
  }

  it('matches routes with re: regex patterns', async () => {
    await createRouteWithSingleChannel('re:^claude-(opus|sonnet)-4-6$');
    const router = new TokenRouter();

    const matched = await router.selectChannel('claude-opus-4-6');
    const unmatched = await router.selectChannel('claude-haiku-4-6');

    expect(matched).toBeTruthy();
    expect(matched?.actualModel).toBe('claude-opus-4-6');
    expect(unmatched).toBeNull();
  });

  it('ignores invalid re: patterns and falls back to next matched route', async () => {
    const invalid = await createRouteWithSingleChannel('re:([a-z');
    const glob = await createRouteWithSingleChannel('claude-*');
    const router = new TokenRouter();

    const selected = await router.selectChannel('claude-opus-4-6');
    expect(selected).toBeTruthy();
    expect(selected?.channel.id).toBe(glob.channel.id);
    expect(selected?.channel.id).not.toBe(invalid.channel.id);
  });

  it('supports exact, glob and re: keys in modelMapping with exact taking precedence', async () => {
    const mapping = JSON.stringify({
      'claude-sonnet-4-6': 'target-exact',
      'claude-sonnet-*': 'target-glob',
      're:^gpt-4o-mini-\\d+$': 'target-regex',
    });
    await createRouteWithSingleChannel('*', mapping);
    const router = new TokenRouter();

    const exact = await router.selectChannel('claude-sonnet-4-6');
    const glob = await router.selectChannel('claude-sonnet-4-7');
    const regex = await router.selectChannel('gpt-4o-mini-20250101');

    expect(exact?.actualModel).toBe('target-exact');
    expect(glob?.actualModel).toBe('target-glob');
    expect(regex?.actualModel).toBe('target-regex');
  });

  it('resolves mapped models from parsed object input for helper-level callers', () => {
    expect(tokenRouterTestUtils.resolveMappedModel('claude-sonnet-4-6', {
      'claude-sonnet-4-6': 'target-exact',
      'claude-sonnet-*': 'target-glob',
    })).toBe('target-exact');
    expect(tokenRouterTestUtils.resolveMappedModel('claude-sonnet-4-7', {
      'claude-sonnet-4-6': 'target-exact',
      'claude-sonnet-*': 'target-glob',
    })).toBe('target-glob');
  });

  it('matches a route by display name alias as an exposed model', async () => {
    await createRouteWithSingleChannel(
      're:^claude-(opus|sonnet)-4-5$',
      undefined,
      {
        displayName: 'claude-opus-4-6',
        sourceModel: 'claude-opus-4-5',
      },
    );
    const router = new TokenRouter();

    const selected = await router.selectChannel('claude-opus-4-6');
    const decision = await router.explainSelection('claude-opus-4-6');
    const exposedModels = await router.getAvailableModels();

    expect(selected).toBeTruthy();
    expect(selected?.actualModel).toBe('claude-opus-4-5');
    expect(decision.actualModel).toBe('claude-opus-4-5');
    expect(exposedModels).toContain('claude-opus-4-6');
  });

  it('prefers an exact route over a colliding group display-name alias', async () => {
    await createRouteWithSingleChannel(
      're:^claude-(opus|sonnet)-4-5$',
      undefined,
      {
        displayName: 'claude-opus-4-6',
        sourceModel: 'claude-opus-4-5',
      },
    );
    const exact = await createRouteWithSingleChannel(
      'claude-opus-4-6',
      undefined,
      {
        sourceModel: 'claude-opus-4-6',
      },
    );
    const router = new TokenRouter();

    const selected = await router.selectChannel('claude-opus-4-6');
    const decision = await router.explainSelection('claude-opus-4-6');

    expect(selected).toBeTruthy();
    expect(selected?.channel.id).toBe(exact.channel.id);
    expect(selected?.actualModel).toBe('claude-opus-4-6');
    expect(decision.actualModel).toBe('claude-opus-4-6');
  });

  it('falls back to the source exact-route model when explicit-group channels omit sourceModel', async () => {
    const source = await createRouteWithSingleChannel('claude-opus-4-5');
    await createExplicitGroupRoute('claude-test-4.6-sonnet', [source.route.id]);
    const router = new TokenRouter();

    const selected = await router.selectChannel('claude-test-4.6-sonnet');
    const decision = await router.explainSelection('claude-test-4.6-sonnet');

    expect(selected).toBeTruthy();
    expect(selected?.actualModel).toBe('claude-opus-4-5');
    expect(decision.actualModel).toBe('claude-opus-4-5');
    expect(decision.summary).toContain('按显示名命中：claude-test-4.6-sonnet');
    expect(decision.summary).toContain('实际转发模型：claude-opus-4-5');
  });
});
