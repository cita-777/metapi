import Fastify, { type FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

type DbModule = typeof import('../../db/index.js');
type ProxyRouterModule = typeof import('./router.js');
type TokenRouterModule = typeof import('../../services/tokenRouter.js');
type TokensRoutesModule = typeof import('../api/tokens.js');
type ConfigModule = typeof import('../../config.js');

describe('/v1/models route', () => {
  let db: DbModule['db'];
  let schema: DbModule['schema'];
  let proxyRoutes: ProxyRouterModule['proxyRoutes'];
  let tokensRoutes: TokensRoutesModule['tokensRoutes'];
  let invalidateTokenRouterCache: TokenRouterModule['invalidateTokenRouterCache'];
  let config: ConfigModule['config'];
  let app: FastifyInstance;
  let dataDir = '';

  beforeAll(async () => {
    dataDir = mkdtempSync(join(tmpdir(), 'metapi-models-route-'));
    process.env.DATA_DIR = dataDir;

    await import('../../db/migrate.js');
    const dbModule = await import('../../db/index.js');
    const proxyRouterModule = await import('./router.js');
    const tokenRouterModule = await import('../../services/tokenRouter.js');
    const tokensRoutesModule = await import('../api/tokens.js');
    const configModule = await import('../../config.js');

    db = dbModule.db;
    schema = dbModule.schema;
    proxyRoutes = proxyRouterModule.proxyRoutes;
    tokensRoutes = tokensRoutesModule.tokensRoutes;
    invalidateTokenRouterCache = tokenRouterModule.invalidateTokenRouterCache;
    config = configModule.config;
    config.proxyToken = 'sk-global-proxy-token';

    app = Fastify();
    await app.register(tokensRoutes);
    await app.register(proxyRoutes);
  });

  beforeEach(async () => {
    invalidateTokenRouterCache();
    await db.delete(schema.routeChannels).run();
    await db.delete(schema.tokenRoutes).run();
    await db.delete(schema.tokenModelAvailability).run();
    await db.delete(schema.modelAvailability).run();
    await db.delete(schema.accountTokens).run();
    await db.delete(schema.accounts).run();
    await db.delete(schema.sites).run();
    await db.delete(schema.downstreamApiKeys).run();
  });

  afterAll(async () => {
    await app.close();
    delete process.env.DATA_DIR;
  });

  it('hides models that have no routable channel even if model availability contains them', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'test-site',
      url: 'https://upstream.example.com',
      platform: 'openai',
      status: 'active',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      accessToken: 'account-access-token',
      status: 'active',
    }).returning().get();

    const token = await db.insert(schema.accountTokens).values({
      accountId: account.id,
      name: 'default',
      token: 'account-api-token',
      enabled: true,
      isDefault: true,
    }).returning().get();

    await db.insert(schema.modelAvailability).values([
      {
        accountId: account.id,
        modelName: 'routable-model',
        available: true,
      },
      {
        accountId: account.id,
        modelName: 'orphan-model',
        available: true,
      },
    ]).run();

    const route = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'routable-model',
      enabled: true,
    }).returning().get();

    await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: account.id,
      tokenId: token.id,
      sourceModel: 'routable-model',
      enabled: true,
    }).run();

    await db.insert(schema.downstreamApiKeys).values({
      name: 'managed-key',
      key: 'sk-managed-models',
      enabled: true,
      supportedModels: JSON.stringify(['routable-model']),
    }).run();

    const response = await app.inject({
      method: 'GET',
      url: '/v1/models',
      headers: {
        authorization: 'Bearer sk-managed-models',
      },
    });

    expect(response.statusCode).toBe(200);
    const body = response.json() as {
      object: 'list';
      data: Array<{ id: string }>;
    };

    const ids = body.data.map((item) => item.id);
    expect(ids).toContain('routable-model');
    expect(ids).not.toContain('orphan-model');
  });

  it('keeps global proxy token unrestricted when no managed key matches', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'global-site',
      url: 'https://global.example.com',
      platform: 'openai',
      status: 'active',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      accessToken: 'global-access-token',
      status: 'active',
    }).returning().get();

    const token = await db.insert(schema.accountTokens).values({
      accountId: account.id,
      name: 'default',
      token: 'global-api-token',
      enabled: true,
      isDefault: true,
    }).returning().get();

    await db.insert(schema.modelAvailability).values({
      accountId: account.id,
      modelName: 'global-routable-model',
      available: true,
    }).run();

    const route = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'global-routable-model',
      enabled: true,
    }).returning().get();

    await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: account.id,
      tokenId: token.id,
      sourceModel: 'global-routable-model',
      enabled: true,
    }).run();

    const response = await app.inject({
      method: 'GET',
      url: '/v1/models',
      headers: {
        authorization: 'Bearer sk-global-proxy-token',
      },
    });

    expect(response.statusCode).toBe(200);
    const body = response.json() as {
      object: 'list';
      data: Array<{ id: string }>;
    };

    expect(body.data.map((item) => item.id)).toContain('global-routable-model');
  });

  it('returns only whitelist models for managed key with supportedModels policy', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'test-site',
      url: 'https://upstream.example.com',
      platform: 'openai',
      status: 'active',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      accessToken: 'account-access-token',
      status: 'active',
    }).returning().get();

    const token = await db.insert(schema.accountTokens).values({
      accountId: account.id,
      name: 'default',
      token: 'account-api-token',
      enabled: true,
      isDefault: true,
    }).returning().get();

    await db.insert(schema.modelAvailability).values([
      {
        accountId: account.id,
        modelName: 'allowed-model',
        available: true,
      },
      {
        accountId: account.id,
        modelName: 'blocked-model',
        available: true,
      },
    ]).run();

    const allowedRoute = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'allowed-model',
      enabled: true,
    }).returning().get();
    const blockedRoute = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'blocked-model',
      enabled: true,
    }).returning().get();

    await db.insert(schema.routeChannels).values([
      {
        routeId: allowedRoute.id,
        accountId: account.id,
        tokenId: token.id,
        sourceModel: 'allowed-model',
        enabled: true,
      },
      {
        routeId: blockedRoute.id,
        accountId: account.id,
        tokenId: token.id,
        sourceModel: 'blocked-model',
        enabled: true,
      },
    ]).run();

    await db.insert(schema.downstreamApiKeys).values({
      name: 'managed-key',
      key: 'sk-managed-whitelist',
      enabled: true,
      supportedModels: JSON.stringify(['allowed-model']),
    }).run();

    const response = await app.inject({
      method: 'GET',
      url: '/v1/models',
      headers: {
        authorization: 'Bearer sk-managed-whitelist',
      },
    });

    expect(response.statusCode).toBe(200);
    const body = response.json() as {
      object: 'list';
      data: Array<{ id: string }>;
    };
    const ids = body.data.map((item) => item.id);
    expect(ids).toContain('allowed-model');
    expect(ids).not.toContain('blocked-model');
  });

  it('returns only selected group route alias for managed key with allowedRouteIds policy', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'test-site',
      url: 'https://upstream.example.com',
      platform: 'openai',
      status: 'active',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      accessToken: 'account-access-token',
      status: 'active',
    }).returning().get();

    const token = await db.insert(schema.accountTokens).values({
      accountId: account.id,
      name: 'default',
      token: 'account-api-token',
      enabled: true,
      isDefault: true,
    }).returning().get();

    await db.insert(schema.modelAvailability).values([
      {
        accountId: account.id,
        modelName: 'claude-opus-4-5',
        available: true,
      },
      {
        accountId: account.id,
        modelName: 'claude-sonnet-4-5',
        available: true,
      },
    ]).run();

    const groupRoute = await db.insert(schema.tokenRoutes).values({
      modelPattern: 're:^claude-(opus|sonnet)-4-5$',
      displayName: 'claude-opus-4-6',
      enabled: true,
    }).returning().get();

    await db.insert(schema.routeChannels).values({
      routeId: groupRoute.id,
      accountId: account.id,
      tokenId: token.id,
      enabled: true,
    }).run();

    await db.insert(schema.downstreamApiKeys).values({
      name: 'managed-key',
      key: 'sk-managed-group-only',
      enabled: true,
      allowedRouteIds: JSON.stringify([groupRoute.id]),
    }).run();

    const response = await app.inject({
      method: 'GET',
      url: '/v1/models',
      headers: {
        authorization: 'Bearer sk-managed-group-only',
      },
    });

    expect(response.statusCode).toBe(200);
    const body = response.json() as {
      object: 'list';
      data: Array<{ id: string }>;
    };

    const ids = body.data.map((item) => item.id);
    expect(ids).toContain('claude-opus-4-6');
    expect(ids).not.toContain('claude-opus-4-5');
    expect(ids).not.toContain('claude-sonnet-4-5');
  });

  it('returns all models for managed key with empty model and group selections', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'deny-all-site',
      url: 'https://deny-all.example.com',
      platform: 'openai',
      status: 'active',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      accessToken: 'deny-all-access-token',
      status: 'active',
    }).returning().get();

    const token = await db.insert(schema.accountTokens).values({
      accountId: account.id,
      name: 'default',
      token: 'deny-all-api-token',
      enabled: true,
      isDefault: true,
    }).returning().get();

    await db.insert(schema.modelAvailability).values([
      {
        accountId: account.id,
        modelName: 'gpt-4o-mini',
        available: true,
      },
      {
        accountId: account.id,
        modelName: 'claude-opus-4-6',
        available: true,
      },
    ]).run();

    const gptRoute = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-4o-mini',
      enabled: true,
    }).returning().get();
    const claudeRoute = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'claude-opus-4-6',
      enabled: true,
    }).returning().get();

    await db.insert(schema.routeChannels).values([
      {
        routeId: gptRoute.id,
        accountId: account.id,
        tokenId: token.id,
        sourceModel: 'gpt-4o-mini',
        enabled: true,
      },
      {
        routeId: claudeRoute.id,
        accountId: account.id,
        tokenId: token.id,
        sourceModel: 'claude-opus-4-6',
        enabled: true,
      },
    ]).run();

    await db.insert(schema.downstreamApiKeys).values({
      name: 'managed-key-deny-all',
      key: 'sk-managed-deny-all',
      enabled: true,
      supportedModels: JSON.stringify([]),
      allowedRouteIds: JSON.stringify([]),
    }).run();

    const response = await app.inject({
      method: 'GET',
      url: '/v1/models',
      headers: {
        authorization: 'Bearer sk-managed-deny-all',
      },
    });

    expect(response.statusCode).toBe(200);
    const body = response.json() as {
      object: 'list';
      data: Array<{ id: string }>;
    };

    expect(body.data.map((item) => item.id).sort()).toEqual([
      'claude-opus-4-6',
      'gpt-4o-mini',
    ]);
  });

  it('returns only explicit-group public name while hiding source exact routes', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'explicit-group-site',
      url: 'https://explicit-group.example.com',
      platform: 'openai',
      status: 'active',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      accessToken: 'explicit-group-access-token',
      status: 'active',
    }).returning().get();

    const token = await db.insert(schema.accountTokens).values({
      accountId: account.id,
      name: 'default',
      token: 'explicit-group-api-token',
      enabled: true,
      isDefault: true,
    }).returning().get();

    await db.insert(schema.modelAvailability).values([
      {
        accountId: account.id,
        modelName: 'claude-opus-4-5',
        available: true,
      },
      {
        accountId: account.id,
        modelName: 'claude-sonnet-4-5',
        available: true,
      },
    ]).run();

    const sourceRouteA = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'claude-opus-4-5',
      enabled: true,
    }).returning().get();
    const sourceRouteB = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'claude-sonnet-4-5',
      enabled: true,
    }).returning().get();

    await db.insert(schema.routeChannels).values([
      {
        routeId: sourceRouteA.id,
        accountId: account.id,
        tokenId: token.id,
        sourceModel: 'claude-opus-4-5',
        enabled: true,
      },
      {
        routeId: sourceRouteB.id,
        accountId: account.id,
        tokenId: token.id,
        sourceModel: 'claude-sonnet-4-5',
        enabled: true,
      },
    ]).run();

    const groupResponse = await app.inject({
      method: 'POST',
      url: '/api/routes',
      payload: {
        routeMode: 'explicit_group',
        displayName: 'claude-opus-4-6',
        sourceRouteIds: [sourceRouteA.id, sourceRouteB.id],
      },
    });
    expect(groupResponse.statusCode).toBe(200);
    const groupId = (groupResponse.json() as { id: number }).id;

    await db.insert(schema.downstreamApiKeys).values({
      name: 'managed-explicit-group-key',
      key: 'sk-managed-explicit-group',
      enabled: true,
      allowedRouteIds: JSON.stringify([groupId]),
    }).run();

    const response = await app.inject({
      method: 'GET',
      url: '/v1/models',
      headers: {
        authorization: 'Bearer sk-managed-explicit-group',
      },
    });

    expect(response.statusCode).toBe(200);
    const body = response.json() as {
      object: 'list';
      data: Array<{ id: string }>;
    };

    const ids = body.data.map((item) => item.id);
    expect(ids).toContain('claude-opus-4-6');
    expect(ids).not.toContain('claude-opus-4-5');
    expect(ids).not.toContain('claude-sonnet-4-5');
  });

  it('filters search pseudo models out of /v1/models', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'search-site',
      url: 'https://search.example.com',
      platform: 'openai',
      status: 'active',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      accessToken: 'search-access-token',
      status: 'active',
    }).returning().get();

    const token = await db.insert(schema.accountTokens).values({
      accountId: account.id,
      name: 'default',
      token: 'search-api-token',
      enabled: true,
      isDefault: true,
    }).returning().get();

    await db.insert(schema.modelAvailability).values([
      {
        accountId: account.id,
        modelName: '__search',
        available: true,
      },
      {
        accountId: account.id,
        modelName: '__tavily_search',
        available: true,
      },
      {
        accountId: account.id,
        modelName: 'gpt-4.1',
        available: true,
      },
    ]).run();

    const searchRoute = await db.insert(schema.tokenRoutes).values({
      modelPattern: '__search',
      enabled: true,
    }).returning().get();

    const llmRoute = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-4.1',
      enabled: true,
    }).returning().get();

    await db.insert(schema.routeChannels).values([
      {
        routeId: searchRoute.id,
        accountId: account.id,
        tokenId: token.id,
        sourceModel: '__search',
        enabled: true,
      },
      {
        routeId: llmRoute.id,
        accountId: account.id,
        tokenId: token.id,
        sourceModel: 'gpt-4.1',
        enabled: true,
      },
    ]).run();

    await db.insert(schema.downstreamApiKeys).values({
      name: 'search-key',
      key: 'sk-search-key',
      enabled: true,
      supportedModels: JSON.stringify(['gpt-4.1']),
    }).run();

    const response = await app.inject({
      method: 'GET',
      url: '/v1/models',
      headers: {
        authorization: 'Bearer sk-search-key',
      },
    });

    expect(response.statusCode).toBe(200);
    const body = response.json() as {
      object: 'list';
      data: Array<{ id: string }>;
    };
    const ids = body.data.map((item) => item.id);
    expect(ids).toContain('gpt-4.1');
    expect(ids).not.toContain('__search');
    expect(ids).not.toContain('__tavily_search');
  });
});
