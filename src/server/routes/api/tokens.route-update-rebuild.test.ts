import Fastify, { type FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { eq } from 'drizzle-orm';

type DbModule = typeof import('../../db/index.js');

describe('PUT /api/routes/:id route rebuild', () => {
  let app: FastifyInstance;
  let db: DbModule['db'];
  let schema: DbModule['schema'];
  let dataDir = '';
  let seedId = 0;

  const nextId = () => {
    seedId += 1;
    return seedId;
  };

  const seedAccountWithToken = async (modelName: string) => {
    const id = nextId();
    const site = await db.insert(schema.sites).values({
      name: `site-${id}`,
      url: `https://example.com/${id}`,
      platform: 'new-api',
      status: 'active',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: `user-${id}`,
      accessToken: `access-${id}`,
      status: 'active',
    }).returning().get();

    const token = await db.insert(schema.accountTokens).values({
      accountId: account.id,
      name: `token-${id}`,
      token: `sk-token-${id}`,
      enabled: true,
      isDefault: true,
    }).returning().get();

    await db.insert(schema.tokenModelAvailability).values({
      tokenId: token.id,
      modelName,
      available: true,
    }).run();

    return { site, account, token };
  };

  beforeAll(async () => {
    dataDir = mkdtempSync(join(tmpdir(), 'metapi-route-update-rebuild-'));
    process.env.DATA_DIR = dataDir;

    await import('../../db/migrate.js');
    const dbModule = await import('../../db/index.js');
    const routesModule = await import('./tokens.js');
    db = dbModule.db;
    schema = dbModule.schema;

    app = Fastify();
    await app.register(routesModule.tokensRoutes);
  });

  beforeEach(async () => {
    await db.delete(schema.routeChannels).run();
    await db.delete(schema.tokenRoutes).run();
    await db.delete(schema.tokenModelAvailability).run();
    await db.delete(schema.modelAvailability).run();
    await db.delete(schema.accountTokens).run();
    await db.delete(schema.accounts).run();
    await db.delete(schema.sites).run();
    seedId = 0;
  });

  afterAll(async () => {
    await app.close();
    delete process.env.DATA_DIR;
  });

  it('rebuilds only automatic channels when modelPattern changes', async () => {
    const oldCandidate = await seedAccountWithToken('claude-opus-4-5');
    const newCandidate = await seedAccountWithToken('gemini-2.0-flash');
    const manualCandidate = await seedAccountWithToken('manual-special');

    const route = await db.insert(schema.tokenRoutes).values({
      modelPattern: 're:^claude-.*$',
      displayName: 'old-group',
      enabled: true,
    }).returning().get();

    const autoChannel = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: oldCandidate.account.id,
      tokenId: oldCandidate.token.id,
      sourceModel: 'claude-opus-4-5',
      priority: 0,
      weight: 10,
      enabled: true,
      manualOverride: false,
    }).returning().get();

    const manualChannel = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: manualCandidate.account.id,
      tokenId: manualCandidate.token.id,
      sourceModel: 'manual-special',
      priority: 7,
      weight: 3,
      enabled: true,
      manualOverride: true,
    }).returning().get();

    const response = await app.inject({
      method: 'PUT',
      url: `/api/routes/${route.id}`,
      payload: {
        modelPattern: 're:^gemini-.*$',
        displayName: 'new-group',
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      id: route.id,
      modelPattern: 're:^gemini-.*$',
      displayName: 'new-group',
    });

    const routeChannels = await db.select().from(schema.routeChannels)
      .where(eq(schema.routeChannels.routeId, route.id))
      .all();

    expect(routeChannels.some((channel) => channel.id === manualChannel.id)).toBe(true);
    expect(routeChannels.some((channel) => channel.id === autoChannel.id)).toBe(false);

    const rebuiltAuto = routeChannels.find((channel) =>
      channel.accountId === newCandidate.account.id
      && channel.tokenId === newCandidate.token.id
      && channel.sourceModel === 'gemini-2.0-flash',
    );

    expect(rebuiltAuto).toBeDefined();
    expect(rebuiltAuto?.manualOverride).toBe(false);
    expect(rebuiltAuto?.priority).toBe(0);
    expect(rebuiltAuto?.weight).toBe(10);
  });

  it('creates explicit-group routes with sourceRouteIds and aggregates source channels', async () => {
    const sourceA = await seedAccountWithToken('claude-opus-4-5');
    const sourceB = await seedAccountWithToken('claude-sonnet-4-5');

    const exactRouteA = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'claude-opus-4-5',
      enabled: true,
    }).returning().get();
    const exactRouteB = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'claude-sonnet-4-5',
      enabled: true,
    }).returning().get();

    await db.insert(schema.routeChannels).values([
      {
        routeId: exactRouteA.id,
        accountId: sourceA.account.id,
        tokenId: sourceA.token.id,
        sourceModel: 'claude-opus-4-5',
        priority: 0,
        weight: 10,
        enabled: true,
        manualOverride: false,
      },
      {
        routeId: exactRouteB.id,
        accountId: sourceB.account.id,
        tokenId: sourceB.token.id,
        sourceModel: 'claude-sonnet-4-5',
        priority: 1,
        weight: 8,
        enabled: true,
        manualOverride: false,
      },
    ]).run();

    const createResponse = await app.inject({
      method: 'POST',
      url: '/api/routes',
      payload: {
        routeMode: 'explicit_group',
        displayName: 'claude-opus-4-6',
        sourceRouteIds: [exactRouteA.id, exactRouteB.id],
        routingStrategy: 'weighted',
      },
    });

    expect(createResponse.statusCode).toBe(200);
    expect(createResponse.json()).toMatchObject({
      displayName: 'claude-opus-4-6',
      routeMode: 'explicit_group',
      sourceRouteIds: [exactRouteA.id, exactRouteB.id],
    });

    const createdRouteId = (createResponse.json() as { id: number }).id;

    const storedChannels = await db.select().from(schema.routeChannels)
      .where(eq(schema.routeChannels.routeId, createdRouteId))
      .all();
    expect(storedChannels).toHaveLength(0);

    const summaryResponse = await app.inject({
      method: 'GET',
      url: '/api/routes/summary',
    });
    expect(summaryResponse.statusCode).toBe(200);
    expect(summaryResponse.json()).toContainEqual(expect.objectContaining({
      id: createdRouteId,
      routeMode: 'explicit_group',
      sourceRouteIds: [exactRouteA.id, exactRouteB.id],
      channelCount: 2,
      enabledChannelCount: 2,
      siteNames: expect.arrayContaining([sourceA.site.name, sourceB.site.name]),
    }));

    const channelsResponse = await app.inject({
      method: 'GET',
      url: `/api/routes/${createdRouteId}/channels`,
    });
    expect(channelsResponse.statusCode).toBe(200);
    expect(channelsResponse.json()).toEqual(expect.arrayContaining([
      expect.objectContaining({
        routeId: exactRouteA.id,
        accountId: sourceA.account.id,
        sourceModel: 'claude-opus-4-5',
      }),
      expect.objectContaining({
        routeId: exactRouteB.id,
        accountId: sourceB.account.id,
        sourceModel: 'claude-sonnet-4-5',
      }),
    ]));
  });

  it('fills missing sourceModel from source exact routes when loading explicit-group channels', async () => {
    const sourceA = await seedAccountWithToken('deepseek-chat');
    const sourceB = await seedAccountWithToken('deepseek-reasoner');

    const exactRouteA = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'deepseek-chat',
      enabled: true,
    }).returning().get();
    const exactRouteB = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'deepseek-reasoner',
      enabled: true,
    }).returning().get();

    await db.insert(schema.routeChannels).values([
      {
        routeId: exactRouteA.id,
        accountId: sourceA.account.id,
        tokenId: sourceA.token.id,
        sourceModel: null,
        priority: 0,
        weight: 10,
        enabled: true,
        manualOverride: false,
      },
      {
        routeId: exactRouteB.id,
        accountId: sourceB.account.id,
        tokenId: sourceB.token.id,
        sourceModel: null,
        priority: 1,
        weight: 8,
        enabled: true,
        manualOverride: false,
      },
    ]).run();

    const createResponse = await app.inject({
      method: 'POST',
      url: '/api/routes',
      payload: {
        routeMode: 'explicit_group',
        displayName: 'deepseekv1',
        sourceRouteIds: [exactRouteA.id, exactRouteB.id],
      },
    });

    expect(createResponse.statusCode).toBe(200);
    const createdRouteId = (createResponse.json() as { id: number }).id;

    const channelsResponse = await app.inject({
      method: 'GET',
      url: `/api/routes/${createdRouteId}/channels`,
    });

    expect(channelsResponse.statusCode).toBe(200);
    expect(channelsResponse.json()).toEqual(expect.arrayContaining([
      expect.objectContaining({
        routeId: exactRouteA.id,
        accountId: sourceA.account.id,
        sourceModel: 'deepseek-chat',
      }),
      expect.objectContaining({
        routeId: exactRouteB.id,
        accountId: sourceB.account.id,
        sourceModel: 'deepseek-reasoner',
      }),
    ]));
  });

  it('rejects invalid explicit-group payloads', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/routes',
      payload: {
        routeMode: 'explicit_group',
        displayName: '',
        sourceRouteIds: [],
      },
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({
      success: false,
    });
  });

  it('prefers an exact route over a colliding explicit-group display name', async () => {
    const exactCandidate = await seedAccountWithToken('claude-opus-4-6');
    const groupedCandidate = await seedAccountWithToken('claude-opus-4-5');

    const exactRoute = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'claude-opus-4-6',
      enabled: true,
    }).returning().get();
    const sourceRoute = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'claude-opus-4-5',
      enabled: true,
    }).returning().get();

    await db.insert(schema.routeChannels).values([
      {
        routeId: exactRoute.id,
        accountId: exactCandidate.account.id,
        tokenId: exactCandidate.token.id,
        sourceModel: 'claude-opus-4-6',
        priority: 0,
        weight: 10,
        enabled: true,
        manualOverride: false,
      },
      {
        routeId: sourceRoute.id,
        accountId: groupedCandidate.account.id,
        tokenId: groupedCandidate.token.id,
        sourceModel: 'claude-opus-4-5',
        priority: 0,
        weight: 10,
        enabled: true,
        manualOverride: false,
      },
    ]).run();

    const groupResponse = await app.inject({
      method: 'POST',
      url: '/api/routes',
      payload: {
        routeMode: 'explicit_group',
        displayName: 'claude-opus-4-6',
        sourceRouteIds: [sourceRoute.id],
      },
    });

    expect(groupResponse.statusCode).toBe(200);

    const decisionResponse = await app.inject({
      method: 'GET',
      url: '/api/routes/decision?model=claude-opus-4-6',
    });

    expect(decisionResponse.statusCode).toBe(200);
    expect(decisionResponse.json()).toMatchObject({
      success: true,
      decision: {
        matched: true,
        routeId: exactRoute.id,
        modelPattern: 'claude-opus-4-6',
        actualModel: 'claude-opus-4-6',
      },
    });
  });
});
