import Fastify, { type FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { eq } from 'drizzle-orm';

type DbModule = typeof import('../../db/index.js');

describe('POST /api/routes/:id/cooldown/clear', () => {
  let app: FastifyInstance;
  let db: DbModule['db'];
  let schema: DbModule['schema'];
  let dataDir = '';
  let seedId = 0;

  const nextId = () => {
    seedId += 1;
    return seedId;
  };

  const seedAccountWithToken = async () => {
    const id = nextId();
    const site = await db.insert(schema.sites).values({
      name: `cooldown-site-${id}`,
      url: `https://cooldown-site-${id}.example.com`,
      platform: 'new-api',
      status: 'active',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: `cooldown-user-${id}`,
      accessToken: `cooldown-access-token-${id}`,
      status: 'active',
    }).returning().get();

    const token = await db.insert(schema.accountTokens).values({
      accountId: account.id,
      name: `cooldown-token-${id}`,
      token: `sk-cooldown-token-${id}`,
      enabled: true,
      isDefault: true,
    }).returning().get();

    return { site, account, token };
  };

  beforeAll(async () => {
    dataDir = mkdtempSync(join(tmpdir(), 'metapi-route-cooldown-clear-'));
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
    await db.delete(schema.routeGroupSources).run();
    await db.delete(schema.routeChannels).run();
    await db.delete(schema.tokenRoutes).run();
    await db.delete(schema.accountTokens).run();
    await db.delete(schema.accounts).run();
    await db.delete(schema.sites).run();
    seedId = 0;
  });

  afterAll(async () => {
    await app.close();
    delete process.env.DATA_DIR;
  });

  it('clears cooldown and failure counters for a direct route', async () => {
    const seeded = await seedAccountWithToken();
    const route = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-4o-mini',
      enabled: true,
    }).returning().get();

    const channel = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: seeded.account.id,
      tokenId: seeded.token.id,
      priority: 0,
      weight: 10,
      enabled: true,
      failCount: 8,
      lastFailAt: '2026-04-01T00:00:00.000Z',
      consecutiveFailCount: 2,
      cooldownLevel: 3,
      cooldownUntil: '2099-01-01T00:00:00.000Z',
    }).returning().get();

    const response = await app.inject({
      method: 'POST',
      url: `/api/routes/${route.id}/cooldown/clear`,
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      success: true,
      clearedChannels: 1,
    });

    const refreshed = await db.select().from(schema.routeChannels)
      .where(eq(schema.routeChannels.id, channel.id))
      .get();

    expect(refreshed).toMatchObject({
      failCount: 0,
      lastFailAt: null,
      consecutiveFailCount: 0,
      cooldownLevel: 0,
      cooldownUntil: null,
    });
  });

  it('clears cooldown for source-route channels exposed by explicit groups', async () => {
    const seeded = await seedAccountWithToken();
    const sourceRoute = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'claude-sonnet-4-5',
      enabled: true,
    }).returning().get();

    const groupRoute = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'claude-opus-4-6',
      displayName: 'claude-opus-4-6',
      routeMode: 'explicit_group',
      enabled: true,
    }).returning().get();

    await db.insert(schema.routeGroupSources).values({
      groupRouteId: groupRoute.id,
      sourceRouteId: sourceRoute.id,
    }).run();

    const channel = await db.insert(schema.routeChannels).values({
      routeId: sourceRoute.id,
      accountId: seeded.account.id,
      tokenId: seeded.token.id,
      sourceModel: 'claude-sonnet-4-5',
      priority: 0,
      weight: 10,
      enabled: true,
      failCount: 5,
      lastFailAt: '2026-04-01T00:00:00.000Z',
      consecutiveFailCount: 1,
      cooldownLevel: 2,
      cooldownUntil: '2099-01-01T00:00:00.000Z',
    }).returning().get();

    const response = await app.inject({
      method: 'POST',
      url: `/api/routes/${groupRoute.id}/cooldown/clear`,
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      success: true,
      clearedChannels: 1,
    });

    const refreshed = await db.select().from(schema.routeChannels)
      .where(eq(schema.routeChannels.id, channel.id))
      .get();

    expect(refreshed).toMatchObject({
      failCount: 0,
      lastFailAt: null,
      consecutiveFailCount: 0,
      cooldownLevel: 0,
      cooldownUntil: null,
    });
  });

  it('only clears cooldown for explicit-group source routes that are enabled exact routes', async () => {
    const seeded = await seedAccountWithToken();
    const visibleSourceRoute = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-5.4',
      enabled: true,
    }).returning().get();
    const disabledSourceRoute = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-4.1',
      enabled: false,
    }).returning().get();
    const wildcardSourceRoute = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-*',
      enabled: true,
    }).returning().get();

    const groupRoute = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-clear-group',
      displayName: 'gpt-clear-group',
      routeMode: 'explicit_group',
      enabled: true,
    }).returning().get();

    await db.insert(schema.routeGroupSources).values([
      { groupRouteId: groupRoute.id, sourceRouteId: visibleSourceRoute.id },
      { groupRouteId: groupRoute.id, sourceRouteId: disabledSourceRoute.id },
      { groupRouteId: groupRoute.id, sourceRouteId: wildcardSourceRoute.id },
    ]).run();

    const visibleChannel = await db.insert(schema.routeChannels).values({
      routeId: visibleSourceRoute.id,
      accountId: seeded.account.id,
      tokenId: seeded.token.id,
      priority: 0,
      weight: 10,
      enabled: true,
      failCount: 4,
      lastFailAt: '2026-04-01T00:00:00.000Z',
      consecutiveFailCount: 1,
      cooldownLevel: 2,
      cooldownUntil: '2099-01-01T00:00:00.000Z',
    }).returning().get();
    const disabledChannel = await db.insert(schema.routeChannels).values({
      routeId: disabledSourceRoute.id,
      accountId: seeded.account.id,
      tokenId: seeded.token.id,
      priority: 0,
      weight: 10,
      enabled: true,
      failCount: 6,
      lastFailAt: '2026-04-01T00:00:00.000Z',
      consecutiveFailCount: 2,
      cooldownLevel: 3,
      cooldownUntil: '2099-01-01T00:00:00.000Z',
    }).returning().get();
    const wildcardChannel = await db.insert(schema.routeChannels).values({
      routeId: wildcardSourceRoute.id,
      accountId: seeded.account.id,
      tokenId: seeded.token.id,
      priority: 0,
      weight: 10,
      enabled: true,
      failCount: 7,
      lastFailAt: '2026-04-01T00:00:00.000Z',
      consecutiveFailCount: 2,
      cooldownLevel: 3,
      cooldownUntil: '2099-01-01T00:00:00.000Z',
    }).returning().get();

    const response = await app.inject({
      method: 'POST',
      url: `/api/routes/${groupRoute.id}/cooldown/clear`,
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      success: true,
      clearedChannels: 1,
    });

    const refreshedVisible = await db.select().from(schema.routeChannels)
      .where(eq(schema.routeChannels.id, visibleChannel.id))
      .get();
    const refreshedDisabled = await db.select().from(schema.routeChannels)
      .where(eq(schema.routeChannels.id, disabledChannel.id))
      .get();
    const refreshedWildcard = await db.select().from(schema.routeChannels)
      .where(eq(schema.routeChannels.id, wildcardChannel.id))
      .get();

    expect(refreshedVisible).toMatchObject({
      failCount: 0,
      lastFailAt: null,
      consecutiveFailCount: 0,
      cooldownLevel: 0,
      cooldownUntil: null,
    });
    expect(refreshedDisabled?.cooldownUntil).toBe('2099-01-01T00:00:00.000Z');
    expect(refreshedWildcard?.cooldownUntil).toBe('2099-01-01T00:00:00.000Z');
  });
});
