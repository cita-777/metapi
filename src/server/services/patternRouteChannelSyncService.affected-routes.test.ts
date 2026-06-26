import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { eq } from 'drizzle-orm';

type DbModule = typeof import('../db/index.js');
type PatternRouteChannelSyncServiceModule = typeof import('./patternRouteChannelSyncService.js');

describe('syncPatternRouteChannelsAfterAffectedRouteChanges', () => {
  let db: DbModule['db'];
  let schema: DbModule['schema'];
  let syncPatternRouteChannelsAfterAffectedRouteChanges: PatternRouteChannelSyncServiceModule['syncPatternRouteChannelsAfterAffectedRouteChanges'];
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

    return { account, token };
  };

  beforeAll(async () => {
    dataDir = mkdtempSync(join(tmpdir(), 'metapi-pattern-sync-affected-routes-'));
    process.env.DATA_DIR = dataDir;

    await import('../db/migrate.js');
    const dbModule = await import('../db/index.js');
    const serviceModule = await import('./patternRouteChannelSyncService.js');

    db = dbModule.db;
    schema = dbModule.schema;
    syncPatternRouteChannelsAfterAffectedRouteChanges = serviceModule.syncPatternRouteChannelsAfterAffectedRouteChanges;
  });

  beforeEach(async () => {
    await db.delete(schema.routeChannels).run();
    await db.delete(schema.routeGroupSources).run();
    await db.delete(schema.tokenRoutes).run();
    await db.delete(schema.tokenModelAvailability).run();
    await db.delete(schema.accountTokens).run();
    await db.delete(schema.accounts).run();
    await db.delete(schema.sites).run();
    seedId = 0;
  });

  afterAll(() => {
    delete process.env.DATA_DIR;
  });

  it('does not rebuild pattern routes for wildcard or explicit-group affected routes', async () => {
    const wildcardRoute = await db.insert(schema.tokenRoutes).values({
      modelPattern: 're:^gpt-5.*$',
      enabled: true,
    }).returning().get();
    const explicitGroupRoute = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-5-group',
      displayName: 'gpt-5-group',
      routeMode: 'explicit_group',
      enabled: true,
    }).returning().get();

    const result = await syncPatternRouteChannelsAfterAffectedRouteChanges({
      affectedRouteIds: [wildcardRoute.id, explicitGroupRoute.id],
      removedRoutes: [{
        modelPattern: 'gpt-5-explicit',
        routeMode: 'explicit_group',
      }],
    });

    expect(result).toEqual({
      rebuiltRoutes: 0,
      routeIds: [],
      removedChannels: 0,
      createdChannels: 0,
    });
  });

  it('rebuilds pattern route channels when an affected route id is an exact source route', async () => {
    const seeded = await seedAccountWithToken('gpt-5-mini');
    const exactRoute = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-5-mini',
      enabled: true,
    }).returning().get();
    const patternRoute = await db.insert(schema.tokenRoutes).values({
      modelPattern: 're:^gpt-5.*$',
      enabled: true,
    }).returning().get();

    await db.insert(schema.routeChannels).values({
      routeId: exactRoute.id,
      accountId: seeded.account.id,
      tokenId: seeded.token.id,
      sourceModel: 'gpt-5-mini',
      priority: 6,
      weight: 4,
      enabled: true,
      manualOverride: true,
    }).run();

    const result = await syncPatternRouteChannelsAfterAffectedRouteChanges({
      affectedRouteIds: [exactRoute.id],
    });

    expect(result.rebuiltRoutes).toBe(1);
    expect(result.createdChannels).toBe(1);
    expect(result.routeIds).toEqual([patternRoute.id]);

    const patternChannels = await db.select().from(schema.routeChannels)
      .where(eq(schema.routeChannels.routeId, patternRoute.id))
      .all();
    expect(patternChannels).toHaveLength(1);
    expect(patternChannels[0]).toMatchObject({
      accountId: seeded.account.id,
      tokenId: seeded.token.id,
      sourceModel: 'gpt-5-mini',
      priority: 6,
      weight: 4,
      manualOverride: false,
    });
  });

  it('uses removed exact route snapshots to clear stale pattern channels after deletion', async () => {
    const seeded = await seedAccountWithToken('gpt-5-removed');
    const exactRoute = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-5-removed',
      enabled: true,
    }).returning().get();
    const patternRoute = await db.insert(schema.tokenRoutes).values({
      modelPattern: 're:^gpt-5.*$',
      enabled: true,
    }).returning().get();

    await db.insert(schema.routeChannels).values({
      routeId: exactRoute.id,
      accountId: seeded.account.id,
      tokenId: seeded.token.id,
      sourceModel: 'gpt-5-removed',
      enabled: true,
      manualOverride: false,
    }).run();

    await syncPatternRouteChannelsAfterAffectedRouteChanges({
      affectedRouteIds: [exactRoute.id],
    });
    let patternChannels = await db.select().from(schema.routeChannels)
      .where(eq(schema.routeChannels.routeId, patternRoute.id))
      .all();
    expect(patternChannels.map((channel) => channel.sourceModel)).toEqual(['gpt-5-removed']);

    await db.delete(schema.tokenRoutes).where(eq(schema.tokenRoutes.id, exactRoute.id)).run();

    const result = await syncPatternRouteChannelsAfterAffectedRouteChanges({
      removedRoutes: [{
        modelPattern: exactRoute.modelPattern,
        routeMode: exactRoute.routeMode,
      }],
    });

    expect(result.rebuiltRoutes).toBe(1);
    expect(result.removedChannels).toBe(1);

    patternChannels = await db.select().from(schema.routeChannels)
      .where(eq(schema.routeChannels.routeId, patternRoute.id))
      .all();
    expect(patternChannels).toHaveLength(0);
  });
});
