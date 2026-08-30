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
    await db.delete(schema.settings).run();
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

  it('rebuilds only pattern groups matching the affected exact model', async () => {
    const gpt = await seedAccountWithToken('gpt-5-mini');
    const claude = await seedAccountWithToken('claude-3-7-sonnet');
    const exactRoute = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-5-mini',
      enabled: true,
    }).returning().get();
    const gptPatternRoute = await db.insert(schema.tokenRoutes).values({
      modelPattern: 're:^gpt-5.*$',
      enabled: true,
    }).returning().get();
    const claudePatternRoute = await db.insert(schema.tokenRoutes).values({
      modelPattern: 're:^claude-3.*$',
      enabled: true,
    }).returning().get();

    await db.insert(schema.routeChannels).values([
      {
        routeId: exactRoute.id,
        accountId: gpt.account.id,
        tokenId: gpt.token.id,
        sourceModel: 'gpt-5-mini',
        enabled: true,
        manualOverride: true,
      },
      {
        routeId: claudePatternRoute.id,
        accountId: claude.account.id,
        tokenId: claude.token.id,
        sourceModel: 'claude-3-7-sonnet',
        enabled: true,
        manualOverride: false,
      },
    ]).run();

    const result = await syncPatternRouteChannelsAfterAffectedRouteChanges({
      affectedRouteIds: [exactRoute.id],
    });

    expect(result.routeIds).toEqual([gptPatternRoute.id]);
    expect(result.rebuiltRoutes).toBe(1);

    const claudeChannels = await db.select().from(schema.routeChannels)
      .where(eq(schema.routeChannels.routeId, claudePatternRoute.id))
      .all();
    expect(claudeChannels).toHaveLength(1);
    expect(claudeChannels[0]).toMatchObject({
      sourceModel: 'claude-3-7-sonnet',
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
        enabled: true,
      }],
    });

    expect(result.rebuiltRoutes).toBe(1);
    expect(result.removedChannels).toBe(1);

    patternChannels = await db.select().from(schema.routeChannels)
      .where(eq(schema.routeChannels.routeId, patternRoute.id))
      .all();
    expect(patternChannels).toHaveLength(0);
  });

  it('keeps deleted exact models excluded during later affected-route rebuilds', async () => {
    const removed = await seedAccountWithToken('gpt-5-removed');
    const replacement = await seedAccountWithToken('gpt-5-replacement');
    const exactRemovedRoute = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-5-removed',
      enabled: true,
    }).returning().get();
    const exactReplacementRoute = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-5-replacement',
      enabled: true,
    }).returning().get();
    const patternRoute = await db.insert(schema.tokenRoutes).values({
      modelPattern: 're:^gpt-5.*$',
      enabled: true,
    }).returning().get();

    await db.insert(schema.routeChannels).values([
      {
        routeId: exactRemovedRoute.id,
        accountId: removed.account.id,
        tokenId: removed.token.id,
        sourceModel: 'gpt-5-removed',
        enabled: true,
        manualOverride: true,
      },
      {
        routeId: exactReplacementRoute.id,
        accountId: replacement.account.id,
        tokenId: replacement.token.id,
        sourceModel: 'gpt-5-replacement',
        enabled: true,
        manualOverride: true,
      },
    ]).run();

    await syncPatternRouteChannelsAfterAffectedRouteChanges({
      affectedRouteIds: [exactRemovedRoute.id],
    });
    await db.delete(schema.tokenRoutes).where(eq(schema.tokenRoutes.id, exactRemovedRoute.id)).run();
    await syncPatternRouteChannelsAfterAffectedRouteChanges({
      removedRoutes: [{
        modelPattern: 'gpt-5-removed',
        routeMode: 'pattern',
        enabled: true,
      }],
    });

    const laterResult = await syncPatternRouteChannelsAfterAffectedRouteChanges({
      affectedRouteIds: [exactReplacementRoute.id],
    });
    expect(laterResult.routeIds).toEqual([patternRoute.id]);

    const patternChannels = await db.select().from(schema.routeChannels)
      .where(eq(schema.routeChannels.routeId, patternRoute.id))
      .all();
    expect(patternChannels.map((channel) => channel.sourceModel)).toEqual(['gpt-5-replacement']);
  });

  it('does not exclude availability models when a disabled exact route is removed', async () => {
    const seeded = await seedAccountWithToken('gpt-5-disabled');
    const exactRoute = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-5-disabled',
      enabled: false,
    }).returning().get();
    const patternRoute = await db.insert(schema.tokenRoutes).values({
      modelPattern: 're:^gpt-5.*$',
      enabled: true,
    }).returning().get();

    await db.delete(schema.tokenRoutes).where(eq(schema.tokenRoutes.id, exactRoute.id)).run();

    const result = await syncPatternRouteChannelsAfterAffectedRouteChanges({
      removedRoutes: [{
        modelPattern: exactRoute.modelPattern,
        routeMode: exactRoute.routeMode,
        enabled: false,
      }],
    });

    expect(result.rebuiltRoutes).toBe(1);
    const patternChannels = await db.select().from(schema.routeChannels)
      .where(eq(schema.routeChannels.routeId, patternRoute.id))
      .all();
    expect(patternChannels).toHaveLength(1);
    expect(patternChannels[0]).toMatchObject({
      accountId: seeded.account.id,
      tokenId: seeded.token.id,
      sourceModel: 'gpt-5-disabled',
    });
  });
});
