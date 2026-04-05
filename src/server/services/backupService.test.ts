import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { asc, eq } from 'drizzle-orm';

type DbModule = typeof import('../db/index.js');
type BackupServiceModule = typeof import('./backupService.js');

describe('backupService', () => {
  let db: DbModule['db'];
  let schema: DbModule['schema'];
  let backupService: BackupServiceModule;
  let dataDir = '';

  beforeAll(async () => {
    dataDir = mkdtempSync(join(tmpdir(), 'metapi-backup-service-'));
    process.env.DATA_DIR = dataDir;

    await import('../db/migrate.js');
    const dbModule = await import('../db/index.js');
    const serviceModule = await import('./backupService.js');

    db = dbModule.db;
    schema = dbModule.schema;
    backupService = serviceModule;
  });

  beforeEach(async () => {
    await db.delete(schema.routeChannels).run();
    await db.delete(schema.routeGroupSources).run();
    await db.delete(schema.tokenRoutes).run();
    await db.delete(schema.tokenModelAvailability).run();
    await db.delete(schema.modelAvailability).run();
    await db.delete(schema.proxyLogs).run();
    await db.delete(schema.checkinLogs).run();
    await db.delete(schema.siteAnnouncements).run();
    await db.delete(schema.siteDisabledModels).run();
    await db.delete(schema.accountTokens).run();
    await db.delete(schema.accounts).run();
    await db.delete(schema.sites).run();
    await db.delete(schema.downstreamApiKeys).run();
    await db.delete(schema.proxyFiles).run();
    await db.delete(schema.proxyVideoTasks).run();
    await db.delete(schema.events).run();
    await db.delete(schema.settings).run();
  });

  afterAll(() => {
    delete process.env.DATA_DIR;
  });

  it('exports backup-owned config in v2.1 backups and still roundtrips core connection fields', async () => {
    const now = new Date().toISOString();
    const site = await db.insert(schema.sites).values({
      name: 'roundtrip-site',
      url: 'https://roundtrip.example.com',
      platform: 'new-api',
      externalCheckinUrl: 'https://checkin.roundtrip.example.com',
      proxyUrl: 'http://127.0.0.1:8080',
      useSystemProxy: true,
      customHeaders: JSON.stringify({
        'cf-access-client-id': 'roundtrip-client',
      }),
      status: 'active',
      isPinned: true,
      sortOrder: 9,
      apiKey: 'site-api-key',
      createdAt: now,
      updatedAt: now,
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'roundtrip-user',
      accessToken: 'session-token',
      apiToken: 'api-token',
      oauthProvider: 'codex',
      oauthAccountKey: 'roundtrip-account-key',
      oauthProjectId: 'roundtrip-project-id',
      balance: 12.3,
      balanceUsed: 4.5,
      quota: 99.9,
      unitCost: 0.2,
      valueScore: 1.1,
      status: 'active',
      isPinned: true,
      sortOrder: 7,
      checkinEnabled: true,
      extraConfig: JSON.stringify({ platformUserId: 123 }),
      createdAt: now,
      updatedAt: now,
    }).returning().get();

    const accountToken = await db.insert(schema.accountTokens).values({
      accountId: account.id,
      name: 'default',
      token: 'sk-roundtrip-token',
      source: 'manual',
      enabled: true,
      isDefault: true,
      createdAt: now,
      updatedAt: now,
    }).returning().get();

    const sourceRoute = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-source-*',
      displayName: 'gpt-source',
      routeMode: 'pattern',
      enabled: true,
      createdAt: now,
      updatedAt: now,
    }).returning().get();

    const route = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-*',
      displayName: 'gpt-route',
      displayIcon: 'icon-gpt',
      modelMapping: JSON.stringify({ to: 'gpt-4o-mini' }),
      routeMode: 'explicit_group',
      decisionSnapshot: JSON.stringify({ channelIds: [1, 2] }),
      decisionRefreshedAt: now,
      routingStrategy: 'round_robin',
      enabled: true,
      createdAt: now,
      updatedAt: now,
    }).returning().get();

    await db.insert(schema.routeGroupSources).values({
      groupRouteId: route.id,
      sourceRouteId: sourceRoute.id,
    }).run();

    await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: account.id,
      tokenId: accountToken.id,
      sourceModel: 'gpt-4o',
      priority: 3,
      weight: 5,
      enabled: true,
      manualOverride: false,
      successCount: 10,
      failCount: 1,
      totalLatencyMs: 2500,
      totalCost: 2.5,
      lastUsedAt: now,
      lastFailAt: now,
      cooldownUntil: now,
    }).run();

    await db.insert(schema.siteDisabledModels).values({
      siteId: site.id,
      modelName: 'gpt-hidden',
      createdAt: now,
    }).run();

    await db.insert(schema.siteApiEndpoints).values({
      siteId: site.id,
      url: 'https://api-roundtrip.example.com',
      enabled: true,
      sortOrder: 0,
      cooldownUntil: null,
      lastSelectedAt: now,
      lastFailedAt: null,
      lastFailureReason: null,
      createdAt: now,
      updatedAt: now,
    }).run();

    await db.insert(schema.modelAvailability).values([
      {
        accountId: account.id,
        modelName: 'gpt-manual',
        available: true,
        isManual: true,
        latencyMs: null,
        checkedAt: now,
      },
      {
        accountId: account.id,
        modelName: 'gpt-discovered',
        available: true,
        isManual: false,
        latencyMs: 42,
        checkedAt: now,
      },
    ]).run();

    await db.insert(schema.downstreamApiKeys).values({
      name: 'Shared Downstream',
      key: 'downstream-roundtrip-key',
      description: 'shared quota',
      groupName: 'team-a',
      tags: '["prod"]',
      enabled: false,
      expiresAt: now,
      maxCost: 100,
      usedCost: 11.5,
      maxRequests: 500,
      usedRequests: 33,
      supportedModels: '["gpt-4o-mini"]',
      allowedRouteIds: `[${route.id}]`,
      siteWeightMultipliers: `{"${site.id}":1.5}`,
      excludedSiteIds: `[${site.id}]`,
      excludedCredentialRefs: JSON.stringify([
        { kind: 'account_token', siteId: site.id, accountId: account.id, tokenId: accountToken.id },
      ]),
      lastUsedAt: now,
      createdAt: now,
      updatedAt: now,
    }).run();

    const exported = await backupService.exportBackup('all') as any;
    expect(exported.version).toBe('2.1');
    expect(exported.accounts.siteDisabledModels).toEqual([
      { siteId: site.id, modelName: 'gpt-hidden' },
    ]);
    expect(exported.accounts.siteApiEndpoints).toEqual([
      expect.objectContaining({
        siteId: site.id,
        url: 'https://api-roundtrip.example.com',
        enabled: true,
        sortOrder: 0,
        cooldownUntil: null,
      }),
    ]);
    expect(exported.accounts.manualModels).toEqual([
      { accountId: account.id, modelName: 'gpt-manual' },
    ]);
    expect(exported.accounts.downstreamApiKeys).toEqual([
      expect.objectContaining({
        name: 'Shared Downstream',
        key: 'downstream-roundtrip-key',
        description: 'shared quota',
        groupName: 'team-a',
        tags: '["prod"]',
        enabled: false,
        expiresAt: now,
        maxCost: 100,
        maxRequests: 500,
        supportedModels: '["gpt-4o-mini"]',
        allowedRouteIds: `[${route.id}]`,
        siteWeightMultipliers: `{"${site.id}":1.5}`,
        excludedSiteIds: `[${site.id}]`,
        excludedCredentialRefs: `[{"kind":"account_token","siteId":${site.id},"accountId":${account.id},"tokenId":${accountToken.id}}]`,
      }),
    ]);
    expect(exported.accounts.accounts[0]).not.toHaveProperty('balanceUsed');
    expect(exported.accounts.accounts[0]).not.toHaveProperty('lastCheckinAt');
    expect(exported.accounts.accounts[0]).not.toHaveProperty('lastBalanceRefresh');
    expect(exported.accounts.routeChannels[0]).not.toHaveProperty('successCount');
    expect(exported.accounts.routeChannels[0]).not.toHaveProperty('lastUsedAt');
    expect(exported.accounts.downstreamApiKeys[0]).not.toHaveProperty('usedCost');
    expect(exported.accounts.downstreamApiKeys[0]).not.toHaveProperty('usedRequests');
    expect(exported.accounts.downstreamApiKeys[0]).not.toHaveProperty('lastUsedAt');

    const result = await backupService.importBackup(exported as Record<string, unknown>);

    expect(result.allImported).toBe(true);
    expect(result.sections.accounts).toBe(true);
    expect(result.summary).toBeUndefined();
    expect(result.warnings).toBeUndefined();

    const restoredSite = await db.select().from(schema.sites).where(eq(schema.sites.id, site.id)).get();
    const restoredAccount = await db.select().from(schema.accounts).where(eq(schema.accounts.id, account.id)).get();
    const restoredRoute = await db.select().from(schema.tokenRoutes).where(eq(schema.tokenRoutes.id, route.id)).get();
    const restoredChannel = await db.select().from(schema.routeChannels).where(eq(schema.routeChannels.routeId, route.id)).get();
    const restoredDisabledModels = await db.select().from(schema.siteDisabledModels).all();
    const restoredModelAvailability = await db.select().from(schema.modelAvailability).all();
    const restoredDownstreamKeys = await db.select().from(schema.downstreamApiKeys).all();

    expect(restoredSite?.proxyUrl).toBe('http://127.0.0.1:8080');
    expect(restoredSite?.externalCheckinUrl).toBe('https://checkin.roundtrip.example.com');
    expect(restoredSite?.useSystemProxy).toBe(true);
    expect(restoredSite?.customHeaders).toBe('{"cf-access-client-id":"roundtrip-client"}');
    expect(restoredSite?.isPinned).toBe(true);
    expect(restoredSite?.sortOrder).toBe(9);

    expect(restoredAccount?.isPinned).toBe(true);
    expect(restoredAccount?.sortOrder).toBe(7);
    expect(restoredAccount?.oauthProvider).toBe('codex');
    expect(restoredAccount?.oauthAccountKey).toBe('roundtrip-account-key');
    expect(restoredAccount?.oauthProjectId).toBe('roundtrip-project-id');

    expect(restoredRoute?.displayName).toBe('gpt-route');
    expect(restoredRoute?.displayIcon).toBe('icon-gpt');
    expect(restoredRoute?.routeMode).toBe('explicit_group');
    expect(restoredRoute?.decisionSnapshot).toBe('{"channelIds":[1,2]}');
    expect(restoredRoute?.decisionRefreshedAt).toBe(now);
    expect(restoredRoute?.routingStrategy).toBe('round_robin');
    const restoredGroupSource = await db.select().from(schema.routeGroupSources).where(eq(schema.routeGroupSources.groupRouteId, route.id)).get();
    expect(restoredGroupSource?.sourceRouteId).toBe(sourceRoute.id);

    expect(restoredChannel?.sourceModel).toBe('gpt-4o');
    expect(restoredDisabledModels).toEqual([
      expect.objectContaining({ siteId: site.id, modelName: 'gpt-hidden' }),
    ]);
    expect(restoredModelAvailability.some((row) => row.modelName === 'gpt-manual' && row.isManual)).toBe(true);
    expect(restoredModelAvailability.some((row) => row.modelName === 'gpt-discovered' && !row.isManual)).toBe(true);
    expect(restoredDownstreamKeys).toEqual([
      expect.objectContaining({
        name: 'Shared Downstream',
        key: 'downstream-roundtrip-key',
        description: 'shared quota',
        groupName: 'team-a',
        tags: '["prod"]',
        enabled: false,
        maxCost: 100,
        usedCost: 11.5,
        maxRequests: 500,
        usedRequests: 33,
        supportedModels: '["gpt-4o-mini"]',
        allowedRouteIds: `[${route.id}]`,
        siteWeightMultipliers: `{"${site.id}":1.5}`,
        excludedSiteIds: `[${site.id}]`,
        excludedCredentialRefs: `[{"kind":"account_token","siteId":${site.id},"accountId":${account.id},"tokenId":${accountToken.id}}]`,
        lastUsedAt: now,
      }),
    ]);
  });

  it('does not export runtime database config in preferences backups', async () => {
    await db.insert(schema.settings).values([
      { key: 'db_type', value: JSON.stringify('postgres') },
      { key: 'db_url', value: JSON.stringify('postgres://metapi:secret@db.example.com:5432/metapi') },
      { key: 'db_ssl', value: JSON.stringify(true) },
      { key: 'routing_fallback_unit_cost', value: JSON.stringify(0.25) },
    ]).run();

    const exported = await backupService.exportBackup('preferences') as any;
    const exportedSettingKeys = exported.preferences.settings.map((row: { key: string }) => row.key);

    expect(exportedSettingKeys).toContain('routing_fallback_unit_cost');
    expect(exportedSettingKeys).not.toContain('db_type');
    expect(exportedSettingKeys).not.toContain('db_url');
    expect(exportedSettingKeys).not.toContain('db_ssl');
  });

  it('ignores imported runtime database config settings', async () => {
    const result = await backupService.importBackup({
      version: '2.1',
      timestamp: Date.now(),
      type: 'preferences',
      preferences: {
        settings: [
          { key: 'db_type', value: 'postgres' },
          { key: 'db_url', value: 'postgres://metapi:secret@db.example.com:5432/metapi' },
          { key: 'db_ssl', value: true },
          { key: 'routing_fallback_unit_cost', value: 0.25 },
        ],
      },
    });

    expect(result.sections.preferences).toBe(true);
    expect(result.appliedSettings).toEqual([
      { key: 'routing_fallback_unit_cost', value: 0.25 },
    ]);

    const settingsRows = await db.select().from(schema.settings).all();
    const savedKeys = settingsRows.map((row) => row.key);

    expect(savedKeys).toContain('routing_fallback_unit_cost');
    expect(savedKeys).not.toContain('db_type');
    expect(savedKeys).not.toContain('db_url');
    expect(savedKeys).not.toContain('db_ssl');
  });

  it('preserves local logs and runtime stats when importing account backups', async () => {
    const exportedAt = '2026-03-20T09:00:00.000Z';
    const localRuntimeAt = '2026-03-21T10:30:00.000Z';
    const site = await db.insert(schema.sites).values({
      name: 'backup-site',
      url: 'https://preserve.example.com',
      platform: 'new-api',
      status: 'active',
      createdAt: exportedAt,
      updatedAt: exportedAt,
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'preserve-user',
      accessToken: 'session-token',
      apiToken: 'api-token',
      balance: 20,
      balanceUsed: 3,
      quota: 100,
      status: 'active',
      checkinEnabled: true,
      createdAt: exportedAt,
      updatedAt: exportedAt,
    }).returning().get();

    const accountToken = await db.insert(schema.accountTokens).values({
      accountId: account.id,
      name: 'default',
      token: 'sk-preserve-token',
      source: 'manual',
      enabled: true,
      isDefault: true,
      createdAt: exportedAt,
      updatedAt: exportedAt,
    }).returning().get();

    const route = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-preserve-*',
      displayName: 'backup-route',
      modelMapping: JSON.stringify({ to: 'gpt-4o-mini' }),
      routeMode: 'pattern',
      routingStrategy: 'weighted',
      enabled: true,
      createdAt: exportedAt,
      updatedAt: exportedAt,
    }).returning().get();

    await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: account.id,
      tokenId: accountToken.id,
      sourceModel: 'gpt-4o',
      priority: 1,
      weight: 10,
      enabled: true,
      manualOverride: false,
      successCount: 1,
      failCount: 0,
      totalLatencyMs: 200,
      totalCost: 0.5,
      lastUsedAt: exportedAt,
      lastSelectedAt: exportedAt,
      lastFailAt: null,
      consecutiveFailCount: 0,
      cooldownLevel: 0,
      cooldownUntil: null,
    }).run();

    const insertedChannel = await db.select()
      .from(schema.routeChannels)
      .where(eq(schema.routeChannels.routeId, route.id))
      .get();

    expect(insertedChannel).toBeTruthy();

    const exported = await backupService.exportBackup('all');

    await db.update(schema.sites).set({
      name: 'mutated-local-site',
      updatedAt: localRuntimeAt,
    }).where(eq(schema.sites.id, site.id)).run();

    await db.update(schema.tokenRoutes).set({
      displayName: 'mutated-local-route',
      updatedAt: localRuntimeAt,
    }).where(eq(schema.tokenRoutes.id, route.id)).run();

    await db.update(schema.accounts).set({
      balanceUsed: 88,
      updatedAt: localRuntimeAt,
    }).where(eq(schema.accounts.id, account.id)).run();

    await db.update(schema.routeChannels).set({
      successCount: 77,
      failCount: 9,
      totalLatencyMs: 4321,
      totalCost: 7.89,
      lastUsedAt: localRuntimeAt,
      lastSelectedAt: localRuntimeAt,
      lastFailAt: localRuntimeAt,
      consecutiveFailCount: 4,
      cooldownLevel: 2,
      cooldownUntil: localRuntimeAt,
    }).where(eq(schema.routeChannels.id, insertedChannel!.id)).run();

    await db.insert(schema.checkinLogs).values({
      accountId: account.id,
      status: 'success',
      message: 'local-checkin',
      reward: '1.5',
      createdAt: localRuntimeAt,
    }).run();

    await db.insert(schema.proxyLogs).values({
      routeId: route.id,
      channelId: insertedChannel!.id,
      accountId: account.id,
      modelRequested: 'gpt-4o',
      modelActual: 'gpt-4o',
      status: 'success',
      totalTokens: 321,
      estimatedCost: 0.123,
      createdAt: localRuntimeAt,
    }).run();

    const result = await backupService.importBackup(exported as unknown as Record<string, unknown>);

    expect(result.allImported).toBe(true);
    expect(result.sections.accounts).toBe(true);

    const restoredSite = await db.select().from(schema.sites).where(eq(schema.sites.id, site.id)).get();
    const restoredAccount = await db.select().from(schema.accounts).where(eq(schema.accounts.id, account.id)).get();
    const restoredRoute = await db.select().from(schema.tokenRoutes).where(eq(schema.tokenRoutes.id, route.id)).get();
    const restoredChannel = await db.select().from(schema.routeChannels).where(eq(schema.routeChannels.id, insertedChannel!.id)).get();
    const restoredProxyLogs = await db.select().from(schema.proxyLogs).all();
    const restoredCheckinLogs = await db.select().from(schema.checkinLogs).all();

    expect(restoredSite?.name).toBe('backup-site');
    expect(restoredRoute?.displayName).toBe('backup-route');
    expect(restoredAccount?.balanceUsed).toBe(88);
    expect(restoredChannel?.successCount).toBe(77);
    expect(restoredChannel?.failCount).toBe(9);
    expect(restoredChannel?.totalLatencyMs).toBe(4321);
    expect(restoredChannel?.totalCost).toBe(7.89);
    expect(restoredChannel?.lastUsedAt).toBe(localRuntimeAt);
    expect(restoredChannel?.lastSelectedAt).toBe(localRuntimeAt);
    expect(restoredChannel?.lastFailAt).toBe(localRuntimeAt);
    expect(restoredChannel?.consecutiveFailCount).toBe(4);
    expect(restoredChannel?.cooldownLevel).toBe(2);
    expect(restoredChannel?.cooldownUntil).toBe(localRuntimeAt);
    expect(restoredProxyLogs).toHaveLength(1);
    expect(restoredProxyLogs[0]?.accountId).toBe(account.id);
    expect(restoredProxyLogs[0]?.routeId).toBe(route.id);
    expect(restoredProxyLogs[0]?.channelId).toBe(insertedChannel!.id);
    expect(restoredProxyLogs[0]?.totalTokens).toBe(321);
    expect(restoredCheckinLogs).toHaveLength(1);
    expect(restoredCheckinLogs[0]?.accountId).toBe(account.id);
    expect(restoredCheckinLogs[0]?.message).toBe('local-checkin');
  });

  it('preserves local-only state while replacing backup-owned config during account imports', async () => {
    const exportedAt = '2026-03-20T09:00:00.000Z';
    const localRuntimeAt = '2026-03-21T10:30:00.000Z';
    const site = await db.insert(schema.sites).values({
      name: 'backup-site',
      url: 'https://preserve-local-state.example.com',
      platform: 'new-api',
      status: 'active',
      createdAt: exportedAt,
      updatedAt: exportedAt,
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'preserve-user',
      accessToken: 'session-token',
      apiToken: 'api-token',
      balance: 20,
      balanceUsed: 3,
      quota: 100,
      status: 'active',
      checkinEnabled: true,
      createdAt: exportedAt,
      updatedAt: exportedAt,
    }).returning().get();

    const accountToken = await db.insert(schema.accountTokens).values({
      accountId: account.id,
      name: 'default',
      token: 'sk-preserve-token',
      source: 'manual',
      enabled: true,
      isDefault: true,
      createdAt: exportedAt,
      updatedAt: exportedAt,
    }).returning().get();

    const route = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-preserve-*',
      displayName: 'backup-route',
      modelMapping: JSON.stringify({ to: 'gpt-4o-mini' }),
      routeMode: 'pattern',
      routingStrategy: 'weighted',
      enabled: true,
      createdAt: exportedAt,
      updatedAt: exportedAt,
    }).returning().get();

    await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: account.id,
      tokenId: accountToken.id,
      sourceModel: 'gpt-4o',
      priority: 1,
      weight: 10,
      enabled: true,
      manualOverride: false,
      successCount: 1,
      failCount: 0,
      totalLatencyMs: 200,
      totalCost: 0.5,
      lastUsedAt: exportedAt,
      lastSelectedAt: exportedAt,
      lastFailAt: null,
      consecutiveFailCount: 0,
      cooldownLevel: 0,
      cooldownUntil: null,
    }).run();

    const insertedChannel = await db.select()
      .from(schema.routeChannels)
      .where(eq(schema.routeChannels.routeId, route.id))
      .get();

    expect(insertedChannel).toBeTruthy();

    await db.insert(schema.siteDisabledModels).values({
      siteId: site.id,
      modelName: 'gpt-backup-disabled',
      createdAt: exportedAt,
    }).run();

    await db.insert(schema.siteApiEndpoints).values([
      {
        siteId: site.id,
        url: 'https://api-a.example.com',
        enabled: true,
        sortOrder: 0,
        cooldownUntil: null,
        lastSelectedAt: exportedAt,
        lastFailedAt: null,
        lastFailureReason: null,
        createdAt: exportedAt,
        updatedAt: exportedAt,
      },
      {
        siteId: site.id,
        url: 'https://api-b.example.com',
        enabled: false,
        sortOrder: 1,
        cooldownUntil: exportedAt,
        lastSelectedAt: null,
        lastFailedAt: exportedAt,
        lastFailureReason: 'HTTP 429',
        createdAt: exportedAt,
        updatedAt: exportedAt,
      },
    ]).run();

    await db.insert(schema.modelAvailability).values([
      {
        accountId: account.id,
        modelName: 'gpt-backup-manual',
        available: true,
        isManual: true,
        latencyMs: null,
        checkedAt: exportedAt,
      },
      {
        accountId: account.id,
        modelName: 'gpt-cached',
        available: false,
        isManual: false,
        latencyMs: 50,
        checkedAt: exportedAt,
      },
    ]).run();

    await db.insert(schema.tokenModelAvailability).values({
      tokenId: accountToken.id,
      modelName: 'gpt-token-cache',
      available: false,
      latencyMs: 33,
      checkedAt: exportedAt,
    }).run();

    await db.insert(schema.siteAnnouncements).values({
      siteId: site.id,
      platform: 'new-api',
      sourceKey: 'notice-1',
      title: 'Backup banner',
      content: 'Backup content',
      level: 'info',
      firstSeenAt: exportedAt,
      lastSeenAt: exportedAt,
      readAt: null,
      dismissedAt: null,
      rawPayload: '{"revision":"backup"}',
    }).run();

    const downstreamKey = await db.insert(schema.downstreamApiKeys).values({
      name: 'Backup Downstream',
      key: 'downstream-shared',
      description: 'backup config',
      groupName: 'team-a',
      tags: '["backup"]',
      enabled: false,
      expiresAt: '2026-12-31T00:00:00.000Z',
      maxCost: 25,
      usedCost: 1.5,
      maxRequests: 250,
      usedRequests: 2,
      supportedModels: '["gpt-4o"]',
      allowedRouteIds: `[${route.id}]`,
      siteWeightMultipliers: `{"${site.id}":1.25}`,
      excludedSiteIds: `[${site.id}]`,
      excludedCredentialRefs: JSON.stringify([
        { kind: 'account_token', siteId: site.id, accountId: account.id, tokenId: accountToken.id },
      ]),
      lastUsedAt: exportedAt,
      createdAt: exportedAt,
      updatedAt: exportedAt,
    }).returning().get();

    const exported = await backupService.exportBackup('accounts') as any;
    expect(exported.version).toBe('2.1');

    await db.insert(schema.events).values({
      type: 'status',
      title: 'keep-event',
      message: 'should stay after import',
      level: 'info',
      createdAt: localRuntimeAt,
    }).run();

    await db.insert(schema.proxyVideoTasks).values({
      publicId: 'video-task-1',
      upstreamVideoId: 'upstream-video-1',
      siteUrl: site.url,
      tokenValue: account.accessToken,
      createdAt: localRuntimeAt,
      updatedAt: localRuntimeAt,
    }).run();

    await db.insert(schema.proxyFiles).values({
      publicId: 'proxy-file-1',
      ownerType: 'message',
      ownerId: 'msg-1',
      filename: 'snapshot.json',
      mimeType: 'application/json',
      byteSize: 4,
      sha256: 'abcd',
      contentBase64: 'e30=',
      createdAt: localRuntimeAt,
      updatedAt: localRuntimeAt,
    }).run();

    await db.update(schema.sites).set({
      name: 'local-site-name',
      updatedAt: localRuntimeAt,
    }).where(eq(schema.sites.id, site.id)).run();

    await db.delete(schema.siteApiEndpoints)
      .where(eq(schema.siteApiEndpoints.siteId, site.id))
      .run();
    await db.insert(schema.siteApiEndpoints).values({
      siteId: site.id,
      url: 'https://api-local-only.example.com',
      enabled: true,
      sortOrder: 9,
      cooldownUntil: null,
      lastSelectedAt: localRuntimeAt,
      lastFailedAt: null,
      lastFailureReason: null,
      createdAt: localRuntimeAt,
      updatedAt: localRuntimeAt,
    }).run();

    await db.update(schema.tokenRoutes).set({
      displayName: 'local-route-name',
      updatedAt: localRuntimeAt,
    }).where(eq(schema.tokenRoutes.id, route.id)).run();

    await db.update(schema.accounts).set({
      balanceUsed: 99,
      lastCheckinAt: localRuntimeAt,
      lastBalanceRefresh: localRuntimeAt,
      updatedAt: localRuntimeAt,
    }).where(eq(schema.accounts.id, account.id)).run();

    await db.update(schema.routeChannels).set({
      successCount: 77,
      failCount: 9,
      totalLatencyMs: 4321,
      totalCost: 7.89,
      lastUsedAt: localRuntimeAt,
      lastSelectedAt: localRuntimeAt,
      lastFailAt: localRuntimeAt,
      consecutiveFailCount: 4,
      cooldownLevel: 2,
      cooldownUntil: localRuntimeAt,
    }).where(eq(schema.routeChannels.id, insertedChannel!.id)).run();

    await db.delete(schema.siteDisabledModels)
      .where(eq(schema.siteDisabledModels.siteId, site.id))
      .run();
    await db.insert(schema.siteDisabledModels).values({
      siteId: site.id,
      modelName: 'gpt-local-disabled',
      createdAt: localRuntimeAt,
    }).run();

    await db.delete(schema.modelAvailability)
      .where(eq(schema.modelAvailability.accountId, account.id))
      .run();
    await db.insert(schema.modelAvailability).values([
      {
        accountId: account.id,
        modelName: 'gpt-local-manual',
        available: true,
        isManual: true,
        latencyMs: null,
        checkedAt: localRuntimeAt,
      },
      {
        accountId: account.id,
        modelName: 'gpt-cached',
        available: true,
        isManual: false,
        latencyMs: 777,
        checkedAt: localRuntimeAt,
      },
    ]).run();

    await db.update(schema.tokenModelAvailability).set({
      available: true,
      latencyMs: 888,
      checkedAt: localRuntimeAt,
    }).where(eq(schema.tokenModelAvailability.tokenId, accountToken.id)).run();

    await db.update(schema.siteAnnouncements).set({
      title: 'Local banner',
      content: 'Local content',
      lastSeenAt: localRuntimeAt,
      readAt: localRuntimeAt,
      dismissedAt: localRuntimeAt,
      rawPayload: '{"revision":"local"}',
    }).where(eq(schema.siteAnnouncements.siteId, site.id)).run();

    await db.update(schema.downstreamApiKeys).set({
      name: 'Local Mutated Downstream',
      description: 'local config',
      groupName: 'team-local',
      tags: '["local"]',
      enabled: true,
      expiresAt: '2027-01-01T00:00:00.000Z',
      maxCost: 999,
      usedCost: 44,
      maxRequests: 999,
      usedRequests: 55,
      supportedModels: '["gpt-local"]',
      allowedRouteIds: '[999]',
      siteWeightMultipliers: '{"999":9}',
      excludedSiteIds: '[999]',
      excludedCredentialRefs: '[{"kind":"default_api_key","siteId":999,"accountId":999}]',
      lastUsedAt: localRuntimeAt,
      updatedAt: localRuntimeAt,
    }).where(eq(schema.downstreamApiKeys.id, downstreamKey.id)).run();

    const localOnlyDownstreamKey = await db.insert(schema.downstreamApiKeys).values({
      name: 'Local Only Downstream',
      key: 'downstream-local-only',
      usedCost: 7,
      usedRequests: 8,
      lastUsedAt: localRuntimeAt,
      createdAt: localRuntimeAt,
      updatedAt: localRuntimeAt,
    }).returning().get();

    await db.insert(schema.checkinLogs).values({
      accountId: account.id,
      status: 'success',
      message: 'local-checkin',
      reward: '1.5',
      createdAt: localRuntimeAt,
    }).run();

    await db.insert(schema.proxyLogs).values([
      {
        routeId: route.id,
        channelId: insertedChannel!.id,
        accountId: account.id,
        downstreamApiKeyId: downstreamKey.id,
        modelRequested: 'gpt-4o',
        modelActual: 'gpt-4o',
        status: 'success',
        totalTokens: 321,
        estimatedCost: 0.123,
        createdAt: localRuntimeAt,
      },
      {
        routeId: route.id,
        channelId: insertedChannel!.id,
        accountId: account.id,
        downstreamApiKeyId: localOnlyDownstreamKey.id,
        modelRequested: 'gpt-4o-mini',
        modelActual: 'gpt-4o-mini',
        status: 'failed',
        totalTokens: 654,
        estimatedCost: 0.456,
        createdAt: localRuntimeAt,
      },
    ]).run();

    const result = await backupService.importBackup(exported as Record<string, unknown>);

    expect(result.allImported).toBe(true);
    expect(result.sections.accounts).toBe(true);

    const restoredSite = await db.select().from(schema.sites).where(eq(schema.sites.id, site.id)).get();
    const restoredAccount = await db.select().from(schema.accounts).where(eq(schema.accounts.id, account.id)).get();
    const restoredRoute = await db.select().from(schema.tokenRoutes).where(eq(schema.tokenRoutes.id, route.id)).get();
    const restoredChannel = await db.select().from(schema.routeChannels).where(eq(schema.routeChannels.id, insertedChannel!.id)).get();
    const restoredSiteApiEndpoints = await db.select()
      .from(schema.siteApiEndpoints)
      .where(eq(schema.siteApiEndpoints.siteId, site.id))
      .orderBy(asc(schema.siteApiEndpoints.sortOrder), asc(schema.siteApiEndpoints.id))
      .all();
    const restoredDisabledModels = await db.select().from(schema.siteDisabledModels).all();
    const restoredAvailability = await db.select().from(schema.modelAvailability).all();
    const restoredTokenAvailability = await db.select().from(schema.tokenModelAvailability).all();
    const restoredAnnouncements = await db.select().from(schema.siteAnnouncements).all();
    const restoredDownstreamKeys = await db.select().from(schema.downstreamApiKeys).all();
    const restoredProxyLogs = await db.select().from(schema.proxyLogs).all();
    const restoredCheckinLogs = await db.select().from(schema.checkinLogs).all();
    const restoredEvents = await db.select().from(schema.events).all();
    const restoredProxyVideoTasks = await db.select().from(schema.proxyVideoTasks).all();
    const restoredProxyFiles = await db.select().from(schema.proxyFiles).all();

    expect(restoredSite?.name).toBe('backup-site');
    expect(restoredRoute?.displayName).toBe('backup-route');
    expect(restoredAccount?.balanceUsed).toBe(99);
    expect(restoredAccount?.lastCheckinAt).toBe(localRuntimeAt);
    expect(restoredAccount?.lastBalanceRefresh).toBe(localRuntimeAt);
    expect(restoredChannel?.successCount).toBe(77);
    expect(restoredChannel?.failCount).toBe(9);
    expect(restoredChannel?.totalLatencyMs).toBe(4321);
    expect(restoredChannel?.totalCost).toBe(7.89);
    expect(restoredChannel?.lastUsedAt).toBe(localRuntimeAt);
    expect(restoredChannel?.lastSelectedAt).toBe(localRuntimeAt);
    expect(restoredChannel?.lastFailAt).toBe(localRuntimeAt);
    expect(restoredChannel?.consecutiveFailCount).toBe(4);
    expect(restoredChannel?.cooldownLevel).toBe(2);
    expect(restoredChannel?.cooldownUntil).toBe(localRuntimeAt);

    expect(restoredSiteApiEndpoints).toEqual([
      expect.objectContaining({
        siteId: site.id,
        url: 'https://api-a.example.com',
        enabled: true,
        sortOrder: 0,
        cooldownUntil: null,
        lastFailureReason: null,
      }),
      expect.objectContaining({
        siteId: site.id,
        url: 'https://api-b.example.com',
        enabled: false,
        sortOrder: 1,
        cooldownUntil: exportedAt,
        lastFailureReason: 'HTTP 429',
      }),
    ]);

    expect(restoredDisabledModels).toEqual([
      expect.objectContaining({ siteId: site.id, modelName: 'gpt-backup-disabled' }),
    ]);

    const restoredManualModels = restoredAvailability
      .filter((row) => row.isManual)
      .map((row) => row.modelName)
      .sort();
    expect(restoredManualModels).toEqual(['gpt-backup-manual']);
    const restoredCachedModel = restoredAvailability.find((row) => row.modelName === 'gpt-cached' && !row.isManual);
    expect(restoredCachedModel).toEqual(expect.objectContaining({
      available: true,
      latencyMs: 777,
      checkedAt: localRuntimeAt,
    }));

    expect(restoredTokenAvailability).toEqual([
      expect.objectContaining({
        tokenId: accountToken.id,
        modelName: 'gpt-token-cache',
        available: true,
        latencyMs: 888,
        checkedAt: localRuntimeAt,
      }),
    ]);

    expect(restoredAnnouncements).toEqual([
      expect.objectContaining({
        siteId: site.id,
        title: 'Local banner',
        content: 'Local content',
        lastSeenAt: localRuntimeAt,
        readAt: localRuntimeAt,
        dismissedAt: localRuntimeAt,
        rawPayload: '{"revision":"local"}',
      }),
    ]);

    expect(restoredDownstreamKeys).toEqual([
      expect.objectContaining({
        name: 'Backup Downstream',
        key: 'downstream-shared',
        description: 'backup config',
        groupName: 'team-a',
        tags: '["backup"]',
        enabled: false,
        expiresAt: '2026-12-31T00:00:00.000Z',
        maxCost: 25,
        usedCost: 44,
        maxRequests: 250,
        usedRequests: 55,
        supportedModels: '["gpt-4o"]',
        allowedRouteIds: `[${route.id}]`,
        siteWeightMultipliers: `{"${site.id}":1.25}`,
        excludedSiteIds: `[${site.id}]`,
        excludedCredentialRefs: `[{"kind":"account_token","siteId":${site.id},"accountId":${account.id},"tokenId":${accountToken.id}}]`,
        lastUsedAt: localRuntimeAt,
      }),
    ]);

    expect(restoredProxyLogs).toHaveLength(2);
    const matchedDownstreamLog = restoredProxyLogs.find((row) => row.totalTokens === 321);
    const orphanedDownstreamLog = restoredProxyLogs.find((row) => row.totalTokens === 654);
    expect(matchedDownstreamLog?.downstreamApiKeyId).toBe(restoredDownstreamKeys[0]?.id);
    expect(orphanedDownstreamLog?.downstreamApiKeyId).toBeNull();
    expect(restoredCheckinLogs).toEqual([
      expect.objectContaining({
        accountId: account.id,
        message: 'local-checkin',
      }),
    ]);
    expect(restoredEvents).toHaveLength(1);
    expect(restoredProxyVideoTasks).toHaveLength(1);
    expect(restoredProxyFiles).toHaveLength(1);
  });

  it('keeps importing native v2.0 backups without the new v2.1 config arrays', async () => {
    const localDownstreamKey = await db.insert(schema.downstreamApiKeys).values({
      name: 'Local downstream',
      key: 'local-downstream-key',
      usedCost: 12,
      usedRequests: 3,
      createdAt: '2026-03-21T08:00:00.000Z',
      updatedAt: '2026-03-21T08:00:00.000Z',
    }).returning().get();

    const payload = {
      version: '2.0',
      timestamp: Date.now(),
      type: 'accounts',
      accounts: {
        sites: [
          {
            id: 1,
            name: 'Legacy native site',
            url: 'https://legacy-native.example.com',
            externalCheckinUrl: null,
            platform: 'new-api',
            proxyUrl: null,
            useSystemProxy: false,
            customHeaders: null,
            status: 'active',
            isPinned: false,
            sortOrder: 0,
            globalWeight: 1,
            apiKey: null,
            createdAt: '2026-03-20T00:00:00.000Z',
            updatedAt: '2026-03-20T00:00:00.000Z',
          },
        ],
        accounts: [
          {
            id: 1,
            siteId: 1,
            username: 'legacy-user',
            accessToken: 'legacy-session-token',
            apiToken: 'legacy-api-token',
            balance: 10,
            quota: 20,
            unitCost: null,
            valueScore: 0,
            status: 'active',
            isPinned: false,
            sortOrder: 0,
            checkinEnabled: true,
            extraConfig: null,
            createdAt: '2026-03-20T00:00:00.000Z',
            updatedAt: '2026-03-20T00:00:00.000Z',
          },
        ],
        accountTokens: [],
        tokenRoutes: [],
        routeChannels: [],
        routeGroupSources: [],
      },
    } as Record<string, unknown>;

    const result = await backupService.importBackup(payload);

    expect(result.allImported).toBe(true);
    expect(result.sections.accounts).toBe(true);

    const restoredSites = await db.select().from(schema.sites).all();
    const restoredAccounts = await db.select().from(schema.accounts).all();
    const restoredDownstreamKeys = await db.select().from(schema.downstreamApiKeys).all();

    expect(restoredSites).toHaveLength(1);
    expect(restoredAccounts).toHaveLength(1);
    expect(restoredAccounts[0]?.username).toBe('legacy-user');
    expect(restoredDownstreamKeys).toHaveLength(1);
    expect(restoredDownstreamKeys[0]?.id).toBe(localDownstreamKey.id);
    expect(restoredDownstreamKeys[0]?.key).toBe('local-downstream-key');
  });

  it('imports ALL-API-Hub style payload with accounts and preferences', async () => {
    const payload = {
      timestamp: Date.now(),
      accounts: {
        accounts: [
          {
            site_url: 'https://legacy.example.com',
            site_type: 'new-api',
            site_name: 'legacy-site',
            username: 'legacy-user',
            authType: 'session',
            account_info: {
              id: 7788,
              username: 'legacy-user',
              access_token: 'legacy-session-token',
              quota: 100000,
              today_quota_consumption: 50000,
            },
            checkIn: {
              autoCheckInEnabled: true,
            },
            created_at: '2026-02-01T00:00:00.000Z',
            updated_at: '2026-02-02T00:00:00.000Z',
          },
        ],
      },
      preferences: {
        locale: 'zh-CN',
      },
      channelConfigs: {
        order: ['a', 'b'],
      },
      apiCredentialProfiles: {
        default: 'main',
      },
      tagStore: {
        groups: ['test'],
      },
    } as Record<string, unknown>;

    const result = await backupService.importBackup(payload);
    expect(result.allImported).toBe(true);
    expect(result.sections.accounts).toBe(true);
    expect(result.sections.preferences).toBe(true);
    expect(result.appliedSettings.length).toBeGreaterThan(0);

    const sites = await db.select().from(schema.sites).all();
    const accounts = await db.select().from(schema.accounts).all();
    const settings = await db.select().from(schema.settings).all();

    expect(sites.length).toBe(1);
    expect(accounts.length).toBe(1);
    expect(accounts[0].username).toBe('legacy-user');
    expect(settings.some((row) => row.key === 'legacy_preferences_ref_v2')).toBe(true);
  });

  it('imports ALL-API-Hub V2 backups into native offline connections and summaries', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    fetchSpy.mockImplementation(async () => {
      throw new Error('network access should not happen during offline import');
    });

    try {
      const payload = {
        version: '2.0',
        timestamp: Date.now(),
        accounts: {
          accounts: [
            {
              id: 'managed-account',
              site_url: 'https://newapi.example.com',
              site_type: 'new-api',
              site_name: 'Managed Site',
              authType: 'access_token',
              account_info: {
                id: 7788,
                username: 'managed-user',
                access_token: 'managed-session-token',
                quota: 100000,
                today_quota_consumption: 50000,
              },
              checkIn: {
                autoCheckInEnabled: true,
              },
              created_at: '2026-02-01T00:00:00.000Z',
              updated_at: '2026-02-02T00:00:00.000Z',
            },
            {
              id: 'cookie-account',
              site_url: 'https://onehub.example.com',
              site_type: 'one-hub',
              site_name: 'Cookie Site',
              username: 'cookie-user',
              authType: 'cookie',
              cookieAuth: {
                sessionCookie: 'sid=cookie-session',
              },
              checkIn: {
                autoCheckInEnabled: false,
              },
              created_at: '2026-02-03T00:00:00.000Z',
              updated_at: '2026-02-04T00:00:00.000Z',
            },
            {
              id: 'direct-openai-account',
              site_url: 'https://api.openai.com',
              site_type: 'openai',
              site_name: 'OpenAI Direct',
              username: 'openai-account',
              authType: 'access_token',
              account_info: {
                username: 'openai-account',
                access_token: 'sk-openai-account',
              },
              created_at: '2026-02-05T00:00:00.000Z',
              updated_at: '2026-02-06T00:00:00.000Z',
            },
            {
              id: 'sub2api-account',
              site_url: 'https://sub2api.example.com',
              site_type: 'sub2api',
              site_name: 'Sub2API',
              authType: 'access_token',
              account_info: {
                id: 99,
                username: 'sub2-user',
                access_token: 'sub2-session-token',
              },
              sub2apiAuth: {
                refreshToken: 'sub2-refresh-token',
                tokenExpiresAt: 1735689600000,
              },
              checkIn: {
                autoCheckInEnabled: true,
              },
              created_at: '2026-02-07T00:00:00.000Z',
              updated_at: '2026-02-08T00:00:00.000Z',
            },
            {
              id: 'skipped-none-account',
              site_url: 'https://skip-none.example.com',
              site_type: 'new-api',
              site_name: 'Skip None',
              authType: 'none',
              username: 'skip-none-user',
              created_at: '2026-02-09T00:00:00.000Z',
              updated_at: '2026-02-10T00:00:00.000Z',
            },
            {
              id: 'skipped-empty-account',
              site_url: 'https://skip-empty.example.com',
              site_type: 'new-api',
              site_name: 'Skip Empty',
              authType: 'access_token',
              account_info: {
                username: 'skip-empty-user',
              },
              created_at: '2026-02-11T00:00:00.000Z',
              updated_at: '2026-02-12T00:00:00.000Z',
            },
          ],
          bookmarks: [
            {
              id: 'bookmark-1',
              name: 'Ignored Bookmark',
              url: 'https://bookmark.example.com',
            },
          ],
          pinnedAccountIds: ['direct-openai-account'],
          orderedAccountIds: ['managed-account', 'cookie-account', 'direct-openai-account'],
          last_updated: 1735689600000,
        },
        preferences: {
          language: 'zh-CN',
        },
        channelConfigs: {
          bySite: {
            demo: { enabled: true },
          },
        },
        tagStore: {
          version: 1,
          tagsById: {},
        },
        apiCredentialProfiles: {
          version: 2,
          profiles: [
            {
              id: 'profile-openai',
              name: 'OpenAI Profile',
              apiType: 'openai',
              baseUrl: 'https://api.openai.com/v1',
              apiKey: 'sk-profile-openai',
              tagIds: [],
              notes: '',
              createdAt: 1735689601000,
              updatedAt: 1735689602000,
            },
            {
              id: 'profile-anthropic',
              name: 'Claude Profile',
              apiType: 'anthropic',
              baseUrl: 'https://api.anthropic.com/v1',
              apiKey: 'sk-profile-claude',
              tagIds: [],
              notes: '',
              createdAt: 1735689603000,
              updatedAt: 1735689604000,
            },
            {
              id: 'profile-gemini',
              name: 'Gemini Profile',
              apiType: 'google',
              baseUrl: 'https://generativelanguage.googleapis.com/v1beta',
              apiKey: 'gemini-profile-key',
              tagIds: [],
              notes: '',
              createdAt: 1735689605000,
              updatedAt: 1735689606000,
            },
            {
              id: 'profile-compat-fallback',
              name: 'Compat Profile',
              apiType: 'openai-compatible',
              baseUrl: 'https://compat.example.com/v1',
              apiKey: 'sk-compat-profile',
              tagIds: [],
              notes: '',
              createdAt: 1735689607000,
              updatedAt: 1735689608000,
            },
          ],
          lastUpdated: 1735689609000,
        },
      } as Record<string, unknown>;

      const result = await backupService.importBackup(payload);
      const summary = (result as any).summary;
      const warnings = (result as any).warnings;

      expect(result.allImported).toBe(true);
      expect(result.sections.accounts).toBe(true);
      expect(result.sections.preferences).toBe(true);
      expect(summary).toMatchObject({
        importedAccounts: 4,
        importedProfiles: 4,
        importedApiKeyConnections: 5,
        importedSites: 7,
        skippedAccounts: 2,
      });
      expect(summary.ignoredSections).toEqual(
        expect.arrayContaining(['accounts.bookmarks', 'channelConfigs', 'tagStore']),
      );
      expect(warnings).toEqual(
        expect.arrayContaining([
          expect.stringContaining('skipped-none-account'),
          expect.stringContaining('skipped-empty-account'),
        ]),
      );

      const sites = await db.select().from(schema.sites).all();
      const accounts = await db.select().from(schema.accounts).all();
      const accountTokens = await db.select().from(schema.accountTokens).all();
      const settings = await db.select().from(schema.settings).all();

      expect(fetchSpy).not.toHaveBeenCalled();
      expect(sites).toHaveLength(7);
      expect(accounts).toHaveLength(8);
      expect(accountTokens).toHaveLength(5);
      expect(settings.some((row) => row.key === 'legacy_preferences_ref_v2')).toBe(true);
      expect(settings.some((row) => row.key === 'legacy_channel_configs_ref_v2')).toBe(true);
      expect(settings.some((row) => row.key === 'legacy_tag_store_ref_v2')).toBe(true);
      expect(settings.some((row) => row.key === 'legacy_api_credential_profiles_ref_v2')).toBe(false);

      const managedAccount = accounts.find((row) => row.username === 'managed-user');
      const cookieAccount = accounts.find((row) => row.username === 'cookie-user');
      const openAiAccount = accounts.find((row) => row.username === 'openai-account');
      const sub2apiAccount = accounts.find((row) => row.username === 'sub2-user');
      const openAiProfileAccount = accounts.find((row) => row.username === 'OpenAI Profile');
      const claudeProfileAccount = accounts.find((row) => row.username === 'Claude Profile');
      const geminiProfileAccount = accounts.find((row) => row.username === 'Gemini Profile');
      const compatProfileAccount = accounts.find((row) => row.username === 'Compat Profile');

      expect(managedAccount?.accessToken).toBe('managed-session-token');
      expect(managedAccount?.apiToken).toBeNull();
      expect(managedAccount?.checkinEnabled).toBe(true);
      expect(JSON.parse(managedAccount?.extraConfig || '{}')).toMatchObject({
        credentialMode: 'session',
        platformUserId: 7788,
      });

      expect(cookieAccount?.accessToken).toBe('sid=cookie-session');
      expect(cookieAccount?.checkinEnabled).toBe(false);
      expect(JSON.parse(cookieAccount?.extraConfig || '{}')).toMatchObject({
        credentialMode: 'session',
      });

      expect(openAiAccount?.accessToken).toBe('');
      expect(openAiAccount?.apiToken).toBe('sk-openai-account');
      expect(openAiAccount?.checkinEnabled).toBe(false);
      expect(JSON.parse(openAiAccount?.extraConfig || '{}')).toMatchObject({
        credentialMode: 'apikey',
      });

      expect(sub2apiAccount?.accessToken).toBe('sub2-session-token');
      expect(JSON.parse(sub2apiAccount?.extraConfig || '{}')).toMatchObject({
        credentialMode: 'session',
        platformUserId: 99,
        sub2apiAuth: {
          refreshToken: 'sub2-refresh-token',
          tokenExpiresAt: 1735689600000,
        },
      });

      expect(openAiProfileAccount?.accessToken).toBe('');
      expect(openAiProfileAccount?.apiToken).toBe('sk-profile-openai');
      expect(JSON.parse(openAiProfileAccount?.extraConfig || '{}')).toMatchObject({
        credentialMode: 'apikey',
      });
      expect(claudeProfileAccount?.apiToken).toBe('sk-profile-claude');
      expect(geminiProfileAccount?.apiToken).toBe('gemini-profile-key');
      expect(compatProfileAccount?.apiToken).toBe('sk-compat-profile');

      const openAiSite = sites.find((row) => row.platform === 'openai' && row.url === 'https://api.openai.com');
      expect(openAiSite).toBeTruthy();
      expect(accounts.filter((row) => row.siteId === openAiSite?.id)).toHaveLength(2);

      expect(accountTokens.map((row) => row.token).sort()).toEqual([
        'gemini-profile-key',
        'sk-compat-profile',
        'sk-openai-account',
        'sk-profile-claude',
        'sk-profile-openai',
      ]);
      expect(accountTokens.every((row) => row.name === 'default' && row.isDefault && row.source === 'legacy')).toBe(true);
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it('backfills oauth columns from extraConfig when importing older backups', async () => {
    const payload = {
      timestamp: Date.now(),
      accounts: {
        sites: [
          {
            id: 1,
            name: 'codex-site',
            url: 'https://codex.example.com',
            platform: 'chatgpt-account',
            proxyUrl: null,
            status: 'active',
            isPinned: false,
            sortOrder: 0,
            apiKey: null,
            createdAt: '2026-03-01T00:00:00.000Z',
            updatedAt: '2026-03-01T00:00:00.000Z',
            externalCheckinUrl: null,
            useSystemProxy: false,
            globalWeight: 1,
            customHeaders: null,
          },
        ],
        accounts: [
          {
            id: 10,
            siteId: 1,
            username: 'oauth-user',
            accessToken: 'oauth-access-token',
            apiToken: null,
            balance: 0,
            balanceUsed: 0,
            quota: 0,
            unitCost: null,
            valueScore: 0,
            status: 'active',
            isPinned: false,
            sortOrder: 0,
            checkinEnabled: true,
            lastCheckinAt: null,
            lastBalanceRefresh: null,
            extraConfig: JSON.stringify({
              credentialMode: 'session',
              oauth: {
                provider: 'gemini-cli',
                accountId: 'oauth-user@example.com',
                accountKey: 'oauth-user@example.com',
                projectId: 'oauth-project-id',
                refreshToken: 'oauth-refresh-token',
              },
            }),
            createdAt: '2026-03-01T00:00:00.000Z',
            updatedAt: '2026-03-01T00:00:00.000Z',
            oauthProvider: null,
            oauthAccountKey: null,
            oauthProjectId: null,
          },
        ],
        accountTokens: [],
        tokenRoutes: [],
        routeChannels: [],
      },
    } as Record<string, unknown>;

    const result = await backupService.importBackup(payload);

    expect(result.allImported).toBe(true);
    expect(result.sections.accounts).toBe(true);

    const restoredAccount = await db.select().from(schema.accounts).where(eq(schema.accounts.id, 10)).get();

    expect(restoredAccount?.oauthProvider).toBe('gemini-cli');
    expect(restoredAccount?.oauthAccountKey).toBe('oauth-user@example.com');
    expect(restoredAccount?.oauthProjectId).toBe('oauth-project-id');
  });

  it('exports configured backup payload to webdav and records sync state', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    fetchSpy.mockResolvedValue(new Response(null, { status: 201 }));

    await db.insert(schema.settings).values({
      key: 'backup_webdav_config_v1',
      value: JSON.stringify({
        enabled: true,
        fileUrl: 'https://dav.example.com/backups/metapi-preferences.json',
        username: 'alice',
        password: 'secret-pass',
        exportType: 'preferences',
        autoSyncEnabled: false,
        autoSyncCron: '0 * * * *',
      }),
    }).run();
    await db.insert(schema.settings).values({
      key: 'ui_locale',
      value: JSON.stringify('zh-CN'),
    }).run();

    const result = await (backupService as any).exportBackupToWebdav();

    expect(result).toMatchObject({
      success: true,
      fileUrl: 'https://dav.example.com/backups/metapi-preferences.json',
      exportType: 'preferences',
    });
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const [targetUrl, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect(targetUrl).toBe('https://dav.example.com/backups/metapi-preferences.json');
    expect(init.method).toBe('PUT');
    expect(init.headers).toMatchObject({
      Authorization: `Basic ${Buffer.from('alice:secret-pass').toString('base64')}`,
      'Content-Type': 'application/json',
    });
    const payload = JSON.parse(String(init.body));
    expect(payload.type).toBe('preferences');
    expect(payload.preferences.settings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ key: 'ui_locale', value: 'zh-CN' }),
      ]),
    );

    const syncState = await db.select().from(schema.settings).where(eq(schema.settings.key, 'backup_webdav_state_v1')).get();
    expect(syncState?.value).toContain('"lastSyncAt"');
    expect(syncState?.value).toContain('"lastError":null');

    fetchSpy.mockRestore();
  });

  it('imports backup payload from webdav into local data', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    const remotePayload = {
      version: '2.0',
      timestamp: Date.now(),
      accounts: {
        sites: [
          {
            id: 1,
            name: 'remote-site',
            url: 'https://remote.example.com',
            platform: 'new-api',
            externalCheckinUrl: null,
            proxyUrl: null,
            useSystemProxy: false,
            customHeaders: null,
            status: 'active',
            isPinned: false,
            sortOrder: 0,
            globalWeight: 1,
            apiKey: null,
            createdAt: '2026-03-20T00:00:00.000Z',
            updatedAt: '2026-03-20T00:00:00.000Z',
          },
        ],
        accounts: [
          {
            id: 1,
            siteId: 1,
            username: 'remote-user',
            accessToken: 'remote-session',
            apiToken: null,
            oauthProvider: null,
            oauthAccountKey: null,
            oauthProjectId: null,
            balance: 0,
            balanceUsed: 0,
            quota: 0,
            unitCost: null,
            valueScore: 0,
            status: 'active',
            isPinned: false,
            sortOrder: 0,
            checkinEnabled: false,
            lastCheckinAt: null,
            lastBalanceRefresh: null,
            extraConfig: null,
            createdAt: '2026-03-20T00:00:00.000Z',
            updatedAt: '2026-03-20T00:00:00.000Z',
          },
        ],
        accountTokens: [],
        tokenRoutes: [],
        routeChannels: [],
        routeGroupSources: [],
      },
    };
    fetchSpy.mockResolvedValue(new Response(JSON.stringify(remotePayload), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    await db.insert(schema.settings).values({
      key: 'backup_webdav_config_v1',
      value: JSON.stringify({
        enabled: true,
        fileUrl: 'https://dav.example.com/backups/metapi-all.json',
        username: 'alice',
        password: 'secret-pass',
        exportType: 'all',
        autoSyncEnabled: false,
        autoSyncCron: '0 * * * *',
      }),
    }).run();

    const result = await (backupService as any).importBackupFromWebdav();

    expect(result.success).toBe(true);
    expect(result.sections.accounts).toBe(true);
    const sites = await db.select().from(schema.sites).all();
    const accounts = await db.select().from(schema.accounts).all();
    expect(sites).toHaveLength(1);
    expect(accounts).toHaveLength(1);
    expect(accounts[0].username).toBe('remote-user');
    expect(fetchSpy).toHaveBeenCalledWith(
      'https://dav.example.com/backups/metapi-all.json',
      expect.objectContaining({
        method: 'GET',
      }),
    );

    fetchSpy.mockRestore();
  });

  it('times out stalled webdav export requests', async () => {
    vi.useFakeTimers();
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    fetchSpy.mockImplementation((_, init) => {
      const signal = init?.signal as AbortSignal | undefined;
      if (!signal) {
        return Promise.reject(new Error('missing abort signal')) as Promise<Response>;
      }
      return new Promise<Response>((_, reject) => {
        signal.addEventListener('abort', () => {
          reject(Object.assign(new Error('aborted'), { name: 'AbortError' }));
        }, { once: true });
      });
    });

    try {
      await db.insert(schema.settings).values({
        key: 'backup_webdav_config_v1',
        value: JSON.stringify({
          enabled: true,
          fileUrl: 'https://dav.example.com/backups/metapi.json',
          username: 'alice',
          password: 'secret-pass',
          exportType: 'all',
          autoSyncEnabled: false,
          autoSyncCron: '0 */6 * * *',
        }),
      }).run();

      const exportAssertion = expect(backupService.exportBackupToWebdav()).rejects.toThrow('WebDAV 请求超时');
      await vi.advanceTimersByTimeAsync(16_000);
      await exportAssertion;
    } finally {
      fetchSpy.mockRestore();
      vi.useRealTimers();
    }
  });

  it('times out stalled webdav import requests', async () => {
    vi.useFakeTimers();
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    fetchSpy.mockImplementation((_, init) => {
      const signal = init?.signal as AbortSignal | undefined;
      if (!signal) {
        return Promise.reject(new Error('missing abort signal')) as Promise<Response>;
      }
      return new Promise<Response>((_, reject) => {
        signal.addEventListener('abort', () => {
          reject(Object.assign(new Error('aborted'), { name: 'AbortError' }));
        }, { once: true });
      });
    });

    try {
      await db.insert(schema.settings).values({
        key: 'backup_webdav_config_v1',
        value: JSON.stringify({
          enabled: true,
          fileUrl: 'https://dav.example.com/backups/metapi.json',
          username: 'alice',
          password: 'secret-pass',
          exportType: 'all',
          autoSyncEnabled: false,
          autoSyncCron: '0 */6 * * *',
        }),
      }).run();

      const importAssertion = expect(backupService.importBackupFromWebdav()).rejects.toThrow('WebDAV 请求超时');
      await vi.advanceTimersByTimeAsync(16_000);
      await importAssertion;
    } finally {
      fetchSpy.mockRestore();
      vi.useRealTimers();
    }
  });

  it('does not schedule malformed imported webdav config', async () => {
    const cronModule = await import('node-cron');
    const scheduleSpy = vi.spyOn(cronModule.default, 'schedule');
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => { });

    try {
      await db.insert(schema.settings).values({
        key: 'backup_webdav_config_v1',
        value: JSON.stringify({
          enabled: true,
          fileUrl: 'not-a-valid-url',
          username: 'alice',
          password: 'secret-pass',
          exportType: 'all',
          autoSyncEnabled: true,
          autoSyncCron: '0 */6 * * *',
        }),
      }).run();

      await expect(backupService.reloadBackupWebdavScheduler()).resolves.toBeUndefined();
      expect(scheduleSpy).not.toHaveBeenCalled();
      expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('invalid config'));
    } finally {
      backupService.__resetBackupWebdavSchedulerForTests();
      scheduleSpy.mockRestore();
      warnSpy.mockRestore();
    }
  });
});
