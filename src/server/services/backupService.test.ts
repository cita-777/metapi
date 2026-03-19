import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { eq } from 'drizzle-orm';

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
    await db.delete(schema.accountTokens).run();
    await db.delete(schema.accounts).run();
    await db.delete(schema.sites).run();
    await db.delete(schema.settings).run();
  });

  afterAll(() => {
    delete process.env.DATA_DIR;
  });

  it('preserves extended fields in full backup import/export roundtrip', async () => {
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

    const exported = await backupService.exportBackup('all');
    const result = await backupService.importBackup(exported as unknown as Record<string, unknown>);

    expect(result.allImported).toBe(true);
    expect(result.sections.accounts).toBe(true);
    expect(result.summary).toBeUndefined();
    expect(result.warnings).toBeUndefined();

    const restoredSite = await db.select().from(schema.sites).where(eq(schema.sites.id, site.id)).get();
    const restoredAccount = await db.select().from(schema.accounts).where(eq(schema.accounts.id, account.id)).get();
    const restoredRoute = await db.select().from(schema.tokenRoutes).where(eq(schema.tokenRoutes.id, route.id)).get();
    const restoredChannel = await db.select().from(schema.routeChannels).where(eq(schema.routeChannels.routeId, route.id)).get();

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
});
