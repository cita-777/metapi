import currentContract from '../db/generated/schemaContract.json' with { type: 'json' };
import { describe, expect, it, vi } from 'vitest';
import {
  __databaseMigrationServiceTestUtils,
  maskConnectionString,
  normalizeMigrationInput,
} from './databaseMigrationService.js';

function cloneContract<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function createDbSchemaMock() {
  return {
    settings: { __table: 'settings' },
    sites: { __table: 'sites' },
    siteAnnouncements: { __table: 'siteAnnouncements' },
    siteDisabledModels: { __table: 'siteDisabledModels' },
    accounts: { __table: 'accounts' },
    accountTokens: { __table: 'accountTokens' },
    checkinLogs: { __table: 'checkinLogs' },
    modelAvailability: { __table: 'modelAvailability' },
    tokenModelAvailability: { __table: 'tokenModelAvailability' },
    tokenRoutes: { __table: 'tokenRoutes' },
    routeChannels: { __table: 'routeChannels' },
    routeGroupSources: { __table: 'routeGroupSources' },
    proxyLogs: { __table: 'proxyLogs' },
    proxyVideoTasks: { __table: 'proxyVideoTasks' },
    proxyFiles: { __table: 'proxyFiles' },
    downstreamApiKeys: { __table: 'downstreamApiKeys' },
    events: { __table: 'events' },
  };
}

function createDbMock(rowsByTable: Record<string, unknown[]>) {
  return {
    select() {
      return {
        from(table: { __table: string }) {
          return {
            all: async () => rowsByTable[table.__table] ?? [],
          };
        },
      };
    },
  };
}

describe('databaseMigrationService', () => {
  it('accepts postgres migration input with normalized url', () => {
    const normalized = normalizeMigrationInput({
      dialect: 'postgres',
      connectionString: '  postgres://user:pass@db.example.com:5432/metapi  ',
      overwrite: true,
    });

    expect(normalized).toEqual({
      dialect: 'postgres',
      connectionString: 'postgres://user:pass@db.example.com:5432/metapi',
      overwrite: true,
      ssl: false,
    });
  });

  it('accepts mysql migration input', () => {
    const normalized = normalizeMigrationInput({
      dialect: 'mysql',
      connectionString: 'mysql://root:pass@db.example.com:3306/metapi',
    });

    expect(normalized.dialect).toBe('mysql');
    expect(normalized.overwrite).toBe(true);
    expect(normalized.ssl).toBe(false);
  });

  it('accepts sqlite file migration target path', () => {
    const normalized = normalizeMigrationInput({
      dialect: 'sqlite',
      connectionString: './data/target.db',
      overwrite: false,
    });

    expect(normalized).toEqual({
      dialect: 'sqlite',
      connectionString: './data/target.db',
      overwrite: false,
      ssl: false,
    });
  });

  it('rejects unknown dialect', () => {
    expect(() => normalizeMigrationInput({
      dialect: 'oracle',
      connectionString: 'oracle://db',
    } as any)).toThrow(/鏂硅█|sqlite\/mysql\/postgres/i);
  });

  it('rejects postgres input when scheme mismatches', () => {
    expect(() => normalizeMigrationInput({
      dialect: 'postgres',
      connectionString: 'mysql://root:pass@127.0.0.1:3306/metapi',
    })).toThrow(/postgres/i);
  });

  it('masks connection string credentials', () => {
    const masked = maskConnectionString('postgres://admin:super-secret@db.example.com:5432/metapi');
    expect(masked).toBe('postgres://admin:***@db.example.com:5432/metapi');
  });

  it('normalizes ssl boolean from input', () => {
    const normalized = normalizeMigrationInput({
      dialect: 'mysql',
      connectionString: 'mysql://user:pass@tidb.example.com:4000/db',
      ssl: true,
    });
    expect(normalized.ssl).toBe(true);
  });

  it('defaults ssl to false when not provided', () => {
    const normalized = normalizeMigrationInput({
      dialect: 'postgres',
      connectionString: 'postgres://user:pass@db.example.com:5432/metapi',
    });
    expect(normalized.ssl).toBe(false);
  });

  it('parses ssl from string values', () => {
    const normalized = normalizeMigrationInput({
      dialect: 'mysql',
      connectionString: 'mysql://user:pass@host:3306/db',
      ssl: '1',
    });
    expect(normalized.ssl).toBe(true);
  });

  it('parses ssl false from string "0"', () => {
    const normalized = normalizeMigrationInput({
      dialect: 'mysql',
      connectionString: 'mysql://user:pass@host:3306/db',
      ssl: '0',
    });
    expect(normalized.ssl).toBe(false);
  });

  it.each(['postgres', 'mysql', 'sqlite'] as const)('creates or patches sites schema with use_system_proxy and custom_headers for %s', async (dialect) => {
    const executedSql: string[] = [];
    const liveContract = cloneContract(currentContract);
    delete liveContract.tables.sites.columns.use_system_proxy;
    delete liveContract.tables.sites.columns.custom_headers;

    await __databaseMigrationServiceTestUtils.ensureSchema({
      dialect,
      connectionString: dialect === 'sqlite' ? ':memory:' : `${dialect}://example.invalid/metapi`,
      ssl: false,
      begin: async () => {},
      commit: async () => {},
      rollback: async () => {},
      execute: async (sqlText) => {
        executedSql.push(sqlText);
        return [];
      },
      queryScalar: async () => 1,
      close: async () => {},
    }, {
      currentContract,
      liveContract,
    });

    const useSystemProxySql = executedSql.find((sqlText) => sqlText.includes('use_system_proxy'));
    const customHeadersSql = executedSql.find((sqlText) => sqlText.includes('custom_headers'));

    expect(useSystemProxySql).toContain('use_system_proxy');
    expect(customHeadersSql).toContain('custom_headers');
  });

  it.each(['postgres', 'mysql'] as const)('patches token_routes decision snapshot columns for %s', async (dialect) => {
    const executedSql: string[] = [];
    const liveContract = cloneContract(currentContract);
    delete liveContract.tables.token_routes.columns.decision_snapshot;

    await __databaseMigrationServiceTestUtils.ensureSchema({
      dialect,
      connectionString: `${dialect}://example.invalid/metapi`,
      ssl: false,
      begin: async () => {},
      commit: async () => {},
      rollback: async () => {},
      execute: async (sqlText) => {
        executedSql.push(sqlText);
        return [];
      },
      queryScalar: async () => 1,
      close: async () => {},
    }, {
      currentContract,
      liveContract,
    });

    expect(
      executedSql.some((sqlText) => sqlText.includes('ADD COLUMN') && sqlText.includes('decision_snapshot')),
    ).toBe(true);
  });

  it('includes useSystemProxy and customHeaders when building site migration statements', () => {
    const statements = __databaseMigrationServiceTestUtils.buildStatements({
      version: 'test',
      timestamp: Date.now(),
      accounts: {
        sites: [{
          id: 1,
          name: 'demo',
          url: 'https://example.com',
          platform: 'openai',
          useSystemProxy: true,
          customHeaders: '{"x-site-scope":"internal"}',
          status: 'active',
        }],
        siteAnnouncements: [],
        siteDisabledModels: [],
        accounts: [],
        accountTokens: [],
        checkinLogs: [],
        modelAvailability: [],
        tokenModelAvailability: [],
        tokenRoutes: [],
        routeChannels: [],
        proxyLogs: [],
        proxyVideoTasks: [],
        proxyFiles: [],
        downstreamApiKeys: [],
        events: [],
      },
      preferences: {
        settings: [],
      },
    });

    const siteStatement = statements.find((statement) => statement.table === 'sites');
    const useSystemProxyIndex = siteStatement?.columns.indexOf('use_system_proxy') ?? -1;
    const customHeadersIndex = siteStatement?.columns.indexOf('custom_headers') ?? -1;

    expect(useSystemProxyIndex).toBeGreaterThanOrEqual(0);
    expect(siteStatement?.values[useSystemProxyIndex]).toBe(true);
    expect(customHeadersIndex).toBeGreaterThanOrEqual(0);
    expect(siteStatement?.values[customHeadersIndex]).toBe('{"x-site-scope":"internal"}');
  });

  it('includes disabled models, proxy video tasks, and proxy files in migration statements', () => {
    const statements = __databaseMigrationServiceTestUtils.buildStatements({
      version: 'test',
      timestamp: Date.now(),
      accounts: {
        sites: [],
        siteAnnouncements: [],
        siteDisabledModels: [{
          id: 3,
          siteId: 12,
          modelName: 'claude-opus-4-6',
          createdAt: '2026-03-14T00:00:00.000Z',
        }],
        accounts: [],
        accountTokens: [],
        checkinLogs: [],
        modelAvailability: [],
        tokenModelAvailability: [],
        tokenRoutes: [{
          id: 10,
          modelPattern: 'claude-opus-4-6',
          displayName: 'claude-opus-4-6',
          displayIcon: 'icon-claude',
          modelMapping: null,
          routeMode: 'explicit_group',
          decisionSnapshot: '{"channels":[1]}',
          decisionRefreshedAt: '2026-03-14T01:30:00.000Z',
          routingStrategy: 'round_robin',
          enabled: true,
          createdAt: '2026-03-14T00:00:00.000Z',
          updatedAt: '2026-03-14T01:00:00.000Z',
        }],
        routeChannels: [],
        proxyLogs: [],
        proxyVideoTasks: [{
          id: 5,
          publicId: 'video-public-id',
          upstreamVideoId: 'upstream-video-id',
          siteUrl: 'https://example.com',
          tokenValue: 'sk-video',
          requestedModel: 'veo-3',
          actualModel: 'veo-3',
          channelId: 7,
          accountId: 9,
          statusSnapshot: '{"status":"done"}',
          upstreamResponseMeta: '{"id":"video"}',
          lastUpstreamStatus: 200,
          lastPolledAt: '2026-03-14T01:00:00.000Z',
          createdAt: '2026-03-14T00:00:00.000Z',
          updatedAt: '2026-03-14T01:00:00.000Z',
        }],
        proxyFiles: [{
          id: 8,
          publicId: 'file-public-id',
          ownerType: 'downstream_key',
          ownerId: 'key-1',
          filename: 'demo.txt',
          mimeType: 'text/plain',
          purpose: 'assistants',
          byteSize: 4,
          sha256: 'abcd',
          contentBase64: 'ZGVtbw==',
          createdAt: '2026-03-14T00:00:00.000Z',
          updatedAt: '2026-03-14T01:00:00.000Z',
          deletedAt: null,
        }],
        routeGroupSources: [{
          id: 9,
          groupRouteId: 12,
          sourceRouteId: 13,
        }],
        downstreamApiKeys: [],
        events: [],
      },
      preferences: {
        settings: [],
      },
    } as any);

    expect(statements.some((statement) => statement.table === 'site_disabled_models')).toBe(true);
    expect(statements.some((statement) => statement.table === 'proxy_video_tasks')).toBe(true);
    expect(statements.some((statement) => statement.table === 'proxy_files')).toBe(true);
    expect(statements.some((statement) => statement.table === 'route_group_sources')).toBe(true);
    const tokenRouteStatement = statements.find((statement) => statement.table === 'token_routes');
    const routeModeIndex = tokenRouteStatement?.columns.indexOf('route_mode') ?? -1;
    expect(routeModeIndex).toBeGreaterThanOrEqual(0);
    expect(tokenRouteStatement?.values[routeModeIndex]).toBe('explicit_group');
  });

  it('includes site announcements in migration statements', () => {
    const statements = __databaseMigrationServiceTestUtils.buildStatements({
      version: 'test',
      timestamp: Date.now(),
      accounts: {
        sites: [],
        siteDisabledModels: [],
        accounts: [],
        accountTokens: [],
        checkinLogs: [],
        modelAvailability: [],
        tokenModelAvailability: [],
        tokenRoutes: [],
        routeChannels: [],
        routeGroupSources: [],
        proxyLogs: [],
        proxyVideoTasks: [],
        proxyFiles: [],
        downstreamApiKeys: [],
        events: [],
        siteAnnouncements: [{
          id: 11,
          siteId: 3,
          platform: 'openai',
          sourceKey: 'notice-1',
          title: '????',
          content: '????',
          level: 'warning',
          sourceUrl: 'https://example.com/notice',
          startsAt: '2026-03-20T00:00:00.000Z',
          endsAt: '2026-03-21T00:00:00.000Z',
          upstreamCreatedAt: '2026-03-19T00:00:00.000Z',
          upstreamUpdatedAt: '2026-03-20T00:00:00.000Z',
          firstSeenAt: '2026-03-20T00:00:00.000Z',
          lastSeenAt: '2026-03-20T01:00:00.000Z',
          readAt: null,
          dismissedAt: null,
          rawPayload: '{"id":"notice-1"}',
        }],
      },
      preferences: {
        settings: [],
      },
    } as any);

    const statement = statements.find((item) => item.table === 'site_announcements');
    expect(statement).toBeDefined();
    expect(statement?.columns).toContain('source_key');
    expect(statement?.values[statement?.columns.indexOf('title') ?? -1]).toBe('????');
  });

  it('includes site announcements in migration summary', async () => {
    vi.resetModules();

    const rowsByTable = {
      settings: [],
      sites: [],
      siteAnnouncements: [{
        id: 11,
        siteId: 3,
        platform: 'openai',
        sourceKey: 'notice-1',
        title: '????',
        content: '????',
        level: 'warning',
        sourceUrl: 'https://example.com/notice',
        startsAt: '2026-03-20T00:00:00.000Z',
        endsAt: '2026-03-21T00:00:00.000Z',
        upstreamCreatedAt: '2026-03-19T00:00:00.000Z',
        upstreamUpdatedAt: '2026-03-20T00:00:00.000Z',
        firstSeenAt: '2026-03-20T00:00:00.000Z',
        lastSeenAt: '2026-03-20T01:00:00.000Z',
        readAt: null,
        dismissedAt: null,
        rawPayload: '{"id":"notice-1"}',
      }],
      siteDisabledModels: [],
      accounts: [],
      accountTokens: [],
      checkinLogs: [],
      modelAvailability: [],
      tokenModelAvailability: [],
      tokenRoutes: [],
      routeChannels: [],
      routeGroupSources: [],
      proxyLogs: [],
      proxyVideoTasks: [],
      proxyFiles: [],
      downstreamApiKeys: [],
      events: [],
    };

    const client = {
      dialect: 'sqlite',
      connectionString: ':memory:',
      ssl: false,
      begin: vi.fn(async () => {}),
      commit: vi.fn(async () => {}),
      rollback: vi.fn(async () => {}),
      execute: vi.fn(async () => []),
      queryScalar: vi.fn(async () => 0),
      close: vi.fn(async () => {}),
    };

    vi.doMock('../db/index.js', () => ({
      db: createDbMock(rowsByTable),
      schema: createDbSchemaMock(),
    }));
    vi.doMock('../db/runtimeSchemaBootstrap.js', () => ({
      createRuntimeSchemaClient: async () => client,
      ensureRuntimeDatabaseSchema: async () => {},
    }));

    try {
      const { migrateCurrentDatabase } = await import('./databaseMigrationService.js');
      const summary = await migrateCurrentDatabase({
        dialect: 'sqlite',
        connectionString: ':memory:',
        overwrite: true,
      });

      expect(summary.rows.siteAnnouncements).toBe(1);
      expect(client.begin).toHaveBeenCalledTimes(1);
      expect(client.commit).toHaveBeenCalledTimes(1);
      expect(client.close).toHaveBeenCalledTimes(1);
    } finally {
      vi.doUnmock('../db/index.js');
      vi.doUnmock('../db/runtimeSchemaBootstrap.js');
      vi.resetModules();
    }
  });

  it('excludes runtime database config settings from migration statements', () => {
    const statements = __databaseMigrationServiceTestUtils.buildStatements({
      version: 'test',
      timestamp: Date.now(),
      accounts: {
        sites: [],
        siteAnnouncements: [],
        siteDisabledModels: [],
        accounts: [],
        accountTokens: [],
        checkinLogs: [],
        modelAvailability: [],
        tokenModelAvailability: [],
        tokenRoutes: [],
        routeChannels: [],
        routeGroupSources: [],
        proxyLogs: [],
        proxyVideoTasks: [],
        proxyFiles: [],
        downstreamApiKeys: [],
        events: [],
      },
      preferences: {
        settings: [
          { key: 'db_type', value: 'sqlite' },
          { key: 'db_url', value: '/app/data/hub.db' },
          { key: 'db_ssl', value: false },
          { key: 'routing_fallback_unit_cost', value: 0.25 },
        ],
      },
    } as any);

    const migratedSettingKeys = statements
      .filter((statement) => statement.table === 'settings')
      .map((statement) => statement.values[0]);

    expect(migratedSettingKeys).toContain('routing_fallback_unit_cost');
    expect(migratedSettingKeys).not.toContain('db_type');
    expect(migratedSettingKeys).not.toContain('db_url');
    expect(migratedSettingKeys).not.toContain('db_ssl');
  });
});
