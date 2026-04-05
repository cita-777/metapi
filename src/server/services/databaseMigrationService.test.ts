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
    siteApiEndpoints: { __table: 'siteApiEndpoints' },
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

  it('includes site api endpoints when building migration statements', () => {
    const statements = __databaseMigrationServiceTestUtils.buildStatements({
      version: 'test',
      timestamp: Date.now(),
      accounts: {
        sites: [{
          id: 1,
          name: 'demo',
          url: 'https://example.com',
          platform: 'new-api',
          status: 'active',
        }],
        siteApiEndpoints: [{
          id: 9,
          siteId: 1,
          url: 'https://api.example.com',
          enabled: true,
          sortOrder: 2,
          cooldownUntil: '2026-03-31T12:05:00.000Z',
          lastSelectedAt: '2026-03-31T12:00:00.000Z',
          lastFailedAt: '2026-03-31T11:59:00.000Z',
          lastFailureReason: 'HTTP 502',
          createdAt: '2026-03-30T00:00:00.000Z',
          updatedAt: '2026-03-31T12:05:00.000Z',
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
        routeGroupSources: [],
        proxyLogs: [],
        proxyVideoTasks: [],
        proxyFiles: [],
        downstreamApiKeys: [],
        events: [],
      },
      preferences: {
        settings: [],
      },
    } as any);

    const endpointStatement = statements.find((statement) => statement.table === 'site_api_endpoints');
    expect(endpointStatement?.columns).toEqual([
      'id',
      'site_id',
      'url',
      'enabled',
      'sort_order',
      'cooldown_until',
      'last_selected_at',
      'last_failed_at',
      'last_failure_reason',
      'created_at',
      'updated_at',
    ]);
    expect(endpointStatement?.values).toEqual([
      9,
      1,
      'https://api.example.com',
      true,
      2,
      '2026-03-31T12:05:00.000Z',
      '2026-03-31T12:00:00.000Z',
      '2026-03-31T11:59:00.000Z',
      'HTTP 502',
      '2026-03-30T00:00:00.000Z',
      '2026-03-31T12:05:00.000Z',
    ]);
  });

  it('serializes parsed JSON-column values when building migration statements', () => {
    const statements = __databaseMigrationServiceTestUtils.buildStatements({
      version: 'test',
      timestamp: Date.now(),
      accounts: {
        sites: [{
          id: 1,
          name: 'demo',
          url: 'https://example.com',
          platform: 'openai',
          customHeaders: { 'x-site-scope': 'internal' },
          status: 'active',
        }],
        siteAnnouncements: [],
        siteDisabledModels: [],
        accounts: [{
          id: 2,
          siteId: 1,
          username: 'user-1',
          accessToken: 'access-1',
          extraConfig: { platformUserId: 42 },
          status: 'active',
        }],
        accountTokens: [],
        checkinLogs: [],
        modelAvailability: [],
        tokenModelAvailability: [],
        tokenRoutes: [{
          id: 3,
          modelPattern: '*',
          modelMapping: { '*': 'gpt-4o-mini' },
          decisionSnapshot: { channels: [1] },
          enabled: true,
        }],
        routeChannels: [],
        routeGroupSources: [],
        proxyLogs: [{
          id: 4,
          billingDetails: { total: 1.25 },
        }],
        proxyVideoTasks: [{
          id: 5,
          publicId: 'video-public-id',
          upstreamVideoId: 'upstream-video-id',
          siteUrl: 'https://example.com',
          tokenValue: 'sk-video',
          statusSnapshot: { status: 'done' },
          upstreamResponseMeta: { id: 'video' },
        }],
        proxyFiles: [],
        downstreamApiKeys: [{
          id: 6,
          name: 'managed-key',
          key: 'mk-demo',
          supportedModels: ['gpt-4o-mini'],
          allowedRouteIds: [3],
          siteWeightMultipliers: { 1: 1.5 },
          excludedSiteIds: [1],
          excludedCredentialRefs: [{ kind: 'default_api_key', siteId: 1, accountId: 2 }],
          enabled: true,
        }],
        events: [],
      },
      preferences: {
        settings: [],
      },
    } as any);

    const siteStatement = statements.find((statement) => statement.table === 'sites');
    const accountStatement = statements.find((statement) => statement.table === 'accounts');
    const tokenRouteStatement = statements.find((statement) => statement.table === 'token_routes');
    const proxyLogStatement = statements.find((statement) => statement.table === 'proxy_logs');
    const proxyVideoStatement = statements.find((statement) => statement.table === 'proxy_video_tasks');
    const downstreamKeyStatement = statements.find((statement) => statement.table === 'downstream_api_keys');

    expect(siteStatement?.values[siteStatement.columns.indexOf('custom_headers')]).toBe('{"x-site-scope":"internal"}');
    expect(accountStatement?.values[accountStatement.columns.indexOf('extra_config')]).toBe('{"platformUserId":42}');
    expect(tokenRouteStatement?.values[tokenRouteStatement.columns.indexOf('model_mapping')]).toBe('{"*":"gpt-4o-mini"}');
    expect(tokenRouteStatement?.values[tokenRouteStatement.columns.indexOf('decision_snapshot')]).toBe('{"channels":[1]}');
    expect(proxyLogStatement?.values[proxyLogStatement.columns.indexOf('billing_details')]).toBe('{"total":1.25}');
    expect(proxyVideoStatement?.values[proxyVideoStatement.columns.indexOf('status_snapshot')]).toBe('{"status":"done"}');
    expect(proxyVideoStatement?.values[proxyVideoStatement.columns.indexOf('upstream_response_meta')]).toBe('{"id":"video"}');
    expect(downstreamKeyStatement?.values[downstreamKeyStatement.columns.indexOf('supported_models')]).toBe('["gpt-4o-mini"]');
    expect(downstreamKeyStatement?.values[downstreamKeyStatement.columns.indexOf('allowed_route_ids')]).toBe('[3]');
    expect(downstreamKeyStatement?.values[downstreamKeyStatement.columns.indexOf('site_weight_multipliers')]).toBe('{"1":1.5}');
    expect(downstreamKeyStatement?.values[downstreamKeyStatement.columns.indexOf('excluded_site_ids')]).toBe('[1]');
    expect(downstreamKeyStatement?.values[downstreamKeyStatement.columns.indexOf('excluded_credential_refs')]).toBe('[{"kind":"default_api_key","siteId":1,"accountId":2}]');
  });

  it('uses schema logical types to serialize JSON columns instead of String(value)', () => {
    expect(__databaseMigrationServiceTestUtils.serializeColumnValue('sites', 'custom_headers', {
      'x-site-scope': 'internal',
    })).toBe('{"x-site-scope":"internal"}');
    expect(__databaseMigrationServiceTestUtils.serializeColumnValue('downstream_api_keys', 'supported_models', [
      'gpt-4o-mini',
    ])).toBe('["gpt-4o-mini"]');
    expect(__databaseMigrationServiceTestUtils.serializeColumnValue('sites', 'name', {
      demo: true,
    })).toBe('[object Object]');
  });

  it('serializes object-backed JSON columns when building migration statements', () => {
    const statements = __databaseMigrationServiceTestUtils.buildStatements({
      version: 'test',
      timestamp: Date.now(),
      accounts: {
        sites: [{
          id: 1,
          name: 'demo',
          url: 'https://example.com',
          platform: 'openai',
          customHeaders: { 'x-site-scope': 'internal' },
          status: 'active',
        }],
        siteAnnouncements: [],
        siteDisabledModels: [],
        accounts: [{
          id: 2,
          siteId: 1,
          accessToken: 'access',
          extraConfig: { platformUserId: 1234 },
          status: 'active',
        }],
        accountTokens: [],
        checkinLogs: [],
        modelAvailability: [],
        tokenModelAvailability: [],
        tokenRoutes: [{
          id: 3,
          modelPattern: 'gpt-*',
          modelMapping: { 'gpt-*': 'gpt-5-mini' },
          decisionSnapshot: { candidates: [1, 2] },
          enabled: true,
        }],
        routeChannels: [],
        routeGroupSources: [],
        proxyLogs: [{
          id: 4,
          billingDetails: { currency: 'usd', total: 1.23 },
        }],
        proxyVideoTasks: [{
          id: 5,
          publicId: 'video-public-id',
          upstreamVideoId: 'upstream-video-id',
          siteUrl: 'https://example.com',
          tokenValue: 'sk-video',
          statusSnapshot: { status: 'done' },
          upstreamResponseMeta: { id: 'video' },
        }],
        proxyFiles: [],
        downstreamApiKeys: [{
          id: 6,
          name: 'managed',
          key: 'sk-managed',
          enabled: true,
          supportedModels: ['gpt-5', 'gpt-5-mini'],
          allowedRouteIds: [10, 11],
          siteWeightMultipliers: { 1: 2, 2: 0.5 },
        }],
        events: [],
      },
      preferences: {
        settings: [],
      },
    } as any);

    const sitesStatement = statements.find((statement) => statement.table === 'sites');
    expect(sitesStatement?.values[sitesStatement.columns.indexOf('custom_headers')]).toBe('{"x-site-scope":"internal"}');

    const accountsStatement = statements.find((statement) => statement.table === 'accounts');
    expect(accountsStatement?.values[accountsStatement.columns.indexOf('extra_config')]).toBe('{"platformUserId":1234}');

    const tokenRoutesStatement = statements.find((statement) => statement.table === 'token_routes');
    expect(tokenRoutesStatement?.values[tokenRoutesStatement.columns.indexOf('model_mapping')]).toBe('{"gpt-*":"gpt-5-mini"}');
    expect(tokenRoutesStatement?.values[tokenRoutesStatement.columns.indexOf('decision_snapshot')]).toBe('{"candidates":[1,2]}');

    const proxyLogsStatement = statements.find((statement) => statement.table === 'proxy_logs');
    expect(proxyLogsStatement?.values[proxyLogsStatement.columns.indexOf('billing_details')]).toBe('{"currency":"usd","total":1.23}');

    const proxyVideoTasksStatement = statements.find((statement) => statement.table === 'proxy_video_tasks');
    expect(proxyVideoTasksStatement?.values[proxyVideoTasksStatement.columns.indexOf('status_snapshot')]).toBe('{"status":"done"}');
    expect(proxyVideoTasksStatement?.values[proxyVideoTasksStatement.columns.indexOf('upstream_response_meta')]).toBe('{"id":"video"}');

    const downstreamApiKeysStatement = statements.find((statement) => statement.table === 'downstream_api_keys');
    expect(downstreamApiKeysStatement?.values[downstreamApiKeysStatement.columns.indexOf('supported_models')]).toBe('["gpt-5","gpt-5-mini"]');
    expect(downstreamApiKeysStatement?.values[downstreamApiKeysStatement.columns.indexOf('allowed_route_ids')]).toBe('[10,11]');
    expect(downstreamApiKeysStatement?.values[downstreamApiKeysStatement.columns.indexOf('site_weight_multipliers')]).toBe('{"1":2,"2":0.5}');
  });

  it('serializes JSON logical-type columns from object and array values', () => {
    const statements = __databaseMigrationServiceTestUtils.buildStatements({
      version: 'test',
      timestamp: Date.now(),
      accounts: {
        sites: [{
          id: 1,
          name: 'demo',
          url: 'https://example.com',
          platform: 'openai',
          customHeaders: { 'x-site-scope': 'internal' },
          status: 'active',
        }],
        siteAnnouncements: [],
        siteDisabledModels: [],
        accounts: [{
          id: 2,
          siteId: 1,
          username: 'user-1',
          accessToken: 'token-1',
          extraConfig: { platformUserId: 1001, credentialMode: 'session' },
          status: 'active',
        }],
        accountTokens: [],
        checkinLogs: [],
        modelAvailability: [],
        tokenModelAvailability: [],
        tokenRoutes: [{
          id: 3,
          modelPattern: 'gpt-*',
          modelMapping: { 'gpt-*': 'gpt-4.1' },
          decisionSnapshot: { matched: true, channels: [1] },
          enabled: true,
        }],
        routeChannels: [],
        routeGroupSources: [],
        proxyLogs: [{
          id: 4,
          billingDetails: { source: 'pricing', total: 1.25 },
        }],
        proxyVideoTasks: [{
          id: 5,
          publicId: 'video-1',
          upstreamVideoId: 'upstream-1',
          siteUrl: 'https://example.com',
          tokenValue: 'sk-video',
          requestedModel: 'veo-3',
          actualModel: 'veo-3',
          channelId: 9,
          accountId: 2,
          statusSnapshot: { status: 'done' },
          upstreamResponseMeta: { id: 'video' },
        }],
        proxyFiles: [],
        downstreamApiKeys: [{
          id: 6,
          name: 'managed',
          key: 'sk-managed',
          supportedModels: ['gpt-4.1', 'gpt-4o'],
          allowedRouteIds: [3, 8],
          siteWeightMultipliers: { 1: 2 },
          enabled: true,
        }],
        events: [],
      },
      preferences: {
        settings: [],
      },
    } as any);

    const siteStatement = statements.find((statement) => statement.table === 'sites');
    const accountStatement = statements.find((statement) => statement.table === 'accounts');
    const routeStatement = statements.find((statement) => statement.table === 'token_routes');
    const proxyLogStatement = statements.find((statement) => statement.table === 'proxy_logs');
    const videoStatement = statements.find((statement) => statement.table === 'proxy_video_tasks');
    const downstreamKeyStatement = statements.find((statement) => statement.table === 'downstream_api_keys');

    expect(siteStatement?.values[siteStatement.columns.indexOf('custom_headers')]).toBe('{"x-site-scope":"internal"}');
    expect(accountStatement?.values[accountStatement.columns.indexOf('extra_config')]).toBe('{"platformUserId":1001,"credentialMode":"session"}');
    expect(routeStatement?.values[routeStatement.columns.indexOf('model_mapping')]).toBe('{"gpt-*":"gpt-4.1"}');
    expect(routeStatement?.values[routeStatement.columns.indexOf('decision_snapshot')]).toBe('{"matched":true,"channels":[1]}');
    expect(proxyLogStatement?.values[proxyLogStatement.columns.indexOf('billing_details')]).toBe('{"source":"pricing","total":1.25}');
    expect(videoStatement?.values[videoStatement.columns.indexOf('status_snapshot')]).toBe('{"status":"done"}');
    expect(videoStatement?.values[videoStatement.columns.indexOf('upstream_response_meta')]).toBe('{"id":"video"}');
    expect(downstreamKeyStatement?.values[downstreamKeyStatement.columns.indexOf('supported_models')]).toBe('["gpt-4.1","gpt-4o"]');
    expect(downstreamKeyStatement?.values[downstreamKeyStatement.columns.indexOf('allowed_route_ids')]).toBe('[3,8]');
    expect(downstreamKeyStatement?.values[downstreamKeyStatement.columns.indexOf('site_weight_multipliers')]).toBe('{"1":2}');
  });

  it('serializes JSON logical-type columns from parsed objects and arrays', () => {
    const statements = __databaseMigrationServiceTestUtils.buildStatements({
      version: 'test',
      timestamp: Date.now(),
      accounts: {
        sites: [{
          id: 1,
          name: 'demo',
          url: 'https://example.com',
          platform: 'openai',
          customHeaders: { 'x-site-scope': 'internal' },
          status: 'active',
        }],
        siteAnnouncements: [],
        siteDisabledModels: [],
        accounts: [{
          id: 2,
          siteId: 1,
          username: 'demo-user',
          accessToken: 'token',
          extraConfig: { platformUserId: 42 },
          status: 'active',
        }],
        accountTokens: [],
        checkinLogs: [],
        modelAvailability: [],
        tokenModelAvailability: [],
        tokenRoutes: [{
          id: 3,
          modelPattern: 'gpt-*',
          modelMapping: { 'gpt-4.1': 'gpt-4o-mini' },
          decisionSnapshot: { matched: true, routeId: 3 },
          enabled: true,
        }],
        routeChannels: [],
        routeGroupSources: [],
        proxyLogs: [{
          id: 4,
          billingDetails: { total: 1.25, currency: 'USD' },
        }],
        proxyVideoTasks: [{
          id: 5,
          publicId: 'vid_1',
          upstreamVideoId: 'upstream_1',
          siteUrl: 'https://example.com',
          tokenValue: 'sk-video',
          statusSnapshot: { status: 'done' },
          upstreamResponseMeta: { id: 'video-1' },
        }],
        proxyFiles: [],
        downstreamApiKeys: [{
          id: 6,
          name: 'managed-key',
          key: 'sk-managed',
          supportedModels: ['gpt-4.1', 'gpt-4o-mini'],
          allowedRouteIds: [3],
          siteWeightMultipliers: { 1: 1.5 },
        }],
        events: [],
      },
      preferences: {
        settings: [],
      },
    } as any);

    const sitesStatement = statements.find((statement) => statement.table === 'sites');
    const accountsStatement = statements.find((statement) => statement.table === 'accounts');
    const tokenRoutesStatement = statements.find((statement) => statement.table === 'token_routes');
    const proxyLogsStatement = statements.find((statement) => statement.table === 'proxy_logs');
    const proxyVideoStatement = statements.find((statement) => statement.table === 'proxy_video_tasks');
    const downstreamStatement = statements.find((statement) => statement.table === 'downstream_api_keys');

    expect(sitesStatement?.values[sitesStatement.columns.indexOf('custom_headers')]).toBe('{"x-site-scope":"internal"}');
    expect(accountsStatement?.values[accountsStatement.columns.indexOf('extra_config')]).toBe('{"platformUserId":42}');
    expect(tokenRoutesStatement?.values[tokenRoutesStatement.columns.indexOf('model_mapping')]).toBe('{"gpt-4.1":"gpt-4o-mini"}');
    expect(tokenRoutesStatement?.values[tokenRoutesStatement.columns.indexOf('decision_snapshot')]).toBe('{"matched":true,"routeId":3}');
    expect(proxyLogsStatement?.values[proxyLogsStatement.columns.indexOf('billing_details')]).toBe('{"total":1.25,"currency":"USD"}');
    expect(proxyVideoStatement?.values[proxyVideoStatement.columns.indexOf('status_snapshot')]).toBe('{"status":"done"}');
    expect(proxyVideoStatement?.values[proxyVideoStatement.columns.indexOf('upstream_response_meta')]).toBe('{"id":"video-1"}');
    expect(downstreamStatement?.values[downstreamStatement.columns.indexOf('supported_models')]).toBe('["gpt-4.1","gpt-4o-mini"]');
    expect(downstreamStatement?.values[downstreamStatement.columns.indexOf('allowed_route_ids')]).toBe('[3]');
    expect(downstreamStatement?.values[downstreamStatement.columns.indexOf('site_weight_multipliers')]).toBe('{"1":1.5}');
  });

  it('serializes JSON logical-type columns without coercing objects to [object Object]', () => {
    const statements = __databaseMigrationServiceTestUtils.buildStatements({
      version: 'test',
      timestamp: Date.now(),
      accounts: {
        sites: [{
          id: 1,
          name: 'demo',
          url: 'https://example.com',
          platform: 'openai',
          customHeaders: { 'x-site-scope': 'internal' },
          status: 'active',
        }],
        siteAnnouncements: [],
        siteDisabledModels: [],
        accounts: [{
          id: 2,
          siteId: 1,
          username: 'user',
          accessToken: 'access',
          apiToken: 'api',
          extraConfig: { platformUserId: 42, credentialMode: 'session' },
          status: 'active',
        }],
        accountTokens: [],
        checkinLogs: [],
        modelAvailability: [],
        tokenModelAvailability: [],
        tokenRoutes: [{
          id: 3,
          modelPattern: '*',
          modelMapping: { 'gpt-4.1': 'gpt-4o-mini' },
          decisionSnapshot: { matched: true, routeId: 3 },
          enabled: true,
        }],
        routeChannels: [],
        routeGroupSources: [],
        proxyLogs: [{
          id: 4,
          billingDetails: { source: 'pricing', usd: 1.25 },
        }],
        proxyVideoTasks: [{
          id: 5,
          publicId: 'vid_1',
          upstreamVideoId: 'upstream_1',
          siteUrl: 'https://example.com',
          tokenValue: 'sk-video',
          requestedModel: 'veo-3',
          actualModel: 'veo-3',
          statusSnapshot: { status: 'done' },
          upstreamResponseMeta: { id: 'video' },
        }],
        proxyFiles: [],
        downstreamApiKeys: [{
          id: 6,
          name: 'managed',
          key: 'key-1',
          supportedModels: ['gpt-4.1'],
          allowedRouteIds: [3],
          siteWeightMultipliers: { 1: 2 },
          enabled: true,
        }],
        events: [],
      },
      preferences: {
        settings: [],
      },
    } as any);

    const sitesStatement = statements.find((statement) => statement.table === 'sites');
    const accountsStatement = statements.find((statement) => statement.table === 'accounts');
    const tokenRoutesStatement = statements.find((statement) => statement.table === 'token_routes');
    const proxyLogsStatement = statements.find((statement) => statement.table === 'proxy_logs');
    const proxyVideoTasksStatement = statements.find((statement) => statement.table === 'proxy_video_tasks');
    const downstreamKeysStatement = statements.find((statement) => statement.table === 'downstream_api_keys');

    expect(sitesStatement?.values[sitesStatement.columns.indexOf('custom_headers')]).toBe('{"x-site-scope":"internal"}');
    expect(accountsStatement?.values[accountsStatement.columns.indexOf('extra_config')]).toBe('{"platformUserId":42,"credentialMode":"session"}');
    expect(tokenRoutesStatement?.values[tokenRoutesStatement.columns.indexOf('model_mapping')]).toBe('{"gpt-4.1":"gpt-4o-mini"}');
    expect(tokenRoutesStatement?.values[tokenRoutesStatement.columns.indexOf('decision_snapshot')]).toBe('{"matched":true,"routeId":3}');
    expect(proxyLogsStatement?.values[proxyLogsStatement.columns.indexOf('billing_details')]).toBe('{"source":"pricing","usd":1.25}');
    expect(proxyVideoTasksStatement?.values[proxyVideoTasksStatement.columns.indexOf('status_snapshot')]).toBe('{"status":"done"}');
    expect(proxyVideoTasksStatement?.values[proxyVideoTasksStatement.columns.indexOf('upstream_response_meta')]).toBe('{"id":"video"}');
    expect(downstreamKeysStatement?.values[downstreamKeysStatement.columns.indexOf('supported_models')]).toBe('["gpt-4.1"]');
    expect(downstreamKeysStatement?.values[downstreamKeysStatement.columns.indexOf('allowed_route_ids')]).toBe('[3]');
    expect(downstreamKeysStatement?.values[downstreamKeysStatement.columns.indexOf('site_weight_multipliers')]).toBe('{"1":2}');
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
