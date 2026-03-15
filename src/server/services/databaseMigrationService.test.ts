import currentContract from '../db/generated/schemaContract.json' with { type: 'json' };
import { describe, expect, it } from 'vitest';
import {
  __databaseMigrationServiceTestUtils,
  maskConnectionString,
  normalizeMigrationInput,
} from './databaseMigrationService.js';

function cloneContract<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
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
        tokenRoutes: [],
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
  });
});
