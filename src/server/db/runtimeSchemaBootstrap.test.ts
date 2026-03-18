import baselineContract from './generated/fixtures/2026-03-14-baseline.schemaContract.json' with { type: 'json' };
import currentContract from './generated/schemaContract.json' with { type: 'json' };
import { classifyLegacyCompatMutation } from './legacySchemaCompat.js';
import { generateUpgradeSql } from './schemaArtifactGenerator.js';
import type { SchemaContract, SchemaContractColumn } from './schemaContract.js';
import { describe, expect, it } from 'vitest';
import {
  __runtimeSchemaBootstrapTestUtils,
  ensureRuntimeDatabaseSchema,
  type RuntimeSchemaClient,
  type RuntimeSchemaDialect,
} from './runtimeSchemaBootstrap.js';

function createStubClient(dialect: RuntimeSchemaDialect, executedSql: string[]): RuntimeSchemaClient {
  return {
    dialect,
    begin: async () => {},
    commit: async () => {},
    rollback: async () => {},
    execute: async (sqlText: string) => {
      if (sqlText.trim().toLowerCase().startsWith('select')) {
        return [];
      }
      executedSql.push(sqlText);
      return [];
    },
    queryScalar: async (sqlText: string, params: unknown[] = []) => {
      if (sqlText.includes('information_schema') || sqlText.includes('sqlite_master') || sqlText.includes('pragma_table_info')) {
        return 1;
      }
      if (params.length > 0) {
        return 1;
      }
      return 0;
    },
    close: async () => {},
  };
}

function makeColumn(overrides: Partial<SchemaContractColumn> = {}): SchemaContractColumn {
  return {
    logicalType: 'text',
    notNull: false,
    defaultValue: null,
    primaryKey: false,
    ...overrides,
  };
}

describe('runtime schema bootstrap', () => {
  it.each(['mysql', 'postgres'] as const)('executes live-schema upgrade statements for %s', async (dialect) => {
    const executedSql: string[] = [];
    const expectedUpgradeSql = __runtimeSchemaBootstrapTestUtils.splitSqlStatements(
      generateUpgradeSql(dialect, currentContract, baselineContract),
    );

    await ensureRuntimeDatabaseSchema(createStubClient(dialect, executedSql), {
      currentContract,
      liveContract: baselineContract,
    });

    expect(executedSql.slice(0, expectedUpgradeSql.length)).toEqual(expectedUpgradeSql);
  });

  it('skips external schema execution when live schema already matches the current contract', async () => {
    const executedSql: string[] = [];
    const expectedUpgradeSql = __runtimeSchemaBootstrapTestUtils.buildExternalUpgradeStatements(
      'mysql',
      currentContract,
      currentContract,
    );

    await ensureRuntimeDatabaseSchema(createStubClient('mysql', executedSql), {
      currentContract,
      liveContract: currentContract,
    });

    expect(expectedUpgradeSql).toEqual([]);
    expect(executedSql.every((sqlText) => classifyLegacyCompatMutation(sqlText) === 'legacy')).toBe(true);
  });

  it('tolerates non-additive live-schema drift and still emits additive runtime patch statements', () => {
    const driftedLiveContract = __runtimeSchemaBootstrapTestUtils.cloneContract(currentContract);

    delete driftedLiveContract.tables.model_availability?.columns.is_manual;
    if (driftedLiveContract.tables.sites?.columns.status) {
      driftedLiveContract.tables.sites.columns.status.defaultValue = null;
    }
    driftedLiveContract.indexes = driftedLiveContract.indexes.filter((index) => index.name !== 'accounts_site_id_idx');
    driftedLiveContract.uniques = driftedLiveContract.uniques.filter((unique) => unique.name !== 'proxy_files_public_id_unique');

    const statements = __runtimeSchemaBootstrapTestUtils.buildExternalUpgradeStatements(
      'mysql',
      currentContract,
      driftedLiveContract,
    );

    expect(statements.some((sqlText) => sqlText.includes('ALTER TABLE `model_availability` ADD COLUMN `is_manual`'))).toBe(true);
    expect(statements.some((sqlText) => sqlText.includes('CREATE INDEX `accounts_site_id_idx`'))).toBe(true);
    expect(statements.some((sqlText) => sqlText.includes('CREATE UNIQUE INDEX `proxy_files_public_id_unique`'))).toBe(true);
  });

  it('ignores duplicate mysql index and column errors when replaying additive schema statements', async () => {
    const executedSql: string[] = [];
    const duplicateColumnSql = __runtimeSchemaBootstrapTestUtils.splitSqlStatements(
      generateUpgradeSql('mysql', currentContract, baselineContract),
    ).find((sqlText) => sqlText.includes('ALTER TABLE `model_availability` ADD COLUMN `is_manual`'));
    const duplicateIndexSql = __runtimeSchemaBootstrapTestUtils.splitSqlStatements(
      generateUpgradeSql('mysql', currentContract, baselineContract),
    ).find((sqlText) => sqlText.includes('proxy_files_public_id_unique'));

    expect(duplicateColumnSql).toBeDefined();
    expect(duplicateIndexSql).toBeDefined();

    await ensureRuntimeDatabaseSchema({
      ...createStubClient('mysql', executedSql),
      execute: async (sqlText: string) => {
        executedSql.push(sqlText);
        if (sqlText === duplicateColumnSql) {
          const error = new Error("Duplicate column name 'is_manual'") as Error & { code?: string };
          error.code = 'ER_DUP_FIELDNAME';
          throw error;
        }
        if (sqlText === duplicateIndexSql) {
          const error = new Error("Duplicate key name 'model_availability_account_model_unique'") as Error & { code?: string };
          error.code = 'ER_DUP_KEYNAME';
          throw error;
        }
        return [];
      },
    }, {
      currentContract,
      liveContract: baselineContract,
    });

    expect(executedSql).toContain(duplicateColumnSql);
    expect(executedSql).toContain(duplicateIndexSql);
  });

  it('ignores postgres relation-already-exists errors when replaying additive schema statements', async () => {
    const executedSql: string[] = [];
    const targetSql = __runtimeSchemaBootstrapTestUtils.splitSqlStatements(
      generateUpgradeSql('postgres', currentContract, baselineContract),
    ).find((sqlText) => sqlText.includes('proxy_files_public_id_unique'));

    expect(targetSql).toBeDefined();

    await ensureRuntimeDatabaseSchema({
      ...createStubClient('postgres', executedSql),
      execute: async (sqlText: string) => {
        executedSql.push(sqlText);
        if (sqlText === targetSql) {
          const error = new Error('relation "model_availability_account_model_unique" already exists') as Error & { code?: string };
          error.code = '42P07';
          throw error;
        }
        return [];
      },
    }, {
      currentContract,
      liveContract: baselineContract,
    });

    expect(executedSql).toContain(targetSql);
  });

  it('adds mysql text prefixes for new indexes when live datetime-like columns are still stored as text', async () => {
    const executedSql: string[] = [];
    const minimalContract: SchemaContract = {
      tables: {
        proxy_logs: {
          columns: {
            downstream_api_key_id: makeColumn({ logicalType: 'integer' }),
            created_at: makeColumn({ logicalType: 'datetime', defaultValue: "datetime('now')" }),
          },
        },
      },
      indexes: [
        {
          name: 'proxy_logs_downstream_api_key_created_at_idx',
          table: 'proxy_logs',
          columns: ['downstream_api_key_id', 'created_at'],
          unique: false,
        },
      ],
      uniques: [],
      foreignKeys: [],
    };

    await ensureRuntimeDatabaseSchema({
      ...createStubClient('mysql', executedSql),
      execute: async (sqlText: string) => {
        if (sqlText.includes('FROM information_schema.columns')) {
          return [[
            {
              table_name: 'proxy_logs',
              column_name: 'downstream_api_key_id',
              data_type: 'int',
              column_type: 'int',
            },
            {
              table_name: 'proxy_logs',
              column_name: 'created_at',
              data_type: 'text',
              column_type: 'text',
            },
          ]];
        }

        executedSql.push(sqlText);
        return [];
      },
      queryScalar: async (sqlText: string, params: unknown[] = []) => {
        if (sqlText.includes('information_schema.tables')) {
          return params[0] === 'proxy_logs' ? 1 : 0;
        }
        if (sqlText.includes('information_schema.columns')) {
          return 1;
        }
        return 0;
      },
    }, {
      currentContract: minimalContract,
      liveContract: {
        ...minimalContract,
        indexes: [],
      },
    });

    expect(executedSql).toContain(
      'CREATE INDEX `proxy_logs_downstream_api_key_created_at_idx` ON `proxy_logs` (`downstream_api_key_id`, `created_at`(191))',
    );
  });

  it('does not add mysql text prefixes when live indexed text columns are varchar-backed', async () => {
    const executedSql: string[] = [];
    const minimalContract: SchemaContract = {
      tables: {
        sites: {
          columns: {
            platform: makeColumn({ logicalType: 'text', notNull: true }),
            url: makeColumn({ logicalType: 'text', notNull: true }),
          },
        },
      },
      indexes: [],
      uniques: [
        {
          name: 'sites_platform_url_unique',
          table: 'sites',
          columns: ['platform', 'url'],
        },
      ],
      foreignKeys: [],
    };

    await ensureRuntimeDatabaseSchema({
      ...createStubClient('mysql', executedSql),
      execute: async (sqlText: string) => {
        if (sqlText.includes('FROM information_schema.columns')) {
          return [[
            {
              table_name: 'sites',
              column_name: 'platform',
              data_type: 'varchar',
              column_type: 'varchar(32)',
            },
            {
              table_name: 'sites',
              column_name: 'url',
              data_type: 'varchar',
              column_type: 'varchar(255)',
            },
          ]];
        }

        executedSql.push(sqlText);
        return [];
      },
      queryScalar: async (sqlText: string, params: unknown[] = []) => {
        if (sqlText.includes('information_schema.tables')) {
          return params[0] === 'sites' ? 1 : 0;
        }
        if (sqlText.includes('information_schema.columns')) {
          return 1;
        }
        return 0;
      },
    }, {
      currentContract: minimalContract,
      liveContract: {
        ...minimalContract,
        uniques: [],
      },
    });

    expect(executedSql).toContain(
      'CREATE UNIQUE INDEX `sites_platform_url_unique` ON `sites` (`platform`, `url`)',
    );
    expect(executedSql).not.toContain(
      'CREATE UNIQUE INDEX `sites_platform_url_unique` ON `sites` (`platform`(191), `url`(191))',
    );
  });
});
