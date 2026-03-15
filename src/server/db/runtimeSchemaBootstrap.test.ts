import baselineContract from './generated/fixtures/2026-03-14-baseline.schemaContract.json' with { type: 'json' };
import currentContract from './generated/schemaContract.json' with { type: 'json' };
import { classifyLegacyCompatMutation } from './legacySchemaCompat.js';
import { generateUpgradeSql } from './schemaArtifactGenerator.js';
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
});
