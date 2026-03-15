import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { generateDialectArtifacts, type GeneratedDialectArtifacts } from './schemaArtifactGenerator.js';
import type { SchemaContract, SchemaContractColumn } from './schemaContract.js';

const dbDir = dirname(fileURLToPath(import.meta.url));
const schemaContractPath = resolve(dbDir, 'generated/schemaContract.json');

function readSchemaContract(): SchemaContract {
  return JSON.parse(readFileSync(schemaContractPath, 'utf8')) as SchemaContract;
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

describe('schema artifact generator', () => {
  it('generates bootstrap sql for mysql and postgres from the contract', () => {
    const artifacts = generateDialectArtifacts(readSchemaContract());

    expect(artifacts.mysqlBootstrap).toContain('CREATE TABLE IF NOT EXISTS `sites`');
    expect(artifacts.mysqlBootstrap).toContain('CREATE TABLE IF NOT EXISTS `site_disabled_models`');
    expect(artifacts.postgresBootstrap).toContain('CREATE TABLE IF NOT EXISTS "account_tokens"');
    expect(artifacts.postgresBootstrap).toContain('"token_group"');
  });

  it('generates additive upgrade sql for newly added tables, columns, indexes, and uniques', () => {
    const previousContract: SchemaContract = {
      tables: {
        sites: {
          columns: {
            id: makeColumn({ logicalType: 'integer', notNull: true, primaryKey: true }),
          },
        },
      },
      indexes: [],
      uniques: [],
      foreignKeys: [],
    };
    const currentContract: SchemaContract = {
      tables: {
        sites: {
          columns: {
            id: makeColumn({ logicalType: 'integer', notNull: true, primaryKey: true }),
            status: makeColumn({ notNull: true, defaultValue: "'active'" }),
          },
        },
        accounts: {
          columns: {
            id: makeColumn({ logicalType: 'integer', notNull: true, primaryKey: true }),
            site_id: makeColumn({ logicalType: 'integer', notNull: true }),
            email: makeColumn({ notNull: true }),
          },
        },
      },
      indexes: [
        { name: 'sites_status_idx', table: 'sites', columns: ['status'], unique: false },
      ],
      uniques: [
        { name: 'accounts_site_email_unique', table: 'accounts', columns: ['site_id', 'email'] },
      ],
      foreignKeys: [
        {
          table: 'accounts',
          columns: ['site_id'],
          referencedTable: 'sites',
          referencedColumns: ['id'],
          onDelete: 'cascade',
        },
      ],
    };

    const artifacts: GeneratedDialectArtifacts = generateDialectArtifacts(currentContract, previousContract);

    expect(artifacts.mysqlUpgrade).toContain('CREATE TABLE IF NOT EXISTS `accounts`');
    expect(artifacts.mysqlUpgrade).toContain('ALTER TABLE `sites` ADD COLUMN `status`');
    expect(artifacts.mysqlUpgrade).toContain('CREATE INDEX `sites_status_idx` ON `sites`');
    expect(artifacts.mysqlUpgrade).toContain('CREATE UNIQUE INDEX `accounts_site_email_unique` ON `accounts`');
    expect(artifacts.postgresUpgrade).toContain('CREATE TABLE IF NOT EXISTS "accounts"');
    expect(artifacts.postgresUpgrade).toContain('ALTER TABLE "sites" ADD COLUMN "status"');
    expect(artifacts.postgresUpgrade).toContain('CREATE INDEX "sites_status_idx" ON "sites"');
    expect(artifacts.postgresUpgrade).toContain('CREATE UNIQUE INDEX "accounts_site_email_unique" ON "accounts"');
  });

  it('orders dependent tables safely and emits executable datetime defaults for external dialects', () => {
    const artifacts = generateDialectArtifacts(readSchemaContract());

    expect(
      artifacts.mysqlBootstrap.indexOf('CREATE TABLE IF NOT EXISTS `accounts`'),
    ).toBeLessThan(
      artifacts.mysqlBootstrap.indexOf('CREATE TABLE IF NOT EXISTS `account_tokens`'),
    );
    expect(
      artifacts.postgresBootstrap.indexOf('CREATE TABLE IF NOT EXISTS "accounts"'),
    ).toBeLessThan(
      artifacts.postgresBootstrap.indexOf('CREATE TABLE IF NOT EXISTS "account_tokens"'),
    );
    expect(artifacts.mysqlBootstrap).toContain('`created_at` DATETIME DEFAULT CURRENT_TIMESTAMP');
    expect(artifacts.postgresBootstrap).toContain('"created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP');
  });

  it('uses varchar for mysql text primary keys so bootstrap ddl stays executable', () => {
    const artifacts = generateDialectArtifacts(readSchemaContract());

    expect(artifacts.mysqlBootstrap).toContain('CREATE TABLE IF NOT EXISTS `settings` (`key` VARCHAR(191) NOT NULL PRIMARY KEY, `value` TEXT)');
    expect(artifacts.mysqlBootstrap).not.toContain('CREATE TABLE IF NOT EXISTS `settings` (`key` TEXT NOT NULL PRIMARY KEY, `value` TEXT)');
  });

  it('does not add mysql text prefixes to non-text index columns', () => {
    const artifacts = generateDialectArtifacts(readSchemaContract());

    expect(artifacts.mysqlBootstrap).toContain('CREATE INDEX `checkin_logs_account_created_at_idx` ON `checkin_logs` (`account_id`, `created_at`)');
    expect(artifacts.mysqlBootstrap).toContain('CREATE INDEX `events_read_created_at_idx` ON `events` (`read`, `created_at`)');
    expect(artifacts.mysqlBootstrap).not.toContain('`created_at`(191)');
    expect(artifacts.mysqlBootstrap).not.toContain('`read`(191)');
  });

  it('rejects destructive diffs when generating additive upgrades', () => {
    const current = readSchemaContract();
    const previous = structuredClone(current);

    delete current.tables.sites.columns.status;

    expect(() => generateDialectArtifacts(current, previous)).toThrow(/non-additive schema diff/i);
  });
});
