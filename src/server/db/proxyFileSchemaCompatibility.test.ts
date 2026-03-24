import { describe, expect, it } from 'vitest';

import {
  ensureProxyFileSchemaCompatibility,
  type ProxyFileSchemaInspector,
} from './proxyFileSchemaCompatibility.js';

function createInspector(
  dialect: ProxyFileSchemaInspector['dialect'],
  options?: {
    hasTable?: boolean;
    existingColumns?: string[];
  },
) {
  const executedSql: string[] = [];
  const hasTable = options?.hasTable ?? false;
  const existingColumns = new Set(options?.existingColumns ?? []);

  const inspector: ProxyFileSchemaInspector = {
    dialect,
    async tableExists(table) {
      return table === 'proxy_files' && hasTable;
    },
    async columnExists(table, column) {
      return table === 'proxy_files' && existingColumns.has(column);
    },
    async execute(sqlText) {
      executedSql.push(sqlText);
    },
  };

  return { inspector, executedSql };
}

describe('ensureProxyFileSchemaCompatibility', () => {
  it.each([
    {
      dialect: 'postgres' as const,
      createPattern: /create table/i,
      uniqueIndexPattern: /create unique index/i,
      ownerIndexPattern: /owner_lookup_idx/i,
    },
    {
      dialect: 'mysql' as const,
      createPattern: /create table/i,
      uniqueIndexPattern: /create unique index/i,
      ownerIndexPattern: /owner_lookup_idx/i,
    },
    {
      dialect: 'sqlite' as const,
      createPattern: /create table/i,
      uniqueIndexPattern: /create unique index/i,
      ownerIndexPattern: /owner_lookup_idx/i,
    },
  ])('creates proxy_files table and indexes for $dialect', async ({ dialect, createPattern, uniqueIndexPattern, ownerIndexPattern }) => {
    const { inspector, executedSql } = createInspector(dialect);

    await ensureProxyFileSchemaCompatibility(inspector);

    expect(executedSql.some((sqlText) => createPattern.test(sqlText) && /proxy_files/i.test(sqlText))).toBe(true);
    expect(executedSql.some((sqlText) => uniqueIndexPattern.test(sqlText) && /proxy_files_public_id_unique/i.test(sqlText))).toBe(true);
    expect(executedSql.some((sqlText) => ownerIndexPattern.test(sqlText))).toBe(true);
  });

  it('emits MySQL indexes compatible with generated bootstrap SQL', async () => {
    const { inspector, executedSql } = createInspector('mysql');

    await ensureProxyFileSchemaCompatibility(inspector);

    expect(executedSql).toContain(
      'CREATE UNIQUE INDEX `proxy_files_public_id_unique` ON `proxy_files` (`public_id`(191))',
    );
    expect(executedSql).toContain(
      'CREATE INDEX `proxy_files_owner_lookup_idx` ON `proxy_files` (`owner_type`(64), `owner_id`(191), `deleted_at`(191))',
    );
  });

  it('adds missing columns on existing table before ensuring indexes', async () => {
    const { inspector, executedSql } = createInspector('postgres', {
      hasTable: true,
      existingColumns: ['public_id', 'owner_type', 'owner_id'],
    });

    await ensureProxyFileSchemaCompatibility(inspector);

    expect(executedSql.some((sqlText) => sqlText.includes('ADD COLUMN "purpose"'))).toBe(true);
    expect(executedSql.some((sqlText) => sqlText.includes('ADD COLUMN "filename"'))).toBe(true);
    expect(executedSql.some((sqlText) => sqlText.includes('ADD COLUMN "deleted_at"'))).toBe(true);
    expect(executedSql.some((sqlText) => sqlText.includes('proxy_files_public_id_unique'))).toBe(true);
  });
});
