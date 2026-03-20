import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { generateDialectArtifacts } from './schemaArtifactGenerator.js';
import type { SchemaContract } from './schemaContract.js';
import * as schema from './schema.js';

const dbDir = dirname(fileURLToPath(import.meta.url));
const schemaContractPath = resolve(dbDir, 'generated/schemaContract.json');

function readSchemaContract(): SchemaContract {
  return JSON.parse(readFileSync(schemaContractPath, 'utf8')) as SchemaContract;
}

describe('site announcements schema', () => {
  it('declares the site_announcements table in the Drizzle schema', () => {
    expect(schema.siteAnnouncements).toBeDefined();
  });

  it('keeps site_announcements in the generated schema contract', () => {
    const contract = readSchemaContract();
    const table = contract.tables.site_announcements;

    expect(table).toBeDefined();
    expect(table?.columns.site_id?.logicalType).toBe('integer');
    expect(table?.columns.source_key?.logicalType).toBe('text');
    expect(table?.columns.first_seen_at?.logicalType).toBe('datetime');
    expect(table?.columns.last_seen_at?.logicalType).toBe('datetime');
    expect(table?.columns.read_at?.logicalType).toBe('datetime');
    expect(table?.columns.raw_payload?.logicalType).toBe('text');
    expect(contract.indexes.some((index) => index.name === 'site_announcements_site_id_first_seen_at_idx')).toBe(true);
    expect(contract.indexes.some((index) => index.name === 'site_announcements_read_at_idx')).toBe(true);
    expect(contract.uniques.some((unique) => unique.name === 'site_announcements_site_source_key_unique')).toBe(true);
  });

  it('emits bootstrap sql for the site_announcements table', () => {
    const artifacts = generateDialectArtifacts(readSchemaContract());

    expect(artifacts.mysqlBootstrap).toContain('CREATE TABLE IF NOT EXISTS `site_announcements`');
    expect(artifacts.mysqlBootstrap).toContain("`first_seen_at` VARCHAR(191) DEFAULT (DATE_FORMAT(NOW(), '%Y-%m-%d %H:%i:%s'))");
    expect(artifacts.mysqlBootstrap).toContain('`upstream_created_at` VARCHAR(191)');
    expect(artifacts.mysqlBootstrap).toContain('`site_announcements_site_source_key_unique`');
    expect(artifacts.postgresBootstrap).toContain('CREATE TABLE IF NOT EXISTS "site_announcements"');
    expect(artifacts.postgresBootstrap).toContain(`"first_seen_at" TEXT DEFAULT to_char(timezone('UTC', CURRENT_TIMESTAMP), 'YYYY-MM-DD HH24:MI:SS')`);
    expect(artifacts.postgresBootstrap).toContain('"upstream_created_at" TEXT');
    expect(artifacts.postgresBootstrap).toContain('"site_announcements_site_source_key_unique"');
  });
});
