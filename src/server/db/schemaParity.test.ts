import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import type { SchemaContract } from './schemaContract.js';
import { SHARED_INDEX_COMPATIBILITY_SPECS } from './sharedIndexSchemaCompatibility.js';

const dbDir = dirname(fileURLToPath(import.meta.url));
const generatedDir = resolve(dbDir, 'generated');
const supportPaths = [
  resolve(dbDir, 'runtimeSchemaBootstrap.ts'),
  resolve(dbDir, 'siteSchemaCompatibility.ts'),
  resolve(dbDir, 'routeGroupingSchemaCompatibility.ts'),
  resolve(dbDir, 'proxyFileSchemaCompatibility.ts'),
  resolve(dbDir, 'accountTokenSchemaCompatibility.ts'),
  resolve(dbDir, 'sharedIndexSchemaCompatibility.ts'),
];
const schemaContractPath = resolve(generatedDir, 'schemaContract.json');

function extractAllMatches(content: string, pattern: RegExp): string[] {
  return Array.from(content.matchAll(pattern), (match) => match[1]);
}

describe('database schema parity', () => {
  it('keeps generated schema artifacts present', () => {
    const artifactPaths = [
      schemaContractPath,
      resolve(generatedDir, 'mysql.bootstrap.sql'),
      resolve(generatedDir, 'mysql.upgrade.sql'),
      resolve(generatedDir, 'postgres.bootstrap.sql'),
      resolve(generatedDir, 'postgres.upgrade.sql'),
    ];

    for (const artifactPath of artifactPaths) {
      expect(existsSync(artifactPath), artifactPath).toBe(true);
      expect(readFileSync(artifactPath, 'utf8').trim().length).toBeGreaterThan(0);
    }
  });

  it('keeps runtime support modules scoped to contract-defined tables and indexes', () => {
    const contract = JSON.parse(readFileSync(schemaContractPath, 'utf8')) as SchemaContract;
    const supportContent = supportPaths
      .map((filePath) => readFileSync(filePath, 'utf8'))
      .join('\n');

    const knownTables = new Set(Object.keys(contract.tables));
    const knownIndexes = new Set([
      ...contract.indexes.map((index) => index.name),
      ...contract.uniques.map((unique) => unique.name),
    ]);

    const supportTables = extractAllMatches(
      supportContent,
      /(?:CREATE TABLE IF NOT EXISTS|ALTER TABLE|INSERT INTO)\s+["`]?([a-z_][a-z0-9_]*)["`]?/gi,
    );
    const supportIndexes = extractAllMatches(
      supportContent,
      /(?:CREATE UNIQUE INDEX(?: IF NOT EXISTS)?|CREATE INDEX(?: IF NOT EXISTS)?|indexName:\s*')["`]?([a-z_][a-z0-9_]*)/gi,
    );

    const unknownTables = [...new Set(supportTables)].filter((tableName) => !knownTables.has(tableName)).sort();
    const unknownIndexes = [...new Set(supportIndexes)].filter((indexName) => !knownIndexes.has(indexName)).sort();

    expect(unknownTables).toEqual([]);
    expect(unknownIndexes).toEqual([]);
  });

  it('does not duplicate contract-defined indexes inside shared index compatibility specs', () => {
    const contract = JSON.parse(readFileSync(schemaContractPath, 'utf8')) as SchemaContract;
    const contractIndexNames = new Set([
      ...contract.indexes.map((index) => index.name),
      ...contract.uniques.map((unique) => unique.name),
    ]);

    const duplicatedSpecs = SHARED_INDEX_COMPATIBILITY_SPECS
      .map((spec) => spec.indexName)
      .filter((indexName) => contractIndexNames.has(indexName));

    expect(duplicatedSpecs).toEqual([]);
  });

  it('keeps proxy_logs downstream api key schema in the generated contract artifacts', () => {
    const contract = JSON.parse(readFileSync(schemaContractPath, 'utf8')) as SchemaContract;
    const mysqlBootstrap = readFileSync(resolve(generatedDir, 'mysql.bootstrap.sql'), 'utf8');
    const postgresBootstrap = readFileSync(resolve(generatedDir, 'postgres.bootstrap.sql'), 'utf8');

    expect(contract.tables.proxy_logs?.columns.downstream_api_key_id?.logicalType).toBe('integer');
    expect(contract.tables.proxy_logs?.columns.is_stream?.logicalType).toBe('boolean');
    expect(contract.tables.proxy_logs?.columns.first_byte_latency_ms?.logicalType).toBe('integer');
    expect(contract.tables.proxy_logs?.columns.client_app_id?.logicalType).toBe('text');
    expect(contract.tables.proxy_logs?.columns.client_family?.logicalType).toBe('text');
    expect(contract.indexes.some((index) => index.name === 'proxy_logs_downstream_api_key_created_at_idx')).toBe(true);
    expect(contract.indexes.some((index) => index.name === 'proxy_logs_client_app_id_created_at_idx')).toBe(true);
    expect(contract.indexes.some((index) => index.name === 'proxy_logs_client_family_created_at_idx')).toBe(true);
    expect(mysqlBootstrap).toContain('`downstream_api_key_id`');
    expect(mysqlBootstrap).toContain('`is_stream`');
    expect(mysqlBootstrap).toContain('`first_byte_latency_ms`');
    expect(mysqlBootstrap).toContain('`proxy_logs_downstream_api_key_created_at_idx`');
    expect(mysqlBootstrap).toContain('`client_app_id`');
    expect(mysqlBootstrap).toContain('`proxy_logs_client_app_id_created_at_idx`');
    expect(postgresBootstrap).toContain('"downstream_api_key_id"');
    expect(postgresBootstrap).toContain('"is_stream"');
    expect(postgresBootstrap).toContain('"first_byte_latency_ms"');
    expect(postgresBootstrap).toContain('"proxy_logs_downstream_api_key_created_at_idx"');
    expect(postgresBootstrap).toContain('"client_app_id"');
    expect(postgresBootstrap).toContain('"proxy_logs_client_app_id_created_at_idx"');
  });
});
