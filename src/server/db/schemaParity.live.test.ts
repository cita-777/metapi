import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import type { SchemaContract } from './schemaContract.js';
import { introspectLiveSchema, materializeFreshSchema } from './schemaIntrospection.js';

const dbDir = dirname(fileURLToPath(import.meta.url));
const schemaContractPath = resolve(dbDir, 'generated/schemaContract.json');
const contract = JSON.parse(readFileSync(schemaContractPath, 'utf8')) as SchemaContract;

const skipLiveSchema = process.env.DB_PARITY_SKIP_LIVE_SCHEMA === 'true';
const sqliteParity = !skipLiveSchema && process.env.DB_PARITY_SQLITE !== 'false' ? it : it.skip;
const mysqlParity = process.env.DB_PARITY_MYSQL_URL ? it : it.skip;
const postgresParity = process.env.DB_PARITY_POSTGRES_URL ? it : it.skip;

describe('live schema parity', () => {
  sqliteParity('matches the contract for sqlite', async () => {
    const sqliteUrl = await materializeFreshSchema('sqlite');
    const live = await introspectLiveSchema({ dialect: 'sqlite', connectionString: sqliteUrl });
    expect(live).toEqual(contract);
  });

  mysqlParity('matches the contract for mysql', async () => {
    const mysqlUrl = await materializeFreshSchema('mysql', {
      connectionString: process.env.DB_PARITY_MYSQL_URL!,
    });
    const live = await introspectLiveSchema({ dialect: 'mysql', connectionString: mysqlUrl });
    expect(live).toEqual(contract);
  });

  postgresParity('matches the contract for postgres', async () => {
    const postgresUrl = await materializeFreshSchema('postgres', {
      connectionString: process.env.DB_PARITY_POSTGRES_URL!,
    });
    const live = await introspectLiveSchema({ dialect: 'postgres', connectionString: postgresUrl });
    expect(live).toEqual(contract);
  });
});
