import baselineContract from './generated/fixtures/2026-03-14-baseline.schemaContract.json' with { type: 'json' };
import currentContract from './generated/schemaContract.json' with { type: 'json' };
import { applyContractFixtureThenUpgrade, introspectLiveSchema } from './schemaIntrospection.js';
import { describe, expect, it } from 'vitest';

const skipLiveSchema = process.env.DB_PARITY_SKIP_LIVE_SCHEMA === 'true';
const sqliteUpgrade = !skipLiveSchema && process.env.DB_PARITY_SQLITE !== 'false' ? it : it.skip;
const mysqlUpgrade = process.env.DB_PARITY_MYSQL_URL ? it : it.skip;
const postgresUpgrade = process.env.DB_PARITY_POSTGRES_URL ? it : it.skip;

describe('schema upgrade parity', () => {
  sqliteUpgrade('upgrades sqlite to the current contract', async () => {
    const sqliteUrl = await applyContractFixtureThenUpgrade('sqlite', baselineContract, currentContract);
    const live = await introspectLiveSchema({ dialect: 'sqlite', connectionString: sqliteUrl });
    expect(live).toEqual(currentContract);
  });

  mysqlUpgrade('upgrades mysql to the current contract', async () => {
    const mysqlUrl = await applyContractFixtureThenUpgrade('mysql', baselineContract, currentContract, {
      connectionString: process.env.DB_PARITY_MYSQL_URL!,
    });
    const live = await introspectLiveSchema({ dialect: 'mysql', connectionString: mysqlUrl });
    expect(live).toEqual(currentContract);
  });

  postgresUpgrade('upgrades postgres to the current contract', async () => {
    const postgresUrl = await applyContractFixtureThenUpgrade('postgres', baselineContract, currentContract, {
      connectionString: process.env.DB_PARITY_POSTGRES_URL!,
    });
    const live = await introspectLiveSchema({ dialect: 'postgres', connectionString: postgresUrl });
    expect(live).toEqual(currentContract);
  });
});
