import baselineContract from './generated/fixtures/2026-03-14-baseline.schemaContract.json' with { type: 'json' };
import currentContract from './generated/schemaContract.json' with { type: 'json' };
import mysql from 'mysql2/promise';
import pg from 'pg';
import { describe, expect, it } from 'vitest';
import { generateBootstrapSql } from './schemaArtifactGenerator.js';
import { __schemaIntrospectionTestUtils, introspectLiveSchema } from './schemaIntrospection.js';
import { bootstrapRuntimeDatabaseSchema } from './runtimeSchemaBootstrap.js';

const mysqlRuntime = process.env.DB_PARITY_MYSQL_URL ? it : it.skip;
const postgresRuntime = process.env.DB_PARITY_POSTGRES_URL ? it : it.skip;

async function resetMySqlSchema(connectionString: string): Promise<void> {
  const connection = await mysql.createConnection({ uri: connectionString });
  try {
    await connection.query('SET FOREIGN_KEY_CHECKS = 0');
    const [rows] = await connection.query(`
      SELECT table_name AS table_name
      FROM information_schema.tables
      WHERE table_schema = DATABASE()
        AND table_type = 'BASE TABLE'
    `);
    for (const row of rows as Array<Record<string, unknown>>) {
      const tableName = String(row.table_name || '');
      if (!tableName) continue;
      await connection.query(`DROP TABLE IF EXISTS \`${tableName}\``);
    }
    await connection.query('SET FOREIGN_KEY_CHECKS = 1');
  } finally {
    await connection.end();
  }
}

async function applyMySqlStatements(connectionString: string, statements: string[]): Promise<void> {
  const connection = await mysql.createConnection({ uri: connectionString });
  try {
    for (const statement of statements) {
      await connection.query(statement);
    }
  } finally {
    await connection.end();
  }
}

async function resetPostgresSchema(connectionString: string): Promise<void> {
  const client = new pg.Client({ connectionString });
  await client.connect();
  try {
    const result = await client.query(`
      SELECT tablename
      FROM pg_tables
      WHERE schemaname = current_schema()
      ORDER BY tablename ASC
    `);
    for (const row of result.rows as Array<{ tablename: string }>) {
      await client.query(`DROP TABLE IF EXISTS "${row.tablename}" CASCADE`);
    }
  } finally {
    await client.end();
  }
}

async function applyPostgresStatements(connectionString: string, statements: string[]): Promise<void> {
  const client = new pg.Client({ connectionString });
  await client.connect();
  try {
    for (const statement of statements) {
      await client.query(statement);
    }
  } finally {
    await client.end();
  }
}

describe('runtime schema bootstrap live upgrade path', () => {
  mysqlRuntime('upgrades mysql runtime schemas from an older live contract', async () => {
    const connectionString = process.env.DB_PARITY_MYSQL_URL!;
    const baselineStatements = __schemaIntrospectionTestUtils.splitSqlStatements(
      generateBootstrapSql('mysql', baselineContract),
    );

    await resetMySqlSchema(connectionString);
    await applyMySqlStatements(connectionString, baselineStatements);

    await bootstrapRuntimeDatabaseSchema({
      dialect: 'mysql',
      connectionString,
    });

    const live = await introspectLiveSchema({ dialect: 'mysql', connectionString });
    expect(live).toEqual(currentContract);
  });

  postgresRuntime('upgrades postgres runtime schemas from an older live contract', async () => {
    const connectionString = process.env.DB_PARITY_POSTGRES_URL!;
    const baselineStatements = __schemaIntrospectionTestUtils.splitSqlStatements(
      generateBootstrapSql('postgres', baselineContract),
    );

    await resetPostgresSchema(connectionString);
    await applyPostgresStatements(connectionString, baselineStatements);

    await bootstrapRuntimeDatabaseSchema({
      dialect: 'postgres',
      connectionString,
    });

    const live = await introspectLiveSchema({ dialect: 'postgres', connectionString });
    expect(live).toEqual(currentContract);
  });
});
