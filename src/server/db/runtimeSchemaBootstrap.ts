import Database from 'better-sqlite3';
import mysql from 'mysql2/promise';
import pg from 'pg';
import { mkdirSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import {
  ensureLegacySchemaCompatibility,
  type LegacySchemaCompatInspector,
} from './legacySchemaCompat.js';
import { generateBootstrapSql, generateUpgradeSql } from './schemaArtifactGenerator.js';
import { introspectLiveSchema } from './schemaIntrospection.js';
import { resolveGeneratedSchemaContractPath, type SchemaContract } from './schemaContract.js';

export type RuntimeSchemaDialect = 'sqlite' | 'mysql' | 'postgres';

export interface RuntimeSchemaClient {
  dialect: RuntimeSchemaDialect;
  connectionString: string;
  ssl: boolean;
  begin(): Promise<void>;
  commit(): Promise<void>;
  rollback(): Promise<void>;
  execute(sqlText: string, params?: unknown[]): Promise<unknown>;
  queryScalar(sqlText: string, params?: unknown[]): Promise<number>;
  close(): Promise<void>;
}

export interface RuntimeSchemaConnectionInput {
  dialect: RuntimeSchemaDialect;
  connectionString: string;
  ssl?: boolean;
}

function normalizeSchemaErrorMessage(error: unknown): string {
  if (typeof error === 'object' && error && 'message' in error) {
    return String((error as { message?: unknown }).message || '');
  }
  return String(error || '');
}

function isExistingSchemaObjectError(error: unknown): boolean {
  const lowered = normalizeSchemaErrorMessage(error).toLowerCase();
  const code = typeof error === 'object' && error && 'code' in error
    ? String((error as { code?: unknown }).code || '')
    : '';

  return code === 'ER_DUP_KEYNAME'
    || code === 'ER_DUP_FIELDNAME'
    || code === 'ER_TABLE_EXISTS_ERROR'
    || code === '42P07'
    || code === '42701'
    || code === '42710'
    || lowered.includes('already exists')
    || lowered.includes('duplicate column')
    || lowered.includes('duplicate key name')
    || lowered.includes('relation') && lowered.includes('already exists');
}

async function executeBootstrapStatement(client: RuntimeSchemaClient, sqlText: string): Promise<void> {
  try {
    await client.execute(sqlText);
  } catch (error) {
    if (!isExistingSchemaObjectError(error)) {
      throw error;
    }
  }
}

function validateIdentifier(identifier: string): string {
  if (!/^[a-z_][a-z0-9_]*$/i.test(identifier)) {
    throw new Error(`Invalid SQL identifier: ${identifier}`);
  }
  return identifier;
}

function createLegacySchemaInspector(client: RuntimeSchemaClient): LegacySchemaCompatInspector {
  if (client.dialect === 'sqlite') {
    return {
      dialect: 'sqlite',
      tableExists: async (table) => {
        const normalizedTable = validateIdentifier(table);
        return (await client.queryScalar(
          `SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = '${normalizedTable}'`,
        )) > 0;
      },
      columnExists: async (table, column) => {
        const normalizedTable = validateIdentifier(table);
        const normalizedColumn = validateIdentifier(column);
        return (await client.queryScalar(
          `SELECT COUNT(*) FROM pragma_table_info('${normalizedTable}') WHERE name = '${normalizedColumn}'`,
        )) > 0;
      },
      execute: async (sqlText) => {
        await client.execute(sqlText);
      },
    };
  }

  if (client.dialect === 'mysql') {
    return {
      dialect: 'mysql',
      tableExists: async (table) => {
        return (await client.queryScalar(
          'SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = ?',
          [table],
        )) > 0;
      },
      columnExists: async (table, column) => {
        return (await client.queryScalar(
          'SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ?',
          [table, column],
        )) > 0;
      },
      execute: async (sqlText) => {
        await client.execute(sqlText);
      },
    };
  }

  return {
    dialect: 'postgres',
    tableExists: async (table) => {
      return (await client.queryScalar(
        'SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = $1',
        [table],
      )) > 0;
    },
    columnExists: async (table, column) => {
      return (await client.queryScalar(
        'SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = $1 AND column_name = $2',
        [table, column],
      )) > 0;
    },
    execute: async (sqlText) => {
      await client.execute(sqlText);
    },
  };
}

function splitSqlStatements(sqlText: string): string[] {
  const withoutCommentLines = sqlText
    .split(/\r?\n/g)
    .filter((line) => !line.trim().startsWith('--'))
    .join('\n');

  return withoutCommentLines
    .split(/;\s*(?:\r?\n|$)/g)
    .map((statement) => statement.trim())
    .filter((statement) => statement.length > 0);
}

function readSchemaContract(): SchemaContract {
  return JSON.parse(readFileSync(resolveGeneratedSchemaContractPath(), 'utf8')) as SchemaContract;
}

function cloneContract(contract: SchemaContract): SchemaContract {
  return JSON.parse(JSON.stringify(contract)) as SchemaContract;
}

function serializeColumn(column: SchemaContract['tables'][string]['columns'][string]): string {
  return [
    column.logicalType,
    column.notNull ? 'not-null' : 'nullable',
    column.defaultValue ?? 'default:null',
    column.primaryKey ? 'pk' : 'non-pk',
  ].join('|');
}

function serializeIndex(index: SchemaContract['indexes'][number]): string {
  return [index.table, index.columns.join(','), index.unique ? 'unique' : 'non-unique'].join('|');
}

function serializeUnique(unique: SchemaContract['uniques'][number]): string {
  return [unique.table, unique.columns.join(',')].join('|');
}

function serializeForeignKey(foreignKey: SchemaContract['foreignKeys'][number]): string {
  return [
    foreignKey.table,
    foreignKey.columns.join(','),
    foreignKey.referencedTable,
    foreignKey.referencedColumns.join(','),
    foreignKey.onDelete ?? 'null',
  ].join('|');
}

function buildCompatibleRuntimeBaseline(
  currentContract: SchemaContract,
  liveContract: SchemaContract,
): SchemaContract {
  const baseline: SchemaContract = {
    tables: {},
    indexes: [],
    uniques: [],
    foreignKeys: [],
  };

  for (const [tableName, liveTable] of Object.entries(liveContract.tables)) {
    const currentTable = currentContract.tables[tableName];
    if (!currentTable) {
      continue;
    }

    const compatibleColumns = Object.fromEntries(
      Object.entries(liveTable.columns)
        .filter(([columnName, liveColumn]) => {
          const currentColumn = currentTable.columns[columnName];
          return currentColumn && serializeColumn(currentColumn) === serializeColumn(liveColumn);
        }),
    );

    baseline.tables[tableName] = { columns: compatibleColumns };
  }

  const currentIndexes = new Map(currentContract.indexes.map((index) => [index.name, index]));
  baseline.indexes = liveContract.indexes
    .filter((index) => {
      const currentIndex = currentIndexes.get(index.name);
      return currentIndex && serializeIndex(currentIndex) === serializeIndex(index);
    });

  const currentUniques = new Map(currentContract.uniques.map((unique) => [unique.name, unique]));
  baseline.uniques = liveContract.uniques
    .filter((unique) => {
      const currentUnique = currentUniques.get(unique.name);
      return currentUnique && serializeUnique(currentUnique) === serializeUnique(unique);
    });

  const currentForeignKeys = new Set(currentContract.foreignKeys.map(serializeForeignKey));
  baseline.foreignKeys = liveContract.foreignKeys
    .filter((foreignKey) => currentForeignKeys.has(serializeForeignKey(foreignKey)));

  return baseline;
}

async function createPostgresClient(connectionString: string, ssl: boolean): Promise<RuntimeSchemaClient> {
  const clientOptions: pg.ClientConfig = { connectionString };
  if (ssl) {
    clientOptions.ssl = { rejectUnauthorized: false };
  }
  const client = new pg.Client(clientOptions);
  await client.connect();

  return {
    dialect: 'postgres',
    connectionString,
    ssl,
    begin: async () => { await client.query('BEGIN'); },
    commit: async () => { await client.query('COMMIT'); },
    rollback: async () => { await client.query('ROLLBACK'); },
    execute: async (sqlText, params = []) => client.query(sqlText, params),
    queryScalar: async (sqlText, params = []) => {
      const result = await client.query(sqlText, params);
      const row = result.rows[0] as Record<string, unknown> | undefined;
      if (!row) return 0;
      return Number(Object.values(row)[0]) || 0;
    },
    close: async () => { await client.end(); },
  };
}

async function createMySqlClient(connectionString: string, ssl: boolean): Promise<RuntimeSchemaClient> {
  const connectionOptions: mysql.ConnectionOptions = { uri: connectionString };
  if (ssl) {
    connectionOptions.ssl = { rejectUnauthorized: false };
  }
  const connection = await mysql.createConnection(connectionOptions);

  return {
    dialect: 'mysql',
    connectionString,
    ssl,
    begin: async () => { await connection.beginTransaction(); },
    commit: async () => { await connection.commit(); },
    rollback: async () => { await connection.rollback(); },
    execute: async (sqlText, params = []) => connection.execute(sqlText, params as any[]),
    queryScalar: async (sqlText, params = []) => {
      const [rows] = await connection.query(sqlText, params as any[]);
      if (!Array.isArray(rows) || rows.length === 0) return 0;
      const row = rows[0] as Record<string, unknown>;
      return Number(Object.values(row)[0]) || 0;
    },
    close: async () => { await connection.end(); },
  };
}

async function createSqliteClient(connectionString: string): Promise<RuntimeSchemaClient> {
  const filePath = connectionString === ':memory:' ? ':memory:' : resolve(connectionString);
  if (filePath !== ':memory:') {
    mkdirSync(dirname(filePath), { recursive: true });
  }
  const sqlite = new Database(filePath);
  sqlite.pragma('journal_mode = WAL');
  sqlite.pragma('foreign_keys = ON');

  return {
    dialect: 'sqlite',
    connectionString,
    ssl: false,
    begin: async () => { sqlite.exec('BEGIN'); },
    commit: async () => { sqlite.exec('COMMIT'); },
    rollback: async () => { sqlite.exec('ROLLBACK'); },
    execute: async (sqlText, params = []) => {
      const lowered = sqlText.trim().toLowerCase();
      const statement = sqlite.prepare(sqlText);
      if (lowered.startsWith('select')) return statement.all(...params);
      return statement.run(...params);
    },
    queryScalar: async (sqlText, params = []) => {
      const row = sqlite.prepare(sqlText).get(...params) as Record<string, unknown> | undefined;
      if (!row) return 0;
      return Number(Object.values(row)[0]) || 0;
    },
    close: async () => { sqlite.close(); },
  };
}

export async function createRuntimeSchemaClient(input: RuntimeSchemaConnectionInput): Promise<RuntimeSchemaClient> {
  if (input.dialect === 'postgres') {
    return createPostgresClient(input.connectionString, !!input.ssl);
  }
  if (input.dialect === 'mysql') {
    return createMySqlClient(input.connectionString, !!input.ssl);
  }
  return createSqliteClient(input.connectionString);
}

type EnsureRuntimeDatabaseSchemaOptions = {
  currentContract?: SchemaContract;
  liveContract?: SchemaContract;
};

async function resolveLiveContract(client: RuntimeSchemaClient, liveContract?: SchemaContract): Promise<SchemaContract> {
  if (liveContract) {
    return liveContract;
  }

  return introspectLiveSchema({
    dialect: client.dialect,
    connectionString: client.connectionString,
    ssl: client.ssl,
  });
}

function buildExternalUpgradeStatements(
  dialect: Exclude<RuntimeSchemaDialect, 'sqlite'>,
  currentContract: SchemaContract,
  liveContract: SchemaContract,
): string[] {
  const compatibleBaseline = buildCompatibleRuntimeBaseline(currentContract, liveContract);
  return splitSqlStatements(generateUpgradeSql(dialect, currentContract, compatibleBaseline));
}

export async function ensureRuntimeDatabaseSchema(
  client: RuntimeSchemaClient,
  options: EnsureRuntimeDatabaseSchemaOptions = {},
): Promise<void> {
  const currentContract = options.currentContract ?? readSchemaContract();
  const statements = client.dialect === 'sqlite'
    ? splitSqlStatements(generateBootstrapSql('sqlite', currentContract))
    : buildExternalUpgradeStatements(
      client.dialect,
      currentContract,
      await resolveLiveContract(client, options.liveContract),
    );

  for (const sqlText of statements) {
    await executeBootstrapStatement(client, sqlText);
  }

  await ensureLegacySchemaCompatibility(createLegacySchemaInspector(client));
}

export async function bootstrapRuntimeDatabaseSchema(input: RuntimeSchemaConnectionInput): Promise<void> {
  const client = await createRuntimeSchemaClient(input);
  try {
    await ensureRuntimeDatabaseSchema(client);
  } finally {
    await client.close();
  }
}

export const __runtimeSchemaBootstrapTestUtils = {
  buildCompatibleRuntimeBaseline,
  cloneContract,
  splitSqlStatements,
  buildExternalUpgradeStatements,
};
