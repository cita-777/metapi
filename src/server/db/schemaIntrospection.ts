import Database from 'better-sqlite3';
import { mkdtempSync, mkdirSync, readFileSync, readdirSync } from 'node:fs';
import mysql from 'mysql2/promise';
import { tmpdir } from 'node:os';
import pg from 'pg';
import { join, resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
import {
  generateBootstrapSql,
  generateUpgradeSql,
  resolveGeneratedArtifactPath,
} from './schemaArtifactGenerator.js';
import type {
  LogicalColumnType,
  SchemaContract,
  SchemaContractColumn,
  SchemaContractForeignKey,
  SchemaContractIndex,
  SchemaContractTable,
  SchemaContractUnique,
} from './schemaContract.js';
import { resolveMigrationsFolder } from './schemaContract.js';

export type SchemaIntrospectionDialect = 'sqlite' | 'mysql' | 'postgres';

export interface SchemaIntrospectionInput {
  dialect: SchemaIntrospectionDialect;
  connectionString: string;
  ssl?: boolean;
}

export interface MaterializeFreshSchemaOptions {
  connectionString?: string;
  ssl?: boolean;
}

export interface ApplyContractFixtureThenUpgradeOptions extends MaterializeFreshSchemaOptions {}

type SqliteTableInfoRow = {
  name: string;
  type: string;
  notnull: number;
  dflt_value: string | null;
  pk: number;
};

type SqliteIndexListRow = {
  name: string;
  unique: number;
};

type SqliteIndexInfoRow = {
  seqno: number;
  name: string;
};

type SqliteForeignKeyRow = {
  id: number;
  table: string;
  from: string;
  to: string;
  on_delete: string;
};

type MySqlColumnRow = {
  table_name: string;
  column_name: string;
  data_type: string;
  column_type: string;
  is_nullable: 'YES' | 'NO';
  column_default: string | null;
};

type MySqlPrimaryKeyRow = {
  table_name: string;
  column_name: string;
};

type MySqlIndexRow = {
  table_name: string;
  index_name: string;
  column_name: string;
  non_unique: number;
};

type MySqlForeignKeyRow = {
  table_name: string;
  constraint_name: string;
  column_name: string;
  referenced_table_name: string;
  referenced_column_name: string;
  delete_rule: string | null;
};

type PostgresColumnRow = {
  table_name: string;
  column_name: string;
  data_type: string;
  udt_name: string;
  is_nullable: 'YES' | 'NO';
  column_default: string | null;
};

type PostgresPrimaryKeyRow = {
  table_name: string;
  column_name: string;
};

type PostgresIndexRow = {
  table_name: string;
  index_name: string;
  is_unique: boolean;
  column_name: string;
};

type PostgresForeignKeyRow = {
  table_name: string;
  constraint_name: string;
  column_name: string;
  referenced_table_name: string;
  referenced_column_name: string;
  delete_rule: string | null;
};

export function readMySqlField<T>(row: Record<string, unknown>, field: string): T | undefined {
  const exact = row[field];
  if (exact !== undefined) return exact as T;

  const upper = row[field.toUpperCase()];
  if (upper !== undefined) return upper as T;

  const lower = row[field.toLowerCase()];
  if (lower !== undefined) return lower as T;

  const matchedKey = Object.keys(row).find((key) => key.toLowerCase() === field.toLowerCase());
  return matchedKey ? row[matchedKey] as T : undefined;
}

function splitMigrationStatements(sqlText: string): string[] {
  return sqlText
    .split('--> statement-breakpoint')
    .map((statement) => statement.trim())
    .filter((statement) => statement.length > 0);
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

function hasBalancedParentheses(value: string): boolean {
  let depth = 0;
  for (const char of value) {
    if (char === '(') depth += 1;
    if (char === ')') depth -= 1;
    if (depth < 0) return false;
  }
  return depth === 0;
}

function unwrapSurroundingParentheses(value: string): string {
  let normalized = value.trim();
  while (normalized.startsWith('(') && normalized.endsWith(')')) {
    const inner = normalized.slice(1, -1).trim();
    if (!hasBalancedParentheses(inner)) {
      break;
    }
    normalized = inner;
  }
  return normalized;
}

function normalizeDeleteRule(value: string | null | undefined): string | null {
  if (!value) return null;
  return value.trim().replace(/\s+/g, ' ').toUpperCase();
}

function isBooleanLikeColumn(columnName: string, defaultValue: string | null): boolean {
  const normalizedColumn = columnName.toLowerCase();
  const normalizedDefault = (defaultValue || '').trim().toLowerCase();
  if (normalizedDefault === 'true' || normalizedDefault === 'false') {
    return true;
  }
  return normalizedColumn.startsWith('is_')
    || normalizedColumn.startsWith('use_')
    || normalizedColumn.startsWith('has_')
    || normalizedColumn.endsWith('_enabled')
    || normalizedColumn.endsWith('_available')
    || normalizedColumn === 'read'
    || normalizedColumn === 'enabled'
    || normalizedColumn === 'available'
    || normalizedColumn === 'manual_override';
}

function isDateTimeLikeColumn(columnName: string, defaultValue: string | null): boolean {
  const normalizedColumn = columnName.toLowerCase();
  const normalizedDefault = (defaultValue || '').toLowerCase();
  return normalizedColumn.endsWith('_at')
    || normalizedColumn.endsWith('_until')
    || normalizedColumn.endsWith('_refresh')
    || normalizedDefault.includes("datetime('now')")
    || normalizedDefault.includes('current_timestamp')
    || normalizedDefault.includes('now()');
}

function isJsonLikeColumn(columnName: string): boolean {
  const normalizedColumn = columnName.toLowerCase();
  return normalizedColumn.endsWith('_json')
    || normalizedColumn.includes('snapshot')
    || normalizedColumn.includes('mapping')
    || normalizedColumn.includes('headers')
    || normalizedColumn.includes('config')
    || normalizedColumn.includes('details')
    || normalizedColumn.includes('meta')
    || normalizedColumn.includes('models')
    || normalizedColumn.includes('route_ids')
    || normalizedColumn.includes('multipliers');
}

export function normalizeSqlType(
  dialect: SchemaIntrospectionDialect,
  declaredType: string,
  columnName: string,
  rawDefaultValue: string | null = null,
): LogicalColumnType {
  const normalizedType = declaredType.trim().toLowerCase();
  const normalizedDefault = normalizeDefaultValue(rawDefaultValue);

  if (dialect === 'mysql') {
    if (normalizedType.includes('tinyint(1)') || normalizedType.includes('boolean') || normalizedType.includes('bool')) {
      return 'boolean';
    }
    if (normalizedType.includes('json')) {
      return 'json';
    }
    if (normalizedType.includes('timestamp') || normalizedType.includes('datetime') || normalizedType === 'date') {
      return 'datetime';
    }
    if (normalizedType.includes('int')) {
      return isBooleanLikeColumn(columnName, normalizedDefault) ? 'boolean' : 'integer';
    }
    if (normalizedType.includes('double') || normalizedType.includes('float') || normalizedType.includes('real') || normalizedType.includes('decimal')) {
      return 'real';
    }
    if (normalizedType.includes('char') || normalizedType.includes('text')) {
      if (isDateTimeLikeColumn(columnName, normalizedDefault)) return 'datetime';
      if (isJsonLikeColumn(columnName)) return 'json';
      return 'text';
    }
  }

  if (dialect === 'postgres') {
    if (normalizedType.includes('bool')) {
      return 'boolean';
    }
    if (normalizedType.includes('json')) {
      return 'json';
    }
    if (normalizedType.includes('timestamp') || normalizedType === 'date') {
      return 'datetime';
    }
    if (normalizedType.includes('int')) {
      return isBooleanLikeColumn(columnName, normalizedDefault) ? 'boolean' : 'integer';
    }
    if (normalizedType.includes('double') || normalizedType.includes('real') || normalizedType.includes('numeric') || normalizedType.includes('decimal')) {
      return 'real';
    }
    if (normalizedType.includes('char') || normalizedType.includes('text')) {
      if (isDateTimeLikeColumn(columnName, normalizedDefault)) return 'datetime';
      if (isJsonLikeColumn(columnName)) return 'json';
      return 'text';
    }
  }

  if (normalizedType.includes('int')) {
    return isBooleanLikeColumn(columnName, normalizedDefault) ? 'boolean' : 'integer';
  }
  if (normalizedType.includes('real') || normalizedType.includes('double') || normalizedType.includes('float') || normalizedType.includes('decimal')) {
    return 'real';
  }
  if (normalizedType.includes('json')) {
    return 'json';
  }
  if (normalizedType.includes('timestamp') || normalizedType.includes('datetime') || normalizedType === 'date') {
    return 'datetime';
  }
  if (normalizedType.includes('text') || normalizedType.includes('char') || normalizedType.includes('clob')) {
    if (isDateTimeLikeColumn(columnName, normalizedDefault)) return 'datetime';
    if (isJsonLikeColumn(columnName)) return 'json';
    return 'text';
  }
  if (isDateTimeLikeColumn(columnName, normalizedDefault)) return 'datetime';
  return 'text';
}

function normalizeDefaultValueForColumn(
  rawDefaultValue: string | null | undefined,
  logicalType: LogicalColumnType | null,
): string | null {
  if (rawDefaultValue == null) return null;

  let normalized = String(rawDefaultValue).trim();
  if (!normalized) return null;

  normalized = normalized.replace(/^default\s+/i, '').trim();
  normalized = unwrapSurroundingParentheses(normalized);
  normalized = normalized.replace(/::[\w\s.\[\]"]+/g, '').trim();
  normalized = unwrapSurroundingParentheses(normalized);

  const lowered = normalized.toLowerCase();
  if (lowered === 'null') return null;

  if (logicalType === 'datetime' || lowered === 'current_timestamp' || lowered === 'current_timestamp()' || lowered === 'now()' || lowered.includes("datetime('now')")) {
    return "datetime('now')";
  }

  if (logicalType === 'boolean') {
    if (lowered === '1' || lowered === 'true' || lowered === "b'1'") return 'true';
    if (lowered === '0' || lowered === 'false' || lowered === "b'0'") return 'false';
  }

  if (lowered === 'true' || lowered === 'false') return lowered;
  if (/^-?\d+(?:\.\d+)?$/.test(normalized)) return normalized;
  if (/^'.*'$/.test(normalized)) return normalized;
  if (/^[a-z_][a-z0-9_]*$/i.test(normalized)) return `'${normalized}'`;
  return normalized;
}

export function normalizeDefaultValue(rawDefaultValue: string | null | undefined): string | null {
  return normalizeDefaultValueForColumn(rawDefaultValue, null);
}

function sortForeignKeys(foreignKeys: SchemaContractForeignKey[]): SchemaContractForeignKey[] {
  return foreignKeys.sort((left, right) => {
    const leftKey = `${left.table}:${left.columns.join(',')}`;
    const rightKey = `${right.table}:${right.columns.join(',')}`;
    return leftKey.localeCompare(rightKey, 'en');
  });
}

function buildSqliteTables(sqlite: Database.Database): Record<string, SchemaContractTable> {
  const tableRows = sqlite.prepare(`
    SELECT name
    FROM sqlite_master
    WHERE type = 'table'
      AND name NOT LIKE 'sqlite_%'
    ORDER BY name ASC
  `).all() as Array<{ name: string }>;

  const tables: Record<string, SchemaContractTable> = {};
  for (const { name: tableName } of tableRows) {
    const rows = sqlite.prepare(`PRAGMA table_info("${tableName}")`).all() as SqliteTableInfoRow[];
    const columns = Object.fromEntries(rows.map((row) => {
      const logicalType = normalizeSqlType('sqlite', row.type, row.name, row.dflt_value);
      return [row.name, {
        logicalType,
        notNull: row.notnull === 1,
        defaultValue: normalizeDefaultValueForColumn(row.dflt_value, logicalType),
        primaryKey: row.pk > 0,
      } satisfies SchemaContractColumn];
    }));
    tables[tableName] = { columns };
  }
  return tables;
}

function buildSqliteIndexes(sqlite: Database.Database, tables: Record<string, SchemaContractTable>): {
  indexes: SchemaContractIndex[];
  uniques: SchemaContractUnique[];
} {
  const indexes: SchemaContractIndex[] = [];
  const uniques: SchemaContractUnique[] = [];

  for (const tableName of Object.keys(tables).sort((left, right) => left.localeCompare(right, 'en'))) {
    const rows = sqlite.prepare(`PRAGMA index_list("${tableName}")`).all() as SqliteIndexListRow[];
    for (const row of rows) {
      if (!row.name || row.name.startsWith('sqlite_autoindex')) {
        continue;
      }

      const columns = (sqlite.prepare(`PRAGMA index_info("${row.name}")`).all() as SqliteIndexInfoRow[])
        .sort((left, right) => left.seqno - right.seqno)
        .map((item) => item.name)
        .filter(Boolean);

      indexes.push({
        name: row.name,
        table: tableName,
        columns,
        unique: row.unique === 1,
      });

      if (row.unique === 1) {
        uniques.push({
          name: row.name,
          table: tableName,
          columns,
        });
      }
    }
  }

  indexes.sort((left, right) => left.name.localeCompare(right.name, 'en'));
  uniques.sort((left, right) => left.name.localeCompare(right.name, 'en'));
  return { indexes, uniques };
}

function buildSqliteForeignKeys(sqlite: Database.Database, tables: Record<string, SchemaContractTable>): SchemaContractForeignKey[] {
  const foreignKeys: SchemaContractForeignKey[] = [];

  for (const tableName of Object.keys(tables).sort((left, right) => left.localeCompare(right, 'en'))) {
    const rows = sqlite.prepare(`PRAGMA foreign_key_list("${tableName}")`).all() as SqliteForeignKeyRow[];
    const grouped = new Map<number, SchemaContractForeignKey>();

    for (const row of rows) {
      const existing = grouped.get(row.id);
      if (existing) {
        existing.columns.push(row.from);
        existing.referencedColumns.push(row.to);
        continue;
      }

      grouped.set(row.id, {
        table: tableName,
        columns: [row.from],
        referencedTable: row.table,
        referencedColumns: [row.to],
        onDelete: normalizeDeleteRule(row.on_delete),
      });
    }

    foreignKeys.push(...grouped.values());
  }

  return sortForeignKeys(foreignKeys);
}

async function introspectSqliteSchema(connectionString: string): Promise<SchemaContract> {
  const sqlitePath = connectionString === ':memory:' ? ':memory:' : resolve(connectionString);
  const sqlite = new Database(sqlitePath, { readonly: true });
  sqlite.pragma('foreign_keys = ON');

  try {
    const tables = buildSqliteTables(sqlite);
    const { indexes, uniques } = buildSqliteIndexes(sqlite, tables);
    const foreignKeys = buildSqliteForeignKeys(sqlite, tables);
    return { tables, indexes, uniques, foreignKeys };
  } finally {
    sqlite.close();
  }
}

async function introspectMySqlSchema(input: SchemaIntrospectionInput): Promise<SchemaContract> {
  const connectionOptions: mysql.ConnectionOptions = { uri: input.connectionString };
  if (input.ssl) {
    connectionOptions.ssl = { rejectUnauthorized: false };
  }
  const connection = await mysql.createConnection(connectionOptions);

  try {
    const [tableRows] = await connection.query(`
      SELECT table_name AS table_name
      FROM information_schema.tables
      WHERE table_schema = DATABASE()
        AND table_type = 'BASE TABLE'
      ORDER BY table_name ASC
    `);
    const tableNames = (tableRows as Array<Record<string, unknown>>)
      .map((row) => readMySqlField<string>(row, 'table_name'))
      .filter((tableName): tableName is string => typeof tableName === 'string');

    const [primaryKeyRows] = await connection.query(`
      SELECT
        kcu.table_name AS table_name,
        kcu.column_name AS column_name
      FROM information_schema.table_constraints tc
      JOIN information_schema.key_column_usage kcu
        ON tc.constraint_schema = kcu.constraint_schema
       AND tc.constraint_name = kcu.constraint_name
       AND tc.table_name = kcu.table_name
      WHERE tc.table_schema = DATABASE()
        AND tc.constraint_type = 'PRIMARY KEY'
    `);
    const primaryKeys = new Set((primaryKeyRows as Array<Record<string, unknown>>).map((row) => {
      const tableName = readMySqlField<string>(row, 'table_name');
      const columnName = readMySqlField<string>(row, 'column_name');
      return tableName && columnName ? `${tableName}.${columnName}` : null;
    }).filter((value): value is string => value !== null));

    const [columnRows] = await connection.query(`
      SELECT
        table_name AS table_name,
        column_name AS column_name,
        data_type AS data_type,
        column_type AS column_type,
        is_nullable AS is_nullable,
        column_default AS column_default
      FROM information_schema.columns
      WHERE table_schema = DATABASE()
      ORDER BY table_name ASC, ordinal_position ASC
    `);

    const tableMap = new Map<string, SchemaContractTable>();
    for (const tableName of tableNames) {
      tableMap.set(tableName, { columns: {} });
    }

    for (const row of columnRows as Array<Record<string, unknown>>) {
      const tableName = readMySqlField<string>(row, 'table_name');
      const columnName = readMySqlField<string>(row, 'column_name');
      const declaredType = readMySqlField<string>(row, 'column_type') || readMySqlField<string>(row, 'data_type');
      const isNullable = readMySqlField<string>(row, 'is_nullable');
      const columnDefault = readMySqlField<string | null>(row, 'column_default') ?? null;
      if (!tableName || !columnName || !declaredType) {
        continue;
      }

      const logicalType = normalizeSqlType('mysql', declaredType, columnName, columnDefault);
      tableMap.get(tableName)!.columns[columnName] = {
        logicalType,
        notNull: isNullable === 'NO',
        defaultValue: primaryKeys.has(`${tableName}.${columnName}`)
          ? null
          : normalizeDefaultValueForColumn(columnDefault, logicalType),
        primaryKey: primaryKeys.has(`${tableName}.${columnName}`),
      };
    }

    const tables = Object.fromEntries(tableNames.map((tableName) => [tableName, tableMap.get(tableName)!]));

    const [indexRows] = await connection.query(`
      SELECT
        table_name AS table_name,
        index_name AS index_name,
        column_name AS column_name,
        non_unique AS non_unique
      FROM information_schema.statistics
      WHERE table_schema = DATABASE()
        AND index_name <> 'PRIMARY'
      ORDER BY table_name ASC, index_name ASC, seq_in_index ASC
    `);
    const indexGroups = new Map<string, SchemaContractIndex>();
    for (const row of indexRows as Array<Record<string, unknown>>) {
      const tableName = readMySqlField<string>(row, 'table_name');
      const indexName = readMySqlField<string>(row, 'index_name');
      const columnName = readMySqlField<string>(row, 'column_name');
      const nonUnique = readMySqlField<number>(row, 'non_unique');
      if (!tableName || !indexName || !columnName) {
        continue;
      }

      const key = `${tableName}:${indexName}`;
      const existing = indexGroups.get(key);
      if (existing) {
        existing.columns.push(columnName);
        continue;
      }
      indexGroups.set(key, {
        name: indexName,
        table: tableName,
        columns: [columnName],
        unique: Number(nonUnique) === 0,
      });
    }

    const indexes = [...indexGroups.values()].sort((left, right) => left.name.localeCompare(right.name, 'en'));
    const uniques = indexes
      .filter((index) => index.unique)
      .map((index) => ({ name: index.name, table: index.table, columns: [...index.columns] }))
      .sort((left, right) => left.name.localeCompare(right.name, 'en'));

    const [foreignKeyRows] = await connection.query(`
      SELECT
        kcu.table_name AS table_name,
        kcu.constraint_name AS constraint_name,
        kcu.column_name AS column_name,
        kcu.referenced_table_name AS referenced_table_name,
        kcu.referenced_column_name AS referenced_column_name,
        rc.delete_rule AS delete_rule
      FROM information_schema.key_column_usage kcu
      JOIN information_schema.referential_constraints rc
        ON rc.constraint_schema = kcu.constraint_schema
       AND rc.constraint_name = kcu.constraint_name
      WHERE kcu.table_schema = DATABASE()
        AND kcu.referenced_table_name IS NOT NULL
      ORDER BY kcu.table_name ASC, kcu.constraint_name ASC, kcu.ordinal_position ASC
    `);
    const foreignKeyGroups = new Map<string, SchemaContractForeignKey>();
    for (const row of foreignKeyRows as Array<Record<string, unknown>>) {
      const tableName = readMySqlField<string>(row, 'table_name');
      const constraintName = readMySqlField<string>(row, 'constraint_name');
      const columnName = readMySqlField<string>(row, 'column_name');
      const referencedTableName = readMySqlField<string>(row, 'referenced_table_name');
      const referencedColumnName = readMySqlField<string>(row, 'referenced_column_name');
      const deleteRule = readMySqlField<string | null>(row, 'delete_rule') ?? null;
      if (!tableName || !constraintName || !columnName || !referencedTableName || !referencedColumnName) {
        continue;
      }

      const key = `${tableName}:${constraintName}`;
      const existing = foreignKeyGroups.get(key);
      if (existing) {
        existing.columns.push(columnName);
        existing.referencedColumns.push(referencedColumnName);
        continue;
      }
      foreignKeyGroups.set(key, {
        table: tableName,
        columns: [columnName],
        referencedTable: referencedTableName,
        referencedColumns: [referencedColumnName],
        onDelete: normalizeDeleteRule(deleteRule),
      });
    }

    return {
      tables,
      indexes,
      uniques,
      foreignKeys: sortForeignKeys([...foreignKeyGroups.values()]),
    };
  } finally {
    await connection.end();
  }
}

async function introspectPostgresSchema(input: SchemaIntrospectionInput): Promise<SchemaContract> {
  const clientOptions: pg.ClientConfig = { connectionString: input.connectionString };
  if (input.ssl) {
    clientOptions.ssl = { rejectUnauthorized: false };
  }
  const client = new pg.Client(clientOptions);
  await client.connect();

  try {
    const tableResult = await client.query(`
      SELECT table_name
      FROM information_schema.tables
      WHERE table_schema = current_schema()
        AND table_type = 'BASE TABLE'
      ORDER BY table_name ASC
    `);
    const tableNames = tableResult.rows.map((row) => String(row.table_name));

    const primaryKeyResult = await client.query(`
      SELECT kcu.table_name, kcu.column_name
      FROM information_schema.table_constraints tc
      JOIN information_schema.key_column_usage kcu
        ON tc.constraint_schema = kcu.constraint_schema
       AND tc.constraint_name = kcu.constraint_name
       AND tc.table_name = kcu.table_name
      WHERE tc.table_schema = current_schema()
        AND tc.constraint_type = 'PRIMARY KEY'
    `);
    const primaryKeys = new Set((primaryKeyResult.rows as PostgresPrimaryKeyRow[]).map((row) => `${row.table_name}.${row.column_name}`));

    const columnResult = await client.query(`
      SELECT table_name, column_name, data_type, udt_name, is_nullable, column_default
      FROM information_schema.columns
      WHERE table_schema = current_schema()
      ORDER BY table_name ASC, ordinal_position ASC
    `);
    const tableMap = new Map<string, SchemaContractTable>();
    for (const tableName of tableNames) {
      tableMap.set(tableName, { columns: {} });
    }

    for (const row of columnResult.rows as PostgresColumnRow[]) {
      const logicalType = normalizeSqlType('postgres', `${row.data_type} ${row.udt_name}`, row.column_name, row.column_default);
      tableMap.get(row.table_name)!.columns[row.column_name] = {
        logicalType,
        notNull: row.is_nullable === 'NO',
        defaultValue: primaryKeys.has(`${row.table_name}.${row.column_name}`)
          ? null
          : normalizeDefaultValueForColumn(row.column_default, logicalType),
        primaryKey: primaryKeys.has(`${row.table_name}.${row.column_name}`),
      };
    }

    const tables = Object.fromEntries(tableNames.map((tableName) => [tableName, tableMap.get(tableName)!]));

    const indexResult = await client.query(`
      SELECT
        t.relname AS table_name,
        i.relname AS index_name,
        ix.indisunique AS is_unique,
        a.attname AS column_name
      FROM pg_class t
      JOIN pg_namespace ns ON ns.oid = t.relnamespace
      JOIN pg_index ix ON t.oid = ix.indrelid
      JOIN pg_class i ON i.oid = ix.indexrelid
      JOIN LATERAL unnest(ix.indkey) WITH ORDINALITY AS ord(attnum, n) ON TRUE
      JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ord.attnum
      WHERE ns.nspname = current_schema()
        AND t.relkind = 'r'
        AND NOT ix.indisprimary
      ORDER BY t.relname ASC, i.relname ASC, ord.n ASC
    `);
    const indexGroups = new Map<string, SchemaContractIndex>();
    for (const row of indexResult.rows as PostgresIndexRow[]) {
      const key = `${row.table_name}:${row.index_name}`;
      const existing = indexGroups.get(key);
      if (existing) {
        existing.columns.push(row.column_name);
        continue;
      }
      indexGroups.set(key, {
        name: row.index_name,
        table: row.table_name,
        columns: [row.column_name],
        unique: !!row.is_unique,
      });
    }

    const indexes = [...indexGroups.values()].sort((left, right) => left.name.localeCompare(right.name, 'en'));
    const uniques = indexes
      .filter((index) => index.unique)
      .map((index) => ({ name: index.name, table: index.table, columns: [...index.columns] }))
      .sort((left, right) => left.name.localeCompare(right.name, 'en'));

    const foreignKeyResult = await client.query(`
      SELECT
        tc.table_name,
        tc.constraint_name,
        kcu.column_name,
        ccu.table_name AS referenced_table_name,
        ccu.column_name AS referenced_column_name,
        rc.delete_rule
      FROM information_schema.table_constraints tc
      JOIN information_schema.key_column_usage kcu
        ON tc.constraint_schema = kcu.constraint_schema
       AND tc.constraint_name = kcu.constraint_name
       AND tc.table_name = kcu.table_name
      JOIN information_schema.referential_constraints rc
        ON tc.constraint_schema = rc.constraint_schema
       AND tc.constraint_name = rc.constraint_name
      JOIN information_schema.constraint_column_usage ccu
        ON rc.unique_constraint_schema = ccu.constraint_schema
       AND rc.unique_constraint_name = ccu.constraint_name
      WHERE tc.table_schema = current_schema()
        AND tc.constraint_type = 'FOREIGN KEY'
      ORDER BY tc.table_name ASC, tc.constraint_name ASC, kcu.ordinal_position ASC
    `);
    const foreignKeyGroups = new Map<string, SchemaContractForeignKey>();
    for (const row of foreignKeyResult.rows as PostgresForeignKeyRow[]) {
      const key = `${row.table_name}:${row.constraint_name}`;
      const existing = foreignKeyGroups.get(key);
      if (existing) {
        existing.columns.push(row.column_name);
        existing.referencedColumns.push(row.referenced_column_name);
        continue;
      }
      foreignKeyGroups.set(key, {
        table: row.table_name,
        columns: [row.column_name],
        referencedTable: row.referenced_table_name,
        referencedColumns: [row.referenced_column_name],
        onDelete: normalizeDeleteRule(row.delete_rule),
      });
    }

    return {
      tables,
      indexes,
      uniques,
      foreignKeys: sortForeignKeys([...foreignKeyGroups.values()]),
    };
  } finally {
    await client.end();
  }
}

export async function introspectLiveSchema(input: SchemaIntrospectionInput): Promise<SchemaContract> {
  if (input.dialect === 'sqlite') {
    return introspectSqliteSchema(input.connectionString);
  }
  if (input.dialect === 'mysql') {
    return introspectMySqlSchema(input);
  }
  return introspectPostgresSchema(input);
}

function readBootstrapSql(dialect: Exclude<SchemaIntrospectionDialect, 'sqlite'>): string {
  const filename = dialect === 'mysql' ? 'mysql.bootstrap.sql' : 'postgres.bootstrap.sql';
  return readFileSync(resolveGeneratedArtifactPath(filename), 'utf8');
}

async function resetMySqlSchema(connection: mysql.Connection): Promise<void> {
  await connection.query('SET FOREIGN_KEY_CHECKS = 0');
  const [rows] = await connection.query(`
    SELECT table_name AS table_name
    FROM information_schema.tables
    WHERE table_schema = DATABASE()
      AND table_type = 'BASE TABLE'
  `);
  for (const row of rows as Array<Record<string, unknown>>) {
    const tableName = readMySqlField<string>(row, 'table_name');
    if (!tableName) {
      continue;
    }
    await connection.query(`DROP TABLE IF EXISTS \`${tableName}\``);
  }
  await connection.query('SET FOREIGN_KEY_CHECKS = 1');
}

async function resetPostgresSchema(client: pg.Client): Promise<void> {
  const result = await client.query(`
    SELECT tablename
    FROM pg_tables
    WHERE schemaname = current_schema()
    ORDER BY tablename ASC
  `);
  for (const row of result.rows as Array<{ tablename: string }>) {
    await client.query(`DROP TABLE IF EXISTS "${row.tablename}" CASCADE`);
  }
}

function applySqliteMigrations(sqlite: Database.Database): void {
  const migrationsFolder = resolveMigrationsFolder();
  const migrationFiles = readdirSync(migrationsFolder)
    .filter((entry) => entry.endsWith('.sql'))
    .sort((left, right) => left.localeCompare(right, 'en'));

  for (const migrationFile of migrationFiles) {
    const sqlText = readFileSync(join(migrationsFolder, migrationFile), 'utf8');
    for (const statement of splitMigrationStatements(sqlText)) {
      sqlite.exec(statement);
    }
  }
}

function createTemporarySqlitePath(): string {
  const tempDir = mkdtempSync(join(tmpdir(), 'metapi-schema-parity-'));
  return resolve(tempDir, `${randomUUID()}.db`);
}

function applySqliteStatements(sqlitePath: string, statements: string[]): void {
  const sqlite = new Database(sqlitePath);
  sqlite.pragma('foreign_keys = ON');
  try {
    for (const statement of statements) {
      sqlite.exec(statement);
    }
  } finally {
    sqlite.close();
  }
}

async function applyMySqlStatements(
  connectionString: string,
  ssl: boolean | undefined,
  statements: string[],
  resetSchema = false,
): Promise<void> {
  const connectionOptions: mysql.ConnectionOptions = { uri: connectionString };
  if (ssl) {
    connectionOptions.ssl = { rejectUnauthorized: false };
  }
  const connection = await mysql.createConnection(connectionOptions);
  try {
    if (resetSchema) {
      await resetMySqlSchema(connection);
    }
    for (const statement of statements) {
      await connection.query(statement);
    }
  } finally {
    await connection.end();
  }
}

async function applyPostgresStatements(
  connectionString: string,
  ssl: boolean | undefined,
  statements: string[],
  resetSchema = false,
): Promise<void> {
  const clientOptions: pg.ClientConfig = { connectionString };
  if (ssl) {
    clientOptions.ssl = { rejectUnauthorized: false };
  }
  const client = new pg.Client(clientOptions);
  await client.connect();
  try {
    if (resetSchema) {
      await resetPostgresSchema(client);
    }
    for (const statement of statements) {
      await client.query(statement);
    }
  } finally {
    await client.end();
  }
}

export async function materializeFreshSchema(
  dialect: SchemaIntrospectionDialect,
  options: MaterializeFreshSchemaOptions = {},
): Promise<string> {
  if (dialect === 'sqlite') {
    const sqlitePath = createTemporarySqlitePath();
    const sqlite = new Database(sqlitePath);
    sqlite.pragma('foreign_keys = ON');
    try {
      applySqliteMigrations(sqlite);
    } finally {
      sqlite.close();
    }
    return sqlitePath;
  }

  if (!options.connectionString) {
    throw new Error(`connectionString is required to materialize ${dialect} parity schema`);
  }

  const bootstrapStatements = splitSqlStatements(readBootstrapSql(dialect));
  if (dialect === 'mysql') {
    await applyMySqlStatements(options.connectionString, options.ssl, bootstrapStatements, true);
    return options.connectionString;
  }

  await applyPostgresStatements(options.connectionString, options.ssl, bootstrapStatements, true);
  return options.connectionString;
}

export async function applyContractFixtureThenUpgrade(
  dialect: SchemaIntrospectionDialect,
  baselineContract: SchemaContract,
  currentContract: SchemaContract,
  options: ApplyContractFixtureThenUpgradeOptions = {},
): Promise<string> {
  const bootstrapStatements = splitSqlStatements(generateBootstrapSql(dialect, baselineContract));
  const upgradeStatements = splitSqlStatements(generateUpgradeSql(dialect, currentContract, baselineContract));

  if (dialect === 'sqlite') {
    const sqlitePath = createTemporarySqlitePath();
    applySqliteStatements(sqlitePath, bootstrapStatements);
    if (upgradeStatements.length > 0) {
      applySqliteStatements(sqlitePath, upgradeStatements);
    }
    return sqlitePath;
  }

  if (!options.connectionString) {
    throw new Error(`connectionString is required to upgrade ${dialect} parity schema`);
  }

  if (dialect === 'mysql') {
    await applyMySqlStatements(options.connectionString, options.ssl, bootstrapStatements, true);
    if (upgradeStatements.length > 0) {
      await applyMySqlStatements(options.connectionString, options.ssl, upgradeStatements, false);
    }
    return options.connectionString;
  }

  await applyPostgresStatements(options.connectionString, options.ssl, bootstrapStatements, true);
  if (upgradeStatements.length > 0) {
    await applyPostgresStatements(options.connectionString, options.ssl, upgradeStatements, false);
  }
  return options.connectionString;
}

export const __schemaIntrospectionTestUtils = {
  splitMigrationStatements,
  splitSqlStatements,
};
