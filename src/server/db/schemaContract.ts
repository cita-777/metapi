import Database from 'better-sqlite3';
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  normalizeLogicalColumnType,
  normalizeSchemaMetadataDefaultValue,
  type LogicalColumnType,
} from './schemaMetadata.js';

export type { LogicalColumnType } from './schemaMetadata.js';

export interface SchemaContractColumn {
  logicalType: LogicalColumnType;
  notNull: boolean;
  defaultValue: string | null;
  primaryKey: boolean;
}

export interface SchemaContractTable {
  columns: Record<string, SchemaContractColumn>;
}

export interface SchemaContractIndex {
  name: string;
  table: string;
  columns: string[];
  unique: boolean;
}

export interface SchemaContractUnique {
  name: string;
  table: string;
  columns: string[];
}

export interface SchemaContractForeignKey {
  table: string;
  columns: string[];
  referencedTable: string;
  referencedColumns: string[];
  onDelete: string | null;
}

export interface SchemaContract {
  tables: Record<string, SchemaContractTable>;
  indexes: SchemaContractIndex[];
  uniques: SchemaContractUnique[];
  foreignKeys: SchemaContractForeignKey[];
}

type TableInfoRow = {
  name: string;
  type: string;
  notnull: number;
  dflt_value: string | null;
  pk: number;
};

type IndexListRow = {
  name: string;
  unique: number;
  origin: string;
  partial: number;
};

type IndexInfoRow = {
  seqno: number;
  cid: number;
  name: string;
};

type ForeignKeyRow = {
  id: number;
  seq: number;
  table: string;
  from: string;
  to: string;
  on_update: string;
  on_delete: string;
  match: string;
};

function resolveDbDir(): string {
  return dirname(fileURLToPath(import.meta.url));
}

export function resolveMigrationsFolder(): string {
  return resolve(resolveDbDir(), '../../../drizzle');
}

export function resolveGeneratedSchemaContractPath(): string {
  return resolve(resolveDbDir(), 'generated/schemaContract.json');
}

function resolveMigrationFiles(migrationsFolder: string): string[] {
  return readdirSync(migrationsFolder)
    .filter((entry) => entry.endsWith('.sql'))
    .sort((left, right) => left.localeCompare(right, 'en'));
}

function splitMigrationStatements(sqlText: string): string[] {
  return sqlText
    .split('--> statement-breakpoint')
    .map((statement) => statement.trim())
    .filter((statement) => statement.length > 0);
}

function applySqliteMigrations(sqlite: Database.Database, migrationsFolder: string): void {
  for (const migrationFile of resolveMigrationFiles(migrationsFolder)) {
    const sqlText = readFileSync(join(migrationsFolder, migrationFile), 'utf8');
    for (const statement of splitMigrationStatements(sqlText)) {
      sqlite.exec(statement);
    }
  }
}

function normalizeDefaultValue(defaultValue: string | null): string | null {
  return normalizeSchemaMetadataDefaultValue(defaultValue);
}

function normalizeLogicalType(columnName: string, declaredType: string, defaultValue: string | null): LogicalColumnType {
  return normalizeLogicalColumnType({
    columnName,
    declaredType,
    defaultValue,
    dialect: 'sqlite',
  });
}

function readTables(sqlite: Database.Database): Record<string, SchemaContractTable> {
  const tables = sqlite.prepare(`
    SELECT name
    FROM sqlite_master
    WHERE type = 'table'
      AND name NOT LIKE 'sqlite_%'
    ORDER BY name ASC
  `).all() as Array<{ name: string }>;

  const result: Record<string, SchemaContractTable> = {};

  for (const table of tables) {
    const rows = sqlite.prepare(`PRAGMA table_info("${table.name}")`).all() as TableInfoRow[];
    const columns = Object.fromEntries(rows.map((row) => {
      const defaultValue = normalizeDefaultValue(row.dflt_value);
      return [row.name, {
        logicalType: normalizeLogicalType(row.name, row.type, defaultValue),
        notNull: row.notnull === 1,
        defaultValue,
        primaryKey: row.pk > 0,
      } satisfies SchemaContractColumn];
    }));

    result[table.name] = { columns };
  }

  return result;
}

function readIndexes(sqlite: Database.Database, tables: Record<string, SchemaContractTable>): {
  indexes: SchemaContractIndex[];
  uniques: SchemaContractUnique[];
} {
  const indexes: SchemaContractIndex[] = [];
  const uniques: SchemaContractUnique[] = [];

  for (const tableName of Object.keys(tables).sort((left, right) => left.localeCompare(right, 'en'))) {
    const rows = sqlite.prepare(`PRAGMA index_list("${tableName}")`).all() as IndexListRow[];
    for (const row of rows) {
      if (!row.name || row.name.startsWith('sqlite_autoindex')) {
        continue;
      }
      const indexColumns = (sqlite.prepare(`PRAGMA index_info("${row.name}")`).all() as IndexInfoRow[])
        .sort((left, right) => left.seqno - right.seqno)
        .map((item) => item.name)
        .filter((name) => !!name);

      const index: SchemaContractIndex = {
        name: row.name,
        table: tableName,
        columns: indexColumns,
        unique: row.unique === 1,
      };
      indexes.push(index);

      if (row.unique === 1) {
        uniques.push({
          name: row.name,
          table: tableName,
          columns: indexColumns,
        });
      }
    }
  }

  indexes.sort((left, right) => left.name.localeCompare(right.name, 'en'));
  uniques.sort((left, right) => left.name.localeCompare(right.name, 'en'));

  return { indexes, uniques };
}

function readForeignKeys(sqlite: Database.Database, tables: Record<string, SchemaContractTable>): SchemaContractForeignKey[] {
  const foreignKeys: SchemaContractForeignKey[] = [];

  for (const tableName of Object.keys(tables).sort((left, right) => left.localeCompare(right, 'en'))) {
    const rows = sqlite.prepare(`PRAGMA foreign_key_list("${tableName}")`).all() as ForeignKeyRow[];
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
        onDelete: row.on_delete || null,
      });
    }

    foreignKeys.push(...grouped.values());
  }

  foreignKeys.sort((left, right) => {
    const leftKey = `${left.table}:${left.columns.join(',')}`;
    const rightKey = `${right.table}:${right.columns.join(',')}`;
    return leftKey.localeCompare(rightKey, 'en');
  });

  return foreignKeys;
}

export function buildSchemaContractFromSqliteMigrations(migrationsFolder = resolveMigrationsFolder()): SchemaContract {
  const sqlite = new Database(':memory:');
  sqlite.pragma('foreign_keys = ON');

  try {
    applySqliteMigrations(sqlite, migrationsFolder);
    const tables = readTables(sqlite);
    const { indexes, uniques } = readIndexes(sqlite, tables);
    const foreignKeys = readForeignKeys(sqlite, tables);

    return {
      tables,
      indexes,
      uniques,
      foreignKeys,
    };
  } finally {
    sqlite.close();
  }
}

export function writeSchemaContractFile(outputPath = resolveGeneratedSchemaContractPath()): SchemaContract {
  const contract = buildSchemaContractFromSqliteMigrations();
  mkdirSync(dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, `${JSON.stringify(contract, null, 2)}\n`, 'utf8');
  return contract;
}

export const __schemaContractTestUtils = {
  splitMigrationStatements,
  normalizeDefaultValue,
  normalizeLogicalType,
  resolveMigrationsFolder,
};
