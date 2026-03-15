import Database from 'better-sqlite3';
import { drizzle } from 'drizzle-orm/better-sqlite3';
import { migrate } from 'drizzle-orm/better-sqlite3/migrator';
import { config } from '../config.js';
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

type MigrationJournalEntry = {
  tag: string;
  when: number;
};

type MigrationJournalFile = {
  entries?: MigrationJournalEntry[];
};

type SchemaMarker = {
  table: string;
  column?: string;
};

type MigrationRecord = {
  createdAt: number;
  hash: string;
};

type RecoveryMigrationRecord = MigrationRecord & {
  tag: string;
};

type RecoveryMigration = RecoveryMigrationRecord & {
  statements: string[];
};

const VERIFIED_BOOTSTRAP_TAG = '0011_downstream_api_key_metadata';
const VERIFIED_SCHEMA_MARKERS: SchemaMarker[] = [
  { table: 'sites' },
  { table: 'settings' },
  { table: 'accounts' },
  { table: 'checkin_logs' },
  { table: 'model_availability' },
  { table: 'proxy_logs' },
  { table: 'token_routes' },
  { table: 'route_channels', column: 'token_id' },
  { table: 'account_tokens' },
  { table: 'token_model_availability' },
  { table: 'events' },
  { table: 'sites', column: 'is_pinned' },
  { table: 'sites', column: 'sort_order' },
  { table: 'accounts', column: 'is_pinned' },
  { table: 'accounts', column: 'sort_order' },
  // 0006: site_disabled_models table
  { table: 'site_disabled_models' },
  // 0007: token_group column on account_tokens
  { table: 'account_tokens', column: 'token_group' },
  // 0009: is_manual column on model_availability
  { table: 'model_availability', column: 'is_manual' },
  // 0010: downstream_api_key_id column on proxy_logs
  { table: 'proxy_logs', column: 'downstream_api_key_id' },
  // 0011: downstream key metadata columns
  { table: 'downstream_api_keys', column: 'group_name' },
  { table: 'downstream_api_keys', column: 'tags' },
];


function resolveSqliteDbPath(): string {
  const raw = (config.dbUrl || '').trim();
  if (!raw) return resolve(`${config.dataDir}/hub.db`);
  if (raw === ':memory:') return raw;
  if (raw.startsWith('file://')) {
    const parsed = new URL(raw);
    return decodeURIComponent(parsed.pathname);
  }
  if (raw.startsWith('sqlite://')) {
    return resolve(raw.slice('sqlite://'.length).trim());
  }
  return resolve(raw);
}

function resolveMigrationsFolder(): string {
  return resolve(dirname(fileURLToPath(import.meta.url)), '../../../drizzle');
}

function tableExists(sqlite: Database.Database, table: string): boolean {
  const row = sqlite.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ? LIMIT 1").get(table);
  return !!row;
}

function columnExists(sqlite: Database.Database, table: string, column: string): boolean {
  if (!tableExists(sqlite, table)) return false;
  const rows = sqlite.prepare(`PRAGMA table_info("${table}")`).all() as Array<{ name?: string }>;
  return rows.some((row) => row.name === column);
}

function hasRecordedDrizzleMigrations(sqlite: Database.Database): boolean {
  if (!tableExists(sqlite, '__drizzle_migrations')) return false;
  const row = sqlite.prepare('SELECT 1 FROM __drizzle_migrations LIMIT 1').get();
  return !!row;
}

function hasVerifiedLegacySchema(sqlite: Database.Database): boolean {
  return VERIFIED_SCHEMA_MARKERS.every((marker) => (
    marker.column
      ? columnExists(sqlite, marker.table, marker.column)
      : tableExists(sqlite, marker.table)
  ));
}

function readVerifiedMigrationRecords(migrationsFolder: string): MigrationRecord[] {
  const journalPath = resolve(migrationsFolder, 'meta', '_journal.json');
  const journal = JSON.parse(readFileSync(journalPath, 'utf8')) as MigrationJournalFile;
  const records: MigrationRecord[] = [];

  for (const entry of journal.entries ?? []) {
    const migrationSql = readFileSync(resolve(migrationsFolder, `${entry.tag}.sql`), 'utf8');
    records.push({
      createdAt: Number(entry.when),
      hash: createHash('sha256').update(migrationSql).digest('hex'),
    });

    if (entry.tag === VERIFIED_BOOTSTRAP_TAG) {
      return records;
    }
  }

  return [];
}

function splitMigrationStatements(sqlText: string): string[] {
  return sqlText
    .split('--> statement-breakpoint')
    .map((statement) => statement.trim())
    .filter((statement) => statement.length > 0);
}

function normalizeSqlForMatch(sqlText: string): string {
  return sqlText
    .replace(/[\n\r\t]+/g, ' ')
    .replace(/["`]/g, '')
    .replace(/\s+/g, ' ')
    .trim()
    .replace(/;+$/g, '')
    .toLowerCase();
}

function extractFailedSqlFromError(error: unknown): string | null {
  const message = normalizeSchemaErrorMessage(error);
  const matched = message.match(/Failed to run the query '([\s\S]*?)'/i);
  const sqlText = matched?.[1]?.trim();
  return sqlText && sqlText.length > 0 ? sqlText : null;
}

function findMatchingSingleStatementMigration(
  migrationsFolder: string,
  failedSqlText: string,
): RecoveryMigrationRecord | null {
  const journalPath = resolve(migrationsFolder, 'meta', '_journal.json');
  const journal = JSON.parse(readFileSync(journalPath, 'utf8')) as MigrationJournalFile;
  const normalizedFailedSql = normalizeSqlForMatch(failedSqlText);

  for (const entry of journal.entries ?? []) {
    const migrationSql = readFileSync(resolve(migrationsFolder, `${entry.tag}.sql`), 'utf8');
    const statements = splitMigrationStatements(migrationSql);
    if (statements.length !== 1) {
      continue;
    }

    if (normalizeSqlForMatch(statements[0]) !== normalizedFailedSql) {
      continue;
    }

    return {
      tag: entry.tag,
      createdAt: Number(entry.when),
      hash: createHash('sha256').update(migrationSql).digest('hex'),
    };
  }

  return null;
}

function findMatchingMigrationByStatement(
  migrationsFolder: string,
  failedSqlText: string,
): RecoveryMigrationRecord | null {
  const normalizedFailedSql = normalizeSqlForMatch(failedSqlText);
  const migrations = readRecoveryMigrations(migrationsFolder);

  for (const migration of migrations) {
    if (!migration.statements.some((statement) => normalizeSqlForMatch(statement) === normalizedFailedSql)) {
      continue;
    }

    return {
      tag: migration.tag,
      createdAt: migration.createdAt,
      hash: migration.hash,
    };
  }

  return null;
}

function readRecoveryMigrations(migrationsFolder: string): RecoveryMigration[] {
  const journalPath = resolve(migrationsFolder, 'meta', '_journal.json');
  const journal = JSON.parse(readFileSync(journalPath, 'utf8')) as MigrationJournalFile;

  return (journal.entries ?? []).map((entry) => {
    const migrationSql = readFileSync(resolve(migrationsFolder, `${entry.tag}.sql`), 'utf8');
    return {
      tag: entry.tag,
      createdAt: Number(entry.when),
      hash: createHash('sha256').update(migrationSql).digest('hex'),
      statements: splitMigrationStatements(migrationSql),
    };
  });
}

function ensureDrizzleMigrationsTable(sqlite: Database.Database): void {
  sqlite.exec(`
    CREATE TABLE IF NOT EXISTS "__drizzle_migrations" (
      id SERIAL PRIMARY KEY,
      hash text NOT NULL,
      created_at numeric
    )
  `);
}

function markMigrationRecordIfMissing(sqlite: Database.Database, record: MigrationRecord): boolean {
  ensureDrizzleMigrationsTable(sqlite);
  const existing = sqlite
    .prepare('SELECT 1 FROM "__drizzle_migrations" WHERE "hash" = ? LIMIT 1')
    .get(record.hash);
  if (existing) {
    return false;
  }

  sqlite
    .prepare('INSERT INTO "__drizzle_migrations" ("hash", "created_at") VALUES (?, ?)')
    .run(record.hash, record.createdAt);

  return true;
}

function normalizeSchemaErrorMessage(error: unknown): string {
  if (!error || typeof error !== 'object') {
    return String(error || '');
  }

  const collected: string[] = [];
  let cursor: unknown = error;
  let depth = 0;

  while (cursor && typeof cursor === 'object' && depth < 8) {
    const current = cursor as { message?: unknown; cause?: unknown };
    if (current.message !== undefined && current.message !== null) {
      const text = String(current.message).trim();
      if (text.length > 0) {
        collected.push(text);
      }
    }

    cursor = current.cause;
    depth += 1;
  }

  if (collected.length > 0) {
    return collected.join(' | ');
  }

  return String(error || '');
}

function isDuplicateColumnError(error: unknown): boolean {
  const lowered = normalizeSchemaErrorMessage(error).toLowerCase();
  return lowered.includes('duplicate column')
    || lowered.includes('already exists')
    || lowered.includes('duplicate column name');
}

function isRecoverableSchemaConflictError(error: unknown): boolean {
  const lowered = normalizeSchemaErrorMessage(error).toLowerCase();
  return lowered.includes('duplicate column')
    || lowered.includes('duplicate column name')
    || lowered.includes('already exists');
}

function getLatestRecordedMigrationCreatedAt(sqlite: Database.Database): number | null {
  if (!tableExists(sqlite, '__drizzle_migrations')) return null;
  const row = sqlite
    .prepare('SELECT created_at FROM "__drizzle_migrations" ORDER BY created_at DESC LIMIT 1')
    .get() as { created_at?: number } | undefined;
  if (!row || row.created_at === undefined || row.created_at === null) {
    return null;
  }
  return Number(row.created_at);
}

function replayMigrationStatements(sqlite: Database.Database, statements: string[]): void {
  for (const statement of statements) {
    try {
      sqlite.exec(statement);
    } catch (error) {
      if (!isRecoverableSchemaConflictError(error)) {
        throw error;
      }
    }
  }
}

function recoverMigrationSequence(
  sqlite: Database.Database,
  migrationsFolder: string,
  failedMigrationTag: string,
): boolean {
  const migrations = readRecoveryMigrations(migrationsFolder);
  const failedMigrationIndex = migrations.findIndex((migration) => migration.tag === failedMigrationTag);
  if (failedMigrationIndex < 0) {
    return false;
  }

  let latestRecordedCreatedAt = getLatestRecordedMigrationCreatedAt(sqlite);
  for (const migration of migrations.slice(0, failedMigrationIndex + 1)) {
    if (latestRecordedCreatedAt !== null && latestRecordedCreatedAt >= migration.createdAt) {
      continue;
    }

    replayMigrationStatements(sqlite, migration.statements);
    markMigrationRecordIfMissing(sqlite, migration);
    latestRecordedCreatedAt = migration.createdAt;
  }

  return true;
}

function tryRecoverDuplicateColumnMigrationError(
  sqlite: Database.Database,
  migrationsFolder: string,
  error: unknown,
): boolean {
  if (!isDuplicateColumnError(error)) {
    return false;
  }

  const failedSqlText = extractFailedSqlFromError(error);
  if (!failedSqlText) {
    return false;
  }

  const matchedMigration = findMatchingMigrationByStatement(migrationsFolder, failedSqlText);
  if (!matchedMigration) {
    return false;
  }

  const recovered = recoverMigrationSequence(sqlite, migrationsFolder, matchedMigration.tag);
  if (recovered) {
    console.warn(`[db] Recovered duplicate-column migration sequence through ${matchedMigration.tag}.`);
  }
  return recovered;
}

export const __migrateTestUtils = {
  splitMigrationStatements,
  normalizeSqlForMatch,
  extractFailedSqlFromError,
  findMatchingSingleStatementMigration,
  findMatchingMigrationByStatement,
  readRecoveryMigrations,
  markMigrationRecordIfMissing,
  recoverMigrationSequence,
  tryRecoverDuplicateColumnMigrationError,
};

function bootstrapLegacyDrizzleMigrations(sqlite: Database.Database, migrationsFolder: string): boolean {
  if (hasRecordedDrizzleMigrations(sqlite)) return false;
  if (!hasVerifiedLegacySchema(sqlite)) return false;

  const records = readVerifiedMigrationRecords(migrationsFolder);
  if (records.length === 0) return false;

  sqlite.exec(`
    CREATE TABLE IF NOT EXISTS "__drizzle_migrations" (
      id SERIAL PRIMARY KEY,
      hash text NOT NULL,
      created_at numeric
    )
  `);

  const insert = sqlite.prepare('INSERT INTO "__drizzle_migrations" ("hash", "created_at") VALUES (?, ?)');
  const applyBootstrap = sqlite.transaction((migrations: MigrationRecord[]) => {
    for (const migrationRecord of migrations) {
      insert.run(migrationRecord.hash, migrationRecord.createdAt);
    }
  });

  applyBootstrap(records);
  console.log('[db] Bootstrapped drizzle migration journal for existing SQLite schema.');
  return true;
}

export function runSqliteMigrations(): void {
  const dbPath = resolveSqliteDbPath();
  const migrationsFolder = resolveMigrationsFolder();
  if (dbPath !== ':memory:') {
    mkdirSync(dirname(dbPath), { recursive: true });
  }

  const sqlite = new Database(dbPath);
  bootstrapLegacyDrizzleMigrations(sqlite, migrationsFolder);

  try {
    migrate(drizzle(sqlite), { migrationsFolder });
  } catch (error) {
    if (!tryRecoverDuplicateColumnMigrationError(sqlite, migrationsFolder, error)) {
      sqlite.close();
      throw error;
    }
    migrate(drizzle(sqlite), { migrationsFolder });
  }

  sqlite.close();
  console.log('Migration complete.');
}

runSqliteMigrations();
