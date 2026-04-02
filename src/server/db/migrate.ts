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

type LegacySiteRow = {
  id: number;
  platform: string;
  url: string;
};

const VERIFIED_BOOTSTRAP_TAG = '0012_account_token_value_status';
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
  // 0012: value_status column on account_tokens
  { table: 'account_tokens', column: 'value_status' },
  // 0019: proxy log stream/timing columns
  { table: 'proxy_logs', column: 'is_stream' },
  { table: 'proxy_logs', column: 'first_byte_latency_ms' },
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

function findMatchingMigrationByErrorMessage(
  migrationsFolder: string,
  error: unknown,
): RecoveryMigrationRecord | null {
  const normalizedErrorMessage = normalizeSqlForMatch(normalizeSchemaErrorMessage(error));
  const migrations = readRecoveryMigrations(migrationsFolder);

  for (const migration of migrations) {
    if (!migration.statements.some((statement) => normalizedErrorMessage.includes(normalizeSqlForMatch(statement)))) {
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

function hasMigrationRecord(sqlite: Database.Database, record: MigrationRecord): boolean {
  if (!tableExists(sqlite, '__drizzle_migrations')) return false;
  const row = sqlite
    .prepare('SELECT 1 FROM "__drizzle_migrations" WHERE "hash" = ? LIMIT 1')
    .get(record.hash);
  return !!row;
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

function isSitesPlatformUrlUniqueConflictError(error: unknown): boolean {
  const lowered = normalizeSchemaErrorMessage(error).toLowerCase();
  if (!lowered.includes('unique constraint failed: sites.platform, sites.url')) {
    return false;
  }

  const failedSqlText = extractFailedSqlFromError(error);
  if (!failedSqlText) {
    return true;
  }

  return normalizeSqlForMatch(failedSqlText)
    === normalizeSqlForMatch('CREATE UNIQUE INDEX `sites_platform_url_unique` ON `sites` (`platform`,`url`);');
}

function replayMigrationStatements(sqlite: Database.Database, statements: string[]): void {
  for (const statement of statements) {
    try {
      sqlite.exec(statement);
    } catch (error) {
      if (isRecoverableSchemaConflictError(error)) {
        continue;
      }

      if (isSitesPlatformUrlUniqueConflictError(error) && deduplicateLegacySitesForUniqueIndex(sqlite)) {
        try {
          sqlite.exec(statement);
          continue;
        } catch (retryError) {
          if (isRecoverableSchemaConflictError(retryError)) {
            continue;
          }
          throw retryError;
        }
      }

      throw error;
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

  for (const migration of migrations.slice(0, failedMigrationIndex + 1)) {
    if (hasMigrationRecord(sqlite, migration)) {
      continue;
    }

    replayMigrationStatements(sqlite, migration.statements);
    markMigrationRecordIfMissing(sqlite, migration);
  }

  return true;
}

function backfillMissingRecordedMigrations(sqlite: Database.Database, migrationsFolder: string): number {
  if (!tableExists(sqlite, '__drizzle_migrations')) return 0;

  let recoveredCount = 0;
  for (const migration of readRecoveryMigrations(migrationsFolder)) {
    if (hasMigrationRecord(sqlite, migration)) {
      continue;
    }

    replayMigrationStatements(sqlite, migration.statements);
    if (markMigrationRecordIfMissing(sqlite, migration)) {
      recoveredCount += 1;
    }
  }

  if (recoveredCount > 0) {
    console.warn(`[db] Backfilled ${recoveredCount} missing drizzle migration record(s).`);
  }

  return recoveredCount;
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
  const matchedMigration = failedSqlText
    ? findMatchingMigrationByStatement(migrationsFolder, failedSqlText)
      ?? findMatchingMigrationByErrorMessage(migrationsFolder, error)
    : findMatchingMigrationByErrorMessage(migrationsFolder, error);
  if (!matchedMigration) {
    return false;
  }

  const recovered = recoverMigrationSequence(sqlite, migrationsFolder, matchedMigration.tag);
  if (recovered) {
    console.warn(`[db] Recovered duplicate-column migration sequence through ${matchedMigration.tag}.`);
  }
  return recovered;
}

function rewriteDownstreamSiteWeightMultipliers(
  sqlite: Database.Database,
  siteIdMapping: Map<number, number>,
): void {
  if (siteIdMapping.size <= 0) return;
  if (!tableExists(sqlite, 'downstream_api_keys')) return;
  if (!columnExists(sqlite, 'downstream_api_keys', 'site_weight_multipliers')) return;

  const rows = sqlite.prepare(`
    SELECT id, site_weight_multipliers
    FROM downstream_api_keys
    WHERE site_weight_multipliers IS NOT NULL
      AND TRIM(site_weight_multipliers) <> ''
  `).all() as Array<{ id: number; site_weight_multipliers: string | null }>;

  const update = sqlite.prepare('UPDATE downstream_api_keys SET site_weight_multipliers = ? WHERE id = ?');
  for (const row of rows) {
    if (!row.site_weight_multipliers) continue;

    let parsed: unknown;
    try {
      parsed = JSON.parse(row.site_weight_multipliers);
    } catch {
      continue;
    }

    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) continue;
    const nextValue = { ...(parsed as Record<string, unknown>) };
    let changed = false;

    for (const [fromSiteId, toSiteId] of siteIdMapping.entries()) {
      const fromKey = String(fromSiteId);
      const toKey = String(toSiteId);
      if (!(fromKey in nextValue)) continue;
      if (!(toKey in nextValue)) {
        nextValue[toKey] = nextValue[fromKey];
      }
      delete nextValue[fromKey];
      changed = true;
    }

    if (!changed) continue;
    update.run(JSON.stringify(nextValue), row.id);
  }
}

function deduplicateLegacySitesForUniqueIndex(sqlite: Database.Database): boolean {
  const duplicateGroups = sqlite.prepare(`
    SELECT platform, url
    FROM sites
    GROUP BY platform, url
    HAVING COUNT(*) > 1
  `).all() as Array<{ platform: string; url: string }>;

  if (duplicateGroups.length <= 0) {
    return false;
  }

  const selectSitesByIdentity = sqlite.prepare(`
    SELECT id, platform, url
    FROM sites
    WHERE platform = ? AND url = ?
    ORDER BY id ASC
  `);
  const rebindAccounts = sqlite.prepare('UPDATE accounts SET site_id = ? WHERE site_id = ?');
  const mergeDisabledModels = sqlite.prepare(`
    INSERT OR IGNORE INTO site_disabled_models (site_id, model_name, created_at)
    SELECT ?, model_name, created_at
    FROM site_disabled_models
    WHERE site_id = ?
  `);
  const deleteDisabledModels = sqlite.prepare('DELETE FROM site_disabled_models WHERE site_id = ?');
  const deleteSite = sqlite.prepare('DELETE FROM sites WHERE id = ?');

  const siteIdMapping = new Map<number, number>();

  const transaction = sqlite.transaction(() => {
    for (const group of duplicateGroups) {
      const sites = selectSitesByIdentity.all(group.platform, group.url) as LegacySiteRow[];
      if (sites.length <= 1) continue;

      const canonicalSiteId = sites[0]!.id;
      for (const site of sites.slice(1)) {
        mergeDisabledModels.run(canonicalSiteId, site.id);
        deleteDisabledModels.run(site.id);
        rebindAccounts.run(canonicalSiteId, site.id);
        siteIdMapping.set(site.id, canonicalSiteId);
        deleteSite.run(site.id);
      }
    }

    rewriteDownstreamSiteWeightMultipliers(sqlite, siteIdMapping);
  });

  transaction();
  if (siteIdMapping.size > 0) {
    console.warn(`[db] Deduplicated ${siteIdMapping.size} legacy site entries before applying sites_platform_url_unique.`);
  }
  return siteIdMapping.size > 0;
}

export const __migrateTestUtils = {
  splitMigrationStatements,
  normalizeSqlForMatch,
  extractFailedSqlFromError,
  findMatchingSingleStatementMigration,
  findMatchingMigrationByStatement,
  findMatchingMigrationByErrorMessage,
  readRecoveryMigrations,
  markMigrationRecordIfMissing,
  recoverMigrationSequence,
  tryRecoverDuplicateColumnMigrationError,
  isSitesPlatformUrlUniqueConflictError,
  deduplicateLegacySitesForUniqueIndex,
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
  backfillMissingRecordedMigrations(sqlite, migrationsFolder);

  try {
    migrate(drizzle(sqlite), { migrationsFolder });
  } catch (error) {
    const recoveredDuplicateColumns = tryRecoverDuplicateColumnMigrationError(sqlite, migrationsFolder, error);
    const recoveredDuplicateSites = (
      !recoveredDuplicateColumns
      && isSitesPlatformUrlUniqueConflictError(error)
      && deduplicateLegacySitesForUniqueIndex(sqlite)
    );
    if (!recoveredDuplicateColumns && !recoveredDuplicateSites) {
      sqlite.close();
      throw error;
    }
    migrate(drizzle(sqlite), { migrationsFolder });
  }

  sqlite.close();
  console.log('Migration complete.');
}

runSqliteMigrations();
