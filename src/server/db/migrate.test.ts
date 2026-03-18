import Database from 'better-sqlite3';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

type MigrationJournalEntry = {
  tag: string;
  when: number;
};

const migrationsDir = resolve(dirname(fileURLToPath(import.meta.url)), '../../../drizzle');

function readMigrationJournalEntries(): MigrationJournalEntry[] {
  const journalPath = join(migrationsDir, 'meta', '_journal.json');
  const journal = JSON.parse(readFileSync(journalPath, 'utf8')) as { entries?: MigrationJournalEntry[] };
  return journal.entries ?? [];
}

function applyMigrationSql(sqlite: Database.Database, sqlText: string) {
  const statements = sqlText
    .split('--> statement-breakpoint')
    .map((statement) => statement.trim())
    .filter((statement) => statement.length > 0);

  for (const statement of statements) {
    sqlite.exec(statement);
  }
}

function recordAppliedMigrations(
  sqlite: Database.Database,
  journalEntries: MigrationJournalEntry[],
) {
  sqlite.exec(`
    CREATE TABLE IF NOT EXISTS "__drizzle_migrations" (
      id SERIAL PRIMARY KEY,
      hash text NOT NULL,
      created_at numeric
    )
  `);

  const insert = sqlite.prepare('INSERT INTO "__drizzle_migrations" ("hash", "created_at") VALUES (?, ?)');
  for (const entry of journalEntries) {
    const sqlText = readFileSync(join(migrationsDir, `${entry.tag}.sql`), 'utf8');
    const hash = createHash('sha256').update(sqlText).digest('hex');
    insert.run(hash, entry.when);
  }
}

describe('sqlite migrate bootstrap', () => {
  afterEach(() => {
    delete process.env.DATA_DIR;
    delete process.env.DB_URL;
    vi.resetModules();
  });

  it('accepts an already-synced sqlite schema with an empty drizzle journal', async () => {
    const dataDir = mkdtempSync(join(tmpdir(), 'metapi-migrate-'));
    const dbPath = join(dataDir, 'hub.db');
    const sqlite = new Database(dbPath);
    const journalEntries = readMigrationJournalEntries();

    for (const entry of journalEntries) {
      const sqlText = readFileSync(join(migrationsDir, `${entry.tag}.sql`), 'utf8');
      applyMigrationSql(sqlite, sqlText);
    }

    sqlite.close();

    process.env.DATA_DIR = dataDir;
    vi.resetModules();

    await expect(import('./migrate.js')).resolves.toMatchObject({
      runSqliteMigrations: expect.any(Function),
    });

    const verified = new Database(dbPath, { readonly: true });
    const appliedRows = verified
      .prepare('select created_at from __drizzle_migrations order by created_at asc')
      .all() as Array<{ created_at: number }>;

    expect(appliedRows.map((row) => Number(row.created_at))).toEqual(
      journalEntries.map((entry) => entry.when),
    );

    verified.close();
  });

  it('recovers from duplicate-column errors for single-statement migrations', async () => {
    const dataDir = mkdtempSync(join(tmpdir(), 'metapi-migrate-recover-'));
    process.env.DATA_DIR = dataDir;
    vi.resetModules();

    const migrateModule = await import('./migrate.js');
    const { __migrateTestUtils } = migrateModule;

    const sqlite = new Database(':memory:');
    sqlite.exec(`
      CREATE TABLE account_tokens (
        id integer PRIMARY KEY AUTOINCREMENT NOT NULL,
        token_group text
      );
    `);

    const tempMigrationsDir = mkdtempSync(join(tmpdir(), 'metapi-migration-files-'));
    mkdirSync(join(tempMigrationsDir, 'meta'), { recursive: true });

    writeFileSync(
      join(tempMigrationsDir, 'meta', '_journal.json'),
      JSON.stringify({
        entries: [
          {
            tag: '0007_account_token_group',
            when: 1772500000000,
          },
        ],
      }),
    );

    writeFileSync(
      join(tempMigrationsDir, '0007_account_token_group.sql'),
      'ALTER TABLE `account_tokens` ADD `token_group` text;\n',
    );

    const duplicateColumnError = new Error(
      "DrizzleError: Failed to run the query 'ALTER TABLE `account_tokens` ADD `token_group` text;\n' duplicate column name: token_group",
    );

    const recovered = __migrateTestUtils.tryRecoverDuplicateColumnMigrationError(
      sqlite,
      tempMigrationsDir,
      duplicateColumnError,
    );

    expect(recovered).toBe(true);

    const applied = sqlite
      .prepare('SELECT hash, created_at FROM __drizzle_migrations')
      .all() as Array<{ hash: string; created_at: number }>;

    expect(applied).toHaveLength(1);
    expect(Number(applied[0].created_at)).toBe(1772500000000);

    sqlite.close();
  });

  it('recovers when duplicate-column message appears only in error cause', async () => {
    const dataDir = mkdtempSync(join(tmpdir(), 'metapi-migrate-recover-cause-'));
    process.env.DATA_DIR = dataDir;
    vi.resetModules();

    const migrateModule = await import('./migrate.js');
    const { __migrateTestUtils } = migrateModule;

    const sqlite = new Database(':memory:');
    sqlite.exec(`
      CREATE TABLE account_tokens (
        id integer PRIMARY KEY AUTOINCREMENT NOT NULL,
        token_group text
      );
    `);

    const tempMigrationsDir = mkdtempSync(join(tmpdir(), 'metapi-migration-files-cause-'));
    mkdirSync(join(tempMigrationsDir, 'meta'), { recursive: true });

    writeFileSync(
      join(tempMigrationsDir, 'meta', '_journal.json'),
      JSON.stringify({
        entries: [
          {
            tag: '0007_account_token_group',
            when: 1772500000001,
          },
        ],
      }),
    );

    writeFileSync(
      join(tempMigrationsDir, '0007_account_token_group.sql'),
      'ALTER TABLE `account_tokens` ADD `token_group` text;\n',
    );

    const drizzleLikeError = {
      message: "DrizzleError: Failed to run the query 'ALTER TABLE `account_tokens` ADD `token_group` text;\n'",
      cause: {
        message: 'SqliteError: duplicate column name: token_group',
      },
    };

    const recovered = __migrateTestUtils.tryRecoverDuplicateColumnMigrationError(
      sqlite,
      tempMigrationsDir,
      drizzleLikeError,
    );

    expect(recovered).toBe(true);

    const applied = sqlite
      .prepare('SELECT hash, created_at FROM __drizzle_migrations')
      .all() as Array<{ hash: string; created_at: number }>;

    expect(applied).toHaveLength(1);
    expect(Number(applied[0].created_at)).toBe(1772500000001);

    sqlite.close();
  });

  it('recovers duplicate-column errors when the failed SQL contains quoted literals', async () => {
    const dataDir = mkdtempSync(join(tmpdir(), 'metapi-migrate-recover-quoted-'));
    process.env.DATA_DIR = dataDir;
    vi.resetModules();

    const migrateModule = await import('./migrate.js');
    const { __migrateTestUtils } = migrateModule;

    const sqlite = new Database(':memory:');
    sqlite.exec(`
      CREATE TABLE account_tokens (
        id integer PRIMARY KEY AUTOINCREMENT NOT NULL,
        value_status text DEFAULT 'ready' NOT NULL
      );
    `);

    const tempMigrationsDir = mkdtempSync(join(tmpdir(), 'metapi-migration-files-quoted-'));
    mkdirSync(join(tempMigrationsDir, 'meta'), { recursive: true });

    writeFileSync(
      join(tempMigrationsDir, 'meta', '_journal.json'),
      JSON.stringify({
        entries: [
          {
            tag: '0012_account_token_value_status',
            when: 1773665311013,
          },
        ],
      }),
    );

    writeFileSync(
      join(tempMigrationsDir, '0012_account_token_value_status.sql'),
      "ALTER TABLE `account_tokens` ADD `value_status` text DEFAULT 'ready' NOT NULL;\n",
    );

    const duplicateColumnError = new Error(
      "DrizzleError: Failed to run the query 'ALTER TABLE `account_tokens` ADD `value_status` text DEFAULT 'ready' NOT NULL;\n' duplicate column name: value_status",
    );

    const recovered = __migrateTestUtils.tryRecoverDuplicateColumnMigrationError(
      sqlite,
      tempMigrationsDir,
      duplicateColumnError,
    );

    expect(recovered).toBe(true);

    const applied = sqlite
      .prepare('SELECT hash, created_at FROM __drizzle_migrations')
      .all() as Array<{ hash: string; created_at: number }>;

    expect(applied).toHaveLength(1);
    expect(Number(applied[0].created_at)).toBe(1773665311013);

    sqlite.close();
  });

  it('recovers duplicate-column errors inside multi-statement migrations by replaying the full migration', async () => {
    const dataDir = mkdtempSync(join(tmpdir(), 'metapi-migrate-recover-multi-'));
    process.env.DATA_DIR = dataDir;
    vi.resetModules();

    const migrateModule = await import('./migrate.js');
    const { __migrateTestUtils } = migrateModule;

    const sqlite = new Database(':memory:');
    sqlite.exec(`
      CREATE TABLE account_tokens (
        id integer PRIMARY KEY AUTOINCREMENT NOT NULL,
        token_group text
      );
    `);

    const tempMigrationsDir = mkdtempSync(join(tmpdir(), 'metapi-migration-files-multi-'));
    mkdirSync(join(tempMigrationsDir, 'meta'), { recursive: true });

    writeFileSync(
      join(tempMigrationsDir, 'meta', '_journal.json'),
      JSON.stringify({
        entries: [
          {
            tag: '0009_model_availability_is_manual',
            when: 1772600000000,
          },
        ],
      }),
    );

    writeFileSync(
      join(tempMigrationsDir, '0009_model_availability_is_manual.sql'),
      [
        'CREATE TABLE IF NOT EXISTS `downstream_api_keys` (`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL);',
        'ALTER TABLE `account_tokens` ADD `token_group` text;',
      ].join('\n--> statement-breakpoint\n'),
    );

    const duplicateColumnError = new Error(
      "DrizzleError: Failed to run the query 'ALTER TABLE `account_tokens` ADD `token_group` text;\n' duplicate column name: token_group",
    );

    const recovered = __migrateTestUtils.tryRecoverDuplicateColumnMigrationError(
      sqlite,
      tempMigrationsDir,
      duplicateColumnError,
    );

    expect(recovered).toBe(true);

    const createdTable = sqlite
      .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'downstream_api_keys'")
      .get() as { name?: string } | undefined;
    const applied = sqlite
      .prepare('SELECT hash, created_at FROM __drizzle_migrations')
      .all() as Array<{ hash: string; created_at: number }>;

    expect(createdTable?.name).toBe('downstream_api_keys');
    expect(applied).toHaveLength(1);
    expect(Number(applied[0].created_at)).toBe(1772600000000);

    sqlite.close();
  });

  it('replays missing migrations before marking a duplicate-column migration as applied', async () => {
    const dataDir = mkdtempSync(join(tmpdir(), 'metapi-migrate-partial-journal-'));
    const dbPath = join(dataDir, 'hub.db');
    const sqlite = new Database(dbPath);
    const journalEntries = readMigrationJournalEntries();
    const missingTags = new Set([
      '0006_site_disabled_models',
      '0007_account_token_group',
      '0008_sqlite_schema_backfill',
      '0009_model_availability_is_manual',
      '0010_proxy_logs_downstream_api_key',
      '0011_downstream_api_key_metadata',
      '0012_account_token_value_status',
      '0013_oauth_multi_provider',
    ]);
    const appliedEntries = journalEntries.filter((entry) => !missingTags.has(entry.tag));

    for (const entry of appliedEntries) {
      const sqlText = readFileSync(join(migrationsDir, `${entry.tag}.sql`), 'utf8');
      applyMigrationSql(sqlite, sqlText);
    }
    recordAppliedMigrations(sqlite, appliedEntries);

    // Simulate legacy compatibility code adding token_group before the formal 0007 migration ran.
    sqlite.exec('ALTER TABLE account_tokens ADD COLUMN token_group text;');
    sqlite.close();

    process.env.DATA_DIR = dataDir;
    vi.resetModules();

    await expect(import('./migrate.js')).resolves.toMatchObject({
      runSqliteMigrations: expect.any(Function),
    });

    const verified = new Database(dbPath, { readonly: true });
    const appliedRows = verified
      .prepare('SELECT created_at FROM __drizzle_migrations ORDER BY created_at ASC')
      .all() as Array<{ created_at: number }>;
    const disabledModelsTable = verified
      .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'site_disabled_models'")
      .get() as { name?: string } | undefined;
    const downstreamApiKeysTable = verified
      .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'downstream_api_keys'")
      .get() as { name?: string } | undefined;

    expect(disabledModelsTable?.name).toBe('site_disabled_models');
    expect(downstreamApiKeysTable?.name).toBe('downstream_api_keys');
    expect(appliedRows.map((row) => Number(row.created_at))).toEqual(
      journalEntries.map((entry) => entry.when),
    );

    verified.close();
  });

  it('deduplicates legacy duplicate sites before applying the oauth site unique index', async () => {
    const dataDir = mkdtempSync(join(tmpdir(), 'metapi-migrate-duplicate-sites-'));
    const dbPath = join(dataDir, 'hub.db');
    const sqlite = new Database(dbPath);
    const journalEntries = readMigrationJournalEntries();
    const appliedEntries = journalEntries.filter((entry) => entry.tag !== '0013_oauth_multi_provider');

    for (const entry of appliedEntries) {
      const sqlText = readFileSync(join(migrationsDir, `${entry.tag}.sql`), 'utf8');
      applyMigrationSql(sqlite, sqlText);
    }
    recordAppliedMigrations(sqlite, appliedEntries);

    sqlite.exec(`
      INSERT INTO sites (id, name, url, platform, status, is_pinned, sort_order, global_weight)
      VALUES
        (101, 'Primary Codex', 'https://chatgpt.com/backend-api/codex', 'codex', 'active', 0, 0, 1),
        (202, 'Duplicate Codex', 'https://chatgpt.com/backend-api/codex', 'codex', 'disabled', 1, 9, 3);

      INSERT INTO accounts (site_id, username, access_token, status, checkin_enabled)
      VALUES
        (101, 'first@example.com', 'token-a', 'active', 0),
        (202, 'second@example.com', 'token-b', 'disabled', 0);

      INSERT INTO site_disabled_models (site_id, model_name)
      VALUES
        (101, 'gpt-5'),
        (202, 'gpt-5'),
        (202, 'gpt-5-mini');
    `);

    sqlite.close();

    process.env.DATA_DIR = dataDir;
    vi.resetModules();

    await expect(import('./migrate.js')).resolves.toMatchObject({
      runSqliteMigrations: expect.any(Function),
    });

    const verified = new Database(dbPath, { readonly: true });
    const sites = verified
      .prepare('SELECT id, name, url, platform, status, is_pinned, sort_order, global_weight FROM sites ORDER BY id ASC')
      .all() as Array<{
      id: number;
      name: string;
      url: string;
      platform: string;
      status: string;
      is_pinned: number;
      sort_order: number;
      global_weight: number;
    }>;
    const accounts = verified
      .prepare('SELECT username, site_id FROM accounts ORDER BY username ASC')
      .all() as Array<{ username: string; site_id: number }>;
    const disabledModels = verified
      .prepare('SELECT site_id, model_name FROM site_disabled_models ORDER BY site_id ASC, model_name ASC')
      .all() as Array<{ site_id: number; model_name: string }>;

    expect(sites).toEqual([
      expect.objectContaining({
        id: 101,
        name: 'Primary Codex',
        url: 'https://chatgpt.com/backend-api/codex',
        platform: 'codex',
      }),
    ]);
    expect(accounts).toEqual([
      { username: 'first@example.com', site_id: 101 },
      { username: 'second@example.com', site_id: 101 },
    ]);
    expect(disabledModels).toEqual([
      { site_id: 101, model_name: 'gpt-5' },
      { site_id: 101, model_name: 'gpt-5-mini' },
    ]);

    verified.close();
  });
});
