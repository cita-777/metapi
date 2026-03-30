import Database from 'better-sqlite3';
import mysql from 'mysql2/promise';
import pg from 'pg';
import { drizzle as drizzleSqliteProxy } from 'drizzle-orm/sqlite-proxy';
import { drizzle as drizzleMysqlProxy } from 'drizzle-orm/mysql-proxy';
import { drizzle as drizzlePgProxy } from 'drizzle-orm/pg-proxy';
import * as schema from './schema.js';
import {
  installPostgresJsonTextParsers,
  resetPostgresJsonTextParsersInstallStateForTests,
} from './postgresJsonTextParsers.js';
import { ensureSiteSchemaCompatibility, type SiteSchemaInspector } from './siteSchemaCompatibility.js';
import { ensureRouteGroupingSchemaCompatibility } from './routeGroupingSchemaCompatibility.js';
import { ensureProxyFileSchemaCompatibility } from './proxyFileSchemaCompatibility.js';
import { executeLegacyCompat, executeLegacyCompatSync } from './legacySchemaCompat.js';
import { config } from '../config.js';
import { ensureRuntimeDatabaseReady } from '../runtimeDatabaseBootstrap.js';
import { mkdirSync } from 'fs';
import { tmpdir } from 'os';
import { dirname, resolve } from 'path';
import { threadId } from 'worker_threads';

export type RuntimeDbDialect = 'sqlite' | 'mysql' | 'postgres';
type SqlMethod = 'all' | 'get' | 'run' | 'values' | 'execute';

const TABLES_WITH_NUMERIC_ID = new Set([
  'sites',
  'accounts',
  'account_tokens',
  'checkin_logs',
  'model_availability',
  'token_model_availability',
  'token_routes',
  'route_group_sources',
  'route_channels',
  'proxy_logs',
  'proxy_debug_traces',
  'proxy_debug_attempts',
  'proxy_video_tasks',
  'proxy_files',
  'downstream_api_keys',
  'site_announcements',
  'events',
]);

export let runtimeDbDialect: RuntimeDbDialect = config.dbType;

let sqliteConnection: Database.Database | null = null;
let mysqlPool: mysql.Pool | null = null;
let pgPool: pg.Pool | null = null;
let proxyLogBillingDetailsColumnAvailable: boolean | null = null;
let proxyLogDownstreamApiKeyIdColumnAvailable: boolean | null = null;
let proxyLogClientColumnsAvailable: boolean | null = null;

function buildMysqlPoolOptions(
  connectionString = config.dbUrl,
  sslEnabled = config.dbSsl,
): mysql.PoolOptions {
  const poolOptions: mysql.PoolOptions = {
    uri: connectionString,
    jsonStrings: true,
  };
  if (sslEnabled) {
    poolOptions.ssl = { rejectUnauthorized: false };
  }
  return poolOptions;
}

function buildPostgresPoolOptions(
  connectionString = config.dbUrl,
  sslEnabled = config.dbSsl,
): pg.PoolConfig {
  const poolOptions: pg.PoolConfig = { connectionString };
  if (sslEnabled) {
    poolOptions.ssl = { rejectUnauthorized: false };
  }
  return poolOptions;
}

function resolveSqlitePath(): string {
  const raw = (config.dbUrl || '').trim();
  if (!raw) {
    const isolatedVitestPath = resolveVitestSqlitePath();
    if (isolatedVitestPath) {
      return isolatedVitestPath;
    }
    return resolve(`${config.dataDir}/hub.db`);
  }
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

function isVitestRuntime(): boolean {
  if ((process.env.VITEST_POOL_ID || '').trim()) {
    return true;
  }
  if ((process.env.VITEST_WORKER_ID || '').trim()) {
    return true;
  }
  const runtimeArgs = [...process.argv, ...process.execArgv]
    .map((value) => String(value || '').toLowerCase());
  return runtimeArgs.some((value) => value.includes('vitest'));
}

function isDefaultRepoDataDir(value: string | undefined): boolean {
  const trimmed = (value || '').trim();
  if (!trimmed) return false;
  return resolve(trimmed) === resolve('./data');
}

function resolveVitestSqlitePath(): string | null {
  if (!isVitestRuntime()) {
    return null;
  }
  if ((process.env.DB_URL || '').trim()) {
    return null;
  }
  if ((process.env.DATA_DIR || '').trim() && !isDefaultRepoDataDir(process.env.DATA_DIR)) {
    return null;
  }

  const workerTag = process.env.VITEST_POOL_ID
    || process.env.VITEST_WORKER_ID
    || `${process.pid}-${threadId}`;
  return resolve(tmpdir(), `metapi-vitest-${workerTag}`, 'hub.db');
}

function requireSqliteConnection(): Database.Database {
  if (!sqliteConnection) {
    throw new Error('SQLite connection is not initialized');
  }
  return sqliteConnection;
}

function tableExists(table: string): boolean {
  const sqlite = requireSqliteConnection();
  const row = sqlite.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ? LIMIT 1")
    .get(table) as { name?: string } | undefined;
  return !!row?.name;
}

function tableColumnExists(table: string, column: string): boolean {
  const sqlite = requireSqliteConnection();
  const rows = sqlite.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name?: string }>;
  return rows.some((row) => row.name === column);
}

function tableIndexExists(indexName: string): boolean {
  const sqlite = requireSqliteConnection();
  const row = sqlite.prepare("SELECT name FROM sqlite_master WHERE type = 'index' AND name = ? LIMIT 1")
    .get(indexName) as { name?: string } | undefined;
  return !!row?.name;
}

function execSqliteStatement(sqlText: string): void {
  requireSqliteConnection().exec(sqlText);
}

function execSqliteLegacyCompat(sqlText: string): void {
  executeLegacyCompatSync(execSqliteStatement, sqlText);
}

function ensureTokenManagementSchema() {
  if (!tableExists('accounts') || !tableExists('route_channels')) {
    return;
  }
  execSqliteLegacyCompat(`
    CREATE TABLE IF NOT EXISTS account_tokens (
      id integer PRIMARY KEY AUTOINCREMENT NOT NULL,
      account_id integer NOT NULL,
      name text NOT NULL,
      token text NOT NULL,
      token_group text,
      value_status text NOT NULL DEFAULT 'ready',
      source text DEFAULT 'manual',
      enabled integer DEFAULT true,
      is_default integer DEFAULT false,
      created_at text DEFAULT (datetime('now')),
      updated_at text DEFAULT (datetime('now')),
      FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE cascade
    );
  `);
  if (!tableColumnExists('route_channels', 'token_id')) {
    execSqliteLegacyCompat('ALTER TABLE route_channels ADD COLUMN token_id integer;');
  }

  if (!tableColumnExists('account_tokens', 'token_group')) {
    execSqliteLegacyCompat('ALTER TABLE account_tokens ADD COLUMN token_group text;');
  }
  if (!tableColumnExists('account_tokens', 'value_status')) {
    execSqliteLegacyCompat("ALTER TABLE account_tokens ADD COLUMN value_status text NOT NULL DEFAULT 'ready';");
  }

  execSqliteStatement(`
    INSERT INTO account_tokens (account_id, name, token, source, enabled, is_default, created_at, updated_at)
    SELECT
      a.id,
      'default',
      a.api_token,
      'legacy',
      true,
      true,
      datetime('now'),
      datetime('now')
    FROM accounts AS a
    WHERE
      a.api_token IS NOT NULL
      AND trim(a.api_token) <> ''
      AND a.access_token IS NOT NULL
      AND trim(a.access_token) <> ''
      AND NOT EXISTS (
        SELECT 1 FROM account_tokens AS t
        WHERE t.account_id = a.id
        AND t.token = a.api_token
      );
  `);

  execSqliteLegacyCompat(`
    CREATE TABLE IF NOT EXISTS token_model_availability (
      id integer PRIMARY KEY AUTOINCREMENT NOT NULL,
      token_id integer NOT NULL,
      model_name text NOT NULL,
      available integer,
      latency_ms integer,
      checked_at text DEFAULT (datetime('now')),
      FOREIGN KEY (token_id) REFERENCES account_tokens(id) ON DELETE cascade
    );
  `);

  execSqliteLegacyCompat(`
    CREATE UNIQUE INDEX IF NOT EXISTS token_model_availability_token_model_unique
    ON token_model_availability(token_id, model_name);
  `);
}

function ensureProxyVideoTaskSchema() {
  execSqliteLegacyCompat(`
    CREATE TABLE IF NOT EXISTS proxy_video_tasks (
      id integer PRIMARY KEY AUTOINCREMENT NOT NULL,
      public_id text NOT NULL,
      upstream_video_id text NOT NULL,
      site_url text NOT NULL,
      token_value text NOT NULL,
      requested_model text,
      actual_model text,
      channel_id integer,
      account_id integer,
      status_snapshot text,
      upstream_response_meta text,
      last_upstream_status integer,
      last_polled_at text,
      created_at text DEFAULT (datetime('now')),
      updated_at text DEFAULT (datetime('now'))
    );
  `);
  if (!tableColumnExists('proxy_video_tasks', 'status_snapshot')) {
    execSqliteLegacyCompat('ALTER TABLE proxy_video_tasks ADD COLUMN status_snapshot text;');
  }
  if (!tableColumnExists('proxy_video_tasks', 'upstream_response_meta')) {
    execSqliteLegacyCompat('ALTER TABLE proxy_video_tasks ADD COLUMN upstream_response_meta text;');
  }
  if (!tableColumnExists('proxy_video_tasks', 'last_upstream_status')) {
    execSqliteLegacyCompat('ALTER TABLE proxy_video_tasks ADD COLUMN last_upstream_status integer;');
  }
  if (!tableColumnExists('proxy_video_tasks', 'last_polled_at')) {
    execSqliteLegacyCompat('ALTER TABLE proxy_video_tasks ADD COLUMN last_polled_at text;');
  }
  execSqliteLegacyCompat(`
    CREATE UNIQUE INDEX IF NOT EXISTS proxy_video_tasks_public_id_unique
    ON proxy_video_tasks(public_id);
  `);
  execSqliteLegacyCompat(`
    CREATE INDEX IF NOT EXISTS proxy_video_tasks_upstream_video_id_idx
    ON proxy_video_tasks(upstream_video_id);
  `);
}

function ensureProxyFileSchema() {
  execSqliteLegacyCompat(`
    CREATE TABLE IF NOT EXISTS proxy_files (
      id integer PRIMARY KEY AUTOINCREMENT NOT NULL,
      public_id text NOT NULL,
      owner_type text NOT NULL,
      owner_id text NOT NULL,
      filename text NOT NULL,
      mime_type text NOT NULL,
      purpose text,
      byte_size integer NOT NULL,
      sha256 text NOT NULL,
      content_base64 text NOT NULL,
      created_at text DEFAULT (datetime('now')),
      updated_at text DEFAULT (datetime('now')),
      deleted_at text
    );
  `);
  execSqliteLegacyCompat(`
    CREATE UNIQUE INDEX IF NOT EXISTS proxy_files_public_id_unique
    ON proxy_files(public_id);
  `);
  execSqliteLegacyCompat(`
    CREATE INDEX IF NOT EXISTS proxy_files_owner_lookup_idx
    ON proxy_files(owner_type, owner_id, deleted_at);
  `);
}

function ensureSiteStatusSchema() {
  if (!tableExists('sites')) {
    return;
  }

  if (!tableColumnExists('sites', 'status')) {
    execSqliteLegacyCompat(`ALTER TABLE sites ADD COLUMN status text DEFAULT 'active';`);
  }

  execSqliteStatement(`
    UPDATE sites
    SET status = lower(trim(status))
    WHERE status IS NOT NULL
      AND lower(trim(status)) IN ('active', 'disabled')
      AND status != lower(trim(status));
  `);

  execSqliteStatement(`
    UPDATE sites
    SET status = 'active'
    WHERE status IS NULL
      OR trim(status) = ''
      OR lower(trim(status)) NOT IN ('active', 'disabled');
  `);
}

function ensureSiteProxySchema() {
  if (!tableExists('sites')) {
    return;
  }

  if (!tableColumnExists('sites', 'proxy_url')) {
    execSqliteLegacyCompat(`ALTER TABLE sites ADD COLUMN proxy_url text;`);
  }
}

function ensureSiteUseSystemProxySchema() {
  if (!tableExists('sites')) {
    return;
  }

  if (!tableColumnExists('sites', 'use_system_proxy')) {
    execSqliteLegacyCompat(`ALTER TABLE sites ADD COLUMN use_system_proxy integer DEFAULT 0;`);
  }

  execSqliteLegacyCompat(`
    UPDATE sites
    SET use_system_proxy = 0
    WHERE use_system_proxy IS NULL;
  `);
}

function ensureSiteCustomHeadersSchema() {
  if (!tableExists('sites')) {
    return;
  }

  if (!tableColumnExists('sites', 'custom_headers')) {
    execSqliteLegacyCompat(`ALTER TABLE sites ADD COLUMN custom_headers text;`);
  }
}

function ensureSiteExternalCheckinUrlSchema() {
  if (!tableExists('sites')) {
    return;
  }

  if (!tableColumnExists('sites', 'external_checkin_url')) {
    execSqliteLegacyCompat(`ALTER TABLE sites ADD COLUMN external_checkin_url text;`);
  }
}

function ensureSiteGlobalWeightSchema() {
  if (!tableExists('sites')) {
    return;
  }

  if (!tableColumnExists('sites', 'global_weight')) {
    execSqliteLegacyCompat(`ALTER TABLE sites ADD COLUMN global_weight real DEFAULT 1;`);
  }

  execSqliteLegacyCompat(`
    UPDATE sites
    SET global_weight = 1
    WHERE global_weight IS NULL
      OR global_weight <= 0;
  `);
}

type RuntimeSchemaInspector = {
  dialect: SiteSchemaInspector['dialect'];
  tableExists(table: string): Promise<boolean>;
  columnExists(table: string, column: string): Promise<boolean>;
  execute(sqlText: string): Promise<void>;
};

function createSqliteSchemaInspector(): RuntimeSchemaInspector {
  return {
    dialect: 'sqlite',
    tableExists: async (table) => tableExists(table),
    columnExists: async (table, column) => tableColumnExists(table, column),
    execute: async (sqlText) => {
      executeLegacyCompatSync(execSqliteStatement, sqlText);
    },
  };
}

function createMysqlSchemaInspector(): RuntimeSchemaInspector | null {
  if (!mysqlPool) return null;
  return {
      dialect: 'mysql',
      tableExists: async (table) => {
        const [rows] = await mysqlPool!.query(
          'SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = ? LIMIT 1',
          [table],
        );
        return Array.isArray(rows) && rows.length > 0;
      },
      columnExists: async (table, column) => {
        const [rows] = await mysqlPool!.query(
          'SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ? LIMIT 1',
          [table, column],
        );
        return Array.isArray(rows) && rows.length > 0;
      },
      execute: async (sqlText) => {
        await executeLegacyCompat((statement) => mysqlPool!.query(statement).then(() => undefined), sqlText);
      },
    };
}

function createPostgresSchemaInspector(): RuntimeSchemaInspector | null {
  if (!pgPool) return null;
  return {
    dialect: 'postgres',
    tableExists: async (table) => {
      const result = await pgPool!.query(
        'SELECT 1 FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = $1 LIMIT 1',
        [table],
      );
      return Number(result.rowCount || 0) > 0;
    },
    columnExists: async (table, column) => {
      const result = await pgPool!.query(
        'SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = $1 AND column_name = $2 LIMIT 1',
        [table, column],
      );
      return Number(result.rowCount || 0) > 0;
    },
    execute: async (sqlText) => {
      await executeLegacyCompat((statement) => pgPool!.query(statement).then(() => undefined), sqlText);
    },
  };
}

function createRuntimeSchemaInspector(): RuntimeSchemaInspector | null {
  if (runtimeDbDialect === 'sqlite') {
    return createSqliteSchemaInspector();
  }
  if (runtimeDbDialect === 'mysql') {
    return createMysqlSchemaInspector();
  }
  return createPostgresSchemaInspector();
}

export async function ensureSiteCompatibilityColumns(): Promise<void> {
  const inspector = createRuntimeSchemaInspector();
  if (!inspector) return;
  await ensureSiteSchemaCompatibility(inspector);
}

export async function ensureRouteGroupingCompatibilityColumns(): Promise<void> {
  const inspector = createRuntimeSchemaInspector();
  if (!inspector) return;
  await ensureRouteGroupingSchemaCompatibility(inspector);
}

export async function ensureProxyFileCompatibilityColumns(): Promise<void> {
  const inspector = createRuntimeSchemaInspector();
  if (!inspector) return;
  await ensureProxyFileSchemaCompatibility(inspector);
}

function ensureRouteGroupingSchema() {
  if (!tableExists('token_routes') || !tableExists('route_channels')) {
    return;
  }

  if (!tableColumnExists('token_routes', 'display_name')) {
    execSqliteLegacyCompat(`ALTER TABLE token_routes ADD COLUMN display_name text;`);
  }

  if (!tableColumnExists('token_routes', 'display_icon')) {
    execSqliteLegacyCompat(`ALTER TABLE token_routes ADD COLUMN display_icon text;`);
  }

  if (!tableColumnExists('token_routes', 'route_mode')) {
    execSqliteLegacyCompat(`ALTER TABLE token_routes ADD COLUMN route_mode text DEFAULT 'pattern';`);
  }

  if (!tableColumnExists('token_routes', 'decision_snapshot')) {
    execSqliteLegacyCompat(`ALTER TABLE token_routes ADD COLUMN decision_snapshot text;`);
  }

  if (!tableColumnExists('token_routes', 'decision_refreshed_at')) {
    execSqliteLegacyCompat(`ALTER TABLE token_routes ADD COLUMN decision_refreshed_at text;`);
  }

  if (!tableColumnExists('token_routes', 'routing_strategy')) {
    execSqliteLegacyCompat(`ALTER TABLE token_routes ADD COLUMN routing_strategy text DEFAULT 'weighted';`);
  }

  if (!tableColumnExists('route_channels', 'source_model')) {
    execSqliteLegacyCompat(`ALTER TABLE route_channels ADD COLUMN source_model text;`);
  }

  if (!tableColumnExists('route_channels', 'last_selected_at')) {
    execSqliteLegacyCompat(`ALTER TABLE route_channels ADD COLUMN last_selected_at text;`);
  }

  if (!tableColumnExists('route_channels', 'consecutive_fail_count')) {
    execSqliteLegacyCompat(`ALTER TABLE route_channels ADD COLUMN consecutive_fail_count integer NOT NULL DEFAULT 0;`);
  }

  if (!tableColumnExists('route_channels', 'cooldown_level')) {
    execSqliteLegacyCompat(`ALTER TABLE route_channels ADD COLUMN cooldown_level integer NOT NULL DEFAULT 0;`);
  }

  execSqliteLegacyCompat(`
    CREATE TABLE IF NOT EXISTS route_group_sources (
      id integer PRIMARY KEY AUTOINCREMENT NOT NULL,
      group_route_id integer NOT NULL REFERENCES token_routes(id) ON DELETE cascade,
      source_route_id integer NOT NULL REFERENCES token_routes(id) ON DELETE cascade
    );
  `);
  execSqliteLegacyCompat(`
    CREATE UNIQUE INDEX IF NOT EXISTS route_group_sources_group_source_unique
    ON route_group_sources(group_route_id, source_route_id);
  `);
  execSqliteLegacyCompat(`
    CREATE INDEX IF NOT EXISTS route_group_sources_source_route_id_idx
    ON route_group_sources(source_route_id);
  `);
}

function ensureDownstreamApiKeySchema() {
  execSqliteLegacyCompat(`
    CREATE TABLE IF NOT EXISTS downstream_api_keys (
      id integer PRIMARY KEY AUTOINCREMENT NOT NULL,
      name text NOT NULL,
      key text NOT NULL,
      description text,
      group_name text,
      tags text,
      enabled integer DEFAULT true,
      expires_at text,
      max_cost real,
      used_cost real DEFAULT 0,
      max_requests integer,
      used_requests integer DEFAULT 0,
      supported_models text,
      allowed_route_ids text,
      site_weight_multipliers text,
      last_used_at text,
      created_at text DEFAULT (datetime('now')),
      updated_at text DEFAULT (datetime('now'))
    );
  `);

  execSqliteLegacyCompat(`
    CREATE UNIQUE INDEX IF NOT EXISTS downstream_api_keys_key_unique
    ON downstream_api_keys(key);
  `);
  execSqliteLegacyCompat(`
    CREATE INDEX IF NOT EXISTS downstream_api_keys_name_idx
    ON downstream_api_keys(name);
  `);
  execSqliteLegacyCompat(`
    CREATE INDEX IF NOT EXISTS downstream_api_keys_enabled_idx
    ON downstream_api_keys(enabled);
  `);
  execSqliteLegacyCompat(`
    CREATE INDEX IF NOT EXISTS downstream_api_keys_expires_at_idx
    ON downstream_api_keys(expires_at);
  `);

  if (!tableColumnExists('downstream_api_keys', 'group_name')) {
    execSqliteLegacyCompat('ALTER TABLE downstream_api_keys ADD COLUMN group_name text;');
  }

  if (!tableColumnExists('downstream_api_keys', 'tags')) {
    execSqliteLegacyCompat('ALTER TABLE downstream_api_keys ADD COLUMN tags text;');
  }
}

function ensureProxyLogBillingDetailsSchema() {
  if (!tableExists('proxy_logs')) {
    return;
  }

  if (!tableColumnExists('proxy_logs', 'billing_details')) {
    execSqliteLegacyCompat('ALTER TABLE proxy_logs ADD COLUMN billing_details text;');
  }

  proxyLogBillingDetailsColumnAvailable = true;
}

function ensureProxyLogDownstreamApiKeyIdSchema() {
  if (!tableExists('proxy_logs')) {
    return;
  }

  if (!tableColumnExists('proxy_logs', 'downstream_api_key_id')) {
    execSqliteLegacyCompat('ALTER TABLE proxy_logs ADD COLUMN downstream_api_key_id integer;');
  }

  proxyLogDownstreamApiKeyIdColumnAvailable = true;
}

function ensureProxyLogClientSchema() {
  if (!tableExists('proxy_logs')) {
    return;
  }

  if (!tableColumnExists('proxy_logs', 'client_family')) {
    execSqliteLegacyCompat('ALTER TABLE proxy_logs ADD COLUMN client_family text;');
  }
  if (!tableColumnExists('proxy_logs', 'client_app_id')) {
    execSqliteLegacyCompat('ALTER TABLE proxy_logs ADD COLUMN client_app_id text;');
  }
  if (!tableColumnExists('proxy_logs', 'client_app_name')) {
    execSqliteLegacyCompat('ALTER TABLE proxy_logs ADD COLUMN client_app_name text;');
  }
  if (!tableColumnExists('proxy_logs', 'client_confidence')) {
    execSqliteLegacyCompat('ALTER TABLE proxy_logs ADD COLUMN client_confidence text;');
  }

  if (!tableIndexExists('proxy_logs_client_app_id_created_at_idx')) {
    execSqliteLegacyCompat(`
      CREATE INDEX IF NOT EXISTS proxy_logs_client_app_id_created_at_idx
      ON proxy_logs(client_app_id, created_at);
    `);
  }
  if (!tableIndexExists('proxy_logs_client_family_created_at_idx')) {
    execSqliteLegacyCompat(`
      CREATE INDEX IF NOT EXISTS proxy_logs_client_family_created_at_idx
      ON proxy_logs(client_family, created_at);
    `);
  }

  proxyLogClientColumnsAvailable = true;
}

function normalizeSchemaErrorMessage(error: unknown): string {
  if (typeof error === 'object' && error && 'message' in error) {
    return String((error as { message?: unknown }).message || '');
  }
  return String(error || '');
}

function isDuplicateColumnError(error: unknown): boolean {
  const lowered = normalizeSchemaErrorMessage(error).toLowerCase();
  return lowered.includes('duplicate column') || lowered.includes('already exists');
}

function isDuplicateIndexError(error: unknown): boolean {
  const lowered = normalizeSchemaErrorMessage(error).toLowerCase();
  return lowered.includes('duplicate key name')
    || lowered.includes('already exists')
    || lowered.includes('relation')
    || lowered.includes('duplicate index');
}

export async function hasProxyLogBillingDetailsColumn(): Promise<boolean> {
  if (proxyLogBillingDetailsColumnAvailable !== null) {
    return proxyLogBillingDetailsColumnAvailable;
  }

  if (runtimeDbDialect === 'sqlite') {
    proxyLogBillingDetailsColumnAvailable = tableExists('proxy_logs')
      && tableColumnExists('proxy_logs', 'billing_details');
    return proxyLogBillingDetailsColumnAvailable;
  }

  if (runtimeDbDialect === 'mysql') {
    if (!mysqlPool) return false;
    const [rows] = await mysqlPool.query('SHOW COLUMNS FROM `proxy_logs` LIKE ?', ['billing_details']);
    proxyLogBillingDetailsColumnAvailable = Array.isArray(rows) && rows.length > 0;
    return proxyLogBillingDetailsColumnAvailable;
  }

  if (!pgPool) return false;
  const result = await pgPool.query(
    'SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = $1 AND column_name = $2 LIMIT 1',
    ['proxy_logs', 'billing_details'],
  );
  proxyLogBillingDetailsColumnAvailable = Number(result.rowCount || 0) > 0;
  return proxyLogBillingDetailsColumnAvailable;
}

export async function ensureProxyLogBillingDetailsColumn(): Promise<boolean> {
  if (runtimeDbDialect === 'sqlite') {
    ensureProxyLogBillingDetailsSchema();
    proxyLogBillingDetailsColumnAvailable = tableExists('proxy_logs')
      && tableColumnExists('proxy_logs', 'billing_details');
    return proxyLogBillingDetailsColumnAvailable;
  }

  if (await hasProxyLogBillingDetailsColumn()) {
    return true;
  }

  try {
    if (runtimeDbDialect === 'mysql') {
      if (!mysqlPool) return false;
      await executeLegacyCompat(
        (statement) => mysqlPool!.query(statement).then(() => undefined),
        'ALTER TABLE `proxy_logs` ADD COLUMN `billing_details` TEXT NULL',
      );
    } else {
      if (!pgPool) return false;
      await executeLegacyCompat(
        (statement) => pgPool!.query(statement).then(() => undefined),
        'ALTER TABLE "proxy_logs" ADD COLUMN "billing_details" TEXT',
      );
    }
    proxyLogBillingDetailsColumnAvailable = true;
    return true;
  } catch (error) {
    if (isDuplicateColumnError(error)) {
      proxyLogBillingDetailsColumnAvailable = true;
      return true;
    }
    proxyLogBillingDetailsColumnAvailable = false;
    console.warn('[db] failed to ensure proxy_logs.billing_details column', error);
    return false;
  }
}

export async function hasProxyLogDownstreamApiKeyIdColumn(): Promise<boolean> {
  if (proxyLogDownstreamApiKeyIdColumnAvailable !== null) {
    return proxyLogDownstreamApiKeyIdColumnAvailable;
  }

  if (runtimeDbDialect === 'sqlite') {
    proxyLogDownstreamApiKeyIdColumnAvailable = tableExists('proxy_logs')
      && tableColumnExists('proxy_logs', 'downstream_api_key_id');
    return proxyLogDownstreamApiKeyIdColumnAvailable;
  }

  if (runtimeDbDialect === 'mysql') {
    if (!mysqlPool) return false;
    const [rows] = await mysqlPool.query('SHOW COLUMNS FROM `proxy_logs` LIKE ?', ['downstream_api_key_id']);
    proxyLogDownstreamApiKeyIdColumnAvailable = Array.isArray(rows) && rows.length > 0;
    return proxyLogDownstreamApiKeyIdColumnAvailable;
  }

  if (!pgPool) return false;
  const result = await pgPool.query(
    'SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = $1 AND column_name = $2 LIMIT 1',
    ['proxy_logs', 'downstream_api_key_id'],
  );
  proxyLogDownstreamApiKeyIdColumnAvailable = Number(result.rowCount || 0) > 0;
  return proxyLogDownstreamApiKeyIdColumnAvailable;
}

export async function ensureProxyLogDownstreamApiKeyIdColumn(): Promise<boolean> {
  if (runtimeDbDialect === 'sqlite') {
    ensureProxyLogDownstreamApiKeyIdSchema();
    proxyLogDownstreamApiKeyIdColumnAvailable = tableExists('proxy_logs')
      && tableColumnExists('proxy_logs', 'downstream_api_key_id');
    return proxyLogDownstreamApiKeyIdColumnAvailable;
  }

  if (await hasProxyLogDownstreamApiKeyIdColumn()) {
    return true;
  }

  try {
    if (runtimeDbDialect === 'mysql') {
      if (!mysqlPool) return false;
      await executeLegacyCompat(
        (statement) => mysqlPool!.query(statement).then(() => undefined),
        'ALTER TABLE `proxy_logs` ADD COLUMN `downstream_api_key_id` INT NULL',
      );
    } else {
      if (!pgPool) return false;
      await executeLegacyCompat(
        (statement) => pgPool!.query(statement).then(() => undefined),
        'ALTER TABLE "proxy_logs" ADD COLUMN "downstream_api_key_id" INTEGER',
      );
    }
    proxyLogDownstreamApiKeyIdColumnAvailable = true;
    return true;
  } catch (error) {
    if (isDuplicateColumnError(error)) {
      proxyLogDownstreamApiKeyIdColumnAvailable = true;
      return true;
    }
    proxyLogDownstreamApiKeyIdColumnAvailable = false;
    console.warn('[db] failed to ensure proxy_logs.downstream_api_key_id column', error);
    return false;
  }
}

async function hasMysqlIndex(indexName: string): Promise<boolean> {
  if (!mysqlPool) return false;
  const [rows] = await mysqlPool.query(
    'SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = ? AND index_name = ? LIMIT 1',
    ['proxy_logs', indexName],
  );
  return Array.isArray(rows) && rows.length > 0;
}

async function hasPostgresIndex(indexName: string): Promise<boolean> {
  if (!pgPool) return false;
  const result = await pgPool.query(
    'SELECT 1 FROM pg_indexes WHERE schemaname = current_schema() AND tablename = $1 AND indexname = $2 LIMIT 1',
    ['proxy_logs', indexName],
  );
  return Number(result.rowCount || 0) > 0;
}

export async function hasProxyLogClientColumns(): Promise<boolean> {
  if (proxyLogClientColumnsAvailable !== null) {
    return proxyLogClientColumnsAvailable;
  }

  const requiredColumns = [
    'client_family',
    'client_app_id',
    'client_app_name',
    'client_confidence',
  ];

  if (runtimeDbDialect === 'sqlite') {
    proxyLogClientColumnsAvailable = tableExists('proxy_logs')
      && requiredColumns.every((columnName) => tableColumnExists('proxy_logs', columnName));
    return proxyLogClientColumnsAvailable;
  }

  if (runtimeDbDialect === 'mysql') {
    if (!mysqlPool) return false;
    const [rows] = await mysqlPool.query(
      'SELECT column_name FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = ? AND column_name IN (?, ?, ?, ?)',
      ['proxy_logs', ...requiredColumns],
    ) as [Array<{ column_name?: string }>, unknown];
    const available = new Set(
      Array.isArray(rows)
        ? rows.map((row) => String(row?.column_name || '').trim().toLowerCase()).filter(Boolean)
        : [],
    );
    proxyLogClientColumnsAvailable = requiredColumns.every((columnName) => available.has(columnName));
    return proxyLogClientColumnsAvailable;
  }

  if (!pgPool) return false;
  const result = await pgPool.query(
    'SELECT column_name FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = $1 AND column_name = ANY($2::text[])',
    ['proxy_logs', requiredColumns],
  );
  const available = new Set(
    result.rows.map((row) => String((row as { column_name?: string }).column_name || '').trim().toLowerCase()).filter(Boolean),
  );
  proxyLogClientColumnsAvailable = requiredColumns.every((columnName) => available.has(columnName));
  return proxyLogClientColumnsAvailable;
}

export async function ensureProxyLogClientColumns(): Promise<boolean> {
  const requiredColumns = [
    { name: 'client_family', sqliteType: 'text', mysqlType: 'TEXT NULL', postgresType: 'TEXT' },
    { name: 'client_app_id', sqliteType: 'text', mysqlType: 'TEXT NULL', postgresType: 'TEXT' },
    { name: 'client_app_name', sqliteType: 'text', mysqlType: 'TEXT NULL', postgresType: 'TEXT' },
    { name: 'client_confidence', sqliteType: 'text', mysqlType: 'TEXT NULL', postgresType: 'TEXT' },
  ];
  const requiredIndexes = [
    {
      name: 'proxy_logs_client_app_id_created_at_idx',
      sqliteSql: 'CREATE INDEX IF NOT EXISTS proxy_logs_client_app_id_created_at_idx ON proxy_logs(client_app_id, created_at);',
      mysqlSql: 'CREATE INDEX `proxy_logs_client_app_id_created_at_idx` ON `proxy_logs` (`client_app_id`(191), `created_at`(191))',
      postgresSql: 'CREATE INDEX "proxy_logs_client_app_id_created_at_idx" ON "proxy_logs" ("client_app_id", "created_at")',
    },
    {
      name: 'proxy_logs_client_family_created_at_idx',
      sqliteSql: 'CREATE INDEX IF NOT EXISTS proxy_logs_client_family_created_at_idx ON proxy_logs(client_family, created_at);',
      mysqlSql: 'CREATE INDEX `proxy_logs_client_family_created_at_idx` ON `proxy_logs` (`client_family`(191), `created_at`(191))',
      postgresSql: 'CREATE INDEX "proxy_logs_client_family_created_at_idx" ON "proxy_logs" ("client_family", "created_at")',
    },
  ];

  if (runtimeDbDialect === 'sqlite') {
    ensureProxyLogClientSchema();
    proxyLogClientColumnsAvailable = tableExists('proxy_logs')
      && requiredColumns.every((column) => tableColumnExists('proxy_logs', column.name));
    return proxyLogClientColumnsAvailable;
  }

  if (await hasProxyLogClientColumns()) {
    for (const requiredIndex of requiredIndexes) {
      const indexExists = runtimeDbDialect === 'mysql'
        ? await hasMysqlIndex(requiredIndex.name)
        : await hasPostgresIndex(requiredIndex.name);
      if (indexExists) continue;
      try {
        if (runtimeDbDialect === 'mysql') {
          if (!mysqlPool) return false;
          await executeLegacyCompat(
            (statement) => mysqlPool!.query(statement).then(() => undefined),
            requiredIndex.mysqlSql,
          );
        } else {
          if (!pgPool) return false;
          await executeLegacyCompat(
            (statement) => pgPool!.query(statement).then(() => undefined),
            requiredIndex.postgresSql,
          );
        }
      } catch (error) {
        if (!isDuplicateIndexError(error)) {
          console.warn(`[db] failed to ensure ${requiredIndex.name}`, error);
        }
      }
    }
    return true;
  }

  try {
    if (runtimeDbDialect === 'mysql') {
      if (!mysqlPool) return false;
      for (const column of requiredColumns) {
        const [rows] = await mysqlPool.query('SHOW COLUMNS FROM `proxy_logs` LIKE ?', [column.name]);
        if (Array.isArray(rows) && rows.length > 0) continue;
        await executeLegacyCompat(
          (statement) => mysqlPool!.query(statement).then(() => undefined),
          `ALTER TABLE \`proxy_logs\` ADD COLUMN \`${column.name}\` ${column.mysqlType}`,
        );
      }
      for (const requiredIndex of requiredIndexes) {
        if (await hasMysqlIndex(requiredIndex.name)) continue;
        await executeLegacyCompat(
          (statement) => mysqlPool!.query(statement).then(() => undefined),
          requiredIndex.mysqlSql,
        );
      }
    } else {
      if (!pgPool) return false;
      for (const column of requiredColumns) {
        const result = await pgPool.query(
          'SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = $1 AND column_name = $2 LIMIT 1',
          ['proxy_logs', column.name],
        );
        if (Number(result.rowCount || 0) > 0) continue;
        await executeLegacyCompat(
          (statement) => pgPool!.query(statement).then(() => undefined),
          `ALTER TABLE "proxy_logs" ADD COLUMN "${column.name}" ${column.postgresType}`,
        );
      }
      for (const requiredIndex of requiredIndexes) {
        if (await hasPostgresIndex(requiredIndex.name)) continue;
        await executeLegacyCompat(
          (statement) => pgPool!.query(statement).then(() => undefined),
          requiredIndex.postgresSql,
        );
      }
    }
    proxyLogClientColumnsAvailable = true;
    return true;
  } catch (error) {
    if (isDuplicateColumnError(error) || isDuplicateIndexError(error)) {
      proxyLogClientColumnsAvailable = await hasProxyLogClientColumns();
      return proxyLogClientColumnsAvailable;
    }
    proxyLogClientColumnsAvailable = false;
    console.warn('[db] failed to ensure proxy_logs client columns', error);
    return false;
  }
}

function resetSchemaCapabilityCache() {
  proxyLogBillingDetailsColumnAvailable = null;
  proxyLogDownstreamApiKeyIdColumnAvailable = null;
  proxyLogClientColumnsAvailable = null;
}

async function sqliteProxyQuery(sqlText: string, params: unknown[], method: SqlMethod) {
  const sqlite = requireSqliteConnection();
  const statement = sqlite.prepare(sqlText);
  if (method === 'run' || method === 'execute') {
    const result = statement.run(...params);
    return {
      rows: [],
      changes: Number(result.changes || 0),
      lastInsertRowid: Number(result.lastInsertRowid || 0),
    };
  }

  if (method === 'get') {
    const row = statement.raw().get(...params) as unknown[] | undefined;
    return { rows: row as any };
  }

  const rows = statement.raw().all(...params) as unknown[][];
  return { rows };
}

type MysqlQueryable = mysql.Pool | mysql.PoolConnection;
async function mysqlProxyQuery(executor: MysqlQueryable, sqlText: string, params: unknown[], method: SqlMethod) {
  const queryOptions = {
    sql: sqlText,
    rowsAsArray: method === 'all' || method === 'values',
  };
  const [rows] = await executor.query(queryOptions as mysql.QueryOptions, params as any[]);

  if (method === 'all' || method === 'values') {
    return { rows: Array.isArray(rows) ? rows : [] };
  }

  if (Array.isArray(rows)) {
    return { rows };
  }
  return { rows: [rows] };
}

type PgQueryable = pg.Pool | pg.PoolClient;
function parseInsertTableName(sqlText: string): string | null {
  const match = sqlText.match(/insert\s+into\s+"?([a-zA-Z0-9_]+)"?/i);
  return match?.[1]?.toLowerCase() || null;
}

async function pgProxyQuery(executor: PgQueryable, sqlText: string, params: unknown[], method: SqlMethod) {
  const trimmedLower = sqlText.trim().toLowerCase();
  const values = params as any[];

  if (method === 'all' || method === 'values') {
    const result = await executor.query({
      text: sqlText,
      values,
      rowMode: 'array',
    } as pg.QueryConfig);
    return { rows: result.rows };
  }

  if (trimmedLower.startsWith('insert') && method === 'execute') {
    const tableName = parseInsertTableName(sqlText);
    const canReturnId = tableName !== null && TABLES_WITH_NUMERIC_ID.has(tableName) && !trimmedLower.includes(' returning ');
    if (canReturnId) {
      const result = await executor.query({
        text: `${sqlText} returning id`,
        values,
      } as pg.QueryConfig);
      const insertedId = Number((result.rows?.[0] as { id?: unknown } | undefined)?.id ?? 0);
      return {
        rows: [{
          changes: Number(result.rowCount || 0),
          lastInsertRowid: Number.isFinite(insertedId) ? insertedId : 0,
        }],
      };
    }
  }

  const result = await executor.query({
    text: sqlText,
    values,
  } as pg.QueryConfig);

  if (trimmedLower.startsWith('select')) {
    return { rows: result.rows };
  }

  return { rows: [{ changes: Number(result.rowCount || 0) }] };
}

function normalizeAllResult(result: unknown): unknown[] {
  if (!Array.isArray(result)) return [];
  if (result.length === 0) return [];
  const first = result[0] as Record<string, unknown> | undefined;
  if (first && typeof first === 'object') {
    if ('affectedRows' in first || 'insertId' in first) return [];
    if ('changes' in first && result.length === 1) return [];
    if ('rowCount' in first && result.length === 1) return [];
  }
  return result;
}

function normalizeRunResult(result: unknown): { changes: number; lastInsertRowid: number } {
  if (!result) return { changes: 0, lastInsertRowid: 0 };

  if (typeof result === 'object' && !Array.isArray(result)) {
    const row = result as Record<string, unknown>;
    if ('changes' in row || 'lastInsertRowid' in row) {
      return {
        changes: Number(row.changes || 0),
        lastInsertRowid: Number(row.lastInsertRowid || 0),
      };
    }
    if ('affectedRows' in row || 'insertId' in row) {
      return {
        changes: Number(row.affectedRows || 0),
        lastInsertRowid: Number(row.insertId || 0),
      };
    }
  }

  if (Array.isArray(result) && result.length > 0) {
    const first = result[0] as Record<string, unknown>;
    if (first && typeof first === 'object') {
      if ('changes' in first || 'lastInsertRowid' in first) {
        return {
          changes: Number(first.changes || 0),
          lastInsertRowid: Number(first.lastInsertRowid || 0),
        };
      }
      if ('affectedRows' in first || 'insertId' in first) {
        return {
          changes: Number(first.affectedRows || 0),
          lastInsertRowid: Number(first.insertId || 0),
        };
      }
      if ('rowCount' in first) {
        return {
          changes: Number(first.rowCount || 0),
          lastInsertRowid: 0,
        };
      }
    }
  }

  return { changes: 0, lastInsertRowid: 0 };
}

const wrappedObjects = new WeakMap<object, unknown>();

function shouldWrapObject(value: unknown): value is object {
  if (!value || typeof value !== 'object') return false;
  // Drizzle query builders are thenable objects (QueryPromise) but are not native Promises.
  // They still need wrapping so we can provide sqlite-style `.all/.get/.run` shims.
  if (value instanceof Promise) return false;
  return true;
}

function wrapQueryLike<T>(value: T): T {
  if (!shouldWrapObject(value)) return value;
  const target = value as unknown as object;
  if (wrappedObjects.has(target)) {
    return wrappedObjects.get(target) as T;
  }

  const proxy = new Proxy(target as Record<string, unknown>, {
    get(innerTarget, prop, receiver) {
      if (prop === 'then' && typeof innerTarget.then === 'function') {
        return innerTarget.then.bind(innerTarget);
      }

      if (prop === 'all' && typeof innerTarget.all !== 'function' && typeof innerTarget.execute === 'function') {
        return async (...args: unknown[]) => normalizeAllResult(await (innerTarget.execute as (...a: unknown[]) => Promise<unknown>)(...args));
      }

      if (prop === 'get' && typeof innerTarget.get !== 'function' && typeof innerTarget.execute === 'function') {
        return async (...args: unknown[]) => {
          const rows = normalizeAllResult(await (innerTarget.execute as (...a: unknown[]) => Promise<unknown>)(...args));
          return rows[0] ?? undefined;
        };
      }

      if (prop === 'run' && typeof innerTarget.run !== 'function' && typeof innerTarget.execute === 'function') {
        return async (...args: unknown[]) => normalizeRunResult(await (innerTarget.execute as (...a: unknown[]) => Promise<unknown>)(...args));
      }

      const original = Reflect.get(innerTarget, prop, receiver);
      if (typeof original !== 'function') {
        return original;
      }

      return (...args: unknown[]) => {
        const result = original.apply(innerTarget, args);
        if (shouldWrapObject(result)) {
          return wrapQueryLike(result);
        }
        return result;
      };
    },
  });

  wrappedObjects.set(target, proxy);
  return proxy as unknown as T;
}

function wrapDbClient<T extends object>(
  rawDb: T,
  customTransaction?: <R>(fn: (tx: any) => Promise<R> | R) => Promise<R>,
) {
  return new Proxy(rawDb as Record<string, unknown>, {
    get(target, prop, receiver) {
      if (prop === 'transaction') {
        if (customTransaction) return customTransaction;

        const originalTransaction = target.transaction;
        if (typeof originalTransaction !== 'function') return undefined;
        return async <R>(fn: (tx: any) => Promise<R> | R) => {
          return await (originalTransaction as (handler: (tx: unknown) => Promise<R> | R) => Promise<R>).call(target, async (tx: unknown) => {
            return await fn(wrapDbClient(tx as object));
          });
        };
      }

      const original = Reflect.get(target, prop, receiver);
      if (typeof original !== 'function') {
        return original;
      }

      return (...args: unknown[]) => {
        const result = original.apply(target, args);
        if (shouldWrapObject(result)) {
          return wrapQueryLike(result);
        }
        return result;
      };
    },
  }) as T;
}

function initSqliteDb() {
  const sqlitePath = resolveSqlitePath();
  if (sqlitePath !== ':memory:') {
    mkdirSync(dirname(sqlitePath), { recursive: true });
  }

  const sqlite = new Database(sqlitePath);
  sqliteConnection = sqlite;
  sqlite.pragma('journal_mode = WAL');
  sqlite.pragma('foreign_keys = ON');

  ensureTokenManagementSchema();
  ensureSiteStatusSchema();
  ensureSiteProxySchema();
  ensureSiteUseSystemProxySchema();
  ensureSiteCustomHeadersSchema();
  ensureSiteExternalCheckinUrlSchema();
  ensureSiteGlobalWeightSchema();
  ensureRouteGroupingSchema();
  ensureDownstreamApiKeySchema();
  ensureProxyLogBillingDetailsSchema();
  ensureProxyLogClientSchema();
  ensureProxyVideoTaskSchema();
  ensureProxyFileSchema();

  const rawDb = drizzleSqliteProxy(
    (sqlText, params, method) => sqliteProxyQuery(sqlText, params, method as SqlMethod),
    { schema },
  ) as any;
  return wrapDbClient(rawDb);
}

type AppDb = ReturnType<typeof initSqliteDb>;

function initMysqlDb(): AppDb {
  if (!config.dbUrl) {
    throw new Error('DB_URL is required when DB_TYPE=mysql');
  }
  mysqlPool = mysql.createPool(buildMysqlPoolOptions());

  const rawDb = drizzleMysqlProxy(
    (sqlText, params, method) => mysqlProxyQuery(mysqlPool!, sqlText, params, method as SqlMethod),
    { schema },
  ) as any;

  return wrapDbClient(rawDb, async <R>(fn: (tx: any) => Promise<R> | R) => {
    const connection = await mysqlPool!.getConnection();
    try {
      await connection.beginTransaction();
      const txRaw = drizzleMysqlProxy(
        (sqlText, params, method) => mysqlProxyQuery(connection, sqlText, params, method as SqlMethod),
        { schema },
      ) as any;
      const txWrapped = wrapDbClient(txRaw);
      const result = await fn(txWrapped);
      await connection.commit();
      return result;
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  }) as AppDb;
}

function initPostgresDb(): AppDb {
  if (!config.dbUrl) {
    throw new Error('DB_URL is required when DB_TYPE=postgres');
  }
  installPostgresJsonTextParsers();
  const poolOptions = buildPostgresPoolOptions();
  pgPool = new pg.Pool(poolOptions);

  const rawDb = drizzlePgProxy(
    (sqlText, params, method) => pgProxyQuery(pgPool!, sqlText, params, method as SqlMethod),
    { schema },
  ) as any;

  return wrapDbClient(rawDb, async <R>(fn: (tx: any) => Promise<R> | R) => {
    const client = await pgPool!.connect();
    try {
      await client.query('BEGIN');
      const txRaw = drizzlePgProxy(
        (sqlText, params, method) => pgProxyQuery(client, sqlText, params, method as SqlMethod),
        { schema },
      ) as any;
      const txWrapped = wrapDbClient(txRaw);
      const result = await fn(txWrapped);
      await client.query('COMMIT');
      return result;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }) as AppDb;
}

function initDb(): AppDb {
  if (runtimeDbDialect === 'mysql') return initMysqlDb();
  if (runtimeDbDialect === 'postgres') return initPostgresDb();
  return initSqliteDb();
}

let activeDb: AppDb = initDb();

export const db: any = new Proxy({}, {
  get(_target, prop) {
    return (activeDb as any)?.[prop as keyof typeof activeDb];
  },
});
export { schema };

export async function closeDbConnections(): Promise<void> {
  resetSchemaCapabilityCache();
  if (mysqlPool) {
    await mysqlPool.end();
    mysqlPool = null;
  }
  if (pgPool) {
    await pgPool.end();
    pgPool = null;
  }
  if (sqliteConnection) {
    sqliteConnection.close();
    sqliteConnection = null;
  }
}

export async function switchRuntimeDatabase(nextDialect: RuntimeDbDialect, nextDbUrl: string, nextDbSsl?: boolean): Promise<void> {
  const previousDialect = runtimeDbDialect;
  const previousDbUrl = config.dbUrl;
  const previousConfigDialect = config.dbType;
  const previousDbSsl = config.dbSsl;

  await closeDbConnections();

  runtimeDbDialect = nextDialect;
  config.dbType = nextDialect;
  config.dbUrl = nextDbUrl;
  if (nextDbSsl !== undefined) {
    config.dbSsl = nextDbSsl;
  }

  try {
    activeDb = initDb();
    await ensureRuntimeDatabaseReady({
      dialect: nextDialect,
      connectionString: nextDbUrl,
      ssl: config.dbSsl,
    });
  } catch (error) {
    await closeDbConnections();
    runtimeDbDialect = previousDialect;
    config.dbType = previousConfigDialect;
    config.dbUrl = previousDbUrl;
    config.dbSsl = previousDbSsl;
    activeDb = initDb();
    throw error;
  }
}

export const __dbProxyTestUtils = {
  wrapQueryLike,
  shouldWrapObject,
  resolveSqlitePath,
  resolveVitestSqlitePath,
  buildMysqlPoolOptions,
  buildPostgresPoolOptions,
  installPostgresJsonTextParsers,
  ensurePostgresJsonTextParsers: installPostgresJsonTextParsers,
  resetPostgresJsonTextParsersInstallStateForTests,
  pg,
};
