import Database from 'better-sqlite3';
import currentSchemaContract from '../db/generated/schemaContract.json' with { type: 'json' };
import { db, schema } from '../db/index.js';
import {
  createRuntimeSchemaClient,
  ensureRuntimeDatabaseSchema,
  type RuntimeSchemaClient,
  type RuntimeSchemaDialect,
} from '../db/runtimeSchemaBootstrap.js';

export type MigrationDialect = RuntimeSchemaDialect;

export interface DatabaseMigrationInput {
  dialect?: unknown;
  connectionString?: unknown;
  overwrite?: unknown;
  ssl?: unknown;
}

export interface NormalizedDatabaseMigrationInput {
  dialect: MigrationDialect;
  connectionString: string;
  overwrite: boolean;
  ssl: boolean;
}

type BackupSnapshot = {
  version: string;
  timestamp: number;
  accounts: {
    sites: Array<Record<string, unknown>>;
    siteApiEndpoints: Array<Record<string, unknown>>;
    siteAnnouncements: Array<Record<string, unknown>>;
    siteDisabledModels: Array<Record<string, unknown>>;
    accounts: Array<Record<string, unknown>>;
    accountTokens: Array<Record<string, unknown>>;
    checkinLogs: Array<Record<string, unknown>>;
    modelAvailability: Array<Record<string, unknown>>;
    tokenModelAvailability: Array<Record<string, unknown>>;
    tokenRoutes: Array<Record<string, unknown>>;
    routeChannels: Array<Record<string, unknown>>;
    routeGroupSources: Array<Record<string, unknown>>;
    proxyLogs: Array<Record<string, unknown>>;
    proxyVideoTasks: Array<Record<string, unknown>>;
    proxyFiles: Array<Record<string, unknown>>;
    downstreamApiKeys: Array<Record<string, unknown>>;
    events: Array<Record<string, unknown>>;
  };
  preferences: {
    settings: Array<{ key: string; value: unknown }>;
  };
};

export interface DatabaseMigrationSummary {
  dialect: MigrationDialect;
  connection: string;
  overwrite: boolean;
  version: string;
  timestamp: number;
  rows: {
    sites: number;
    siteApiEndpoints: number;
    siteAnnouncements: number;
    siteDisabledModels: number;
    accounts: number;
    accountTokens: number;
    tokenRoutes: number;
    routeChannels: number;
    routeGroupSources: number;
    checkinLogs: number;
    modelAvailability: number;
    tokenModelAvailability: number;
    proxyLogs: number;
    proxyVideoTasks: number;
    proxyFiles: number;
    downstreamApiKeys: number;
    events: number;
    settings: number;
  };
}

type SqlClient = RuntimeSchemaClient;

interface InsertStatement {
  table: string;
  columns: string[];
  values: unknown[];
}

const DIALECTS: MigrationDialect[] = ['sqlite', 'mysql', 'postgres'];
const RUNTIME_DATABASE_SETTING_KEYS = new Set(['db_type', 'db_url', 'db_ssl']);
type SchemaContractShape = {
  tables: Record<string, {
    columns: Record<string, {
      logicalType: string | null;
    }>;
  }>;
};
type LogicalColumnTypeShape = string | null;
const schemaContract = currentSchemaContract as SchemaContractShape;

function asString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function asBoolean(value: unknown, fallback: boolean): boolean {
  if (typeof value === 'boolean') return value;
  if (typeof value === 'number') return value !== 0;
  if (typeof value === 'string') {
    const normalized = value.trim().toLowerCase();
    if (['1', 'true', 'yes', 'on'].includes(normalized)) return true;
    if (['0', 'false', 'no', 'off'].includes(normalized)) return false;
  }
  return fallback;
}

function asNumber(value: unknown, fallback: number | null = null): number | null {
  if (value === null || value === undefined) return fallback;
  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric : fallback;
}

function asNullableString(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  return String(value);
}

function getColumnLogicalType(
  table: string,
  column: string,
  contract: SchemaContractShape = schemaContract,
): LogicalColumnTypeShape | null {
  return contract.tables[table]?.columns[column]?.logicalType ?? null;
}

function serializeJsonColumnValue(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  if (typeof value === 'string') return value;
  return JSON.stringify(value);
}

function serializeColumnValue(
  table: string,
  column: string,
  value: unknown,
  contract: SchemaContractShape = schemaContract,
): string | null {
  if (getColumnLogicalType(table, column, contract) === 'json') {
    return serializeJsonColumnValue(value);
  }
  return asNullableString(value);
}

function toJsonString(value: unknown): string {
  return JSON.stringify(value ?? null);
}

function assertDialectUrl(dialect: MigrationDialect, connectionString: string): void {
  if (dialect === 'sqlite') return;
  let parsed: URL;
  try {
    parsed = new URL(connectionString);
  } catch {
    throw new Error(`数据库连接串无效：${dialect} 需要合法 URL`);
  }

  if (dialect === 'postgres' && parsed.protocol !== 'postgres:' && parsed.protocol !== 'postgresql:') {
    throw new Error('PostgreSQL 连接串必须以 postgres:// 或 postgresql:// 开头');
  }

  if (dialect === 'mysql' && parsed.protocol !== 'mysql:') {
    throw new Error('MySQL 连接串必须以 mysql:// 开头');
  }
}

function normalizeSqliteTarget(raw: string): string {
  if (!raw) throw new Error('SQLite 目标路径不能为空');
  const trimmed = raw.trim();
  if (!trimmed) throw new Error('SQLite 目标路径不能为空');
  if (trimmed === ':memory:') return trimmed;

  const lower = trimmed.toLowerCase();
  if (lower.startsWith('file://')) {
    const parsed = new URL(trimmed);
    return decodeURIComponent(parsed.pathname);
  }
  if (lower.startsWith('sqlite://')) {
    return trimmed.slice('sqlite://'.length).trim();
  }

  // Guard against accidentally saving a network URL under sqlite dialect.
  // This would be treated as a local sqlite file path and produce a broken runtime DB.
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)) {
    throw new Error('SQLite 连接串不能是网络 URL，请先选择 MySQL 或 PostgreSQL');
  }
  return trimmed;
}

export function normalizeMigrationInput(input: DatabaseMigrationInput): NormalizedDatabaseMigrationInput {
  const rawDialect = asString(input.dialect).toLowerCase();
  if (!DIALECTS.includes(rawDialect as MigrationDialect)) {
    throw new Error('数据库方言无效，仅支持 sqlite/mysql/postgres');
  }

  const dialect = rawDialect as MigrationDialect;
  let connectionString = asString(input.connectionString);
  if (!connectionString) {
    throw new Error('数据库连接串不能为空');
  }

  if (dialect === 'sqlite') {
    connectionString = normalizeSqliteTarget(connectionString);
  } else {
    assertDialectUrl(dialect, connectionString);
  }

  return {
    dialect,
    connectionString,
    overwrite: input.overwrite === undefined ? true : asBoolean(input.overwrite, true),
    ssl: asBoolean(input.ssl, false),
  };
}

export function maskConnectionString(connectionString: string): string {
  try {
    const parsed = new URL(connectionString);
    if (!parsed.password) return connectionString;
    parsed.password = '***';
    return parsed.toString();
  } catch {
    return connectionString;
  }
}

function quoteIdent(dialect: MigrationDialect, identifier: string): string {
  return dialect === 'mysql' ? `\`${identifier}\`` : `"${identifier}"`;
}

function parseSettingValue(raw: string | null): unknown {
  if (raw === null || raw === undefined) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return raw;
  }
}

async function toBackupSnapshot(): Promise<BackupSnapshot> {
  const settingsRows = await db.select().from(schema.settings).all();
  return {
    version: 'live-db-snapshot',
    timestamp: Date.now(),
    accounts: {
      sites: await db.select().from(schema.sites).all() as Array<Record<string, unknown>>,
      siteApiEndpoints: await db.select().from(schema.siteApiEndpoints).all() as Array<Record<string, unknown>>,
      siteAnnouncements: await db.select().from(schema.siteAnnouncements).all() as Array<Record<string, unknown>>,
      siteDisabledModels: await db.select().from(schema.siteDisabledModels).all() as Array<Record<string, unknown>>,
      accounts: await db.select().from(schema.accounts).all() as Array<Record<string, unknown>>,
      accountTokens: await db.select().from(schema.accountTokens).all() as Array<Record<string, unknown>>,
      checkinLogs: await db.select().from(schema.checkinLogs).all() as Array<Record<string, unknown>>,
      modelAvailability: await db.select().from(schema.modelAvailability).all() as Array<Record<string, unknown>>,
      tokenModelAvailability: await db.select().from(schema.tokenModelAvailability).all() as Array<Record<string, unknown>>,
      tokenRoutes: await db.select().from(schema.tokenRoutes).all() as Array<Record<string, unknown>>,
      routeChannels: await db.select().from(schema.routeChannels).all() as Array<Record<string, unknown>>,
      routeGroupSources: await db.select().from(schema.routeGroupSources).all() as Array<Record<string, unknown>>,
      proxyLogs: await db.select().from(schema.proxyLogs).all() as Array<Record<string, unknown>>,
      proxyVideoTasks: await db.select().from(schema.proxyVideoTasks).all() as Array<Record<string, unknown>>,
      proxyFiles: await db.select().from(schema.proxyFiles).all() as Array<Record<string, unknown>>,
      downstreamApiKeys: await db.select().from(schema.downstreamApiKeys).all() as Array<Record<string, unknown>>,
      events: await db.select().from(schema.events).all() as Array<Record<string, unknown>>,
    },
    preferences: {
      settings: settingsRows.map((row) => ({ key: row.key, value: parseSettingValue(row.value) })),
    },
  };
}

async function createClient(input: NormalizedDatabaseMigrationInput): Promise<SqlClient> {
  return createRuntimeSchemaClient(input);
}

async function ensureTargetState(client: SqlClient, overwrite: boolean): Promise<void> {
  const siteCount = await client.queryScalar(`SELECT COUNT(*) FROM ${quoteIdent(client.dialect, 'sites')}`);
  const settingCount = await client.queryScalar(`SELECT COUNT(*) FROM ${quoteIdent(client.dialect, 'settings')}`);
  if (!overwrite && (siteCount > 0 || settingCount > 0)) {
    throw new Error('目标数据库已包含数据。若确认覆盖，请勾选“覆盖目标数据库现有数据”');
  }
}

async function clearTargetData(client: SqlClient): Promise<void> {
  const tables = [
    'route_channels',
    'route_group_sources',
    'token_model_availability',
    'model_availability',
    'checkin_logs',
    'proxy_logs',
    'proxy_video_tasks',
    'proxy_files',
    'account_tokens',
    'accounts',
    'site_announcements',
    'site_disabled_models',
    'site_api_endpoints',
    'token_routes',
    'sites',
    'downstream_api_keys',
    'events',
    'settings',
  ];
  for (const table of tables) {
    await client.execute(`DELETE FROM ${quoteIdent(client.dialect, table)}`);
  }
}

function buildStatements(
  snapshot: BackupSnapshot,
  contract: SchemaContractShape = schemaContract,
): InsertStatement[] {
  const statements: InsertStatement[] = [];

  for (const row of snapshot.accounts.sites) {
    statements.push({
      table: 'sites',
      columns: ['id', 'name', 'url', 'external_checkin_url', 'platform', 'proxy_url', 'use_system_proxy', 'custom_headers', 'status', 'is_pinned', 'sort_order', 'global_weight', 'api_key', 'created_at', 'updated_at'],
      values: [
        asNumber(row.id, 0),
        asNullableString(row.name),
        asNullableString(row.url),
        asNullableString(row.externalCheckinUrl),
        asNullableString(row.platform),
        asNullableString(row.proxyUrl),
        asBoolean(row.useSystemProxy, false),
        serializeColumnValue('sites', 'custom_headers', row.customHeaders, contract),
        asNullableString(row.status) ?? 'active',
        asBoolean(row.isPinned, false),
        asNumber(row.sortOrder, 0),
        asNumber(row.globalWeight, 1),
        asNullableString(row.apiKey),
        asNullableString(row.createdAt),
        asNullableString(row.updatedAt),
      ],
    });
  }

  for (const row of snapshot.accounts.siteApiEndpoints || []) {
    statements.push({
      table: 'site_api_endpoints',
      columns: [
        'id',
        'site_id',
        'url',
        'enabled',
        'sort_order',
        'cooldown_until',
        'last_selected_at',
        'last_failed_at',
        'last_failure_reason',
        'created_at',
        'updated_at',
      ],
      values: [
        asNumber(row.id, 0),
        asNumber(row.siteId, 0),
        asNullableString(row.url),
        asBoolean(row.enabled, true),
        asNumber(row.sortOrder, 0),
        asNullableString(row.cooldownUntil),
        asNullableString(row.lastSelectedAt),
        asNullableString(row.lastFailedAt),
        asNullableString(row.lastFailureReason),
        asNullableString(row.createdAt),
        asNullableString(row.updatedAt),
      ],
    });
  }

  for (const row of snapshot.accounts.siteDisabledModels) {
    statements.push({
      table: 'site_disabled_models',
      columns: ['id', 'site_id', 'model_name', 'created_at'],
      values: [
        asNumber(row.id, 0),
        asNumber(row.siteId, 0),
        asNullableString(row.modelName),
        asNullableString(row.createdAt),
      ],
    });
  }

  for (const row of snapshot.accounts.siteAnnouncements || []) {
    statements.push({
      table: 'site_announcements',
      columns: [
        'id',
        'site_id',
        'platform',
        'source_key',
        'title',
        'content',
        'level',
        'source_url',
        'starts_at',
        'ends_at',
        'upstream_created_at',
        'upstream_updated_at',
        'first_seen_at',
        'last_seen_at',
        'read_at',
        'dismissed_at',
        'raw_payload',
      ],
      values: [
        asNumber(row.id, 0),
        asNumber(row.siteId, 0),
        asNullableString(row.platform),
        asNullableString(row.sourceKey),
        asNullableString(row.title),
        asNullableString(row.content),
        asNullableString(row.level) ?? 'info',
        asNullableString(row.sourceUrl),
        asNullableString(row.startsAt),
        asNullableString(row.endsAt),
        asNullableString(row.upstreamCreatedAt),
        asNullableString(row.upstreamUpdatedAt),
        asNullableString(row.firstSeenAt),
        asNullableString(row.lastSeenAt),
        asNullableString(row.readAt),
        asNullableString(row.dismissedAt),
        asNullableString(row.rawPayload),
      ],
    });
  }

  for (const row of snapshot.accounts.accounts) {
    statements.push({
      table: 'accounts',
      columns: ['id', 'site_id', 'username', 'access_token', 'api_token', 'balance', 'balance_used', 'quota', 'unit_cost', 'value_score', 'status', 'is_pinned', 'sort_order', 'checkin_enabled', 'last_checkin_at', 'last_balance_refresh', 'extra_config', 'created_at', 'updated_at'],
      values: [
        asNumber(row.id, 0),
        asNumber(row.siteId, 0),
        asNullableString(row.username),
        asNullableString(row.accessToken),
        asNullableString(row.apiToken),
        asNumber(row.balance, 0),
        asNumber(row.balanceUsed, 0),
        asNumber(row.quota, 0),
        asNumber(row.unitCost, null),
        asNumber(row.valueScore, 0),
        asNullableString(row.status) ?? 'active',
        asBoolean(row.isPinned, false),
        asNumber(row.sortOrder, 0),
        asBoolean(row.checkinEnabled, true),
        asNullableString(row.lastCheckinAt),
        asNullableString(row.lastBalanceRefresh),
        serializeColumnValue('accounts', 'extra_config', row.extraConfig, contract),
        asNullableString(row.createdAt),
        asNullableString(row.updatedAt),
      ],
    });
  }

  for (const row of snapshot.accounts.accountTokens) {
    statements.push({
      table: 'account_tokens',
      columns: ['id', 'account_id', 'name', 'token', 'token_group', 'value_status', 'source', 'enabled', 'is_default', 'created_at', 'updated_at'],
      values: [
        asNumber(row.id, 0),
        asNumber(row.accountId, 0),
        asNullableString(row.name),
        asNullableString(row.token),
        asNullableString(row.tokenGroup),
        asNullableString((row as { valueStatus?: unknown }).valueStatus) ?? 'ready',
        asNullableString(row.source) ?? 'manual',
        asBoolean(row.enabled, true),
        asBoolean(row.isDefault, false),
        asNullableString(row.createdAt),
        asNullableString(row.updatedAt),
      ],
    });
  }

  for (const row of snapshot.accounts.checkinLogs) {
    statements.push({
      table: 'checkin_logs',
      columns: ['id', 'account_id', 'status', 'message', 'reward', 'created_at'],
      values: [
        asNumber(row.id, 0),
        asNumber(row.accountId, 0),
        asNullableString(row.status) ?? 'success',
        asNullableString(row.message),
        asNullableString(row.reward),
        asNullableString(row.createdAt),
      ],
    });
  }

  for (const row of snapshot.accounts.modelAvailability) {
    statements.push({
      table: 'model_availability',
      columns: ['id', 'account_id', 'model_name', 'available', 'latency_ms', 'checked_at'],
      values: [
        asNumber(row.id, 0),
        asNumber(row.accountId, 0),
        asNullableString(row.modelName),
        asBoolean(row.available, false),
        asNumber(row.latencyMs, null),
        asNullableString(row.checkedAt),
      ],
    });
  }

  for (const row of snapshot.accounts.tokenModelAvailability) {
    statements.push({
      table: 'token_model_availability',
      columns: ['id', 'token_id', 'model_name', 'available', 'latency_ms', 'checked_at'],
      values: [
        asNumber(row.id, 0),
        asNumber(row.tokenId, 0),
        asNullableString(row.modelName),
        asBoolean(row.available, false),
        asNumber(row.latencyMs, null),
        asNullableString(row.checkedAt),
      ],
    });
  }

  for (const row of snapshot.accounts.tokenRoutes) {
    statements.push({
      table: 'token_routes',
      columns: ['id', 'model_pattern', 'display_name', 'display_icon', 'model_mapping', 'route_mode', 'decision_snapshot', 'decision_refreshed_at', 'routing_strategy', 'enabled', 'created_at', 'updated_at'],
      values: [
        asNumber(row.id, 0),
        asNullableString(row.modelPattern),
        asNullableString(row.displayName),
        asNullableString(row.displayIcon),
        serializeColumnValue('token_routes', 'model_mapping', row.modelMapping, contract),
        asNullableString(row.routeMode) ?? 'pattern',
        serializeColumnValue('token_routes', 'decision_snapshot', row.decisionSnapshot, contract),
        asNullableString(row.decisionRefreshedAt),
        asNullableString(row.routingStrategy),
        asBoolean(row.enabled, true),
        asNullableString(row.createdAt),
        asNullableString(row.updatedAt),
      ],
    });
  }

  for (const row of snapshot.accounts.routeChannels) {
    statements.push({
      table: 'route_channels',
      columns: ['id', 'route_id', 'account_id', 'token_id', 'source_model', 'priority', 'weight', 'enabled', 'manual_override', 'success_count', 'fail_count', 'total_latency_ms', 'total_cost', 'last_used_at', 'last_selected_at', 'last_fail_at', 'consecutive_fail_count', 'cooldown_level', 'cooldown_until'],
      values: [
        asNumber(row.id, 0),
        asNumber(row.routeId, 0),
        asNumber(row.accountId, 0),
        asNumber(row.tokenId, null),
        asNullableString(row.sourceModel),
        asNumber(row.priority, 0),
        asNumber(row.weight, 10),
        asBoolean(row.enabled, true),
        asBoolean(row.manualOverride, false),
        asNumber(row.successCount, 0),
        asNumber(row.failCount, 0),
        asNumber(row.totalLatencyMs, 0),
        asNumber(row.totalCost, 0),
        asNullableString(row.lastUsedAt),
        asNullableString(row.lastSelectedAt),
        asNullableString(row.lastFailAt),
        asNumber(row.consecutiveFailCount, 0),
        asNumber(row.cooldownLevel, 0),
        asNullableString(row.cooldownUntil),
      ],
    });
  }

  for (const row of (snapshot.accounts.routeGroupSources || [])) {
    statements.push({
      table: 'route_group_sources',
      columns: ['id', 'group_route_id', 'source_route_id'],
      values: [
        asNumber(row.id, 0),
        asNumber(row.groupRouteId, 0),
        asNumber(row.sourceRouteId, 0),
      ],
    });
  }

  for (const row of snapshot.accounts.proxyLogs) {
    statements.push({
      table: 'proxy_logs',
      columns: ['id', 'route_id', 'channel_id', 'account_id', 'downstream_api_key_id', 'model_requested', 'model_actual', 'status', 'http_status', 'latency_ms', 'prompt_tokens', 'completion_tokens', 'total_tokens', 'estimated_cost', 'billing_details', 'error_message', 'retry_count', 'created_at'],
      values: [
        asNumber(row.id, 0),
        asNumber(row.routeId, null),
        asNumber(row.channelId, null),
        asNumber(row.accountId, null),
        asNumber((row as any).downstreamApiKeyId ?? (row as any).downstream_api_key_id, null),
        asNullableString(row.modelRequested),
        asNullableString(row.modelActual),
        asNullableString(row.status),
        asNumber(row.httpStatus, null),
        asNumber(row.latencyMs, null),
        asNumber(row.promptTokens, null),
        asNumber(row.completionTokens, null),
        asNumber(row.totalTokens, null),
        asNumber(row.estimatedCost, null),
        serializeColumnValue('proxy_logs', 'billing_details', row.billingDetails, contract),
        asNullableString(row.errorMessage),
        asNumber(row.retryCount, 0),
        asNullableString(row.createdAt),
      ],
    });
  }

  for (const row of snapshot.accounts.proxyVideoTasks) {
    statements.push({
      table: 'proxy_video_tasks',
      columns: ['id', 'public_id', 'upstream_video_id', 'site_url', 'token_value', 'requested_model', 'actual_model', 'channel_id', 'account_id', 'status_snapshot', 'upstream_response_meta', 'last_upstream_status', 'last_polled_at', 'created_at', 'updated_at'],
      values: [
        asNumber(row.id, 0),
        asNullableString(row.publicId),
        asNullableString(row.upstreamVideoId),
        asNullableString(row.siteUrl),
        asNullableString(row.tokenValue),
        asNullableString(row.requestedModel),
        asNullableString(row.actualModel),
        asNumber(row.channelId, null),
        asNumber(row.accountId, null),
        serializeColumnValue('proxy_video_tasks', 'status_snapshot', row.statusSnapshot, contract),
        serializeColumnValue('proxy_video_tasks', 'upstream_response_meta', row.upstreamResponseMeta, contract),
        asNumber(row.lastUpstreamStatus, null),
        asNullableString(row.lastPolledAt),
        asNullableString(row.createdAt),
        asNullableString(row.updatedAt),
      ],
    });
  }

  for (const row of snapshot.accounts.proxyFiles) {
    statements.push({
      table: 'proxy_files',
      columns: ['id', 'public_id', 'owner_type', 'owner_id', 'filename', 'mime_type', 'purpose', 'byte_size', 'sha256', 'content_base64', 'created_at', 'updated_at', 'deleted_at'],
      values: [
        asNumber(row.id, 0),
        asNullableString(row.publicId),
        asNullableString(row.ownerType),
        asNullableString(row.ownerId),
        asNullableString(row.filename),
        asNullableString(row.mimeType),
        asNullableString(row.purpose),
        asNumber(row.byteSize, 0),
        asNullableString(row.sha256),
        asNullableString(row.contentBase64),
        asNullableString(row.createdAt),
        asNullableString(row.updatedAt),
        asNullableString(row.deletedAt),
      ],
    });
  }

  for (const row of snapshot.accounts.downstreamApiKeys) {
    statements.push({
      table: 'downstream_api_keys',
      columns: ['id', 'name', 'key', 'description', 'enabled', 'expires_at', 'max_cost', 'used_cost', 'max_requests', 'used_requests', 'supported_models', 'allowed_route_ids', 'site_weight_multipliers', 'excluded_site_ids', 'excluded_credential_refs', 'last_used_at', 'created_at', 'updated_at'],
      values: [
        asNumber(row.id, 0),
        asNullableString(row.name),
        asNullableString(row.key),
        asNullableString(row.description),
        asBoolean(row.enabled, true),
        asNullableString(row.expiresAt),
        asNumber(row.maxCost, null),
        asNumber(row.usedCost, 0),
        asNumber(row.maxRequests, null),
        asNumber(row.usedRequests, 0),
        serializeColumnValue('downstream_api_keys', 'supported_models', row.supportedModels, contract),
        serializeColumnValue('downstream_api_keys', 'allowed_route_ids', row.allowedRouteIds, contract),
        serializeColumnValue('downstream_api_keys', 'site_weight_multipliers', row.siteWeightMultipliers, contract),
        serializeColumnValue('downstream_api_keys', 'excluded_site_ids', row.excludedSiteIds, contract),
        serializeColumnValue('downstream_api_keys', 'excluded_credential_refs', row.excludedCredentialRefs, contract),
        asNullableString(row.lastUsedAt),
        asNullableString(row.createdAt),
        asNullableString(row.updatedAt),
      ],
    });
  }

  for (const row of snapshot.accounts.events) {
    statements.push({
      table: 'events',
      columns: ['id', 'type', 'title', 'message', 'level', 'read', 'related_id', 'related_type', 'created_at'],
      values: [
        asNumber(row.id, 0),
        asNullableString(row.type),
        asNullableString(row.title),
        asNullableString(row.message),
        asNullableString(row.level) ?? 'info',
        asBoolean(row.read, false),
        asNumber(row.relatedId, null),
        asNullableString(row.relatedType),
        asNullableString(row.createdAt),
      ],
    });
  }

  for (const row of snapshot.preferences.settings) {
    if (RUNTIME_DATABASE_SETTING_KEYS.has(row.key)) {
      continue;
    }
    statements.push({
      table: 'settings',
      columns: ['key', 'value'],
      values: [row.key, toJsonString(row.value)],
    });
  }

  return statements;
}

function buildInsertSql(dialect: MigrationDialect, statement: InsertStatement): { sqlText: string; params: unknown[] } {
  const table = quoteIdent(dialect, statement.table);
  const columns = statement.columns.map((item) => quoteIdent(dialect, item)).join(', ');
  const placeholders = statement.columns.map((_, index) => (dialect === 'postgres' ? `$${index + 1}` : '?')).join(', ');
  const params = statement.values.map((value) => {
    if (dialect === 'sqlite' && typeof value === 'boolean') {
      return value ? 1 : 0;
    }
    return value;
  });
  return {
    sqlText: `INSERT INTO ${table} (${columns}) VALUES (${placeholders})`,
    params,
  };
}

async function insertAllRows(client: SqlClient, statements: InsertStatement[]): Promise<void> {
  for (const statement of statements) {
    const { sqlText, params } = buildInsertSql(client.dialect, statement);
    await client.execute(sqlText, params);
  }
}

async function syncPostgresSequences(client: SqlClient): Promise<void> {
  if (client.dialect !== 'postgres') return;
  const tables = [
    'sites',
    'site_api_endpoints',
    'site_announcements',
    'site_disabled_models',
    'accounts',
    'account_tokens',
    'checkin_logs',
    'model_availability',
    'token_model_availability',
    'token_routes',
    'route_channels',
    'route_group_sources',
    'proxy_logs',
    'proxy_video_tasks',
    'proxy_files',
    'downstream_api_keys',
    'events',
  ];
  for (const table of tables) {
      await client.execute(`SELECT setval(pg_get_serial_sequence('${table}', 'id'), COALESCE((SELECT MAX(id) FROM "${table}"), 1), TRUE)`);
    }
  }

export async function bootstrapRuntimeDatabaseSchema(input: Pick<NormalizedDatabaseMigrationInput, 'dialect' | 'connectionString' | 'ssl'>): Promise<void> {
  const client = await createClient({
    dialect: input.dialect,
    connectionString: input.connectionString,
    overwrite: true,
    ssl: input.ssl,
  });
  try {
    await ensureRuntimeDatabaseSchema(client);
  } finally {
    await client.close();
  }
}

export async function migrateCurrentDatabase(input: DatabaseMigrationInput): Promise<DatabaseMigrationSummary> {
  const normalized = normalizeMigrationInput(input);
  const snapshot = await toBackupSnapshot();
  const client = await createClient(normalized);

  try {
    await ensureRuntimeDatabaseSchema(client);
    await ensureTargetState(client, normalized.overwrite);

    await client.begin();
    try {
      if (normalized.overwrite) {
        await clearTargetData(client);
      }
      await insertAllRows(client, buildStatements(snapshot));
      await syncPostgresSequences(client);
      await client.commit();
    } catch (error) {
      await client.rollback();
      throw error;
    }
  } finally {
    await client.close();
  }

  return {
    dialect: normalized.dialect,
    connection: maskConnectionString(normalized.connectionString),
    overwrite: normalized.overwrite,
    version: snapshot.version,
    timestamp: snapshot.timestamp,
    rows: {
      sites: snapshot.accounts.sites.length,
      siteApiEndpoints: snapshot.accounts.siteApiEndpoints.length,
      siteAnnouncements: snapshot.accounts.siteAnnouncements.length,
      siteDisabledModels: snapshot.accounts.siteDisabledModels.length,
      accounts: snapshot.accounts.accounts.length,
      accountTokens: snapshot.accounts.accountTokens.length,
      tokenRoutes: snapshot.accounts.tokenRoutes.length,
      routeChannels: snapshot.accounts.routeChannels.length,
      checkinLogs: snapshot.accounts.checkinLogs.length,
      modelAvailability: snapshot.accounts.modelAvailability.length,
      tokenModelAvailability: snapshot.accounts.tokenModelAvailability.length,
      proxyLogs: snapshot.accounts.proxyLogs.length,
      proxyVideoTasks: snapshot.accounts.proxyVideoTasks.length,
      proxyFiles: snapshot.accounts.proxyFiles.length,
      downstreamApiKeys: snapshot.accounts.downstreamApiKeys.length,
      events: snapshot.accounts.events.length,
      settings: snapshot.preferences.settings.length,
      routeGroupSources: snapshot.accounts.routeGroupSources.length,
    },
  };
}

export async function testDatabaseConnection(input: DatabaseMigrationInput): Promise<{ dialect: MigrationDialect; connection: string }> {
  const normalized = normalizeMigrationInput(input);
  const client = await createClient(normalized);
  try {
    await client.execute('SELECT 1');
  } finally {
    await client.close();
  }

  return {
    dialect: normalized.dialect,
    connection: maskConnectionString(normalized.connectionString),
  };
}

export const __databaseMigrationServiceTestUtils = {
  ensureSchema: ensureRuntimeDatabaseSchema,
  buildStatements,
  serializeColumnValue,
};
