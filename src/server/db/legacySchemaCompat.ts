import {
  ACCOUNT_TOKEN_COLUMN_COMPATIBILITY_SPECS,
  ensureAccountTokenSchemaCompatibility,
  type AccountTokenSchemaInspector,
} from './accountTokenSchemaCompatibility.js';
import {
  ensureProxyFileSchemaCompatibility,
  PROXY_FILE_COLUMN_COMPATIBILITY_SPECS,
  PROXY_FILE_INDEX_COMPATIBILITY_SPECS,
  PROXY_FILE_TABLE_COMPATIBILITY_SPECS,
  type ProxyFileSchemaInspector,
} from './proxyFileSchemaCompatibility.js';
import {
  ensureRouteGroupingSchemaCompatibility,
  ROUTE_GROUPING_COLUMN_COMPATIBILITY_SPECS,
  ROUTE_GROUPING_TABLE_COMPATIBILITY_SPECS,
  type RouteGroupingSchemaInspector,
} from './routeGroupingSchemaCompatibility.js';
import {
  ensureSharedIndexSchemaCompatibility,
  SHARED_INDEX_COMPATIBILITY_SPECS,
  type SharedIndexSchemaInspector,
} from './sharedIndexSchemaCompatibility.js';
import {
  ensureSiteSchemaCompatibility,
  SITE_COLUMN_COMPATIBILITY_SPECS,
  SITE_TABLE_COMPATIBILITY_SPECS,
  type SiteSchemaInspector,
} from './siteSchemaCompatibility.js';

export type LegacySchemaCompatClassification = 'legacy' | 'forbidden';

export interface LegacySchemaCompatInspector extends
  SiteSchemaInspector,
  RouteGroupingSchemaInspector,
  ProxyFileSchemaInspector,
  AccountTokenSchemaInspector,
  SharedIndexSchemaInspector {}

const BOOTSTRAP_OWNED_LEGACY_TABLES = [
  'account_tokens',
  'token_model_availability',
  'proxy_video_tasks',
  'downstream_api_keys',
];

const BOOTSTRAP_OWNED_LEGACY_COLUMNS = [
  'sites.status',
  'route_channels.token_id',
  'proxy_video_tasks.status_snapshot',
  'proxy_video_tasks.upstream_response_meta',
  'proxy_video_tasks.last_upstream_status',
  'proxy_video_tasks.last_polled_at',
  'downstream_api_keys.group_name',
  'downstream_api_keys.tags',
  'proxy_logs.billing_details',
  'proxy_logs.client_family',
  'proxy_logs.client_app_id',
  'proxy_logs.client_app_name',
  'proxy_logs.client_confidence',
  'proxy_logs.downstream_api_key_id',
];

const BOOTSTRAP_OWNED_LEGACY_INDEXES = [
  'token_model_availability_token_model_unique',
  'proxy_video_tasks_public_id_unique',
  'proxy_video_tasks_upstream_video_id_idx',
  'downstream_api_keys_key_unique',
  'downstream_api_keys_name_idx',
  'downstream_api_keys_enabled_idx',
  'downstream_api_keys_expires_at_idx',
  'proxy_logs_client_app_id_created_at_idx',
  'proxy_logs_client_family_created_at_idx',
  'proxy_logs_downstream_api_key_created_at_idx',
];

function normalizeSqlText(sqlText: string): string {
  return sqlText.trim().replace(/\s+/g, ' ').toLowerCase();
}

function extractIndexName(sqlText: string): string | null {
  const match = normalizeSqlText(sqlText).match(
    /^create (?:unique )?index(?: if not exists)? [`"]?([a-z0-9_]+)[`"]?/i,
  );
  return match?.[1] ?? null;
}

const LEGACY_COMPAT_TABLES = new Set([
  ...SITE_TABLE_COMPATIBILITY_SPECS.map((spec) => spec.table),
  ...ROUTE_GROUPING_TABLE_COMPATIBILITY_SPECS.map((spec) => spec.table),
  ...PROXY_FILE_TABLE_COMPATIBILITY_SPECS.map((spec) => spec.table),
  ...BOOTSTRAP_OWNED_LEGACY_TABLES,
]);

const LEGACY_COMPAT_COLUMNS = new Set([
  ...SITE_COLUMN_COMPATIBILITY_SPECS.map((spec) => `sites.${spec.column}`),
  ...ACCOUNT_TOKEN_COLUMN_COMPATIBILITY_SPECS.map((spec) => `${spec.table}.${spec.column}`),
  ...ROUTE_GROUPING_COLUMN_COMPATIBILITY_SPECS.map((spec) => `${spec.table}.${spec.column}`),
  ...PROXY_FILE_COLUMN_COMPATIBILITY_SPECS.map((spec) => `${spec.table}.${spec.column}`),
  ...BOOTSTRAP_OWNED_LEGACY_COLUMNS,
]);

const LEGACY_COMPAT_INDEXES = new Set([
  ...SITE_TABLE_COMPATIBILITY_SPECS.flatMap((spec) => spec.postCreateSql ? Object.values(spec.postCreateSql) : [])
    .flat()
    .map((sqlText) => extractIndexName(sqlText))
    .filter((indexName): indexName is string => Boolean(indexName)),
  ...ROUTE_GROUPING_TABLE_COMPATIBILITY_SPECS.flatMap((spec) => Object.values(spec.createSql))
    .flat()
    .map((sqlText) => extractIndexName(sqlText))
    .filter((indexName): indexName is string => Boolean(indexName)),
  ...PROXY_FILE_INDEX_COMPATIBILITY_SPECS.map((spec) => spec.indexName),
  ...BOOTSTRAP_OWNED_LEGACY_INDEXES,
  ...SHARED_INDEX_COMPATIBILITY_SPECS.map((spec) => spec.indexName),
]);

const LEGACY_COMPAT_UPDATES = new Set(
  SITE_COLUMN_COMPATIBILITY_SPECS
    .flatMap((spec) => spec.normalizeSql ? Object.values(spec.normalizeSql) : [])
    .map((sqlText) => normalizeSqlText(sqlText)),
);

export function classifyLegacyCompatMutation(sqlText: string): LegacySchemaCompatClassification {
  const normalized = normalizeSqlText(sqlText);

  if (LEGACY_COMPAT_UPDATES.has(normalized)) {
    return 'legacy';
  }

  const createTableMatch = normalized.match(/^create table if not exists [`"]?([a-z0-9_]+)[`"]?/i);
  if (createTableMatch) {
    return LEGACY_COMPAT_TABLES.has(createTableMatch[1]) ? 'legacy' : 'forbidden';
  }

  const alterTableMatch = normalized.match(
    /^alter table [`"]?([a-z0-9_]+)[`"]? add column [`"]?([a-z0-9_]+)[`"]?/i,
  );
  if (alterTableMatch) {
    const [, tableName, columnName] = alterTableMatch;
    return LEGACY_COMPAT_COLUMNS.has(`${tableName}.${columnName}`) ? 'legacy' : 'forbidden';
  }

  const createIndexMatch = normalized.match(
    /^create (?:unique )?index(?: if not exists)? [`"]?([a-z0-9_]+)[`"]?/i,
  );
  if (createIndexMatch) {
    return LEGACY_COMPAT_INDEXES.has(createIndexMatch[1]) ? 'legacy' : 'forbidden';
  }

  return 'forbidden';
}

function assertLegacyCompatMutation(sqlText: string): void {
  if (classifyLegacyCompatMutation(sqlText) === 'forbidden') {
    throw new Error(`Forbidden legacy schema mutation: ${sqlText}`);
  }
}

export async function executeLegacyCompat(
  execute: (sqlText: string) => Promise<void>,
  sqlText: string,
): Promise<void> {
  assertLegacyCompatMutation(sqlText);
  await execute(sqlText);
}

export function executeLegacyCompatSync(
  execute: (sqlText: string) => void,
  sqlText: string,
): void {
  assertLegacyCompatMutation(sqlText);
  execute(sqlText);
}

function wrapLegacyCompatInspector(inspector: LegacySchemaCompatInspector): LegacySchemaCompatInspector {
  return {
    ...inspector,
    execute: async (sqlText: string) => {
      await executeLegacyCompat((statement) => inspector.execute(statement), sqlText);
    },
  };
}

export async function ensureLegacySchemaCompatibility(inspector: LegacySchemaCompatInspector): Promise<void> {
  const wrappedInspector = wrapLegacyCompatInspector(inspector);
  await ensureSiteSchemaCompatibility(wrappedInspector);
  await ensureRouteGroupingSchemaCompatibility(wrappedInspector);
  await ensureProxyFileSchemaCompatibility(wrappedInspector);
  await ensureAccountTokenSchemaCompatibility(wrappedInspector);
  await ensureSharedIndexSchemaCompatibility(wrappedInspector);
}
