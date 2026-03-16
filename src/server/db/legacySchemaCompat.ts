import {
  ensureAccountTokenSchemaCompatibility,
  type AccountTokenSchemaInspector,
} from './accountTokenSchemaCompatibility.js';
import {
  ensureProxyFileSchemaCompatibility,
  type ProxyFileSchemaInspector,
} from './proxyFileSchemaCompatibility.js';
import {
  ensureRouteGroupingSchemaCompatibility,
  type RouteGroupingSchemaInspector,
} from './routeGroupingSchemaCompatibility.js';
import {
  ensureSharedIndexSchemaCompatibility,
  SHARED_INDEX_COMPATIBILITY_SPECS,
  type SharedIndexSchemaInspector,
} from './sharedIndexSchemaCompatibility.js';
import {
  ensureSiteSchemaCompatibility,
  type SiteSchemaInspector,
} from './siteSchemaCompatibility.js';

export type LegacySchemaCompatClassification = 'legacy' | 'forbidden';

export interface LegacySchemaCompatInspector extends
  SiteSchemaInspector,
  RouteGroupingSchemaInspector,
  ProxyFileSchemaInspector,
  AccountTokenSchemaInspector,
  SharedIndexSchemaInspector {}

const LEGACY_COMPAT_TABLES = new Set([
  'account_tokens',
  'token_model_availability',
  'proxy_video_tasks',
  'proxy_files',
  'downstream_api_keys',
  'site_disabled_models',
]);

const LEGACY_COMPAT_COLUMNS = new Set([
  'sites.status',
  'sites.proxy_url',
  'sites.use_system_proxy',
  'sites.custom_headers',
  'sites.external_checkin_url',
  'sites.global_weight',
  'account_tokens.token_group',
  'account_tokens.value_status',
  'token_routes.display_name',
  'token_routes.display_icon',
  'token_routes.decision_snapshot',
  'token_routes.decision_refreshed_at',
  'token_routes.routing_strategy',
  'route_channels.token_id',
  'route_channels.source_model',
  'route_channels.last_selected_at',
  'route_channels.consecutive_fail_count',
  'route_channels.cooldown_level',
  'proxy_video_tasks.status_snapshot',
  'proxy_video_tasks.upstream_response_meta',
  'proxy_video_tasks.last_upstream_status',
  'proxy_video_tasks.last_polled_at',
  'downstream_api_keys.group_name',
  'downstream_api_keys.tags',
  'proxy_logs.billing_details',
  'proxy_logs.downstream_api_key_id',
]);

const LEGACY_COMPAT_INDEXES = new Set([
  'site_disabled_models_site_model_unique',
  'site_disabled_models_site_id_idx',
  'token_model_availability_token_model_unique',
  'proxy_video_tasks_public_id_unique',
  'proxy_video_tasks_upstream_video_id_idx',
  'proxy_files_public_id_unique',
  'proxy_files_owner_lookup_idx',
  'downstream_api_keys_key_unique',
  'downstream_api_keys_name_idx',
  'downstream_api_keys_enabled_idx',
  'downstream_api_keys_expires_at_idx',
  'proxy_logs_downstream_api_key_created_at_idx',
  ...SHARED_INDEX_COMPATIBILITY_SPECS.map((spec) => spec.indexName),
]);

function normalizeSqlText(sqlText: string): string {
  return sqlText.trim().replace(/\s+/g, ' ').toLowerCase();
}

const LEGACY_COMPAT_UPDATES = new Set([
  'UPDATE sites SET use_system_proxy = 0 WHERE use_system_proxy IS NULL;',
  'UPDATE `sites` SET `use_system_proxy` = FALSE WHERE `use_system_proxy` IS NULL',
  'UPDATE "sites" SET "use_system_proxy" = FALSE WHERE "use_system_proxy" IS NULL',
  'UPDATE sites SET global_weight = 1 WHERE global_weight IS NULL OR global_weight <= 0;',
  'UPDATE `sites` SET `global_weight` = 1 WHERE `global_weight` IS NULL OR `global_weight` <= 0',
  'UPDATE "sites" SET "global_weight" = 1 WHERE "global_weight" IS NULL OR "global_weight" <= 0',
].map((sqlText) => normalizeSqlText(sqlText)));

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
