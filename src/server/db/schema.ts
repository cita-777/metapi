import { sqliteTable, text, integer, real, uniqueIndex, index } from 'drizzle-orm/sqlite-core';
import { sql } from 'drizzle-orm';

export const sites = sqliteTable('sites', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  name: text('name').notNull(),
  url: text('url').notNull(),
  externalCheckinUrl: text('external_checkin_url'),
  platform: text('platform').notNull(), // 'new-api' | 'one-api' | 'veloera' | 'one-hub' | 'done-hub' | 'sub2api' | 'openai' | 'claude' | 'gemini' | 'codex' | 'gemini-cli' | 'antigravity'
  proxyUrl: text('proxy_url'),
  useSystemProxy: integer('use_system_proxy', { mode: 'boolean' }).default(false),
  customHeaders: text('custom_headers'),
  status: text('status').notNull().default('active'), // 'active' | 'disabled'
  isPinned: integer('is_pinned', { mode: 'boolean' }).default(false),
  sortOrder: integer('sort_order').default(0),
  globalWeight: real('global_weight').default(1),
  apiKey: text('api_key'),
  createdAt: text('created_at').default(sql`(datetime('now'))`),
  updatedAt: text('updated_at').default(sql`(datetime('now'))`),
}, (table) => ({
  statusIdx: index('sites_status_idx').on(table.status),
  platformUrlUnique: uniqueIndex('sites_platform_url_unique').on(table.platform, table.url),
}));

export const siteDisabledModels = sqliteTable('site_disabled_models', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  siteId: integer('site_id').notNull().references(() => sites.id, { onDelete: 'cascade' }),
  modelName: text('model_name').notNull(),
  createdAt: text('created_at').default(sql`(datetime('now'))`),
}, (table) => ({
  siteModelUnique: uniqueIndex('site_disabled_models_site_model_unique').on(table.siteId, table.modelName),
  siteIdIdx: index('site_disabled_models_site_id_idx').on(table.siteId),
}));

export const accounts = sqliteTable('accounts', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  siteId: integer('site_id').notNull().references(() => sites.id, { onDelete: 'cascade' }),
  username: text('username'),
  accessToken: text('access_token').notNull(),
  apiToken: text('api_token'),
  balance: real('balance').default(0),
  balanceUsed: real('balance_used').default(0),
  quota: real('quota').default(0),
  unitCost: real('unit_cost'),
  valueScore: real('value_score').default(0),
  status: text('status').default('active'), // 'active' | 'disabled' | 'expired'
  isPinned: integer('is_pinned', { mode: 'boolean' }).default(false),
  sortOrder: integer('sort_order').default(0),
  checkinEnabled: integer('checkin_enabled', { mode: 'boolean' }).default(true),
  lastCheckinAt: text('last_checkin_at'),
  lastBalanceRefresh: text('last_balance_refresh'),
  oauthProvider: text('oauth_provider'),
  oauthAccountKey: text('oauth_account_key'),
  oauthProjectId: text('oauth_project_id'),
  extraConfig: text('extra_config'), // JSON string
  createdAt: text('created_at').default(sql`(datetime('now'))`),
  updatedAt: text('updated_at').default(sql`(datetime('now'))`),
}, (table) => ({
  siteIdIdx: index('accounts_site_id_idx').on(table.siteId),
  statusIdx: index('accounts_status_idx').on(table.status),
  siteStatusIdx: index('accounts_site_status_idx').on(table.siteId, table.status),
  oauthProviderIdx: index('accounts_oauth_provider_idx').on(table.oauthProvider),
  oauthIdentityIdx: index('accounts_oauth_identity_idx').on(table.oauthProvider, table.oauthAccountKey, table.oauthProjectId),
}));

export const accountTokens = sqliteTable('account_tokens', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  accountId: integer('account_id').notNull().references(() => accounts.id, { onDelete: 'cascade' }),
  name: text('name').notNull(),
  token: text('token').notNull(),
  tokenGroup: text('token_group'),
  valueStatus: text('value_status').notNull().default('ready'),
  source: text('source').default('manual'), // 'manual' | 'sync' | 'legacy'
  enabled: integer('enabled', { mode: 'boolean' }).default(true),
  isDefault: integer('is_default', { mode: 'boolean' }).default(false),
  createdAt: text('created_at').default(sql`(datetime('now'))`),
  updatedAt: text('updated_at').default(sql`(datetime('now'))`),
}, (table) => ({
  accountIdIdx: index('account_tokens_account_id_idx').on(table.accountId),
  accountEnabledIdx: index('account_tokens_account_enabled_idx').on(table.accountId, table.enabled),
  enabledIdx: index('account_tokens_enabled_idx').on(table.enabled),
}));

export const checkinLogs = sqliteTable('checkin_logs', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  accountId: integer('account_id').notNull().references(() => accounts.id, { onDelete: 'cascade' }),
  status: text('status').notNull(), // 'success' | 'failed' | 'skipped'
  message: text('message'),
  reward: text('reward'),
  createdAt: text('created_at').default(sql`(datetime('now'))`),
}, (table) => ({
  accountCreatedIdx: index('checkin_logs_account_created_at_idx').on(table.accountId, table.createdAt),
  createdAtIdx: index('checkin_logs_created_at_idx').on(table.createdAt),
  statusIdx: index('checkin_logs_status_idx').on(table.status),
}));

export const modelAvailability = sqliteTable('model_availability', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  accountId: integer('account_id').notNull().references(() => accounts.id, { onDelete: 'cascade' }),
  modelName: text('model_name').notNull(),
  available: integer('available', { mode: 'boolean' }),
  isManual: integer('is_manual', { mode: 'boolean' }).default(false),
  latencyMs: integer('latency_ms'),
  checkedAt: text('checked_at').default(sql`(datetime('now'))`),
}, (table) => ({
  accountModelUnique: uniqueIndex('model_availability_account_model_unique').on(table.accountId, table.modelName),
  accountAvailableIdx: index('model_availability_account_available_idx').on(table.accountId, table.available),
  modelNameIdx: index('model_availability_model_name_idx').on(table.modelName),
}));

export const tokenModelAvailability = sqliteTable('token_model_availability', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  tokenId: integer('token_id').notNull().references(() => accountTokens.id, { onDelete: 'cascade' }),
  modelName: text('model_name').notNull(),
  available: integer('available', { mode: 'boolean' }),
  latencyMs: integer('latency_ms'),
  checkedAt: text('checked_at').default(sql`(datetime('now'))`),
}, (table) => ({
  tokenModelUnique: uniqueIndex('token_model_availability_token_model_unique').on(table.tokenId, table.modelName),
  tokenAvailableIdx: index('token_model_availability_token_available_idx').on(table.tokenId, table.available),
  modelNameIdx: index('token_model_availability_model_name_idx').on(table.modelName),
  availableIdx: index('token_model_availability_available_idx').on(table.available),
}));

export const tokenRoutes = sqliteTable('token_routes', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  modelPattern: text('model_pattern').notNull(),
  displayName: text('display_name'),
  displayIcon: text('display_icon'),
  routeMode: text('route_mode').default('pattern'),
  modelMapping: text('model_mapping'), // JSON
  decisionSnapshot: text('decision_snapshot'), // JSON
  decisionRefreshedAt: text('decision_refreshed_at'),
  routingStrategy: text('routing_strategy').default('weighted'),
  enabled: integer('enabled', { mode: 'boolean' }).default(true),
  createdAt: text('created_at').default(sql`(datetime('now'))`),
  updatedAt: text('updated_at').default(sql`(datetime('now'))`),
}, (table) => ({
  modelPatternIdx: index('token_routes_model_pattern_idx').on(table.modelPattern),
  enabledIdx: index('token_routes_enabled_idx').on(table.enabled),
}));

export const routeGroupSources = sqliteTable('route_group_sources', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  groupRouteId: integer('group_route_id').notNull().references(() => tokenRoutes.id, { onDelete: 'cascade' }),
  sourceRouteId: integer('source_route_id').notNull().references(() => tokenRoutes.id, { onDelete: 'cascade' }),
}, (table) => ({
  groupSourceUnique: uniqueIndex('route_group_sources_group_source_unique').on(table.groupRouteId, table.sourceRouteId),
  sourceRouteIdx: index('route_group_sources_source_route_id_idx').on(table.sourceRouteId),
}));

export const routeChannels = sqliteTable('route_channels', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  routeId: integer('route_id').notNull().references(() => tokenRoutes.id, { onDelete: 'cascade' }),
  accountId: integer('account_id').notNull().references(() => accounts.id, { onDelete: 'cascade' }),
  tokenId: integer('token_id').references(() => accountTokens.id, { onDelete: 'set null' }),
  sourceModel: text('source_model'),
  priority: integer('priority').default(0),
  weight: integer('weight').default(10),
  enabled: integer('enabled', { mode: 'boolean' }).default(true),
  manualOverride: integer('manual_override', { mode: 'boolean' }).default(false),
  successCount: integer('success_count').default(0),
  failCount: integer('fail_count').default(0),
  totalLatencyMs: integer('total_latency_ms').default(0),
  totalCost: real('total_cost').default(0),
  lastUsedAt: text('last_used_at'),
  lastSelectedAt: text('last_selected_at'),
  lastFailAt: text('last_fail_at'),
  consecutiveFailCount: integer('consecutive_fail_count').notNull().default(0),
  cooldownLevel: integer('cooldown_level').notNull().default(0),
  cooldownUntil: text('cooldown_until'),
}, (table) => ({
  routeIdIdx: index('route_channels_route_id_idx').on(table.routeId),
  accountIdIdx: index('route_channels_account_id_idx').on(table.accountId),
  tokenIdIdx: index('route_channels_token_id_idx').on(table.tokenId),
  routeEnabledIdx: index('route_channels_route_enabled_idx').on(table.routeId, table.enabled),
  routeTokenIdx: index('route_channels_route_token_idx').on(table.routeId, table.tokenId),
}));

export const proxyLogs = sqliteTable('proxy_logs', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  routeId: integer('route_id'),
  channelId: integer('channel_id'),
  accountId: integer('account_id'),
  downstreamApiKeyId: integer('downstream_api_key_id'),
  modelRequested: text('model_requested'),
  modelActual: text('model_actual'),
  status: text('status'), // 'success' | 'failed' | 'retried'
  httpStatus: integer('http_status'),
  latencyMs: integer('latency_ms'),
  promptTokens: integer('prompt_tokens'),
  completionTokens: integer('completion_tokens'),
  totalTokens: integer('total_tokens'),
  estimatedCost: real('estimated_cost'),
  billingDetails: text('billing_details'),
  clientFamily: text('client_family'),
  clientAppId: text('client_app_id'),
  clientAppName: text('client_app_name'),
  clientConfidence: text('client_confidence'),
  errorMessage: text('error_message'),
  retryCount: integer('retry_count').default(0),
  createdAt: text('created_at').default(sql`(datetime('now'))`),
}, (table) => ({
  createdAtIdx: index('proxy_logs_created_at_idx').on(table.createdAt),
  accountCreatedIdx: index('proxy_logs_account_created_at_idx').on(table.accountId, table.createdAt),
  statusCreatedIdx: index('proxy_logs_status_created_at_idx').on(table.status, table.createdAt),
  modelActualCreatedIdx: index('proxy_logs_model_actual_created_at_idx').on(table.modelActual, table.createdAt),
  downstreamKeyCreatedIdx: index('proxy_logs_downstream_api_key_created_at_idx').on(table.downstreamApiKeyId, table.createdAt),
  clientAppCreatedIdx: index('proxy_logs_client_app_id_created_at_idx').on(table.clientAppId, table.createdAt),
  clientFamilyCreatedIdx: index('proxy_logs_client_family_created_at_idx').on(table.clientFamily, table.createdAt),
}));

export const proxyDebugTraces = sqliteTable('proxy_debug_traces', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  downstreamPath: text('downstream_path').notNull(),
  clientKind: text('client_kind'),
  sessionId: text('session_id'),
  traceHint: text('trace_hint'),
  requestedModel: text('requested_model'),
  downstreamApiKeyId: integer('downstream_api_key_id'),
  requestHeadersJson: text('request_headers_json'),
  requestBodyJson: text('request_body_json'),
  stickySessionKey: text('sticky_session_key'),
  stickyHitChannelId: integer('sticky_hit_channel_id'),
  selectedChannelId: integer('selected_channel_id'),
  selectedRouteId: integer('selected_route_id'),
  selectedAccountId: integer('selected_account_id'),
  selectedSiteId: integer('selected_site_id'),
  selectedSitePlatform: text('selected_site_platform'),
  endpointCandidatesJson: text('endpoint_candidates_json'),
  endpointRuntimeStateJson: text('endpoint_runtime_state_json'),
  decisionSummaryJson: text('decision_summary_json'),
  finalStatus: text('final_status'),
  finalHttpStatus: integer('final_http_status'),
  finalUpstreamPath: text('final_upstream_path'),
  finalResponseHeadersJson: text('final_response_headers_json'),
  finalResponseBodyJson: text('final_response_body_json'),
  createdAt: text('created_at').default(sql`(datetime('now'))`),
  updatedAt: text('updated_at').default(sql`(datetime('now'))`),
}, (table) => ({
  createdAtIdx: index('proxy_debug_traces_created_at_idx').on(table.createdAt),
  sessionCreatedIdx: index('proxy_debug_traces_session_created_at_idx').on(table.sessionId, table.createdAt),
  modelCreatedIdx: index('proxy_debug_traces_model_created_at_idx').on(table.requestedModel, table.createdAt),
  finalStatusCreatedIdx: index('proxy_debug_traces_final_status_created_at_idx').on(table.finalStatus, table.createdAt),
}));

export const proxyDebugAttempts = sqliteTable('proxy_debug_attempts', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  traceId: integer('trace_id').notNull().references(() => proxyDebugTraces.id, { onDelete: 'cascade' }),
  attemptIndex: integer('attempt_index').notNull(),
  endpoint: text('endpoint').notNull(),
  requestPath: text('request_path').notNull(),
  targetUrl: text('target_url').notNull(),
  runtimeExecutor: text('runtime_executor'),
  requestHeadersJson: text('request_headers_json'),
  requestBodyJson: text('request_body_json'),
  responseStatus: integer('response_status'),
  responseHeadersJson: text('response_headers_json'),
  responseBodyJson: text('response_body_json'),
  rawErrorText: text('raw_error_text'),
  recoverApplied: integer('recover_applied', { mode: 'boolean' }).default(false),
  downgradeDecision: integer('downgrade_decision', { mode: 'boolean' }).default(false),
  downgradeReason: text('downgrade_reason'),
  memoryWriteJson: text('memory_write_json'),
  createdAt: text('created_at').default(sql`(datetime('now'))`),
}, (table) => ({
  traceAttemptUnique: uniqueIndex('proxy_debug_attempts_trace_attempt_unique').on(table.traceId, table.attemptIndex),
  traceCreatedIdx: index('proxy_debug_attempts_trace_created_at_idx').on(table.traceId, table.createdAt),
}));

export const proxyVideoTasks = sqliteTable('proxy_video_tasks', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  publicId: text('public_id').notNull(),
  upstreamVideoId: text('upstream_video_id').notNull(),
  siteUrl: text('site_url').notNull(),
  tokenValue: text('token_value').notNull(),
  requestedModel: text('requested_model'),
  actualModel: text('actual_model'),
  channelId: integer('channel_id'),
  accountId: integer('account_id'),
  statusSnapshot: text('status_snapshot'),
  upstreamResponseMeta: text('upstream_response_meta'),
  lastUpstreamStatus: integer('last_upstream_status'),
  lastPolledAt: text('last_polled_at'),
  createdAt: text('created_at').default(sql`(datetime('now'))`),
  updatedAt: text('updated_at').default(sql`(datetime('now'))`),
}, (table) => ({
  publicIdUnique: uniqueIndex('proxy_video_tasks_public_id_unique').on(table.publicId),
  upstreamVideoIdIdx: index('proxy_video_tasks_upstream_video_id_idx').on(table.upstreamVideoId),
  createdAtIdx: index('proxy_video_tasks_created_at_idx').on(table.createdAt),
}));

export const proxyFiles = sqliteTable('proxy_files', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  publicId: text('public_id').notNull(),
  ownerType: text('owner_type').notNull(),
  ownerId: text('owner_id').notNull(),
  filename: text('filename').notNull(),
  mimeType: text('mime_type').notNull(),
  purpose: text('purpose'),
  byteSize: integer('byte_size').notNull(),
  sha256: text('sha256').notNull(),
  contentBase64: text('content_base64').notNull(),
  createdAt: text('created_at').default(sql`(datetime('now'))`),
  updatedAt: text('updated_at').default(sql`(datetime('now'))`),
  deletedAt: text('deleted_at'),
}, (table) => ({
  publicIdUnique: uniqueIndex('proxy_files_public_id_unique').on(table.publicId),
  ownerLookupIdx: index('proxy_files_owner_lookup_idx').on(table.ownerType, table.ownerId, table.deletedAt),
}));

export const settings = sqliteTable('settings', {
  key: text('key').primaryKey(),
  value: text('value'), // JSON
});

export const downstreamApiKeys = sqliteTable('downstream_api_keys', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  name: text('name').notNull(),
  key: text('key').notNull(),
  description: text('description'),
  groupName: text('group_name'),
  tags: text('tags'), // JSON array<string>
  enabled: integer('enabled', { mode: 'boolean' }).default(true),
  expiresAt: text('expires_at'),
  maxCost: real('max_cost'),
  usedCost: real('used_cost').default(0),
  maxRequests: integer('max_requests'),
  usedRequests: integer('used_requests').default(0),
  supportedModels: text('supported_models'), // JSON array<string>
  allowedRouteIds: text('allowed_route_ids'), // JSON array<number>
  siteWeightMultipliers: text('site_weight_multipliers'), // JSON object { [siteId]: multiplier }
  lastUsedAt: text('last_used_at'),
  createdAt: text('created_at').default(sql`(datetime('now'))`),
  updatedAt: text('updated_at').default(sql`(datetime('now'))`),
}, (table) => ({
  keyUnique: uniqueIndex('downstream_api_keys_key_unique').on(table.key),
  nameIdx: index('downstream_api_keys_name_idx').on(table.name),
  enabledIdx: index('downstream_api_keys_enabled_idx').on(table.enabled),
  expiresAtIdx: index('downstream_api_keys_expires_at_idx').on(table.expiresAt),
}));

export const siteAnnouncements = sqliteTable('site_announcements', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  siteId: integer('site_id').notNull().references(() => sites.id, { onDelete: 'cascade' }),
  platform: text('platform').notNull(),
  sourceKey: text('source_key').notNull(),
  title: text('title').notNull(),
  content: text('content').notNull(),
  level: text('level').notNull().default('info'),
  sourceUrl: text('source_url'),
  startsAt: text('starts_at'),
  endsAt: text('ends_at'),
  upstreamCreatedAt: text('upstream_created_at'),
  upstreamUpdatedAt: text('upstream_updated_at'),
  firstSeenAt: text('first_seen_at').default(sql`(datetime('now'))`),
  lastSeenAt: text('last_seen_at').default(sql`(datetime('now'))`),
  readAt: text('read_at'),
  dismissedAt: text('dismissed_at'),
  rawPayload: text('raw_payload'),
}, (table) => ({
  siteSourceKeyUnique: uniqueIndex('site_announcements_site_source_key_unique').on(table.siteId, table.sourceKey),
  siteIdFirstSeenAtIdx: index('site_announcements_site_id_first_seen_at_idx').on(table.siteId, table.firstSeenAt),
  readAtIdx: index('site_announcements_read_at_idx').on(table.readAt),
}));

export const events = sqliteTable('events', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  type: text('type').notNull(), // 'checkin' | 'balance' | 'token' | 'proxy' | 'status'
  title: text('title').notNull(),
  message: text('message'),
  level: text('level').notNull().default('info'), // 'info' | 'warning' | 'error'
  read: integer('read', { mode: 'boolean' }).default(false),
  relatedId: integer('related_id'),
  relatedType: text('related_type'), // 'account' | 'site' | 'route'
  createdAt: text('created_at').default(sql`(datetime('now'))`),
}, (table) => ({
  readCreatedIdx: index('events_read_created_at_idx').on(table.read, table.createdAt),
  typeCreatedIdx: index('events_type_created_at_idx').on(table.type, table.createdAt),
  createdAtIdx: index('events_created_at_idx').on(table.createdAt),
}));
