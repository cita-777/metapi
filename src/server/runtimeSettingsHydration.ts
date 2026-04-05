import {
  config,
  normalizeTokenRouterFailureCooldownMaxSec,
} from './config.js';
import { normalizePayloadRulesConfig } from './services/payloadRules.js';
import { normalizeLogCleanupRetentionDays } from './shared/logCleanupRetentionDays.js';

export function parseSettingFromMap<T>(settingsMap: Map<string, string>, key: string): T | undefined {
  const raw = settingsMap.get(key);
  if (typeof raw !== 'string' || !raw) return undefined;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return undefined;
  }
}

function toStringList(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value
      .map((item) => (typeof item === 'string' ? item.trim() : ''))
      .filter((item) => item.length > 0);
  }
  if (typeof value === 'string') {
    return value
      .split(',')
      .map((item) => item.trim())
      .filter((item) => item.length > 0);
  }
  return [];
}

export function applyRuntimeSettings(settingsMap: Map<string, string>) {
  const authToken = parseSettingFromMap<string>(settingsMap, 'auth_token');
  if (typeof authToken === 'string' && authToken) config.authToken = authToken;

  const proxyToken = parseSettingFromMap<string>(settingsMap, 'proxy_token');
  if (typeof proxyToken === 'string' && proxyToken) config.proxyToken = proxyToken;

  const systemProxyUrl = parseSettingFromMap<string>(settingsMap, 'system_proxy_url');
  if (typeof systemProxyUrl === 'string') config.systemProxyUrl = systemProxyUrl;

  const modelAvailabilityProbeEnabled = parseSettingFromMap<boolean>(settingsMap, 'model_availability_probe_enabled');
  if (typeof modelAvailabilityProbeEnabled === 'boolean') {
    config.modelAvailabilityProbeEnabled = modelAvailabilityProbeEnabled;
  }

  const codexUpstreamWebsocketEnabled = parseSettingFromMap<boolean>(settingsMap, 'codex_upstream_websocket_enabled');
  if (typeof codexUpstreamWebsocketEnabled === 'boolean') {
    config.codexUpstreamWebsocketEnabled = codexUpstreamWebsocketEnabled;
  }

  const responsesCompactFallbackToResponsesEnabled = parseSettingFromMap<boolean>(settingsMap, 'responses_compact_fallback_to_responses_enabled');
  if (typeof responsesCompactFallbackToResponsesEnabled === 'boolean') {
    config.responsesCompactFallbackToResponsesEnabled = responsesCompactFallbackToResponsesEnabled;
  }

  const disableCrossProtocolFallback = parseSettingFromMap<boolean>(settingsMap, 'disable_cross_protocol_fallback');
  if (typeof disableCrossProtocolFallback === 'boolean') {
    config.disableCrossProtocolFallback = disableCrossProtocolFallback;
  }

  const proxyErrorKeywords = parseSettingFromMap<string[] | string>(settingsMap, 'proxy_error_keywords');
  if (proxyErrorKeywords !== undefined) {
    config.proxyErrorKeywords = toStringList(proxyErrorKeywords);
  }

  const proxyEmptyContentFailEnabled = parseSettingFromMap<boolean>(settingsMap, 'proxy_empty_content_fail_enabled');
  if (typeof proxyEmptyContentFailEnabled === 'boolean') {
    config.proxyEmptyContentFailEnabled = proxyEmptyContentFailEnabled;
  }

  const globalBlockedBrands = parseSettingFromMap<string[]>(settingsMap, 'global_blocked_brands');
  if (Array.isArray(globalBlockedBrands)) {
    config.globalBlockedBrands = globalBlockedBrands.filter((b): b is string => typeof b === 'string').map((b) => b.trim()).filter(Boolean);
  }

  const globalAllowedModels = parseSettingFromMap<string[] | string>(settingsMap, 'global_allowed_models');
  if (globalAllowedModels !== undefined) {
    config.globalAllowedModels = toStringList(globalAllowedModels);
  }

  const codexHeaderDefaults = parseSettingFromMap<unknown>(settingsMap, 'codex_header_defaults');
  if (codexHeaderDefaults && typeof codexHeaderDefaults === 'object') {
    const next = codexHeaderDefaults as Record<string, unknown>;
    config.codexHeaderDefaults = {
      userAgent: typeof next.userAgent === 'string'
        ? next.userAgent.trim()
        : (typeof next['user-agent'] === 'string' ? next['user-agent'].trim() : config.codexHeaderDefaults.userAgent),
      betaFeatures: typeof next.betaFeatures === 'string'
        ? next.betaFeatures.trim()
        : (typeof next['beta-features'] === 'string' ? next['beta-features'].trim() : config.codexHeaderDefaults.betaFeatures),
    };
  }

  if (settingsMap.has('payload_rules')) {
    config.payloadRules = normalizePayloadRulesConfig(parseSettingFromMap<unknown>(settingsMap, 'payload_rules'));
  }

  const checkinCron = parseSettingFromMap<string>(settingsMap, 'checkin_cron');
  if (typeof checkinCron === 'string' && checkinCron) config.checkinCron = checkinCron;

  const checkinScheduleMode = parseSettingFromMap<string>(settingsMap, 'checkin_schedule_mode');
  if (checkinScheduleMode === 'cron' || checkinScheduleMode === 'interval') {
    config.checkinScheduleMode = checkinScheduleMode;
  }

  const checkinIntervalHours = parseSettingFromMap<number>(settingsMap, 'checkin_interval_hours');
  if (typeof checkinIntervalHours === 'number' && Number.isFinite(checkinIntervalHours) && checkinIntervalHours >= 1 && checkinIntervalHours <= 24) {
    config.checkinIntervalHours = Math.trunc(checkinIntervalHours);
  }

  const balanceRefreshCron = parseSettingFromMap<string>(settingsMap, 'balance_refresh_cron');
  if (typeof balanceRefreshCron === 'string' && balanceRefreshCron) config.balanceRefreshCron = balanceRefreshCron;

  const logCleanupCron = parseSettingFromMap<string>(settingsMap, 'log_cleanup_cron');
  if (typeof logCleanupCron === 'string' && logCleanupCron) config.logCleanupCron = logCleanupCron;

  const logCleanupUsageLogsEnabled = parseSettingFromMap<boolean>(settingsMap, 'log_cleanup_usage_logs_enabled');
  if (typeof logCleanupUsageLogsEnabled === 'boolean') {
    config.logCleanupUsageLogsEnabled = logCleanupUsageLogsEnabled;
  }

  const logCleanupProgramLogsEnabled = parseSettingFromMap<boolean>(settingsMap, 'log_cleanup_program_logs_enabled');
  if (typeof logCleanupProgramLogsEnabled === 'boolean') {
    config.logCleanupProgramLogsEnabled = logCleanupProgramLogsEnabled;
  }

  const logCleanupRetentionDays = parseSettingFromMap<number>(settingsMap, 'log_cleanup_retention_days');
  if (typeof logCleanupRetentionDays === 'number' && Number.isFinite(logCleanupRetentionDays) && logCleanupRetentionDays >= 1) {
    config.logCleanupRetentionDays = normalizeLogCleanupRetentionDays(logCleanupRetentionDays);
  }

  const proxySessionChannelConcurrencyLimit = parseSettingFromMap<number>(settingsMap, 'proxy_session_channel_concurrency_limit');
  if (
    typeof proxySessionChannelConcurrencyLimit === 'number'
    && Number.isFinite(proxySessionChannelConcurrencyLimit)
    && proxySessionChannelConcurrencyLimit >= 0
  ) {
    config.proxySessionChannelConcurrencyLimit = Math.trunc(proxySessionChannelConcurrencyLimit);
  }

  const proxySessionChannelQueueWaitMs = parseSettingFromMap<number>(settingsMap, 'proxy_session_channel_queue_wait_ms');
  if (
    typeof proxySessionChannelQueueWaitMs === 'number'
    && Number.isFinite(proxySessionChannelQueueWaitMs)
    && proxySessionChannelQueueWaitMs >= 0
  ) {
    config.proxySessionChannelQueueWaitMs = Math.trunc(proxySessionChannelQueueWaitMs);
  }

  const proxyDebugTraceEnabled = parseSettingFromMap<boolean>(settingsMap, 'proxy_debug_trace_enabled');
  if (typeof proxyDebugTraceEnabled === 'boolean') {
    config.proxyDebugTraceEnabled = proxyDebugTraceEnabled;
  }

  const proxyDebugCaptureHeaders = parseSettingFromMap<boolean>(settingsMap, 'proxy_debug_capture_headers');
  if (typeof proxyDebugCaptureHeaders === 'boolean') {
    config.proxyDebugCaptureHeaders = proxyDebugCaptureHeaders;
  }

  const proxyDebugCaptureBodies = parseSettingFromMap<boolean>(settingsMap, 'proxy_debug_capture_bodies');
  if (typeof proxyDebugCaptureBodies === 'boolean') {
    config.proxyDebugCaptureBodies = proxyDebugCaptureBodies;
  }

  const proxyDebugCaptureStreamChunks = parseSettingFromMap<boolean>(settingsMap, 'proxy_debug_capture_stream_chunks');
  if (typeof proxyDebugCaptureStreamChunks === 'boolean') {
    config.proxyDebugCaptureStreamChunks = proxyDebugCaptureStreamChunks;
  }

  const proxyDebugTargetSessionId = parseSettingFromMap<string>(settingsMap, 'proxy_debug_target_session_id');
  if (typeof proxyDebugTargetSessionId === 'string') {
    config.proxyDebugTargetSessionId = proxyDebugTargetSessionId.trim();
  }

  const proxyDebugTargetClientKind = parseSettingFromMap<string>(settingsMap, 'proxy_debug_target_client_kind');
  if (typeof proxyDebugTargetClientKind === 'string') {
    config.proxyDebugTargetClientKind = proxyDebugTargetClientKind.trim();
  }

  const proxyDebugTargetModel = parseSettingFromMap<string>(settingsMap, 'proxy_debug_target_model');
  if (typeof proxyDebugTargetModel === 'string') {
    config.proxyDebugTargetModel = proxyDebugTargetModel.trim();
  }

  const proxyDebugRetentionHours = parseSettingFromMap<number>(settingsMap, 'proxy_debug_retention_hours');
  if (typeof proxyDebugRetentionHours === 'number' && Number.isFinite(proxyDebugRetentionHours) && proxyDebugRetentionHours >= 1) {
    config.proxyDebugRetentionHours = Math.trunc(proxyDebugRetentionHours);
  }

  const proxyDebugMaxBodyBytes = parseSettingFromMap<number>(settingsMap, 'proxy_debug_max_body_bytes');
  if (typeof proxyDebugMaxBodyBytes === 'number' && Number.isFinite(proxyDebugMaxBodyBytes) && proxyDebugMaxBodyBytes >= 1024) {
    config.proxyDebugMaxBodyBytes = Math.trunc(proxyDebugMaxBodyBytes);
  }

  const routingWeights = parseSettingFromMap<Partial<typeof config.routingWeights>>(settingsMap, 'routing_weights');
  if (routingWeights && typeof routingWeights === 'object') {
    config.routingWeights = {
      ...config.routingWeights,
      ...routingWeights,
    };
  }

  const routingFallbackUnitCost = parseSettingFromMap<number>(settingsMap, 'routing_fallback_unit_cost');
  if (typeof routingFallbackUnitCost === 'number' && Number.isFinite(routingFallbackUnitCost) && routingFallbackUnitCost > 0) {
    config.routingFallbackUnitCost = Math.max(1e-6, routingFallbackUnitCost);
  }

  const proxyFirstByteTimeoutSec = parseSettingFromMap<number>(settingsMap, 'proxy_first_byte_timeout_sec');
  if (typeof proxyFirstByteTimeoutSec === 'number' && Number.isFinite(proxyFirstByteTimeoutSec) && proxyFirstByteTimeoutSec >= 0) {
    config.proxyFirstByteTimeoutSec = Math.max(0, Math.trunc(proxyFirstByteTimeoutSec));
  }

  const tokenRouterFailureCooldownMaxSec = parseSettingFromMap<number>(settingsMap, 'token_router_failure_cooldown_max_sec');
  const normalizedFailureCooldownMaxSec = normalizeTokenRouterFailureCooldownMaxSec(tokenRouterFailureCooldownMaxSec);
  if (normalizedFailureCooldownMaxSec != null) {
    config.tokenRouterFailureCooldownMaxSec = normalizedFailureCooldownMaxSec;
  }

  const webhookUrl = parseSettingFromMap<string>(settingsMap, 'webhook_url');
  if (typeof webhookUrl === 'string') config.webhookUrl = webhookUrl;

  const webhookEnabled = parseSettingFromMap<boolean>(settingsMap, 'webhook_enabled');
  if (typeof webhookEnabled === 'boolean') config.webhookEnabled = webhookEnabled;

  const barkUrl = parseSettingFromMap<string>(settingsMap, 'bark_url');
  if (typeof barkUrl === 'string') config.barkUrl = barkUrl;

  const barkEnabled = parseSettingFromMap<boolean>(settingsMap, 'bark_enabled');
  if (typeof barkEnabled === 'boolean') config.barkEnabled = barkEnabled;

  const serverChanEnabled = parseSettingFromMap<boolean>(settingsMap, 'serverchan_enabled');
  if (typeof serverChanEnabled === 'boolean') config.serverChanEnabled = serverChanEnabled;

  const serverChanKey = parseSettingFromMap<string>(settingsMap, 'serverchan_key');
  if (typeof serverChanKey === 'string') config.serverChanKey = serverChanKey;

  const telegramEnabled = parseSettingFromMap<boolean>(settingsMap, 'telegram_enabled');
  if (typeof telegramEnabled === 'boolean') config.telegramEnabled = telegramEnabled;

  const telegramApiBaseUrl = parseSettingFromMap<string>(settingsMap, 'telegram_api_base_url');
  if (typeof telegramApiBaseUrl === 'string' && telegramApiBaseUrl.trim()) {
    config.telegramApiBaseUrl = telegramApiBaseUrl.trim().replace(/\/+$/, '');
  }

  const telegramBotToken = parseSettingFromMap<string>(settingsMap, 'telegram_bot_token');
  if (typeof telegramBotToken === 'string') config.telegramBotToken = telegramBotToken;

  const telegramChatId = parseSettingFromMap<string>(settingsMap, 'telegram_chat_id');
  if (typeof telegramChatId === 'string') config.telegramChatId = telegramChatId;

  const telegramUseSystemProxy = parseSettingFromMap<boolean>(settingsMap, 'telegram_use_system_proxy');
  if (typeof telegramUseSystemProxy === 'boolean') config.telegramUseSystemProxy = telegramUseSystemProxy;

  const telegramMessageThreadId = parseSettingFromMap<string>(settingsMap, 'telegram_message_thread_id');
  if (typeof telegramMessageThreadId === 'string') config.telegramMessageThreadId = telegramMessageThreadId;

  const smtpEnabled = parseSettingFromMap<boolean>(settingsMap, 'smtp_enabled');
  if (typeof smtpEnabled === 'boolean') config.smtpEnabled = smtpEnabled;

  const smtpHost = parseSettingFromMap<string>(settingsMap, 'smtp_host');
  if (typeof smtpHost === 'string') config.smtpHost = smtpHost;

  const smtpPort = parseSettingFromMap<number>(settingsMap, 'smtp_port');
  if (typeof smtpPort === 'number' && Number.isFinite(smtpPort) && smtpPort > 0) {
    config.smtpPort = Math.trunc(smtpPort);
  }

  const smtpSecure = parseSettingFromMap<boolean>(settingsMap, 'smtp_secure');
  if (typeof smtpSecure === 'boolean') config.smtpSecure = smtpSecure;

  const smtpUser = parseSettingFromMap<string>(settingsMap, 'smtp_user');
  if (typeof smtpUser === 'string') config.smtpUser = smtpUser;

  const smtpPass = parseSettingFromMap<string>(settingsMap, 'smtp_pass');
  if (typeof smtpPass === 'string') config.smtpPass = smtpPass;

  const smtpFrom = parseSettingFromMap<string>(settingsMap, 'smtp_from');
  if (typeof smtpFrom === 'string') config.smtpFrom = smtpFrom;

  const smtpTo = parseSettingFromMap<string>(settingsMap, 'smtp_to');
  if (typeof smtpTo === 'string') config.smtpTo = smtpTo;

  const notifyCooldownSec = parseSettingFromMap<number>(settingsMap, 'notify_cooldown_sec');
  if (typeof notifyCooldownSec === 'number' && Number.isFinite(notifyCooldownSec) && notifyCooldownSec >= 0) {
    config.notifyCooldownSec = Math.trunc(notifyCooldownSec);
  }

  const adminIpAllowlist = parseSettingFromMap<string[] | string>(settingsMap, 'admin_ip_allowlist');
  if (adminIpAllowlist !== undefined) {
    config.adminIpAllowlist = toStringList(adminIpAllowlist);
  }
}
