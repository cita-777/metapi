import { FastifyInstance } from 'fastify';
import cron from 'node-cron';
import { fetch } from 'undici';
import { config } from '../../config.js';
import { db, runtimeDbDialect, schema } from '../../db/index.js';
import { upsertSetting } from '../../db/upsertSetting.js';
import * as routeRefreshWorkflow from '../../services/routeRefreshWorkflow.js';
import { getAllBrandNames } from '../../services/brandMatcher.js';
import { updateBalanceRefreshCron, updateCheckinSchedule, updateLogCleanupSettings } from '../../services/checkinScheduler.js';
import { sendNotification } from '../../services/notifyService.js';
import {
  exportBackup,
  exportBackupToWebdav,
  getBackupWebdavConfig,
  importBackup,
  importBackupFromWebdav,
  reloadBackupWebdavScheduler,
  saveBackupWebdavConfig,
  type BackupExportType,
} from '../../services/backupService.js';
import { startBackgroundTask } from '../../services/backgroundTaskService.js';
import {
  maskConnectionString,
  migrateCurrentDatabase,
  normalizeMigrationInput,
  testDatabaseConnection,
  type MigrationDialect,
} from '../../services/databaseMigrationService.js';
import { formatUtcSqlDateTime, getResolvedTimeZone } from '../../services/localTimeService.js';
import { extractClientIp, isIpAllowed } from '../../middleware/auth.js';
import { invalidateSiteProxyCache, normalizeSiteProxyUrl, withExplicitProxyRequestInit } from '../../services/siteProxy.js';
import { performFactoryReset } from '../../services/factoryResetService.js';
import { normalizeLogCleanupRetentionDays } from '../../services/logCleanupService.js';
import { stopProxyLogRetentionService } from '../../services/proxyLogRetentionService.js';

type RoutingWeights = typeof config.routingWeights;

interface RuntimeSettingsBody {
  proxyToken?: string;
  systemProxyUrl?: string;
  codexUpstreamWebsocketEnabled?: boolean;
  proxySessionChannelConcurrencyLimit?: number;
  proxySessionChannelQueueWaitMs?: number;
  proxyDebugTraceEnabled?: boolean;
  proxyDebugCaptureHeaders?: boolean;
  proxyDebugCaptureBodies?: boolean;
  proxyDebugCaptureStreamChunks?: boolean;
  proxyDebugTargetSessionId?: string;
  proxyDebugTargetClientKind?: string;
  proxyDebugTargetModel?: string;
  proxyDebugRetentionHours?: number;
  proxyDebugMaxBodyBytes?: number;
  checkinCron?: string;
  checkinScheduleMode?: 'cron' | 'interval';
  checkinIntervalHours?: number;
  balanceRefreshCron?: string;
  logCleanupCron?: string;
  logCleanupUsageLogsEnabled?: boolean;
  logCleanupProgramLogsEnabled?: boolean;
  logCleanupRetentionDays?: number;
  webhookUrl?: string;
  barkUrl?: string;
  webhookEnabled?: boolean;
  barkEnabled?: boolean;
  serverChanEnabled?: boolean;
  serverChanKey?: string;
  telegramEnabled?: boolean;
  telegramApiBaseUrl?: string;
  telegramBotToken?: string;
  telegramChatId?: string;
  telegramUseSystemProxy?: boolean;
  telegramMessageThreadId?: string;
  smtpEnabled?: boolean;
  smtpHost?: string;
  smtpPort?: number;
  smtpSecure?: boolean;
  smtpUser?: string;
  smtpPass?: string;
  smtpFrom?: string;
  smtpTo?: string;
  notifyCooldownSec?: number;
  adminIpAllowlist?: string[] | string;
  routingFallbackUnitCost?: number;
  routingWeights?: Partial<RoutingWeights>;
  proxyErrorKeywords?: string[] | string;
  proxyEmptyContentFailEnabled?: boolean;
  globalBlockedBrands?: string[];
}

interface DatabaseMigrationBody {
  dialect?: unknown;
  connectionString?: unknown;
  overwrite?: unknown;
  ssl?: unknown;
}

interface SystemProxyTestBody {
  proxyUrl?: unknown;
}

interface BackupWebdavConfigBody {
  enabled?: unknown;
  fileUrl?: unknown;
  username?: unknown;
  password?: unknown;
  clearPassword?: unknown;
  exportType?: unknown;
  autoSyncEnabled?: unknown;
  autoSyncCron?: unknown;
}

type RuntimeDatabaseConfig = {
  dialect: MigrationDialect;
  connectionString: string;
  ssl: boolean;
};

const PROXY_TOKEN_PREFIX = 'sk-';
const DB_TYPE_SETTING_KEY = 'db_type';
const DB_URL_SETTING_KEY = 'db_url';
const DB_SSL_SETTING_KEY = 'db_ssl';
const SYSTEM_PROXY_TEST_PROBE_URL = 'https://www.gstatic.com/generate_204';
const SYSTEM_PROXY_TEST_TIMEOUT_MS = 15_000;

function isValidProxyToken(value: string): boolean {
  return value.startsWith(PROXY_TOKEN_PREFIX) && value.length >= 6;
}

function maskSecret(value: string): string {
  if (!value) return '';
  if (value.length <= 8) return '****';
  return `${value.slice(0, 4)}****${value.slice(-4)}`;
}



async function appendSettingsEvent(input: {
  type: 'checkin' | 'balance' | 'proxy' | 'status' | 'token';
  title: string;
  message: string;
  level?: 'info' | 'warning' | 'error';
}) {
  try {
    const createdAt = formatUtcSqlDateTime(new Date());
    await db.insert(schema.events).values({
      type: input.type,
      title: input.title,
      message: input.message,
      level: input.level || 'info',
      relatedType: 'settings',
      createdAt,
    }).run();
  } catch { }
}

function toPositiveNumberOrFallback(value: unknown, fallback: number) {
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0) return fallback;
  return n;
}

function extractNestedErrorMessages(error: unknown): string[] {
  const messages: string[] = [];
  const visited = new Set<unknown>();
  let current: any = error;

  while (current && !visited.has(current)) {
    visited.add(current);
    const message = typeof current?.message === 'string' ? current.message.trim() : '';
    if (message) {
      messages.push(message);
    }
    current = current?.cause;
  }

  return messages;
}

function describeSystemProxyTestFailure(error: unknown): string {
  const messages = extractNestedErrorMessages(error);
  const detail = messages.find((message) => message && message !== 'fetch failed')
    || messages[0]
    || '未知错误';

  if (/ECONNREFUSED/i.test(detail)) {
    return '系统代理测试失败：连接被拒绝，请检查代理地址、端口和本地代理程序是否已启动';
  }

  if (/ETIMEDOUT|timed out|timeout/i.test(detail)) {
    return '系统代理测试失败：连接超时，请检查代理服务或当前网络是否可用';
  }

  if (/ENOTFOUND|EAI_AGAIN/i.test(detail)) {
    return '系统代理测试失败：域名解析失败，请检查网络或代理的 DNS 配置';
  }

  if (/ECONNRESET/i.test(detail)) {
    return '系统代理测试失败：连接被对端重置，请检查代理链路是否稳定';
  }

  if (/407/.test(detail) || /proxy authentication/i.test(detail)) {
    return '系统代理测试失败：代理要求认证，请检查用户名、密码或代理配置';
  }

  return `系统代理测试失败：${detail}`;
}

async function testSystemProxyConnectivity(proxyUrl: string) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), SYSTEM_PROXY_TEST_TIMEOUT_MS);
  const startedAt = Date.now();

  try {
    const response = await fetch(
      SYSTEM_PROXY_TEST_PROBE_URL,
      withExplicitProxyRequestInit(proxyUrl, {
        method: 'GET',
        signal: controller.signal,
        headers: {
          'cache-control': 'no-cache',
          'user-agent': 'metapi-system-proxy-tester/1.0',
        },
      }),
    );

    try {
      await response.arrayBuffer();
    } catch {
      // Ignore body drain failures; reachability is determined by receiving a response.
    }

    return {
      reachable: true,
      ok: response.ok,
      statusCode: response.status,
      latencyMs: Math.max(1, Date.now() - startedAt),
      probeUrl: SYSTEM_PROXY_TEST_PROBE_URL,
      finalUrl: response.url || SYSTEM_PROXY_TEST_PROBE_URL,
    };
  } catch (error: any) {
    if (error?.name === 'AbortError') {
      throw new Error(`系统代理测试超时（${Math.round(SYSTEM_PROXY_TEST_TIMEOUT_MS / 1000)}s）`);
    }
    throw new Error(describeSystemProxyTestFailure(error));
  } finally {
    clearTimeout(timeout);
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

function parseProxyErrorKeywords(value: unknown): string[] {
  const splitKeywords = (input: string): string[] => input
    .split(/\r?\n|,/)
    .map((item) => item.trim())
    .filter((item) => item.length > 0);

  if (Array.isArray(value)) {
    const keywords = value.flatMap((item) => {
      if (typeof item !== 'string') return [];
      return splitKeywords(item);
    });
    return keywords;
  }

  if (typeof value === 'string') {
    const keywords = splitKeywords(value);
    return keywords;
  }

  throw new Error('上游错误关键词格式无效：需要 string 或 string[]');
}

function parseBooleanFlag(value: unknown, label: string): boolean {
  if (typeof value === 'boolean') return value;
  throw new Error(`${label}格式无效：需要 boolean`);
}

function isValidHttpUrl(raw: string): boolean {
  const value = String(raw || '').trim();
  if (!value) return false;
  try {
    const parsed = new URL(value);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

function normalizeTelegramApiBaseUrl(raw: string): string {
  return String(raw || '').trim().replace(/\/+$/, '');
}

function normalizeTelegramMessageThreadId(raw: unknown): string {
  return String(raw || '').trim();
}

function isValidTelegramMessageThreadId(raw: string): boolean {
  return /^[1-9]\d*$/.test(raw);
}

function applyImportedSettingToRuntime(key: string, value: unknown) {
  switch (key) {
    case 'checkin_cron': {
      if (typeof value !== 'string' || !value || !cron.validate(value)) return;
      config.checkinCron = value;
      updateCheckinSchedule({
        mode: config.checkinScheduleMode,
        cronExpr: config.checkinCron,
        intervalHours: config.checkinIntervalHours,
      });
      return;
    }
    case 'checkin_schedule_mode': {
      if (value !== 'cron' && value !== 'interval') return;
      const nextMode: 'cron' | 'interval' = value;
      config.checkinScheduleMode = nextMode;
      updateCheckinSchedule({
        mode: config.checkinScheduleMode,
        cronExpr: config.checkinCron,
        intervalHours: config.checkinIntervalHours,
      });
      return;
    }
    case 'checkin_interval_hours': {
      const intervalHours = Number(value);
      if (!Number.isFinite(intervalHours) || intervalHours < 1 || intervalHours > 24) return;
      config.checkinIntervalHours = Math.trunc(intervalHours);
      updateCheckinSchedule({
        mode: config.checkinScheduleMode,
        cronExpr: config.checkinCron,
        intervalHours: config.checkinIntervalHours,
      });
      return;
    }
    case 'balance_refresh_cron': {
      if (typeof value !== 'string' || !value || !cron.validate(value)) return;
      config.balanceRefreshCron = value;
      updateBalanceRefreshCron(value);
      return;
    }
    case 'log_cleanup_cron': {
      if (typeof value !== 'string' || !value || !cron.validate(value)) return;
      config.logCleanupConfigured = true;
      updateLogCleanupSettings({ cronExpr: value });
      stopProxyLogRetentionService();
      return;
    }
    case 'log_cleanup_usage_logs_enabled': {
      if (typeof value !== 'boolean') return;
      config.logCleanupConfigured = true;
      updateLogCleanupSettings({ usageLogsEnabled: value });
      stopProxyLogRetentionService();
      return;
    }
    case 'log_cleanup_program_logs_enabled': {
      if (typeof value !== 'boolean') return;
      config.logCleanupConfigured = true;
      updateLogCleanupSettings({ programLogsEnabled: value });
      stopProxyLogRetentionService();
      return;
    }
    case 'log_cleanup_retention_days': {
      const retentionDays = Number(value);
      if (!Number.isFinite(retentionDays) || retentionDays < 1) return;
      config.logCleanupConfigured = true;
      updateLogCleanupSettings({ retentionDays: Math.trunc(retentionDays) });
      stopProxyLogRetentionService();
      return;
    }
    case 'proxy_token': {
      if (typeof value !== 'string') return;
      const nextToken = value.trim();
      if (!isValidProxyToken(nextToken)) return;
      config.proxyToken = nextToken;
      return;
    }
    case 'system_proxy_url': {
      if (typeof value !== 'string') return;
      config.systemProxyUrl = normalizeSiteProxyUrl(value) || '';
      return;
    }
    case 'codex_upstream_websocket_enabled': {
      if (typeof value !== 'boolean') return;
      config.codexUpstreamWebsocketEnabled = value;
      return;
    }
    case 'proxy_error_keywords': {
      try {
        config.proxyErrorKeywords = parseProxyErrorKeywords(value);
      } catch {
        return;
      }
      return;
    }
    case 'proxy_session_channel_concurrency_limit': {
      const limit = Number(value);
      if (!Number.isFinite(limit) || limit < 0) return;
      config.proxySessionChannelConcurrencyLimit = Math.trunc(limit);
      return;
    }
    case 'proxy_session_channel_queue_wait_ms': {
      const queueWaitMs = Number(value);
      if (!Number.isFinite(queueWaitMs) || queueWaitMs < 0) return;
      config.proxySessionChannelQueueWaitMs = Math.trunc(queueWaitMs);
      return;
    }
    case 'proxy_debug_trace_enabled': {
      try {
        config.proxyDebugTraceEnabled = parseBooleanFlag(value, '代理调试追踪开关');
      } catch {
        return;
      }
      return;
    }
    case 'proxy_debug_capture_headers': {
      try {
        config.proxyDebugCaptureHeaders = parseBooleanFlag(value, '代理调试请求头采集');
      } catch {
        return;
      }
      return;
    }
    case 'proxy_debug_capture_bodies': {
      try {
        config.proxyDebugCaptureBodies = parseBooleanFlag(value, '代理调试请求体采集');
      } catch {
        return;
      }
      return;
    }
    case 'proxy_debug_capture_stream_chunks': {
      try {
        config.proxyDebugCaptureStreamChunks = parseBooleanFlag(value, '代理调试流式分片采集');
      } catch {
        return;
      }
      return;
    }
    case 'proxy_debug_target_session_id': {
      config.proxyDebugTargetSessionId = typeof value === 'string' ? value.trim() : '';
      return;
    }
    case 'proxy_debug_target_client_kind': {
      config.proxyDebugTargetClientKind = typeof value === 'string' ? value.trim() : '';
      return;
    }
    case 'proxy_debug_target_model': {
      config.proxyDebugTargetModel = typeof value === 'string' ? value.trim() : '';
      return;
    }
    case 'proxy_debug_retention_hours': {
      const retentionHours = Number(value);
      if (!Number.isFinite(retentionHours) || retentionHours < 1) return;
      config.proxyDebugRetentionHours = Math.trunc(retentionHours);
      return;
    }
    case 'proxy_debug_max_body_bytes': {
      const maxBodyBytes = Number(value);
      if (!Number.isFinite(maxBodyBytes) || maxBodyBytes < 1024) return;
      config.proxyDebugMaxBodyBytes = Math.trunc(maxBodyBytes);
      return;
    }
    case 'proxy_empty_content_fail_enabled': {
      try {
        config.proxyEmptyContentFailEnabled = parseBooleanFlag(value, '空内容判定失败开关');
      } catch {
        return;
      }
      return;
    }
    case 'global_blocked_brands': {
      try {
        const parsed = typeof value === 'string' ? JSON.parse(value) : value;
        if (Array.isArray(parsed)) {
          const nextBrands = parsed.filter((b): b is string => typeof b === 'string').map((b) => b.trim()).filter(Boolean);
          const prev = JSON.stringify(config.globalBlockedBrands);
          config.globalBlockedBrands = nextBrands;
          if (prev !== JSON.stringify(nextBrands)) {
            startBackgroundTask(
              {
                type: 'maintenance',
                title: '品牌屏蔽变更后重建路由',
                dedupeKey: 'refresh-models-and-rebuild-routes',
              },
              async () => routeRefreshWorkflow.refreshModelsAndRebuildRoutes(),
            );
          }
        }
      } catch {
        return;
      }
      return;
    }
    case 'webhook_url': {
      if (typeof value !== 'string') return;
      config.webhookUrl = value.trim();
      return;
    }
    case 'webhook_enabled': {
      config.webhookEnabled = !!value;
      return;
    }
    case 'bark_url': {
      if (typeof value !== 'string') return;
      config.barkUrl = value.trim();
      return;
    }
    case 'bark_enabled': {
      config.barkEnabled = !!value;
      return;
    }
    case 'serverchan_enabled': {
      config.serverChanEnabled = !!value;
      return;
    }
    case 'serverchan_key': {
      if (typeof value !== 'string') return;
      config.serverChanKey = value.trim();
      return;
    }
    case 'telegram_enabled': {
      config.telegramEnabled = !!value;
      return;
    }
    case 'telegram_api_base_url': {
      if (typeof value !== 'string') return;
      config.telegramApiBaseUrl = normalizeTelegramApiBaseUrl(value) || 'https://api.telegram.org';
      return;
    }
    case 'telegram_bot_token': {
      if (typeof value !== 'string') return;
      config.telegramBotToken = value.trim();
      return;
    }
    case 'telegram_chat_id': {
      if (typeof value !== 'string') return;
      config.telegramChatId = value.trim();
      return;
    }
    case 'telegram_use_system_proxy': {
      config.telegramUseSystemProxy = !!value;
      return;
    }
    case 'telegram_message_thread_id': {
      if (typeof value !== 'string') return;
      config.telegramMessageThreadId = value.trim();
      return;
    }
    case 'smtp_enabled': {
      config.smtpEnabled = !!value;
      return;
    }
    case 'smtp_host': {
      if (typeof value !== 'string') return;
      config.smtpHost = value.trim();
      return;
    }
    case 'smtp_port': {
      const n = Number(value);
      if (!Number.isFinite(n) || n <= 0) return;
      config.smtpPort = Math.trunc(n);
      return;
    }
    case 'smtp_secure': {
      config.smtpSecure = !!value;
      return;
    }
    case 'smtp_user': {
      if (typeof value !== 'string') return;
      config.smtpUser = value.trim();
      return;
    }
    case 'smtp_pass': {
      if (typeof value !== 'string') return;
      config.smtpPass = value.trim();
      return;
    }
    case 'smtp_from': {
      if (typeof value !== 'string') return;
      config.smtpFrom = value.trim();
      return;
    }
    case 'smtp_to': {
      if (typeof value !== 'string') return;
      config.smtpTo = value.trim();
      return;
    }
    case 'notify_cooldown_sec': {
      const n = Number(value);
      if (!Number.isFinite(n) || n < 0) return;
      config.notifyCooldownSec = Math.trunc(n);
      return;
    }
    case 'admin_ip_allowlist': {
      config.adminIpAllowlist = toStringList(value);
      return;
    }
    case 'routing_weights': {
      if (!value || typeof value !== 'object') return;
      const rw = value as Partial<RoutingWeights>;
      config.routingWeights = {
        baseWeightFactor: toPositiveNumberOrFallback(rw.baseWeightFactor, config.routingWeights.baseWeightFactor),
        valueScoreFactor: toPositiveNumberOrFallback(rw.valueScoreFactor, config.routingWeights.valueScoreFactor),
        costWeight: toPositiveNumberOrFallback(rw.costWeight, config.routingWeights.costWeight),
        balanceWeight: toPositiveNumberOrFallback(rw.balanceWeight, config.routingWeights.balanceWeight),
        usageWeight: toPositiveNumberOrFallback(rw.usageWeight, config.routingWeights.usageWeight),
      };
      return;
    }
    case 'routing_fallback_unit_cost': {
      const n = Number(value);
      if (!Number.isFinite(n) || n <= 0) return;
      config.routingFallbackUnitCost = Math.max(1e-6, n);
      return;
    }
    default:
      return;
  }
}

function getRuntimeSettingsResponse(currentAdminIp = '') {
  return {
    checkinCron: config.checkinCron,
    checkinScheduleMode: config.checkinScheduleMode,
    checkinIntervalHours: config.checkinIntervalHours,
    balanceRefreshCron: config.balanceRefreshCron,
    logCleanupCron: config.logCleanupCron,
    logCleanupUsageLogsEnabled: config.logCleanupUsageLogsEnabled,
    logCleanupProgramLogsEnabled: config.logCleanupProgramLogsEnabled,
    logCleanupRetentionDays: config.logCleanupRetentionDays,
    codexUpstreamWebsocketEnabled: config.codexUpstreamWebsocketEnabled,
    proxySessionChannelConcurrencyLimit: config.proxySessionChannelConcurrencyLimit,
    proxySessionChannelQueueWaitMs: config.proxySessionChannelQueueWaitMs,
    proxyDebugTraceEnabled: config.proxyDebugTraceEnabled,
    proxyDebugCaptureHeaders: config.proxyDebugCaptureHeaders,
    proxyDebugCaptureBodies: config.proxyDebugCaptureBodies,
    proxyDebugCaptureStreamChunks: config.proxyDebugCaptureStreamChunks,
    proxyDebugTargetSessionId: config.proxyDebugTargetSessionId,
    proxyDebugTargetClientKind: config.proxyDebugTargetClientKind,
    proxyDebugTargetModel: config.proxyDebugTargetModel,
    proxyDebugRetentionHours: config.proxyDebugRetentionHours,
    proxyDebugMaxBodyBytes: config.proxyDebugMaxBodyBytes,
    routingFallbackUnitCost: config.routingFallbackUnitCost,
    routingWeights: config.routingWeights,
    webhookUrl: config.webhookUrl,
    barkUrl: config.barkUrl,
    webhookEnabled: config.webhookEnabled,
    barkEnabled: config.barkEnabled,
    serverChanEnabled: config.serverChanEnabled,
    serverChanKeyMasked: maskSecret(config.serverChanKey),
    telegramEnabled: config.telegramEnabled,
    telegramApiBaseUrl: config.telegramApiBaseUrl,
    telegramBotTokenMasked: maskSecret(config.telegramBotToken),
    telegramChatId: config.telegramChatId,
    telegramUseSystemProxy: config.telegramUseSystemProxy,
    telegramMessageThreadId: config.telegramMessageThreadId,
    smtpEnabled: config.smtpEnabled,
    smtpHost: config.smtpHost,
    smtpPort: config.smtpPort,
    smtpSecure: config.smtpSecure,
    smtpUser: config.smtpUser,
    smtpPassMasked: maskSecret(config.smtpPass),
    smtpFrom: config.smtpFrom,
    smtpTo: config.smtpTo,
    notifyCooldownSec: config.notifyCooldownSec,
    adminIpAllowlist: config.adminIpAllowlist,
    currentAdminIp,
    serverTimeZone: getResolvedTimeZone(),
    systemProxyUrl: config.systemProxyUrl,
    proxyErrorKeywords: config.proxyErrorKeywords,
    proxyEmptyContentFailEnabled: config.proxyEmptyContentFailEnabled,
    proxyTokenMasked: maskSecret(config.proxyToken),
    globalBlockedBrands: config.globalBlockedBrands,
  };
}

function parseJsonValue(raw: unknown): unknown {
  if (typeof raw !== 'string' || !raw) return undefined;
  try {
    return JSON.parse(raw);
  } catch {
    return undefined;
  }
}

function maskRuntimeConnection(dialect: MigrationDialect, connectionString: string): string {
  const normalized = connectionString.trim();
  if (dialect === 'sqlite' && !normalized) return '(default sqlite path)';
  return maskConnectionString(normalized);
}

async function loadSavedRuntimeDatabaseConfig(): Promise<RuntimeDatabaseConfig | null> {
  const settingsRows = await db.select().from(schema.settings).all();
  const map = new Map(settingsRows.map((row) => [row.key, row.value]));
  const rawDialect = parseJsonValue(map.get(DB_TYPE_SETTING_KEY));
  const rawConnection = parseJsonValue(map.get(DB_URL_SETTING_KEY));
  const rawSsl = parseJsonValue(map.get(DB_SSL_SETTING_KEY));
  if (typeof rawDialect !== 'string' || typeof rawConnection !== 'string') {
    return null;
  }

  try {
    const normalized = normalizeMigrationInput({
      dialect: rawDialect,
      connectionString: rawConnection,
      ssl: rawSsl,
    });
    return {
      dialect: normalized.dialect,
      connectionString: normalized.connectionString,
      ssl: normalized.ssl,
    };
  } catch {
    return null;
  }
}

function buildRuntimeDatabaseState(saved: RuntimeDatabaseConfig | null) {
  const activeDialect = runtimeDbDialect;
  const activeConnection = (config.dbUrl || '').trim();
  const activeSsl = config.dbSsl;
  const restartRequired = !!saved && (
    saved.dialect !== activeDialect ||
    saved.connectionString.trim() !== activeConnection ||
    saved.ssl !== activeSsl
  );

  return {
    active: {
      dialect: activeDialect,
      connection: maskRuntimeConnection(activeDialect, activeConnection),
      ssl: activeSsl,
    },
    saved: saved
      ? {
        dialect: saved.dialect,
        connection: maskRuntimeConnection(saved.dialect, saved.connectionString),
        ssl: saved.ssl,
      }
      : null,
    restartRequired,
  };
}

export async function settingsRoutes(app: FastifyInstance) {
  await app.get('/api/settings/runtime', async (request) => {
    const currentAdminIp = extractClientIp(request.ip, request.headers['x-forwarded-for']);
    return getRuntimeSettingsResponse(currentAdminIp);
  });

  app.get('/api/settings/brand-list', async () => {
    return { brands: getAllBrandNames() };
  });

  app.post<{ Body: SystemProxyTestBody }>('/api/settings/system-proxy/test', async (request, reply) => {
    const rawProxyUrl = request.body?.proxyUrl === undefined
      ? config.systemProxyUrl
      : String(request.body.proxyUrl || '').trim();
    const normalizedProxyUrl = rawProxyUrl
      ? normalizeSiteProxyUrl(rawProxyUrl)
      : '';

    if (!rawProxyUrl) {
      return reply.code(400).send({
        success: false,
        message: '请先填写系统代理地址',
      });
    }

    if (!normalizedProxyUrl) {
      return reply.code(400).send({
        success: false,
        message: '系统代理地址无效，请填写合法的 http(s)/socks 代理 URL',
      });
    }

    try {
      const result = await testSystemProxyConnectivity(normalizedProxyUrl);
      return {
        success: true,
        proxyUrl: normalizedProxyUrl,
        ...result,
      };
    } catch (error: any) {
      return reply.code(502).send({
        success: false,
        message: error?.message || '系统代理测试失败',
      });
    }
  });

  app.put<{ Body: RuntimeSettingsBody }>('/api/settings/runtime', async (request, reply) => {
    const body = request.body || {};
    const changedLabels: string[] = [];
    const currentRequestIp = extractClientIp(request.ip, request.headers['x-forwarded-for']);

    const webhookTouched = body.webhookUrl !== undefined || body.webhookEnabled !== undefined;
    const nextWebhookUrl = body.webhookUrl !== undefined
      ? String(body.webhookUrl || '').trim()
      : config.webhookUrl;
    const nextWebhookEnabled = body.webhookEnabled !== undefined
      ? !!body.webhookEnabled
      : config.webhookEnabled;
    if (webhookTouched && nextWebhookEnabled) {
      if (!nextWebhookUrl) {
        return reply.code(400).send({ success: false, message: 'Webhook URL 不能为空（启用 Webhook 时）' });
      }
      if (!isValidHttpUrl(nextWebhookUrl)) {
        return reply.code(400).send({ success: false, message: 'Webhook URL 无效，请填写 http/https 地址' });
      }
    }

    const barkTouched = body.barkUrl !== undefined || body.barkEnabled !== undefined;
    const nextBarkUrl = body.barkUrl !== undefined
      ? String(body.barkUrl || '').trim()
      : config.barkUrl;
    const nextBarkEnabled = body.barkEnabled !== undefined
      ? !!body.barkEnabled
      : config.barkEnabled;
    if (barkTouched && nextBarkEnabled) {
      if (!nextBarkUrl) {
        return reply.code(400).send({ success: false, message: 'Bark URL 不能为空（启用 Bark 时）' });
      }
      if (!isValidHttpUrl(nextBarkUrl)) {
        return reply.code(400).send({ success: false, message: 'Bark URL 无效，请填写 http/https 地址' });
      }
    }

    const telegramTouched = body.telegramEnabled !== undefined
      || body.telegramApiBaseUrl !== undefined
      || body.telegramBotToken !== undefined
      || body.telegramChatId !== undefined
      || body.telegramUseSystemProxy !== undefined
      || body.telegramMessageThreadId !== undefined;
    const nextTelegramEnabled = body.telegramEnabled !== undefined
      ? !!body.telegramEnabled
      : config.telegramEnabled;
    const nextTelegramApiBaseUrl = body.telegramApiBaseUrl !== undefined
      ? normalizeTelegramApiBaseUrl(body.telegramApiBaseUrl)
      : config.telegramApiBaseUrl;
    const nextTelegramBotToken = body.telegramBotToken !== undefined
      ? String(body.telegramBotToken || '').trim()
      : config.telegramBotToken;
    const nextTelegramChatId = body.telegramChatId !== undefined
      ? String(body.telegramChatId || '').trim()
      : config.telegramChatId;
    const nextTelegramMessageThreadId = body.telegramMessageThreadId !== undefined
      ? normalizeTelegramMessageThreadId(body.telegramMessageThreadId)
      : config.telegramMessageThreadId;
    if (telegramTouched && nextTelegramEnabled) {
      if (!nextTelegramBotToken) {
        return reply.code(400).send({ success: false, message: 'Telegram Bot Token 不能为空（启用 Telegram 时）' });
      }
      if (!nextTelegramBotToken.includes(':')) {
        return reply.code(400).send({ success: false, message: 'Telegram Bot Token 格式无效（示例：123456:abcDEF）' });
      }
      if (!nextTelegramChatId) {
        return reply.code(400).send({ success: false, message: 'Telegram Chat ID 不能为空（启用 Telegram 时）' });
      }
      if (nextTelegramMessageThreadId && !isValidTelegramMessageThreadId(nextTelegramMessageThreadId)) {
        return reply.code(400).send({ success: false, message: 'Telegram Topic ID 格式无效，需要正整数' });
      }
      if (nextTelegramApiBaseUrl && !isValidHttpUrl(nextTelegramApiBaseUrl)) {
        return reply.code(400).send({ success: false, message: 'Telegram API Base URL 无效，请填写 http/https 地址' });
      }
    } else if (body.telegramApiBaseUrl !== undefined && nextTelegramApiBaseUrl && !isValidHttpUrl(nextTelegramApiBaseUrl)) {
      return reply.code(400).send({ success: false, message: 'Telegram API Base URL 无效，请填写 http/https 地址' });
    } else if (body.telegramMessageThreadId !== undefined && nextTelegramMessageThreadId && !isValidTelegramMessageThreadId(nextTelegramMessageThreadId)) {
      return reply.code(400).send({ success: false, message: 'Telegram Topic ID 格式无效，需要正整数' });
    }

    const checkinScheduleTouched = body.checkinCron !== undefined
      || body.checkinScheduleMode !== undefined
      || body.checkinIntervalHours !== undefined;

    if (body.checkinCron !== undefined) {
      if (!cron.validate(body.checkinCron)) {
        return reply.code(400).send({ success: false, message: '签到 Cron 表达式无效' });
      }
      if (body.checkinCron !== config.checkinCron) {
        changedLabels.push(`签到 Cron（${config.checkinCron} -> ${body.checkinCron}）`);
      }
    }

    if (body.checkinScheduleMode !== undefined) {
      if (body.checkinScheduleMode !== 'cron' && body.checkinScheduleMode !== 'interval') {
        return reply.code(400).send({ success: false, message: '签到方式无效：仅支持 cron 或 interval' });
      }
      if (body.checkinScheduleMode !== config.checkinScheduleMode) {
        changedLabels.push('签到方式');
      }
      config.checkinScheduleMode = body.checkinScheduleMode;
    }

    if (body.checkinIntervalHours !== undefined) {
      const intervalHours = Number(body.checkinIntervalHours);
      if (!Number.isFinite(intervalHours) || intervalHours < 1 || intervalHours > 24) {
        return reply.code(400).send({ success: false, message: '签到间隔必须是 1 到 24 的整数小时' });
      }
      const nextIntervalHours = Math.trunc(intervalHours);
      if (nextIntervalHours !== config.checkinIntervalHours) {
        changedLabels.push(`签到间隔（${config.checkinIntervalHours}h -> ${nextIntervalHours}h）`);
      }
      config.checkinIntervalHours = nextIntervalHours;
    }

    if (checkinScheduleTouched) {
      const nextCheckinCron = body.checkinCron !== undefined ? body.checkinCron : config.checkinCron;
      const nextCheckinScheduleMode: 'cron' | 'interval' = body.checkinScheduleMode !== undefined
        ? body.checkinScheduleMode
        : config.checkinScheduleMode;
      const nextCheckinIntervalHours = body.checkinIntervalHours !== undefined
        ? Math.trunc(Number(body.checkinIntervalHours))
        : config.checkinIntervalHours;

      updateCheckinSchedule({
        mode: nextCheckinScheduleMode,
        cronExpr: nextCheckinCron,
        intervalHours: nextCheckinIntervalHours,
      });
      config.checkinCron = nextCheckinCron;
      config.checkinScheduleMode = nextCheckinScheduleMode;
      config.checkinIntervalHours = nextCheckinIntervalHours;
      upsertSetting('checkin_cron', config.checkinCron);
      upsertSetting('checkin_schedule_mode', config.checkinScheduleMode);
      upsertSetting('checkin_interval_hours', config.checkinIntervalHours);
    }

    if (body.balanceRefreshCron !== undefined) {
      if (!cron.validate(body.balanceRefreshCron)) {
        return reply.code(400).send({ success: false, message: '余额刷新 Cron 表达式无效' });
      }
      if (body.balanceRefreshCron !== config.balanceRefreshCron) {
        changedLabels.push(`余额刷新 Cron（${config.balanceRefreshCron} -> ${body.balanceRefreshCron}）`);
      }
      updateBalanceRefreshCron(body.balanceRefreshCron);
      upsertSetting('balance_refresh_cron', body.balanceRefreshCron);
    }

    const logCleanupTouched =
      body.logCleanupCron !== undefined
      || body.logCleanupUsageLogsEnabled !== undefined
      || body.logCleanupProgramLogsEnabled !== undefined
      || body.logCleanupRetentionDays !== undefined;

    if (logCleanupTouched) {
      const nextLogCleanupCron = body.logCleanupCron !== undefined
        ? String(body.logCleanupCron || '').trim()
        : config.logCleanupCron;
      if (!cron.validate(nextLogCleanupCron)) {
        return reply.code(400).send({ success: false, message: '日志清理 Cron 表达式无效' });
      }

      const rawRetentionDays = body.logCleanupRetentionDays !== undefined
        ? Number(body.logCleanupRetentionDays)
        : config.logCleanupRetentionDays;
      if (!Number.isFinite(rawRetentionDays) || rawRetentionDays < 1) {
        return reply.code(400).send({ success: false, message: '日志清理保留天数必须是大于等于 1 的整数' });
      }
      const nextLogCleanupRetentionDays = normalizeLogCleanupRetentionDays(rawRetentionDays);
      const nextUsageLogsEnabled = body.logCleanupUsageLogsEnabled !== undefined
        ? !!body.logCleanupUsageLogsEnabled
        : config.logCleanupUsageLogsEnabled;
      const nextProgramLogsEnabled = body.logCleanupProgramLogsEnabled !== undefined
        ? !!body.logCleanupProgramLogsEnabled
        : config.logCleanupProgramLogsEnabled;

      if (nextLogCleanupCron !== config.logCleanupCron) {
        changedLabels.push(`日志清理 Cron（${config.logCleanupCron} -> ${nextLogCleanupCron}）`);
      }
      if (nextUsageLogsEnabled !== config.logCleanupUsageLogsEnabled) {
        changedLabels.push(`自动清理使用日志（${config.logCleanupUsageLogsEnabled ? '开启' : '关闭'} -> ${nextUsageLogsEnabled ? '开启' : '关闭'}）`);
      }
      if (nextProgramLogsEnabled !== config.logCleanupProgramLogsEnabled) {
        changedLabels.push(`自动清理程序日志（${config.logCleanupProgramLogsEnabled ? '开启' : '关闭'} -> ${nextProgramLogsEnabled ? '开启' : '关闭'}）`);
      }
      if (nextLogCleanupRetentionDays !== config.logCleanupRetentionDays) {
        changedLabels.push(`日志清理保留天数（${config.logCleanupRetentionDays} -> ${nextLogCleanupRetentionDays}）`);
      }

      config.logCleanupConfigured = true;
      updateLogCleanupSettings({
        cronExpr: nextLogCleanupCron,
        usageLogsEnabled: nextUsageLogsEnabled,
        programLogsEnabled: nextProgramLogsEnabled,
        retentionDays: nextLogCleanupRetentionDays,
      });
      stopProxyLogRetentionService();
      upsertSetting('log_cleanup_cron', nextLogCleanupCron);
      upsertSetting('log_cleanup_usage_logs_enabled', nextUsageLogsEnabled);
      upsertSetting('log_cleanup_program_logs_enabled', nextProgramLogsEnabled);
      upsertSetting('log_cleanup_retention_days', nextLogCleanupRetentionDays);
    }

    if (body.proxyToken !== undefined) {
      const proxyToken = String(body.proxyToken).trim();
      if (!proxyToken.startsWith(PROXY_TOKEN_PREFIX)) {
        return reply.code(400).send({ success: false, message: '下游访问令牌必须以 sk- 开头' });
      }
      if (proxyToken.length < 6) {
        return reply.code(400).send({ success: false, message: '下游访问令牌至少 6 位（含 sk-）' });
      }
      if (proxyToken !== config.proxyToken) {
        changedLabels.push('代理访问 Token');
      }
      config.proxyToken = proxyToken;
      upsertSetting('proxy_token', proxyToken);
    }

    if (body.systemProxyUrl !== undefined) {
      const rawSystemProxyUrl = String(body.systemProxyUrl || '').trim();
      const normalizedSystemProxyUrl = rawSystemProxyUrl
        ? normalizeSiteProxyUrl(rawSystemProxyUrl)
        : '';
      if (rawSystemProxyUrl && !normalizedSystemProxyUrl) {
        return reply.code(400).send({ success: false, message: '系统代理地址无效，请填写合法的 http(s)/socks 代理 URL' });
      }
      if (normalizedSystemProxyUrl !== config.systemProxyUrl) {
        changedLabels.push('系统代理');
      }
      config.systemProxyUrl = normalizedSystemProxyUrl || '';
      upsertSetting('system_proxy_url', config.systemProxyUrl);
      invalidateSiteProxyCache();
    }

    if (body.codexUpstreamWebsocketEnabled !== undefined) {
      let nextValue = false;
      try {
        nextValue = parseBooleanFlag(body.codexUpstreamWebsocketEnabled, 'Codex 上游 WebSocket 开关');
      } catch (err: any) {
        return reply.code(400).send({
          success: false,
          message: err?.message || 'Codex 上游 WebSocket 开关格式无效',
        });
      }

      if (nextValue !== config.codexUpstreamWebsocketEnabled) {
        changedLabels.push('Codex 上游 WebSocket 默认策略');
      }
      config.codexUpstreamWebsocketEnabled = nextValue;
      upsertSetting('codex_upstream_websocket_enabled', config.codexUpstreamWebsocketEnabled);
    }

    if (body.proxySessionChannelConcurrencyLimit !== undefined) {
      const limit = Number(body.proxySessionChannelConcurrencyLimit);
      if (!Number.isFinite(limit) || limit < 0) {
        return reply.code(400).send({ success: false, message: '会话通道并发上限必须是大于等于 0 的整数' });
      }
      const nextLimit = Math.trunc(limit);
      if (nextLimit !== config.proxySessionChannelConcurrencyLimit) {
        changedLabels.push(`会话通道并发上限（${config.proxySessionChannelConcurrencyLimit} -> ${nextLimit}）`);
      }
      config.proxySessionChannelConcurrencyLimit = nextLimit;
      upsertSetting('proxy_session_channel_concurrency_limit', config.proxySessionChannelConcurrencyLimit);
    }

    if (body.proxySessionChannelQueueWaitMs !== undefined) {
      const rawQueueWaitMs = Number(body.proxySessionChannelQueueWaitMs);
      if (!Number.isFinite(rawQueueWaitMs) || rawQueueWaitMs < 0) {
        return reply.code(400).send({ success: false, message: '会话通道排队等待时间必须是大于等于 0 的整数毫秒' });
      }
      const nextQueueWaitMs = Math.trunc(rawQueueWaitMs);
      if (nextQueueWaitMs !== config.proxySessionChannelQueueWaitMs) {
        changedLabels.push(`会话通道排队等待（${config.proxySessionChannelQueueWaitMs}ms -> ${nextQueueWaitMs}ms）`);
      }
      config.proxySessionChannelQueueWaitMs = nextQueueWaitMs;
      upsertSetting('proxy_session_channel_queue_wait_ms', config.proxySessionChannelQueueWaitMs);
    }

    if (body.proxyDebugTraceEnabled !== undefined) {
      let nextValue = false;
      try {
        nextValue = parseBooleanFlag(body.proxyDebugTraceEnabled, '代理调试追踪开关');
      } catch (err: any) {
        return reply.code(400).send({
          success: false,
          message: err?.message || '代理调试追踪开关格式无效',
        });
      }
      if (nextValue !== config.proxyDebugTraceEnabled) {
        changedLabels.push('代理调试追踪');
      }
      config.proxyDebugTraceEnabled = nextValue;
      upsertSetting('proxy_debug_trace_enabled', config.proxyDebugTraceEnabled);
    }

    if (body.proxyDebugCaptureHeaders !== undefined) {
      let nextValue = false;
      try {
        nextValue = parseBooleanFlag(body.proxyDebugCaptureHeaders, '代理调试请求头采集');
      } catch (err: any) {
        return reply.code(400).send({
          success: false,
          message: err?.message || '代理调试请求头采集格式无效',
        });
      }
      if (nextValue !== config.proxyDebugCaptureHeaders) {
        changedLabels.push('代理调试请求头采集');
      }
      config.proxyDebugCaptureHeaders = nextValue;
      upsertSetting('proxy_debug_capture_headers', config.proxyDebugCaptureHeaders);
    }

    if (body.proxyDebugCaptureBodies !== undefined) {
      let nextValue = false;
      try {
        nextValue = parseBooleanFlag(body.proxyDebugCaptureBodies, '代理调试请求体采集');
      } catch (err: any) {
        return reply.code(400).send({
          success: false,
          message: err?.message || '代理调试请求体采集格式无效',
        });
      }
      if (nextValue !== config.proxyDebugCaptureBodies) {
        changedLabels.push('代理调试请求体采集');
      }
      config.proxyDebugCaptureBodies = nextValue;
      upsertSetting('proxy_debug_capture_bodies', config.proxyDebugCaptureBodies);
    }

    if (body.proxyDebugCaptureStreamChunks !== undefined) {
      let nextValue = false;
      try {
        nextValue = parseBooleanFlag(body.proxyDebugCaptureStreamChunks, '代理调试流式分片采集');
      } catch (err: any) {
        return reply.code(400).send({
          success: false,
          message: err?.message || '代理调试流式分片采集格式无效',
        });
      }
      if (nextValue !== config.proxyDebugCaptureStreamChunks) {
        changedLabels.push('代理调试流式分片采集');
      }
      config.proxyDebugCaptureStreamChunks = nextValue;
      upsertSetting('proxy_debug_capture_stream_chunks', config.proxyDebugCaptureStreamChunks);
    }

    if (body.proxyDebugTargetSessionId !== undefined) {
      const nextValue = String(body.proxyDebugTargetSessionId || '').trim();
      if (nextValue !== config.proxyDebugTargetSessionId) {
        changedLabels.push('代理调试目标会话');
      }
      config.proxyDebugTargetSessionId = nextValue;
      upsertSetting('proxy_debug_target_session_id', config.proxyDebugTargetSessionId);
    }

    if (body.proxyDebugTargetClientKind !== undefined) {
      const nextValue = String(body.proxyDebugTargetClientKind || '').trim();
      if (nextValue !== config.proxyDebugTargetClientKind) {
        changedLabels.push('代理调试目标客户端');
      }
      config.proxyDebugTargetClientKind = nextValue;
      upsertSetting('proxy_debug_target_client_kind', config.proxyDebugTargetClientKind);
    }

    if (body.proxyDebugTargetModel !== undefined) {
      const nextValue = String(body.proxyDebugTargetModel || '').trim();
      if (nextValue !== config.proxyDebugTargetModel) {
        changedLabels.push('代理调试目标模型');
      }
      config.proxyDebugTargetModel = nextValue;
      upsertSetting('proxy_debug_target_model', config.proxyDebugTargetModel);
    }

    if (body.proxyDebugRetentionHours !== undefined) {
      const retentionHours = Number(body.proxyDebugRetentionHours);
      if (!Number.isFinite(retentionHours) || retentionHours < 1) {
        return reply.code(400).send({ success: false, message: '代理调试保留时长必须是大于等于 1 的整数小时' });
      }
      const nextValue = Math.trunc(retentionHours);
      if (nextValue !== config.proxyDebugRetentionHours) {
        changedLabels.push(`代理调试保留时长（${config.proxyDebugRetentionHours}h -> ${nextValue}h）`);
      }
      config.proxyDebugRetentionHours = nextValue;
      upsertSetting('proxy_debug_retention_hours', config.proxyDebugRetentionHours);
    }

    if (body.proxyDebugMaxBodyBytes !== undefined) {
      const maxBodyBytes = Number(body.proxyDebugMaxBodyBytes);
      if (!Number.isFinite(maxBodyBytes) || maxBodyBytes < 1024) {
        return reply.code(400).send({ success: false, message: '代理调试抓取体积上限必须是大于等于 1024 的整数字节' });
      }
      const nextValue = Math.trunc(maxBodyBytes);
      if (nextValue !== config.proxyDebugMaxBodyBytes) {
        changedLabels.push(`代理调试抓取体积上限（${config.proxyDebugMaxBodyBytes}B -> ${nextValue}B）`);
      }
      config.proxyDebugMaxBodyBytes = nextValue;
      upsertSetting('proxy_debug_max_body_bytes', config.proxyDebugMaxBodyBytes);
    }

    if (body.proxyErrorKeywords !== undefined) {
      let nextKeywords: string[] = [];
      try {
        nextKeywords = parseProxyErrorKeywords(body.proxyErrorKeywords);
      } catch (err: any) {
        return reply.code(400).send({
          success: false,
          message: err?.message || '上游错误关键词格式无效',
        });
      }

      if (JSON.stringify(nextKeywords) !== JSON.stringify(config.proxyErrorKeywords || [])) {
        changedLabels.push('上游错误关键词');
      }
      config.proxyErrorKeywords = nextKeywords;
      upsertSetting('proxy_error_keywords', config.proxyErrorKeywords);
    }

    if (body.proxyEmptyContentFailEnabled !== undefined) {
      let nextValue = false;
      try {
        nextValue = parseBooleanFlag(body.proxyEmptyContentFailEnabled, '空内容判定失败开关');
      } catch (err: any) {
        return reply.code(400).send({
          success: false,
          message: err?.message || '空内容判定失败开关格式无效',
        });
      }

      if (nextValue !== config.proxyEmptyContentFailEnabled) {
        changedLabels.push('空内容判定失败');
      }
      config.proxyEmptyContentFailEnabled = nextValue;
      upsertSetting('proxy_empty_content_fail_enabled', config.proxyEmptyContentFailEnabled);
    }

    if (body.globalBlockedBrands !== undefined) {
      if (!Array.isArray(body.globalBlockedBrands)) {
        return reply.code(400).send({ error: 'globalBlockedBrands must be an array of strings' });
      }
      const nextBrands = body.globalBlockedBrands.filter((b): b is string => typeof b === 'string').map((b) => b.trim()).filter(Boolean);
      const uniqueBrands = Array.from(new Set(nextBrands));
      const prev = JSON.stringify(config.globalBlockedBrands);
      const next = JSON.stringify(uniqueBrands);
      if (prev !== next) {
        changedLabels.push('全局品牌屏蔽');
      }
      config.globalBlockedBrands = uniqueBrands;
      upsertSetting('global_blocked_brands', JSON.stringify(uniqueBrands));
      if (prev !== next) {
        startBackgroundTask(
          {
            type: 'maintenance',
            title: '品牌屏蔽变更后重建路由',
            dedupeKey: 'refresh-models-and-rebuild-routes',
          },
          async () => routeRefreshWorkflow.refreshModelsAndRebuildRoutes(),
        );
      }
    }

    if (body.webhookUrl !== undefined) {
      if (String(body.webhookUrl || '').trim() !== config.webhookUrl) {
        changedLabels.push('Webhook 地址');
      }
      config.webhookUrl = String(body.webhookUrl || '').trim();
      upsertSetting('webhook_url', config.webhookUrl);
    }

    if (body.webhookEnabled !== undefined) {
      if (!!body.webhookEnabled !== config.webhookEnabled) {
        changedLabels.push('Webhook 开关');
      }
      config.webhookEnabled = !!body.webhookEnabled;
      upsertSetting('webhook_enabled', config.webhookEnabled);
    }

    if (body.barkUrl !== undefined) {
      if (String(body.barkUrl || '').trim() !== config.barkUrl) {
        changedLabels.push('Bark 地址');
      }
      config.barkUrl = String(body.barkUrl || '').trim();
      upsertSetting('bark_url', config.barkUrl);
    }

    if (body.barkEnabled !== undefined) {
      if (!!body.barkEnabled !== config.barkEnabled) {
        changedLabels.push('Bark 开关');
      }
      config.barkEnabled = !!body.barkEnabled;
      upsertSetting('bark_enabled', config.barkEnabled);
    }

    if (body.serverChanEnabled !== undefined) {
      if (!!body.serverChanEnabled !== config.serverChanEnabled) {
        changedLabels.push('Server 酱开关');
      }
      config.serverChanEnabled = !!body.serverChanEnabled;
      upsertSetting('serverchan_enabled', config.serverChanEnabled);
    }

    if (body.serverChanKey !== undefined) {
      if (String(body.serverChanKey || '').trim() !== config.serverChanKey) {
        changedLabels.push('Server 酱密钥');
      }
      config.serverChanKey = String(body.serverChanKey || '').trim();
      upsertSetting('serverchan_key', config.serverChanKey);
    }

    if (body.telegramEnabled !== undefined) {
      if (!!body.telegramEnabled !== config.telegramEnabled) {
        changedLabels.push('Telegram 开关');
      }
      config.telegramEnabled = !!body.telegramEnabled;
      upsertSetting('telegram_enabled', config.telegramEnabled);
    }

    if (body.telegramApiBaseUrl !== undefined) {
      const normalizedTelegramApiBaseUrl = normalizeTelegramApiBaseUrl(body.telegramApiBaseUrl);
      const nextTelegramApiBaseUrl = normalizedTelegramApiBaseUrl || 'https://api.telegram.org';
      if (nextTelegramApiBaseUrl !== config.telegramApiBaseUrl) {
        changedLabels.push('Telegram API Base URL');
      }
      config.telegramApiBaseUrl = nextTelegramApiBaseUrl;
      upsertSetting('telegram_api_base_url', config.telegramApiBaseUrl);
    }

    if (body.telegramBotToken !== undefined) {
      if (String(body.telegramBotToken || '').trim() !== config.telegramBotToken) {
        changedLabels.push('Telegram Bot Token');
      }
      config.telegramBotToken = String(body.telegramBotToken || '').trim();
      upsertSetting('telegram_bot_token', config.telegramBotToken);
    }

    if (body.telegramChatId !== undefined) {
      if (String(body.telegramChatId || '').trim() !== config.telegramChatId) {
        changedLabels.push('Telegram Chat ID');
      }
      config.telegramChatId = String(body.telegramChatId || '').trim();
      upsertSetting('telegram_chat_id', config.telegramChatId);
    }

    if (body.telegramUseSystemProxy !== undefined) {
      if (!!body.telegramUseSystemProxy !== config.telegramUseSystemProxy) {
        changedLabels.push('Telegram 使用系统代理');
      }
      config.telegramUseSystemProxy = !!body.telegramUseSystemProxy;
      upsertSetting('telegram_use_system_proxy', config.telegramUseSystemProxy);
    }

    if (body.telegramMessageThreadId !== undefined) {
      const nextTelegramMessageThreadId = normalizeTelegramMessageThreadId(body.telegramMessageThreadId);
      if (nextTelegramMessageThreadId !== config.telegramMessageThreadId) {
        changedLabels.push('Telegram Topic ID');
      }
      config.telegramMessageThreadId = nextTelegramMessageThreadId;
      upsertSetting('telegram_message_thread_id', config.telegramMessageThreadId);
    }

    if (body.smtpEnabled !== undefined) {
      if (!!body.smtpEnabled !== config.smtpEnabled) {
        changedLabels.push('SMTP 开关');
      }
      config.smtpEnabled = !!body.smtpEnabled;
      upsertSetting('smtp_enabled', config.smtpEnabled);
    }

    if (body.smtpHost !== undefined) {
      if (String(body.smtpHost || '').trim() !== config.smtpHost) {
        changedLabels.push('SMTP 主机');
      }
      config.smtpHost = String(body.smtpHost || '').trim();
      upsertSetting('smtp_host', config.smtpHost);
    }

    if (body.smtpPort !== undefined) {
      const smtpPort = Number(body.smtpPort);
      if (!Number.isFinite(smtpPort) || smtpPort <= 0) {
        return reply.code(400).send({ success: false, message: 'SMTP 端口无效' });
      }
      if (Math.trunc(smtpPort) !== config.smtpPort) {
        changedLabels.push(`SMTP 端口（${config.smtpPort} -> ${Math.trunc(smtpPort)}）`);
      }
      config.smtpPort = Math.trunc(smtpPort);
      upsertSetting('smtp_port', config.smtpPort);
    }

    if (body.smtpSecure !== undefined) {
      if (!!body.smtpSecure !== config.smtpSecure) {
        changedLabels.push('SMTP 安全连接');
      }
      config.smtpSecure = !!body.smtpSecure;
      upsertSetting('smtp_secure', config.smtpSecure);
    }

    if (body.smtpUser !== undefined) {
      if (String(body.smtpUser || '').trim() !== config.smtpUser) {
        changedLabels.push('SMTP 用户');
      }
      config.smtpUser = String(body.smtpUser || '').trim();
      upsertSetting('smtp_user', config.smtpUser);
    }

    if (body.smtpPass !== undefined) {
      if (String(body.smtpPass || '').trim() !== config.smtpPass) {
        changedLabels.push('SMTP 密码');
      }
      config.smtpPass = String(body.smtpPass || '').trim();
      upsertSetting('smtp_pass', config.smtpPass);
    }

    if (body.smtpFrom !== undefined) {
      if (String(body.smtpFrom || '').trim() !== config.smtpFrom) {
        changedLabels.push('发件人地址');
      }
      config.smtpFrom = String(body.smtpFrom || '').trim();
      upsertSetting('smtp_from', config.smtpFrom);
    }

    if (body.smtpTo !== undefined) {
      if (String(body.smtpTo || '').trim() !== config.smtpTo) {
        changedLabels.push('收件人地址');
      }
      config.smtpTo = String(body.smtpTo || '').trim();
      upsertSetting('smtp_to', config.smtpTo);
    }

    if (body.notifyCooldownSec !== undefined) {
      const notifyCooldownSec = Number(body.notifyCooldownSec);
      if (!Number.isFinite(notifyCooldownSec) || notifyCooldownSec < 0) {
        return reply.code(400).send({ success: false, message: '告警冷静期必须是大于等于 0 的数字（秒）' });
      }
      const nextCooldown = Math.trunc(notifyCooldownSec);
      if (nextCooldown !== config.notifyCooldownSec) {
        changedLabels.push(`告警冷静期（${config.notifyCooldownSec}s -> ${nextCooldown}s）`);
      }
      config.notifyCooldownSec = nextCooldown;
      upsertSetting('notify_cooldown_sec', config.notifyCooldownSec);
    }

    if (body.adminIpAllowlist !== undefined) {
      const nextAllowlist = toStringList(body.adminIpAllowlist);
      if (nextAllowlist.length > 0 && !isIpAllowed(currentRequestIp, nextAllowlist)) {
        return reply.code(400).send({
          success: false,
          message: `保存失败：当前请求 IP（${currentRequestIp || 'unknown'}）不在新白名单中。请至少保留当前 IP，避免把自己锁出后台。`,
        });
      }
      if (JSON.stringify(nextAllowlist) !== JSON.stringify(config.adminIpAllowlist)) {
        changedLabels.push('管理端 IP 白名单');
      }
      config.adminIpAllowlist = nextAllowlist;
      upsertSetting('admin_ip_allowlist', nextAllowlist);
    }

    if (body.routingWeights !== undefined) {
      const nextWeights: RoutingWeights = {
        baseWeightFactor: toPositiveNumberOrFallback(body.routingWeights.baseWeightFactor, config.routingWeights.baseWeightFactor),
        valueScoreFactor: toPositiveNumberOrFallback(body.routingWeights.valueScoreFactor, config.routingWeights.valueScoreFactor),
        costWeight: toPositiveNumberOrFallback(body.routingWeights.costWeight, config.routingWeights.costWeight),
        balanceWeight: toPositiveNumberOrFallback(body.routingWeights.balanceWeight, config.routingWeights.balanceWeight),
        usageWeight: toPositiveNumberOrFallback(body.routingWeights.usageWeight, config.routingWeights.usageWeight),
      };
      if (JSON.stringify(nextWeights) !== JSON.stringify(config.routingWeights)) {
        changedLabels.push('路由权重');
      }
      config.routingWeights = nextWeights;
      upsertSetting('routing_weights', nextWeights);
    }

    if (body.routingFallbackUnitCost !== undefined) {
      const nextRoutingFallbackUnitCost = Number(body.routingFallbackUnitCost);
      if (!Number.isFinite(nextRoutingFallbackUnitCost) || nextRoutingFallbackUnitCost <= 0) {
        return reply.code(400).send({ success: false, message: '无价模型默认单价必须是大于 0 的数字' });
      }
      const normalized = Math.max(1e-6, nextRoutingFallbackUnitCost);
      if (Math.abs(normalized - config.routingFallbackUnitCost) > 1e-12) {
        changedLabels.push(`无价模型默认单价（${config.routingFallbackUnitCost} -> ${normalized}）`);
      }
      config.routingFallbackUnitCost = normalized;
      upsertSetting('routing_fallback_unit_cost', normalized);
    }

    if (changedLabels.length > 0) {
      let eventType: 'checkin' | 'balance' | 'proxy' | 'status' | 'token' = 'status';
      if (changedLabels.length === 1) {
        if (changedLabels[0].startsWith('签到 Cron')) eventType = 'checkin';
        else if (changedLabels[0].startsWith('余额刷新 Cron')) eventType = 'balance';
        else if (changedLabels[0] === '代理访问 Token') eventType = 'proxy';
      }
      appendSettingsEvent({
        type: eventType,
        title: '运行时设置已更新',
        message: `已更新：${changedLabels.join('、')}`,
      });
    }

    return {
      success: true,
      message: '运行时设置已更新',
      ...getRuntimeSettingsResponse(currentRequestIp),
    };
  });

  app.get('/api/settings/database/runtime', async () => {
    const saved = await loadSavedRuntimeDatabaseConfig();
    return {
      success: true,
      ...buildRuntimeDatabaseState(saved),
    };
  });

  app.put<{ Body: DatabaseMigrationBody }>('/api/settings/database/runtime', async (request, reply) => {
    try {
      const normalized = normalizeMigrationInput(request.body || {});
      await upsertSetting(DB_TYPE_SETTING_KEY, normalized.dialect);
      await upsertSetting(DB_URL_SETTING_KEY, normalized.connectionString);
      await upsertSetting(DB_SSL_SETTING_KEY, normalized.ssl);

      await appendSettingsEvent({
        type: 'status',
        title: '数据库运行配置已更新',
        message: `已保存运行数据库配置：${normalized.dialect}${normalized.ssl ? ' (SSL)' : ''}（重启后生效）`,
      });

      const saved: RuntimeDatabaseConfig = {
        dialect: normalized.dialect,
        connectionString: normalized.connectionString,
        ssl: normalized.ssl,
      };

      return {
        success: true,
        message: '数据库运行配置已保存，重启容器后生效',
        ...buildRuntimeDatabaseState(saved),
      };
    } catch (err: any) {
      return reply.code(400).send({
        success: false,
        message: err?.message || '数据库运行配置保存失败',
      });
    }
  });

  app.post<{ Body: DatabaseMigrationBody }>('/api/settings/database/test-connection', async (request, reply) => {
    try {
      const result = await testDatabaseConnection(request.body || {});
      return {
        success: true,
        message: '目标数据库连接成功',
        ...result,
      };
    } catch (err: any) {
      return reply.code(400).send({
        success: false,
        message: err?.message || '数据库连接失败',
      });
    }
  });

  app.post<{ Body: DatabaseMigrationBody }>('/api/settings/database/migrate', async (request, reply) => {
    try {
      const result = await migrateCurrentDatabase(request.body || {});
      appendSettingsEvent({
        type: 'status',
        title: '数据库迁移已完成',
        message: `目标 ${result.dialect}，已迁移站点 ${result.rows.sites}、账号 ${result.rows.accounts}、令牌 ${result.rows.accountTokens}、路由 ${result.rows.tokenRoutes}、通道 ${result.rows.routeChannels}、设置 ${result.rows.settings}`,
      });
      return {
        success: true,
        message: '数据库迁移完成',
        ...result,
      };
    } catch (err: any) {
      return reply.code(400).send({
        success: false,
        message: err?.message || '数据库迁移失败',
      });
    }
  });

  await app.get<{ Querystring: { type?: string } }>('/api/settings/backup/export', async (request, reply) => {
    const rawType = String(request.query.type || 'all').trim().toLowerCase();
    const type: BackupExportType = rawType === 'accounts' || rawType === 'preferences' ? rawType : 'all';
    if (rawType && !['all', 'accounts', 'preferences'].includes(rawType)) {
      return reply.code(400).send({ success: false, message: '导出类型无效，仅支持 all/accounts/preferences' });
    }
    return await exportBackup(type);
  });

  app.post<{ Body: { data?: Record<string, unknown> } }>('/api/settings/backup/import', async (request, reply) => {
    const payload = request.body?.data;
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
      return reply.code(400).send({ success: false, message: '导入数据格式错误：需要 JSON 对象' });
    }

    try {
      const result = await importBackup(payload);
      for (const item of result.appliedSettings) {
        applyImportedSettingToRuntime(item.key, item.value);
      }
      if (result.appliedSettings.some((item) => item.key === 'backup_webdav_config_v1')) {
        await reloadBackupWebdavScheduler();
      }
      return {
        success: true,
        message: '导入完成',
        ...result,
      };
    } catch (err: any) {
      return reply.code(400).send({
        success: false,
        message: err?.message || '导入失败',
      });
    }
  });

  app.get('/api/settings/backup/webdav', async () => {
    return getBackupWebdavConfig();
  });

  app.put<{ Body: BackupWebdavConfigBody }>('/api/settings/backup/webdav', async (request, reply) => {
    try {
      const body = request.body || {};
      const result = await saveBackupWebdavConfig({
        enabled: body.enabled === undefined ? undefined : body.enabled === true,
        fileUrl: body.fileUrl === undefined ? undefined : String(body.fileUrl || ''),
        username: body.username === undefined ? undefined : String(body.username || ''),
        password: body.password === undefined ? undefined : String(body.password),
        clearPassword: body.clearPassword === true,
        exportType: body.exportType === undefined ? undefined : String(body.exportType || '') as BackupExportType,
        autoSyncEnabled: body.autoSyncEnabled === undefined ? undefined : body.autoSyncEnabled === true,
        autoSyncCron: body.autoSyncCron === undefined ? undefined : String(body.autoSyncCron || ''),
      });
      return result;
    } catch (err: any) {
      return reply.code(400).send({
        success: false,
        message: err?.message || 'WebDAV 配置保存失败',
      });
    }
  });

  app.post<{ Body: { type?: string } }>('/api/settings/backup/webdav/export', async (request, reply) => {
    try {
      const rawType = typeof request.body?.type === 'string' ? request.body.type.trim().toLowerCase() : '';
      const type: BackupExportType | undefined = rawType === 'all' || rawType === 'accounts' || rawType === 'preferences'
        ? rawType
        : undefined;
      return await exportBackupToWebdav(type);
    } catch (err: any) {
      return reply.code(400).send({
        success: false,
        message: err?.message || 'WebDAV 导出失败',
      });
    }
  });

  app.post('/api/settings/backup/webdav/import', async (_, reply) => {
    try {
      const result = await importBackupFromWebdav();
      for (const item of result.appliedSettings) {
        applyImportedSettingToRuntime(item.key, item.value);
      }
      if (result.appliedSettings.some((item) => item.key === 'backup_webdav_config_v1')) {
        await reloadBackupWebdavScheduler();
      }
      return result;
    } catch (err: any) {
      return reply.code(400).send({
        success: false,
        message: err?.message || 'WebDAV 导入失败',
      });
    }
  });

  app.post('/api/settings/notify/test', async (_, reply) => {
    try {
      const result = await sendNotification(
        '测试通知',
        '您好，这是一条来自系统设置的连通性测试通知，您的通知相关配置目前工作正常！',
        'info',
        {
          bypassThrottle: true,
          requireChannel: true,
          throwOnFailure: true,
        },
      );
      return {
        success: true,
        message: `测试通知已发送（成功 ${result.succeeded}/${result.attempted}）`,
      };
    } catch (err: any) {
      return reply.code(400).send({
        success: false,
        message: err?.message || '测试通知发送失败',
      });
    }
  });

  app.post('/api/settings/maintenance/clear-cache', async (_, reply) => {
    const deletedModelAvailability = (await db.delete(schema.modelAvailability).run()).changes;
    const deletedRouteChannels = (await db.delete(schema.routeChannels).run()).changes;
    const deletedTokenRoutes = (await db.delete(schema.tokenRoutes).run()).changes;

    const { task, reused } = startBackgroundTask(
      {
        type: 'maintenance',
        title: '清理缓存并重建路由',
        dedupeKey: 'refresh-models-and-rebuild-routes',
        notifyOnFailure: true,
        successMessage: (currentTask) => {
          const rebuild = (currentTask.result as any)?.rebuild;
          if (!rebuild) return '缓存清理后重建路由已完成';
          return `缓存清理后重建完成：新增路由 ${rebuild.createdRoutes}，移除旧路由 ${rebuild.removedRoutes ?? 0}，新增通道 ${rebuild.createdChannels}，移除通道 ${rebuild.removedChannels}`;
        },
        failureMessage: (currentTask) => `缓存清理后重建失败：${currentTask.error || 'unknown error'}`,
      },
      async () => routeRefreshWorkflow.refreshModelsAndRebuildRoutes(),
    );

    return reply.code(202).send({
      success: true,
      queued: true,
      reused,
      jobId: task.id,
      message: '缓存已清理，重建路由已开始执行',
      deletedModelAvailability,
      deletedRouteChannels,
      deletedTokenRoutes,
    });
  });

  app.post('/api/settings/maintenance/clear-usage', async () => {
    const deletedProxyLogs = (await db.delete(schema.proxyLogs).run()).changes;

    await db.update(schema.routeChannels).set({
      successCount: 0,
      failCount: 0,
      totalLatencyMs: 0,
      totalCost: 0,
      lastUsedAt: null,
      lastSelectedAt: null,
      lastFailAt: null,
      consecutiveFailCount: 0,
      cooldownLevel: 0,
      cooldownUntil: null,
    }).run();

    await db.update(schema.accounts).set({
      balanceUsed: 0,
      updatedAt: new Date().toISOString(),
    }).run();

    appendSettingsEvent({
      type: 'status',
      title: '占用统计与使用日志已清理',
      message: `已清理使用日志 ${deletedProxyLogs} 条，并重置路由与账号占用统计`,
      level: 'warning',
    });

    return {
      success: true,
      message: '占用统计已清理',
      deletedProxyLogs,
    };
  });

  app.post('/api/settings/maintenance/factory-reset', async (_, reply) => {
    try {
      await performFactoryReset();
      return {
        success: true,
      };
    } catch (err: any) {
      return reply.code(500).send({
        success: false,
        message: err?.message || '重新初始化系统失败',
      });
    }
  });
}
