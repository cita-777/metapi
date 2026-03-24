import Fastify from 'fastify';
import cors from '@fastify/cors';
import fastifyStatic from '@fastify/static';
import { buildFastifyOptions, config } from './config.js';
import { normalizePayloadRulesConfig } from './services/payloadRules.js';
import { authMiddleware } from './middleware/auth.js';
import { sitesRoutes } from './routes/api/sites.js';
import { accountsRoutes } from './routes/api/accounts.js';
import { checkinRoutes } from './routes/api/checkin.js';
import { tokensRoutes } from './routes/api/tokens.js';
import { statsRoutes } from './routes/api/stats.js';
import { authRoutes } from './routes/api/auth.js';
import { settingsRoutes } from './routes/api/settings.js';
import { accountTokensRoutes } from './routes/api/accountTokens.js';
import { searchRoutes } from './routes/api/search.js';
import { eventsRoutes } from './routes/api/events.js';
import { taskRoutes } from './routes/api/tasks.js';
import { testRoutes } from './routes/api/test.js';
import { monitorRoutes } from './routes/api/monitor.js';
import { downstreamApiKeysRoutes } from './routes/api/downstreamApiKeys.js';
import { oauthRoutes } from './routes/api/oauth.js';
import { siteAnnouncementsRoutes } from './routes/api/siteAnnouncements.js';
import { proxyRoutes } from './routes/proxy/router.js';
import { startScheduler } from './services/checkinScheduler.js';
import * as routeRefreshWorkflow from './services/routeRefreshWorkflow.js';
import { startProxyFileRetentionService, stopProxyFileRetentionService } from './services/proxyFileRetentionService.js';
import { setLegacyProxyLogRetentionFallbackEnabled, stopProxyLogRetentionService } from './services/proxyLogRetentionService.js';
import { buildStartupSummaryLines } from './services/startupInfo.js';
import { repairStoredCreatedAtValues } from './services/storedTimestampRepairService.js';
import { migrateSiteApiKeysToAccounts } from './services/siteApiKeyMigrationService.js';
import { ensureDefaultSitesSeeded } from './services/defaultSiteSeedService.js';
import { ensureOauthIdentityBackfill } from './services/oauth/oauthIdentityBackfill.js';
import { startOAuthLoopbackCallbackServers, stopOAuthLoopbackCallbackServers } from './services/oauth/localCallbackServer.js';
import { startSiteAnnouncementPolling } from './services/siteAnnouncementPollingService.js';
import { reloadBackupWebdavScheduler } from './services/backupService.js';
import { ensureRuntimeDatabaseReady } from './runtimeDatabaseBootstrap.js';
import { isPublicApiRoute, registerDesktopRoutes } from './desktop.js';
import { existsSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, normalize, resolve, sep } from 'path';
import { normalizeLogCleanupRetentionDays } from './services/logCleanupService.js';
import {
  db,
  ensureProxyFileCompatibilityColumns,
  ensureProxyLogClientColumns,
  ensureProxyLogDownstreamApiKeyIdColumn,
  ensureProxyLogBillingDetailsColumn,
  ensureRouteGroupingCompatibilityColumns,
  ensureSiteCompatibilityColumns,
  runtimeDbDialect,
  schema,
  switchRuntimeDatabase,
  type RuntimeDbDialect,
} from './db/index.js';

function toSettingsMap(rows: Array<{ key: string; value: string }>) {
  return new Map(rows.map((row) => [row.key, row.value]));
}

function parseSettingFromMap<T>(settingsMap: Map<string, string>, key: string): T | undefined {
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

function normalizeSavedDbType(value: unknown): RuntimeDbDialect | null {
  if (typeof value !== 'string') return null;
  const normalized = value.trim().toLowerCase();
  if (normalized === 'sqlite') return 'sqlite';
  if (normalized === 'mysql') return 'mysql';
  if (normalized === 'postgres' || normalized === 'postgresql') return 'postgres';
  return null;
}

function validateSavedDbUrl(dialect: RuntimeDbDialect, value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const normalized = value.trim();
  if (!normalized) return null;
  if (dialect === 'sqlite') return normalized;
  if (dialect === 'mysql' && normalized.startsWith('mysql://')) return normalized;
  if (dialect === 'postgres' && (normalized.startsWith('postgres://') || normalized.startsWith('postgresql://'))) return normalized;
  return null;
}

function extractSavedRuntimeDatabaseConfig(settingsMap: Map<string, string>): { dialect: RuntimeDbDialect; dbUrl: string; ssl: boolean } | null {
  const rawType = parseSettingFromMap<unknown>(settingsMap, 'db_type');
  const rawUrl = parseSettingFromMap<unknown>(settingsMap, 'db_url');
  const rawSsl = parseSettingFromMap<boolean>(settingsMap, 'db_ssl');
  const dialect = normalizeSavedDbType(rawType);
  if (!dialect) return null;
  const dbUrl = validateSavedDbUrl(dialect, rawUrl);
  if (!dbUrl) return null;
  return {
    dialect,
    dbUrl,
    ssl: typeof rawSsl === 'boolean' ? rawSsl : false,
  };
}

const LOG_CLEANUP_SETTING_KEYS = [
  'log_cleanup_cron',
  'log_cleanup_usage_logs_enabled',
  'log_cleanup_program_logs_enabled',
  'log_cleanup_retention_days',
] as const;

function hasExplicitLogCleanupSettings(settingsMap: Map<string, string>): boolean {
  return LOG_CLEANUP_SETTING_KEYS.some((key) => settingsMap.has(key));
}

function applyRuntimeSettings(settingsMap: Map<string, string>) {
  const authToken = parseSettingFromMap<string>(settingsMap, 'auth_token');
  if (typeof authToken === 'string' && authToken) config.authToken = authToken;

  const proxyToken = parseSettingFromMap<string>(settingsMap, 'proxy_token');
  if (typeof proxyToken === 'string' && proxyToken) config.proxyToken = proxyToken;

  const systemProxyUrl = parseSettingFromMap<string>(settingsMap, 'system_proxy_url');
  if (typeof systemProxyUrl === 'string') config.systemProxyUrl = systemProxyUrl;

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

  const webhookUrl = parseSettingFromMap<string>(settingsMap, 'webhook_url');
  if (typeof webhookUrl === 'string') config.webhookUrl = webhookUrl;

  const barkUrl = parseSettingFromMap<string>(settingsMap, 'bark_url');
  if (typeof barkUrl === 'string') config.barkUrl = barkUrl;

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
    config.smtpPort = smtpPort;
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

// Ensure the current runtime database is bootstrapped before reading settings.
await ensureRuntimeDatabaseReady({
  dialect: runtimeDbDialect,
  connectionString: config.dbUrl,
  ssl: config.dbSsl,
});

// Load runtime config overrides from settings
try {
  const initialRows = await db.select().from(schema.settings).all();
  const initialMap = toSettingsMap(initialRows);
  const savedDbConfig = extractSavedRuntimeDatabaseConfig(initialMap);
  const activeDbUrl = (config.dbUrl || '').trim();
  const originalRuntimeConfig = {
    dialect: runtimeDbDialect,
    dbUrl: activeDbUrl,
    ssl: config.dbSsl,
  };
  if (savedDbConfig && (savedDbConfig.dialect !== runtimeDbDialect || savedDbConfig.dbUrl !== activeDbUrl || savedDbConfig.ssl !== config.dbSsl)) {
    try {
      await switchRuntimeDatabase(savedDbConfig.dialect, savedDbConfig.dbUrl, savedDbConfig.ssl);
      console.log(`Loaded runtime DB config from settings: ${savedDbConfig.dialect}`);
    } catch (error) {
      const currentDbUrl = (config.dbUrl || '').trim();
      const switchedAway = runtimeDbDialect !== originalRuntimeConfig.dialect
        || currentDbUrl !== originalRuntimeConfig.dbUrl
        || config.dbSsl !== originalRuntimeConfig.ssl;
      if (switchedAway) {
        await switchRuntimeDatabase(
          originalRuntimeConfig.dialect,
          originalRuntimeConfig.dbUrl,
          originalRuntimeConfig.ssl,
        );
      }
      console.warn(`Failed to switch runtime DB from settings: ${(error as Error)?.message || 'unknown error'}`);
    }
  }

  await ensureSiteCompatibilityColumns();
  await ensureRouteGroupingCompatibilityColumns();
  await ensureProxyFileCompatibilityColumns();
  await ensureProxyLogClientColumns();
  await ensureProxyLogDownstreamApiKeyIdColumn();
  const finalRows = await db.select().from(schema.settings).all();
  const finalMap = toSettingsMap(finalRows);
  applyRuntimeSettings(finalMap);
  config.logCleanupConfigured = hasExplicitLogCleanupSettings(finalMap);
  if (!config.logCleanupConfigured && config.proxyLogRetentionDays > 0) {
    config.logCleanupUsageLogsEnabled = true;
    config.logCleanupProgramLogsEnabled = false;
    config.logCleanupRetentionDays = normalizeLogCleanupRetentionDays(config.proxyLogRetentionDays);
  }
  await ensureProxyLogBillingDetailsColumn();
  await repairStoredCreatedAtValues();
  await migrateSiteApiKeysToAccounts();
  await ensureDefaultSitesSeeded();
  await ensureOauthIdentityBackfill();
  await routeRefreshWorkflow.rebuildRoutesOnly();

  console.log('Loaded runtime settings overrides');
} catch (error) {
  console.warn(`Failed to load runtime settings overrides: ${(error as Error)?.message || 'unknown error'}`);
}

const app = Fastify(buildFastifyOptions(config));

await app.register(cors);

// Auth middleware for /api routes
app.addHook('onRequest', async (request, reply) => {
  if (request.url.startsWith('/api/') && !isPublicApiRoute(request.url)) {
    await authMiddleware(request, reply);
  }
});

// Register API routes
await app.register(registerDesktopRoutes);
await app.register(sitesRoutes);
await app.register(accountsRoutes);
await app.register(checkinRoutes);
await app.register(tokensRoutes);
await app.register(statsRoutes);
await app.register(authRoutes);
await app.register(settingsRoutes);
await app.register(accountTokensRoutes);
await app.register(searchRoutes);
  await app.register(eventsRoutes);
  await app.register(siteAnnouncementsRoutes);
  await app.register(taskRoutes);
await app.register(testRoutes);
await app.register(monitorRoutes);
await app.register(downstreamApiKeysRoutes);
await app.register(oauthRoutes);

// Register OpenAI-compatible proxy routes
await app.register(proxyRoutes);

// Serve static web frontend in production
const webDir = resolve(dirname(fileURLToPath(import.meta.url)), '../web');
if (existsSync(webDir)) {
  await app.register(fastifyStatic, {
    root: webDir,
    prefix: '/',
    wildcard: false,
    setHeaders: (res, filePath) => {
      const normalizedPath = normalize(filePath);
      if (normalizedPath.includes(`${sep}assets${sep}`)) {
        res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
        return;
      }
      if (normalizedPath.endsWith(`${sep}index.html`)) {
        res.setHeader('Cache-Control', 'no-cache');
      }
    },
  });
  // SPA fallback
  app.setNotFoundHandler(async (request, reply) => {
    if (!request.url.startsWith('/api/') && !request.url.startsWith('/v1/')) {
      return reply.sendFile('index.html');
    }
    reply.code(404).send({ error: 'Not found' });
  });
}

// Start scheduler
await startScheduler();
await reloadBackupWebdavScheduler();
startSiteAnnouncementPolling();
try {
  await startOAuthLoopbackCallbackServers();
} catch (error) {
  console.warn(`Failed to start OAuth callback listeners: ${(error as Error)?.message || 'unknown error'}`);
}
setLegacyProxyLogRetentionFallbackEnabled(!config.logCleanupConfigured);
startProxyFileRetentionService();
app.addHook('onClose', async () => {
  stopProxyFileRetentionService();
  stopProxyLogRetentionService();
  await stopOAuthLoopbackCallbackServers();
});

// Start server
try {
  await app.listen({ port: config.port, host: config.listenHost });
  const summaryLines = buildStartupSummaryLines({
    port: config.port,
    host: config.listenHost,
    authToken: config.authToken,
    proxyToken: config.proxyToken,
  });
  for (const line of summaryLines) {
    console.log(line);
  }
} catch (err) {
  app.log.error(err);
  process.exit(1);
}
