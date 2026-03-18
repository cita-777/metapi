import 'dotenv/config';
import type { FastifyServerOptions } from 'fastify';

const DEFAULT_REQUEST_BODY_LIMIT = 20 * 1024 * 1024;
const DEFAULT_CODEX_CLIENT_ID = 'app_EMoamEEZ73f0CkXaXp7hrann';
const DEFAULT_CLAUDE_CLIENT_ID = '9d1c250a-e61b-44d9-88ed-5944d1962f5e';
const DEFAULT_GEMINI_CLI_CLIENT_ID = '681255809395-oo8ft2oprdrnp9e3aqf6av3hmdib135j.apps.googleusercontent.com';
const DEFAULT_GEMINI_CLI_CLIENT_SECRET = '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';

function parseBoolean(value: string | undefined, fallback = false): boolean {
  if (value === undefined) return fallback;
  const normalized = value.trim().toLowerCase();
  return normalized === '1' || normalized === 'true' || normalized === 'yes' || normalized === 'on';
}

function parseNumber(value: string | undefined, fallback: number): number {
  if (value === undefined) return fallback;
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return parsed;
}

function parseCsvList(value: string | undefined): string[] {
  if (!value) return [];
  return value
    .split(',')
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
}

function parseOptionalSecret(value: string | undefined): string {
  return (value || '').trim();
}

function parseDbType(value: string | undefined): 'sqlite' | 'mysql' | 'postgres' {
  const normalized = (value || 'sqlite').trim().toLowerCase();
  if (normalized === 'mysql') return 'mysql';
  if (normalized === 'postgres' || normalized === 'postgresql') return 'postgres';
  return 'sqlite';
}

function parseListenHost(env: NodeJS.ProcessEnv): string {
  return (env.HOST || '0.0.0.0').trim() || '0.0.0.0';
}

export function buildConfig(env: NodeJS.ProcessEnv) {
  const dataDir = env.DATA_DIR || './data';

  return {
    authToken: env.AUTH_TOKEN || 'change-me-admin-token',
    proxyToken: env.PROXY_TOKEN || 'change-me-proxy-sk-token',
    codexClientId: parseOptionalSecret(env.CODEX_CLIENT_ID) || DEFAULT_CODEX_CLIENT_ID,
    claudeClientId: parseOptionalSecret(env.CLAUDE_CLIENT_ID) || DEFAULT_CLAUDE_CLIENT_ID,
    claudeClientSecret: parseOptionalSecret(env.CLAUDE_CLIENT_SECRET),
    geminiCliClientId: parseOptionalSecret(env.GEMINI_CLI_CLIENT_ID) || DEFAULT_GEMINI_CLI_CLIENT_ID,
    geminiCliClientSecret: parseOptionalSecret(env.GEMINI_CLI_CLIENT_SECRET) || DEFAULT_GEMINI_CLI_CLIENT_SECRET,
    systemProxyUrl: env.SYSTEM_PROXY_URL || '',
    accountCredentialSecret: env.ACCOUNT_CREDENTIAL_SECRET || env.AUTH_TOKEN || 'change-me-admin-token',
    checkinCron: env.CHECKIN_CRON || '0 8 * * *',
    balanceRefreshCron: env.BALANCE_REFRESH_CRON || '0 * * * *',
    logCleanupCron: env.LOG_CLEANUP_CRON || '0 6 * * *',
    logCleanupConfigured: false,
    logCleanupUsageLogsEnabled: parseBoolean(env.LOG_CLEANUP_USAGE_LOGS_ENABLED, false),
    logCleanupProgramLogsEnabled: parseBoolean(env.LOG_CLEANUP_PROGRAM_LOGS_ENABLED, false),
    logCleanupRetentionDays: Math.max(1, Math.trunc(parseNumber(env.LOG_CLEANUP_RETENTION_DAYS, 30))),
    webhookUrl: env.WEBHOOK_URL || '',
    barkUrl: env.BARK_URL || '',
    webhookEnabled: parseBoolean(env.WEBHOOK_ENABLED, true),
    barkEnabled: parseBoolean(env.BARK_ENABLED, true),
    serverChanEnabled: parseBoolean(env.SERVERCHAN_ENABLED, true),
    serverChanKey: env.SERVERCHAN_KEY || '',
    telegramEnabled: parseBoolean(env.TELEGRAM_ENABLED, false),
    telegramApiBaseUrl: 'https://api.telegram.org',
    telegramBotToken: env.TELEGRAM_BOT_TOKEN || '',
    telegramChatId: env.TELEGRAM_CHAT_ID || '',
    smtpEnabled: parseBoolean(env.SMTP_ENABLED, false),
    smtpHost: env.SMTP_HOST || '',
    smtpPort: parseInt(env.SMTP_PORT || '587'),
    smtpSecure: parseBoolean(env.SMTP_SECURE, false),
    smtpUser: env.SMTP_USER || '',
    smtpPass: env.SMTP_PASS || '',
    smtpFrom: env.SMTP_FROM || '',
    smtpTo: env.SMTP_TO || '',
    notifyCooldownSec: Math.max(0, Math.trunc(parseNumber(env.NOTIFY_COOLDOWN_SEC, 300))),
    adminIpAllowlist: parseCsvList(env.ADMIN_IP_ALLOWLIST),
    port: Math.trunc(parseNumber(env.PORT, 4000)),
    listenHost: parseListenHost(env),
    dataDir,
    dbType: parseDbType(env.DB_TYPE),
    dbUrl: (env.DB_URL || '').trim(),
    dbSsl: parseBoolean(env.DB_SSL, false),
    requestBodyLimit: DEFAULT_REQUEST_BODY_LIMIT,
    routingFallbackUnitCost: Math.max(1e-6, parseNumber(env.ROUTING_FALLBACK_UNIT_COST, 1)),
    tokenRouterCacheTtlMs: Math.max(100, Math.trunc(parseNumber(env.TOKEN_ROUTER_CACHE_TTL_MS, 1_500))),
    proxyLogRetentionDays: Math.max(0, Math.trunc(parseNumber(env.PROXY_LOG_RETENTION_DAYS, 30))),
    proxyLogRetentionPruneIntervalMinutes: Math.max(1, Math.trunc(parseNumber(env.PROXY_LOG_RETENTION_PRUNE_INTERVAL_MINUTES, 30))),
    proxyErrorKeywords: parseCsvList(env.PROXY_ERROR_KEYWORDS),
    proxyEmptyContentFailEnabled: parseBoolean(env.PROXY_EMPTY_CONTENT_FAIL, false),
    routingWeights: {
      baseWeightFactor: parseNumber(env.BASE_WEIGHT_FACTOR, 0.5),
      valueScoreFactor: parseNumber(env.VALUE_SCORE_FACTOR, 0.5),
      costWeight: parseNumber(env.COST_WEIGHT, 0.4),
      balanceWeight: parseNumber(env.BALANCE_WEIGHT, 0.3),
      usageWeight: parseNumber(env.USAGE_WEIGHT, 0.3),
    },
  };
}

export const config = buildConfig(process.env);

export function buildFastifyOptions(
  appConfig: ReturnType<typeof buildConfig>,
): FastifyServerOptions {
  return {
    logger: true,
    bodyLimit: appConfig.requestBodyLimit,
  };
}
