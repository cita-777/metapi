import 'dotenv/config';
import type { FastifyServerOptions } from 'fastify';
import { normalizePayloadRulesConfig } from './services/payloadRules.js';

const DEFAULT_REQUEST_BODY_LIMIT = 20 * 1024 * 1024;
const DEFAULT_CODEX_CLIENT_ID = 'app_EMoamEEZ73f0CkXaXp7hrann';
const DEFAULT_CLAUDE_CLIENT_ID = '9d1c250a-e61b-44d9-88ed-5944d1962f5e';
const DEFAULT_GEMINI_CLI_CLIENT_ID = '681255809395-oo8ft2oprdrnp9e3aqf6av3hmdib135j.apps.googleusercontent.com';
const DEFAULT_GEMINI_CLI_CLIENT_SECRET = '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';
export const TOKEN_ROUTER_FAILURE_COOLDOWN_MAX_SEC_CEILING = 30 * 24 * 60 * 60;

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

function parseJsonValue(value: string | undefined): unknown {
  if (!value) return undefined;
  try {
    return JSON.parse(value);
  } catch {
    return undefined;
  }
}

function parseDbType(value: string | undefined): 'sqlite' | 'mysql' | 'postgres' {
  const normalized = (value || 'sqlite').trim().toLowerCase();
  if (normalized === 'mysql') return 'mysql';
  if (normalized === 'postgres' || normalized === 'postgresql') return 'postgres';
  return 'sqlite';
}

export function normalizeTokenRouterFailureCooldownMaxSec(value: unknown): number | null {
  const normalized = Number(value);
  if (!Number.isFinite(normalized) || normalized <= 0) return null;
  return Math.min(
    TOKEN_ROUTER_FAILURE_COOLDOWN_MAX_SEC_CEILING,
    Math.max(1, Math.trunc(normalized)),
  );
}

function parseListenHost(env: NodeJS.ProcessEnv): string {
  return (env.HOST || '0.0.0.0').trim() || '0.0.0.0';
}

export function buildConfig(env: NodeJS.ProcessEnv) {
  const dataDir = env.DATA_DIR || './data';

  return {
    authToken: env.AUTH_TOKEN || 'change-me-admin-token',
    proxyToken: env.PROXY_TOKEN || 'change-me-proxy-sk-token',
    deployHelperToken: parseOptionalSecret(env.DEPLOY_HELPER_TOKEN || env.UPDATE_CENTER_HELPER_TOKEN),
    codexClientId: parseOptionalSecret(env.CODEX_CLIENT_ID) || DEFAULT_CODEX_CLIENT_ID,
    claudeClientId: parseOptionalSecret(env.CLAUDE_CLIENT_ID) || DEFAULT_CLAUDE_CLIENT_ID,
    claudeClientSecret: parseOptionalSecret(env.CLAUDE_CLIENT_SECRET),
    geminiCliClientId: parseOptionalSecret(env.GEMINI_CLI_CLIENT_ID) || DEFAULT_GEMINI_CLI_CLIENT_ID,
    geminiCliClientSecret: parseOptionalSecret(env.GEMINI_CLI_CLIENT_SECRET) || DEFAULT_GEMINI_CLI_CLIENT_SECRET,
    systemProxyUrl: env.SYSTEM_PROXY_URL || '',
    accountCredentialSecret: env.ACCOUNT_CREDENTIAL_SECRET || env.AUTH_TOKEN || 'change-me-admin-token',
    checkinCron: env.CHECKIN_CRON || '0 8 * * *',
    checkinScheduleMode: (env.CHECKIN_SCHEDULE_MODE || 'cron').trim().toLowerCase() === 'interval'
      ? 'interval' as const
      : 'cron' as const,
    checkinIntervalHours: Math.min(8, Math.max(1, Math.trunc(parseNumber(env.CHECKIN_INTERVAL_HOURS, 6)))),
