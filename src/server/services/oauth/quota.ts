import { eq } from 'drizzle-orm';
import { db, schema } from '../../db/index.js';
import { mergeAccountExtraConfig } from '../accountExtraConfig.js';
import { buildOauthInfo, getOauthInfoFromExtraConfig, type OauthInfo } from './oauthAccount.js';
import type { OauthQuotaSnapshot, OauthQuotaWindowSnapshot } from './quotaTypes.js';

type CodexJwtClaims = {
  'https://api.openai.com/auth'?: {
    chatgpt_plan_type?: unknown;
    chatgpt_subscription_active_start?: unknown;
    chatgpt_subscription_active_until?: unknown;
  };
};

function asTrimmedString(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  return trimmed || undefined;
}

function asIsoDateTime(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  if (!trimmed) return undefined;
  const parsed = Date.parse(trimmed);
  return Number.isNaN(parsed) ? undefined : new Date(parsed).toISOString();
}

function parseCodexJwtClaims(idToken?: string): CodexJwtClaims | null {
  if (!idToken) return null;
  const parts = idToken.split('.');
  if (parts.length !== 3) return null;
  try {
    const payload = JSON.parse(Buffer.from(parts[1] || '', 'base64url').toString('utf8')) as unknown;
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return null;
    return payload as CodexJwtClaims;
  } catch {
    return null;
  }
}

function buildUnsupportedWindow(message: string): OauthQuotaWindowSnapshot {
  return { supported: false, message };
}

function buildCodexUnsupportedWindows(): OauthQuotaSnapshot['windows'] {
  return {
    fiveHour: buildUnsupportedWindow('official 5h quota window is not exposed by current codex oauth artifacts'),
    sevenDay: buildUnsupportedWindow('official 7d quota window is not exposed by current codex oauth artifacts'),
  };
}

function buildProviderUnsupportedSnapshot(provider: string): OauthQuotaSnapshot {
  return {
    status: 'unsupported',
    source: 'official',
    providerMessage: `official quota windows are not exposed for ${provider} oauth`,
    windows: {
      fiveHour: buildUnsupportedWindow('official 5h quota window is unavailable for this provider'),
      sevenDay: buildUnsupportedWindow('official 7d quota window is unavailable for this provider'),
    },
  };
}

function normalizeStoredWindow(value: unknown): OauthQuotaWindowSnapshot | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const raw = value as Record<string, unknown>;
  const supported = typeof raw.supported === 'boolean' ? raw.supported : undefined;
  if (supported === undefined) return undefined;
  const pickNumber = (field: string) => {
    const item = raw[field];
    return typeof item === 'number' && Number.isFinite(item) ? item : undefined;
  };
  const normalized: OauthQuotaWindowSnapshot = {
    supported,
  };
  const limit = pickNumber('limit');
  const used = pickNumber('used');
  const remaining = pickNumber('remaining');
  const resetAt = asIsoDateTime(raw.resetAt);
  const message = asTrimmedString(raw.message);
  if (limit !== undefined) normalized.limit = limit;
  if (used !== undefined) normalized.used = used;
  if (remaining !== undefined) normalized.remaining = remaining;
  if (resetAt) normalized.resetAt = resetAt;
  if (message) normalized.message = message;
  return normalized;
}

function normalizeStoredQuotaSnapshot(value: unknown): OauthQuotaSnapshot | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const raw = value as Record<string, unknown>;
  const status = raw.status === 'supported' || raw.status === 'unsupported' || raw.status === 'error'
    ? raw.status
    : undefined;
  const source = raw.source === 'official' || raw.source === 'reverse_engineered'
    ? raw.source
    : undefined;
  const windowsRaw = raw.windows;
  if (!status || !source || !windowsRaw || typeof windowsRaw !== 'object' || Array.isArray(windowsRaw)) {
    return undefined;
  }
  const windowsObject = windowsRaw as Record<string, unknown>;
  const fiveHour = normalizeStoredWindow(windowsObject.fiveHour);
  const sevenDay = normalizeStoredWindow(windowsObject.sevenDay);
  if (!fiveHour || !sevenDay) return undefined;

  const subscriptionRaw = raw.subscription;
  const subscription = subscriptionRaw && typeof subscriptionRaw === 'object' && !Array.isArray(subscriptionRaw)
    ? {
      planType: asTrimmedString((subscriptionRaw as Record<string, unknown>).planType),
      activeStart: asIsoDateTime((subscriptionRaw as Record<string, unknown>).activeStart),
      activeUntil: asIsoDateTime((subscriptionRaw as Record<string, unknown>).activeUntil),
    }
    : undefined;

  return {
    status,
    source,
    ...(asIsoDateTime(raw.lastSyncAt) ? { lastSyncAt: asIsoDateTime(raw.lastSyncAt)! } : {}),
    ...(asTrimmedString(raw.lastError) ? { lastError: asTrimmedString(raw.lastError)! } : {}),
    ...(asTrimmedString(raw.providerMessage) ? { providerMessage: asTrimmedString(raw.providerMessage)! } : {}),
    ...(subscription && (subscription.planType || subscription.activeStart || subscription.activeUntil)
      ? { subscription }
      : {}),
    windows: { fiveHour, sevenDay },
    ...(asIsoDateTime(raw.lastLimitResetAt) ? { lastLimitResetAt: asIsoDateTime(raw.lastLimitResetAt)! } : {}),
  };
}

function buildStoredCodexSnapshot(oauth: Pick<OauthInfo, 'planType' | 'idToken' | 'quota'>): OauthQuotaSnapshot {
  const claims = parseCodexJwtClaims(oauth.idToken);
  const authClaims = claims?.['https://api.openai.com/auth'];
  const storedQuota = normalizeStoredQuotaSnapshot(oauth.quota);
  const subscription = {
    planType: asTrimmedString(authClaims?.chatgpt_plan_type) || oauth.planType,
    activeStart: asIsoDateTime(authClaims?.chatgpt_subscription_active_start),
    activeUntil: asIsoDateTime(authClaims?.chatgpt_subscription_active_until),
  };

  return {
    status: storedQuota?.status || 'supported',
    source: storedQuota?.source || 'reverse_engineered',
    ...(storedQuota?.lastSyncAt ? { lastSyncAt: storedQuota.lastSyncAt } : {}),
    ...(storedQuota?.lastError ? { lastError: storedQuota.lastError } : {}),
    providerMessage: storedQuota?.providerMessage || 'current codex oauth signals do not expose stable 5h/7d remaining values',
    ...((subscription.planType || subscription.activeStart || subscription.activeUntil) ? { subscription } : {}),
    windows: storedQuota?.windows || buildCodexUnsupportedWindows(),
    ...(storedQuota?.lastLimitResetAt ? { lastLimitResetAt: storedQuota.lastLimitResetAt } : {}),
  };
}

export function buildQuotaSnapshotFromOauthInfo(oauth: Pick<OauthInfo, 'provider' | 'planType' | 'idToken' | 'quota'>): OauthQuotaSnapshot {
  if (oauth.provider === 'codex') {
    return buildStoredCodexSnapshot(oauth);
  }
  return buildProviderUnsupportedSnapshot(oauth.provider);
}

export function parseCodexQuotaResetHint(
  statusCode: number,
  errorBody: string | null | undefined,
  nowMs = Date.now(),
): { resetAt: string; message: string } | null {
  if (statusCode !== 429 || !errorBody) return null;
  try {
    const parsed = JSON.parse(errorBody) as Record<string, any>;
    const error = parsed?.error;
    if (!error || typeof error !== 'object' || error.type !== 'usage_limit_reached') {
      return null;
    }
    if (typeof error.resets_at === 'number' && Number.isFinite(error.resets_at) && error.resets_at > 0) {
      return {
        resetAt: new Date(error.resets_at * 1000).toISOString(),
        message: 'codex usage_limit_reached reset hint observed from upstream',
      };
    }
    if (typeof error.resets_in_seconds === 'number' && Number.isFinite(error.resets_in_seconds) && error.resets_in_seconds > 0) {
      return {
        resetAt: new Date(nowMs + error.resets_in_seconds * 1000).toISOString(),
        message: 'codex usage_limit_reached reset hint observed from upstream',
      };
    }
  } catch {
    return null;
  }
  return null;
}

async function persistQuotaSnapshot(accountId: number, snapshot: OauthQuotaSnapshot) {
  const account = await db.select().from(schema.accounts).where(eq(schema.accounts.id, accountId)).get();
  if (!account) {
    throw new Error('oauth account not found');
  }
  const oauth = getOauthInfoFromExtraConfig(account.extraConfig);
  if (!oauth) {
    throw new Error('account is not managed by oauth');
  }
  const nextExtraConfig = mergeAccountExtraConfig(account.extraConfig, {
    oauth: buildOauthInfo(account.extraConfig, {
      quota: snapshot,
    }),
  });
  await db.update(schema.accounts).set({
    extraConfig: nextExtraConfig,
    updatedAt: new Date().toISOString(),
  }).where(eq(schema.accounts.id, accountId)).run();
  return snapshot;
}

export async function refreshOauthQuotaSnapshot(accountId: number): Promise<OauthQuotaSnapshot> {
  const account = await db.select().from(schema.accounts).where(eq(schema.accounts.id, accountId)).get();
  if (!account) {
    throw new Error('oauth account not found');
  }
  const oauth = getOauthInfoFromExtraConfig(account.extraConfig);
  if (!oauth) {
    throw new Error('account is not managed by oauth');
  }
  const baseSnapshot = buildQuotaSnapshotFromOauthInfo(oauth);
  const snapshot: OauthQuotaSnapshot = {
    ...baseSnapshot,
    lastSyncAt: new Date().toISOString(),
    ...(baseSnapshot.status === 'error' ? {} : { lastError: undefined }),
  };
  return persistQuotaSnapshot(accountId, snapshot);
}

export async function recordOauthQuotaResetHint(input: {
  accountId: number;
  statusCode: number;
  errorText?: string | null;
}): Promise<OauthQuotaSnapshot | null> {
  const resetHint = parseCodexQuotaResetHint(input.statusCode, input.errorText);
  if (!resetHint) return null;

  const account = await db.select().from(schema.accounts).where(eq(schema.accounts.id, input.accountId)).get();
  if (!account) return null;
  const oauth = getOauthInfoFromExtraConfig(account.extraConfig);
  if (!oauth || oauth.provider !== 'codex') return null;

  const baseSnapshot = buildQuotaSnapshotFromOauthInfo({
    ...oauth,
    quota: {
      ...normalizeStoredQuotaSnapshot(oauth.quota),
      status: 'supported',
      source: 'reverse_engineered',
      lastLimitResetAt: resetHint.resetAt,
      providerMessage: 'current codex oauth signals do not expose stable 5h/7d remaining values',
      windows: normalizeStoredQuotaSnapshot(oauth.quota)?.windows || buildCodexUnsupportedWindows(),
    },
  });

  return persistQuotaSnapshot(input.accountId, {
    ...baseSnapshot,
    lastSyncAt: new Date().toISOString(),
    lastLimitResetAt: resetHint.resetAt,
  });
}
