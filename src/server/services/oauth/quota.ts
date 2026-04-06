import { randomUUID } from 'node:crypto';
import { eq } from 'drizzle-orm';
import { fetch } from 'undici';
import { db, schema } from '../../db/index.js';
import { mergeAccountExtraConfig } from '../accountExtraConfig.js';
import { runWithSiteApiEndpointPool } from '../siteApiEndpointService.js';
import { withExplicitProxyRequestInit } from '../siteProxy.js';
import {
  buildStoredOauthStateFromAccount,
  getOauthInfoFromAccount,
  type OauthInfo,
} from './oauthAccount.js';
import { resolveOauthAccountProxyUrl } from './requestProxy.js';
import type { OauthQuotaSnapshot, OauthQuotaWindowSnapshot } from './quotaTypes.js';

type CodexJwtClaims = {
  'https://api.openai.com/auth'?: {
    chatgpt_plan_type?: unknown;
    chatgpt_subscription_active_start?: unknown;
    chatgpt_subscription_active_until?: unknown;
  };
};

type HeaderSource = {
  get(name: string): string | null;
} | Record<string, unknown>;

type CodexQuotaHeaderSnapshot = {
  primaryUsedPercent?: number;
  primaryResetAfterSeconds?: number;
  primaryWindowMinutes?: number;
  secondaryUsedPercent?: number;
  secondaryResetAfterSeconds?: number;
  secondaryWindowMinutes?: number;
  capturedAt: string;
};

type NormalizedCodexQuotaHeaders = {
  fiveHour?: {
    usedPercent?: number;
    resetAfterSeconds?: number;
    windowMinutes?: number;
  };
  sevenDay?: {
    usedPercent?: number;
    resetAfterSeconds?: number;
    windowMinutes?: number;
  };
};

const CODEX_QUOTA_PROBE_MODEL = 'gpt-5.1-codex';
const CODEX_QUOTA_PROBE_VERSION = '0.101.0';
const CODEX_QUOTA_PROBE_USER_AGENT = 'codex_cli_rs/0.101.0 (Mac OS 26.0.1; arm64) Apple_Terminal/464';
const CODEX_QUOTA_PROBE_BETA = 'responses-2025-03-11';
const CODEX_QUOTA_PROBE_INSTRUCTIONS = 'You are a helpful assistant.';
const CODEX_QUOTA_PROBE_TIMEOUT_MS = 10_000;
const QUOTA_HEADER_SNAPSHOT_DEDUPE_WINDOW_MS = 30_000;
const recentQuotaHeaderSnapshotByAccount = new Map<number, {
  fingerprint: string;
  recordedAtMs: number;
}>();
const pendingQuotaHeaderSnapshotKeys = new Set<string>();

function asTrimmedString(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  return trimmed || undefined;
}

function getHeaderValue(headers: HeaderSource, key: string): string | undefined {
  if (typeof (headers as { get?: unknown }).get === 'function') {
    const value = (headers as { get(name: string): string | null }).get(key);
    return asTrimmedString(value);
  }

  for (const [candidateKey, candidateValue] of Object.entries(headers)) {
    if (candidateKey.toLowerCase() !== key.toLowerCase()) continue;
    if (typeof candidateValue === 'string') return asTrimmedString(candidateValue);
    if (Array.isArray(candidateValue)) {
      for (const item of candidateValue) {
        const normalized = asTrimmedString(item);
        if (normalized) return normalized;
      }
    }
  }

  return undefined;
}

function asFiniteNumber(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value !== 'string') return undefined;
  const parsed = Number.parseFloat(value.trim());
  return Number.isFinite(parsed) ? parsed : undefined;
}

function asFiniteInteger(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) return Math.trunc(value);
  if (typeof value !== 'string') return undefined;
  const parsed = Number.parseInt(value.trim(), 10);
  return Number.isFinite(parsed) ? parsed : undefined;
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

function roundPercent(value: number): number {
  return Math.round(value * 100) / 100;
}

function addSecondsToIso(baseIso: string, seconds?: number): string | undefined {
  if (typeof seconds !== 'number' || !Number.isFinite(seconds)) return undefined;
  const parsed = Date.parse(baseIso);
  if (Number.isNaN(parsed)) return undefined;
  const clampedSeconds = Math.max(0, Math.trunc(seconds));
  return new Date(parsed + clampedSeconds * 1000).toISOString();
}

function parseCodexQuotaHeaders(
  headers: HeaderSource,
  capturedAt = new Date().toISOString(),
): CodexQuotaHeaderSnapshot | null {
  const snapshot: CodexQuotaHeaderSnapshot = { capturedAt };
  let hasAnyValue = false;

  const assignField = (
    field: keyof Omit<CodexQuotaHeaderSnapshot, 'capturedAt'>,
    value: number | undefined,
  ) => {
    if (typeof value !== 'number' || !Number.isFinite(value)) return;
    snapshot[field] = value as CodexQuotaHeaderSnapshot[keyof Omit<CodexQuotaHeaderSnapshot, 'capturedAt'>];
    hasAnyValue = true;
  };

  assignField('primaryUsedPercent', asFiniteNumber(getHeaderValue(headers, 'x-codex-primary-used-percent')));
  assignField('primaryResetAfterSeconds', asFiniteInteger(getHeaderValue(headers, 'x-codex-primary-reset-after-seconds')));
  assignField('primaryWindowMinutes', asFiniteInteger(getHeaderValue(headers, 'x-codex-primary-window-minutes')));
  assignField('secondaryUsedPercent', asFiniteNumber(getHeaderValue(headers, 'x-codex-secondary-used-percent')));
  assignField('secondaryResetAfterSeconds', asFiniteInteger(getHeaderValue(headers, 'x-codex-secondary-reset-after-seconds')));
  assignField('secondaryWindowMinutes', asFiniteInteger(getHeaderValue(headers, 'x-codex-secondary-window-minutes')));

  return hasAnyValue ? snapshot : null;
}

function normalizeCodexQuotaHeaders(snapshot: CodexQuotaHeaderSnapshot): NormalizedCodexQuotaHeaders | null {
  const primaryWindow = snapshot.primaryWindowMinutes;
  const secondaryWindow = snapshot.secondaryWindowMinutes;
  const hasPrimaryWindow = typeof primaryWindow === 'number' && Number.isFinite(primaryWindow);
  const hasSecondaryWindow = typeof secondaryWindow === 'number' && Number.isFinite(secondaryWindow);

  let fiveHourSource: 'primary' | 'secondary' | null = null;
  let sevenDaySource: 'primary' | 'secondary' | null = null;

  if (hasPrimaryWindow && hasSecondaryWindow) {
    if ((primaryWindow || 0) < (secondaryWindow || 0)) {
      fiveHourSource = 'primary';
      sevenDaySource = 'secondary';
    } else {
      fiveHourSource = 'secondary';
      sevenDaySource = 'primary';
    }
  } else if (hasPrimaryWindow) {
    if ((primaryWindow || 0) <= 360) {
      fiveHourSource = 'primary';
    } else {
      sevenDaySource = 'primary';
    }
  } else if (hasSecondaryWindow) {
    if ((secondaryWindow || 0) <= 360) {
      fiveHourSource = 'secondary';
    } else {
      sevenDaySource = 'secondary';
    }
  } else {
    sevenDaySource = 'primary';
    fiveHourSource = 'secondary';
  }

  const pickSource = (source: 'primary' | 'secondary' | null) => {
    if (!source) return undefined;
    if (source === 'primary') {
      return {
        usedPercent: snapshot.primaryUsedPercent,
        resetAfterSeconds: snapshot.primaryResetAfterSeconds,
        windowMinutes: snapshot.primaryWindowMinutes,
      };
    }
    return {
      usedPercent: snapshot.secondaryUsedPercent,
      resetAfterSeconds: snapshot.secondaryResetAfterSeconds,
      windowMinutes: snapshot.secondaryWindowMinutes,
    };
  };

  const normalized: NormalizedCodexQuotaHeaders = {
    fiveHour: pickSource(fiveHourSource),
    sevenDay: pickSource(sevenDaySource),
  };

  const hasData = !!(
    normalized.fiveHour?.usedPercent !== undefined
    || normalized.fiveHour?.resetAfterSeconds !== undefined
    || normalized.sevenDay?.usedPercent !== undefined
    || normalized.sevenDay?.resetAfterSeconds !== undefined
  );
  return hasData ? normalized : null;
}

function buildCodexQuotaHeadersFingerprint(headers: HeaderSource): string | null {
  const parsed = parseCodexQuotaHeaders(headers, 'fingerprint');
  if (!parsed) return null;
  const { capturedAt: _capturedAt, ...stableFields } = parsed;
  return JSON.stringify(stableFields);
}

function buildCodexWindowFromNormalized(input: {
  usedPercent?: number;
  resetAfterSeconds?: number;
  windowMinutes?: number;
  capturedAt: string;
}): OauthQuotaWindowSnapshot | null {
  const usedPercent = typeof input.usedPercent === 'number' && Number.isFinite(input.usedPercent)
    ? roundPercent(input.usedPercent)
    : undefined;
  const resetAt = addSecondsToIso(input.capturedAt, input.resetAfterSeconds);
  if (usedPercent === undefined && !resetAt) {
    return null;
  }

  return {
    supported: true,
    ...(usedPercent !== undefined
      ? {
        used: usedPercent,
        limit: 100,
        remaining: roundPercent(Math.max(0, 100 - usedPercent)),
      }
      : {}),
    ...(resetAt ? { resetAt } : {}),
    message: typeof input.windowMinutes === 'number' && Number.isFinite(input.windowMinutes)
      ? `codex ${Math.max(0, Math.trunc(input.windowMinutes))}m window inferred from rate limit headers`
      : 'codex window inferred from rate limit headers',
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

function buildQuotaErrorSnapshot(input: {
  oauth: Pick<OauthInfo, 'provider' | 'planType' | 'idToken' | 'quota'>;
  message: string;
  syncedAt: string;
  lastLimitResetAt?: string;
}): OauthQuotaSnapshot {
  const baseSnapshot = buildQuotaSnapshotFromOauthInfo(input.oauth);
  return {
    ...baseSnapshot,
    status: 'error',
    lastSyncAt: input.syncedAt,
    lastError: input.message,
    providerMessage: input.message,
    ...(input.lastLimitResetAt
      ? { lastLimitResetAt: input.lastLimitResetAt }
      : (baseSnapshot.lastLimitResetAt ? { lastLimitResetAt: baseSnapshot.lastLimitResetAt } : {})),
  };
}

export function buildCodexQuotaSnapshotFromHeaders(
  oauth: Pick<OauthInfo, 'provider' | 'planType' | 'idToken' | 'quota'>,
  headers: HeaderSource,
  capturedAt = new Date().toISOString(),
): OauthQuotaSnapshot | null {
  if (oauth.provider !== 'codex') return null;
  const parsedHeaders = parseCodexQuotaHeaders(headers, capturedAt);
  if (!parsedHeaders) return null;
  const normalizedHeaders = normalizeCodexQuotaHeaders(parsedHeaders);
  if (!normalizedHeaders) return null;

  const baseSnapshot = buildQuotaSnapshotFromOauthInfo(oauth);
  const fiveHour = normalizedHeaders.fiveHour
    ? buildCodexWindowFromNormalized({
      ...normalizedHeaders.fiveHour,
      capturedAt: parsedHeaders.capturedAt,
    })
    : null;
  const sevenDay = normalizedHeaders.sevenDay
    ? buildCodexWindowFromNormalized({
      ...normalizedHeaders.sevenDay,
      capturedAt: parsedHeaders.capturedAt,
    })
    : null;
  if (!fiveHour && !sevenDay) return null;

  const lastLimitResetAt = fiveHour?.resetAt || sevenDay?.resetAt || baseSnapshot.lastLimitResetAt;

  return {
    ...baseSnapshot,
    status: 'supported',
    source: 'reverse_engineered',
    lastSyncAt: parsedHeaders.capturedAt,
    lastError: undefined,
    providerMessage: 'codex usage windows inferred from rate limit response headers',
    windows: {
      fiveHour: fiveHour || baseSnapshot.windows.fiveHour,
      sevenDay: sevenDay || baseSnapshot.windows.sevenDay,
    },
    ...(lastLimitResetAt ? { lastLimitResetAt } : {}),
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
  const oauth = getOauthInfoFromAccount(account);
  if (!oauth) {
    throw new Error('account is not managed by oauth');
  }
  const nextExtraConfig = mergeAccountExtraConfig(account.extraConfig, {
    oauth: buildStoredOauthStateFromAccount(account, {
      quota: snapshot,
    }),
  });
  await db.update(schema.accounts).set({
    extraConfig: nextExtraConfig,
    updatedAt: new Date().toISOString(),
  }).where(eq(schema.accounts.id, accountId)).run();
  return snapshot;
}

export async function recordOauthQuotaHeadersSnapshot(input: {
  accountId: number;
  headers: HeaderSource;
}): Promise<OauthQuotaSnapshot | null> {
  const account = await db.select().from(schema.accounts).where(eq(schema.accounts.id, input.accountId)).get();
  if (!account) return null;
  const oauth = getOauthInfoFromAccount(account);
  if (!oauth || oauth.provider !== 'codex') return null;

  const fingerprint = buildCodexQuotaHeadersFingerprint(input.headers);
  if (!fingerprint) return null;
  const nowMs = Date.now();
  const lastRecorded = recentQuotaHeaderSnapshotByAccount.get(input.accountId);
  if (
    lastRecorded
    && lastRecorded.fingerprint === fingerprint
    && nowMs - lastRecorded.recordedAtMs < QUOTA_HEADER_SNAPSHOT_DEDUPE_WINDOW_MS
  ) {
    return buildQuotaSnapshotFromOauthInfo(oauth);
  }
  const pendingKey = `${input.accountId}:${fingerprint}`;
  if (pendingQuotaHeaderSnapshotKeys.has(pendingKey)) {
    return buildQuotaSnapshotFromOauthInfo(oauth);
  }

  const snapshot = buildCodexQuotaSnapshotFromHeaders(oauth, input.headers);
  if (!snapshot) return null;
  pendingQuotaHeaderSnapshotKeys.add(pendingKey);
  try {
    const persisted = await persistQuotaSnapshot(input.accountId, snapshot);
    recentQuotaHeaderSnapshotByAccount.set(input.accountId, {
      fingerprint,
      recordedAtMs: nowMs,
    });
    return persisted;
  } finally {
    pendingQuotaHeaderSnapshotKeys.delete(pendingKey);
  }
}

function buildCodexQuotaProbePayload(): Record<string, unknown> {
  return {
    model: CODEX_QUOTA_PROBE_MODEL,
    input: [
      {
        role: 'user',
        content: [
          {
            type: 'input_text',
            text: 'hi',
          },
        ],
      },
    ],
    stream: true,
    store: false,
    instructions: CODEX_QUOTA_PROBE_INSTRUCTIONS,
  };
}

function buildCodexQuotaProbeUrl(baseUrl: string): string {
  return `${baseUrl.replace(/\/+$/, '')}/responses`;
}

function buildCodexQuotaProbeHeaders(input: {
  accessToken: string;
  accountId?: string;
}): Record<string, string> {
  return {
    Authorization: `Bearer ${input.accessToken.trim()}`,
    'Content-Type': 'application/json',
    Accept: 'text/event-stream',
    Connection: 'Keep-Alive',
    Originator: 'codex_cli_rs',
    Version: CODEX_QUOTA_PROBE_VERSION,
    'User-Agent': CODEX_QUOTA_PROBE_USER_AGENT,
    'OpenAI-Beta': CODEX_QUOTA_PROBE_BETA,
    Session_id: randomUUID(),
    ...(input.accountId ? { 'Chatgpt-Account-Id': input.accountId } : {}),
  };
}

async function probeCodexQuotaSnapshot(input: {
  account: typeof schema.accounts.$inferSelect;
  oauth: OauthInfo;
  syncedAt: string;
}): Promise<OauthQuotaSnapshot> {
  const site = await db.select().from(schema.sites).where(eq(schema.sites.id, input.account.siteId)).get();
  if (!site) {
    throw new Error('oauth site not found');
  }
  const accessToken = (input.account.accessToken || '').trim();
  if (!accessToken) {
    throw new Error('codex oauth access token missing');
  }
  const proxyUrl = await resolveOauthAccountProxyUrl({
    siteId: input.account.siteId,
    extraConfig: input.account.extraConfig,
  });
  const requestBody = JSON.stringify(buildCodexQuotaProbePayload());

  return runWithSiteApiEndpointPool(site, async (target) => {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), CODEX_QUOTA_PROBE_TIMEOUT_MS);
    let response: Awaited<ReturnType<typeof fetch>>;
    try {
      response = await fetch(
        buildCodexQuotaProbeUrl(target.baseUrl),
        withExplicitProxyRequestInit(proxyUrl, {
          method: 'POST',
          headers: buildCodexQuotaProbeHeaders({
            accessToken,
            accountId: input.oauth.accountId || input.oauth.accountKey,
          }),
          body: requestBody,
          signal: controller.signal,
        }),
      );
    } catch (error) {
      if (controller.signal.aborted) {
        throw new Error(`codex quota probe timeout (${Math.round(CODEX_QUOTA_PROBE_TIMEOUT_MS / 1000)}s)`);
      }
      throw error;
    } finally {
      clearTimeout(timeout);
    }

    const snapshot = buildCodexQuotaSnapshotFromHeaders(input.oauth, response.headers, input.syncedAt);
    if (snapshot) {
      const responseBody = response as { body?: { cancel?: () => Promise<void> | void } };
      void Promise.resolve(responseBody.body?.cancel?.()).catch(() => {});
      return snapshot;
    }

    const errorText = await response.text().catch(() => '');
    if (!response.ok) {
      const resetHint = parseCodexQuotaResetHint(response.status, errorText, Date.now());
      return buildQuotaErrorSnapshot({
        oauth: input.oauth,
        message: errorText || `codex quota probe failed with status ${response.status}`,
        syncedAt: input.syncedAt,
        ...(resetHint ? { lastLimitResetAt: resetHint.resetAt } : {}),
      });
    }

    return buildQuotaErrorSnapshot({
      oauth: input.oauth,
      message: 'codex quota probe response did not expose x-codex rate limit headers',
      syncedAt: input.syncedAt,
    });
  });
}

export async function refreshOauthQuotaSnapshot(accountId: number): Promise<OauthQuotaSnapshot> {
  const account = await db.select().from(schema.accounts).where(eq(schema.accounts.id, accountId)).get();
  if (!account) {
    throw new Error('oauth account not found');
  }
  const oauth = getOauthInfoFromAccount(account);
  if (!oauth) {
    throw new Error('account is not managed by oauth');
  }
  if (oauth.provider === 'codex') {
    const syncedAt = new Date().toISOString();
    try {
      const snapshot = await probeCodexQuotaSnapshot({
        account,
        oauth,
        syncedAt,
      });
      return persistQuotaSnapshot(accountId, snapshot);
    } catch (error) {
      const message = error instanceof Error
        ? (error.message || error.name)
        : String(error || 'codex quota probe failed');
      return persistQuotaSnapshot(accountId, buildQuotaErrorSnapshot({
        oauth,
        message,
        syncedAt,
      }));
    }
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
  const oauth = getOauthInfoFromAccount(account);
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
