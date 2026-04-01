import { and, eq, inArray, isNull } from 'drizzle-orm';
import { db, schema } from '../db/index.js';
import { upsertSetting } from '../db/upsertSetting.js';
import {
  config,
  normalizeTokenRouterFailureCooldownMaxSec,
  TOKEN_ROUTER_FAILURE_COOLDOWN_MAX_SEC_CEILING,
} from '../config.js';
import { getCachedModelRoutingReferenceCost, refreshModelPricingCatalog } from './modelPricingService.js';
import { RETRYABLE_TIMEOUT_PATTERNS } from './proxyRetryPolicy.js';
import {
  normalizeRouteRoutingStrategy,
  type RouteRoutingStrategy,
} from './routeRoutingStrategy.js';
import { type DownstreamRoutingPolicy, EMPTY_DOWNSTREAM_ROUTING_POLICY } from './downstreamPolicyTypes.js';
import { isUsableAccountToken } from './accountTokenService.js';
import { getOauthInfoFromAccount } from './oauth/oauthAccount.js';
import { parseCodexQuotaResetHint } from './oauth/quota.js';
import {
  isExactTokenRouteModelPattern,
  isTokenRouteRegexPattern,
  matchesTokenRouteModelPattern,
  parseTokenRouteRegexPattern,
} from '../../shared/tokenRoutePatterns.js';
import {
  normalizeTokenRouteMode,
  type RouteDecision,
  type RouteDecisionCandidate,
  type RouteMode,
} from '../../shared/tokenRouteContract.js';

interface RouteMatch {
  route: RouteRow;
  channels: Array<{
    channel: typeof schema.routeChannels.$inferSelect;
    account: typeof schema.accounts.$inferSelect;
    site: typeof schema.sites.$inferSelect;
    token: typeof schema.accountTokens.$inferSelect | null;
  }>;
}

type RouteChannelCandidate = RouteMatch['channels'][number];

interface SelectedChannel {
  channel: typeof schema.routeChannels.$inferSelect;
  account: typeof schema.accounts.$inferSelect;
  site: typeof schema.sites.$inferSelect;
  token: typeof schema.accountTokens.$inferSelect | null;
  tokenValue: string;
  tokenName: string;
  actualModel: string;
}

type FailureAwareChannel = {
  failCount?: number | null;
  lastFailAt?: string | null;
};

type SiteRuntimeFailureContext = {
  status?: number | null;
  errorText?: string | null;
  modelName?: string | null;
};

type SiteRuntimeHealthState = {
  penaltyScore: number;
  latencyEmaMs: number | null;
  transientFailureStreak: number;
  lastTransientFailureAtMs: number | null;
  breakerLevel: number;
  breakerUntilMs: number | null;
  lastUpdatedAtMs: number;
  lastFailureAtMs: number | null;
  lastSuccessAtMs: number | null;
};

const FAILURE_BACKOFF_BASE_SEC = 15;
const SHORT_WINDOW_LIMIT_COOLDOWN_MS = 5 * 60 * 1000;
// Keep weighted-route backoff within the JavaScript Date range when fail counts grow large.
const MAX_FAILURE_BACKOFF_SEC = 30 * 24 * 60 * 60;
const MIN_EFFECTIVE_UNIT_COST = 1e-6;
const ROUND_ROBIN_FAILURE_THRESHOLD = 3;
const ROUND_ROBIN_COOLDOWN_LEVELS_SEC = [0, 10 * 60, 60 * 60, 24 * 60 * 60] as const;
const SITE_RUNTIME_HEALTH_DECAY_HALF_LIFE_MS = 10 * 60 * 1000;
const SITE_RUNTIME_MIN_MULTIPLIER = 0.08;
const SITE_RUNTIME_LATENCY_BASELINE_MS = 2_500;
const SITE_RUNTIME_LATENCY_WINDOW_MS = 30_000;
const SITE_RUNTIME_MAX_LATENCY_PENALTY = 0.35;
const SITE_RUNTIME_LATENCY_EMA_ALPHA = 0.3;
const SITE_RUNTIME_BREAKER_STREAK_THRESHOLD = 3;
const SITE_RUNTIME_BREAKER_LEVELS_MS = [0, 60_000, 5 * 60_000, 30 * 60 * 1000] as const;
const SITE_TRANSIENT_STREAK_WINDOW_MS = 5 * 60 * 1000;
const SITE_HISTORICAL_HEALTH_MIN_MULTIPLIER = 0.45;
const SITE_HISTORICAL_HEALTH_MAX_SAMPLE = 24;
const SITE_HISTORICAL_LATENCY_BASELINE_MS = 2_000;
const SITE_HISTORICAL_LATENCY_WINDOW_MS = 20_000;
const SITE_HISTORICAL_MAX_LATENCY_PENALTY = 0.18;
const SITE_RUNTIME_HEALTH_SETTING_KEY = 'token_router_site_runtime_health_v1';
const SITE_RUNTIME_HEALTH_PERSIST_DEBOUNCE_MS = 500;
const SITE_RUNTIME_HEALTH_PERSIST_STALE_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const SITE_RUNTIME_HEALTH_PERSIST_IDLE_TTL_MS = 12 * 60 * 60 * 1000;
const SITE_RUNTIME_HEALTH_PERSIST_MIN_PENALTY = 0.02;

const SITE_PROTOCOL_FAILURE_PATTERNS: RegExp[] = [
  /unsupported\s+legacy\s+protocol/i,
  /please\s+use\s+\/v1\/responses/i,
  /please\s+use\s+\/v1\/messages/i,
  /please\s+use\s+\/v1\/chat\/completions/i,
  /does\s+not\s+allow\s+\/v1\/[a-z0-9/_:-]+\s+dispatch/i,
  /unsupported\s+endpoint/i,
  /unsupported\s+path/i,
  /unknown\s+endpoint/i,
  /unrecognized\s+request\s+url/i,
  /no\s+route\s+matched/i,
];

const SITE_MODEL_FAILURE_PATTERNS: RegExp[] = [
  /unsupported\s+model/i,
  /model\s+not\s+supported/i,
  /does\s+not\s+support(?:\s+the)?\s+model/i,
  /no\s+such\s+model/i,
  /unknown\s+model/i,
  /invalid\s+model/i,
  /model.*does\s+not\s+exist/i,
  /当前\s*api\s*不支持所选模型/i,
  /不支持所选模型/i,
];

const SITE_VALIDATION_FAILURE_PATTERNS: RegExp[] = [
  /invalid\s+request\s+body/i,
  /validation/i,
  /missing\s+required/i,
  /required\s+parameter/i,
  /unknown\s+parameter/i,
  /unrecognized\s+(field|key|parameter)/i,
  /malformed/i,
  /invalid\s+json/i,
  /cannot\s+parse/i,
  /unsupported\s+media\s+type/i,
];

const SITE_TRANSIENT_FAILURE_PATTERNS: RegExp[] = [
  /bad\s+gateway/i,
  /gateway\s+time-?out/i,
  ...RETRYABLE_TIMEOUT_PATTERNS,
  /service\s+unavailable/i,
  /temporar(?:y|ily)\s+unavailable/i,
  /cpu\s+overloaded/i,
  /overloaded/i,
  /connection\s+reset/i,
  /connection\s+refused/i,
  /econnreset/i,
  /econnrefused/i,
];

const USAGE_LIMIT_RATE_LIMIT_PATTERNS: RegExp[] = [
  /usage_limit_reached/i,
  /usage\s+limit\s+has\s+been\s+reached/i,
  /quota\s+exceeded/i,
  /rate\s+limit/i,
  /\blimit\b/i,
];

type SiteRuntimeHealthPersistencePayload = {
  version: 1;
  savedAtMs: number;
  globalBySiteId: Record<string, SiteRuntimeHealthState>;
  modelBySiteId: Record<string, Record<string, SiteRuntimeHealthState>>;
};

type SiteRuntimeHealthDetails = {
  globalMultiplier: number;
  modelMultiplier: number;
  combinedMultiplier: number;
  globalBreakerOpen: boolean;
  modelBreakerOpen: boolean;
  modelKey: string;
};

type WeightedSelectionMode = 'weighted' | 'stable_first';

const siteRuntimeHealthStates = new Map<number, SiteRuntimeHealthState>();
const siteModelRuntimeHealthStates = new Map<number, Map<string, SiteRuntimeHealthState>>();
let siteRuntimeHealthLoaded = false;
let siteRuntimeHealthLoadPromise: Promise<void> | null = null;
let siteRuntimeHealthSaveTimer: ReturnType<typeof setTimeout> | null = null;
let siteRuntimeHealthPersistInFlight: Promise<void> | null = null;

function fibonacciNumber(index: number): number {
  if (index <= 2) return 1;
  let prev = 1;
  let current = 1;
  for (let i = 3; i <= index; i += 1) {
    const next = prev + current;
    prev = current;
    current = next;
  }
  return current;
}

/**
 * Weighted-route failures use a Fibonacci backoff, but the resulting cooldown must stay
 * representable as a JavaScript Date for downstream `toISOString()` calls.
 */
function resolveFailureBackoffSec(failCount?: number | null): number {
  const normalizedFailCount = Math.max(1, Math.trunc(failCount ?? 0));
  return Math.min(FAILURE_BACKOFF_BASE_SEC * fibonacciNumber(normalizedFailCount), MAX_FAILURE_BACKOFF_SEC);
}

function resolveConfiguredFailureCooldownMaxMs(): number {
  const normalized = normalizeTokenRouterFailureCooldownMaxSec(config.tokenRouterFailureCooldownMaxSec)
    ?? TOKEN_ROUTER_FAILURE_COOLDOWN_MAX_SEC_CEILING;
  return Math.max(1_000, normalized * 1000);
}

function clampFailureCooldownMs(cooldownMs: number): number {
  const normalized = Math.max(0, Math.trunc(cooldownMs));
  return Math.min(normalized, resolveConfiguredFailureCooldownMaxMs());
}

function resolveEffectiveFailureCooldownMs(failCount?: number | null): number {
  return clampFailureCooldownMs(resolveFailureBackoffSec(failCount) * 1000);
}

function resolveRoundRobinCooldownSec(level: number): number {
  const normalizedLevel = Math.max(0, Math.min(ROUND_ROBIN_COOLDOWN_LEVELS_SEC.length - 1, Math.trunc(level)));
  return ROUND_ROBIN_COOLDOWN_LEVELS_SEC[normalizedLevel] ?? 0;
}

function resolveSiteRuntimeBreakerMs(level: number): number {
  const normalizedLevel = Math.max(0, Math.min(SITE_RUNTIME_BREAKER_LEVELS_MS.length - 1, Math.trunc(level)));
  return SITE_RUNTIME_BREAKER_LEVELS_MS[normalizedLevel] ?? 0;
}

function matchesAnyPattern(patterns: RegExp[], input?: string | null): boolean {
  const text = (input || '').trim();
  if (!text) return false;
  return patterns.some((pattern) => pattern.test(text));
}

function isUsageLimitRateLimitFailure(context: SiteRuntimeFailureContext = {}): boolean {
  const status = typeof context.status === 'number' ? context.status : 0;
  if (status !== 429) return false;
  return matchesAnyPattern(USAGE_LIMIT_RATE_LIMIT_PATTERNS, context.errorText);
}

function clampNumber(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function readFiniteNumber(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

function readFiniteInteger(value: unknown): number | null {
  const normalized = readFiniteNumber(value);
  return normalized == null ? null : Math.trunc(normalized);
}

function readNullableTimestamp(value: unknown): number | null {
  const normalized = readFiniteInteger(value);
  if (normalized == null || normalized <= 0) return null;
  return normalized;
}

function resolveSiteRuntimeFailurePenalty(context: SiteRuntimeFailureContext = {}): number {
  const status = typeof context.status === 'number' ? context.status : 0;
  const errorText = (context.errorText || '').trim();

  if (isUsageLimitRateLimitFailure({ status, errorText })) {
    return 0.4;
  }

  if (status >= 500 || matchesAnyPattern(SITE_TRANSIENT_FAILURE_PATTERNS, errorText)) {
    return 2.5;
  }

  if (status === 429) {
    return 2.2;
  }

  if (status === 401 || status === 403) {
    return 1.8;
  }

  if (matchesAnyPattern(SITE_PROTOCOL_FAILURE_PATTERNS, errorText)) {
    return 0.6;
  }

  if (matchesAnyPattern(SITE_MODEL_FAILURE_PATTERNS, errorText)) {
    return 0.9;
  }

  if (matchesAnyPattern(SITE_VALIDATION_FAILURE_PATTERNS, errorText)) {
    return 0.25;
  }

  if (status >= 400 && status < 500) {
    return 0.9;
  }

  return 1.2;
}

function isTransientSiteRuntimeFailure(context: SiteRuntimeFailureContext = {}): boolean {
  const status = typeof context.status === 'number' ? context.status : 0;
  const errorText = (context.errorText || '').trim();
  if (isUsageLimitRateLimitFailure({ status, errorText })) {
    return false;
  }
  return status >= 500 || status === 429 || matchesAnyPattern(SITE_TRANSIENT_FAILURE_PATTERNS, errorText);
}

function resolveShortWindowLimitCooldown(
  account: typeof schema.accounts.$inferSelect,
  context: SiteRuntimeFailureContext = {},
  nowMs = Date.now(),
): string | null {
  const status = typeof context.status === 'number' ? context.status : 0;
  const errorText = (context.errorText || '').trim();
  if (!isUsageLimitRateLimitFailure({ status, errorText })) return null;

  const resetHint = parseCodexQuotaResetHint(status, errorText, nowMs);
  if (resetHint) {
    const hintMs = Date.parse(resetHint.resetAt);
    if (Number.isFinite(hintMs) && hintMs > nowMs) {
      return new Date(hintMs).toISOString();
    }
  }

  const oauth = getOauthInfoFromAccount(account);
  const storedResetAt = oauth?.quota?.lastLimitResetAt;
  if (oauth?.provider === 'codex' && storedResetAt) {
    const storedMs = Date.parse(storedResetAt);
    if (Number.isFinite(storedMs) && storedMs > nowMs) {
      return new Date(storedMs).toISOString();
    }
  }

  return new Date(nowMs + SHORT_WINDOW_LIMIT_COOLDOWN_MS).toISOString();
}

async function loadCredentialScopedChannelIds(
  channel: typeof schema.routeChannels.$inferSelect,
  accountId: number,
): Promise<number[]> {
  if (typeof channel.tokenId === 'number' && channel.tokenId > 0) {
    const rows = await db.select({ id: schema.routeChannels.id })
      .from(schema.routeChannels)
      .where(eq(schema.routeChannels.tokenId, channel.tokenId))
      .all();
    return rows.map((row) => row.id);
  }

  const rows = await db.select({ id: schema.routeChannels.id })
    .from(schema.routeChannels)
    .where(and(
      eq(schema.routeChannels.accountId, accountId),
      isNull(schema.routeChannels.tokenId),
    ))
    .all();
  return rows.map((row) => row.id);
}

function getDecayedSiteRuntimePenalty(state: SiteRuntimeHealthState, nowMs: number): number {
  if (!Number.isFinite(state.penaltyScore) || state.penaltyScore <= 0) return 0;
  const elapsedMs = Math.max(0, nowMs - state.lastUpdatedAtMs);
  if (elapsedMs <= 0) return state.penaltyScore;
  const decayFactor = Math.pow(0.5, elapsedMs / SITE_RUNTIME_HEALTH_DECAY_HALF_LIFE_MS);
  return state.penaltyScore * decayFactor;
}

function hydrateSiteRuntimeHealthState(raw: unknown): SiteRuntimeHealthState | null {
  if (!isRecord(raw)) return null;

  const lastUpdatedAtMs = readFiniteInteger(raw.lastUpdatedAtMs) ?? Date.now();
  return {
    penaltyScore: Math.max(0, readFiniteNumber(raw.penaltyScore) ?? 0),
    latencyEmaMs: readFiniteNumber(raw.latencyEmaMs),
    transientFailureStreak: Math.max(0, readFiniteInteger(raw.transientFailureStreak) ?? 0),
    lastTransientFailureAtMs: readNullableTimestamp(raw.lastTransientFailureAtMs),
    breakerLevel: Math.max(0, readFiniteInteger(raw.breakerLevel) ?? 0),
    breakerUntilMs: readNullableTimestamp(raw.breakerUntilMs),
    lastUpdatedAtMs: Math.max(0, lastUpdatedAtMs),
    lastFailureAtMs: readNullableTimestamp(raw.lastFailureAtMs),
    lastSuccessAtMs: readNullableTimestamp(raw.lastSuccessAtMs),
  };
}

function cloneSiteRuntimeHealthState(state: SiteRuntimeHealthState): SiteRuntimeHealthState {
  return {
    penaltyScore: state.penaltyScore,
    latencyEmaMs: state.latencyEmaMs,
    transientFailureStreak: state.transientFailureStreak,
    lastTransientFailureAtMs: state.lastTransientFailureAtMs,
    breakerLevel: state.breakerLevel,
    breakerUntilMs: state.breakerUntilMs,
    lastUpdatedAtMs: state.lastUpdatedAtMs,
    lastFailureAtMs: state.lastFailureAtMs,
    lastSuccessAtMs: state.lastSuccessAtMs,
  };
}

function getOrCreateRuntimeHealthState<K>(states: Map<K, SiteRuntimeHealthState>, key: K, nowMs = Date.now()): SiteRuntimeHealthState {
  const existing = states.get(key);
  if (!existing) {
    const initial: SiteRuntimeHealthState = {
      penaltyScore: 0,
      latencyEmaMs: null,
      transientFailureStreak: 0,
      lastTransientFailureAtMs: null,
      breakerLevel: 0,
      breakerUntilMs: null,
      lastUpdatedAtMs: nowMs,
      lastFailureAtMs: null,
      lastSuccessAtMs: null,
    };
    states.set(key, initial);
    return initial;
  }

  const nextPenalty = getDecayedSiteRuntimePenalty(existing, nowMs);
  if (nextPenalty !== existing.penaltyScore || existing.lastUpdatedAtMs !== nowMs) {
    existing.penaltyScore = nextPenalty;
    existing.lastUpdatedAtMs = nowMs;
  }
  return existing;
}

function getOrCreateSiteRuntimeHealthState(siteId: number, nowMs = Date.now()): SiteRuntimeHealthState {
  return getOrCreateRuntimeHealthState(siteRuntimeHealthStates, siteId, nowMs);
}

function getSiteModelRuntimeHealthState(siteId: number, modelName?: string | null): SiteRuntimeHealthState | null {
  const modelKey = normalizeModelAlias(modelName || '');
  if (!modelKey) return null;
  return siteModelRuntimeHealthStates.get(siteId)?.get(modelKey) ?? null;
}

function getOrCreateSiteModelRuntimeHealthState(
  siteId: number,
  modelName?: string | null,
  nowMs = Date.now(),
): SiteRuntimeHealthState | null {
  const modelKey = normalizeModelAlias(modelName || '');
  if (!modelKey) return null;
  let modelStates = siteModelRuntimeHealthStates.get(siteId);
  if (!modelStates) {
    modelStates = new Map<string, SiteRuntimeHealthState>();
    siteModelRuntimeHealthStates.set(siteId, modelStates);
  }
  return getOrCreateRuntimeHealthState(modelStates, modelKey, nowMs);
}

function isRuntimeHealthBreakerOpen(state: SiteRuntimeHealthState | null | undefined, nowMs = Date.now()): boolean {
  if (!state) return false;
  return typeof state.breakerUntilMs === 'number' && state.breakerUntilMs > nowMs;
}

function getRuntimeHealthMultiplier(state: SiteRuntimeHealthState | null | undefined, nowMs = Date.now()): number {
  if (!state) return 1;
  if (isRuntimeHealthBreakerOpen(state, nowMs)) {
    return SITE_RUNTIME_MIN_MULTIPLIER;
  }
  const penaltyScore = getDecayedSiteRuntimePenalty(state, nowMs);
  const failurePenaltyFactor = 1 / (1 + penaltyScore);
  const latencyPenaltyRatio = state.latencyEmaMs == null
    ? 0
    : clampNumber(
      (state.latencyEmaMs - SITE_RUNTIME_LATENCY_BASELINE_MS) / SITE_RUNTIME_LATENCY_WINDOW_MS,
      0,
      1,
    );
  const latencyFactor = 1 - (latencyPenaltyRatio * SITE_RUNTIME_MAX_LATENCY_PENALTY);
  return clampNumber(failurePenaltyFactor * latencyFactor, SITE_RUNTIME_MIN_MULTIPLIER, 1);
}

function getSiteRuntimeHealthDetails(siteId: number, modelName?: string | null, nowMs = Date.now()): SiteRuntimeHealthDetails {
  const modelKey = normalizeModelAlias(modelName || '');
  const globalState = siteRuntimeHealthStates.get(siteId);
  const modelState = modelKey ? getSiteModelRuntimeHealthState(siteId, modelKey) : null;
  const globalMultiplier = getRuntimeHealthMultiplier(globalState, nowMs);
  const modelMultiplier = modelState ? getRuntimeHealthMultiplier(modelState, nowMs) : 1;
  return {
    globalMultiplier,
    modelMultiplier,
    combinedMultiplier: clampNumber(
      globalMultiplier * modelMultiplier,
      SITE_RUNTIME_MIN_MULTIPLIER * SITE_RUNTIME_MIN_MULTIPLIER,
      1,
    ),
    globalBreakerOpen: isRuntimeHealthBreakerOpen(globalState, nowMs),
    modelBreakerOpen: isRuntimeHealthBreakerOpen(modelState, nowMs),
    modelKey,
  };
}

function applyRuntimeHealthFailure(state: SiteRuntimeHealthState, context: SiteRuntimeFailureContext = {}, nowMs = Date.now()): void {
  state.penaltyScore += resolveSiteRuntimeFailurePenalty(context);
  if (isTransientSiteRuntimeFailure(context)) {
    const lastTransientFailureAtMs = state.lastTransientFailureAtMs;
    const shouldContinueStreak = (
      typeof lastTransientFailureAtMs === 'number'
      && (nowMs - lastTransientFailureAtMs) <= SITE_TRANSIENT_STREAK_WINDOW_MS
    );
    state.transientFailureStreak = shouldContinueStreak
      ? state.transientFailureStreak + 1
      : 1;
    state.lastTransientFailureAtMs = nowMs;
    if (state.transientFailureStreak >= SITE_RUNTIME_BREAKER_STREAK_THRESHOLD) {
      state.breakerLevel = Math.min(state.breakerLevel + 1, SITE_RUNTIME_BREAKER_LEVELS_MS.length - 1);
      const breakerMs = resolveSiteRuntimeBreakerMs(state.breakerLevel);
      state.breakerUntilMs = breakerMs > 0 ? nowMs + breakerMs : null;
      state.transientFailureStreak = 0;
    }
  } else {
    state.transientFailureStreak = 0;
    state.lastTransientFailureAtMs = null;
  }
  state.lastFailureAtMs = nowMs;
}

function applyRuntimeHealthSuccess(state: SiteRuntimeHealthState, latencyMs: number, nowMs = Date.now()): void {
  state.penaltyScore = Math.max(0, state.penaltyScore * 0.2 - 0.3);
  state.transientFailureStreak = 0;
  state.lastTransientFailureAtMs = null;
  state.breakerLevel = 0;
  state.breakerUntilMs = null;
  state.lastSuccessAtMs = nowMs;
  const normalizedLatencyMs = Math.max(0, Math.trunc(latencyMs));
  state.latencyEmaMs = state.latencyEmaMs == null
    ? normalizedLatencyMs
    : (state.latencyEmaMs * (1 - SITE_RUNTIME_LATENCY_EMA_ALPHA))
      + (normalizedLatencyMs * SITE_RUNTIME_LATENCY_EMA_ALPHA);
}

function shouldPersistSiteRuntimeHealthState(state: SiteRuntimeHealthState, nowMs = Date.now()): boolean {
  const lastTouchedAtMs = Math.max(
    state.lastUpdatedAtMs,
    state.lastFailureAtMs ?? 0,
    state.lastSuccessAtMs ?? 0,
    state.lastTransientFailureAtMs ?? 0,
  );
  if ((nowMs - lastTouchedAtMs) > SITE_RUNTIME_HEALTH_PERSIST_STALE_TTL_MS) {
    return false;
  }

  if (isRuntimeHealthBreakerOpen(state, nowMs)) return true;
  if (getDecayedSiteRuntimePenalty(state, nowMs) >= SITE_RUNTIME_HEALTH_PERSIST_MIN_PENALTY) return true;
  if ((state.latencyEmaMs ?? 0) > 0) return true;
  return (nowMs - lastTouchedAtMs) <= SITE_RUNTIME_HEALTH_PERSIST_IDLE_TTL_MS;
}

function buildSiteRuntimeHealthPersistencePayload(nowMs = Date.now()): SiteRuntimeHealthPersistencePayload {
  const globalBySiteId: Record<string, SiteRuntimeHealthState> = {};
  const modelBySiteId: Record<string, Record<string, SiteRuntimeHealthState>> = {};

  for (const [siteId, state] of siteRuntimeHealthStates.entries()) {
    if (!shouldPersistSiteRuntimeHealthState(state, nowMs)) continue;
    globalBySiteId[String(siteId)] = cloneSiteRuntimeHealthState(state);
  }

  for (const [siteId, modelStates] of siteModelRuntimeHealthStates.entries()) {
    const persistedModels: Record<string, SiteRuntimeHealthState> = {};
    for (const [modelKey, state] of modelStates.entries()) {
      if (!shouldPersistSiteRuntimeHealthState(state, nowMs)) continue;
      persistedModels[modelKey] = cloneSiteRuntimeHealthState(state);
    }
    if (Object.keys(persistedModels).length > 0) {
      modelBySiteId[String(siteId)] = persistedModels;
    }
  }

  return {
    version: 1,
    savedAtMs: nowMs,
    globalBySiteId,
    modelBySiteId,
  };
}

async function persistSiteRuntimeHealthState(): Promise<void> {
  if (siteRuntimeHealthPersistInFlight) {
    await siteRuntimeHealthPersistInFlight;
    return;
  }
  const persistTask = (async () => {
    const payload = buildSiteRuntimeHealthPersistencePayload();
    await upsertSetting(SITE_RUNTIME_HEALTH_SETTING_KEY, payload);
  })();
  siteRuntimeHealthPersistInFlight = persistTask.finally(() => {
    if (siteRuntimeHealthPersistInFlight === persistTask) {
      siteRuntimeHealthPersistInFlight = null;
    }
  });
  await siteRuntimeHealthPersistInFlight;
}

function scheduleSiteRuntimeHealthPersistence(): void {
  if (siteRuntimeHealthSaveTimer) return;
  siteRuntimeHealthSaveTimer = setTimeout(() => {
    siteRuntimeHealthSaveTimer = null;
    void persistSiteRuntimeHealthState().catch((error) => {
      console.error('Failed to persist site runtime health state', error);
    });
  }, SITE_RUNTIME_HEALTH_PERSIST_DEBOUNCE_MS);
}

async function loadSiteRuntimeHealthStateFromSettings(): Promise<void> {
  siteRuntimeHealthStates.clear();
  siteModelRuntimeHealthStates.clear();

  const row = await db.select({ value: schema.settings.value })
    .from(schema.settings)
    .where(eq(schema.settings.key, SITE_RUNTIME_HEALTH_SETTING_KEY))
    .get();
  if (!row?.value) return;

  let parsed: unknown;
  try {
    parsed = JSON.parse(row.value);
  } catch {
    return;
  }
  if (!isRecord(parsed)) return;

  const globalBySiteId = isRecord(parsed.globalBySiteId) ? parsed.globalBySiteId : {};
  for (const [siteIdKey, stateRaw] of Object.entries(globalBySiteId)) {
    const siteId = Number(siteIdKey);
    if (!Number.isFinite(siteId) || siteId <= 0) continue;
    const state = hydrateSiteRuntimeHealthState(stateRaw);
    if (!state) continue;
    siteRuntimeHealthStates.set(siteId, state);
  }

  const modelBySiteId = isRecord(parsed.modelBySiteId) ? parsed.modelBySiteId : {};
  for (const [siteIdKey, modelStatesRaw] of Object.entries(modelBySiteId)) {
    const siteId = Number(siteIdKey);
    if (!Number.isFinite(siteId) || siteId <= 0 || !isRecord(modelStatesRaw)) continue;
    const hydratedModelStates = new Map<string, SiteRuntimeHealthState>();
    for (const [rawModelKey, stateRaw] of Object.entries(modelStatesRaw)) {
      const modelKey = normalizeModelAlias(rawModelKey);
      if (!modelKey) continue;
      const state = hydrateSiteRuntimeHealthState(stateRaw);
      if (!state) continue;
      hydratedModelStates.set(modelKey, state);
    }
    if (hydratedModelStates.size > 0) {
      siteModelRuntimeHealthStates.set(siteId, hydratedModelStates);
    }
  }
}

async function ensureSiteRuntimeHealthStateLoaded(): Promise<void> {
  if (siteRuntimeHealthLoaded) return;
  if (!siteRuntimeHealthLoadPromise) {
    siteRuntimeHealthLoadPromise = (async () => {
      try {
        await loadSiteRuntimeHealthStateFromSettings();
        siteRuntimeHealthLoaded = true;
      } catch (error) {
        console.warn('Failed to restore site runtime health state from settings', error);
        siteRuntimeHealthLoadPromise = null;
        siteRuntimeHealthLoaded = false;
      }
    })();
  }
  await siteRuntimeHealthLoadPromise;
}

function recordSiteRuntimeFailure(siteId: number, context: SiteRuntimeFailureContext = {}, nowMs = Date.now()): void {
  applyRuntimeHealthFailure(getOrCreateSiteRuntimeHealthState(siteId, nowMs), context, nowMs);
  const modelState = getOrCreateSiteModelRuntimeHealthState(siteId, context.modelName, nowMs);
  if (modelState) {
    applyRuntimeHealthFailure(modelState, context, nowMs);
  }
  scheduleSiteRuntimeHealthPersistence();
}

function recordSiteRuntimeSuccess(siteId: number, latencyMs: number, modelName?: string | null, nowMs = Date.now()): void {
  applyRuntimeHealthSuccess(getOrCreateSiteRuntimeHealthState(siteId, nowMs), latencyMs, nowMs);
  const modelState = getOrCreateSiteModelRuntimeHealthState(siteId, modelName, nowMs);
  if (modelState) {
    applyRuntimeHealthSuccess(modelState, latencyMs, nowMs);
  }
  scheduleSiteRuntimeHealthPersistence();
}

export function resetSiteRuntimeHealthState(): void {
  siteRuntimeHealthStates.clear();
  siteModelRuntimeHealthStates.clear();
  siteRuntimeHealthLoaded = false;
  siteRuntimeHealthLoadPromise = null;
  if (siteRuntimeHealthSaveTimer) {
    clearTimeout(siteRuntimeHealthSaveTimer);
    siteRuntimeHealthSaveTimer = null;
  }
  siteRuntimeHealthPersistInFlight = null;
}

export async function flushSiteRuntimeHealthPersistence(): Promise<void> {
  if (siteRuntimeHealthSaveTimer) {
    clearTimeout(siteRuntimeHealthSaveTimer);
    siteRuntimeHealthSaveTimer = null;
    await persistSiteRuntimeHealthState();
    return;
  }
  if (siteRuntimeHealthPersistInFlight) {
    await siteRuntimeHealthPersistInFlight;
  }
}

function clearRuntimeHealthStatesForChannels(rows: Array<{
  siteId: number;
  sourceModel: string | null;
  routeModelPattern: string;
}>): boolean {
  let changed = false;
  const modelKeysBySiteId = new Map<number, Set<string>>();

  for (const row of rows) {
    if (siteRuntimeHealthStates.delete(row.siteId)) {
      changed = true;
    }

    const resolvedModelName = normalizeChannelSourceModel(row.sourceModel)
      || (isExactRouteModelPattern(row.routeModelPattern) ? row.routeModelPattern.trim() : '');
    const modelKey = normalizeModelAlias(resolvedModelName);
    if (!modelKey) continue;
    if (!modelKeysBySiteId.has(row.siteId)) {
      modelKeysBySiteId.set(row.siteId, new Set());
    }
    modelKeysBySiteId.get(row.siteId)!.add(modelKey);
  }

  for (const [siteId, modelKeys] of modelKeysBySiteId.entries()) {
    const modelStates = siteModelRuntimeHealthStates.get(siteId);
    if (!modelStates) continue;
    for (const modelKey of modelKeys) {
      if (modelStates.delete(modelKey)) {
        changed = true;
      }
    }
    if (modelStates.size === 0) {
      siteModelRuntimeHealthStates.delete(siteId);
    }
  }

  return changed;
}

export function getSiteRuntimeHealthMultiplier(siteId: number, nowMs = Date.now()): number {
  const state = siteRuntimeHealthStates.get(siteId);
  return getRuntimeHealthMultiplier(state, nowMs);
}

export function isSiteRuntimeBreakerOpen(siteId: number, nowMs = Date.now()): boolean {
  const state = siteRuntimeHealthStates.get(siteId);
  return isRuntimeHealthBreakerOpen(state, nowMs);
}

export function filterSiteRuntimeBrokenCandidates<T extends { site: { id: number } }>(
  candidates: T[],
  nowMs = Date.now(),
): T[] {
  if (candidates.length <= 1) return candidates;
  const healthy = candidates.filter((candidate) => !isSiteRuntimeBreakerOpen(candidate.site.id, nowMs));
  return healthy.length > 0 ? healthy : candidates;
}

function buildRuntimeBreakerReason(details: SiteRuntimeHealthDetails): string {
  if (details.globalBreakerOpen && details.modelBreakerOpen) {
    return '站点熔断中，模型熔断中，优先避让';
  }
  if (details.globalBreakerOpen) {
    return '站点熔断中，优先避让';
  }
  if (details.modelBreakerOpen) {
    return '模型熔断中，优先避让';
  }
  return '运行时熔断中，优先避让';
}

function filterSiteRuntimeBrokenCandidatesByModel(
  candidates: RouteChannelCandidate[],
  modelName: string | ((candidate: RouteChannelCandidate) => string),
  nowMs = Date.now(),
): {
  candidates: RouteChannelCandidate[];
  avoided: Array<{ candidate: RouteChannelCandidate; reason: string }>;
} {
  if (candidates.length <= 1) {
    return {
      candidates,
      avoided: [],
    };
  }

  const resolveModelName = typeof modelName === 'function'
    ? modelName
    : (() => modelName);
  const avoided: Array<{ candidate: RouteChannelCandidate; reason: string }> = [];
  const healthy = candidates.filter((candidate) => {
    const details = getSiteRuntimeHealthDetails(candidate.site.id, resolveModelName(candidate), nowMs);
    const blocked = details.globalBreakerOpen || details.modelBreakerOpen;
    if (blocked) {
      avoided.push({
        candidate,
        reason: buildRuntimeBreakerReason(details),
      });
    }
    return !blocked;
  });

  return healthy.length > 0
    ? {
      candidates: healthy,
      avoided,
    }
    : {
      candidates,
      avoided: [],
    };
}

type RouteRow = typeof schema.tokenRoutes.$inferSelect & {
  routeMode: RouteMode;
  sourceRouteIds: number[];
};
type ChannelRow = typeof schema.routeChannels.$inferSelect;

type RouteCacheSnapshot = {
  loadedAt: number;
  routes: RouteRow[];
};

type RouteMatchCacheSnapshot = {
  loadedAt: number;
  match: RouteMatch;
};

let routeCacheSnapshot: RouteCacheSnapshot = {
  loadedAt: 0,
  routes: [],
};

const routeMatchCache = new Map<number, RouteMatchCacheSnapshot>();

function resolveTokenRouterCacheTtlMs(): number {
  const raw = Math.trunc(config.tokenRouterCacheTtlMs || 0);
  return Math.max(100, raw);
}

function isCacheFresh(loadedAt: number, nowMs: number): boolean {
  return nowMs - loadedAt < resolveTokenRouterCacheTtlMs();
}

async function loadEnabledRoutes(nowMs = Date.now()): Promise<RouteRow[]> {
  if (isCacheFresh(routeCacheSnapshot.loadedAt, nowMs)) {
    return routeCacheSnapshot.routes;
  }

  const rawRoutes = await db.select().from(schema.tokenRoutes)
    .where(eq(schema.tokenRoutes.enabled, true))
    .all();
  const explicitGroupRouteIds = rawRoutes
    .filter((route) => normalizeRouteMode(route.routeMode) === 'explicit_group')
    .map((route) => route.id);
  const sourceRows = explicitGroupRouteIds.length > 0
    ? await db.select().from(schema.routeGroupSources)
      .where(inArray(schema.routeGroupSources.groupRouteId, explicitGroupRouteIds))
      .all()
    : [];
  const sourceIdsByRouteId = new Map<number, number[]>();
  for (const row of sourceRows) {
    if (!sourceIdsByRouteId.has(row.groupRouteId)) {
      sourceIdsByRouteId.set(row.groupRouteId, []);
    }
    sourceIdsByRouteId.get(row.groupRouteId)!.push(row.sourceRouteId);
  }
  const routes = rawRoutes.map((route) => ({
    ...route,
    routeMode: normalizeRouteMode(route.routeMode),
    sourceRouteIds: Array.from(new Set(sourceIdsByRouteId.get(route.id) ?? [])),
  }));
  routeCacheSnapshot = {
    loadedAt: nowMs,
    routes,
  };
  return routes;
}

async function loadRouteMatch(route: RouteRow, nowMs = Date.now()): Promise<RouteMatch> {
  const cached = routeMatchCache.get(route.id);
  if (cached && isCacheFresh(cached.loadedAt, nowMs)) {
    return cached.match;
  }

  const enabledRoutes = await loadEnabledRoutes(nowMs);
  const routeIds = (() => {
    if (!isExplicitGroupRoute(route)) {
      return [route.id];
    }
    return Array.from(new Set(route.sourceRouteIds.filter((routeId) => Number.isFinite(routeId) && routeId > 0)));
  })();
  const enabledSourceRoutes = isExplicitGroupRoute(route)
    ? enabledRoutes.filter((item) => (
      routeIds.includes(item.id)
      && !isExplicitGroupRoute(item)
      && isExactRouteModelPattern(item.modelPattern)
    ))
    : enabledRoutes.filter((item) => routeIds.includes(item.id));
  const enabledSourceRouteIds = enabledSourceRoutes.map((item) => item.id);
  const fallbackSourceModelByRouteId = new Map<number, string>(
    enabledSourceRoutes
      .filter((item) => isExactRouteModelPattern(item.modelPattern))
      .map((item) => [item.id, (item.modelPattern || '').trim()]),
  );
  const channels = enabledSourceRouteIds.length > 0
    ? await db
      .select()
      .from(schema.routeChannels)
      .innerJoin(schema.accounts, eq(schema.routeChannels.accountId, schema.accounts.id))
      .innerJoin(schema.sites, eq(schema.accounts.siteId, schema.sites.id))
      .leftJoin(schema.accountTokens, eq(schema.routeChannels.tokenId, schema.accountTokens.id))
      .where(inArray(schema.routeChannels.routeId, enabledSourceRouteIds))
      .all()
    : [];

  const mapped = channels.map((row) => ({
    channel: {
      ...row.route_channels,
      sourceModel: normalizeChannelSourceModel(row.route_channels.sourceModel)
        || fallbackSourceModelByRouteId.get(row.route_channels.routeId)
        || null,
    },
    account: row.accounts,
    site: row.sites,
    token: row.account_tokens,
  }));

  const match = { route, channels: mapped };
  routeMatchCache.set(route.id, {
    loadedAt: nowMs,
    match,
  });
  return match;
}

function patchCachedChannel(channelId: number, apply: (channel: ChannelRow) => void): void {
  for (const entry of routeMatchCache.values()) {
    const target = entry.match.channels.find((item) => item.channel.id === channelId);
    if (!target) continue;
    apply(target.channel);
    break;
  }
}

export function invalidateTokenRouterCache(): void {
  routeCacheSnapshot = {
    loadedAt: 0,
    routes: [],
  };
  routeMatchCache.clear();
}

function isSiteDisabled(status?: string | null): boolean {
  return (status || 'active') === 'disabled';
}

export function isChannelRecentlyFailed(
  channel: FailureAwareChannel,
  nowMs = Date.now(),
  avoidSec = resolveFailureBackoffSec(channel.failCount),
): boolean {
  const avoidMs = clampFailureCooldownMs(avoidSec * 1000);
  if (avoidMs <= 0) return false;
  if ((channel.failCount ?? 0) <= 0) return false;
  if (!channel.lastFailAt) return false;

  const failTs = Date.parse(channel.lastFailAt);
  if (Number.isNaN(failTs)) return false;

  return nowMs - failTs < avoidMs;
}

export function filterRecentlyFailedCandidates<T extends { channel: FailureAwareChannel }>(
  candidates: T[],
  nowMs = Date.now(),
  avoidSec?: number,
): T[] {
  if (candidates.length <= 1) return candidates;
  if (avoidSec == null || avoidSec <= 0) return candidates;

  const healthy = candidates.filter((candidate) => !isChannelRecentlyFailed(candidate.channel, nowMs, avoidSec));
  // If all channels failed recently, keep them all and let weight/random decide.
  return healthy.length > 0 ? healthy : candidates;
}

export type RouteDecisionExplanation = RouteDecision & {
  routeId?: number;
  modelPattern?: string;
  selectedAccountId?: number;
};

const DEFAULT_DOWNSTREAM_POLICY: DownstreamRoutingPolicy = EMPTY_DOWNSTREAM_ROUTING_POLICY;

type ExplainSelectionOptions = {
  excludeChannelIds?: number[];
  bypassSourceModelCheck?: boolean;
  useChannelSourceModelForCost?: boolean;
  downstreamPolicy?: DownstreamRoutingPolicy;
};

type PricingReferenceRefreshOptions = {
  useChannelSourceModelForCost?: boolean;
  downstreamPolicy?: DownstreamRoutingPolicy;
  refreshedKeys?: Set<string>;
};

type CandidateEligibilityOptions = {
  requestedModel: string;
  bypassSourceModelCheck?: boolean;
  excludeChannelIds?: number[];
  nowIso?: string;
};

type CostSignal = {
  unitCost: number;
  source: 'observed' | 'configured' | 'catalog' | 'fallback';
};

export function isRegexModelPattern(pattern: string): boolean {
  return isTokenRouteRegexPattern(pattern);
}

export function parseRegexModelPattern(pattern: string): { test(value: string): boolean } | null {
  return parseTokenRouteRegexPattern(pattern).regex;
}

export function matchesModelPattern(model: string, pattern: string): boolean {
  return matchesTokenRouteModelPattern(model, pattern);
}

function isExactRouteModelPattern(pattern: string): boolean {
  return isExactTokenRouteModelPattern(pattern);
}

function normalizeRouteMode(routeMode: string | null | undefined): RouteMode {
  return normalizeTokenRouteMode(routeMode);
}

function isExplicitGroupRoute(route: Pick<RouteRow, 'routeMode'> | Pick<typeof schema.tokenRoutes.$inferSelect, 'routeMode'>): boolean {
  return normalizeRouteMode(route.routeMode) === 'explicit_group';
}

function normalizeRouteDisplayName(displayName: string | null | undefined): string {
  return (displayName || '').trim();
}

function isRouteDisplayNameMatch(model: string, displayName: string | null | undefined): boolean {
  const alias = normalizeRouteDisplayName(displayName);
  return !!alias && alias === model;
}

function matchesRouteRequestModel(model: string, route: RouteRow): boolean {
  if (isExplicitGroupRoute(route)) {
    return isRouteDisplayNameMatch(model, route.displayName);
  }
  return matchesModelPattern(model, route.modelPattern) || isRouteDisplayNameMatch(model, route.displayName);
}

function getExposedModelNameForRoute(route: RouteRow): string {
  return normalizeRouteDisplayName(route.displayName) || route.modelPattern;
}

function hasCustomDisplayName(route: Pick<RouteRow, 'modelPattern' | 'displayName'>): boolean {
  const displayName = normalizeRouteDisplayName(route.displayName);
  const modelPattern = (route.modelPattern || '').trim();
  return !!displayName && displayName !== modelPattern;
}

function buildVisibleEnabledRoutes(routes: RouteRow[]): RouteRow[] {
  const exactModelNames = new Set(
    routes
      .filter((route) => !isExplicitGroupRoute(route) && isExactRouteModelPattern(route.modelPattern))
      .map((route) => (route.modelPattern || '').trim())
      .filter(Boolean),
  );
  const coveringGroups = routes.filter((route) => (
    route.enabled
    && (
      (isExplicitGroupRoute(route) && normalizeRouteDisplayName(route.displayName).length > 0 && route.sourceRouteIds.length > 0)
      || (!isExplicitGroupRoute(route) && !isExactRouteModelPattern(route.modelPattern) && hasCustomDisplayName(route))
    )
  ));

  if (coveringGroups.length === 0) return routes;

  return routes.filter((route) => {
    if (isExplicitGroupRoute(route)) {
      return normalizeRouteDisplayName(route.displayName).length > 0;
    }
    if (!isExactRouteModelPattern(route.modelPattern)) return true;
    if (hasCustomDisplayName(route)) return true;

    const exactModel = (route.modelPattern || '').trim();
    if (!exactModel) return true;

    return !coveringGroups.some((groupRoute) => {
      if (groupRoute.id === route.id) return false;
      const groupDisplayName = normalizeRouteDisplayName(groupRoute.displayName);
      if (!groupDisplayName || exactModelNames.has(groupDisplayName)) return false;
      if (isExplicitGroupRoute(groupRoute)) {
        return groupRoute.sourceRouteIds.includes(route.id);
      }
      return matchesModelPattern(exactModel, groupRoute.modelPattern);
    });
  });
}

function normalizeModelAlias(modelName: string): string {
  const normalized = (modelName || '').trim().toLowerCase();
  if (!normalized) return '';
  const slashIndex = normalized.lastIndexOf('/');
  if (slashIndex >= 0 && slashIndex < normalized.length - 1) {
    return normalized.slice(slashIndex + 1);
  }
  return normalized;
}

function isModelAliasEquivalent(left: string, right: string): boolean {
  const a = normalizeModelAlias(left);
  const b = normalizeModelAlias(right);
  return !!a && !!b && a === b;
}

function channelSupportsRequestedModel(channelSourceModel: string | null | undefined, requestedModel: string): boolean {
  const source = (channelSourceModel || '').trim();
  if (!source) return true;
  if (source === requestedModel) return true;
  if (isModelAliasEquivalent(source, requestedModel)) return true;
  if (matchesModelPattern(requestedModel, source)) return true;
  return false;
}

function isModelAllowedByDownstreamPolicy(requestedModel: string, policy: DownstreamRoutingPolicy): boolean {
  const supportedPatterns = Array.isArray(policy.supportedModels)
    ? policy.supportedModels
    : [];
  const hasSupportedPatterns = supportedPatterns.length > 0;
  const hasAllowedRoutes = policy.allowedRouteIds.length > 0;
  if (!hasSupportedPatterns && !hasAllowedRoutes) return policy.denyAllWhenEmpty === true ? false : true;
  const matchedSupportedPattern = supportedPatterns.some((pattern) => matchesModelPattern(requestedModel, pattern));
  if (matchedSupportedPattern) return true;
  if (hasAllowedRoutes) return true;
  return false;
}

function parseModelMappingRecord(modelMapping?: string | Record<string, unknown> | null): Record<string, unknown> | null {
  if (!modelMapping) return null;
  if (typeof modelMapping === 'object' && !Array.isArray(modelMapping)) {
    return modelMapping as Record<string, unknown>;
  }
  if (typeof modelMapping !== 'string') return null;
  try {
    const parsed = JSON.parse(modelMapping);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
    return parsed as Record<string, unknown>;
  } catch {
    return null;
  }
}

function resolveMappedModel(requestedModel: string, modelMapping?: string | Record<string, unknown> | null): string {
  const parsed = parseModelMappingRecord(modelMapping);
  if (!parsed) return requestedModel;

  const entries = Object.entries(parsed)
    .filter(([, value]) => typeof value === 'string' && value.trim().length > 0) as Array<[string, string]>;

  const exact = entries.find(([pattern]) => pattern === requestedModel);
  if (exact) return exact[1].trim();

  for (const [pattern, target] of entries) {
    if (matchesModelPattern(requestedModel, pattern)) {
      return target.trim();
    }
  }

  return requestedModel;
}

function normalizeChannelSourceModel(channelSourceModel: string | null | undefined): string {
  return (channelSourceModel || '').trim();
}

function resolveActualModelForSelectedChannel(
  requestedModel: string,
  route: RouteRow,
  mappedModel: string,
  channelSourceModel: string | null | undefined,
): string {
  const sourceModel = normalizeChannelSourceModel(channelSourceModel);
  if (isRouteDisplayNameMatch(requestedModel, route.displayName) && sourceModel) {
    return sourceModel;
  }
  return mappedModel;
}

function resolveRouteStrategy(route: RouteRow): RouteRoutingStrategy {
  return normalizeRouteRoutingStrategy(route.routingStrategy);
}

function parseIsoTimeMs(value?: string | null): number | null {
  if (!value) return null;
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? null : parsed;
}

function compareNullableTimeAsc(left?: string | null, right?: string | null): number {
  const leftMs = parseIsoTimeMs(left);
  const rightMs = parseIsoTimeMs(right);
  if (leftMs == null && rightMs == null) return 0;
  if (leftMs == null) return -1;
  if (rightMs == null) return 1;
  return leftMs - rightMs;
}

function resolveEffectiveUnitCost(candidate: RouteChannelCandidate, modelName: string): CostSignal {
  const successCount = Math.max(0, candidate.channel.successCount ?? 0);
  const totalCost = Math.max(0, candidate.channel.totalCost ?? 0);
  const configured = candidate.account.unitCost ?? null;

  if (successCount > 0 && totalCost > 0) {
    return {
      unitCost: Math.max(totalCost / successCount, MIN_EFFECTIVE_UNIT_COST),
      source: 'observed',
    };
  }

  if (typeof configured === 'number' && Number.isFinite(configured) && configured > 0) {
    return {
      unitCost: Math.max(configured, MIN_EFFECTIVE_UNIT_COST),
      source: 'configured',
    };
  }

  const catalogCost = getCachedModelRoutingReferenceCost({
    siteId: candidate.site.id,
    accountId: candidate.account.id,
    modelName,
  });
  if (typeof catalogCost === 'number' && Number.isFinite(catalogCost) && catalogCost > 0) {
    return {
      unitCost: Math.max(catalogCost, MIN_EFFECTIVE_UNIT_COST),
      source: 'catalog',
    };
  }

  return {
    unitCost: Math.max(config.routingFallbackUnitCost || 1, MIN_EFFECTIVE_UNIT_COST),
    source: 'fallback',
  };
}

type SiteHistoricalHealthMetrics = {
  multiplier: number;
  totalCalls: number;
  successRate: number | null;
  avgLatencyMs: number | null;
};

function buildSiteHistoricalHealthMetrics(candidates: RouteChannelCandidate[]): Map<number, SiteHistoricalHealthMetrics> {
  const totals = new Map<number, {
    totalCalls: number;
    successCount: number;
    failCount: number;
    totalLatencyMs: number;
    latencySamples: number;
  }>();

  for (const candidate of candidates) {
    const siteId = candidate.site.id;
    if (!totals.has(siteId)) {
      totals.set(siteId, {
        totalCalls: 0,
        successCount: 0,
        failCount: 0,
        totalLatencyMs: 0,
        latencySamples: 0,
      });
    }
    const target = totals.get(siteId)!;
    const successCount = Math.max(0, candidate.channel.successCount ?? 0);
    const failCount = Math.max(0, candidate.channel.failCount ?? 0);
    target.successCount += successCount;
    target.failCount += failCount;
    target.totalCalls += successCount + failCount;
    if (successCount > 0) {
      target.totalLatencyMs += Math.max(0, candidate.channel.totalLatencyMs ?? 0);
      target.latencySamples += successCount;
    }
  }

  const metrics = new Map<number, SiteHistoricalHealthMetrics>();
  for (const [siteId, total] of totals.entries()) {
    if (total.totalCalls <= 0) {
      metrics.set(siteId, {
        multiplier: 1,
        totalCalls: 0,
        successRate: null,
        avgLatencyMs: null,
      });
      continue;
    }

    const sampleFactor = clampNumber(total.totalCalls / SITE_HISTORICAL_HEALTH_MAX_SAMPLE, 0, 1);
    const successRate = total.successCount / total.totalCalls;
    const successPenaltyFactor = 1 - ((1 - successRate) * 0.55 * sampleFactor);
    const avgLatencyMs = total.latencySamples > 0
      ? Math.round(total.totalLatencyMs / total.latencySamples)
      : null;
    const latencyPenaltyRatio = avgLatencyMs == null
      ? 0
      : clampNumber(
        (avgLatencyMs - SITE_HISTORICAL_LATENCY_BASELINE_MS) / SITE_HISTORICAL_LATENCY_WINDOW_MS,
        0,
        1,
      ) * sampleFactor;
    const latencyFactor = 1 - (latencyPenaltyRatio * SITE_HISTORICAL_MAX_LATENCY_PENALTY);
    metrics.set(siteId, {
      multiplier: clampNumber(
        successPenaltyFactor * latencyFactor,
        SITE_HISTORICAL_HEALTH_MIN_MULTIPLIER,
        1,
      ),
      totalCalls: total.totalCalls,
      successRate,
      avgLatencyMs,
    });
  }

  return metrics;
}

function isExplicitTokenChannel(candidate: RouteChannelCandidate): boolean {
  return typeof candidate.channel.tokenId === 'number' && candidate.channel.tokenId > 0;
}

export class TokenRouter {
  /**
   * Find matching route and select a channel for the given model.
   * Returns null if no route/channel available.
   */
  async selectChannel(requestedModel: string, downstreamPolicy: DownstreamRoutingPolicy = DEFAULT_DOWNSTREAM_POLICY): Promise<SelectedChannel | null> {
    if (!isModelAllowedByDownstreamPolicy(requestedModel, downstreamPolicy)) return null;
    await ensureSiteRuntimeHealthStateLoaded();

    const match = await this.findRoute(requestedModel, downstreamPolicy);
    if (!match) return null;
    return await this.selectFromMatch(match, requestedModel, downstreamPolicy);
  }

  async previewSelectedChannel(
    requestedModel: string,
    downstreamPolicy: DownstreamRoutingPolicy = DEFAULT_DOWNSTREAM_POLICY,
  ): Promise<SelectedChannel | null> {
    if (!isModelAllowedByDownstreamPolicy(requestedModel, downstreamPolicy)) return null;
    await ensureSiteRuntimeHealthStateLoaded();

    const match = await this.findRoute(requestedModel, downstreamPolicy);
    if (!match) return null;
    return await this.selectFromMatch(match, requestedModel, downstreamPolicy, [], false);
  }

  /**
   * Select next channel for failover (exclude already-tried channels).
   */
  async selectNextChannel(
    requestedModel: string,
    excludeChannelIds: number[],
    downstreamPolicy: DownstreamRoutingPolicy = DEFAULT_DOWNSTREAM_POLICY,
  ): Promise<SelectedChannel | null> {
    if (!isModelAllowedByDownstreamPolicy(requestedModel, downstreamPolicy)) return null;
    await ensureSiteRuntimeHealthStateLoaded();

    const match = await this.findRoute(requestedModel, downstreamPolicy);
    if (!match) return null;
    return await this.selectFromMatch(match, requestedModel, downstreamPolicy, excludeChannelIds);
  }

  async selectPreferredChannel(
    requestedModel: string,
    preferredChannelId: number,
    downstreamPolicy: DownstreamRoutingPolicy = DEFAULT_DOWNSTREAM_POLICY,
    excludeChannelIds: number[] = [],
  ): Promise<SelectedChannel | null> {
    if (!isModelAllowedByDownstreamPolicy(requestedModel, downstreamPolicy)) return null;
    const normalizedPreferredChannelId = Math.trunc(preferredChannelId || 0);
    if (normalizedPreferredChannelId <= 0) return null;
    await ensureSiteRuntimeHealthStateLoaded();

    const match = await this.findRoute(requestedModel, downstreamPolicy);
    if (!match) return null;
    return await this.selectPreferredFromMatch(
      match,
      requestedModel,
      normalizedPreferredChannelId,
      excludeChannelIds,
    );
  }

  async explainSelection(
    requestedModel: string,
    excludeChannelIds: number[] = [],
    downstreamPolicy: DownstreamRoutingPolicy = DEFAULT_DOWNSTREAM_POLICY,
  ): Promise<RouteDecisionExplanation> {
    await ensureSiteRuntimeHealthStateLoaded();
    const match = await this.findRoute(requestedModel, downstreamPolicy);
    return this.explainSelectionFromMatch(match, requestedModel, { excludeChannelIds, downstreamPolicy });
  }

  async explainSelectionForRoute(
    routeId: number,
    requestedModel: string,
    excludeChannelIds: number[] = [],
    downstreamPolicy: DownstreamRoutingPolicy = DEFAULT_DOWNSTREAM_POLICY,
  ): Promise<RouteDecisionExplanation> {
    await ensureSiteRuntimeHealthStateLoaded();
    const match = await this.findRouteById(routeId, downstreamPolicy);
    return this.explainSelectionFromMatch(match, requestedModel, { excludeChannelIds, downstreamPolicy });
  }

  async explainSelectionRouteWide(routeId: number, downstreamPolicy: DownstreamRoutingPolicy = DEFAULT_DOWNSTREAM_POLICY): Promise<RouteDecisionExplanation> {
    await ensureSiteRuntimeHealthStateLoaded();
    const match = await this.findRouteById(routeId, downstreamPolicy);
    const fallbackRequestedModel = match?.route.modelPattern || `route:${routeId}`;
    return this.explainSelectionFromMatch(match, fallbackRequestedModel, {
      bypassSourceModelCheck: true,
      useChannelSourceModelForCost: true,
      downstreamPolicy,
    });
  }

  async refreshPricingReferenceCosts(
    requestedModel: string,
    options: PricingReferenceRefreshOptions = {},
  ): Promise<void> {
    const downstreamPolicy = options.downstreamPolicy ?? DEFAULT_DOWNSTREAM_POLICY;
    const match = await this.findRoute(requestedModel, downstreamPolicy);
    await this.refreshPricingReferenceCostsForMatch(match, requestedModel, options);
  }

  async refreshPricingReferenceCostsForRoute(
    routeId: number,
    requestedModel: string,
    options: PricingReferenceRefreshOptions = {},
  ): Promise<void> {
    const downstreamPolicy = options.downstreamPolicy ?? DEFAULT_DOWNSTREAM_POLICY;
    const match = await this.findRouteById(routeId, downstreamPolicy);
    await this.refreshPricingReferenceCostsForMatch(match, requestedModel, options);
  }

  async refreshRouteWidePricingReferenceCosts(
    routeId: number,
    options: Omit<PricingReferenceRefreshOptions, 'useChannelSourceModelForCost'> = {},
  ): Promise<void> {
    const downstreamPolicy = options.downstreamPolicy ?? DEFAULT_DOWNSTREAM_POLICY;
    const match = await this.findRouteById(routeId, downstreamPolicy);
    const requestedModel = match?.route.modelPattern || `route:${routeId}`;
    await this.refreshPricingReferenceCostsForMatch(match, requestedModel, {
      ...options,
      useChannelSourceModelForCost: true,
    });
  }

  private explainSelectionFromMatch(
    match: RouteMatch | null,
    requestedModel: string,
    options: ExplainSelectionOptions = {},
  ): RouteDecisionExplanation {
    const excludeChannelIds = options.excludeChannelIds ?? [];
    const downstreamPolicy = options.downstreamPolicy ?? DEFAULT_DOWNSTREAM_POLICY;

    if (!match) {
      return {
        requestedModel,
        actualModel: requestedModel,
        matched: false,
        summary: ['未匹配到启用的路由'],
        candidates: [],
      };
    }

    const requestedByDisplayName = isRouteDisplayNameMatch(requestedModel, match.route.displayName);
    const bypassSourceModelCheck = (options.bypassSourceModelCheck ?? false) || requestedByDisplayName;
    const useChannelSourceModelForCost = (options.useChannelSourceModelForCost ?? false) || requestedByDisplayName;
    const mappedModel = resolveMappedModel(requestedModel, match.route.modelMapping);
    const routeStrategy = resolveRouteStrategy(match.route);
    const runtimeModelResolver = requestedByDisplayName
      ? ((candidate: RouteChannelCandidate) => normalizeChannelSourceModel(candidate.channel.sourceModel) || mappedModel)
      : mappedModel;

    const nowIso = new Date().toISOString();
    const nowMs = Date.now();
    const summary: string[] = [
      `命中路由：${match.route.modelPattern}`,
      routeStrategy === 'round_robin'
        ? '路由策略：轮询'
        : (routeStrategy === 'stable_first' ? '路由策略：稳定优先' : '路由策略：按权重随机'),
    ];
    if (requestedByDisplayName) {
      summary.push(`按显示名命中：${normalizeRouteDisplayName(match.route.displayName)}`);
      summary.push('显示名仅用于聚合展示，实际转发模型按选中通道来源模型决定');
    }
    const availableByPriority = new Map<number, RouteChannelCandidate[]>();
    const candidates: RouteDecisionCandidate[] = [];
    const candidateMap = new Map<number, RouteDecisionCandidate>();

    for (const row of match.channels) {
      const reasonParts = this.getCandidateEligibilityReasons(row, {
        requestedModel,
        bypassSourceModelCheck,
        excludeChannelIds,
        nowIso,
      });

      const recentlyFailed = routeStrategy !== 'round_robin'
        ? isChannelRecentlyFailed(row.channel, nowMs)
        : false;
      const eligible = reasonParts.length === 0;
      const candidate: RouteDecisionCandidate = {
        channelId: row.channel.id,
        accountId: row.account.id,
        username: row.account.username || `account-${row.account.id}`,
        siteName: row.site.name || 'unknown',
        tokenName: row.token?.name || 'default',
        priority: row.channel.priority ?? 0,
        weight: row.channel.weight ?? 10,
        eligible,
        recentlyFailed,
        avoidedByRecentFailure: false,
        probability: 0,
        reason: eligible ? '可用' : reasonParts.join('、'),
      };
      candidates.push(candidate);
      candidateMap.set(candidate.channelId, candidate);

      if (eligible) {
        const priority = row.channel.priority ?? 0;
        if (!availableByPriority.has(priority)) availableByPriority.set(priority, []);
        availableByPriority.get(priority)!.push(row);
      }
    }

    if (availableByPriority.size === 0) {
      summary.push('没有可用通道（全部被禁用、站点不可用、冷却或令牌不可用）');
      return {
        requestedModel,
        actualModel: mappedModel,
        matched: true,
        routeId: match.route.id,
        modelPattern: match.route.modelPattern,
        summary,
        candidates,
      };
    }

    if (routeStrategy === 'round_robin') {
      const rawOrdered = this.getRoundRobinCandidates(match.channels.filter((row) => {
        const target = candidateMap.get(row.channel.id);
        return !!target?.eligible;
      }));
      const breakerFiltered = filterSiteRuntimeBrokenCandidatesByModel(rawOrdered, runtimeModelResolver, nowMs);
      if (breakerFiltered.avoided.length > 0) {
        for (const item of breakerFiltered.avoided) {
          const target = candidateMap.get(item.candidate.channel.id);
          if (!target) continue;
          target.reason = item.reason;
        }
        const breakerSummaryLabel = breakerFiltered.avoided.some((item) => item.reason.includes('模型熔断'))
          ? '运行时熔断避让'
          : '站点熔断避让';
        summary.push(`${breakerSummaryLabel} ${breakerFiltered.avoided.length}`);
      }
      const ordered = breakerFiltered.candidates;
      let selected: RouteChannelCandidate | null = null;

      for (let index = 0; index < ordered.length; index += 1) {
        const target = candidateMap.get(ordered[index].channel.id);
        if (!target || !target.eligible) continue;
        target.probability = index === 0 ? 100 : 0;
        target.reason = index === 0
          ? `轮询命中（全局第 1 / ${ordered.length} 位，忽略优先级）`
          : `轮询排队中（全局第 ${index + 1} / ${ordered.length} 位，忽略优先级）`;
        if (index === 0) {
          selected = ordered[index];
        }
      }

      if (!selected) {
        summary.push('本次未选出通道');
        return {
          requestedModel,
          actualModel: mappedModel,
          matched: true,
          routeId: match.route.id,
          modelPattern: match.route.modelPattern,
          summary,
          candidates,
        };
      }

      const selectedChannel = candidateMap.get(selected.channel.id);
      const selectedLabel = selectedChannel
        ? `${selectedChannel.username} @ ${selectedChannel.siteName} / ${selectedChannel.tokenName}`
        : `channel-${selected.channel.id}`;
      const actualModel = resolveActualModelForSelectedChannel(
        requestedModel,
        match.route,
        mappedModel,
        selected.channel.sourceModel,
      );
      summary.push(`全局轮询：可用 ${ordered.length}，忽略优先级`);
      summary.push(`最终选择：${selectedLabel}`);
      if (actualModel !== mappedModel) {
        summary.push(`实际转发模型：${actualModel}`);
      }

      return {
        requestedModel,
        actualModel,
        matched: true,
        routeId: match.route.id,
        modelPattern: match.route.modelPattern,
        selectedChannelId: selected.channel.id,
        selectedAccountId: selected.account.id,
        selectedLabel,
        summary,
        candidates,
      };
    }

    const sortedPriorities = Array.from(availableByPriority.keys()).sort((a, b) => a - b);
    let selected: RouteChannelCandidate | null = null;
    let selectedPriority = 0;

    for (const priority of sortedPriorities) {
      const rawLayer = availableByPriority.get(priority) ?? [];
      if (rawLayer.length === 0) continue;

      const breakerFiltered = filterSiteRuntimeBrokenCandidatesByModel(rawLayer, runtimeModelResolver, nowMs);
      if (breakerFiltered.avoided.length > 0) {
        for (const item of breakerFiltered.avoided) {
          const target = candidateMap.get(item.candidate.channel.id);
          if (!target) continue;
          target.reason = item.reason;
        }
      }

      const filteredLayer = filterRecentlyFailedCandidates(breakerFiltered.candidates, nowMs);
      const avoided = breakerFiltered.candidates.filter((row) => !filteredLayer.some((item) => item.channel.id === row.channel.id));
      if (avoided.length > 0) {
        for (const row of avoided) {
          const target = candidateMap.get(row.channel.id);
          if (!target) continue;
          target.avoidedByRecentFailure = true;
          target.reason = `最近失败，优先避让（${resolveFailureBackoffSec(row.channel.failCount)} 秒窗口）`;
        }
      }

      const weighted = this.calculateWeightedSelection(
        filteredLayer,
        useChannelSourceModelForCost ? runtimeModelResolver : mappedModel,
        downstreamPolicy,
        nowMs,
        routeStrategy === 'stable_first' ? 'stable_first' : 'weighted',
      );
      for (const detail of weighted.details) {
        const target = candidateMap.get(detail.candidate.channel.id);
        if (!target) continue;
        target.probability = Number((detail.probability * 100).toFixed(2));
        if (target.eligible && !target.avoidedByRecentFailure) {
          target.reason = detail.reason;
        }
      }

      if (!weighted.selected) continue;
      selected = weighted.selected;
      selectedPriority = priority;
      const layerSummaryParts = [`优先级 P${priority}：可用 ${rawLayer.length}`];
      if (breakerFiltered.avoided.length > 0) {
        const breakerSummaryLabel = breakerFiltered.avoided.some((item) => item.reason.includes('模型熔断'))
          ? '运行时熔断避让'
          : '站点熔断避让';
        layerSummaryParts.push(`${breakerSummaryLabel} ${breakerFiltered.avoided.length}`);
      }
      if (avoided.length > 0) {
        layerSummaryParts.push(`最近失败避让 ${avoided.length}`);
      }
      summary.push(layerSummaryParts.join('，'));
      break;
    }

    if (!selected) {
      summary.push('本次未选出通道');
      return {
        requestedModel,
        actualModel: mappedModel,
        matched: true,
        routeId: match.route.id,
        modelPattern: match.route.modelPattern,
        summary,
        candidates,
      };
    }

    const selectedChannel = candidateMap.get(selected.channel.id);
    const selectedLabel = selectedChannel
      ? `${selectedChannel.username} @ ${selectedChannel.siteName} / ${selectedChannel.tokenName}`
      : `channel-${selected.channel.id}`;
    const actualModel = resolveActualModelForSelectedChannel(
      requestedModel,
      match.route,
      mappedModel,
      selected.channel.sourceModel,
    );
    summary.push(`最终选择：${selectedLabel}（P${selectedPriority}）`);
    if (actualModel !== mappedModel) {
      summary.push(`实际转发模型：${actualModel}`);
    }

    return {
      requestedModel,
      actualModel,
      matched: true,
      routeId: match.route.id,
      modelPattern: match.route.modelPattern,
      selectedChannelId: selected.channel.id,
      selectedAccountId: selected.account.id,
      selectedLabel,
      summary,
      candidates,
    };
  }

  private async refreshPricingReferenceCostsForMatch(
    match: RouteMatch | null,
    requestedModel: string,
    options: PricingReferenceRefreshOptions = {},
  ): Promise<void> {
    if (!match) return;

    const requestedByDisplayName = isRouteDisplayNameMatch(requestedModel, match.route.displayName);
    const useChannelSourceModelForCost = (options.useChannelSourceModelForCost ?? false) || requestedByDisplayName;
    const mappedModel = resolveMappedModel(requestedModel, match.route.modelMapping);
    const refreshedKeys = options.refreshedKeys ?? new Set<string>();

    await Promise.allSettled(match.channels.map(async (candidate) => {
      const refreshKey = `${candidate.site.id}:${candidate.account.id}`;
      if (refreshedKeys.has(refreshKey)) return;
      refreshedKeys.add(refreshKey);

      const modelName = useChannelSourceModelForCost
        ? (normalizeChannelSourceModel(candidate.channel.sourceModel) || mappedModel)
        : mappedModel;
      if (!modelName) return;

      await refreshModelPricingCatalog({
        site: {
          id: candidate.site.id,
          url: candidate.site.url,
          platform: candidate.site.platform,
          apiKey: candidate.site.apiKey,
        },
        account: {
          id: candidate.account.id,
          accessToken: candidate.account.accessToken,
          apiToken: candidate.account.apiToken,
        },
        modelName,
      });
    }));
  }

  /**
   * Record success for a channel.
   */
  async recordSuccess(channelId: number, latencyMs: number, cost: number, modelName?: string | null) {
    await ensureSiteRuntimeHealthStateLoaded();
    const row = await db.select()
      .from(schema.routeChannels)
      .innerJoin(schema.accounts, eq(schema.routeChannels.accountId, schema.accounts.id))
      .where(eq(schema.routeChannels.id, channelId))
      .get();
    if (!row) return;
    const ch = row.route_channels;
    const account = row.accounts;
    const nowIso = new Date().toISOString();
    const nextSuccessCount = (ch.successCount ?? 0) + 1;
    const nextTotalLatencyMs = (ch.totalLatencyMs ?? 0) + latencyMs;
    const nextTotalCost = (ch.totalCost ?? 0) + cost;
    await db.update(schema.routeChannels).set({
      successCount: nextSuccessCount,
      totalLatencyMs: nextTotalLatencyMs,
      totalCost: nextTotalCost,
      lastUsedAt: nowIso,
      cooldownUntil: null,
      lastFailAt: null,
      consecutiveFailCount: 0,
      cooldownLevel: 0,
    }).where(eq(schema.routeChannels.id, channelId)).run();

    patchCachedChannel(channelId, (channel) => {
      channel.successCount = nextSuccessCount;
      channel.totalLatencyMs = nextTotalLatencyMs;
      channel.totalCost = nextTotalCost;
      channel.lastUsedAt = nowIso;
      channel.cooldownUntil = null;
      channel.lastFailAt = null;
      channel.consecutiveFailCount = 0;
      channel.cooldownLevel = 0;
    });

    recordSiteRuntimeSuccess(account.siteId, latencyMs, modelName);
  }

  /**
   * Clear persisted failure and cooldown state for the given channels.
   */
  async clearChannelFailureState(channelIds: number[]): Promise<number> {
    const normalizedChannelIds = Array.from(new Set(
      channelIds
        .filter((channelId): channelId is number => Number.isFinite(channelId) && channelId > 0)
        .map((channelId) => Math.trunc(channelId)),
    ));
    if (normalizedChannelIds.length === 0) return 0;

    await ensureSiteRuntimeHealthStateLoaded();
    const runtimeHealthRows = await db.select({
      siteId: schema.accounts.siteId,
      sourceModel: schema.routeChannels.sourceModel,
      routeModelPattern: schema.tokenRoutes.modelPattern,
    }).from(schema.routeChannels)
      .innerJoin(schema.accounts, eq(schema.routeChannels.accountId, schema.accounts.id))
      .innerJoin(schema.tokenRoutes, eq(schema.routeChannels.routeId, schema.tokenRoutes.id))
      .where(inArray(schema.routeChannels.id, normalizedChannelIds))
      .all();

    const result = await db.update(schema.routeChannels).set({
      failCount: 0,
      lastFailAt: null,
      consecutiveFailCount: 0,
      cooldownLevel: 0,
      cooldownUntil: null,
    }).where(inArray(schema.routeChannels.id, normalizedChannelIds)).run();

    if (clearRuntimeHealthStatesForChannels(runtimeHealthRows)) {
      await persistSiteRuntimeHealthState();
    }

    invalidateTokenRouterCache();
    return Number(result?.changes || normalizedChannelIds.length);
  }

  /**
   * Record failure and set cooldown.
   */
  async recordFailure(channelId: number, context: SiteRuntimeFailureContext | string | null = {}) {
    await ensureSiteRuntimeHealthStateLoaded();
    const row = await db.select()
      .from(schema.routeChannels)
      .innerJoin(schema.accounts, eq(schema.routeChannels.accountId, schema.accounts.id))
      .innerJoin(schema.tokenRoutes, eq(schema.routeChannels.routeId, schema.tokenRoutes.id))
      .where(eq(schema.routeChannels.id, channelId))
      .get();
    if (!row) return;

    const ch = row.route_channels;
    const account = row.accounts;
    const route = row.token_routes;
    const nowMs = Date.now();
    const nowIso = new Date(nowMs).toISOString();
    const normalizedContext: SiteRuntimeFailureContext = typeof context === 'string'
      ? { modelName: context }
      : (context ?? {});
    const shortWindowLimitCooldownUntil = resolveShortWindowLimitCooldown(account, normalizedContext, nowMs);
    const failCount = shortWindowLimitCooldownUntil ? 0 : ((ch.failCount ?? 0) + 1);
    const routeStrategy = resolveRouteStrategy(route);
    const affectedChannelIds = shortWindowLimitCooldownUntil
      ? await loadCredentialScopedChannelIds(ch, account.id)
      : [channelId];
    let cooldownUntil: string | null = null;
    let consecutiveFailCount = Math.max(0, ch.consecutiveFailCount ?? 0) + 1;
    let cooldownLevel = Math.max(0, ch.cooldownLevel ?? 0);

    if (shortWindowLimitCooldownUntil) {
      cooldownUntil = shortWindowLimitCooldownUntil;
      consecutiveFailCount = 0;
      cooldownLevel = 0;
    } else if (routeStrategy === 'round_robin') {
      if (consecutiveFailCount >= ROUND_ROBIN_FAILURE_THRESHOLD) {
        cooldownLevel = Math.min(cooldownLevel + 1, ROUND_ROBIN_COOLDOWN_LEVELS_SEC.length - 1);
        const cooldownSec = resolveRoundRobinCooldownSec(cooldownLevel);
        cooldownUntil = cooldownSec > 0
          ? new Date(nowMs + clampFailureCooldownMs(cooldownSec * 1000)).toISOString()
          : null;
        consecutiveFailCount = 0;
      }
    } else {
      cooldownUntil = new Date(nowMs + resolveEffectiveFailureCooldownMs(failCount)).toISOString();
      consecutiveFailCount = 0;
      cooldownLevel = 0;
    }

    await db.update(schema.routeChannels).set({
      failCount,
      lastFailAt: nowIso,
      consecutiveFailCount,
      cooldownLevel,
      cooldownUntil,
    }).where(inArray(schema.routeChannels.id, affectedChannelIds)).run();

    for (const affectedChannelId of affectedChannelIds) {
      patchCachedChannel(affectedChannelId, (channel) => {
        channel.failCount = failCount;
        channel.lastFailAt = nowIso;
        channel.cooldownUntil = cooldownUntil;
        channel.consecutiveFailCount = consecutiveFailCount;
        channel.cooldownLevel = cooldownLevel;
      });
    }

    recordSiteRuntimeFailure(account.siteId, normalizedContext, nowMs);
  }

  /**
   * Get all available models (aggregated from all routes).
   */
  async getAvailableModels(): Promise<string[]> {
    const routes = await loadEnabledRoutes();
    const exposed = buildVisibleEnabledRoutes(routes)
      .map((route) => getExposedModelNameForRoute(route).trim())
      .filter((name) => name.length > 0);
    return Array.from(new Set(exposed));
  }

  // --- Private methods ---

  private async selectFromMatch(
    match: RouteMatch,
    requestedModel: string,
    downstreamPolicy: DownstreamRoutingPolicy,
    excludeChannelIds: number[] = [],
    recordSelection = true,
  ): Promise<SelectedChannel | null> {
    const mappedModel = resolveMappedModel(requestedModel, match.route.modelMapping);
    const requestedByDisplayName = isRouteDisplayNameMatch(requestedModel, match.route.displayName);
    const bypassSourceModelCheck = requestedByDisplayName;
    const routeStrategy = resolveRouteStrategy(match.route);
    const runtimeModelResolver = requestedByDisplayName
      ? ((candidate: RouteChannelCandidate) => normalizeChannelSourceModel(candidate.channel.sourceModel) || mappedModel)
      : mappedModel;

    const nowIso = new Date().toISOString();
    const nowMs = Date.now();
    const available = match.channels.filter((candidate) => (
      this.getCandidateEligibilityReasons(candidate, {
        requestedModel,
        bypassSourceModelCheck,
        excludeChannelIds,
        nowIso,
      }).length === 0
    ));

    if (available.length === 0) return null;

    if (routeStrategy === 'round_robin') {
      const breakerFiltered = filterSiteRuntimeBrokenCandidatesByModel(available, runtimeModelResolver, nowMs);
      const selected = this.selectRoundRobinCandidate(breakerFiltered.candidates);
      if (!selected) return null;

      const tokenValue = this.resolveChannelTokenValue(selected);
      if (!tokenValue) return null;
      if (recordSelection) {
        await this.recordChannelSelection(selected.channel.id);
      }

      const actualModel = resolveActualModelForSelectedChannel(
        requestedModel,
        match.route,
        mappedModel,
        selected.channel.sourceModel,
      );

      return {
        ...selected,
        tokenValue,
        tokenName: selected.token?.name || 'default',
        actualModel,
      };
    }

    const layers = new Map<number, typeof available>();
    for (const candidate of available) {
      const priority = candidate.channel.priority ?? 0;
      if (!layers.has(priority)) layers.set(priority, []);
      layers.get(priority)!.push(candidate);
    }

    const sortedPriorities = Array.from(layers.keys()).sort((a, b) => a - b);
    for (const priority of sortedPriorities) {
      const rawLayer = layers.get(priority) ?? [];
      const breakerFiltered = filterSiteRuntimeBrokenCandidatesByModel(rawLayer, runtimeModelResolver, nowMs);
      const candidates = filterRecentlyFailedCandidates(breakerFiltered.candidates, nowMs);
      const selected = routeStrategy === 'stable_first'
        ? this.stableFirstSelect(
          candidates,
          requestedByDisplayName ? runtimeModelResolver : mappedModel,
          downstreamPolicy,
          nowMs,
        )
        : this.weightedRandomSelect(
        candidates,
        requestedByDisplayName ? runtimeModelResolver : mappedModel,
        downstreamPolicy,
        nowMs,
      );
      if (!selected) continue;

      const tokenValue = this.resolveChannelTokenValue(selected);
      if (!tokenValue) continue;
      if (routeStrategy === 'stable_first' && recordSelection) {
        await this.recordChannelSelection(selected.channel.id);
      }

      const actualModel = resolveActualModelForSelectedChannel(
        requestedModel,
        match.route,
        mappedModel,
        selected.channel.sourceModel,
      );

      return {
        ...selected,
        tokenValue,
        tokenName: selected.token?.name || 'default',
        actualModel,
      };
    }

    return null;
  }

  private async selectPreferredFromMatch(
    match: RouteMatch,
    requestedModel: string,
    preferredChannelId: number,
    excludeChannelIds: number[] = [],
    recordSelection = true,
  ): Promise<SelectedChannel | null> {
    const mappedModel = resolveMappedModel(requestedModel, match.route.modelMapping);
    const requestedByDisplayName = isRouteDisplayNameMatch(requestedModel, match.route.displayName);
    const bypassSourceModelCheck = requestedByDisplayName;
    const routeStrategy = resolveRouteStrategy(match.route);
    const runtimeModelResolver = requestedByDisplayName
      ? ((candidate: RouteChannelCandidate) => normalizeChannelSourceModel(candidate.channel.sourceModel) || mappedModel)
      : mappedModel;

    const nowIso = new Date().toISOString();
    const nowMs = Date.now();
    const available = match.channels.filter((candidate) => (
      this.getCandidateEligibilityReasons(candidate, {
        requestedModel,
        bypassSourceModelCheck,
        excludeChannelIds,
        nowIso,
      }).length === 0
    ));

    const preferred = available.find((candidate) => candidate.channel.id === preferredChannelId);
    if (!preferred) return null;

    const breakerFiltered = filterSiteRuntimeBrokenCandidatesByModel([preferred], runtimeModelResolver, nowMs);
    if (breakerFiltered.candidates.length <= 0) return null;

    const selected = breakerFiltered.candidates.find((candidate) => candidate.channel.id === preferredChannelId);
    if (!selected) return null;
    if (routeStrategy !== 'round_robin' && isChannelRecentlyFailed(selected.channel, nowMs)) {
      return null;
    }

    const tokenValue = this.resolveChannelTokenValue(selected);
    if (!tokenValue) return null;
    if (recordSelection && (routeStrategy === 'round_robin' || routeStrategy === 'stable_first')) {
      await this.recordChannelSelection(selected.channel.id);
    }

    const actualModel = resolveActualModelForSelectedChannel(
      requestedModel,
      match.route,
      mappedModel,
      selected.channel.sourceModel,
    );

    return {
      ...selected,
      tokenValue,
      tokenName: selected.token?.name || 'default',
      actualModel,
    };
  }

  private async findRoute(model: string, downstreamPolicy: DownstreamRoutingPolicy): Promise<RouteMatch | null> {
    let routes = await loadEnabledRoutes();

    const supportedPatterns = Array.isArray(downstreamPolicy.supportedModels)
      ? downstreamPolicy.supportedModels
      : [];
    const matchedSupportedPattern = supportedPatterns.some((pattern) => matchesModelPattern(model, pattern));

    if (downstreamPolicy.allowedRouteIds.length > 0 && !matchedSupportedPattern) {
      const allowSet = new Set(downstreamPolicy.allowedRouteIds);
      routes = routes.filter((route) => allowSet.has(route.id));
    }

    const matchedRoute = routes.find((route) => (
      !isExplicitGroupRoute(route)
      && isExactRouteModelPattern(route.modelPattern)
      && (route.modelPattern || '').trim() === model
    ))
      || routes.find((route) => isExplicitGroupRoute(route) && isRouteDisplayNameMatch(model, route.displayName))
      || routes.find((route) => !isExplicitGroupRoute(route) && isRouteDisplayNameMatch(model, route.displayName))
      || routes.find((route) => !isExplicitGroupRoute(route) && matchesModelPattern(model, route.modelPattern));

    if (!matchedRoute) return null;

    return await this.loadRouteMatch(matchedRoute);
  }

  private async findRouteById(routeId: number, downstreamPolicy: DownstreamRoutingPolicy): Promise<RouteMatch | null> {
    if (downstreamPolicy.allowedRouteIds.length > 0 && !downstreamPolicy.allowedRouteIds.includes(routeId)) {
      return null;
    }

    const route = (await loadEnabledRoutes()).find((item) => item.id === routeId);
    if (!route) return null;

    return await this.loadRouteMatch(route);
  }

  private async loadRouteMatch(route: RouteRow): Promise<RouteMatch> {
    return await loadRouteMatch(route);
  }

  private resolveChannelTokenValue(candidate: {
    channel: typeof schema.routeChannels.$inferSelect;
    account: typeof schema.accounts.$inferSelect;
    site?: typeof schema.sites.$inferSelect | null;
    token: typeof schema.accountTokens.$inferSelect | null;
  }): string | null {
    if (candidate.channel.tokenId) {
      if (!candidate.token) return null;
      if (!isUsableAccountToken(candidate.token)) return null;
      const token = candidate.token.token?.trim();
      return token ? token : null;
    }

    if (getOauthInfoFromAccount(candidate.account)) {
      const accessToken = candidate.account.accessToken?.trim();
      if (accessToken) return accessToken;
      return null;
    }

    const fallback = candidate.account.apiToken?.trim();
    if (fallback) return fallback;

    return null;
  }

  private getCandidateEligibilityReasons(
    candidate: RouteChannelCandidate,
    options: CandidateEligibilityOptions,
  ): string[] {
    const reasonParts: string[] = [];
    const bypassSourceModelCheck = options.bypassSourceModelCheck ?? false;
    const excludeChannelIds = options.excludeChannelIds ?? [];
    const nowIso = options.nowIso ?? new Date().toISOString();

    if (!bypassSourceModelCheck && !channelSupportsRequestedModel(candidate.channel.sourceModel, options.requestedModel)) {
      reasonParts.push(`来源模型不匹配=${candidate.channel.sourceModel || ''}`);
    }

    if (!candidate.channel.enabled) reasonParts.push('通道禁用');

    if (isExplicitTokenChannel(candidate)) {
      if (candidate.account.status === 'disabled') {
        reasonParts.push(`账号状态=${candidate.account.status}`);
      }
    } else if (candidate.account.status !== 'active') {
      reasonParts.push(`账号状态=${candidate.account.status}`);
    }

    if (isSiteDisabled(candidate.site.status)) {
      reasonParts.push(`站点状态=${candidate.site.status || 'disabled'}`);
    }

    if (excludeChannelIds.includes(candidate.channel.id)) {
      reasonParts.push('当前请求已尝试');
    }

    const tokenValue = this.resolveChannelTokenValue(candidate);
    if (!tokenValue) reasonParts.push('令牌不可用');

    if (candidate.channel.cooldownUntil && candidate.channel.cooldownUntil > nowIso) {
      reasonParts.push('冷却中');
    }

    return reasonParts;
  }

  private getRoundRobinCandidates(candidates: RouteChannelCandidate[]): RouteChannelCandidate[] {
    return [...candidates].sort((left, right) => {
      const selectionOrder = compareNullableTimeAsc(
        left.channel.lastSelectedAt || left.channel.lastUsedAt,
        right.channel.lastSelectedAt || right.channel.lastUsedAt,
      );
      if (selectionOrder !== 0) return selectionOrder;

      const usedOrder = compareNullableTimeAsc(left.channel.lastUsedAt, right.channel.lastUsedAt);
      if (usedOrder !== 0) return usedOrder;

      return (left.channel.id ?? 0) - (right.channel.id ?? 0);
    });
  }

  private selectRoundRobinCandidate(candidates: RouteChannelCandidate[]): RouteChannelCandidate | null {
    return this.getRoundRobinCandidates(candidates)[0] ?? null;
  }

  private compareStableFirstCandidates(left: RouteChannelCandidate, right: RouteChannelCandidate): number {
    const selectionOrder = compareNullableTimeAsc(
      left.channel.lastSelectedAt || left.channel.lastUsedAt,
      right.channel.lastSelectedAt || right.channel.lastUsedAt,
    );
    if (selectionOrder !== 0) return selectionOrder;

    const usedOrder = compareNullableTimeAsc(left.channel.lastUsedAt, right.channel.lastUsedAt);
    if (usedOrder !== 0) return usedOrder;

    return (left.channel.id ?? 0) - (right.channel.id ?? 0);
  }

  private async recordChannelSelection(channelId: number): Promise<void> {
    const nowIso = new Date().toISOString();
    await db.update(schema.routeChannels).set({
      lastSelectedAt: nowIso,
    }).where(eq(schema.routeChannels.id, channelId)).run();

    patchCachedChannel(channelId, (channel) => {
      channel.lastSelectedAt = nowIso;
    });
  }

  private weightedRandomSelect(
    candidates: RouteChannelCandidate[],
    modelName: string | ((candidate: RouteChannelCandidate) => string),
    downstreamPolicy: DownstreamRoutingPolicy,
    nowMs = Date.now(),
  ) {
    return this.calculateWeightedSelection(candidates, modelName, downstreamPolicy, nowMs, 'weighted').selected;
  }

  private stableFirstSelect(
    candidates: RouteChannelCandidate[],
    modelName: string | ((candidate: RouteChannelCandidate) => string),
    downstreamPolicy: DownstreamRoutingPolicy,
    nowMs = Date.now(),
  ) {
    return this.calculateWeightedSelection(candidates, modelName, downstreamPolicy, nowMs, 'stable_first').selected;
  }

  private calculateWeightedSelection(
    candidates: RouteChannelCandidate[],
    modelName: string | ((candidate: RouteChannelCandidate) => string),
    downstreamPolicy: DownstreamRoutingPolicy,
    nowMs = Date.now(),
    selectionMode: WeightedSelectionMode = 'weighted',
  ) {
    if (candidates.length === 0) {
      return {
        selected: null as RouteChannelCandidate | null,
        details: [] as Array<{ candidate: RouteChannelCandidate; probability: number; reason: string }>,
      };
    }

    if (candidates.length === 1) {
      return {
        selected: candidates[0],
        details: [{
          candidate: candidates[0],
          probability: 1,
          reason: selectionMode === 'stable_first' ? '稳定优先（唯一可用候选）' : '唯一可用候选',
        }],
      };
    }

    const { baseWeightFactor, valueScoreFactor, costWeight, balanceWeight, usageWeight } = config.routingWeights;
    const resolveModelName = typeof modelName === 'function'
      ? modelName
      : (() => modelName);
    const effectiveCosts = candidates.map((candidate) => resolveEffectiveUnitCost(candidate, resolveModelName(candidate)));
    const runtimeHealthDetails = candidates.map((candidate) => (
      getSiteRuntimeHealthDetails(candidate.site.id, resolveModelName(candidate), nowMs)
    ));

    const valueScores = candidates.map((c, i) => {
      const unitCost = effectiveCosts[i]?.unitCost || 1;
      const balance = c.account.balance || 0;
      const totalUsed = (c.channel.successCount ?? 0) + (c.channel.failCount ?? 0);
      const recentUsage = Math.max(totalUsed, 1);
      return costWeight * (1 / unitCost) + balanceWeight * balance + usageWeight * (1 / recentUsage);
    });

    const maxVS = Math.max(...valueScores, 0.001);
    const minVS = Math.min(...valueScores, 0);
    const range = maxVS - minVS || 1;
    const normalizedVS = valueScores.map((v) => (v - minVS) / range);

    const baseContributions = candidates.map((c, i) => {
      const weight = c.channel.weight ?? 10;
      return (weight + 10) * (baseWeightFactor + normalizedVS[i] * valueScoreFactor);
    });

    // Avoid over-favoring a site that has many tokens/channels for the same route.
    // Site-level total contribution remains comparable, then split across its channels.
    const siteChannelCounts = new Map<number, number>();
    for (const candidate of candidates) {
      siteChannelCounts.set(candidate.site.id, (siteChannelCounts.get(candidate.site.id) || 0) + 1);
    }
    const siteHistoricalHealthMetrics = buildSiteHistoricalHealthMetrics(candidates);

    const contributions = candidates.map((candidate, i) => {
      const siteChannels = Math.max(1, siteChannelCounts.get(candidate.site.id) || 1);
      let contribution = baseContributions[i] / siteChannels;
      const downstreamSiteMultiplier = downstreamPolicy.siteWeightMultipliers[candidate.site.id] ?? 1;
      const normalizedDownstreamSiteMultiplier =
        (Number.isFinite(downstreamSiteMultiplier) && downstreamSiteMultiplier > 0)
          ? downstreamSiteMultiplier
          : 1;
      const siteGlobalWeight =
        (Number.isFinite(candidate.site.globalWeight) && (candidate.site.globalWeight || 0) > 0)
          ? (candidate.site.globalWeight as number)
          : 1;
      const combinedSiteWeight = siteGlobalWeight * normalizedDownstreamSiteMultiplier;
      if (combinedSiteWeight > 0 && Number.isFinite(combinedSiteWeight)) {
        contribution *= combinedSiteWeight;
      }

      contribution *= runtimeHealthDetails[i]?.combinedMultiplier ?? 1;
      contribution *= siteHistoricalHealthMetrics.get(candidate.site.id)?.multiplier ?? 1;

      // If upstream price is unknown and we are using fallback unit cost,
      // apply an explicit penalty so raising fallback cost meaningfully lowers probability.
      if (effectiveCosts[i]?.source === 'fallback') {
        contribution *= 1 / Math.max(1, effectiveCosts[i]?.unitCost || 1);
      }

      return contribution;
    });

    const totalContribution = contributions.reduce((a, b) => a + b, 0);
    const rankedIndices = candidates.map((_, index) => index)
      .sort((leftIndex, rightIndex) => {
        const contributionDiff = contributions[rightIndex] - contributions[leftIndex];
        if (Math.abs(contributionDiff) > 1e-9) {
          return contributionDiff > 0 ? 1 : -1;
        }
        return this.compareStableFirstCandidates(candidates[leftIndex], candidates[rightIndex]);
      });
    const rankByIndex = new Map<number, number>();
    rankedIndices.forEach((candidateIndex, rank) => {
      rankByIndex.set(candidateIndex, rank + 1);
    });
    const details = candidates.map((candidate, i) => {
      const probability = totalContribution > 0 ? contributions[i] / totalContribution : 0;
      const weight = candidate.channel.weight ?? 10;
      const cost = effectiveCosts[i];
      const costSourceText = cost?.source === 'observed'
        ? '实测'
        : (cost?.source === 'configured' ? '配置' : (cost?.source === 'catalog' ? '目录' : '默认'));
      const siteChannels = Math.max(1, siteChannelCounts.get(candidate.site.id) || 1);
      const downstreamSiteMultiplier = downstreamPolicy.siteWeightMultipliers[candidate.site.id] ?? 1;
      const normalizedDownstreamSiteMultiplier =
        (Number.isFinite(downstreamSiteMultiplier) && downstreamSiteMultiplier > 0)
          ? downstreamSiteMultiplier
          : 1;
      const siteGlobalWeight =
        (Number.isFinite(candidate.site.globalWeight) && (candidate.site.globalWeight || 0) > 0)
          ? (candidate.site.globalWeight as number)
          : 1;
      const combinedSiteWeight = siteGlobalWeight * normalizedDownstreamSiteMultiplier;
      const siteRuntimeDetail = runtimeHealthDetails[i];
      const siteHistoricalHealth = siteHistoricalHealthMetrics.get(candidate.site.id);
      const siteHistoricalMultiplier = siteHistoricalHealth?.multiplier ?? 1;
      const historicalSuccessRateText = siteHistoricalHealth?.successRate == null
        ? '—'
        : `${(siteHistoricalHealth.successRate * 100).toFixed(1)}%`;
      const historicalLatencyText = siteHistoricalHealth?.avgLatencyMs == null
        ? '—'
        : `${siteHistoricalHealth.avgLatencyMs}ms`;
      const runtimeHealthText = siteRuntimeDetail.modelKey
        ? `${siteRuntimeDetail.combinedMultiplier.toFixed(2)}（站点=${siteRuntimeDetail.globalMultiplier.toFixed(2)}，模型=${siteRuntimeDetail.modelMultiplier.toFixed(2)}）`
        : `${siteRuntimeDetail.globalMultiplier.toFixed(2)}`;
      const reasonPrefix = selectionMode === 'stable_first'
        ? `稳定优先（综合评分第 ${rankByIndex.get(i) ?? 1} / ${candidates.length}`
        : '按权重随机';
      return {
        candidate,
        probability,
        reason: selectionMode === 'stable_first'
          ? `${reasonPrefix}，W=${weight}，成本=${costSourceText}:${(cost?.unitCost || 1).toFixed(6)}，站点权重=${siteGlobalWeight.toFixed(2)}x下游倍率=${normalizedDownstreamSiteMultiplier.toFixed(2)}=${combinedSiteWeight.toFixed(2)}，运行时健康=${runtimeHealthText}，历史健康=${siteHistoricalMultiplier.toFixed(2)}（成功率=${historicalSuccessRateText}，均延迟=${historicalLatencyText}，样本=${siteHistoricalHealth?.totalCalls ?? 0}），同站点通道=${siteChannels}，评分占比≈${(probability * 100).toFixed(1)}%）`
          : `按权重随机（W=${weight}，成本=${costSourceText}:${(cost?.unitCost || 1).toFixed(6)}，站点权重=${siteGlobalWeight.toFixed(2)}x下游倍率=${normalizedDownstreamSiteMultiplier.toFixed(2)}=${combinedSiteWeight.toFixed(2)}，运行时健康=${runtimeHealthText}，历史健康=${siteHistoricalMultiplier.toFixed(2)}（成功率=${historicalSuccessRateText}，均延迟=${historicalLatencyText}，样本=${siteHistoricalHealth?.totalCalls ?? 0}），同站点通道=${siteChannels}，概率≈${(probability * 100).toFixed(1)}%）`,
      };
    });

    let selected = candidates[rankedIndices[0] ?? 0];
    if (selectionMode === 'weighted') {
      let rand = Math.random() * totalContribution;
      selected = candidates[candidates.length - 1];
      for (let i = 0; i < candidates.length; i++) {
        rand -= contributions[i];
        if (rand <= 0) {
          selected = candidates[i];
          break;
        }
      }
    }

    return { selected, details };
  }
}

export const tokenRouter = new TokenRouter();

export const __tokenRouterTestUtils = {
  resolveMappedModel,
};

