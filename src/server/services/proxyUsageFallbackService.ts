import { fetch } from 'undici';
import { resolvePlatformUserId } from './accountExtraConfig.js';
import {
  buildNewApiCookieCandidates,
  fetchJsonWithShieldCookieRetry,
} from './platforms/newApiShield.js';
import { withExplicitProxyRequestInit, withSiteRecordProxyRequestInit } from './siteProxy.js';

const SELF_LOG_FETCH_TIMEOUT_MS = 8_000;
const SELF_LOG_PAGE_SIZE = 20;
const MATCH_LOOKBACK_MS = 25_000;
const MATCH_LOOKAHEAD_MS = 120_000;
const MATCH_MAX_CREATED_DELTA_MS = 90_000;
const MATCH_MAX_LATENCY_DELTA_MS = 12_000;
const QUOTA_PER_UNIT = 500_000;
const SUPPORTED_USAGE_FALLBACK_PLATFORMS = new Set(['done-hub', 'one-hub', 'new-api', 'anyrouter', 'sub2api']);
const ALWAYS_LOOKUP_SELF_LOG_PLATFORMS = new Set(['done-hub', 'one-hub', 'anyrouter', 'sub2api']);
const PLATFORM_REQUIRES_USER_HEADER = new Set(['new-api', 'anyrouter']);

interface ProxyUsage {
  promptTokens: number;
  completionTokens: number;
  totalTokens: number;
}

interface ProxyUsageFallbackInput {
  site: {
    url: string;
    platform: string;
    apiKey?: string | null;
    useSystemProxy?: boolean | null;
    proxyUrl?: string | null;
  };
  account: {
    accessToken?: string | null;
    apiToken?: string | null;
    username?: string | null;
    extraConfig?: string | null;
    platformUserId?: number | null;
  };
  tokenValue?: string | null;
  tokenName?: string | null;
  modelName: string;
  requestStartedAtMs: number;
  requestEndedAtMs: number;
  localLatencyMs: number;
  upstreamUsagePresent?: boolean;
  usage: ProxyUsage;
}

interface ProxyUsageFallbackResult extends ProxyUsage {
  recoveredFromSelfLog: boolean;
  estimatedCostFromQuota: number;
  selfLogBillingMeta: SelfLogBillingMeta | null;
  usageSource: 'upstream' | 'self-log' | 'unknown';
}

export interface SelfLogBillingMeta {
  modelRatio: number;
  completionRatio: number;
  cacheRatio: number;
  cacheCreationRatio: number;
  groupRatio: number;
  cacheReadTokens: number;
  cacheCreationTokens: number;
  promptTokensIncludeCache: boolean;
}

export interface SelfLogItem {
  modelName: string;
  tokenName: string;
  tokenValue?: string;
  promptTokens: number;
  completionTokens: number;
  totalTokens: number;
  quota: number;
  recoveredCost?: number;
  createdAtMs: number;
  requestTimeMs: number;
  billingMeta: SelfLogBillingMeta | null;
}

interface SelfLogMatchInput {
  modelName: string;
  tokenName?: string | null;
  tokenValue?: string | null;
  requestStartedAtMs: number;
  requestEndedAtMs: number;
  localLatencyMs: number;
}

function toNumber(value: unknown, fallback = 0): number {
  const n = typeof value === 'number' ? value : Number(value);
  if (!Number.isFinite(n)) return fallback;
  return n;
}

function toPositiveInt(value: unknown): number {
  return Math.max(0, Math.round(toNumber(value, 0)));
}

function roundCost(value: number): number {
  return Math.round(Math.max(0, value) * 1_000_000) / 1_000_000;
}

function normalizePositiveRatio(value: unknown, fallback: number): number {
  const ratio = toNumber(value, Number.NaN);
  if (Number.isFinite(ratio) && ratio >= 0) return ratio;
  return fallback;
}

function toTimestampMs(value: unknown): number {
  if (typeof value === 'number' && Number.isFinite(value)) {
    if (value > 1_000_000_000_000) return Math.round(value);
    if (value > 1_000_000_000) return Math.round(value * 1000);
    return 0;
  }

  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (!trimmed) return 0;

    const numeric = Number(trimmed);
    if (Number.isFinite(numeric)) {
      return toTimestampMs(numeric);
    }

    const parsed = Date.parse(trimmed);
    return Number.isNaN(parsed) ? 0 : parsed;
  }

  return 0;
}

function normalizeUsage(usage: ProxyUsage): ProxyUsage {
  const promptTokens = toPositiveInt(usage.promptTokens);
  const completionTokens = toPositiveInt(usage.completionTokens);
  const totalTokensRaw = toPositiveInt(usage.totalTokens);
  const totalTokens = totalTokensRaw > 0 ? totalTokensRaw : (promptTokens + completionTokens);
  return {
    promptTokens,
    completionTokens,
    totalTokens,
  };
}

function isUsageMissing(usage: ProxyUsage): boolean {
  return usage.promptTokens <= 0 && usage.completionTokens <= 0 && usage.totalTokens <= 0;
}

export function shouldLookupSelfLog(
  platform: string,
  usage: ProxyUsage,
  upstreamUsagePresent?: boolean,
): boolean {
  const normalizedPlatform = String(platform || '').toLowerCase();
  if (!SUPPORTED_USAGE_FALLBACK_PLATFORMS.has(normalizedPlatform)) return false;
  if (ALWAYS_LOOKUP_SELF_LOG_PLATFORMS.has(normalizedPlatform)) return true;
  const normalizedUsage = normalizeUsage(usage);
  const hasUpstreamUsage = upstreamUsagePresent ?? !isUsageMissing(normalizedUsage);
  return !hasUpstreamUsage;
}

function normalizeUrl(url: string): string {
  return url.replace(/\/+$/, '');
}

function getArrayNode(value: unknown): unknown[] | null {
  if (Array.isArray(value)) return value;
  if (!value || typeof value !== 'object') return null;

  const record = value as Record<string, unknown>;
  if (Array.isArray(record.data)) return record.data;
  if (Array.isArray(record.items)) return record.items;
  return null;
}

function modelNameMatches(left: string, right: string): boolean {
  const normalizedLeft = left.trim().toLowerCase();
  const normalizedRight = right.trim().toLowerCase();
  if (!normalizedLeft || !normalizedRight) return false;
  if (normalizedLeft === normalizedRight) return true;
  if (normalizedLeft.endsWith(`/${normalizedRight}`)) return true;
  if (normalizedRight.endsWith(`/${normalizedLeft}`)) return true;

  const leftTail = normalizedLeft.split('/').pop() || '';
  const rightTail = normalizedRight.split('/').pop() || '';
  return !!leftTail && leftTail === rightTail;
}

function normalizeTokenMatchValue(value: string | null | undefined): string {
  return String(value || '').trim();
}

function getPayloadList(payload: unknown): unknown[] {
  const candidates = [
    payload,
    (payload as any)?.data,
    (payload as any)?.data?.data,
    (payload as any)?.data?.items,
    (payload as any)?.items,
  ];

  for (const candidate of candidates) {
    const list = getArrayNode(candidate);
    if (list) return list;
  }

  return [];
}

function mapSelfLogItem(raw: unknown): SelfLogItem | null {
  if (!raw || typeof raw !== 'object') return null;
  const row = raw as Record<string, unknown>;

  const modelName = String(row.model_name ?? row.modelName ?? row.model ?? '').trim();
  if (!modelName) return null;

  const promptTokens = toPositiveInt(
    row.prompt_tokens
      ?? row.promptTokens
      ?? row.input_tokens
      ?? row.inputTokens,
  );
  const completionTokens = toPositiveInt(
    row.completion_tokens
      ?? row.completionTokens
      ?? row.output_tokens
      ?? row.outputTokens,
  );
  const totalTokensRaw = toPositiveInt(row.total_tokens ?? row.totalTokens);
  const totalTokens = totalTokensRaw > 0 ? totalTokensRaw : (promptTokens + completionTokens);
  const createdAtMs = toTimestampMs(row.created_at ?? row.createdAt);
  if (createdAtMs <= 0) return null;
  const recoveredCost = roundCost(toNumber(row.actual_cost ?? row.actualCost ?? row.total_cost ?? row.totalCost, 0));
  const rawApiKey = row.api_key ?? row.apiKey;
  const apiKeyRecord = rawApiKey && typeof rawApiKey === 'object'
    ? rawApiKey as Record<string, unknown>
    : null;
  const tokenName = String(
    row.token_name
      ?? row.tokenName
      ?? apiKeyRecord?.name
      ?? '',
  ).trim();
  const tokenValue = normalizeTokenMatchValue(
    typeof apiKeyRecord?.key === 'string' ? apiKeyRecord.key : '',
  );
  const requestTimeMs = toPositiveInt(
    row.request_time
      ?? row.requestTime
      ?? row.duration_ms
      ?? row.durationMs,
  );

  return {
    modelName,
    tokenName,
    ...(tokenValue ? { tokenValue } : {}),
    promptTokens,
    completionTokens,
    totalTokens,
    quota: toPositiveInt(row.quota),
    ...(recoveredCost > 0 ? { recoveredCost } : {}),
    createdAtMs,
    requestTimeMs,
    billingMeta: parseSelfLogBillingMeta(row.other),
  };
}

function parseSelfLogBillingMeta(rawOther: unknown): SelfLogBillingMeta | null {
  let payload = rawOther;
  if (typeof rawOther === 'string') {
    const trimmed = rawOther.trim();
    if (!trimmed) return null;
    try {
      payload = JSON.parse(trimmed);
    } catch {
      return null;
    }
  }

  if (!payload || typeof payload !== 'object') return null;
  const other = payload as Record<string, unknown>;

  const modelRatio = normalizePositiveRatio(other.model_ratio ?? other.modelRatio, 1);
  const completionRatio = normalizePositiveRatio(
    other.completion_ratio ?? other.completionRatio,
    1,
  );
  const cacheRatio = normalizePositiveRatio(
    other.cache_ratio ?? other.cacheRatio,
    1,
  );
  const cacheCreationRatio = normalizePositiveRatio(
    other.cache_creation_ratio
      ?? other.cacheCreationRatio
      ?? other.create_cache_ratio
      ?? other.createCacheRatio,
    1,
  );
  const groupRatio = normalizePositiveRatio(other.group_ratio ?? other.groupRatio, 1);
  const cacheReadTokens = toPositiveInt(
    other.cache_tokens ?? other.cacheTokens ?? other.cache_read_tokens ?? other.cacheReadTokens,
  );
  const cacheCreationTokens = toPositiveInt(
    other.cache_creation_tokens
      ?? other.cacheCreationTokens
      ?? other.create_cache_tokens
      ?? other.createCacheTokens,
  );

  const hasMeaningfulData = (
    cacheReadTokens > 0
    || cacheCreationTokens > 0
    || modelRatio !== 1
    || completionRatio !== 1
    || cacheRatio !== 1
    || cacheCreationRatio !== 1
    || groupRatio !== 1
  );
  if (!hasMeaningfulData) return null;

  return {
    modelRatio,
    completionRatio,
    cacheRatio,
    cacheCreationRatio,
    groupRatio,
    cacheReadTokens,
    cacheCreationTokens,
    promptTokensIncludeCache: true,
  };
}

function buildTokenCandidates(input: ProxyUsageFallbackInput): string[] {
  const candidates = [
    input.account.accessToken,
    input.tokenValue,
    input.account.apiToken,
  ]
    .map((value) => (typeof value === 'string' ? value.trim() : ''))
    .filter(Boolean);
  return Array.from(new Set(candidates));
}

function resolveSelfLogUserId(input: ProxyUsageFallbackInput): number | undefined {
  const direct = toPositiveInt(input.account.platformUserId);
  if (direct > 0) return direct;
  return resolvePlatformUserId(input.account.extraConfig, input.account.username);
}

async function fetchSelfLogPayload(baseUrl: string, token: string, input: ProxyUsageFallbackInput): Promise<unknown> {
  const controller = new AbortController();
  let timeoutHandle: ReturnType<typeof setTimeout> | null = setTimeout(() => {
    controller.abort();
  }, SELF_LOG_FETCH_TIMEOUT_MS);

  try {
    const platform = String(input.site.platform || '').toLowerCase();
    if (platform === 'sub2api') {
      const query = new URLSearchParams({
        page: '1',
        page_size: String(SELF_LOG_PAGE_SIZE),
        model: input.modelName,
      });
      const response = await fetch(`${baseUrl}/api/v1/usage?${query.toString()}`, withSiteRecordProxyRequestInit(input.site, {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${token}`,
        },
        signal: controller.signal,
      }));

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      const text = await response.text();
      if (!text.trim()) return null;

      try {
        return JSON.parse(text);
      } catch {
        return null;
      }
    }

    const pageSizeParam = String(input.site.platform || '').toLowerCase() === 'anyrouter'
      ? 'page_size'
      : 'size';
    const query = `p=0&page=1&${pageSizeParam}=${SELF_LOG_PAGE_SIZE}&order=-created_at`;
    const url = `${baseUrl}/api/log/self?${query}`;
    const headers: Record<string, string> = {
      Authorization: `Bearer ${token}`,
    };
    if (PLATFORM_REQUIRES_USER_HEADER.has(platform)) {
      const userId = resolveSelfLogUserId(input);
      if (userId) {
        headers['New-Api-User'] = String(userId);
      }
    }

    const shouldTryShieldCookie = platform === 'anyrouter' || token.includes('=');
    if (shouldTryShieldCookie) {
      for (const cookie of buildNewApiCookieCandidates(token)) {
        const result = await fetchJsonWithShieldCookieRetry(url, {
          method: 'GET',
          headers: {
            ...Object.fromEntries(
              Object.entries(headers).filter(([key]) => key.toLowerCase() !== 'authorization'),
            ),
            Cookie: cookie,
          },
          signal: controller.signal,
        });
        if (result.data) return result.data;
      }
    }

    const response = await fetch(url, withSiteRecordProxyRequestInit(input.site, {
      method: 'GET',
      headers,
      signal: controller.signal,
    }));

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const text = await response.text();
    if (!text.trim()) return null;

    try {
      return JSON.parse(text);
    } catch {
      return null;
    }
  } finally {
    if (timeoutHandle) {
      clearTimeout(timeoutHandle);
      timeoutHandle = null;
    }
  }
}

async function fetchRecentSelfLogItems(input: ProxyUsageFallbackInput): Promise<SelfLogItem[]> {
  const baseUrl = normalizeUrl(input.site.url);
  const tokens = buildTokenCandidates(input);
  for (const token of tokens) {
    try {
      const payload = await fetchSelfLogPayload(baseUrl, token, input);
      const items = extractSelfLogItems(payload);
      if (items.length > 0) return items;
    } catch {}
  }
  return [];
}

export function extractSelfLogItems(payload: unknown): SelfLogItem[] {
  const rows = getPayloadList(payload);
  const items = rows
    .map((row) => mapSelfLogItem(row))
    .filter((item): item is SelfLogItem => item !== null)
    .sort((a, b) => b.createdAtMs - a.createdAtMs);

  return items;
}

export function findBestSelfLogMatch(items: SelfLogItem[], input: SelfLogMatchInput): SelfLogItem | null {
  const requestedModel = input.modelName.trim();
  if (!requestedModel || items.length === 0) return null;

  const windowStart = input.requestStartedAtMs - MATCH_LOOKBACK_MS;
  const windowEnd = input.requestEndedAtMs + MATCH_LOOKAHEAD_MS;
  let candidates = items.filter((item) => (
    modelNameMatches(item.modelName, requestedModel)
    && item.createdAtMs >= windowStart
    && item.createdAtMs <= windowEnd
    && (item.totalTokens > 0 || item.quota > 0 || item.requestTimeMs > 0)
  ));
  if (candidates.length === 0) return null;

  const tokenValue = normalizeTokenMatchValue(input.tokenValue);
  if (tokenValue) {
    const tokenValueMatched = candidates.filter((item) => normalizeTokenMatchValue(item.tokenValue) === tokenValue);
    if (tokenValueMatched.length > 0) {
      candidates = tokenValueMatched;
    }
  }

  const tokenName = String(input.tokenName || '').trim().toLowerCase();
  if (tokenName) {
    const tokenMatched = candidates.filter((item) => item.tokenName.trim().toLowerCase() === tokenName);
    if (tokenMatched.length > 0) {
      candidates = tokenMatched;
    }
  }

  let best: SelfLogItem | null = null;
  let bestScore = Number.POSITIVE_INFINITY;

  for (const candidate of candidates) {
    const createdAtDelta = Math.abs(candidate.createdAtMs - input.requestEndedAtMs);
    const latencyDelta = (input.localLatencyMs > 0 && candidate.requestTimeMs > 0)
      ? Math.abs(candidate.requestTimeMs - input.localLatencyMs)
      : 0;
    const score = createdAtDelta + (latencyDelta * 2);

    if (score < bestScore) {
      best = candidate;
      bestScore = score;
    }
  }

  if (!best) return null;

  const createdDelta = Math.abs(best.createdAtMs - input.requestEndedAtMs);
  if (createdDelta > MATCH_MAX_CREATED_DELTA_MS) return null;

  if (input.localLatencyMs > 0 && best.requestTimeMs > 0) {
    const latencyDelta = Math.abs(best.requestTimeMs - input.localLatencyMs);
    if (latencyDelta > MATCH_MAX_LATENCY_DELTA_MS) return null;
  }

  return best;
}

function toQuotaCost(quota: number): number {
  return roundCost(toPositiveInt(quota) / QUOTA_PER_UNIT);
}

function toRecoveredCost(item: SelfLogItem): number {
  if (typeof item.recoveredCost === 'number' && item.recoveredCost > 0) return item.recoveredCost;
  return toQuotaCost(item.quota);
}

export async function resolveProxyUsageWithSelfLogFallback(
  input: ProxyUsageFallbackInput,
): Promise<ProxyUsageFallbackResult> {
  const normalizedUsage = normalizeUsage(input.usage);
  const hasUpstreamUsage = input.upstreamUsagePresent ?? !isUsageMissing(normalizedUsage);
  const fallbackUsageSource = hasUpstreamUsage ? 'upstream' : 'unknown';
  const fallback: ProxyUsageFallbackResult = {
    ...normalizedUsage,
    recoveredFromSelfLog: false,
    estimatedCostFromQuota: 0,
    selfLogBillingMeta: null,
    usageSource: fallbackUsageSource,
  };

  const platform = String(input.site.platform || '').toLowerCase();
  if (!shouldLookupSelfLog(platform, normalizedUsage, hasUpstreamUsage)) {
    return fallback;
  }

  try {
    const items = await fetchRecentSelfLogItems(input);
    const matched = findBestSelfLogMatch(items, {
      modelName: input.modelName,
      tokenName: input.tokenName,
      tokenValue: input.tokenValue,
      requestStartedAtMs: input.requestStartedAtMs,
      requestEndedAtMs: input.requestEndedAtMs,
      localLatencyMs: input.localLatencyMs,
    });

    if (!matched) return fallback;

    const matchedUsage: ProxyUsage = {
      promptTokens: matched.promptTokens,
      completionTokens: matched.completionTokens,
      totalTokens: matched.totalTokens,
    };
    const normalizedMatched = normalizeUsage(matchedUsage);
    const useMatchedTokens = normalizedMatched.totalTokens > 0
      || normalizedMatched.promptTokens > 0
      || normalizedMatched.completionTokens > 0;
    const resolvedTokens = useMatchedTokens ? normalizedMatched : normalizedUsage;

    return {
      promptTokens: resolvedTokens.promptTokens,
      completionTokens: resolvedTokens.completionTokens,
      totalTokens: resolvedTokens.totalTokens,
      recoveredFromSelfLog: true,
      estimatedCostFromQuota: toRecoveredCost(matched),
      selfLogBillingMeta: matched.billingMeta,
      usageSource: useMatchedTokens ? 'self-log' : fallbackUsageSource,
    };
  } catch {
    return fallback;
  }
}
