interface ParsedProxyUsage {
  promptTokens: number;
  completionTokens: number;
  totalTokens: number;
  cacheReadTokens: number;
  cacheCreationTokens: number;
  promptTokensIncludeCache: boolean | null;
}

const ZERO_USAGE: ParsedProxyUsage = {
  promptTokens: 0,
  completionTokens: 0,
  totalTokens: 0,
  cacheReadTokens: 0,
  cacheCreationTokens: 0,
  promptTokensIncludeCache: null,
};

const USAGE_DIRECT_KEYS = [
  'prompt_tokens',
  'promptTokens',
  'prompt_token_count',
  'promptTokenCount',
  'input_tokens',
  'inputTokens',
  'input_token_count',
  'inputTokenCount',
  'completion_tokens',
  'completionTokens',
  'completion_token_count',
  'completionTokenCount',
  'candidates_token_count',
  'candidatesTokenCount',
  'output_tokens',
  'outputTokens',
  'output_token_count',
  'outputTokenCount',
  'total_tokens',
  'totalTokens',
  'total_token_count',
  'totalTokenCount',
  'cache_read_input_tokens',
  'cacheReadInputTokens',
  'prompt_cache_hit_tokens',
  'promptCacheHitTokens',
  'cached_tokens',
  'cachedTokens',
  'cache_read_tokens',
  'cacheReadTokens',
  'cache_creation_input_tokens',
  'cacheCreationInputTokens',
  'cache_creation_tokens',
  'cacheCreationTokens',
  'claude_cache_creation_5_m_tokens',
  'claudeCacheCreation5mTokens',
  'claude_cache_creation_1_h_tokens',
  'claudeCacheCreation1hTokens',
] as const;

const USAGE_DETAIL_KEYS = [
  'prompt_tokens_details',
  'promptTokensDetails',
  'input_tokens_details',
  'inputTokensDetails',
  'completion_tokens_details',
  'completionTokensDetails',
  'output_tokens_details',
  'outputTokensDetails',
  'cache_creation',
  'cacheCreation',
] as const;

function toPositiveInt(value: unknown): number {
  const n = typeof value === 'number' ? value : Number(value);
  if (!Number.isFinite(n)) return 0;
  return Math.max(0, Math.round(n));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object';
}

function hasOwn(record: Record<string, unknown>, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(record, key);
}

function hasExplicitUsageValue(value: unknown): boolean {
  if (value === null || value === undefined) return false;
  if (typeof value === 'number') return Number.isFinite(value);
  if (typeof value === 'string') {
    const trimmed = value.trim();
    return trimmed.length > 0 && Number.isFinite(Number(trimmed));
  }
  if (Array.isArray(value)) {
    return value.some((entry) => hasExplicitUsageValue(entry));
  }
  if (!isRecord(value)) return false;
  return Object.values(value).some((entry) => hasExplicitUsageValue(entry));
}

function collectUsageCandidates(payload: unknown): Array<Record<string, unknown>> {
  const candidates: Array<Record<string, unknown>> = [];
  const visited = new Set<object>();
  const queue: unknown[] = [];

  const enqueue = (value: unknown) => {
    if (!value || typeof value !== 'object') return;
    queue.push(value);
  };

  enqueue(payload);
  enqueue((payload as any)?.usage);
  enqueue((payload as any)?.usageMetadata);
  enqueue((payload as any)?.usage_metadata);
  enqueue((payload as any)?.token_usage);
  enqueue((payload as any)?.tokenUsage);

  // Guard against unexpectedly deep/large payloads.
  let inspected = 0;
  const MAX_INSPECT = 200;

  while (queue.length > 0 && inspected < MAX_INSPECT) {
    const current = queue.shift();
    inspected += 1;

    if (Array.isArray(current)) {
      for (const item of current) enqueue(item);
      continue;
    }

    if (!isRecord(current)) continue;
    if (visited.has(current)) continue;
    visited.add(current);
    candidates.push(current);

    for (const value of Object.values(current)) {
      enqueue(value);
    }
  }

  return candidates;
}

function firstPositiveInt(record: Record<string, unknown>, keys: string[]): number {
  for (const key of keys) {
    const value = toPositiveInt(record[key]);
    if (value > 0) return value;
  }
  return 0;
}

function sumNumericFields(value: unknown): number {
  if (!isRecord(value)) return 0;
  return Object.values(value).reduce<number>((sum, item) => sum + toPositiveInt(item), 0);
}

function detectPromptTokensIncludeCache(record: Record<string, unknown>): boolean | null {
  const hasAnthropicCacheFields = [
    'cache_read_input_tokens',
    'cacheReadInputTokens',
    'cache_creation_input_tokens',
    'cacheCreationInputTokens',
    'cache_creation',
    'cacheCreation',
    'claude_cache_creation_5_m_tokens',
    'claudeCacheCreation5mTokens',
    'claude_cache_creation_1_h_tokens',
    'claudeCacheCreation1hTokens',
  ].some((key) => key in record);
  if (hasAnthropicCacheFields) return false;

  const hasDetailCacheFields = [
    'prompt_tokens_details',
    'promptTokensDetails',
    'input_tokens_details',
    'inputTokensDetails',
    'prompt_cache_hit_tokens',
    'promptCacheHitTokens',
  ].some((key) => key in record);
  if (hasDetailCacheFields) return true;

  return null;
}

function getCacheReadTokens(record: Record<string, unknown>): number {
  const direct = firstPositiveInt(record, [
    'cache_read_input_tokens',
    'cacheReadInputTokens',
    'prompt_cache_hit_tokens',
    'promptCacheHitTokens',
    'cached_tokens',
    'cachedTokens',
    'cache_read_tokens',
    'cacheReadTokens',
  ]);
  if (direct > 0) return direct;

  return Math.max(
    toPositiveInt((record.prompt_tokens_details as any)?.cached_tokens),
    toPositiveInt((record.promptTokensDetails as any)?.cachedTokens),
    toPositiveInt((record.input_tokens_details as any)?.cached_tokens),
    toPositiveInt((record.inputTokensDetails as any)?.cachedTokens),
  );
}

function getCacheCreationTokens(record: Record<string, unknown>): number {
  const direct = firstPositiveInt(record, [
    'cache_creation_input_tokens',
    'cacheCreationInputTokens',
    'cache_creation_tokens',
    'cacheCreationTokens',
  ]);
  if (direct > 0) return direct;

  const split = Math.max(
    toPositiveInt((record.cache_creation as any)?.ephemeral_5m_input_tokens)
      + toPositiveInt((record.cache_creation as any)?.ephemeral_1h_input_tokens),
    toPositiveInt((record.cacheCreation as any)?.ephemeral5mInputTokens)
      + toPositiveInt((record.cacheCreation as any)?.ephemeral1hInputTokens),
    toPositiveInt(record.claude_cache_creation_5_m_tokens)
      + toPositiveInt(record.claude_cache_creation_1_h_tokens),
    toPositiveInt(record.claudeCacheCreation5mTokens)
      + toPositiveInt(record.claudeCacheCreation1hTokens),
  );
  if (split > 0) return split;

  return Math.max(
    toPositiveInt((record.prompt_tokens_details as any)?.cache_creation_tokens),
    toPositiveInt((record.promptTokensDetails as any)?.cacheCreationTokens),
    toPositiveInt((record.input_tokens_details as any)?.cache_creation_tokens),
    toPositiveInt((record.inputTokensDetails as any)?.cacheCreationTokens),
  );
}

function parseUsageRecord(record: Record<string, unknown>): ParsedProxyUsage {
  let promptTokens = firstPositiveInt(record, [
    'prompt_tokens',
    'promptTokens',
    'prompt_token_count',
    'promptTokenCount',
    'input_tokens',
    'inputTokens',
    'input_token_count',
    'inputTokenCount',
  ]);
  let completionTokens = firstPositiveInt(record, [
    'completion_tokens',
    'completionTokens',
    'completion_token_count',
    'completionTokenCount',
    'candidates_token_count',
    'candidatesTokenCount',
    'output_tokens',
    'outputTokens',
    'output_token_count',
    'outputTokenCount',
  ]);
  let totalTokens = firstPositiveInt(record, [
    'total_tokens',
    'totalTokens',
    'total_token_count',
    'totalTokenCount',
  ]);
  const cacheReadTokens = getCacheReadTokens(record);
  const cacheCreationTokens = getCacheCreationTokens(record);
  const promptTokensIncludeCache = detectPromptTokensIncludeCache(record);

  if (promptTokens <= 0) {
    promptTokens = Math.max(
      sumNumericFields(record.prompt_tokens_details),
      sumNumericFields(record.promptTokensDetails),
      sumNumericFields(record.input_tokens_details),
      sumNumericFields(record.inputTokensDetails),
    );
  }

  if (completionTokens <= 0) {
    completionTokens = Math.max(
      sumNumericFields(record.completion_tokens_details),
      sumNumericFields(record.completionTokensDetails),
      sumNumericFields(record.output_tokens_details),
      sumNumericFields(record.outputTokensDetails),
    );
  }

  if (totalTokens <= 0) {
    totalTokens = promptTokens + completionTokens;
  }

  if (promptTokens <= 0 && totalTokens > completionTokens) {
    promptTokens = totalTokens - completionTokens;
  }
  if (completionTokens <= 0 && totalTokens > promptTokens) {
    completionTokens = totalTokens - promptTokens;
  }

  return {
    promptTokens,
    completionTokens,
    totalTokens: Math.max(totalTokens, promptTokens + completionTokens),
    cacheReadTokens,
    cacheCreationTokens,
    promptTokensIncludeCache,
  };
}

export function parseProxyUsage(payload: unknown): ParsedProxyUsage {
  if (!payload || typeof payload !== 'object') return { ...ZERO_USAGE };
  const candidates = collectUsageCandidates(payload);

  let best = { ...ZERO_USAGE };
  let bestScore = -1;

  for (const candidate of candidates) {
    const parsed = parseUsageRecord(candidate);
    const score = parsed.totalTokens > 0
      ? (parsed.totalTokens * 10_000 + parsed.promptTokens + parsed.completionTokens)
      : (parsed.promptTokens + parsed.completionTokens);
    if (score > bestScore) {
      best = parsed;
      bestScore = score;
    }
  }

  return best;
}

export function hasProxyUsagePayload(payload: unknown): boolean {
  if (!payload || typeof payload !== 'object') return false;
  const candidates = collectUsageCandidates(payload);
  return candidates.some((candidate) => (
    USAGE_DIRECT_KEYS.some((key) => hasOwn(candidate, key) && hasExplicitUsageValue(candidate[key]))
    || USAGE_DETAIL_KEYS.some((key) => hasOwn(candidate, key) && hasExplicitUsageValue(candidate[key]))
  ));
}

export function mergeProxyUsage(base: ParsedProxyUsage, incoming: ParsedProxyUsage): ParsedProxyUsage {
  const normalizeUsage = (usage: ParsedProxyUsage): ParsedProxyUsage => ({
    promptTokens: toPositiveInt(usage.promptTokens),
    completionTokens: toPositiveInt(usage.completionTokens),
    totalTokens: Math.max(
      toPositiveInt(usage.totalTokens),
      toPositiveInt(usage.promptTokens) + toPositiveInt(usage.completionTokens),
    ),
    cacheReadTokens: toPositiveInt(usage.cacheReadTokens),
    cacheCreationTokens: toPositiveInt(usage.cacheCreationTokens),
    promptTokensIncludeCache: usage.promptTokensIncludeCache ?? null,
  });
  const baseCacheReadTokens = toPositiveInt(base.cacheReadTokens);
  const baseCacheCreationTokens = toPositiveInt(base.cacheCreationTokens);
  const incomingCacheReadTokens = toPositiveInt(incoming.cacheReadTokens);
  const incomingCacheCreationTokens = toPositiveInt(incoming.cacheCreationTokens);
  const baseScore = base.totalTokens > 0
    ? (base.totalTokens * 10_000 + base.promptTokens + base.completionTokens + baseCacheReadTokens + baseCacheCreationTokens)
    : (base.promptTokens + base.completionTokens + baseCacheReadTokens + baseCacheCreationTokens);
  const incomingScore = incoming.totalTokens > 0
    ? (incoming.totalTokens * 10_000 + incoming.promptTokens + incoming.completionTokens + incomingCacheReadTokens + incomingCacheCreationTokens)
    : (incoming.promptTokens + incoming.completionTokens + incomingCacheReadTokens + incomingCacheCreationTokens);

  if (incomingScore > baseScore) return normalizeUsage(incoming);

  const promptTokens = Math.max(base.promptTokens, incoming.promptTokens);
  const completionTokens = Math.max(base.completionTokens, incoming.completionTokens);
  const totalTokens = Math.max(base.totalTokens, incoming.totalTokens, promptTokens + completionTokens);
  const cacheReadTokens = Math.max(baseCacheReadTokens, incomingCacheReadTokens);
  const cacheCreationTokens = Math.max(baseCacheCreationTokens, incomingCacheCreationTokens);
  const promptTokensIncludeCache = incoming.promptTokensIncludeCache ?? base.promptTokensIncludeCache;

  return normalizeUsage({
    promptTokens,
    completionTokens,
    totalTokens,
    cacheReadTokens,
    cacheCreationTokens,
    promptTokensIncludeCache,
  });
}

export function pullSseDataEvents(buffer: string): { events: string[]; rest: string } {
  const normalized = buffer.replace(/\r\n/g, '\n');
  const events: string[] = [];
  let rest = normalized;

  while (true) {
    const boundary = rest.indexOf('\n\n');
    if (boundary < 0) break;
    const block = rest.slice(0, boundary);
    rest = rest.slice(boundary + 2);

    if (!block.trim()) continue;

    const dataLines = block
      .split('\n')
      .filter((line) => line.startsWith('data:'))
      .map((line) => line.slice(5).trimStart());

    if (dataLines.length <= 0) continue;
    const payload = dataLines.join('\n').trim();
    if (!payload || payload === '[DONE]') continue;
    events.push(payload);
  }

  return { events, rest };
}
