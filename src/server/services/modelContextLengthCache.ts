/**
 * In-memory cache for model context length metadata.
 *
 * Populated during upstream model discovery when the upstream /v1/models
 * response includes per-model context_length (or similar fields).
 * Used by the /v1/models surface to enrich the downstream response.
 *
 * Default context length: 1_000_000 (1M tokens) when upstream does not provide one.
 */

const DEFAULT_CONTEXT_LENGTH = 1_000_000;
const DEFAULT_SOURCE_SCOPE = '__default__';

const cache = new Map<string, Map<string, number>>();

function normalizeKey(modelName: string): string {
  return modelName.trim().toLowerCase();
}

function normalizeSourceScope(sourceScope?: string): string {
  const normalized = String(sourceScope || '').trim().toLowerCase();
  return normalized || DEFAULT_SOURCE_SCOPE;
}

function getOrCreateScopeCache(sourceScope?: string): Map<string, number> {
  const scopeKey = normalizeSourceScope(sourceScope);
  const scopedCache = cache.get(scopeKey);
  if (scopedCache) return scopedCache;
  const next = new Map<string, number>();
  cache.set(scopeKey, next);
  return next;
}

function getNormalizedModelKey(modelName: string): string {
  return normalizeKey(modelName);
}

function isValidContextLength(value: number): boolean {
  return Number.isFinite(value) && value > 0;
}

function buildScopedEntryKey(sourceScope: string | undefined, modelName: string): [string, string] | null {
  const normalizedModelName = getNormalizedModelKey(modelName);
  if (!normalizedModelName) return null;
  return [normalizeSourceScope(sourceScope), normalizedModelName];
}

export function buildAccountModelContextLengthScope(accountId: number): string {
  return `account:${accountId}`;
}

export function buildEndpointModelContextLengthScope(baseUrl: string): string {
  return `endpoint:${normalizeKey(baseUrl)}`;
}

/**
 * Store context length for a single model.
 */
export function setModelContextLength(
  modelName: string,
  contextLength: number,
  sourceScope?: string,
): void {
  const scopedEntry = buildScopedEntryKey(sourceScope, modelName);
  if (!scopedEntry || !isValidContextLength(contextLength)) return;
  const [scopeKey, normalizedModelName] = scopedEntry;
  getOrCreateScopeCache(scopeKey).set(normalizedModelName, Math.round(contextLength));
}

/**
 * Bulk-store context lengths from a map (e.g. extracted from upstream payload).
 * Replaces the existing cache for the provided source scope so stale values
 * do not linger when an upstream stops sending context metadata.
 */
export function setModelContextLengths(
  entries: Map<string, number>,
  sourceScope?: string,
): void {
  const scopeKey = normalizeSourceScope(sourceScope);
  const nextScopeCache = new Map<string, number>();
  for (const [name, length] of entries) {
    const scopedEntry = buildScopedEntryKey(scopeKey, name);
    if (!scopedEntry || !isValidContextLength(length)) continue;
    nextScopeCache.set(scopedEntry[1], Math.round(length));
  }

  if (nextScopeCache.size === 0) {
    cache.delete(scopeKey);
    return;
  }

  cache.set(scopeKey, nextScopeCache);
}

/**
 * Get context length for a model. Returns the default if not found.
 */
export function getModelContextLength(modelName: string, sourceScope?: string): number {
  const scopedEntry = buildScopedEntryKey(sourceScope, modelName);
  if (!scopedEntry) return DEFAULT_CONTEXT_LENGTH;
  return cache.get(scopedEntry[0])?.get(scopedEntry[1]) ?? DEFAULT_CONTEXT_LENGTH;
}

/**
 * Check if a model has an explicit context length in the cache.
 */
export function hasModelContextLength(modelName: string, sourceScope?: string): boolean {
  const scopedEntry = buildScopedEntryKey(sourceScope, modelName);
  if (!scopedEntry) return false;
  return cache.get(scopedEntry[0])?.has(scopedEntry[1]) ?? false;
}

/**
 * Get cached entries for a specific source scope.
 */
export function getAllModelContextLengths(sourceScope?: string): ReadonlyMap<string, number> {
  return cache.get(normalizeSourceScope(sourceScope)) ?? new Map<string, number>();
}

/**
 * Clear the cache (for testing or refresh).
 */
export function clearModelContextLengthCache(sourceScope?: string): void {
  if (sourceScope === undefined) {
    cache.clear();
    return;
  }
  cache.delete(normalizeSourceScope(sourceScope));
}

/**
 * Extract context lengths from an OpenAI-compatible /v1/models payload.
 *
 * Looks for context_length on each item in data[]. If none of the items
 * carry context_length, returns an empty map (caller should fall back to default).
 */
export function extractContextLengthsFromPayload(payload: unknown): Map<string, number> {
  const result = new Map<string, number>();
  if (!payload || typeof payload !== 'object') return result;

  const data = (payload as Record<string, unknown>).data;
  if (!Array.isArray(data)) return result;

  for (const item of data) {
    if (!item || typeof item !== 'object') continue;
    const record = item as Record<string, unknown>;

    const id = typeof record.id === 'string' ? record.id.trim() : '';
    if (!id) continue;

    // Try multiple field names that upstreams may use
    const contextLength = pickPositiveInt(record, [
      'context_length',
      'contextLength',
      'max_context_length',
      'maxContextLength',
      'context_window',
      'contextWindow',
    ]);

    if (contextLength > 0) {
      result.set(id, contextLength);
    }
  }

  return result;
}

function pickPositiveInt(obj: Record<string, unknown>, keys: string[]): number {
  for (const key of keys) {
    const value = obj[key];
    if (typeof value === 'number' && Number.isFinite(value) && value > 0) {
      return Math.round(value);
    }
    if (typeof value === 'string') {
      const parsed = Number(value);
      if (Number.isFinite(parsed) && parsed > 0) {
        return Math.round(parsed);
      }
    }
  }
  return 0;
}
