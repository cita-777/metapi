const MAX_CODEX_SESSION_RESPONSE_IDS = 10_000;

const codexSessionResponseIds = new Map<string, string>();

const SCOPED_SESSION_SEGMENT_PREFIX = 'session:';
const SCOPED_STORE_KEY_SEGMENT_PATTERN = /^(site|account|channel):\d+$/;

function buildScopedSessionSegment(sessionId: string): string {
  return `${SCOPED_SESSION_SEGMENT_PREFIX}${encodeURIComponent(sessionId)}`;
}

function extractScopedSessionSegment(sessionId: string): string {
  const normalizedSessionId = normalizeSessionId(sessionId);
  if (!normalizedSessionId) return '';

  if (normalizedSessionId.startsWith(SCOPED_SESSION_SEGMENT_PREFIX)) {
    return normalizedSessionId;
  }

  const scopedSegments = normalizedSessionId
    .split('|')
    .map((segment) => segment.trim())
    .filter(Boolean);
  if (scopedSegments.length <= 1) return '';

  const sessionSegment = scopedSegments[scopedSegments.length - 1];
  if (!sessionSegment.startsWith(SCOPED_SESSION_SEGMENT_PREFIX)) {
    return '';
  }
  const scopeSegments = scopedSegments.slice(0, -1);
  if (!scopeSegments.every((segment) => SCOPED_STORE_KEY_SEGMENT_PATTERN.test(segment))) {
    return '';
  }
  return sessionSegment;
}

function getBareSessionStoreKey(sessionId: string): string {
  return extractScopedSessionSegment(sessionId);
}

function getFallbackSessionStoreKeys(sessionId: string): string[] {
  const normalizedSessionId = normalizeSessionId(sessionId);
  if (!normalizedSessionId) return [];

  const bareSessionKey = getBareSessionStoreKey(normalizedSessionId);
  if (!bareSessionKey) return [];
  if (normalizedSessionId === bareSessionKey) return [];
  return [bareSessionKey];
}

function getSessionStoreKeys(sessionId: string): string[] {
  const normalizedSessionId = normalizeSessionId(sessionId);
  if (!normalizedSessionId) return [];
  return [
    normalizedSessionId,
    ...getFallbackSessionStoreKeys(normalizedSessionId),
  ];
}

function reconcileScopedSessionFallback(bareSessionKey: string): void {
  if (!bareSessionKey) return;

  for (const key of codexSessionResponseIds.keys()) {
    if (key === bareSessionKey) continue;
    if (getBareSessionStoreKey(key) !== bareSessionKey) continue;
    codexSessionResponseIds.delete(key);
  }
}

function normalizeSessionId(sessionId: string): string {
  return sessionId.trim();
}

export function buildCodexSessionResponseStoreKey(input: {
  sessionId: string;
  siteId?: number | null;
  accountId?: number | null;
  channelId?: number | null;
}): string {
  const normalizedSessionId = normalizeSessionId(input.sessionId);
  if (!normalizedSessionId) return '';
  const parts = [
    Number.isFinite(input.siteId as number) && Number(input.siteId) > 0 ? `site:${Math.trunc(Number(input.siteId))}` : '',
    Number.isFinite(input.accountId as number) && Number(input.accountId) > 0 ? `account:${Math.trunc(Number(input.accountId))}` : '',
    Number.isFinite(input.channelId as number) && Number(input.channelId) > 0 ? `channel:${Math.trunc(Number(input.channelId))}` : '',
    buildScopedSessionSegment(normalizedSessionId),
  ].filter(Boolean);
  return parts.join('|');
}

export function getCodexSessionResponseId(sessionId: string): string | null {
  const normalized = normalizeSessionId(sessionId);
  if (!normalized) return null;

  const direct = codexSessionResponseIds.get(normalized);
  if (direct) return direct;

  for (const fallbackKey of getFallbackSessionStoreKeys(normalized)) {
    const fallback = codexSessionResponseIds.get(fallbackKey);
    if (fallback) {
      reconcileScopedSessionFallback(fallbackKey);
      return fallback;
    }
  }

  return null;
}

export function setCodexSessionResponseId(sessionId: string, responseId: string): void {
  const normalizedSessionId = normalizeSessionId(sessionId);
  const normalizedResponseId = responseId.trim();
  if (!normalizedSessionId || !normalizedResponseId) return;

  const keysToWrite = new Set<string>(getSessionStoreKeys(normalizedSessionId));

  for (const key of keysToWrite) {
    if (codexSessionResponseIds.has(key)) {
      codexSessionResponseIds.delete(key);
    }
    codexSessionResponseIds.set(key, normalizedResponseId);
  }

  while (codexSessionResponseIds.size > MAX_CODEX_SESSION_RESPONSE_IDS) {
    const oldestKey = codexSessionResponseIds.keys().next().value;
    if (!oldestKey) break;
    codexSessionResponseIds.delete(oldestKey);
  }
}

export function clearCodexSessionResponseId(sessionId: string): void {
  const normalized = normalizeSessionId(sessionId);
  if (!normalized) return;
  for (const key of getSessionStoreKeys(normalized)) {
    codexSessionResponseIds.delete(key);
  }
}

export function resetCodexSessionResponseStore(): void {
  codexSessionResponseIds.clear();
}
