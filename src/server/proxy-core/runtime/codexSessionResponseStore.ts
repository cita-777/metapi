const MAX_CODEX_SESSION_RESPONSE_IDS = 10_000;

const codexSessionResponseIds = new Map<string, string>();

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
    `session:${normalizedSessionId}`,
  ].filter(Boolean);
  return parts.join('|');
}

export function getCodexSessionResponseId(sessionId: string): string | null {
  const normalized = normalizeSessionId(sessionId);
  if (!normalized) return null;
  return codexSessionResponseIds.get(normalized) ?? null;
}

export function setCodexSessionResponseId(sessionId: string, responseId: string): void {
  const normalizedSessionId = normalizeSessionId(sessionId);
  const normalizedResponseId = responseId.trim();
  if (!normalizedSessionId || !normalizedResponseId) return;
  if (codexSessionResponseIds.has(normalizedSessionId)) {
    codexSessionResponseIds.delete(normalizedSessionId);
  }
  codexSessionResponseIds.set(normalizedSessionId, normalizedResponseId);
  while (codexSessionResponseIds.size > MAX_CODEX_SESSION_RESPONSE_IDS) {
    const oldestKey = codexSessionResponseIds.keys().next().value;
    if (!oldestKey) break;
    codexSessionResponseIds.delete(oldestKey);
  }
}

export function clearCodexSessionResponseId(sessionId: string): void {
  const normalized = normalizeSessionId(sessionId);
  if (!normalized) return;
  codexSessionResponseIds.delete(normalized);
}

export function resetCodexSessionResponseStore(): void {
  codexSessionResponseIds.clear();
}
