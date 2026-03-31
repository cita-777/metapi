const codexSessionResponseIds = new Map<string, string>();

function normalizeSessionId(sessionId: string): string {
  return sessionId.trim();
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
  codexSessionResponseIds.set(normalizedSessionId, normalizedResponseId);
}

export function clearCodexSessionResponseId(sessionId: string): void {
  const normalized = normalizeSessionId(sessionId);
  if (!normalized) return;
  codexSessionResponseIds.delete(normalized);
}

export function resetCodexSessionResponseStore(): void {
  codexSessionResponseIds.clear();
}
