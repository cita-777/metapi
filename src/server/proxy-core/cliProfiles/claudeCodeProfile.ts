import type { CliProfileDefinition } from './types.js';

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

const claudeCodeUserIdPattern = /^user_[0-9a-f]{64}_account__session_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const claudeCodeUserAgentPattern = /^claude-cli\/\d+\.\d+\.\d+/i;

function isClaudeSurface(path: string): boolean {
  const normalizedPath = path.trim().toLowerCase();
  return normalizedPath === '/v1/messages'
    || normalizedPath === '/anthropic/v1/messages'
    || normalizedPath === '/v1/messages/count_tokens';
}

function getHeaderValue(headers: Record<string, unknown> | undefined, targetKey: string): string | null {
  if (!headers) return null;
  const normalizedTarget = targetKey.trim().toLowerCase();
  for (const [rawKey, rawValue] of Object.entries(headers)) {
    if (rawKey.trim().toLowerCase() !== normalizedTarget) continue;
    if (typeof rawValue === 'string') {
      const trimmed = rawValue.trim();
      return trimmed || null;
    }
    if (!Array.isArray(rawValue)) continue;
    for (const item of rawValue) {
      if (typeof item !== 'string') continue;
      const trimmed = item.trim();
      if (trimmed) return trimmed;
    }
  }
  return null;
}

function hasClaudeCodeHeaderFingerprint(headers: Record<string, unknown> | undefined): boolean {
  const userAgent = getHeaderValue(headers, 'user-agent') || '';
  if (!claudeCodeUserAgentPattern.test(userAgent)) return false;
  if (!getHeaderValue(headers, 'anthropic-beta')) return false;
  if (!getHeaderValue(headers, 'anthropic-version')) return false;
  return (getHeaderValue(headers, 'x-app') || '').trim().toLowerCase() === 'cli';
}

export function extractClaudeCodeSessionId(userId: string): string | null {
  const trimmed = userId.trim();
  if (!claudeCodeUserIdPattern.test(trimmed)) return null;

  const sessionPrefix = '__session_';
  const sessionIndex = trimmed.lastIndexOf(sessionPrefix);
  if (sessionIndex === -1) return null;

  const sessionId = trimmed.slice(sessionIndex + sessionPrefix.length).trim();
  return sessionId || null;
}

export const claudeCodeCliProfile: CliProfileDefinition = {
  id: 'claude_code',
  capabilities: {
    supportsResponsesCompact: false,
    supportsResponsesWebsocketIncremental: false,
    preservesContinuation: true,
    supportsCountTokens: true,
    echoesTurnState: false,
  },
  detect(input) {
    if (!isClaudeSurface(input.downstreamPath)) return null;
    const userId = isRecord(input.body) && isRecord(input.body.metadata) && typeof input.body.metadata.user_id === 'string'
      ? input.body.metadata.user_id.trim()
      : '';
    const sessionId = userId ? extractClaudeCodeSessionId(userId) : null;
    if (!sessionId && !hasClaudeCodeHeaderFingerprint(input.headers)) return null;

    return {
      id: 'claude_code',
      ...(sessionId ? { sessionId, traceHint: sessionId } : {}),
      clientAppId: 'claude_code',
      clientAppName: 'Claude Code',
      clientConfidence: 'exact',
    };
  },
};
