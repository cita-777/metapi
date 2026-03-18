import type { CliProfileDefinition } from './types.js';

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

const claudeCodeUserIdPattern = /^user_[0-9a-f]{64}_account__session_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function isClaudeSurface(path: string): boolean {
  const normalizedPath = path.trim().toLowerCase();
  return normalizedPath === '/v1/messages'
    || normalizedPath === '/anthropic/v1/messages'
    || normalizedPath === '/v1/messages/count_tokens';
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
    if (!isRecord(input.body) || !isRecord(input.body.metadata)) return null;

    const userId = typeof input.body.metadata.user_id === 'string'
      ? input.body.metadata.user_id.trim()
      : '';
    const sessionId = userId ? extractClaudeCodeSessionId(userId) : null;
    if (!sessionId) return null;

    return {
      id: 'claude_code',
      sessionId,
      traceHint: sessionId,
    };
  },
};
