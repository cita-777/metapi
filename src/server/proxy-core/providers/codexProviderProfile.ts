import { createHash, randomUUID } from 'node:crypto';
import type { PreparedProviderRequest, PrepareProviderRequestInput, ProviderProfile } from './types.js';

const CODEX_CLIENT_VERSION = '0.101.0';
const CODEX_DEFAULT_USER_AGENT = 'codex_cli_rs/0.101.0 (Mac OS 26.0.1; arm64) Apple_Terminal/464';

function asTrimmedString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function headerValueToString(value: unknown): string | null {
  if (typeof value === 'string') {
    const trimmed = value.trim();
    return trimmed || null;
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      if (typeof item !== 'string') continue;
      const trimmed = item.trim();
      if (trimmed) return trimmed;
    }
  }
  return null;
}

function getInputHeader(
  headers: Record<string, unknown> | Record<string, string> | undefined,
  key: string,
): string | null {
  if (!headers) return null;
  for (const [candidateKey, candidateValue] of Object.entries(headers)) {
    if (candidateKey.toLowerCase() !== key.toLowerCase()) continue;
    return headerValueToString(candidateValue);
  }
  return null;
}

function uuidFromSeed(seed: string): string {
  const hash = createHash('sha1').update(seed).digest();
  const bytes = new Uint8Array(hash.subarray(0, 16));
  bytes[6] = (bytes[6]! & 0x0f) | 0x50;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  const hex = Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('');
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20, 32),
  ].join('-');
}

function buildCodexRuntimeHeaders(input: {
  baseHeaders: Record<string, string>;
  providerHeaders?: Record<string, string>;
  explicitSessionId?: string | null;
  continuityKey?: string | null;
}): Record<string, string> {
  const authorization = (
    getInputHeader(input.baseHeaders, 'authorization')
    || getInputHeader(input.baseHeaders, 'Authorization')
    || ''
  );
  const originator = getInputHeader(input.providerHeaders, 'originator') || 'codex_cli_rs';
  const accountId = getInputHeader(input.providerHeaders, 'chatgpt-account-id');
  const version = getInputHeader(input.baseHeaders, 'version') || CODEX_CLIENT_VERSION;
  const userAgent = getInputHeader(input.baseHeaders, 'user-agent') || CODEX_DEFAULT_USER_AGENT;
  const explicitSessionId = asTrimmedString(input.explicitSessionId);
  const continuityKey = asTrimmedString(input.continuityKey);
  const sessionId = (
    getInputHeader(input.baseHeaders, 'session_id')
    || getInputHeader(input.baseHeaders, 'session-id')
    || explicitSessionId
    || (continuityKey ? uuidFromSeed(`metapi:codex:${continuityKey}`) : null)
    || randomUUID()
  );
  const conversationId = (
    getInputHeader(input.baseHeaders, 'conversation_id')
    || getInputHeader(input.baseHeaders, 'conversation-id')
    || explicitSessionId
    || (continuityKey ? sessionId : null)
  );

  return {
    Authorization: authorization,
    'Content-Type': 'application/json',
    ...(accountId ? { 'Chatgpt-Account-Id': accountId } : {}),
    Originator: originator,
    Version: version,
    Session_id: sessionId,
    ...(conversationId ? { Conversation_id: conversationId } : {}),
    'User-Agent': userAgent,
    Accept: 'text/event-stream',
    Connection: 'Keep-Alive',
  };
}

export const codexProviderProfile: ProviderProfile = {
  id: 'codex',
  prepareRequest(input: PrepareProviderRequestInput): PreparedProviderRequest {
    const headers = buildCodexRuntimeHeaders({
      baseHeaders: input.baseHeaders,
      providerHeaders: input.providerHeaders,
      explicitSessionId: asTrimmedString(input.codexExplicitSessionId) || null,
      continuityKey: asTrimmedString(input.codexSessionCacheKey) || null,
    });
    const codexSessionId = getInputHeader(headers, 'session_id') || getInputHeader(headers, 'session-id');
    const shouldInjectDerivedPromptCacheKey = !!codexSessionId
      && !asTrimmedString(input.body.prompt_cache_key)
      && !asTrimmedString(input.codexExplicitSessionId)
      && !!asTrimmedString(input.codexSessionCacheKey);
    const body = shouldInjectDerivedPromptCacheKey
      ? {
        ...input.body,
        prompt_cache_key: codexSessionId,
      }
      : input.body;

    return {
      path: '/responses',
      headers,
      body,
      runtime: {
        executor: 'codex',
        modelName: input.modelName,
        stream: input.stream,
        oauthProjectId: asTrimmedString(input.oauthProjectId) || null,
      },
    };
  },
};
