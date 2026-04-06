import { pbkdf2Sync, randomUUID } from 'node:crypto';

const CODEX_CLIENT_VERSION = '0.101.0';
const CODEX_DEFAULT_USER_AGENT = 'codex_cli_rs/0.101.0 (Mac OS 26.0.1; arm64) Apple_Terminal/464';
const CLAUDE_DEFAULT_USER_AGENT = 'claude-cli/2.1.63 (external, cli)';
const CLAUDE_DEFAULT_BETA_HEADER = 'claude-code-20250219,oauth-2025-04-20,interleaved-thinking-2025-05-14,context-management-2025-06-27,prompt-caching-scope-2026-01-05';

export function headerValueToString(value: unknown): string | null {
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

export function getInputHeader(
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

function normalizeLowerCaseHeaderMap(
  sources: Array<Record<string, unknown> | Record<string, string> | undefined>,
  shouldSkip: (key: string) => boolean,
): Record<string, string> {
  const normalized: Record<string, string> = {};
  for (const source of sources) {
    if (!source) continue;
    for (const [key, value] of Object.entries(source)) {
      const normalizedValue = headerValueToString(value);
      if (!normalizedValue) continue;
      const normalizedKey = key.toLowerCase();
      if (shouldSkip(normalizedKey)) continue;
      normalized[normalizedKey] = normalizedValue;
    }
  }
  return normalized;
}

export function uuidFromSeed(seed: string): string {
  const derived = pbkdf2Sync(seed, 'metapi-runtime-header-seed', 10_000, 16, 'sha256');
  const bytes = new Uint8Array(derived);
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

export function mergeClaudeBetaHeader(
  explicitValue: string | null,
  defaultValue: string,
  extraBetas: string[] = [],
): string {
  const seen = new Set<string>();
  const merged: string[] = [];
  for (const source of [defaultValue, explicitValue ?? '', ...extraBetas]) {
    for (const entry of source.split(',')) {
      const normalized = entry.trim();
      if (!normalized || seen.has(normalized)) continue;
      seen.add(normalized);
      merged.push(normalized);
    }
  }
  return merged.join(',');
}

export function parseGeminiCliUserAgentRuntime(userAgent: string | null): {
  version: string;
  platform: string;
  arch: string;
} | null {
  if (!userAgent) return null;
  const match = /^GeminiCLI\/([^/]+)\/[^ ]+ \(([^;]+); ([^)]+)\)$/i.exec(userAgent.trim());
  if (!match) return null;
  return {
    version: match[1] || '0.31.0',
    platform: match[2] || 'win32',
    arch: match[3] || 'x64',
  };
}

export function buildGeminiCliUserAgent(modelName: string, existingUserAgent?: string | null): string {
  const parsed = parseGeminiCliUserAgentRuntime(existingUserAgent ?? null);
  const version = parsed?.version || '0.31.0';
  const platform = parsed?.platform || 'win32';
  const arch = parsed?.arch || 'x64';
  const effectiveModel = typeof modelName === 'string' ? modelName.trim() : '';
  return `GeminiCLI/${version}/${effectiveModel || 'unknown'} (${platform}; ${arch})`;
}

function asTrimmedString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

export function buildCodexRuntimeHeaders(input: {
  baseHeaders: Record<string, string>;
  providerHeaders?: Record<string, string>;
  stream?: boolean;
  explicitSessionId?: string | null;
  continuityKey?: string | null;
  versionDefault?: string;
  userAgentDefault?: string;
  userAgentOverride?: string | null;
  originatorDefault?: string;
  codexBetaFeatures?: string | null;
  codexTurnState?: string | null;
  codexTurnMetadata?: string | null;
  timingMetrics?: string | null;
  openAiBeta?: string | null;
}): Record<string, string> {
  const authorization = (
    getInputHeader(input.baseHeaders, 'authorization')
    || getInputHeader(input.baseHeaders, 'Authorization')
    || ''
  );
  const originator = getInputHeader(input.providerHeaders, 'originator')
    || input.originatorDefault
    || 'codex_cli_rs';
  const accountId = getInputHeader(input.providerHeaders, 'chatgpt-account-id');
  const version = getInputHeader(input.baseHeaders, 'version')
    || input.versionDefault
    || CODEX_CLIENT_VERSION;
  const userAgent = input.userAgentOverride
    || getInputHeader(input.baseHeaders, 'user-agent')
    || input.userAgentDefault
    || CODEX_DEFAULT_USER_AGENT;
  const codexBetaFeatures = input.codexBetaFeatures || null;
  const codexTurnState = input.codexTurnState || null;
  const codexTurnMetadata = input.codexTurnMetadata || null;
  const timingMetrics = input.timingMetrics || null;
  const openAiBeta = input.openAiBeta || null;
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
    ...(authorization ? { Authorization: authorization } : {}),
    'Content-Type': 'application/json',
    ...(accountId ? { 'Chatgpt-Account-Id': accountId } : {}),
    Originator: originator,
    Version: version,
    ...(codexBetaFeatures ? { 'x-codex-beta-features': codexBetaFeatures } : {}),
    ...(codexTurnState ? { 'x-codex-turn-state': codexTurnState } : {}),
    ...(codexTurnMetadata ? { 'x-codex-turn-metadata': codexTurnMetadata } : {}),
    ...(timingMetrics ? { 'x-responsesapi-include-timing-metrics': timingMetrics } : {}),
    ...(openAiBeta ? { 'OpenAI-Beta': openAiBeta } : {}),
    Session_id: sessionId,
    ...(conversationId ? { Conversation_id: conversationId } : {}),
    'User-Agent': userAgent,
    Accept: input.stream === false ? 'application/json' : 'text/event-stream',
    Connection: 'Keep-Alive',
  };
}

export function buildClaudeRuntimeHeaders(input: {
  baseHeaders: Record<string, string>;
  claudeHeaders: Record<string, string>;
  anthropicVersion: string;
  stream: boolean;
  isClaudeOauthUpstream: boolean;
  tokenValue: string;
  extraBetas?: string[];
  defaultBetaHeader?: string;
  defaultUserAgent?: string;
}): Record<string, string> {
  const anthropicBeta = mergeClaudeBetaHeader(
    getInputHeader(input.claudeHeaders, 'anthropic-beta'),
    input.defaultBetaHeader || CLAUDE_DEFAULT_BETA_HEADER,
    input.extraBetas,
  );
  const passthroughHeaders = normalizeLowerCaseHeaderMap(
    [input.baseHeaders, input.claudeHeaders],
    (key) => (
      key === 'accept'
      || key === 'accept-encoding'
      || key === 'anthropic-beta'
      || key === 'anthropic-dangerous-direct-browser-access'
      || key === 'anthropic-version'
      || key === 'authorization'
      || key === 'connection'
      || key === 'user-agent'
      || key === 'x-api-key'
      || key === 'x-app'
      || key.startsWith('x-stainless-')
    ),
  );
  const headers: Record<string, string> = {
    ...passthroughHeaders,
    'anthropic-version': input.anthropicVersion,
    ...(anthropicBeta ? { 'anthropic-beta': anthropicBeta } : {}),
    'Anthropic-Dangerous-Direct-Browser-Access': 'true',
    'X-App': 'cli',
    'X-Stainless-Retry-Count': getInputHeader(input.claudeHeaders, 'x-stainless-retry-count') || '0',
    'X-Stainless-Runtime-Version': getInputHeader(input.claudeHeaders, 'x-stainless-runtime-version') || 'v24.3.0',
    'X-Stainless-Package-Version': getInputHeader(input.claudeHeaders, 'x-stainless-package-version') || '0.74.0',
    'X-Stainless-Runtime': getInputHeader(input.claudeHeaders, 'x-stainless-runtime') || 'node',
    'X-Stainless-Lang': getInputHeader(input.claudeHeaders, 'x-stainless-lang') || 'js',
    'X-Stainless-Arch': getInputHeader(input.claudeHeaders, 'x-stainless-arch') || 'x64',
    'X-Stainless-Os': getInputHeader(input.claudeHeaders, 'x-stainless-os') || 'Windows',
    'X-Stainless-Timeout': getInputHeader(input.claudeHeaders, 'x-stainless-timeout') || '600',
    'User-Agent': getInputHeader(input.claudeHeaders, 'user-agent') || input.defaultUserAgent || CLAUDE_DEFAULT_USER_AGENT,
    Connection: 'keep-alive',
    Accept: input.stream ? 'text/event-stream' : 'application/json',
    'Accept-Encoding': 'gzip, deflate, br, zstd',
  };
  if (input.isClaudeOauthUpstream) {
    headers.Authorization = `Bearer ${input.tokenValue}`;
  } else {
    headers['x-api-key'] = input.tokenValue;
  }
  return headers;
}

export function buildGeminiCliRuntimeHeaders(input: {
  baseHeaders: Record<string, string>;
  providerHeaders?: Record<string, string>;
  modelName: string;
  stream: boolean;
}): Record<string, string> {
  const authorization = getInputHeader(input.baseHeaders, 'authorization');
  const apiClient = (
    getInputHeader(input.providerHeaders, 'x-goog-api-client')
    || getInputHeader(input.baseHeaders, 'x-goog-api-client')
  );
  const userAgent = buildGeminiCliUserAgent(
    input.modelName,
    getInputHeader(input.providerHeaders, 'user-agent') || getInputHeader(input.baseHeaders, 'user-agent'),
  );

  const headers: Record<string, string> = {
    ...(authorization ? { Authorization: authorization } : {}),
    'Content-Type': 'application/json',
    'User-Agent': userAgent,
  };
  if (apiClient) {
    headers['X-Goog-Api-Client'] = apiClient;
  }
  if (input.stream) {
    headers.Accept = 'text/event-stream';
  }
  return headers;
}
