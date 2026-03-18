import type { PreparedProviderRequest, PrepareProviderRequestInput, ProviderProfile } from './types.js';

const CLAUDE_DEFAULT_USER_AGENT = 'claude-cli/2.1.63 (external, cli)';
const CLAUDE_DEFAULT_BETA_HEADER = 'claude-code-20250219,oauth-2025-04-20,interleaved-thinking-2025-05-14,context-management-2025-06-27,prompt-caching-scope-2026-01-05';

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

function mergeClaudeBetaHeader(
  explicitValue: string | null,
  extraBetas: string[] = [],
): string {
  const source = explicitValue || CLAUDE_DEFAULT_BETA_HEADER;
  const seen = new Set<string>();
  const merged: string[] = [];
  for (const entry of source.split(',')) {
    const normalized = entry.trim();
    if (!normalized || seen.has(normalized)) continue;
    seen.add(normalized);
    merged.push(normalized);
  }
  if (!explicitValue) {
    for (const entry of extraBetas) {
      const normalized = entry.trim();
      if (!normalized || seen.has(normalized)) continue;
      seen.add(normalized);
      merged.push(normalized);
    }
  }
  return merged.join(',');
}

function buildClaudeRuntimeHeaders(input: {
  baseHeaders: Record<string, string>;
  claudeHeaders: Record<string, string>;
  anthropicVersion: string;
  stream: boolean;
  isClaudeOauthUpstream: boolean;
  tokenValue: string;
}): Record<string, string> {
  const anthropicBeta = mergeClaudeBetaHeader(
    getInputHeader(input.claudeHeaders, 'anthropic-beta'),
  );
  const headers: Record<string, string> = {
    ...input.baseHeaders,
    ...input.claudeHeaders,
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
    'User-Agent': getInputHeader(input.claudeHeaders, 'user-agent') || CLAUDE_DEFAULT_USER_AGENT,
    Connection: 'keep-alive',
    Accept: input.stream ? 'text/event-stream' : 'application/json',
    'Accept-Encoding': input.stream ? 'identity' : 'gzip, deflate, br, zstd',
  };
  if (input.isClaudeOauthUpstream) {
    headers.Authorization = `Bearer ${input.tokenValue}`;
  } else {
    headers['x-api-key'] = input.tokenValue;
  }
  return headers;
}

export const claudeProviderProfile: ProviderProfile = {
  id: 'claude',
  prepareRequest(input: PrepareProviderRequestInput): PreparedProviderRequest {
    const anthropicVersion = (
      input.claudeHeaders?.['anthropic-version']
      || input.baseHeaders['anthropic-version']
      || '2023-06-01'
    );
    const isClaudeOauthUpstream = input.sitePlatform?.trim().toLowerCase() === 'claude'
      && input.oauthProvider === 'claude';
    const isCountTokens = input.action === 'countTokens';

    return {
      path: isCountTokens ? '/v1/messages/count_tokens?beta=true' : '/v1/messages',
      headers: buildClaudeRuntimeHeaders({
        baseHeaders: input.baseHeaders,
        claudeHeaders: input.claudeHeaders ?? {},
        anthropicVersion,
        stream: isCountTokens ? false : input.stream,
        isClaudeOauthUpstream,
        tokenValue: input.tokenValue,
      }),
      body: input.body,
      runtime: {
        executor: 'claude',
        modelName: input.modelName,
        stream: isCountTokens ? false : input.stream,
        oauthProjectId: null,
        ...(isCountTokens ? { action: 'countTokens' } : {}),
      },
    };
  },
};
