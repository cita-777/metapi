import { createHash, randomUUID } from 'node:crypto';
import { resolveProviderProfile } from '../../proxy-core/providers/registry.js';
import { fetchModelPricingCatalog } from '../../services/modelPricingService.js';
import type { DownstreamFormat } from '../../transformers/shared/normalized.js';
import {
  convertOpenAiBodyToResponsesBody as convertOpenAiBodyToResponsesBodyViaTransformer,
  sanitizeResponsesBodyForProxy as sanitizeResponsesBodyForProxyViaTransformer,
} from '../../transformers/openai/responses/conversion.js';
import {
  convertOpenAiBodyToAnthropicMessagesBody,
  sanitizeAnthropicMessagesBody,
} from '../../transformers/anthropic/messages/conversion.js';
import {
  buildGeminiGenerateContentRequestFromOpenAi,
} from './geminiCliCompat.js';
export {
  buildMinimalJsonHeadersForCompatibility,
  isEndpointDispatchDeniedError,
  isEndpointDowngradeError,
  isUnsupportedMediaTypeError,
  promoteResponsesCandidateAfterLegacyChatError,
  shouldPreferResponsesAfterLegacyChatError,
} from '../../transformers/shared/endpointCompatibility.js';

export type UpstreamEndpoint = 'chat' | 'messages' | 'responses';
export type EndpointPreference = DownstreamFormat | 'responses';

type ChannelContext = {
  site: {
    id: number;
    url: string;
    platform: string;
    apiKey?: string | null;
  };
  account: {
    id: number;
    accessToken?: string | null;
    apiToken?: string | null;
  };
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object';
}

function asTrimmedString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function normalizePlatformName(platform: unknown): string {
  return asTrimmedString(platform).toLowerCase();
}

function isClaudeFamilyModel(modelName: string): boolean {
  const normalized = asTrimmedString(modelName).toLowerCase();
  if (!normalized) return false;
  return normalized === 'claude' || normalized.startsWith('claude-') || normalized.includes('claude');
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

const HOP_BY_HOP_HEADERS = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]);

const BLOCKED_PASSTHROUGH_HEADERS = new Set([
  'host',
  'content-type',
  'content-length',
  'accept-encoding',
  'cookie',
  'authorization',
  'x-api-key',
  'x-goog-api-key',
  'sec-websocket-key',
  'sec-websocket-version',
  'sec-websocket-extensions',
]);

const CODEX_CLIENT_VERSION = '0.101.0';
const CODEX_DEFAULT_USER_AGENT = 'codex_cli_rs/0.101.0 (Mac OS 26.0.1; arm64) Apple_Terminal/464';
const ANTIGRAVITY_RUNTIME_USER_AGENT = 'antigravity/1.19.6 darwin/arm64';
const CLAUDE_DEFAULT_USER_AGENT = 'claude-cli/2.1.63 (external, cli)';
const CLAUDE_DEFAULT_BETA_HEADER = 'claude-code-20250219,oauth-2025-04-20,interleaved-thinking-2025-05-14,context-management-2025-06-27,prompt-caching-scope-2026-01-05';

function shouldSkipPassthroughHeader(key: string): boolean {
  return HOP_BY_HOP_HEADERS.has(key) || BLOCKED_PASSTHROUGH_HEADERS.has(key);
}

function extractSafePassthroughHeaders(
  headers?: Record<string, unknown>,
): Record<string, string> {
  if (!headers) return {};

  const forwarded: Record<string, string> = {};
  for (const [rawKey, rawValue] of Object.entries(headers)) {
    const key = rawKey.toLowerCase();
    if (!key || shouldSkipPassthroughHeader(key)) continue;

    const value = headerValueToString(rawValue);
    if (!value) continue;
    forwarded[key] = value;
  }

  return forwarded;
}

function extractClaudePassthroughHeaders(
  headers?: Record<string, unknown>,
): Record<string, string> {
  if (!headers) return {};

  const forwarded: Record<string, string> = {};
  for (const [rawKey, rawValue] of Object.entries(headers)) {
    const key = rawKey.toLowerCase();
    const shouldForward = (
      key.startsWith('anthropic-')
      || key.startsWith('x-claude-')
      || key.startsWith('x-stainless-')
    );
    if (!shouldForward) continue;

    const value = headerValueToString(rawValue);
    if (!value) continue;
    forwarded[key] = value;
  }

  return forwarded;
}

function extractResponsesPassthroughHeaders(
  headers?: Record<string, unknown>,
): Record<string, string> {
  if (!headers) return {};

  const forwarded: Record<string, string> = {};
  for (const [rawKey, rawValue] of Object.entries(headers)) {
    const key = rawKey.toLowerCase();
    const shouldForward = (
      key.startsWith('openai-')
      || key.startsWith('x-openai-')
      || key.startsWith('x-stainless-')
      || key.startsWith('chatgpt-')
      || key === 'originator'
    );
    if (!shouldForward) continue;

    const value = headerValueToString(rawValue);
    if (!value) continue;
    forwarded[key] = value;
  }

  return forwarded;
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

function parseGeminiCliUserAgentRuntime(userAgent: string | null): {
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

function buildGeminiCLIUserAgent(modelName: string, existingUserAgent?: string | null): string {
  const parsed = parseGeminiCliUserAgentRuntime(existingUserAgent ?? null);
  const version = parsed?.version || '0.31.0';
  const platform = parsed?.platform || 'win32';
  const arch = parsed?.arch || 'x64';
  const effectiveModel = asTrimmedString(modelName) || 'unknown';
  return `GeminiCLI/${version}/${effectiveModel} (${platform}; ${arch})`;
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

function extractClaudeBetasFromBody(body: Record<string, unknown>): {
  body: Record<string, unknown>;
  betas: string[];
} {
  const next = { ...body };
  const rawBetas = next.betas;
  delete next.betas;

  if (typeof rawBetas === 'string') {
    return {
      body: next,
      betas: rawBetas.split(',').map((entry) => entry.trim()).filter(Boolean),
    };
  }

  if (Array.isArray(rawBetas)) {
    return {
      body: next,
      betas: rawBetas
        .map((entry) => asTrimmedString(entry))
        .filter(Boolean),
    };
  }

  return {
    body: next,
    betas: [],
  };
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

function buildGeminiCliRuntimeHeaders(input: {
  baseHeaders: Record<string, string>;
  providerHeaders?: Record<string, string>;
  modelName: string;
  stream: boolean;
}): Record<string, string> {
  const apiClient = (
    getInputHeader(input.providerHeaders, 'x-goog-api-client')
    || getInputHeader(input.baseHeaders, 'x-goog-api-client')
  );
  const userAgent = buildGeminiCLIUserAgent(
    input.modelName,
    getInputHeader(input.providerHeaders, 'user-agent') || getInputHeader(input.baseHeaders, 'user-agent'),
  );

  const headers: Record<string, string> = {
    Authorization: input.baseHeaders.Authorization,
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

function buildAntigravityRuntimeHeaders(input: {
  baseHeaders: Record<string, string>;
  stream: boolean;
}): Record<string, string> {
  const headers: Record<string, string> = {
    Authorization: input.baseHeaders.Authorization,
    'Content-Type': 'application/json',
    Accept: input.stream ? 'text/event-stream' : 'application/json',
    'User-Agent': ANTIGRAVITY_RUNTIME_USER_AGENT,
  };
  return headers;
}

function buildClaudeRuntimeHeaders(input: {
  baseHeaders: Record<string, string>;
  claudeHeaders: Record<string, string>;
  anthropicVersion: string;
  stream: boolean;
  isClaudeOauthUpstream: boolean;
  tokenValue: string;
  extraBetas?: string[];
}): Record<string, string> {
  const anthropicBeta = mergeClaudeBetaHeader(
    getInputHeader(input.claudeHeaders, 'anthropic-beta'),
    input.extraBetas,
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

function ensureStreamAcceptHeader(
  headers: Record<string, string>,
  stream: boolean,
): Record<string, string> {
  if (!stream) return headers;

  const existingAccept = (
    headerValueToString(headers.accept)
    || headerValueToString((headers as Record<string, unknown>).Accept)
  );
  if (existingAccept) return headers;

  return {
    ...headers,
    accept: 'text/event-stream',
  };
}

function toFiniteNumber(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

function ensureCodexResponsesInstructions(
  body: Record<string, unknown>,
  sitePlatform: string,
): Record<string, unknown> {
  if (sitePlatform !== 'codex') return body;
  if (typeof body.instructions === 'string') return body;
  return {
    ...body,
    instructions: '',
  };
}

function ensureCodexResponsesStoreFalse(
  body: Record<string, unknown>,
  sitePlatform: string,
): Record<string, unknown> {
  if (sitePlatform !== 'codex') return body;
  if (body.store === false) return body;
  return {
    ...body,
    store: false,
  };
}

function convertCodexSystemRoleToDeveloper(input: unknown): unknown {
  if (!Array.isArray(input)) return input;
  return input.map((item) => {
    if (!isRecord(item)) return item;
    if (asTrimmedString(item.type).toLowerCase() !== 'message') return item;
    if (asTrimmedString(item.role).toLowerCase() !== 'system') return item;
    return {
      ...item,
      role: 'developer',
    };
  });
}

function applyCodexResponsesCompatibility(
  body: Record<string, unknown>,
  sitePlatform: string,
  options?: {
    preservePreviousResponseId?: boolean;
  },
): Record<string, unknown> {
  if (sitePlatform !== 'codex') return body;

  const next: Record<string, unknown> = {
    ...body,
    stream: true,
    store: false,
    parallel_tool_calls: true,
    include: ['reasoning.encrypted_content'],
    input: convertCodexSystemRoleToDeveloper(body.input),
  };

  if (typeof next.instructions !== 'string') {
    next.instructions = '';
  }

  for (const key of [
    'max_output_tokens',
    'max_completion_tokens',
    'temperature',
    'top_p',
    'truncation',
    'user',
    'context_management',
    'prompt_cache_retention',
    'safety_identifier',
  ]) {
    delete next[key];
  }
  if (!options?.preservePreviousResponseId) {
    delete next.previous_response_id;
  }

  if (asTrimmedString(next.service_tier).toLowerCase() !== 'priority') {
    delete next.service_tier;
  }

  return next;
}


function normalizeEndpointTypes(value: unknown): UpstreamEndpoint[] {
  const raw = asTrimmedString(value).toLowerCase();
  if (!raw) return [];

  const normalized = new Set<UpstreamEndpoint>();

  if (
    raw.includes('/v1/messages')
    || raw === 'messages'
    || raw.includes('anthropic')
    || raw.includes('claude')
  ) {
    normalized.add('messages');
  }

  if (
    raw.includes('/v1/responses')
    || raw === 'responses'
    || raw.includes('response')
  ) {
    normalized.add('responses');
  }

  if (
    raw.includes('/v1/chat/completions')
    || raw.includes('chat/completions')
    || raw === 'chat'
    || raw === 'chat_completions'
    || raw === 'completions'
    || raw.includes('chat')
  ) {
    normalized.add('chat');
  }

  // Some upstreams return protocol families instead of concrete endpoint paths.
  if (raw === 'openai' || raw.includes('openai')) {
    normalized.add('chat');
    normalized.add('responses');
  }

  return Array.from(normalized);
}

function preferredEndpointOrder(
  downstreamFormat: EndpointPreference,
  sitePlatform?: string,
  preferMessagesForClaudeModel = false,
): UpstreamEndpoint[] {
  const platform = normalizePlatformName(sitePlatform);

  if (platform === 'codex') {
    return ['responses'];
  }

  if (platform === 'gemini') {
    // Gemini upstream is routed through OpenAI-compatible chat endpoint.
    return ['chat'];
  }

  if (platform === 'gemini-cli') {
    return ['chat'];
  }

  if (platform === 'antigravity') {
    return ['chat'];
  }

  if (platform === 'openai') {
    if (preferMessagesForClaudeModel && downstreamFormat !== 'responses') {
      // Some OpenAI-compatible gateways expose Claude natively via /v1/messages.
      // Keep chat/responses as fallbacks when messages is unavailable.
      return ['messages', 'chat', 'responses'];
    }
    return downstreamFormat === 'responses'
      ? ['responses', 'chat', 'messages']
      : ['chat', 'responses', 'messages'];
  }

  if (platform === 'claude') {
    return ['messages'];
  }

  // Unknown/generic upstreams: prefer endpoint family that matches the
  // downstream API surface, then degrade progressively.
  if (downstreamFormat === 'responses') {
    if (preferMessagesForClaudeModel) {
      // Claude-family models on generic/new-api upstreams are commonly
      // messages-first even when downstream API is /v1/responses.
      return ['messages', 'chat', 'responses'];
    }
    return ['responses', 'chat', 'messages'];
  }

  if (downstreamFormat === 'claude') {
    return ['messages', 'chat', 'responses'];
  }

  if (downstreamFormat === 'openai' && preferMessagesForClaudeModel) {
    // Claude-family models are most stable with native Messages semantics.
    return ['messages', 'chat', 'responses'];
  }

  return ['chat', 'messages', 'responses'];
}

export async function resolveUpstreamEndpointCandidates(
  context: ChannelContext,
  modelName: string,
  downstreamFormat: EndpointPreference,
  requestedModelHint?: string,
  requestCapabilities?: {
    hasNonImageFileInput?: boolean;
    wantsNativeResponsesReasoning?: boolean;
  },
): Promise<UpstreamEndpoint[]> {
  const sitePlatform = normalizePlatformName(context.site.platform);
  const preferMessagesForClaudeModel = (
    isClaudeFamilyModel(modelName)
    || isClaudeFamilyModel(asTrimmedString(requestedModelHint))
  );
  const hasNonImageFileInput = requestCapabilities?.hasNonImageFileInput === true;
  const wantsNativeResponsesReasoning = requestCapabilities?.wantsNativeResponsesReasoning === true;
  if (sitePlatform === 'anyrouter') {
    // anyrouter deployments are effectively anthropic-protocol first.
    if (hasNonImageFileInput) {
      return downstreamFormat === 'responses'
        ? ['responses', 'messages', 'chat']
        : ['messages', 'responses', 'chat'];
    }
    if (downstreamFormat === 'responses') {
      return ['responses', 'messages', 'chat'];
    }
    return ['messages', 'chat', 'responses'];
  }

  const preferred = preferredEndpointOrder(
    downstreamFormat,
    context.site.platform,
    preferMessagesForClaudeModel,
  );
  const preferredWithCapabilities = hasNonImageFileInput
    ? (() => {
      if (sitePlatform === 'claude') return ['messages'] as UpstreamEndpoint[];
      if (sitePlatform === 'gemini') return ['responses', 'chat'] as UpstreamEndpoint[];
      if (sitePlatform === 'gemini-cli' || sitePlatform === 'antigravity') return ['chat'] as UpstreamEndpoint[];
      if (preferMessagesForClaudeModel) return ['messages', 'responses', 'chat'] as UpstreamEndpoint[];
      return ['responses', 'messages', 'chat'] as UpstreamEndpoint[];
    })()
    : preferred;
  const prioritizedPreferredEndpoints: UpstreamEndpoint[] = (
    wantsNativeResponsesReasoning
    && preferMessagesForClaudeModel
    && preferredWithCapabilities.includes('responses')
  )
    ? [
      'responses',
      ...preferredWithCapabilities.filter((endpoint): endpoint is UpstreamEndpoint => endpoint !== 'responses'),
    ]
    : preferredWithCapabilities;
  const forceMessagesFirstForClaudeModel = (
    downstreamFormat === 'openai'
    && preferMessagesForClaudeModel
    && sitePlatform !== 'openai'
    && sitePlatform !== 'gemini'
    && sitePlatform !== 'antigravity'
    && sitePlatform !== 'gemini-cli'
  );

  try {
    const catalog = await fetchModelPricingCatalog({
      site: {
        id: context.site.id,
        url: context.site.url,
        platform: context.site.platform,
      },
      account: {
        id: context.account.id,
        accessToken: context.account.accessToken ?? null,
        apiToken: context.account.apiToken ?? null,
      },
      modelName,
      totalTokens: 0,
    });

    if (!catalog || !Array.isArray(catalog.models) || catalog.models.length === 0) {
      return prioritizedPreferredEndpoints;
    }

    const matched = catalog.models.find((item) =>
      asTrimmedString(item?.modelName).toLowerCase() === modelName.toLowerCase(),
    );
    if (!matched) return prioritizedPreferredEndpoints;

    const shouldIgnoreCatalogOrderingForClaudeMessages = (
      preferMessagesForClaudeModel
      && (downstreamFormat !== 'responses' || sitePlatform !== 'openai')
    );
    if (shouldIgnoreCatalogOrderingForClaudeMessages) {
      return prioritizedPreferredEndpoints;
    }

    const supportedRaw = Array.isArray(matched.supportedEndpointTypes) ? matched.supportedEndpointTypes : [];
    const normalizedSupportedRaw = supportedRaw
      .map((item) => asTrimmedString(item).toLowerCase())
      .filter((item) => item.length > 0);
    const hasConcreteEndpointHint = normalizedSupportedRaw.some((raw) => (
      raw.includes('/v1/messages')
      || raw.includes('/v1/chat/completions')
      || raw.includes('/v1/responses')
      || raw === 'messages'
      || raw === 'chat'
      || raw === 'chat_completions'
      || raw === 'completions'
      || raw === 'responses'
    ));
    if (forceMessagesFirstForClaudeModel && !hasConcreteEndpointHint) {
      // Generic labels like openai/anthropic are too coarse for Claude models;
      // keep messages-first order in this case.
      return prioritizedPreferredEndpoints;
    }

    const supported = new Set<UpstreamEndpoint>();
    for (const endpoint of supportedRaw) {
      const normalizedList = normalizeEndpointTypes(endpoint);
      for (const normalized of normalizedList) {
        supported.add(normalized);
      }
    }

    if (supported.size === 0) return prioritizedPreferredEndpoints;

    const firstSupported = prioritizedPreferredEndpoints.find((endpoint) => supported.has(endpoint));
    if (!firstSupported) return prioritizedPreferredEndpoints;

    // Catalog metadata can be incomplete/inaccurate, so only use it to pick
    // the first attempt. Keep downstream-driven fallback order unchanged.
    return [
      firstSupported,
      ...prioritizedPreferredEndpoints.filter((endpoint) => endpoint !== firstSupported),
    ];
  } catch {
    return prioritizedPreferredEndpoints;
  }
}

export function buildUpstreamEndpointRequest(input: {
  endpoint: UpstreamEndpoint;
  modelName: string;
  stream: boolean;
  tokenValue: string;
  oauthProvider?: string;
  oauthProjectId?: string;
  sitePlatform?: string;
  siteUrl?: string;
  openaiBody: Record<string, unknown>;
  downstreamFormat: EndpointPreference;
  claudeOriginalBody?: Record<string, unknown>;
  forceNormalizeClaudeBody?: boolean;
  responsesOriginalBody?: Record<string, unknown>;
  downstreamHeaders?: Record<string, unknown>;
  providerHeaders?: Record<string, string>;
  codexSessionCacheKey?: string | null;
  codexExplicitSessionId?: string | null;
}): {
  path: string;
  headers: Record<string, string>;
  body: Record<string, unknown>;
  runtime?: {
    executor: 'default' | 'codex' | 'gemini-cli' | 'antigravity' | 'claude';
    modelName?: string;
    stream?: boolean;
    oauthProjectId?: string | null;
    action?: 'generateContent' | 'streamGenerateContent' | 'countTokens';
  };
} {
  const sitePlatform = normalizePlatformName(input.sitePlatform);
  const providerProfile = resolveProviderProfile(sitePlatform);
  const isClaudeUpstream = sitePlatform === 'claude';
  const isGeminiUpstream = sitePlatform === 'gemini';
  const isGeminiCliUpstream = sitePlatform === 'gemini-cli';
  const isAntigravityUpstream = sitePlatform === 'antigravity';
  const isInternalGeminiUpstream = isGeminiCliUpstream || isAntigravityUpstream;
  const isClaudeOauthUpstream = isClaudeUpstream && input.oauthProvider === 'claude';

  const resolveGeminiEndpointPath = (endpoint: UpstreamEndpoint): string => {
    const normalizedSiteUrl = asTrimmedString(input.siteUrl).toLowerCase();
    const openAiCompatBase = /\/openai(?:\/|$)/.test(normalizedSiteUrl);
    if (openAiCompatBase) {
      return endpoint === 'responses'
        ? '/responses'
        : '/chat/completions';
    }
    return endpoint === 'responses'
      ? '/v1beta/openai/responses'
      : '/v1beta/openai/chat/completions';
  };

  const resolveEndpointPath = (endpoint: UpstreamEndpoint): string => {
    if (isGeminiUpstream) {
      return resolveGeminiEndpointPath(endpoint);
    }

    if (sitePlatform === 'openai') {
      if (endpoint === 'messages') return '/v1/messages';
      if (endpoint === 'responses') return '/v1/responses';
      return '/v1/chat/completions';
    }

    if (sitePlatform === 'codex') {
      return '/responses';
    }

    if (sitePlatform === 'gemini-cli' || sitePlatform === 'antigravity') {
      return input.stream
        ? '/v1internal:streamGenerateContent?alt=sse'
        : '/v1internal:generateContent';
    }

    if (sitePlatform === 'claude') {
      return '/v1/messages';
    }

    if (endpoint === 'messages') return '/v1/messages';
    if (endpoint === 'responses') return '/v1/responses';
    return '/v1/chat/completions';
  };

  const passthroughHeaders = extractSafePassthroughHeaders(input.downstreamHeaders);
  const commonHeaders: Record<string, string> = {
    ...passthroughHeaders,
    'Content-Type': 'application/json',
    ...(input.providerHeaders || {}),
  };
  if (!isClaudeUpstream) {
    commonHeaders.Authorization = `Bearer ${input.tokenValue}`;
  }

  const stripGeminiUnsupportedFields = (body: Record<string, unknown>) => {
    const next = { ...body };
    if (isGeminiUpstream || isInternalGeminiUpstream) {
      for (const key of [
        'frequency_penalty',
        'presence_penalty',
        'logit_bias',
        'logprobs',
        'top_logprobs',
        'store',
      ]) {
        delete next[key];
      }
    }
    return next;
  };

  const openaiBody = stripGeminiUnsupportedFields(input.openaiBody);
  const runtime = {
    executor: (
      sitePlatform === 'codex'
        ? 'codex'
        : sitePlatform === 'gemini-cli'
          ? 'gemini-cli'
          : sitePlatform === 'antigravity'
            ? 'antigravity'
            : sitePlatform === 'claude'
              ? 'claude'
              : 'default'
    ) as 'default' | 'codex' | 'gemini-cli' | 'antigravity' | 'claude',
    modelName: input.modelName,
    stream: input.stream,
    oauthProjectId: asTrimmedString(input.oauthProjectId) || null,
  };

  if (isInternalGeminiUpstream) {
    const instructions = (
      input.downstreamFormat === 'responses'
      && typeof input.responsesOriginalBody?.instructions === 'string'
    )
      ? input.responsesOriginalBody.instructions
      : undefined;
    const geminiRequest = buildGeminiGenerateContentRequestFromOpenAi({
      body: openaiBody,
      modelName: input.modelName,
      instructions,
    });
    if (!providerProfile) {
      throw new Error(`missing provider profile for platform: ${sitePlatform}`);
    }
    return providerProfile.prepareRequest({
      endpoint: input.endpoint,
      modelName: input.modelName,
      stream: input.stream,
      tokenValue: input.tokenValue,
      oauthProvider: input.oauthProvider,
      oauthProjectId: input.oauthProjectId,
      sitePlatform,
      baseHeaders: commonHeaders,
      providerHeaders: input.providerHeaders,
      body: geminiRequest,
      action: input.stream ? 'streamGenerateContent' : 'generateContent',
    });
  }

  if (input.endpoint === 'messages') {
    const claudeHeaders = input.downstreamFormat === 'claude'
      ? extractClaudePassthroughHeaders(input.downstreamHeaders)
      : {};
    const anthropicVersion = (
      claudeHeaders['anthropic-version']
      || passthroughHeaders['anthropic-version']
      || '2023-06-01'
    );
    const nativeClaudeBody = (
      input.downstreamFormat === 'claude'
      && input.claudeOriginalBody
      && input.forceNormalizeClaudeBody !== true
    )
      ? {
        ...input.claudeOriginalBody,
        model: input.modelName,
        stream: input.stream,
      }
      : null;
    const normalizedClaudeBody = (
      input.downstreamFormat === 'claude'
      && input.claudeOriginalBody
      && input.forceNormalizeClaudeBody === true
    )
      ? sanitizeAnthropicMessagesBody({
        ...input.claudeOriginalBody,
        model: input.modelName,
        stream: input.stream,
      })
      : null;
    const sanitizedBody = nativeClaudeBody
      ?? normalizedClaudeBody
      ?? sanitizeAnthropicMessagesBody(
        convertOpenAiBodyToAnthropicMessagesBody(openaiBody, input.modelName, input.stream),
      );

    if (providerProfile?.id === 'claude') {
      return providerProfile.prepareRequest({
        endpoint: 'messages',
        modelName: input.modelName,
        stream: input.stream,
        tokenValue: input.tokenValue,
        oauthProvider: input.oauthProvider,
        oauthProjectId: input.oauthProjectId,
        sitePlatform,
        baseHeaders: commonHeaders,
        claudeHeaders,
        body: sanitizedBody,
      });
    }

    const headers = buildClaudeRuntimeHeaders({
      baseHeaders: commonHeaders,
      claudeHeaders,
      anthropicVersion,
      stream: input.stream,
      isClaudeOauthUpstream,
      tokenValue: input.tokenValue,
    });

    return {
      path: resolveEndpointPath('messages'),
      headers,
      body: sanitizedBody,
      runtime,
    };
  }

  if (input.endpoint === 'responses') {
    const websocketMode = Object.entries(input.downstreamHeaders || {}).find(([rawKey]) => rawKey.trim().toLowerCase() === 'x-metapi-responses-websocket-mode');
    const preserveWebsocketIncrementalMode = asTrimmedString(websocketMode?.[1]).toLowerCase() === 'incremental';
    const responsesHeaders = input.downstreamFormat === 'responses'
      ? extractResponsesPassthroughHeaders(input.downstreamHeaders)
      : {};
    const rawBody = (
      input.downstreamFormat === 'responses' && input.responsesOriginalBody
        ? {
          ...stripGeminiUnsupportedFields(input.responsesOriginalBody),
          model: input.modelName,
          stream: input.stream,
        }
        : convertOpenAiBodyToResponsesBodyViaTransformer(openaiBody, input.modelName, input.stream)
    );
    const sanitizedResponsesBody = sanitizeResponsesBodyForProxyViaTransformer(rawBody, input.modelName, input.stream);
    if (preserveWebsocketIncrementalMode && rawBody.generate === false) {
      sanitizedResponsesBody.generate = false;
    }
    const body = ensureCodexResponsesStoreFalse(
      ensureCodexResponsesInstructions(
        applyCodexResponsesCompatibility(
          sanitizedResponsesBody,
          sitePlatform,
          { preservePreviousResponseId: preserveWebsocketIncrementalMode },
        ),
        sitePlatform,
      ),
      sitePlatform,
    );

    if (providerProfile?.id === 'codex') {
      return providerProfile.prepareRequest({
        endpoint: 'responses',
        modelName: input.modelName,
        stream: input.stream,
        tokenValue: input.tokenValue,
        oauthProvider: input.oauthProvider,
        oauthProjectId: input.oauthProjectId,
        sitePlatform,
        baseHeaders: {
          ...commonHeaders,
          ...responsesHeaders,
        },
        providerHeaders: input.providerHeaders,
        codexSessionCacheKey: input.codexSessionCacheKey,
        codexExplicitSessionId: input.codexExplicitSessionId,
        body,
      });
    }

    const headers = sitePlatform === 'codex'
      ? buildCodexRuntimeHeaders({
        baseHeaders: {
          ...commonHeaders,
          ...responsesHeaders,
        },
        providerHeaders: input.providerHeaders,
        explicitSessionId: asTrimmedString(input.codexExplicitSessionId) || null,
        continuityKey: asTrimmedString(input.codexSessionCacheKey) || null,
      })
      : ensureStreamAcceptHeader({
        ...commonHeaders,
        ...responsesHeaders,
      }, input.stream);
    const codexSessionId = sitePlatform === 'codex'
      ? (getInputHeader(headers, 'session_id') || getInputHeader(headers, 'session-id'))
      : null;
    const shouldInjectDerivedPromptCacheKey = sitePlatform === 'codex'
      && !!codexSessionId
      && !asTrimmedString((body as Record<string, unknown>).prompt_cache_key)
      && !asTrimmedString(input.codexExplicitSessionId)
      && !!asTrimmedString(input.codexSessionCacheKey);
    const runtimeBody = shouldInjectDerivedPromptCacheKey
      ? {
        ...body,
        prompt_cache_key: codexSessionId,
      }
      : body;

    return {
      path: resolveEndpointPath('responses'),
      headers,
      body: runtimeBody,
      runtime,
    };
  }

  const headers = ensureStreamAcceptHeader(commonHeaders, input.stream);
  return {
    path: resolveEndpointPath('chat'),
    headers,
    body: {
      ...openaiBody,
      model: input.modelName,
      stream: input.stream,
    },
    runtime,
  };
}

export function buildClaudeCountTokensUpstreamRequest(input: {
  modelName: string;
  tokenValue: string;
  oauthProvider?: string;
  sitePlatform?: string;
  claudeBody: Record<string, unknown>;
  downstreamHeaders?: Record<string, unknown>;
}): {
  path: string;
  headers: Record<string, string>;
  body: Record<string, unknown>;
  runtime: {
    executor: 'claude';
    modelName: string;
    stream: false;
    action: 'countTokens';
  };
} {
  const sitePlatform = normalizePlatformName(input.sitePlatform);
  const claudeHeaders = extractClaudePassthroughHeaders(input.downstreamHeaders);
  const { body: bodyWithoutBetas, betas } = extractClaudeBetasFromBody({
    ...input.claudeBody,
    model: input.modelName,
  });
  const sanitizedBody = sanitizeAnthropicMessagesBody(bodyWithoutBetas);
  delete sanitizedBody.max_tokens;
  delete sanitizedBody.maxTokens;
  delete sanitizedBody.stream;
  const providerProfile = resolveProviderProfile(sitePlatform);
  if (providerProfile?.id !== 'claude') {
    throw new Error(`missing claude provider profile for platform: ${sitePlatform || 'unknown'}`);
  }

  const prepared = providerProfile.prepareRequest({
    endpoint: 'messages',
    modelName: input.modelName,
    stream: false,
    tokenValue: input.tokenValue,
    oauthProvider: input.oauthProvider,
    sitePlatform,
    baseHeaders: {
      'Content-Type': 'application/json',
    },
    claudeHeaders: {
      ...claudeHeaders,
      ...(betas.length > 0 ? { 'anthropic-beta': betas.join(',') } : {}),
    },
    body: sanitizedBody,
    action: 'countTokens',
  });

  return {
    path: prepared.path,
    headers: prepared.headers,
    body: prepared.body,
    runtime: {
      executor: 'claude',
      modelName: input.modelName,
      stream: false,
      action: 'countTokens',
    },
  };
}


