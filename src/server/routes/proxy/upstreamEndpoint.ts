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

  if (platform === 'gemini') {
    // Gemini upstream is routed through OpenAI-compatible chat endpoint.
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
  sitePlatform?: string;
  siteUrl?: string;
  openaiBody: Record<string, unknown>;
  downstreamFormat: EndpointPreference;
  claudeOriginalBody?: Record<string, unknown>;
  forceNormalizeClaudeBody?: boolean;
  responsesOriginalBody?: Record<string, unknown>;
  downstreamHeaders?: Record<string, unknown>;
}): {
  path: string;
  headers: Record<string, string>;
  body: Record<string, unknown>;
} {
  const sitePlatform = normalizePlatformName(input.sitePlatform);
  const isClaudeUpstream = sitePlatform === 'claude';
  const isGeminiUpstream = sitePlatform === 'gemini';

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
  };
  if (!isClaudeUpstream) {
    commonHeaders.Authorization = `Bearer ${input.tokenValue}`;
  }

  const stripGeminiUnsupportedFields = (body: Record<string, unknown>) => {
    const next = { ...body };
    if (isGeminiUpstream) {
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

    const headers = ensureStreamAcceptHeader({
      ...commonHeaders,
      ...claudeHeaders,
      'x-api-key': input.tokenValue,
      'anthropic-version': anthropicVersion,
    }, input.stream);

    return {
      path: resolveEndpointPath('messages'),
      headers,
      body: sanitizedBody,
    };
  }

  if (input.endpoint === 'responses') {
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
    const body = sanitizeResponsesBodyForProxyViaTransformer(rawBody, input.modelName, input.stream);

    const headers = ensureStreamAcceptHeader({
      ...commonHeaders,
      ...responsesHeaders,
    }, input.stream);

    return {
      path: resolveEndpointPath('responses'),
      headers,
      body,
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
  };
}


