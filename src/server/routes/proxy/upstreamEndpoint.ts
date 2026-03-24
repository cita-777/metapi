import { randomUUID, createHash } from 'node:crypto';
import {
  rankConversationFileEndpoints,
  type ConversationFileInputSummary,
} from '../../proxy-core/capabilities/conversationFileCapabilities.js';
import { resolveProviderProfile } from '../../proxy-core/providers/registry.js';
import { config } from '../../config.js';
import { fetchModelPricingCatalog } from '../../services/modelPricingService.js';
import { applyPayloadRules } from '../../services/payloadRules.js';
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
import {
  buildMinimalJsonHeadersForCompatibility,
  isEndpointDispatchDeniedError,
  isEndpointDowngradeError,
  isUnsupportedMediaTypeError,
  promoteResponsesCandidateAfterLegacyChatError,
  shouldPreferResponsesAfterLegacyChatError,
} from '../../transformers/shared/endpointCompatibility.js';
import {
  buildClaudeRuntimeHeaders,
  buildGeminiCliUserAgent,
  headerValueToString,
} from '../../proxy-core/providers/headerUtils.js';
export {
  buildMinimalJsonHeadersForCompatibility,
  isEndpointDispatchDeniedError,
  isEndpointDowngradeError,
  isUnsupportedMediaTypeError,
  promoteResponsesCandidateAfterLegacyChatError,
  shouldPreferResponsesAfterLegacyChatError,
};

export type UpstreamEndpoint = 'chat' | 'messages' | 'responses';
export type EndpointPreference = DownstreamFormat | 'responses';

type EndpointCapabilityProfile = {
  modelKey: string;
  preferMessagesForClaudeModel: boolean;
  hasImageInput: boolean;
  hasAudioInput: boolean;
  hasNonImageFileInput: boolean;
  hasRemoteDocumentUrl: boolean;
  wantsNativeResponsesReasoning: boolean;
};

type EndpointRuntimeState = {
  preferredEndpoint: UpstreamEndpoint | null;
  preferredUpdatedAtMs: number;
  lastTouchedAtMs: number;
  blockedUntilMsByEndpoint: Partial<Record<UpstreamEndpoint, number>>;
};

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

const ENDPOINT_RUNTIME_PREFERRED_TTL_MS = 24 * 60 * 60 * 1000;
const ENDPOINT_RUNTIME_BLOCK_TTL_MS = 6 * 60 * 60 * 1000;
const MAX_ENDPOINT_RUNTIME_STATES = 512;
export const MAX_ENDPOINT_RUNTIME_MODEL_KEY_LENGTH = 64;
export const MODEL_KEY_HASH_SUFFIX_LENGTH = 8;
const endpointRuntimeStates = new Map<string, EndpointRuntimeState>();

export function boundEndpointRuntimeModelKey(value: string): string {
  if (value.length <= MAX_ENDPOINT_RUNTIME_MODEL_KEY_LENGTH) {
    return value;
  }

  const prefix = value.slice(0, MAX_ENDPOINT_RUNTIME_MODEL_KEY_LENGTH);
  const hash = createHash('sha256')
    .update(value)
    .digest('hex')
    .slice(0, MODEL_KEY_HASH_SUFFIX_LENGTH);
  return `${prefix}-${hash}`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object';
}

function asTrimmedString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function normalizeEndpointRuntimeModelKey(...values: Array<unknown>): string {
  for (const value of values) {
    const normalized = asTrimmedString(value).toLowerCase();
    if (normalized) return boundEndpointRuntimeModelKey(normalized);
  }
  return boundEndpointRuntimeModelKey('unknown-model');
}

function resolveRequestedModelForPayloadRules(input: {
  modelName: string;
  openaiBody: Record<string, unknown>;
  claudeOriginalBody?: Record<string, unknown>;
  responsesOriginalBody?: Record<string, unknown>;
}): string {
  return (
    asTrimmedString(input.responsesOriginalBody?.model)
    || asTrimmedString(input.claudeOriginalBody?.model)
    || asTrimmedString(input.openaiBody.model)
    || asTrimmedString(input.modelName)
  );
}

function normalizePlatformName(platform: unknown): string {
  return asTrimmedString(platform).toLowerCase();
}

function isClaudeFamilyModel(modelName: string): boolean {
  const normalized = asTrimmedString(modelName).toLowerCase();
  if (!normalized) return false;
  return normalized === 'claude' || normalized.startsWith('claude-') || normalized.includes('claude');
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

const ANTIGRAVITY_RUNTIME_USER_AGENT = 'antigravity/1.19.6 darwin/arm64';

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

function normalizeResponsesFallbackChatFunctionTool(rawTool: unknown): Record<string, unknown> | null {
  if (!isRecord(rawTool)) return null;
  if (asTrimmedString(rawTool.type).toLowerCase() !== 'function') return null;

  if (isRecord(rawTool.function)) {
    const name = asTrimmedString(rawTool.function.name);
    if (!name) return null;
    return {
      ...rawTool,
      type: 'function',
      function: {
        ...rawTool.function,
        name,
      },
    };
  }

  const name = asTrimmedString(rawTool.name);
  if (!name) return null;

  const fn: Record<string, unknown> = { name };
  const description = asTrimmedString(rawTool.description);
  if (description) fn.description = description;
  if (rawTool.parameters !== undefined) fn.parameters = rawTool.parameters;
  if (rawTool.strict !== undefined) fn.strict = rawTool.strict;

  return {
    type: 'function',
    function: fn,
  };
}

function normalizeResponsesFallbackChatToolChoice(
  rawToolChoice: unknown,
  allowedToolNames: Set<string>,
): unknown {
  if (rawToolChoice === undefined) return undefined;

  if (typeof rawToolChoice === 'string') {
    const normalized = rawToolChoice.trim().toLowerCase();
    if (normalized === 'none') return 'none';
    if (allowedToolNames.size <= 0) return undefined;
    if (normalized === 'auto' || normalized === 'required') return normalized;
    return undefined;
  }

  if (!isRecord(rawToolChoice)) return undefined;
  if (asTrimmedString(rawToolChoice.type).toLowerCase() !== 'function') return undefined;

  const nestedFunction = isRecord(rawToolChoice.function) ? rawToolChoice.function : null;
  const name = asTrimmedString(nestedFunction?.name ?? rawToolChoice.name);
  if (!name || !allowedToolNames.has(name)) return undefined;

  return {
    type: 'function',
    function: {
      ...(nestedFunction || {}),
      name,
    },
  };
}

function sanitizeResponsesFallbackChatBody(
  body: Record<string, unknown>,
): Record<string, unknown> {
  const next: Record<string, unknown> = { ...body };
  const normalizedTools = Array.isArray(body.tools)
    ? body.tools
      .map((tool) => normalizeResponsesFallbackChatFunctionTool(tool))
      .filter((tool): tool is Record<string, unknown> => !!tool)
    : [];

  if (normalizedTools.length > 0) {
    next.tools = normalizedTools;
  } else {
    delete next.tools;
  }

  const allowedToolNames = new Set(
    normalizedTools
      .map((tool) => (
        isRecord(tool.function)
          ? asTrimmedString(tool.function.name)
          : ''
      ))
      .filter((name) => name.length > 0),
  );
  const normalizedToolChoice = normalizeResponsesFallbackChatToolChoice(
    body.tool_choice,
    allowedToolNames,
  );
  if (normalizedToolChoice !== undefined) {
    next.tool_choice = normalizedToolChoice;
  } else {
    delete next.tool_choice;
  }

  return next;
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
  return body;
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
): Record<string, unknown> {
  if (sitePlatform !== 'codex') return body;

  const next: Record<string, unknown> = {
    ...body,
    input: convertCodexSystemRoleToDeveloper(body.input),
  };

  if (typeof next.instructions !== 'string') {
    next.instructions = '';
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

function buildEndpointCapabilityProfile(input?: {
  modelName?: string;
  requestedModelHint?: string;
  requestCapabilities?: {
    hasNonImageFileInput?: boolean;
    conversationFileSummary?: ConversationFileInputSummary;
    wantsNativeResponsesReasoning?: boolean;
  };
}): EndpointCapabilityProfile {
  const conversationFileSummary = input?.requestCapabilities?.conversationFileSummary;
  return {
    modelKey: normalizeEndpointRuntimeModelKey(input?.modelName, input?.requestedModelHint),
    preferMessagesForClaudeModel: (
      isClaudeFamilyModel(asTrimmedString(input?.modelName))
      || isClaudeFamilyModel(asTrimmedString(input?.requestedModelHint))
    ),
    hasImageInput: conversationFileSummary?.hasImage === true,
    hasAudioInput: conversationFileSummary?.hasAudio === true,
    hasNonImageFileInput: (
      conversationFileSummary?.hasDocument === true
      || input?.requestCapabilities?.hasNonImageFileInput === true
    ),
    hasRemoteDocumentUrl: (
      conversationFileSummary?.hasRemoteDocumentUrl === true
    ),
    wantsNativeResponsesReasoning: input?.requestCapabilities?.wantsNativeResponsesReasoning === true,
  };
}

function shouldUseEndpointRuntimeMemory(capabilityProfile: EndpointCapabilityProfile): boolean {
  // Attachment-capable requests are not protocol-equivalent across chat/messages/responses.
  // A transient 200 on one endpoint should not bias later multimodal requests onto a lossy path.
  return (
    !capabilityProfile.hasImageInput
    && !capabilityProfile.hasAudioInput
    && !capabilityProfile.hasNonImageFileInput
  );
}

function buildEndpointRuntimeStateKey(input: {
  siteId: number;
  downstreamFormat: EndpointPreference;
  capabilityProfile: EndpointCapabilityProfile;
}): string {
  const capabilityProfile = input.capabilityProfile;
  return [
    String(input.siteId),
    input.downstreamFormat,
    capabilityProfile.modelKey,
    capabilityProfile.hasNonImageFileInput ? 'files' : 'nofiles',
    capabilityProfile.hasRemoteDocumentUrl ? 'remoteurl' : 'noremoteurl',
    capabilityProfile.wantsNativeResponsesReasoning ? 'reasoning' : 'noreasoning',
  ].join(':');
}

function getOrCreateEndpointRuntimeState(key: string, nowMs = Date.now()): EndpointRuntimeState {
  sweepEndpointRuntimeStates(nowMs);
  const existing = endpointRuntimeStates.get(key);
  if (existing) {
    existing.lastTouchedAtMs = nowMs;
    return existing;
  }

  const initial: EndpointRuntimeState = {
    preferredEndpoint: null,
    preferredUpdatedAtMs: nowMs,
    lastTouchedAtMs: nowMs,
    blockedUntilMsByEndpoint: {},
  };
  endpointRuntimeStates.set(key, initial);
  enforceEndpointRuntimeStateLimit();
  return initial;
}

function maybeDeleteEndpointRuntimeState(key: string, nowMs = Date.now()): void {
  const state = endpointRuntimeStates.get(key);
  if (!state) return;

  const hasActiveBlock = Object.values(state.blockedUntilMsByEndpoint).some((untilMs) => (
    typeof untilMs === 'number' && untilMs > nowMs
  ));
  const preferredFresh = (
    !!state.preferredEndpoint
    && (state.preferredUpdatedAtMs + ENDPOINT_RUNTIME_PREFERRED_TTL_MS) > nowMs
  );
  if (!hasActiveBlock && !preferredFresh) {
    endpointRuntimeStates.delete(key);
  }
}

function applyEndpointRuntimePreference(
  candidates: UpstreamEndpoint[],
  key: string,
  nowMs = Date.now(),
): UpstreamEndpoint[] {
  const state = endpointRuntimeStates.get(key);
  if (!state || candidates.length <= 1) return candidates;
  state.lastTouchedAtMs = nowMs;

  const blocked = new Set<UpstreamEndpoint>();
  for (const endpoint of candidates) {
    const untilMs = state.blockedUntilMsByEndpoint[endpoint];
    if (typeof untilMs === 'number' && untilMs > nowMs) {
      blocked.add(endpoint);
    }
  }

  let next = candidates.filter((endpoint) => !blocked.has(endpoint));
  if (next.length === 0) {
    next = [...candidates];
  }

  const preferredFresh = (
    !!state.preferredEndpoint
    && (state.preferredUpdatedAtMs + ENDPOINT_RUNTIME_PREFERRED_TTL_MS) > nowMs
  );
  if (preferredFresh && state.preferredEndpoint && next.includes(state.preferredEndpoint)) {
    next = [
      state.preferredEndpoint,
      ...next.filter((endpoint) => endpoint !== state.preferredEndpoint),
    ];
  }

  maybeDeleteEndpointRuntimeState(key, nowMs);
  return next;
}

function sweepEndpointRuntimeStates(nowMs = Date.now()): void {
  for (const [key, state] of endpointRuntimeStates.entries()) {
    const hasActiveBlock = Object.values(state.blockedUntilMsByEndpoint).some((untilMs) => (
      typeof untilMs === 'number' && untilMs > nowMs
    ));
    const preferredFresh = (
      !!state.preferredEndpoint
      && (state.preferredUpdatedAtMs + ENDPOINT_RUNTIME_PREFERRED_TTL_MS) > nowMs
    );
    const recentlyTouched = (state.lastTouchedAtMs + ENDPOINT_RUNTIME_PREFERRED_TTL_MS) > nowMs;
    if (!hasActiveBlock && !preferredFresh && !recentlyTouched) {
      endpointRuntimeStates.delete(key);
    }
  }
}

function enforceEndpointRuntimeStateLimit(): void {
  if (endpointRuntimeStates.size <= MAX_ENDPOINT_RUNTIME_STATES) return;

  const entries = [...endpointRuntimeStates.entries()]
    .sort((left, right) => left[1].lastTouchedAtMs - right[1].lastTouchedAtMs);
  const overflowCount = endpointRuntimeStates.size - MAX_ENDPOINT_RUNTIME_STATES;
  for (const [key] of entries.slice(0, overflowCount)) {
    endpointRuntimeStates.delete(key);
  }
}

function inferSuggestedEndpointFromError(errorText?: string | null): UpstreamEndpoint | null {
  const text = (errorText || '').toLowerCase();
  if (!text) return null;
  if (text.includes('/v1/responses')) return 'responses';
  if (text.includes('/v1/messages')) return 'messages';
  if (text.includes('/v1/chat/completions')) return 'chat';
  return null;
}

function shouldBlockEndpointByError(status: number, errorText?: string | null): boolean {
  if (isEndpointDispatchDeniedError(status, errorText)) return true;
  if (status === 404 || status === 405 || status === 415 || status === 501) return true;
  if (isUnsupportedMediaTypeError(status, errorText)) return true;

  const text = (errorText || '').toLowerCase();
  return (
    text.includes('convert_request_failed')
    || text.includes('endpoint_not_found')
    || text.includes('unknown_endpoint')
    || text.includes('unsupported_endpoint')
    || text.includes('unsupported_path')
    || text.includes('not_found_error')
    || text.includes('unsupported legacy protocol')
    || text.includes('please use /v1/')
    || text.includes('does not allow /v1/')
    || text.includes('unknown endpoint')
    || text.includes('unsupported endpoint')
    || text.includes('unsupported path')
    || text.includes('unrecognized request url')
    || text.includes('no route matched')
    || text.includes('does not exist')
  );
}

function shouldRememberSuccessfulEndpoint(input: {
  endpoint: UpstreamEndpoint;
  downstreamFormat: EndpointPreference;
}): boolean {
  if (input.downstreamFormat !== 'responses') return true;
  return input.endpoint === 'responses';
}

export function resetUpstreamEndpointRuntimeState(): void {
  endpointRuntimeStates.clear();
}

export function recordUpstreamEndpointSuccess(input: {
  siteId: number;
  endpoint: UpstreamEndpoint;
  downstreamFormat: EndpointPreference;
  modelName?: string;
  requestedModelHint?: string;
  requestCapabilities?: {
    hasNonImageFileInput?: boolean;
    conversationFileSummary?: ConversationFileInputSummary;
    wantsNativeResponsesReasoning?: boolean;
  };
}): void {
  const capabilityProfile = buildEndpointCapabilityProfile({
    modelName: input.modelName,
    requestedModelHint: input.requestedModelHint,
    requestCapabilities: input.requestCapabilities,
  });
  if (!shouldUseEndpointRuntimeMemory(capabilityProfile)) return;
  if (!shouldRememberSuccessfulEndpoint(input)) return;

  const nowMs = Date.now();
  const key = buildEndpointRuntimeStateKey({
    siteId: input.siteId,
    downstreamFormat: input.downstreamFormat,
    capabilityProfile,
  });
  const state = getOrCreateEndpointRuntimeState(key, nowMs);
  state.preferredEndpoint = input.endpoint;
  state.preferredUpdatedAtMs = nowMs;
  delete state.blockedUntilMsByEndpoint[input.endpoint];
}

export function recordUpstreamEndpointFailure(input: {
  siteId: number;
  endpoint: UpstreamEndpoint;
  downstreamFormat: EndpointPreference;
  status: number;
  errorText?: string | null;
  modelName?: string;
  requestedModelHint?: string;
  requestCapabilities?: {
    hasNonImageFileInput?: boolean;
    conversationFileSummary?: ConversationFileInputSummary;
    wantsNativeResponsesReasoning?: boolean;
  };
}): void {
  const capabilityProfile = buildEndpointCapabilityProfile({
    modelName: input.modelName,
    requestedModelHint: input.requestedModelHint,
    requestCapabilities: input.requestCapabilities,
  });
  if (!shouldUseEndpointRuntimeMemory(capabilityProfile)) return;
  if (!shouldBlockEndpointByError(input.status, input.errorText)) return;

  const nowMs = Date.now();
  const key = buildEndpointRuntimeStateKey({
    siteId: input.siteId,
    downstreamFormat: input.downstreamFormat,
    capabilityProfile,
  });
  const state = getOrCreateEndpointRuntimeState(key, nowMs);
  state.blockedUntilMsByEndpoint[input.endpoint] = nowMs + ENDPOINT_RUNTIME_BLOCK_TTL_MS;

  const suggestedEndpoint = inferSuggestedEndpointFromError(input.errorText);
  if (suggestedEndpoint && suggestedEndpoint !== input.endpoint) {
    state.preferredEndpoint = suggestedEndpoint;
    state.preferredUpdatedAtMs = nowMs;
    delete state.blockedUntilMsByEndpoint[suggestedEndpoint];
  }
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
    conversationFileSummary?: ConversationFileInputSummary;
    wantsNativeResponsesReasoning?: boolean;
  },
): Promise<UpstreamEndpoint[]> {
  const sitePlatform = normalizePlatformName(context.site.platform);
  const capabilityProfile = buildEndpointCapabilityProfile({
    modelName,
    requestedModelHint,
    requestCapabilities,
  });
  const preferMessagesForClaudeModel = capabilityProfile.preferMessagesForClaudeModel;
  const hasNonImageFileInput = capabilityProfile.hasNonImageFileInput;
  const wantsNativeResponsesReasoning = capabilityProfile.wantsNativeResponsesReasoning;
  const runtimeStateKey = buildEndpointRuntimeStateKey({
    siteId: context.site.id,
    downstreamFormat,
    capabilityProfile,
  });
  const applyRuntimePreference = (candidates: UpstreamEndpoint[]) => (
    shouldUseEndpointRuntimeMemory(capabilityProfile)
      ? applyEndpointRuntimePreference(candidates, runtimeStateKey)
      : candidates
  );
  const conversationFileSummary = requestCapabilities?.conversationFileSummary ?? {
    hasImage: false,
    hasAudio: false,
    hasDocument: hasNonImageFileInput,
    hasRemoteDocumentUrl: false,
  };
  if (sitePlatform === 'anyrouter') {
    // anyrouter deployments are effectively anthropic-protocol first.
    if (hasNonImageFileInput) {
      return applyRuntimePreference(downstreamFormat === 'responses'
        ? ['responses', 'messages', 'chat']
        : ['messages', 'responses', 'chat']);
    }
    if (downstreamFormat === 'responses') {
      return applyRuntimePreference(['responses', 'messages', 'chat']);
    }
    return applyRuntimePreference(['messages', 'chat', 'responses']);
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
      return rankConversationFileEndpoints({
        sitePlatform,
        requestedOrder: preferMessagesForClaudeModel
          ? ['messages', 'responses', 'chat']
          : ['responses', 'messages', 'chat'],
        summary: conversationFileSummary,
        preferMessagesForClaudeModel,
      });
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
      return applyRuntimePreference(prioritizedPreferredEndpoints);
    }

    const matched = catalog.models.find((item) =>
      asTrimmedString(item?.modelName).toLowerCase() === modelName.toLowerCase(),
    );
    if (!matched) return applyRuntimePreference(prioritizedPreferredEndpoints);

    const shouldIgnoreCatalogOrderingForClaudeMessages = (
      preferMessagesForClaudeModel
      && (downstreamFormat !== 'responses' || sitePlatform !== 'openai')
    );
    if (shouldIgnoreCatalogOrderingForClaudeMessages) {
      return applyRuntimePreference(prioritizedPreferredEndpoints);
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
      return applyRuntimePreference(prioritizedPreferredEndpoints);
    }

    const supported = new Set<UpstreamEndpoint>();
    for (const endpoint of supportedRaw) {
      const normalizedList = normalizeEndpointTypes(endpoint);
      for (const normalized of normalizedList) {
        supported.add(normalized);
      }
    }

    if (supported.size === 0) return applyRuntimePreference(prioritizedPreferredEndpoints);

    const firstSupported = prioritizedPreferredEndpoints.find((endpoint) => supported.has(endpoint));
    if (!firstSupported) return applyRuntimePreference(prioritizedPreferredEndpoints);

    // Catalog metadata can be incomplete/inaccurate, so only use it to pick
    // the first attempt. Keep downstream-driven fallback order unchanged.
    return applyRuntimePreference([
      firstSupported,
      ...prioritizedPreferredEndpoints.filter((endpoint) => endpoint !== firstSupported),
    ]);
  } catch {
    return applyRuntimePreference(prioritizedPreferredEndpoints);
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
  const requestedModelForPayloadRules = resolveRequestedModelForPayloadRules(input);
  const applyConfiguredPayloadRules = <T extends Record<string, unknown>>(body: T): T => (
    applyPayloadRules({
      rules: config.payloadRules,
      payload: body,
      modelName: input.modelName,
      requestedModel: requestedModelForPayloadRules,
      protocol: sitePlatform,
    }) as T
  );

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
    const configuredGeminiRequest = applyConfiguredPayloadRules(geminiRequest);
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
      body: configuredGeminiRequest,
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
    const configuredClaudeBody = applyConfiguredPayloadRules(sanitizedBody);

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
        body: configuredClaudeBody,
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
      body: configuredClaudeBody,
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
        ),
        sitePlatform,
      ),
      sitePlatform,
    );
    const configuredResponsesBody = applyConfiguredPayloadRules(body);

    if (sitePlatform === 'codex') {
      if (providerProfile?.id !== 'codex') {
        throw new Error(`missing codex provider profile for platform: ${sitePlatform}`);
      }
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
        body: configuredResponsesBody,
      });
    }

    const headers = ensureStreamAcceptHeader({
      ...commonHeaders,
      ...responsesHeaders,
    }, input.stream);
    return {
      path: resolveEndpointPath('responses'),
      headers,
      body: configuredResponsesBody,
      runtime,
    };
  }

  const headers = ensureStreamAcceptHeader(commonHeaders, input.stream);
  const chatBody = {
    ...openaiBody,
    model: input.modelName,
    stream: input.stream,
  };
  const configuredChatBody = applyConfiguredPayloadRules(
    input.downstreamFormat === 'responses'
      ? sanitizeResponsesFallbackChatBody(chatBody)
      : chatBody,
  );
  return {
    path: resolveEndpointPath('chat'),
    headers,
    body: configuredChatBody,
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
  const effectiveClaudeHeaders = {
    ...claudeHeaders,
    ...(betas.length > 0 ? { 'anthropic-beta': betas.join(',') } : {}),
  };

  if (providerProfile?.id === 'claude') {
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
      claudeHeaders: effectiveClaudeHeaders,
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

  const anthropicVersion = (
    effectiveClaudeHeaders['anthropic-version']
    || '2023-06-01'
  );
  const isClaudeOauthUpstream = sitePlatform === 'claude' && input.oauthProvider === 'claude';
  const headers = buildClaudeRuntimeHeaders({
    baseHeaders: {
      'Content-Type': 'application/json',
    },
    claudeHeaders: effectiveClaudeHeaders,
    anthropicVersion,
    stream: false,
    isClaudeOauthUpstream,
    tokenValue: input.tokenValue,
  });

  return {
    path: '/v1/messages/count_tokens?beta=true',
    headers,
    body: sanitizedBody,
    runtime: {
      executor: 'claude',
      modelName: input.modelName,
      stream: false,
      action: 'countTokens',
    },
  };
}
