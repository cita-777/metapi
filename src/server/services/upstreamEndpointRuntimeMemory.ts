import { createHash } from 'node:crypto';
import type { ConversationFileInputSummary } from '../proxy-core/capabilities/conversationFileCapabilities.js';
import type { DownstreamFormat } from '../transformers/shared/normalized.js';
import {
  isEndpointDispatchDeniedError,
  isUnsupportedMediaTypeError,
} from '../transformers/shared/endpointCompatibility.js';

export type UpstreamEndpointRuntimeEndpoint = 'chat' | 'messages' | 'responses';
export type UpstreamEndpointRuntimePreference = DownstreamFormat | 'responses';
export type UpstreamEndpointRuntimeMemoryWrite =
  | {
    action: 'success';
    endpoint: UpstreamEndpointRuntimeEndpoint;
    preferredEndpoint: UpstreamEndpointRuntimeEndpoint;
    stateKey: string;
    timestampMs: number;
  }
  | {
    action: 'failure';
    endpoint: UpstreamEndpointRuntimeEndpoint;
    blockedEndpoint: UpstreamEndpointRuntimeEndpoint;
    preferredEndpoint: UpstreamEndpointRuntimeEndpoint | null;
    stateKey: string;
    timestampMs: number;
  };

export type EndpointCapabilityProfile = {
  modelKey: string;
  preferMessagesForClaudeModel: boolean;
  hasImageInput: boolean;
  hasAudioInput: boolean;
  hasNonImageFileInput: boolean;
  hasRemoteDocumentUrl: boolean;
  wantsNativeResponsesReasoning: boolean;
};

type EndpointRuntimeState = {
  preferredEndpoint: UpstreamEndpointRuntimeEndpoint | null;
  preferredUpdatedAtMs: number;
  lastTouchedAtMs: number;
  blockedUntilMsByEndpoint: Partial<Record<UpstreamEndpointRuntimeEndpoint, number>>;
};

const ENDPOINT_RUNTIME_PREFERRED_TTL_MS = 24 * 60 * 60 * 1000;
const ENDPOINT_RUNTIME_BLOCK_TTL_MS = 6 * 60 * 60 * 1000;
const MAX_ENDPOINT_RUNTIME_STATES = 512;
export const MAX_ENDPOINT_RUNTIME_MODEL_KEY_LENGTH = 64;
export const MODEL_KEY_HASH_SUFFIX_LENGTH = 8;

const endpointRuntimeStates = new Map<string, EndpointRuntimeState>();

function asTrimmedString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function isClaudeFamilyModel(modelName: string): boolean {
  const normalized = asTrimmedString(modelName).toLowerCase();
  if (!normalized) return false;
  return normalized === 'claude' || normalized.startsWith('claude-') || normalized.includes('claude');
}

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

function normalizeEndpointRuntimeModelKey(...values: Array<unknown>): string {
  for (const value of values) {
    const normalized = asTrimmedString(value).toLowerCase();
    if (normalized) return boundEndpointRuntimeModelKey(normalized);
  }
  return boundEndpointRuntimeModelKey('unknown-model');
}

export function buildEndpointCapabilityProfile(input?: {
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
  return (
    !capabilityProfile.hasImageInput
    && !capabilityProfile.hasAudioInput
    && !capabilityProfile.hasNonImageFileInput
  );
}

function buildEndpointRuntimeStateKey(input: {
  siteId: number;
  downstreamFormat: UpstreamEndpointRuntimePreference;
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

function inferSuggestedEndpointFromError(errorText?: string | null): UpstreamEndpointRuntimeEndpoint | null {
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
  endpoint: UpstreamEndpointRuntimeEndpoint;
  downstreamFormat: UpstreamEndpointRuntimePreference;
}): boolean {
  if (input.downstreamFormat !== 'responses') return true;
  return input.endpoint === 'responses';
}

export function getUpstreamEndpointRuntimeStateSnapshot(input: {
  siteId: number;
  downstreamFormat: UpstreamEndpointRuntimePreference;
  modelName?: string;
  requestedModelHint?: string;
  requestCapabilities?: {
    hasNonImageFileInput?: boolean;
    conversationFileSummary?: ConversationFileInputSummary;
    wantsNativeResponsesReasoning?: boolean;
  };
}) {
  const capabilityProfile = buildEndpointCapabilityProfile({
    modelName: input.modelName,
    requestedModelHint: input.requestedModelHint,
    requestCapabilities: input.requestCapabilities,
  });
  const enabled = shouldUseEndpointRuntimeMemory(capabilityProfile);
  const stateKey = buildEndpointRuntimeStateKey({
    siteId: input.siteId,
    downstreamFormat: input.downstreamFormat,
    capabilityProfile,
  });
  const nowMs = Date.now();
  const state = endpointRuntimeStates.get(stateKey);
  const preferredEndpoint = (
    enabled
    && state?.preferredEndpoint
    && (state.preferredUpdatedAtMs + ENDPOINT_RUNTIME_PREFERRED_TTL_MS) > nowMs
    && !(
      typeof state.blockedUntilMsByEndpoint[state.preferredEndpoint] === 'number'
      && (state.blockedUntilMsByEndpoint[state.preferredEndpoint] as number) > nowMs
    )
  ) ? state.preferredEndpoint : null;

  return {
    enabled,
    stateKey,
    preferredEndpoint,
    blockedEndpoints: enabled
      ? (['chat', 'messages', 'responses'] as UpstreamEndpointRuntimeEndpoint[]).filter((endpoint) => {
        const untilMs = state?.blockedUntilMsByEndpoint[endpoint];
        return typeof untilMs === 'number' && untilMs > nowMs;
      })
      : [],
  };
}

export function applyUpstreamEndpointRuntimePreference(
  candidates: UpstreamEndpointRuntimeEndpoint[],
  input: {
    siteId: number;
    downstreamFormat: UpstreamEndpointRuntimePreference;
    capabilityProfile: EndpointCapabilityProfile;
  },
  nowMs = Date.now(),
): UpstreamEndpointRuntimeEndpoint[] {
  if (!shouldUseEndpointRuntimeMemory(input.capabilityProfile)) {
    return candidates;
  }

  const key = buildEndpointRuntimeStateKey({
    siteId: input.siteId,
    downstreamFormat: input.downstreamFormat,
    capabilityProfile: input.capabilityProfile,
  });
  const state = endpointRuntimeStates.get(key);
  if (!state || candidates.length <= 1) return candidates;
  state.lastTouchedAtMs = nowMs;

  const blocked = new Set<UpstreamEndpointRuntimeEndpoint>();
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

export function resetUpstreamEndpointRuntimeState(): void {
  endpointRuntimeStates.clear();
}

export function recordUpstreamEndpointSuccess(input: {
  siteId: number;
  endpoint: UpstreamEndpointRuntimeEndpoint;
  downstreamFormat: UpstreamEndpointRuntimePreference;
  modelName?: string;
  requestedModelHint?: string;
  requestCapabilities?: {
    hasNonImageFileInput?: boolean;
    conversationFileSummary?: ConversationFileInputSummary;
    wantsNativeResponsesReasoning?: boolean;
  };
}): UpstreamEndpointRuntimeMemoryWrite | null {
  const capabilityProfile = buildEndpointCapabilityProfile({
    modelName: input.modelName,
    requestedModelHint: input.requestedModelHint,
    requestCapabilities: input.requestCapabilities,
  });
  if (!shouldUseEndpointRuntimeMemory(capabilityProfile)) return null;
  if (!shouldRememberSuccessfulEndpoint(input)) return null;

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
  return {
    action: 'success',
    endpoint: input.endpoint,
    preferredEndpoint: input.endpoint,
    stateKey: key,
    timestampMs: nowMs,
  };
}

export function recordUpstreamEndpointFailure(input: {
  siteId: number;
  endpoint: UpstreamEndpointRuntimeEndpoint;
  downstreamFormat: UpstreamEndpointRuntimePreference;
  status: number;
  errorText?: string | null;
  modelName?: string;
  requestedModelHint?: string;
  requestCapabilities?: {
    hasNonImageFileInput?: boolean;
    conversationFileSummary?: ConversationFileInputSummary;
    wantsNativeResponsesReasoning?: boolean;
  };
}): UpstreamEndpointRuntimeMemoryWrite | null {
  const capabilityProfile = buildEndpointCapabilityProfile({
    modelName: input.modelName,
    requestedModelHint: input.requestedModelHint,
    requestCapabilities: input.requestCapabilities,
  });
  if (!shouldUseEndpointRuntimeMemory(capabilityProfile)) return null;
  if (!shouldBlockEndpointByError(input.status, input.errorText)) return null;

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
  return {
    action: 'failure',
    endpoint: input.endpoint,
    blockedEndpoint: input.endpoint,
    preferredEndpoint: (
      suggestedEndpoint && suggestedEndpoint !== input.endpoint
        ? suggestedEndpoint
        : null
    ),
    stateKey: key,
    timestampMs: nowMs,
  };
}
