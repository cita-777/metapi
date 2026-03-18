export {
  buildSyntheticOpenAiChunks,
  createClaudeDownstreamContext,
  createStreamTransformContext,
  normalizeStopReason,
  normalizeUpstreamFinalResponse,
  normalizeUpstreamStreamEvent,
  parseDownstreamChatRequest,
  pullSseEventsWithDone,
  serializeFinalResponse,
  serializeNormalizedStreamEvent,
  serializeStreamDone,
  toClaudeStopReason,
  type ClaudeDownstreamContext,
  type DownstreamFormat,
  type NormalizedFinalResponse,
  type NormalizedStreamEvent,
  type ParsedDownstreamChatRequest,
  type ParsedSseEvent,
  type StreamTransformContext,
} from './chatFormatsCore.js';

export type NormalizedContentBlockType =
  | 'text'
  | 'image_url'
  | 'image_inline'
  | 'input_file'
  | 'input_audio'
  | 'output_audio'
  | 'tool_call'
  | 'tool_result'
  | 'function_response'
  | 'reasoning'
  | 'redacted_reasoning';

export type NormalizedContentBlock = {
  type: NormalizedContentBlockType;
  role?: string | null;
  text?: string | null;
  mimeType?: string | null;
  url?: string | null;
  data?: string | null;
  fileId?: string | null;
  filename?: string | null;
  toolName?: string | null;
  toolCallId?: string | null;
  argumentsText?: string | null;
  result?: unknown;
  metadata?: Record<string, unknown> | null;
};

export type NormalizedUsage = {
  promptTokens?: number | null;
  completionTokens?: number | null;
  totalTokens?: number | null;
  cachedTokens?: number | null;
  cacheReadTokens?: number | null;
  cacheCreationTokens?: number | null;
  reasoningTokens?: number | null;
  audioInputTokens?: number | null;
  audioOutputTokens?: number | null;
  acceptedPredictionTokens?: number | null;
  rejectedPredictionTokens?: number | null;
};

export type ParsedDownstreamChatRequestResult = {
  value?: import('./chatFormatsCore.js').ParsedDownstreamChatRequest;
  error?: { statusCode: number; payload: unknown };
};

export type TransformerMetadata = {
  include?: unknown;
  maxToolCalls?: number | null;
  promptCacheKey?: unknown;
  promptCacheRetention?: unknown;
  truncation?: unknown;
  serviceTier?: unknown;
  includeObfuscation?: boolean | null;
  citations?: unknown;
  annotations?: unknown;
  groundingMetadata?: unknown;
  usageMetadata?: unknown;
  geminiSafetySettings?: unknown;
  geminiImageConfig?: unknown;
  thoughtSignature?: string | null;
  thoughtSignatures?: string[];
  passthrough?: Record<string, unknown>;
};

export type NormalizedRequest = {
  protocol: import('./chatFormatsCore.js').DownstreamFormat | 'responses' | 'gemini' | 'gemini-cli';
  model: string;
  stream: boolean;
  rawBody: unknown;
  parsed: import('./chatFormatsCore.js').ParsedDownstreamChatRequest | null;
  contentBlocks?: NormalizedContentBlock[];
  metadata?: TransformerMetadata;
};

export type NormalizedResponseEnvelope = {
  protocol: import('./chatFormatsCore.js').DownstreamFormat | 'responses' | 'gemini' | 'gemini-cli';
  model: string;
  final: import('./chatFormatsCore.js').NormalizedFinalResponse;
  usage?: unknown;
  contentBlocks?: NormalizedContentBlock[];
  metadata?: TransformerMetadata;
};

export type NormalizedStreamEnvelope = {
  protocol: import('./chatFormatsCore.js').DownstreamFormat | 'responses' | 'gemini' | 'gemini-cli';
  model: string;
  event: import('./chatFormatsCore.js').NormalizedStreamEvent;
  metadata?: TransformerMetadata;
};

export function createEmptyNormalizedUsage(): NormalizedUsage {
  return {
    promptTokens: 0,
    completionTokens: 0,
    totalTokens: 0,
    cachedTokens: 0,
    cacheReadTokens: 0,
    cacheCreationTokens: 0,
    reasoningTokens: 0,
    audioInputTokens: 0,
    audioOutputTokens: 0,
    acceptedPredictionTokens: 0,
    rejectedPredictionTokens: 0,
  };
}

export function mergeNormalizedUsage(
  base: NormalizedUsage | undefined,
  next: NormalizedUsage | undefined,
): NormalizedUsage {
  const merged = { ...createEmptyNormalizedUsage(), ...(base || {}) };
  const incoming = next || {};
  return {
    promptTokens: (merged.promptTokens || 0) + (incoming.promptTokens || 0),
    completionTokens: (merged.completionTokens || 0) + (incoming.completionTokens || 0),
    totalTokens: (merged.totalTokens || 0) + (incoming.totalTokens || 0),
    cachedTokens: (merged.cachedTokens || 0) + (incoming.cachedTokens || 0),
    cacheReadTokens: (merged.cacheReadTokens || 0) + (incoming.cacheReadTokens || 0),
    cacheCreationTokens: (merged.cacheCreationTokens || 0) + (incoming.cacheCreationTokens || 0),
    reasoningTokens: (merged.reasoningTokens || 0) + (incoming.reasoningTokens || 0),
    audioInputTokens: (merged.audioInputTokens || 0) + (incoming.audioInputTokens || 0),
    audioOutputTokens: (merged.audioOutputTokens || 0) + (incoming.audioOutputTokens || 0),
    acceptedPredictionTokens: (merged.acceptedPredictionTokens || 0) + (incoming.acceptedPredictionTokens || 0),
    rejectedPredictionTokens: (merged.rejectedPredictionTokens || 0) + (incoming.rejectedPredictionTokens || 0),
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function cloneJsonValue<T>(value: T): T {
  if (Array.isArray(value)) {
    return value.map((item) => cloneJsonValue(item)) as T;
  }
  if (isRecord(value)) {
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [key, cloneJsonValue(item)]),
    ) as T;
  }
  return value;
}

const TRANSFORMER_METADATA_PASSTHROUGH_KEYS = new Set([
  'systemInstruction',
  'cachedContent',
  'toolConfig',
  'tools',
  'stopSequences',
  'responseModalities',
  'responseMimeType',
  'responseSchema',
  'candidateCount',
  'maxOutputTokens',
  'temperature',
  'topP',
  'topK',
  'presencePenalty',
  'frequencyPenalty',
  'seed',
  'responseLogprobs',
  'logprobs',
  'thinkingConfig',
]);

export function toTransformerMetadataRecord(
  metadata: TransformerMetadata | undefined,
): Record<string, unknown> | undefined {
  if (!metadata) return undefined;

  const record: Record<string, unknown> = {};
  if (metadata.include !== undefined) record.include = cloneJsonValue(metadata.include);
  if (metadata.maxToolCalls !== undefined) record.maxToolCalls = metadata.maxToolCalls;
  if (metadata.promptCacheKey !== undefined) record.promptCacheKey = cloneJsonValue(metadata.promptCacheKey);
  if (metadata.promptCacheRetention !== undefined) {
    record.promptCacheRetention = cloneJsonValue(metadata.promptCacheRetention);
  }
  if (metadata.truncation !== undefined) record.truncation = cloneJsonValue(metadata.truncation);
  if (metadata.serviceTier !== undefined) record.serviceTier = cloneJsonValue(metadata.serviceTier);
  if (metadata.includeObfuscation !== undefined) record.includeObfuscation = metadata.includeObfuscation;
  if (metadata.citations !== undefined) record.citations = cloneJsonValue(metadata.citations);
  if (metadata.annotations !== undefined) record.annotations = cloneJsonValue(metadata.annotations);
  if (metadata.groundingMetadata !== undefined) {
    record.groundingMetadata = cloneJsonValue(metadata.groundingMetadata);
  }
  if (metadata.usageMetadata !== undefined) {
    record.usageMetadata = cloneJsonValue(metadata.usageMetadata);
  }
  if (metadata.geminiSafetySettings !== undefined) {
    record.safetySettings = cloneJsonValue(metadata.geminiSafetySettings);
  }
  if (metadata.geminiImageConfig !== undefined) {
    record.imageConfig = cloneJsonValue(metadata.geminiImageConfig);
  }
  if (metadata.thoughtSignature !== undefined) record.thoughtSignature = metadata.thoughtSignature;
  if (metadata.thoughtSignatures !== undefined) {
    record.thoughtSignatures = cloneJsonValue(metadata.thoughtSignatures);
  }
  if (isRecord(metadata.passthrough)) {
    for (const [key, value] of Object.entries(metadata.passthrough)) {
      if (record[key] === undefined) {
        record[key] = cloneJsonValue(value);
      }
    }
  }

  return Object.keys(record).length > 0 ? record : undefined;
}

export function fromTransformerMetadataRecord(
  value: unknown,
): TransformerMetadata | undefined {
  if (!isRecord(value)) return undefined;

  const metadata: TransformerMetadata = {};
  if (value.include !== undefined) metadata.include = cloneJsonValue(value.include);
  if (typeof value.maxToolCalls === 'number' && Number.isFinite(value.maxToolCalls)) {
    metadata.maxToolCalls = value.maxToolCalls;
  }
  if (value.promptCacheKey !== undefined) metadata.promptCacheKey = cloneJsonValue(value.promptCacheKey);
  if (value.promptCacheRetention !== undefined) {
    metadata.promptCacheRetention = cloneJsonValue(value.promptCacheRetention);
  }
  if (value.truncation !== undefined) metadata.truncation = cloneJsonValue(value.truncation);
  if (value.serviceTier !== undefined) metadata.serviceTier = cloneJsonValue(value.serviceTier);
  if (typeof value.includeObfuscation === 'boolean') metadata.includeObfuscation = value.includeObfuscation;
  if (value.citations !== undefined) metadata.citations = cloneJsonValue(value.citations);
  if (value.annotations !== undefined) metadata.annotations = cloneJsonValue(value.annotations);
  if (value.groundingMetadata !== undefined) {
    metadata.groundingMetadata = cloneJsonValue(value.groundingMetadata);
  }
  if (value.usageMetadata !== undefined) {
    metadata.usageMetadata = cloneJsonValue(value.usageMetadata);
  }
  if (value.safetySettings !== undefined) {
    metadata.geminiSafetySettings = cloneJsonValue(value.safetySettings);
  }
  if (value.imageConfig !== undefined) {
    metadata.geminiImageConfig = cloneJsonValue(value.imageConfig);
  }
  if (typeof value.thoughtSignature === 'string') metadata.thoughtSignature = value.thoughtSignature;
  if (Array.isArray(value.thoughtSignatures)) {
    metadata.thoughtSignatures = value.thoughtSignatures
      .filter((item): item is string => typeof item === 'string');
  }

  const passthroughEntries = Object.entries(value)
    .filter(([key]) => TRANSFORMER_METADATA_PASSTHROUGH_KEYS.has(key));
  if (passthroughEntries.length > 0) {
    metadata.passthrough = Object.fromEntries(
      passthroughEntries.map(([key, entry]) => [key, cloneJsonValue(entry)]),
    );
  }

  return Object.keys(metadata).length > 0 ? metadata : undefined;
}
