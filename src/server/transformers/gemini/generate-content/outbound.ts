import {
  applyGeminiGenerateContentAggregate,
  createGeminiGenerateContentAggregateState,
  type GeminiGenerateContentAggregateState,
} from './aggregator.js';
import {
  toTransformerMetadataRecord,
  type TransformerMetadata,
} from '../../shared/normalized.js';
import {
  resolveGeminiGenerateContentUrl,
  resolveGeminiModelsUrl,
  resolveGeminiNativeBaseUrl,
} from './urlResolver.js';

type GeminiRecord = Record<string, unknown>;

function isRecord(value: unknown): value is GeminiRecord {
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

function isAggregateState(value: unknown): value is GeminiGenerateContentAggregateState {
  return isRecord(value) && Array.isArray(value.parts) && Array.isArray(value.groundingMetadata) && Array.isArray(value.citations);
}

function ensureAggregateState(payload: unknown): GeminiGenerateContentAggregateState {
  if (isAggregateState(payload)) return payload;

  const state = createGeminiGenerateContentAggregateState();
  const chunks = Array.isArray(payload) ? payload : [payload];
  for (const chunk of chunks) {
    applyGeminiGenerateContentAggregate(state, chunk);
  }
  return state;
}

function buildUsageMetadata(state: GeminiGenerateContentAggregateState): GeminiRecord | undefined {
  const usage = state.usage;
  const next: GeminiRecord = {};
  if (typeof usage.promptTokenCount === 'number') next.promptTokenCount = usage.promptTokenCount;
  if (typeof usage.candidatesTokenCount === 'number') next.candidatesTokenCount = usage.candidatesTokenCount;
  if (typeof usage.totalTokenCount === 'number') next.totalTokenCount = usage.totalTokenCount;
  if (typeof usage.cachedContentTokenCount === 'number') next.cachedContentTokenCount = usage.cachedContentTokenCount;
  if (typeof usage.thoughtsTokenCount === 'number') next.thoughtsTokenCount = usage.thoughtsTokenCount;
  return Object.keys(next).length > 0 ? next : undefined;
}

function buildCandidates(state: GeminiGenerateContentAggregateState): GeminiRecord[] {
  if (state.candidates.length > 0) {
    return state.candidates
      .slice()
      .sort((left, right) => left.index - right.index)
      .map((candidate) => {
        const next: GeminiRecord = {
          index: candidate.index,
          finishReason: candidate.finishReason || 'STOP',
          content: {
            role: 'model',
            parts: candidate.parts,
          },
        };
        if (candidate.groundingMetadata) next.groundingMetadata = candidate.groundingMetadata;
        if (candidate.citationMetadata) next.citationMetadata = candidate.citationMetadata;
        return next;
      });
  }

  const fallback: GeminiRecord = {
    index: 0,
    finishReason: state.finishReason || 'STOP',
    content: {
      role: 'model',
      parts: state.parts,
    },
  };
  if (state.groundingMetadata.length > 0) {
    fallback.groundingMetadata = state.groundingMetadata[0];
  }
  if (state.citations.length > 0) {
    fallback.citationMetadata = state.citations[0];
  }
  return [fallback];
}

function extractOrderedCandidateMetadata(
  state: GeminiGenerateContentAggregateState,
  key: 'groundingMetadata' | 'citationMetadata',
): GeminiRecord[] {
  if (state.candidates.length > 0) {
    return state.candidates
      .slice()
      .sort((left, right) => left.index - right.index)
      .map((candidate) => candidate[key])
      .filter((item): item is GeminiRecord => isRecord(item))
      .map((item) => cloneJsonValue(item));
  }

  const fallback = key === 'groundingMetadata' ? state.groundingMetadata : state.citations;
  return fallback.map((item) => cloneJsonValue(item));
}

function extractOrderedThoughtSignatures(
  state: GeminiGenerateContentAggregateState,
): {
  all: string[];
  preferred: string | undefined;
} {
  const ordered = new Set<string>();
  const preferredThoughts = new Set<string>();

  const candidates = state.candidates.length > 0
    ? state.candidates.slice().sort((left, right) => left.index - right.index)
    : [{ index: 0, finishReason: state.finishReason, parts: state.parts }];

  for (const candidate of candidates) {
    for (const part of candidate.parts) {
      if (!isRecord(part) || typeof part.thoughtSignature !== 'string' || !part.thoughtSignature.trim()) {
        continue;
      }
      ordered.add(part.thoughtSignature);
      if (part.thought === true) {
        preferredThoughts.add(part.thoughtSignature);
      }
    }
  }

  const orderedList = [...ordered];
  const preferred = [...preferredThoughts][0]
    ?? (orderedList.length === 1 ? orderedList[0] : undefined);

  return {
    all: orderedList.length > 0 ? orderedList : [...state.thoughtSignatures],
    preferred,
  };
}

function ensurePassthrough(metadata: TransformerMetadata): Record<string, unknown> {
  if (!metadata.passthrough) metadata.passthrough = {};
  return metadata.passthrough;
}

function extractRequestSemantics(requestPayload: unknown): TransformerMetadata {
  if (!isRecord(requestPayload)) return {};

  const metadata: TransformerMetadata = {};
  const passthrough = ensurePassthrough(metadata);
  if (requestPayload.systemInstruction !== undefined) {
    passthrough.systemInstruction = cloneJsonValue(requestPayload.systemInstruction);
  }
  if (requestPayload.cachedContent !== undefined) {
    passthrough.cachedContent = cloneJsonValue(requestPayload.cachedContent);
  }
  if (requestPayload.safetySettings !== undefined) {
    metadata.geminiSafetySettings = cloneJsonValue(requestPayload.safetySettings);
  }
  if (requestPayload.toolConfig !== undefined) {
    passthrough.toolConfig = cloneJsonValue(requestPayload.toolConfig);
  }

  const generationConfig = isRecord(requestPayload.generationConfig) ? requestPayload.generationConfig : null;
  if (generationConfig) {
    const preservedKeys = [
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
      'imageConfig',
    ];
    for (const key of preservedKeys) {
      if (generationConfig[key] !== undefined) {
        if (key === 'imageConfig') {
          metadata.geminiImageConfig = cloneJsonValue(generationConfig[key]);
        } else {
          passthrough[key] = cloneJsonValue(generationConfig[key]);
        }
      }
    }
  }

  if (Array.isArray(requestPayload.tools)) {
    const requestTools = requestPayload.tools
      .filter((item) => isRecord(item))
      .map((item) => {
        const next: GeminiRecord = {};
        if (item.googleSearch !== undefined) next.googleSearch = cloneJsonValue(item.googleSearch);
        if (item.urlContext !== undefined) next.urlContext = cloneJsonValue(item.urlContext);
        if (item.codeExecution !== undefined) next.codeExecution = cloneJsonValue(item.codeExecution);
        if (item.functionDeclarations !== undefined) next.functionDeclarations = cloneJsonValue(item.functionDeclarations);
        return next;
      })
      .filter((item) => Object.keys(item).length > 0);

    if (requestTools.length > 0) {
      passthrough.tools = requestTools;
    }
  }

  if (metadata.passthrough && Object.keys(metadata.passthrough).length <= 0) {
    delete metadata.passthrough;
  }

  return metadata;
}

export function serializeGeminiAggregateResponse(
  payload: GeminiGenerateContentAggregateState | unknown,
): GeminiRecord {
  const state = ensureAggregateState(payload);
  const response: GeminiRecord = {
    responseId: state.responseId || '',
    modelVersion: state.modelVersion || '',
    candidates: buildCandidates(state),
  };

  const usageMetadata = buildUsageMetadata(state);
  if (usageMetadata) {
    response.usageMetadata = usageMetadata;
  }

  return response;
}

export function extractTransformerMetadata(payload: unknown, requestPayload?: unknown): TransformerMetadata {
  const state = ensureAggregateState(payload);
  const metadata = extractRequestSemantics(requestPayload);

  const citations = extractOrderedCandidateMetadata(state, 'citationMetadata');
  const groundingMetadata = extractOrderedCandidateMetadata(state, 'groundingMetadata');
  const thoughtSignatures = extractOrderedThoughtSignatures(state);

  if (citations.length > 0) metadata.citations = citations;
  if (groundingMetadata.length > 0) metadata.groundingMetadata = groundingMetadata;
  if (thoughtSignatures.all.length > 0) {
    if (thoughtSignatures.preferred) {
      metadata.thoughtSignature = thoughtSignatures.preferred;
    }
    metadata.thoughtSignatures = thoughtSignatures.all;
  }
  const usageMetadata = buildUsageMetadata(state);
  if (usageMetadata) metadata.usageMetadata = usageMetadata;

  return metadata;
}

export function extractResponseMetadata(payload: unknown, requestPayload?: unknown): GeminiRecord {
  return toTransformerMetadataRecord(extractTransformerMetadata(payload, requestPayload)) ?? {};
}

export const geminiGenerateContentOutbound = {
  resolveBaseUrl: resolveGeminiNativeBaseUrl,
  resolveModelsUrl: resolveGeminiModelsUrl,
  resolveActionUrl: resolveGeminiGenerateContentUrl,
  extractTransformerMetadata,
  extractResponseMetadata,
  serializeAggregateResponse: serializeGeminiAggregateResponse,
};
