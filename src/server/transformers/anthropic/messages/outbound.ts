import { normalizeUpstreamFinalResponse, toClaudeStopReason, type NormalizedFinalResponse } from '../../shared/normalized.js';
import { decodeAnthropicReasoningSignature } from '../../shared/reasoningTransport.js';
import { toAnthropicUsagePayload } from './usage.js';

type AnthropicRecord = Record<string, unknown>;

type AnthropicMessagesNormalizedFinalResponse = NormalizedFinalResponse & {
  nativeContent?: AnthropicRecord[];
  stopSequence?: string | null;
  usagePayload?: AnthropicRecord;
};

function isRecord(value: unknown): value is AnthropicRecord {
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

function asTrimmedString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function parseJsonLike(raw: string): unknown {
  const trimmed = raw.trim();
  if (!trimmed) return {};
  try {
    return JSON.parse(trimmed);
  } catch {
    return { value: raw };
  }
}

function buildClaudeMessageId(sourceId: string): string {
  if (sourceId.startsWith('msg_')) return sourceId;
  const sanitized = sourceId.replace(/[^A-Za-z0-9_-]/g, '_');
  return `msg_${sanitized || Date.now()}`;
}

function cleanAnthropicReasoningSignature(value: unknown): string | null {
  const raw = typeof value === 'string' ? value.trim() : '';
  if (!raw) return null;
  const decoded = decodeAnthropicReasoningSignature(raw);
  if (decoded) return decoded;
  if (raw.startsWith('metapi:')) return null;
  return raw;
}

function buildAnthropicContent(normalized: NormalizedFinalResponse): Array<Record<string, unknown>> {
  const anthropicNormalized = normalized as AnthropicMessagesNormalizedFinalResponse;
  if (Array.isArray(anthropicNormalized.nativeContent) && anthropicNormalized.nativeContent.length > 0) {
    return anthropicNormalized.nativeContent.map((block) => {
      const cloned = cloneJsonValue(block);
      const blockType = asTrimmedString(cloned.type).toLowerCase();
      if (blockType === 'thinking') {
        const signature = cleanAnthropicReasoningSignature(cloned.signature);
        if (signature) cloned.signature = signature;
        else delete cloned.signature;
      }
      return cloned;
    });
  }

  const contentBlocks: Array<Record<string, unknown>> = [];
  const cleanSignature = cleanAnthropicReasoningSignature(normalized.reasoningSignature);
  if (normalized.reasoningContent || cleanSignature) {
    const thinkingBlock: Record<string, unknown> = {
      type: 'thinking',
      thinking: normalized.reasoningContent || '',
    };
    if (cleanSignature) {
      thinkingBlock.signature = cleanSignature;
    }
    contentBlocks.push(thinkingBlock);
  }
  if (normalized.redactedReasoningContent) {
    contentBlocks.push({
      type: 'redacted_thinking',
      data: normalized.redactedReasoningContent,
    });
  }
  if (normalized.content) {
    contentBlocks.push({
      type: 'text',
      text: normalized.content,
    });
  }
  const toolCalls = Array.isArray(normalized.toolCalls) ? normalized.toolCalls : [];
  for (let index = 0; index < toolCalls.length; index += 1) {
    const toolCall = toolCalls[index];
    contentBlocks.push({
      type: 'tool_use',
      id: toolCall.id || `toolu_${index}`,
      name: toolCall.name || `tool_${index}`,
      input: parseJsonLike(toolCall.arguments || ''),
    });
  }
  return contentBlocks.length > 0
    ? contentBlocks
    : [{ type: 'text', text: '' }];
}

function extractNativeAnthropicContent(payload: unknown): AnthropicRecord[] | undefined {
  if (!isRecord(payload) || !Array.isArray(payload.content)) return undefined;
  const content = payload.content
    .filter((block): block is AnthropicRecord => isRecord(block))
    .map((block) => cloneJsonValue(block));
  return content.length > 0 ? content : undefined;
}

function extractStopSequence(payload: unknown): string | null {
  if (!isRecord(payload) || typeof payload.stop_sequence !== 'string') return null;
  return payload.stop_sequence;
}

function extractUsagePayload(payload: unknown): AnthropicRecord | undefined {
  if (!isRecord(payload) || !isRecord(payload.usage)) return undefined;
  return cloneJsonValue(payload.usage);
}

function mergeUsagePayload(
  usage: unknown,
  normalized: AnthropicMessagesNormalizedFinalResponse,
): AnthropicRecord {
  const merged = toAnthropicUsagePayload(usage ?? normalized.usagePayload);
  const usagePayload = normalized.usagePayload;
  if (!usagePayload) return merged;

  for (const [key, value] of Object.entries(usagePayload)) {
    if (key === 'input_tokens' || key === 'output_tokens') continue;
    if (key === 'cache_creation' && isRecord(value) && isRecord(merged.cache_creation)) {
      merged.cache_creation = {
        ...cloneJsonValue(value),
        ...merged.cache_creation,
      };
      continue;
    }
    if (merged[key] === undefined) {
      merged[key] = cloneJsonValue(value);
    }
  }

  return merged;
}

export const anthropicMessagesOutbound = {
  normalizeFinal(payload: unknown, modelName: string, fallbackText = ''): AnthropicMessagesNormalizedFinalResponse {
    const nativeContent = extractNativeAnthropicContent(payload);
    const stopSequence = extractStopSequence(payload);
    const usagePayload = extractUsagePayload(payload);

    return {
      ...normalizeUpstreamFinalResponse(payload, modelName, fallbackText),
      ...(nativeContent ? { nativeContent } : {}),
      ...(stopSequence !== null ? { stopSequence } : {}),
      ...(usagePayload ? { usagePayload } : {}),
    };
  },
  serializeFinal(normalized: NormalizedFinalResponse, usage?: unknown) {
    const anthropicNormalized = normalized as AnthropicMessagesNormalizedFinalResponse;
    return {
      id: buildClaudeMessageId(normalized.id),
      type: 'message',
      role: 'assistant',
      model: normalized.model,
      content: buildAnthropicContent(normalized),
      stop_reason: toClaudeStopReason(normalized.finishReason),
      stop_sequence: anthropicNormalized.stopSequence ?? null,
      usage: mergeUsagePayload(usage, anthropicNormalized),
    };
  },
};
