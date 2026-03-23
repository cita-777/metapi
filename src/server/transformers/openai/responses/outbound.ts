import {
  normalizeUpstreamFinalResponse,
  type NormalizedFinalResponse,
} from '../../shared/normalized.js';
import { decodeOpenAiEncryptedReasoning } from '../../shared/reasoningTransport.js';
import { decodeResponsesMcpCompatToolCall } from './mcpCompatibility.js';

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object';
}

function asTrimmedString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function cloneJson<T>(value: T): T {
  if (Array.isArray(value)) {
    return value.map((item) => cloneJson(item)) as T;
  }
  if (isRecord(value)) {
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [key, cloneJson(item)]),
    ) as T;
  }
  return value;
}

function ensureResponseId(rawId: string): string {
  const trimmed = rawId.trim() || `resp_${Date.now()}`;
  return trimmed.startsWith('resp_') ? trimmed : `resp_${trimmed}`;
}

function ensureMessageId(rawId: string): string {
  const trimmed = rawId.trim() || `msg_${Date.now()}`;
  return trimmed.startsWith('msg_') ? trimmed : `msg_${trimmed}`;
}

function ensureFunctionCallId(rawId: string): string {
  const trimmed = rawId.trim();
  if (!trimmed) return `call_${Date.now()}`;
  return trimmed.startsWith('call_') ? trimmed : `call_${trimmed}`;
}

function stringifyToolInput(input: unknown): string {
  if (typeof input === 'string') return input;
  if (!input || typeof input !== 'object') return '';
  try {
    return JSON.stringify(input);
  } catch {
    return '';
  }
}

export type ResponsesUsageSummary = {
  promptTokens: number;
  completionTokens: number;
  totalTokens: number;
  inputTokensDetails?: Record<string, unknown>;
  outputTokensDetails?: Record<string, unknown>;
};

export type ResponsesToolCall = {
  id: string;
  name: string;
  arguments: string;
};

export type ResponsesFinalSerializationMode = 'response' | 'compact';

type ResponsesOutputItem = Record<string, unknown>;

function extractToolCallsFromUpstream(payload: unknown): ResponsesToolCall[] {
  if (!isRecord(payload)) return [];

  if (Array.isArray(payload.choices)) {
    const choice = payload.choices[0];
    const message = isRecord((choice as any)?.message) ? (choice as any).message : {};
    const toolCalls = Array.isArray((message as any).tool_calls) ? (message as any).tool_calls : [];
    return toolCalls
      .map((item: unknown, index: number) => {
        if (!isRecord(item)) return null;
        const fn = isRecord(item.function) ? item.function : {};
        const id = typeof item.id === 'string' && item.id.trim().length > 0
          ? item.id
          : `call_${index}`;
        const name = typeof fn.name === 'string' ? fn.name : '';
        const args = typeof fn.arguments === 'string' ? fn.arguments : '';
        return {
          id: ensureFunctionCallId(id),
          name,
          arguments: args,
        };
      })
      .filter((item): item is ResponsesToolCall => !!item);
  }

  if (payload.type === 'message' && Array.isArray(payload.content)) {
    return payload.content
      .map((item: unknown, index: number) => {
        if (!isRecord(item) || item.type !== 'tool_use') return null;
        const id = typeof item.id === 'string' && item.id.trim().length > 0
          ? item.id
          : `call_${index}`;
        const name = typeof item.name === 'string' ? item.name : '';
        const args = stringifyToolInput(item.input);
        return {
          id: ensureFunctionCallId(id),
          name,
          arguments: args,
        };
      })
      .filter((item): item is ResponsesToolCall => !!item);
  }

  return [];
}

function extractToolCallsFromNormalized(normalized: NormalizedFinalResponse): ResponsesToolCall[] {
  return Array.isArray(normalized.toolCalls)
    ? normalized.toolCalls
      .map((item) => {
        const id = ensureFunctionCallId(asTrimmedString(item.id));
        const name = asTrimmedString(item.name);
        if (!name) return null;
        return {
          id,
          name,
          arguments: typeof item.arguments === 'string' ? item.arguments : '',
        };
      })
      .filter((item): item is ResponsesToolCall => !!item)
    : [];
}

function extractAnnotationsFromUpstream(payload: unknown): unknown[] {
  if (!isRecord(payload)) return [];

  if (Array.isArray(payload.choices)) {
    const choice = payload.choices[0];
    const message = isRecord((choice as any)?.message) ? (choice as any).message : {};
    const annotations = Array.isArray((message as any).annotations) ? (message as any).annotations : [];
    return annotations.map((item) => cloneJson(item));
  }

  if (payload.type === 'message' && Array.isArray(payload.content)) {
    const annotations = payload.content
      .filter((item): item is Record<string, unknown> => isRecord(item))
      .flatMap((item) => (Array.isArray(item.annotations) ? item.annotations : []));
    return annotations.map((item) => cloneJson(item));
  }

  return [];
}

function extractSyntheticOutputItemsFromUpstream(payload: unknown): ResponsesOutputItem[] {
  if (!isRecord(payload) || !Array.isArray(payload.output)) return [];

  return payload.output
    .map((rawItem): ResponsesOutputItem | null => {
      if (!isRecord(rawItem)) return null;
      const itemType = asTrimmedString(rawItem.type).toLowerCase();
      if (!itemType) return null;

      if (itemType === 'message') {
        return {
          id: asTrimmedString(rawItem.id) || ensureMessageId(''),
          type: 'message',
          role: asTrimmedString(rawItem.role) || 'assistant',
          status: asTrimmedString(rawItem.status) || 'completed',
          content: Array.isArray(rawItem.content) ? cloneJson(rawItem.content) : [],
        };
      }

      if (itemType === 'reasoning') {
        return {
          id: asTrimmedString(rawItem.id) || ensureMessageId(''),
          type: 'reasoning',
          status: asTrimmedString(rawItem.status) || 'completed',
          encrypted_content: rawItem.encrypted_content,
          summary: Array.isArray(rawItem.summary) ? cloneJson(rawItem.summary) : [],
        };
      }

      if (itemType === 'function_call') {
        return {
          id: asTrimmedString(rawItem.id) || ensureFunctionCallId(''),
          type: 'function_call',
          status: asTrimmedString(rawItem.status) || 'completed',
          call_id: asTrimmedString(rawItem.call_id) || ensureFunctionCallId(asTrimmedString(rawItem.id)),
          name: asTrimmedString(rawItem.name),
          arguments: typeof rawItem.arguments === 'string' ? rawItem.arguments : '',
        };
      }

      if (itemType === 'custom_tool_call') {
        return {
          id: asTrimmedString(rawItem.id) || ensureFunctionCallId(''),
          type: 'custom_tool_call',
          status: asTrimmedString(rawItem.status) || 'completed',
          call_id: asTrimmedString(rawItem.call_id) || ensureFunctionCallId(asTrimmedString(rawItem.id)),
          name: asTrimmedString(rawItem.name),
          input: typeof rawItem.input === 'string' ? rawItem.input : '',
        };
      }

      if (itemType === 'function_call_output' || itemType === 'custom_tool_call_output') {
        return {
          id: asTrimmedString(rawItem.id) || ensureMessageId(''),
          type: itemType,
          status: asTrimmedString(rawItem.status) || 'completed',
          call_id: asTrimmedString(rawItem.call_id),
          output: cloneJson(rawItem.output),
        };
      }

      if (itemType === 'image_generation_call') {
        return {
          id: asTrimmedString(rawItem.id) || ensureMessageId(''),
          type: 'image_generation_call',
          status: asTrimmedString(rawItem.status) || 'completed',
          result: cloneJson(rawItem.result),
          partial_images: Array.isArray(rawItem.partial_images) ? cloneJson(rawItem.partial_images) : [],
          ...(rawItem.background !== undefined ? { background: cloneJson(rawItem.background) } : {}),
          ...(rawItem.mime_type !== undefined ? { mime_type: cloneJson(rawItem.mime_type) } : {}),
          ...(rawItem.output_format !== undefined ? { output_format: cloneJson(rawItem.output_format) } : {}),
          ...(rawItem.quality !== undefined ? { quality: cloneJson(rawItem.quality) } : {}),
          ...(rawItem.size !== undefined ? { size: cloneJson(rawItem.size) } : {}),
          ...(rawItem.revised_prompt !== undefined ? { revised_prompt: cloneJson(rawItem.revised_prompt) } : {}),
        };
      }

      if (itemType.startsWith('mcp_')) {
        return cloneJson(rawItem);
      }

      return null;
    })
    .filter((item): item is ResponsesOutputItem => item !== null);
}

function collectOutputTextFromItems(items: ResponsesOutputItem[]): string {
  const textParts: string[] = [];

  for (const item of items) {
    if (asTrimmedString(item.type).toLowerCase() !== 'message') continue;
    const content = Array.isArray(item.content) ? item.content : [];
    for (const part of content) {
      if (!isRecord(part)) continue;
      const partType = asTrimmedString(part.type).toLowerCase();
      if ((partType === 'output_text' || partType === 'text') && typeof part.text === 'string') {
        textParts.push(part.text);
      }
    }
  }

  return textParts.join('');
}

function extractSyntheticUsageDetails(upstreamPayload: unknown): {
  inputTokensDetails?: Record<string, unknown>;
  outputTokensDetails?: Record<string, unknown>;
} {
  if (!isRecord(upstreamPayload) || !isRecord(upstreamPayload.usage)) {
    return {};
  }

  const usage = upstreamPayload.usage;
  const promptDetails = (
    (isRecord(usage.input_tokens_details) ? usage.input_tokens_details : null)
    ?? (isRecord(usage.prompt_tokens_details) ? usage.prompt_tokens_details : null)
  );
  const completionDetails = (
    (isRecord(usage.output_tokens_details) ? usage.output_tokens_details : null)
    ?? (isRecord(usage.completion_tokens_details) ? usage.completion_tokens_details : null)
  );

  return {
    ...(promptDetails ? { inputTokensDetails: cloneJson(promptDetails) } : {}),
    ...(completionDetails ? { outputTokensDetails: cloneJson(completionDetails) } : {}),
  };
}

export function normalizeResponsesFinalPayload(
  payload: unknown,
  modelName: string,
  fallbackText = '',
): NormalizedFinalResponse {
  return normalizeUpstreamFinalResponse(payload, modelName, fallbackText);
}

function buildResponsesUsagePayload(
  usage: ResponsesUsageSummary,
  syntheticUsageDetails: {
    inputTokensDetails?: Record<string, unknown>;
    outputTokensDetails?: Record<string, unknown>;
  },
): Record<string, unknown> {
  return {
    input_tokens: usage.promptTokens,
    output_tokens: usage.completionTokens,
    total_tokens: usage.totalTokens,
    ...(usage.inputTokensDetails ?? syntheticUsageDetails.inputTokensDetails
      ? { input_tokens_details: cloneJson(usage.inputTokensDetails ?? syntheticUsageDetails.inputTokensDetails) }
      : {}),
    ...(usage.outputTokensDetails ?? syntheticUsageDetails.outputTokensDetails
      ? { output_tokens_details: cloneJson(usage.outputTokensDetails ?? syntheticUsageDetails.outputTokensDetails) }
      : {}),
  };
}

export function serializeResponsesFinalPayload(input: {
  upstreamPayload: unknown;
  normalized: NormalizedFinalResponse;
  usage: ResponsesUsageSummary;
  serializationMode?: ResponsesFinalSerializationMode;
}): Record<string, unknown> {
  const {
    upstreamPayload,
    normalized,
    usage,
    serializationMode = 'response',
  } = input;
  if (isRecord(upstreamPayload)) {
    if (upstreamPayload.object === 'response.compaction') {
      return upstreamPayload;
    }
    if (serializationMode === 'response' && upstreamPayload.object === 'response') {
      return upstreamPayload;
    }
  }

  const normalizedId = typeof normalized.id === 'string' && normalized.id.trim()
    ? normalized.id.trim()
    : `resp_${Date.now()}`;
  const responseId = ensureResponseId(normalizedId);
  const messageId = ensureMessageId(normalizedId);
  const syntheticOutput = extractSyntheticOutputItemsFromUpstream(upstreamPayload);
  const syntheticUsageDetails = extractSyntheticUsageDetails(upstreamPayload);
  const toolCalls = (() => {
    const extracted = extractToolCallsFromUpstream(upstreamPayload);
    if (extracted.length > 0) return extracted;
    return extractToolCallsFromNormalized(normalized);
  })();
  const rawReasoningSignature = typeof normalized.reasoningSignature === 'string'
    ? normalized.reasoningSignature.trim()
    : '';
  const encryptedReasoning = decodeOpenAiEncryptedReasoning(rawReasoningSignature)
    ?? (rawReasoningSignature && !rawReasoningSignature.startsWith('metapi:') ? rawReasoningSignature : null);
  const annotations = extractAnnotationsFromUpstream(upstreamPayload);

  const output: Array<Record<string, unknown>> = syntheticOutput.map((item) => cloneJson(item));
  const hasReasoningItem = output.some((item) => asTrimmedString(item.type).toLowerCase() === 'reasoning');
  const hasMessageItem = output.some((item) => asTrimmedString(item.type).toLowerCase() === 'message');
  const hasToolLikeItem = output.some((item) => {
    const itemType = asTrimmedString(item.type).toLowerCase();
    return (
      itemType === 'function_call'
      || itemType === 'custom_tool_call'
      || itemType === 'function_call_output'
      || itemType === 'custom_tool_call_output'
      || itemType === 'image_generation_call'
    );
  });

  if ((normalized.reasoningContent || encryptedReasoning) && !hasReasoningItem) {
    const reasoningItem: Record<string, unknown> = {
      id: ensureMessageId(`${normalizedId}_reasoning`),
      type: 'reasoning',
      status: 'completed',
      summary: normalized.reasoningContent
        ? [{
          type: 'summary_text',
          text: normalized.reasoningContent,
        }]
        : [],
    };
    if (encryptedReasoning) {
      reasoningItem.encrypted_content = encryptedReasoning;
    }
    output.push(reasoningItem);
  }

  if ((normalized.content || (!hasToolLikeItem && output.length === 0 && toolCalls.length === 0)) && !hasMessageItem) {
    const textPart: Record<string, unknown> = {
      type: 'output_text',
      text: normalized.content || '',
    };
    if (annotations.length > 0) {
      textPart.annotations = annotations;
    }
    output.push({
      id: messageId,
      type: 'message',
      role: 'assistant',
      status: 'completed',
      content: [textPart],
    });
  }

  if (toolCalls.length > 0 && !hasToolLikeItem) {
    for (const toolCall of toolCalls) {
      const mcpItem = decodeResponsesMcpCompatToolCall(toolCall.name, toolCall.arguments);
      if (mcpItem) {
        output.push(mcpItem);
        continue;
      }

      output.push({
        id: toolCall.id,
        type: 'function_call',
        status: 'completed',
        call_id: toolCall.id,
        name: toolCall.name,
        arguments: toolCall.arguments,
      });
    }
  }

  const usagePayload = buildResponsesUsagePayload(usage, syntheticUsageDetails);
  if (serializationMode === 'compact') {
    return {
      id: responseId,
      object: 'response.compaction',
      created_at: normalized.created,
      output,
      usage: usagePayload,
    };
  }

  return {
    id: responseId,
    object: 'response',
    created_at: normalized.created,
    status: 'completed',
    model: normalized.model,
    output,
    output_text: normalized.content || collectOutputTextFromItems(output),
    usage: usagePayload,
  };
}

export const openAiResponsesOutbound = {
  normalizeFinal: normalizeResponsesFinalPayload,
  serializeFinal: serializeResponsesFinalPayload,
};

export {
  serializeResponsesFinalPayload as toResponsesPayload,
};
