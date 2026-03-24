import {
  createClaudeDownstreamContext,
  createStreamTransformContext,
  normalizeStopReason,
  normalizeUpstreamStreamEvent,
  pullSseEventsWithDone,
  type ClaudeDownstreamContext,
  type NormalizedFinalResponse,
  type NormalizedStreamEvent,
  type StreamTransformContext,
} from '../../shared/normalized.js';
import { decodeAnthropicReasoningSignature } from '../../shared/reasoningTransport.js';
import { type AnthropicExtendedStreamEvent } from './aggregator.js';

type AnthropicStreamPayload = Record<string, unknown>;
type AnthropicMessagesNormalizedFinalResponse = NormalizedFinalResponse & {
  nativeContent?: AnthropicStreamPayload[];
};

type AnthropicBlockKind = 'thinking' | 'text' | 'tool_use' | 'redacted_thinking';

type ExtendedToolBlockState = {
  contentIndex: number;
  id: string;
  name: string;
  open: boolean;
  sourceIndex: number | null;
};

type ExtendedClaudeDownstreamContext = ClaudeDownstreamContext & {
  toolBlocks: Record<number, ExtendedToolBlockState>;
  thinkingBlockIndex?: number | null;
  thinkingSourceIndex?: number | null;
  redactedBlockIndex?: number | null;
  redactedSourceIndex?: number | null;
  textSourceIndex?: number | null;
  pendingSignature?: string | null;
  activeToolSlot?: number | null;
};

export const ANTHROPIC_RAW_SSE_EVENT_NAMES = new Set([
  'message_start',
  'content_block_start',
  'content_block_delta',
  'content_block_stop',
  'message_delta',
  'message_stop',
  'ping',
  'error',
]);

function isRecord(value: unknown): value is AnthropicStreamPayload {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function asTrimmedString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function serializeSse(event: string, payload: Record<string, unknown>): string {
  return `event: ${event}\ndata: ${JSON.stringify(payload)}\n\n`;
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

function cleanAnthropicReasoningSignature(value: unknown): string | null {
  const raw = typeof value === 'string' ? value.trim() : '';
  if (!raw) return null;
  const decoded = decodeAnthropicReasoningSignature(raw);
  if (decoded) return decoded;
  if (raw.startsWith('metapi:')) return null;
  return raw;
}

function buildAnthropicFinalContentBlocks(
  normalizedFinal: NormalizedFinalResponse,
): AnthropicStreamPayload[] {
  const anthropicNormalized = normalizedFinal as AnthropicMessagesNormalizedFinalResponse;
  if (Array.isArray(anthropicNormalized.nativeContent) && anthropicNormalized.nativeContent.length > 0) {
    return anthropicNormalized.nativeContent
      .filter((block): block is AnthropicStreamPayload => isRecord(block))
      .map((block) => {
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

  const contentBlocks: AnthropicStreamPayload[] = [];
  const cleanSignature = cleanAnthropicReasoningSignature(normalizedFinal.reasoningSignature);
  if (normalizedFinal.reasoningContent || cleanSignature) {
    const thinkingBlock: AnthropicStreamPayload = {
      type: 'thinking',
      thinking: normalizedFinal.reasoningContent || '',
    };
    if (cleanSignature) thinkingBlock.signature = cleanSignature;
    contentBlocks.push(thinkingBlock);
  }
  if (normalizedFinal.redactedReasoningContent) {
    contentBlocks.push({
      type: 'redacted_thinking',
      data: normalizedFinal.redactedReasoningContent,
    });
  }
  if (normalizedFinal.content) {
    contentBlocks.push({
      type: 'text',
      text: normalizedFinal.content,
    });
  }
  if (Array.isArray(normalizedFinal.toolCalls)) {
    for (let index = 0; index < normalizedFinal.toolCalls.length; index += 1) {
      const toolCall = normalizedFinal.toolCalls[index];
      contentBlocks.push({
        type: 'tool_use',
        id: toolCall.id || `toolu_${index}`,
        name: toolCall.name || `tool_${index}`,
        input: (() => {
          const rawArguments = toolCall.arguments || '';
          try {
            return rawArguments ? JSON.parse(rawArguments) : {};
          } catch {
            return { value: rawArguments };
          }
        })(),
      });
    }
  }

  if (contentBlocks.length <= 0) {
    contentBlocks.push({
      type: 'text',
      text: '',
    });
  }
  return contentBlocks;
}

function serializeToolInputDelta(input: unknown): string | null {
  if (input === undefined) return null;
  if (typeof input === 'string') return input;
  try {
    return JSON.stringify(input);
  } catch {
    return JSON.stringify({});
  }
}

export function isAnthropicRawSseEventName(value: unknown): value is string {
  return typeof value === 'string' && ANTHROPIC_RAW_SSE_EVENT_NAMES.has(value);
}

export function serializeAnthropicRawSseEvent(event: string, data: string): string {
  const dataLines = data.split('\n').map((line) => `data: ${line}`).join('\n');
  if (event) {
    return `event: ${event}\n${dataLines}\n\n`;
  }
  return `${dataLines}\n\n`;
}

function ensureContext(context: ClaudeDownstreamContext): ExtendedClaudeDownstreamContext {
  const extended = context as ExtendedClaudeDownstreamContext;
  if (extended.thinkingBlockIndex === undefined) extended.thinkingBlockIndex = null;
  if (extended.thinkingSourceIndex === undefined) extended.thinkingSourceIndex = null;
  if (extended.redactedBlockIndex === undefined) extended.redactedBlockIndex = null;
  if (extended.redactedSourceIndex === undefined) extended.redactedSourceIndex = null;
  if (extended.textSourceIndex === undefined) extended.textSourceIndex = null;
  if (extended.pendingSignature === undefined) extended.pendingSignature = null;
  if (extended.activeToolSlot === undefined) extended.activeToolSlot = null;
  return extended;
}

export function syncAnthropicRawStreamStateFromEvent(
  eventName: string,
  parsedPayload: unknown,
  streamContext: StreamTransformContext,
  downstreamContext: ClaudeDownstreamContext,
) {
  const context = ensureContext(downstreamContext);
  if (eventName === 'message_start') {
    context.messageStarted = true;
    if (isRecord(parsedPayload) && isRecord(parsedPayload.message)) {
      const message = parsedPayload.message;
      if (typeof message.id === 'string' && message.id.trim().length > 0) {
        streamContext.id = message.id;
      }
      if (typeof message.model === 'string' && message.model.trim().length > 0) {
        streamContext.model = message.model;
      }
    }
    return;
  }

  if (eventName === 'content_block_start') {
    context.contentBlockStarted = true;
    return;
  }

  if (eventName === 'content_block_stop') {
    context.contentBlockStarted = false;
    return;
  }

  if (eventName === 'message_stop') {
    context.doneSent = true;
  }
}

function buildClaudeMessageId(sourceId: string): string {
  if (sourceId.startsWith('msg_')) return sourceId;
  const sanitized = sourceId.replace(/[^A-Za-z0-9_-]/g, '_');
  return `msg_${sanitized || Date.now()}`;
}

function ensureClaudeStartEvents(
  streamContext: StreamTransformContext,
  context: ExtendedClaudeDownstreamContext,
): string[] {
  if (context.messageStarted) return [];
  context.messageStarted = true;
  return [
    serializeSse('message_start', {
      type: 'message_start',
      message: {
        id: buildClaudeMessageId(streamContext.id),
        type: 'message',
        role: 'assistant',
        model: streamContext.model,
        content: [],
        stop_reason: null,
        stop_sequence: null,
        usage: {
          input_tokens: 0,
          output_tokens: 0,
        },
      },
    }),
  ];
}

function closeTextBlock(context: ExtendedClaudeDownstreamContext): string[] {
  if (context.textBlockIndex === null || context.textBlockIndex === undefined) return [];
  const index = context.textBlockIndex;
  context.textBlockIndex = null;
  context.textSourceIndex = null;
  context.contentBlockStarted = false;
  return [
    serializeSse('content_block_stop', {
      type: 'content_block_stop',
      index,
    }),
  ];
}

function emitPendingSignature(context: ExtendedClaudeDownstreamContext): string[] {
  if (!context.pendingSignature || context.thinkingBlockIndex === null || context.thinkingBlockIndex === undefined) {
    return [];
  }
  const signature = context.pendingSignature;
  context.pendingSignature = null;
  return [
    serializeSse('content_block_delta', {
      type: 'content_block_delta',
      index: context.thinkingBlockIndex,
      delta: {
        type: 'signature_delta',
        signature,
      },
    }),
  ];
}

function bufferPendingSignature(
  context: ExtendedClaudeDownstreamContext,
  signature: string,
): void {
  context.pendingSignature = `${context.pendingSignature || ''}${signature}`;
}

function closeThinkingBlock(context: ExtendedClaudeDownstreamContext): string[] {
  if (context.thinkingBlockIndex === null || context.thinkingBlockIndex === undefined) return [];
  const index = context.thinkingBlockIndex;
  const events = [
    ...emitPendingSignature(context),
    serializeSse('content_block_stop', {
      type: 'content_block_stop',
      index,
    }),
  ];
  context.thinkingBlockIndex = null;
  context.thinkingSourceIndex = null;
  return events;
}

function closeRedactedBlock(context: ExtendedClaudeDownstreamContext): string[] {
  if (context.redactedBlockIndex === null || context.redactedBlockIndex === undefined) return [];
  const index = context.redactedBlockIndex;
  context.redactedBlockIndex = null;
  context.redactedSourceIndex = null;
  return [
    serializeSse('content_block_stop', {
      type: 'content_block_stop',
      index,
    }),
  ];
}

function closeToolBlocks(context: ExtendedClaudeDownstreamContext): string[] {
  const openBlocks = Object.values(context.toolBlocks)
    .filter((item) => item.open)
    .sort((a, b) => a.contentIndex - b.contentIndex);

  if (openBlocks.length <= 0) return [];

  const events: string[] = [];
  for (const block of openBlocks) {
    block.open = false;
    events.push(serializeSse('content_block_stop', {
      type: 'content_block_stop',
      index: block.contentIndex,
    }));
  }
  context.activeToolSlot = null;
  return events;
}

function emitPendingSignatureAsThinkingBlock(
  context: ExtendedClaudeDownstreamContext,
): string[] {
  if (!context.pendingSignature) return [];
  const signature = context.pendingSignature;
  const events = [
    ...ensureThinkingBlockStart(context),
  ];
  context.pendingSignature = signature;
  events.push(...emitPendingSignature(context));
  events.push(...closeThinkingBlock(context));
  return events;
}

function closeAllBlocks(context: ExtendedClaudeDownstreamContext): string[] {
  return [
    ...closeTextBlock(context),
    ...closeThinkingBlock(context),
    ...closeRedactedBlock(context),
    ...closeToolBlocks(context),
  ];
}

function normalizeBlockIndex(value: unknown): number | null {
  if (typeof value !== 'number' || !Number.isFinite(value)) return null;
  return Math.max(0, Math.trunc(value));
}

function allocateContentIndex(
  context: ExtendedClaudeDownstreamContext,
  preferredIndex?: number | null,
): number {
  const normalizedPreferred = normalizeBlockIndex(preferredIndex);
  if (normalizedPreferred !== null) {
    if (context.nextContentBlockIndex <= normalizedPreferred) {
      context.nextContentBlockIndex = normalizedPreferred + 1;
    }
    return normalizedPreferred;
  }

  const index = context.nextContentBlockIndex;
  context.nextContentBlockIndex += 1;
  return index;
}

function ensureTextBlockStart(
  context: ExtendedClaudeDownstreamContext,
  preferredIndex?: number | null,
): string[] {
  if (context.textBlockIndex !== null && context.textBlockIndex !== undefined) return [];
  const index = allocateContentIndex(context, preferredIndex);
  context.textBlockIndex = index;
  context.textSourceIndex = normalizeBlockIndex(preferredIndex) ?? index;
  context.contentBlockStarted = true;
  return [
    serializeSse('content_block_start', {
      type: 'content_block_start',
      index,
      content_block: {
        type: 'text',
        text: '',
      },
    }),
  ];
}

function ensureThinkingBlockStart(
  context: ExtendedClaudeDownstreamContext,
  preferredIndex?: number | null,
): string[] {
  if (context.thinkingBlockIndex !== null && context.thinkingBlockIndex !== undefined) return [];
  const index = allocateContentIndex(context, preferredIndex);
  context.thinkingBlockIndex = index;
  context.thinkingSourceIndex = normalizeBlockIndex(preferredIndex) ?? index;
  return [
    serializeSse('content_block_start', {
      type: 'content_block_start',
      index,
      content_block: {
        type: 'thinking',
        thinking: '',
      },
    }),
  ];
}

function ensureRedactedBlockStart(
  context: ExtendedClaudeDownstreamContext,
  data: string,
  preferredIndex?: number | null,
): string[] {
  if (context.redactedBlockIndex !== null && context.redactedBlockIndex !== undefined) return [];
  const index = allocateContentIndex(context, preferredIndex);
  context.redactedBlockIndex = index;
  context.redactedSourceIndex = normalizeBlockIndex(preferredIndex) ?? index;
  return [
    serializeSse('content_block_start', {
      type: 'content_block_start',
      index,
      content_block: {
        type: 'redacted_thinking',
        data,
      },
    }),
  ];
}

function ensureToolBlockStart(
  context: ExtendedClaudeDownstreamContext,
  toolDelta: NonNullable<AnthropicExtendedStreamEvent['toolCallDeltas']>[number],
): { events: string[]; contentIndex: number } {
  const toolSlot = Number.isFinite(toolDelta.index) ? Math.max(0, Math.trunc(toolDelta.index)) : 0;
  let state = context.toolBlocks[toolSlot];
  if (!state) {
    state = {
      contentIndex: allocateContentIndex(context),
      id: toolDelta.id || `toolu_${toolSlot}`,
      name: toolDelta.name || `tool_${toolSlot}`,
      open: false,
      sourceIndex: toolSlot,
    };
    context.toolBlocks[toolSlot] = state;
  } else {
    if (toolDelta.id) state.id = toolDelta.id;
    if (toolDelta.name) state.name = toolDelta.name;
  }

  const events: string[] = [];
  if (!state.open) {
    state.open = true;
    events.push(serializeSse('content_block_start', {
      type: 'content_block_start',
      index: state.contentIndex,
      content_block: {
        type: 'tool_use',
        id: state.id,
        name: state.name,
        input: {},
      },
    }));
  }

  context.activeToolSlot = toolSlot;
  return { events, contentIndex: state.contentIndex };
}

function ensureExplicitToolBlockStart(
  context: ExtendedClaudeDownstreamContext,
  sourceIndex?: number | null,
): string[] {
  const toolSlot = normalizeBlockIndex(sourceIndex) ?? 0;
  const state = context.toolBlocks[toolSlot];
  const toolDelta: NonNullable<AnthropicExtendedStreamEvent['toolCallDeltas']>[number] = {
    index: toolSlot,
    id: state?.id,
    name: state?.name,
  };
  return ensureToolBlockStart(context, toolDelta).events;
}

function closePreviousToolBlockIfNeeded(
  context: ExtendedClaudeDownstreamContext,
  toolSlot: number,
): string[] {
  const activeToolSlot = context.activeToolSlot;
  if (activeToolSlot === null || activeToolSlot === undefined || activeToolSlot === toolSlot) {
    return [];
  }
  return closeToolBlocks(context);
}

function isMatchingBlockIndex(
  targetIndex: number,
  contentIndex: number | null | undefined,
  sourceIndex: number | null | undefined,
): boolean {
  if (sourceIndex !== null && sourceIndex !== undefined) return sourceIndex === targetIndex;
  if (contentIndex !== null && contentIndex !== undefined) return contentIndex === targetIndex;
  return false;
}

function handleExplicitBlockStart(
  kind: AnthropicBlockKind,
  sourceIndex: number | null,
  context: ExtendedClaudeDownstreamContext,
): string[] {
  if (kind === 'thinking') {
    return [
      ...closeRedactedBlock(context),
      ...closeToolBlocks(context),
      ...closeTextBlock(context),
      ...ensureThinkingBlockStart(context, sourceIndex),
    ];
  }

  if (kind === 'text') {
    return [
      ...closeRedactedBlock(context),
      ...closeToolBlocks(context),
      ...closeThinkingBlock(context),
      ...ensureTextBlockStart(context, sourceIndex),
    ];
  }

  if (kind === 'tool_use') {
    return [
      ...closeRedactedBlock(context),
      ...closeTextBlock(context),
      ...closeThinkingBlock(context),
      ...closePreviousToolBlockIfNeeded(context, normalizeBlockIndex(sourceIndex) ?? 0),
      ...ensureExplicitToolBlockStart(context, sourceIndex),
    ];
  }

  return [];
}

function buildDoneEvents(
  streamContext: StreamTransformContext,
  context: ExtendedClaudeDownstreamContext,
  finishReason?: string | null,
): string[] {
  if (context.doneSent) return [];

  const events = [
    ...ensureClaudeStartEvents(streamContext, context),
    ...closeAllBlocks(context),
    ...emitPendingSignatureAsThinkingBlock(context),
    serializeSse('message_delta', {
      type: 'message_delta',
      delta: {
        stop_reason: toClaudeStopReason(finishReason),
        stop_sequence: null,
      },
      usage: {
        output_tokens: 0,
      },
    }),
    serializeSse('message_stop', {
      type: 'message_stop',
    }),
  ];
  context.doneSent = true;
  return events;
}

export function serializeAnthropicFinalAsStream(
  normalizedFinal: NormalizedFinalResponse,
  streamContext: StreamTransformContext,
  downstreamContext: ClaudeDownstreamContext,
): string[] {
  streamContext.id = normalizedFinal.id;
  streamContext.model = normalizedFinal.model;
  streamContext.created = normalizedFinal.created;

  const lines = [
    ...anthropicMessagesStream.serializeEvent({ role: 'assistant' }, streamContext, downstreamContext),
  ];
  const serializeAnthropicEvent = (event: AnthropicExtendedStreamEvent) => anthropicMessagesStream.serializeEvent(
    event,
    streamContext,
    downstreamContext,
  );
  const contentBlocks = buildAnthropicFinalContentBlocks(normalizedFinal);

  for (let index = 0; index < contentBlocks.length; index += 1) {
    const block = contentBlocks[index];
    const blockType = asTrimmedString(block.type).toLowerCase();

    if (blockType === 'thinking') {
      lines.push(...serializeAnthropicEvent(
        {
          anthropic: {
            startBlock: {
              kind: 'thinking',
              index,
            },
          },
        },
      ));
      const thinkingText = asTrimmedString(block.thinking);
      if (thinkingText) {
        lines.push(...anthropicMessagesStream.serializeEvent(
          { reasoningDelta: thinkingText },
          streamContext,
          downstreamContext,
        ));
      }
      const cleanSignature = cleanAnthropicReasoningSignature(block.signature);
      if (cleanSignature) {
        lines.push(...serializeAnthropicEvent(
          {
            anthropic: {
              signatureDelta: cleanSignature,
            },
          },
        ));
      }
      lines.push(...serializeAnthropicEvent(
        {
          anthropic: {
            stopBlockIndex: index,
          },
        },
      ));
      continue;
    }

    if (blockType === 'redacted_thinking') {
      lines.push(...serializeAnthropicEvent(
        {
          anthropic: {
            startBlock: {
              kind: 'redacted_thinking',
              index,
            },
            redactedThinkingData: asTrimmedString(block.data),
          },
        },
      ));
      lines.push(...serializeAnthropicEvent(
        {
          anthropic: {
            stopBlockIndex: index,
          },
        },
      ));
      continue;
    }

    if (blockType === 'tool_use') {
      const argumentsDelta = serializeToolInputDelta(block.input);
      lines.push(...anthropicMessagesStream.serializeEvent(
        {
          toolCallDeltas: [{
            index,
            id: asTrimmedString(block.id) || undefined,
            name: asTrimmedString(block.name) || undefined,
            ...(argumentsDelta !== null ? { argumentsDelta } : {}),
          }],
        },
        streamContext,
        downstreamContext,
      ));
      lines.push(...serializeAnthropicEvent(
        {
          anthropic: {
            stopBlockIndex: index,
          },
        },
      ));
      continue;
    }

    lines.push(...serializeAnthropicEvent(
      {
        anthropic: {
          startBlock: {
            kind: 'text',
            index,
          },
        },
      },
    ));
    if (typeof block.text === 'string') {
      lines.push(...anthropicMessagesStream.serializeEvent(
        { contentDelta: block.text },
        streamContext,
        downstreamContext,
      ));
    }
    lines.push(...serializeAnthropicEvent(
      {
        anthropic: {
          stopBlockIndex: index,
        },
      },
    ));
  }

  lines.push(
    ...anthropicMessagesStream.serializeEvent(
      { finishReason: normalizedFinal.finishReason },
      streamContext,
      downstreamContext,
    ),
  );

  return lines;
}

export function serializeAnthropicUpstreamFinalAsStream(
  payload: unknown,
  modelName: string,
  fallbackText: string,
  normalizeFinal: (payload: unknown, modelName: string, fallbackText?: string) => NormalizedFinalResponse,
  streamContext: StreamTransformContext,
  downstreamContext: ClaudeDownstreamContext,
): string[] {
  const normalizedFinal = normalizeFinal(payload, modelName, fallbackText);
  return serializeAnthropicFinalAsStream(normalizedFinal, streamContext, downstreamContext);
}

function toClaudeStopReason(finishReason: string | null | undefined): string {
  const normalized = normalizeStopReason(finishReason);
  if (normalized === 'length') return 'max_tokens';
  if (normalized === 'tool_calls') return 'tool_use';
  return 'end_turn';
}

function normalizeAnthropicRawEvent(
  payload: AnthropicStreamPayload,
  context: StreamTransformContext,
  fallbackModel: string,
): AnthropicExtendedStreamEvent | null {
  const type = asTrimmedString(payload.type);
  if (!type) return null;

  if (type === 'message_start' && isRecord(payload.message)) {
    const message = payload.message;
    if (asTrimmedString(message.id)) context.id = asTrimmedString(message.id);
    if (asTrimmedString(message.model)) context.model = asTrimmedString(message.model);
    else if (!context.model) context.model = fallbackModel;
    return { role: 'assistant' };
  }

  if (type === 'content_block_start' && isRecord(payload.content_block)) {
    const contentBlock = payload.content_block;
    const blockType = asTrimmedString(contentBlock.type);
    const index = typeof payload.index === 'number' ? payload.index : undefined;

    if (blockType === 'text') {
      return {
        anthropic: {
          startBlock: {
            kind: 'text',
            index,
          },
        },
      };
    }

    if (blockType === 'thinking') {
      return {
        anthropic: {
          startBlock: {
            kind: 'thinking',
            index,
          },
        },
      };
    }

    if (blockType === 'redacted_thinking') {
      return {
        anthropic: {
          startBlock: {
            kind: 'redacted_thinking',
            index,
          },
          redactedThinkingData: asTrimmedString(contentBlock.data),
        },
      };
    }

    if (blockType === 'tool_use') {
      return {
        anthropic: {
          startBlock: {
            kind: 'tool_use',
            index,
          },
        },
        toolCallDeltas: [{
          index: typeof index === 'number' ? index : 0,
          id: asTrimmedString(contentBlock.id) || undefined,
          name: asTrimmedString(contentBlock.name) || undefined,
        }],
      };
    }
  }

  if (type === 'content_block_delta' && isRecord(payload.delta)) {
    const delta = payload.delta;
    const deltaType = asTrimmedString(delta.type);
    const index = typeof payload.index === 'number' ? payload.index : 0;

    if (deltaType === 'thinking_delta') {
      return {
        reasoningDelta: asTrimmedString(delta.thinking ?? delta.text) || undefined,
      };
    }

    if (deltaType === 'signature_delta') {
      return {
        anthropic: {
          signatureDelta: asTrimmedString(delta.signature) || undefined,
        },
      };
    }

    if (deltaType === 'text_delta') {
      return {
        contentDelta: asTrimmedString(delta.text) || undefined,
      };
    }

    if (deltaType === 'input_json_delta') {
      return {
        toolCallDeltas: [{
          index,
          argumentsDelta: asTrimmedString(delta.partial_json),
        }],
      };
    }
  }

  if (type === 'content_block_stop') {
    return {
      anthropic: {
        stopBlockIndex: typeof payload.index === 'number' ? payload.index : null,
      },
    };
  }

  if (type === 'message_delta' && isRecord(payload.delta)) {
    return {
      finishReason: normalizeStopReason(payload.delta.stop_reason ?? payload.stop_reason),
    };
  }

  if (type === 'message_stop') {
    return { done: true };
  }

  return null;
}

export type AnthropicConsumedSseEvent = {
  handled: boolean;
  lines: string[];
  done: boolean;
  parsedPayload: unknown | null;
};

export function consumeAnthropicSseEvent(
  eventBlock: { event: string; data: string },
  streamContext: StreamTransformContext,
  downstreamContext: ClaudeDownstreamContext,
  fallbackModel: string,
): AnthropicConsumedSseEvent {
  const context = ensureContext(downstreamContext);
  let parsedPayload: unknown = null;

  try {
    parsedPayload = JSON.parse(eventBlock.data);
  } catch {
    parsedPayload = null;
  }

  if (parsedPayload && isRecord(parsedPayload)) {
    const payloadType = typeof parsedPayload.type === 'string' ? parsedPayload.type : '';
    const claudeEventName = isAnthropicRawSseEventName(eventBlock.event)
      ? eventBlock.event
      : (isAnthropicRawSseEventName(payloadType) ? payloadType : '');

    if (claudeEventName) {
      syncAnthropicRawStreamStateFromEvent(
        claudeEventName,
        parsedPayload,
        streamContext,
        context,
      );
      return {
        handled: true,
        lines: [serializeAnthropicRawSseEvent(claudeEventName, eventBlock.data)],
        done: context.doneSent,
        parsedPayload,
      };
    }
  }

  return {
    handled: false,
    lines: [],
    done: false,
    parsedPayload,
  };
}

export const anthropicMessagesStream = {
  createContext(modelName: string): StreamTransformContext {
    return createStreamTransformContext(modelName);
  },
  createDownstreamContext(): ClaudeDownstreamContext {
    return ensureContext(createClaudeDownstreamContext());
  },
  normalizeEvent(payload: unknown, context: StreamTransformContext, modelName: string): AnthropicExtendedStreamEvent {
    if (isRecord(payload)) {
      const anthropicEvent = normalizeAnthropicRawEvent(payload, context, modelName);
      if (anthropicEvent) return anthropicEvent;
    }
    return normalizeUpstreamStreamEvent(payload, context, modelName) as AnthropicExtendedStreamEvent;
  },
  serializeEvent(
    event: NormalizedStreamEvent,
    streamContext: StreamTransformContext,
    downstreamContext: ClaudeDownstreamContext,
  ): string[] {
    const context = ensureContext(downstreamContext);
    const anthropicEvent = event as AnthropicExtendedStreamEvent;
    const events: string[] = [];
    const startBlock = anthropicEvent.anthropic?.startBlock;
    const normalizedStartIndex = normalizeBlockIndex(startBlock?.index);

    const needsStart = (
      event.role === 'assistant'
      || !!event.contentDelta
      || !!event.reasoningDelta
      || (Array.isArray(event.toolCallDeltas) && event.toolCallDeltas.length > 0)
      || !!anthropicEvent.anthropic
      || !!event.finishReason
      || !!event.done
    );
    if (needsStart) {
      events.push(...ensureClaudeStartEvents(streamContext, context));
    }

    if (startBlock && startBlock.kind !== 'redacted_thinking') {
      events.push(...handleExplicitBlockStart(startBlock.kind, normalizedStartIndex, context));
    }

    const signatureDelta = anthropicEvent.anthropic?.signatureDelta
      ?? (typeof event.reasoningSignature === 'string' ? event.reasoningSignature : undefined);
    const cleanSignatureDelta = cleanAnthropicReasoningSignature(signatureDelta);
    if (cleanSignatureDelta) {
      bufferPendingSignature(context, cleanSignatureDelta);
    }

    if (anthropicEvent.anthropic?.redactedThinkingData) {
      events.push(...closeToolBlocks(context));
      events.push(...closeTextBlock(context));
      events.push(...closeThinkingBlock(context));
      events.push(...ensureRedactedBlockStart(
        context,
        anthropicEvent.anthropic.redactedThinkingData,
        normalizedStartIndex,
      ));
    }

    if (event.reasoningDelta) {
      events.push(...closeRedactedBlock(context));
      events.push(...closeToolBlocks(context));
      events.push(...closeTextBlock(context));
      events.push(...ensureThinkingBlockStart(context, normalizedStartIndex));
      events.push(serializeSse('content_block_delta', {
        type: 'content_block_delta',
        index: context.thinkingBlockIndex ?? 0,
        delta: {
          type: 'thinking_delta',
          thinking: event.reasoningDelta,
        },
      }));
    }

    if (Array.isArray(event.toolCallDeltas) && event.toolCallDeltas.length > 0) {
      events.push(...closeRedactedBlock(context));
      events.push(...closeTextBlock(context));
      events.push(...closeThinkingBlock(context));
      for (const toolDelta of event.toolCallDeltas) {
        events.push(...closePreviousToolBlockIfNeeded(
          context,
          Number.isFinite(toolDelta.index) ? Math.max(0, Math.trunc(toolDelta.index)) : 0,
        ));
        const toolBlock = ensureToolBlockStart(context, toolDelta);
        events.push(...toolBlock.events);
        if (toolDelta.argumentsDelta) {
          events.push(serializeSse('content_block_delta', {
            type: 'content_block_delta',
            index: toolBlock.contentIndex,
            delta: {
              type: 'input_json_delta',
              partial_json: toolDelta.argumentsDelta,
            },
          }));
        }
      }
    }

    if (event.contentDelta) {
      events.push(...closeRedactedBlock(context));
      events.push(...closeToolBlocks(context));
      events.push(...closeThinkingBlock(context));
      events.push(...ensureTextBlockStart(context, normalizedStartIndex));
      events.push(serializeSse('content_block_delta', {
        type: 'content_block_delta',
        index: context.textBlockIndex ?? 0,
        delta: {
          type: 'text_delta',
          text: event.contentDelta,
        },
      }));
    }

    if (
      anthropicEvent.anthropic?.stopBlockIndex !== undefined
      && anthropicEvent.anthropic.stopBlockIndex !== null
    ) {
      const targetIndex = anthropicEvent.anthropic.stopBlockIndex;
      if (isMatchingBlockIndex(targetIndex, context.thinkingBlockIndex, context.thinkingSourceIndex)) {
        events.push(...closeThinkingBlock(context));
      }
      if (isMatchingBlockIndex(targetIndex, context.textBlockIndex, context.textSourceIndex)) {
        events.push(...closeTextBlock(context));
      }
      if (isMatchingBlockIndex(targetIndex, context.redactedBlockIndex, context.redactedSourceIndex)) {
        events.push(...closeRedactedBlock(context));
      }
      const matchingToolBlock = Object.values(context.toolBlocks).find((item) => (
        item.open
        && isMatchingBlockIndex(targetIndex, item.contentIndex, item.sourceIndex)
      ));
      if (matchingToolBlock) {
        matchingToolBlock.open = false;
        if (typeof context.activeToolSlot === 'number') {
          const activeState = context.toolBlocks[context.activeToolSlot];
          if (activeState?.contentIndex === matchingToolBlock.contentIndex) {
            context.activeToolSlot = null;
          }
        }
        events.push(serializeSse('content_block_stop', {
          type: 'content_block_stop',
          index: matchingToolBlock.contentIndex,
        }));
      }
    }

    if (event.finishReason || event.done) {
      events.push(...buildDoneEvents(streamContext, context, event.finishReason));
    }

    return events;
  },
  serializeDone(
    streamContext: StreamTransformContext,
    downstreamContext: ClaudeDownstreamContext,
  ): string[] {
    const context = ensureContext(downstreamContext);
    return buildDoneEvents(streamContext, context, 'stop');
  },
  pullSseEvents(buffer: string) {
    return pullSseEventsWithDone(buffer);
  },
  consumeAnthropicSseEvent,
  serializeUpstreamFinalAsStream(
    payload: unknown,
    modelName: string,
    fallbackText: string,
    normalizeFinal: (payload: unknown, modelName: string, fallbackText?: string) => NormalizedFinalResponse,
    streamContext: StreamTransformContext,
    downstreamContext: ClaudeDownstreamContext,
  ) {
    return serializeAnthropicUpstreamFinalAsStream(
      payload,
      modelName,
      fallbackText,
      normalizeFinal,
      streamContext,
      downstreamContext,
    );
  },
};
