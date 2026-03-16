import {
  applyGeminiGenerateContentAggregate,
  createGeminiGenerateContentAggregateState,
  type GeminiGenerateContentAggregateState,
} from './aggregator.js';
import { serializeGeminiAggregateResponse } from './outbound.js';

type ParsedSsePayloads = {
  events: unknown[];
  lines: string[];
  rest: string;
};

type GeminiGenerateContentStreamFormat = 'sse' | 'json';

type ParsedGeminiStreamPayload = {
  format: GeminiGenerateContentStreamFormat;
  events: unknown[];
  lines?: string[];
  rest: string;
};

type AppliedGeminiStreamPayloads = ParsedGeminiStreamPayload & {
  state: GeminiGenerateContentAggregateState;
};

function serializeSsePayload(payload: unknown): string {
  return `data: ${JSON.stringify(payload)}\n\n`;
}

function parseSsePayloads(buffer: string): ParsedSsePayloads {
  const events: unknown[] = [];
  const lines: string[] = [];
  let cursor = 0;

  while (cursor < buffer.length) {
    const boundaryMatch = /\r?\n\r?\n/.exec(buffer.slice(cursor));
    if (!boundaryMatch || typeof boundaryMatch.index !== 'number') break;

    const boundary = cursor + boundaryMatch.index;
    const block = buffer.slice(cursor, boundary);
    const rawBlock = buffer.slice(cursor, boundary + boundaryMatch[0].length);
    cursor = boundary + boundaryMatch[0].length;

    if (!block.trim()) continue;
    lines.push(rawBlock);

    const data = block
      .replace(/\r\n/g, '\n')
      .split('\n')
      .filter((line) => line.startsWith('data:'))
      .map((line) => line.slice(5).trimStart())
      .join('\n')
      .trim();

    if (!data || data === '[DONE]') continue;

    try {
      events.push(JSON.parse(data));
    } catch {
      // Ignore malformed event payloads so aggregation remains tolerant.
    }
  }

  return {
    events,
    lines,
    rest: buffer.slice(cursor),
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function parseJsonArrayPayload(payload: unknown): unknown[] {
  if (Array.isArray(payload)) return payload;
  if (isRecord(payload)) return [payload];
  return [];
}

function parseGeminiStreamPayload(
  payload: unknown,
  contentType?: string | null,
): ParsedGeminiStreamPayload {
  if (geminiGenerateContentStream.isSseContentType(contentType)) {
    const parsed = parseSsePayloads(String(payload ?? ''));
    return {
      format: 'sse',
      events: parsed.events,
      lines: parsed.lines,
      rest: parsed.rest,
    };
  }

  if (typeof payload === 'string') {
    const trimmed = payload.trim();
    if (trimmed) {
      try {
        const parsedJson = JSON.parse(trimmed);
        return {
          format: 'json',
          events: parseJsonArrayPayload(parsedJson),
          rest: '',
        };
      } catch {
        const parsed = parseSsePayloads(payload);
        return {
          format: 'sse',
          events: parsed.events,
          rest: parsed.rest,
        };
      }
    }
    return {
      format: 'json',
      events: [],
      rest: '',
    };
  }

  return {
    format: 'json',
    events: parseJsonArrayPayload(payload),
    rest: '',
  };
}

function applyParsedPayloadToAggregate(
  state: GeminiGenerateContentAggregateState,
  parsed: ParsedGeminiStreamPayload,
): AppliedGeminiStreamPayloads {
  for (const event of parsed.events) {
    applyGeminiGenerateContentAggregate(state, event);
  }

  return {
    ...parsed,
    state,
  };
}

function applyJsonPayloadToAggregate(
  state: GeminiGenerateContentAggregateState,
  payload: unknown,
): GeminiGenerateContentAggregateState {
  applyParsedPayloadToAggregate(state, parseGeminiStreamPayload(payload, 'application/json'));
  return state;
}

function applySsePayloadsToAggregate(
  state: GeminiGenerateContentAggregateState,
  buffer: string,
): AppliedGeminiStreamPayloads {
  return applyParsedPayloadToAggregate(state, parseGeminiStreamPayload(buffer, 'text/event-stream'));
}

function consumeUpstreamSseBuffer(
  state: GeminiGenerateContentAggregateState,
  buffer: string,
): AppliedGeminiStreamPayloads & { lines: string[] } {
  const applied = applySsePayloadsToAggregate(state, buffer);
  return {
    ...applied,
    lines: applied.lines ?? [],
  };
}

function serializeAggregateJsonPayload(
  payload: GeminiGenerateContentAggregateState | unknown,
): unknown {
  return serializeGeminiAggregateResponse(payload);
}

function serializeAggregateSsePayload(
  payload: GeminiGenerateContentAggregateState | unknown,
): string {
  return serializeSsePayload(serializeAggregateJsonPayload(payload));
}

function serializeAggregatePayload(
  payload: GeminiGenerateContentAggregateState | unknown,
  format: GeminiGenerateContentStreamFormat = 'json',
): unknown {
  return format === 'sse'
    ? serializeAggregateSsePayload(payload)
    : serializeAggregateJsonPayload(payload);
}

function serializeUpstreamJsonPayload(
  state: GeminiGenerateContentAggregateState,
  payload: unknown,
  streamAction = false,
): unknown {
  if (streamAction) {
    const events = parseJsonArrayPayload(payload);
    for (const event of events) {
      applyGeminiGenerateContentAggregate(state, event);
    }
    return payload;
  }

  applyJsonPayloadToAggregate(state, payload);
  return serializeAggregateJsonPayload(state);
}

export const geminiGenerateContentStream = {
  isSseContentType(contentType: string | null | undefined): boolean {
    return (contentType || '').toLowerCase().includes('text/event-stream');
  },

  parseJsonArrayPayload,
  parseGeminiStreamPayload,
  parseSsePayloads,
  serializeSsePayload,
  serializeAggregateJsonPayload,
  serializeAggregatePayload,
  serializeAggregateSsePayload,
  serializeUpstreamJsonPayload,
  applyParsedPayloadToAggregate,
  applyJsonPayloadToAggregate,
  applySsePayloadsToAggregate,
  consumeUpstreamSseBuffer,

  createAggregateState(): GeminiGenerateContentAggregateState {
    return createGeminiGenerateContentAggregateState();
  },

  applyAggregate(state: GeminiGenerateContentAggregateState, payload: unknown): GeminiGenerateContentAggregateState {
    return applyGeminiGenerateContentAggregate(state, payload);
  },
};

export {
  applyParsedPayloadToAggregate,
  applyJsonPayloadToAggregate,
  applySsePayloadsToAggregate,
  parseGeminiStreamPayload,
  parseJsonArrayPayload,
  parseSsePayloads,
  serializeAggregateJsonPayload,
  serializeAggregatePayload,
  serializeAggregateSsePayload,
  serializeUpstreamJsonPayload,
  serializeSsePayload,
  consumeUpstreamSseBuffer,
};
export type {
  AppliedGeminiStreamPayloads,
  GeminiGenerateContentStreamFormat,
  ParsedGeminiStreamPayload,
  ParsedSsePayloads,
};
