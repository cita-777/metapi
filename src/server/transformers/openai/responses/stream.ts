import {
  createStreamTransformContext,
  normalizeUpstreamStreamEvent,
  pullSseEventsWithDone,
  type NormalizedStreamEvent,
  type StreamTransformContext,
} from '../../shared/normalized.js';
import {
  completeResponsesStream,
  createOpenAiResponsesAggregateState,
  failResponsesStream,
  serializeConvertedResponsesEvents,
  type OpenAiResponsesAggregateState,
} from './aggregator.js';

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object';
}

export type OpenAiResponsesStreamEvent = NormalizedStreamEvent & {
  responsesEventType?: string;
  responsesPayload?: Record<string, unknown>;
  usagePayload?: Record<string, unknown>;
};

export const openAiResponsesStream = {
  eventNames: [
    'response.created',
    'response.in_progress',
    'response.output_item.added',
    'response.output_item.done',
    'response.content_part.added',
    'response.content_part.done',
    'response.output_text.delta',
    'response.output_text.done',
    'response.function_call_arguments.delta',
    'response.function_call_arguments.done',
    'response.custom_tool_call_input.delta',
    'response.custom_tool_call_input.done',
    'response.reasoning_summary_part.added',
    'response.reasoning_summary_part.done',
    'response.reasoning_summary_text.delta',
    'response.reasoning_summary_text.done',
    'response.image_generation_call.generating',
    'response.image_generation_call.in_progress',
    'response.image_generation_call.partial_image',
    'response.image_generation_call.completed',
    'response.completed',
    'response.incomplete',
    'response.failed',
  ] as const,
  createContext(modelName: string): StreamTransformContext {
    return createStreamTransformContext(modelName);
  },
  normalizeEvent(payload: unknown, context: StreamTransformContext, modelName: string): OpenAiResponsesStreamEvent {
    const normalized = normalizeUpstreamStreamEvent(payload, context, modelName) as OpenAiResponsesStreamEvent;
    if (isRecord(payload) && typeof payload.type === 'string' && payload.type.startsWith('response.')) {
      normalized.responsesEventType = payload.type;
      normalized.responsesPayload = payload;
    }
    if (isRecord(payload) && isRecord(payload.usage)) {
      normalized.usagePayload = payload.usage;
    }
    return normalized;
  },
  pullSseEvents(buffer: string) {
    return pullSseEventsWithDone(buffer);
  },
};

export type ResponsesStreamState = OpenAiResponsesAggregateState;

export function createResponsesStreamState(modelName: string): ResponsesStreamState {
  return createOpenAiResponsesAggregateState(modelName);
}

export {
  completeResponsesStream,
  failResponsesStream,
  serializeConvertedResponsesEvents,
};
