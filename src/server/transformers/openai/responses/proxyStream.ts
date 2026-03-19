import { createProxyStreamLifecycle } from '../../shared/protocolLifecycle.js';
import { type ParsedSseEvent } from '../../shared/normalized.js';
import { completeResponsesStream, createOpenAiResponsesAggregateState, failResponsesStream, serializeConvertedResponsesEvents } from './aggregator.js';
import { openAiResponsesOutbound } from './outbound.js';
import { openAiResponsesStream } from './stream.js';

type StreamReader = {
  read(): Promise<{ done: boolean; value?: Uint8Array }>;
  cancel(reason?: unknown): Promise<unknown>;
  releaseLock(): void;
};

type ResponseSink = {
  end(): void;
};

type ResponsesProxyStreamResult = {
  status: 'completed' | 'failed';
  errorMessage: string | null;
};

type ResponsesProxyStreamSessionInput = {
  modelName: string;
  successfulUpstreamPath: string;
  strictTerminalEvents?: boolean;
  getUsage: () => {
    promptTokens: number;
    completionTokens: number;
    totalTokens: number;
    cacheReadTokens: number;
    cacheCreationTokens: number;
    promptTokensIncludeCache: boolean | null;
  };
  onParsedPayload?: (payload: unknown) => void;
  writeLines: (lines: string[]) => void;
  writeRaw: (chunk: string) => void;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object';
}

function getResponsesStreamFailureMessage(payload: unknown, fallback = 'upstream stream failed'): string {
  if (isRecord(payload)) {
    if (isRecord(payload.error) && typeof payload.error.message === 'string' && payload.error.message.trim()) {
      return payload.error.message.trim();
    }
    if (typeof payload.message === 'string' && payload.message.trim()) {
      return payload.message.trim();
    }
    if (isRecord(payload.response) && isRecord(payload.response.error) && typeof payload.response.error.message === 'string' && payload.response.error.message.trim()) {
      return payload.response.error.message.trim();
    }
  }
  return fallback;
}

export function createResponsesProxyStreamSession(input: ResponsesProxyStreamSessionInput) {
  const streamContext = openAiResponsesStream.createContext(input.modelName);
  const responsesState = createOpenAiResponsesAggregateState(input.modelName);
  let finalized = false;
  let terminalResult: ResponsesProxyStreamResult = {
    status: 'completed',
    errorMessage: null,
  };

  const finalize = () => {
    if (finalized) return;
    finalized = true;
    terminalResult = {
      status: 'completed',
      errorMessage: null,
    };
    input.writeLines(completeResponsesStream(responsesState, streamContext, input.getUsage()));
  };

  const fail = (payload: unknown, fallbackMessage?: string) => {
    if (finalized) return;
    finalized = true;
    terminalResult = {
      status: 'failed',
      errorMessage: getResponsesStreamFailureMessage(payload, fallbackMessage),
    };
    input.writeLines(failResponsesStream(responsesState, streamContext, input.getUsage(), payload));
  };

  const closeOut = () => {
    if (finalized) return;
    if (input.strictTerminalEvents) {
      finalized = true;
      terminalResult = {
        status: 'failed',
        errorMessage: 'stream closed before response.completed',
      };
      return;
    }
    finalize();
  };

  const handleEventBlock = (eventBlock: ParsedSseEvent): boolean => {
    if (eventBlock.data === '[DONE]') {
      closeOut();
      return true;
    }

    let parsedPayload: unknown = null;
    try {
      parsedPayload = JSON.parse(eventBlock.data);
    } catch {
      parsedPayload = null;
    }

    if (parsedPayload && typeof parsedPayload === 'object') {
      input.onParsedPayload?.(parsedPayload);
    }

    const payloadType = (isRecord(parsedPayload) && typeof parsedPayload.type === 'string')
      ? parsedPayload.type
      : '';
    const isFailureEvent = (
      eventBlock.event === 'error'
      || eventBlock.event === 'response.failed'
      || payloadType === 'error'
      || payloadType === 'response.failed'
    );
    if (isFailureEvent) {
      fail(parsedPayload);
      return true;
    }

    if (parsedPayload && typeof parsedPayload === 'object') {
      const normalizedEvent = openAiResponsesStream.normalizeEvent(parsedPayload, streamContext, input.modelName);
      input.writeLines(serializeConvertedResponsesEvents({
        state: responsesState,
        streamContext,
        event: normalizedEvent,
        usage: input.getUsage(),
      }));
      return false;
    }

    input.writeLines(serializeConvertedResponsesEvents({
      state: responsesState,
      streamContext,
      event: { contentDelta: eventBlock.data },
      usage: input.getUsage(),
    }));
    return false;
  };

  return {
    consumeUpstreamFinalPayload(payload: unknown, fallbackText: string, response?: ResponseSink): ResponsesProxyStreamResult {
      if (payload && typeof payload === 'object') {
        input.onParsedPayload?.(payload);
      }

      const payloadType = (isRecord(payload) && typeof payload.type === 'string')
        ? payload.type
        : '';
      if (payloadType === 'error' || payloadType === 'response.failed') {
        fail(payload);
        response?.end();
        return terminalResult;
      }

      const normalizedFinal = openAiResponsesOutbound.normalizeFinal(payload, input.modelName, fallbackText);
      streamContext.id = normalizedFinal.id;
      streamContext.model = normalizedFinal.model;
      streamContext.created = normalizedFinal.created;

      const streamPayload = openAiResponsesOutbound.serializeFinal({
        upstreamPayload: payload,
        normalized: normalizedFinal,
        usage: input.getUsage(),
        serializationMode: 'response',
      });
      const createdPayload = {
        ...streamPayload,
        status: 'in_progress',
        output: [],
        output_text: '',
      };

      finalized = true;
      terminalResult = {
        status: 'completed',
        errorMessage: null,
      };
      input.writeLines([
        `event: response.created\ndata: ${JSON.stringify({ type: 'response.created', response: createdPayload })}\n\n`,
        `event: response.completed\ndata: ${JSON.stringify({ type: 'response.completed', response: streamPayload })}\n\n`,
        'data: [DONE]\n\n',
      ]);
      response?.end();
      return terminalResult;
    },
    async run(reader: StreamReader | null | undefined, response: ResponseSink): Promise<ResponsesProxyStreamResult> {
      const lifecycle = createProxyStreamLifecycle<ParsedSseEvent>({
        reader,
        response,
        pullEvents: (buffer) => openAiResponsesStream.pullSseEvents(buffer),
        handleEvent: handleEventBlock,
        onEof: closeOut,
      });
      await lifecycle.run();
      return terminalResult;
    },
  };
}
