import { anthropicMessagesTransformer } from '../../anthropic/messages/index.js';
import { createProxyStreamLifecycle } from '../../shared/protocolLifecycle.js';
import { type DownstreamFormat, type ParsedSseEvent } from '../../shared/normalized.js';
import { createOpenAiChatAggregateState, applyOpenAiChatStreamEvent, finalizeOpenAiChatAggregate } from './aggregator.js';
import { openAiChatOutbound } from './outbound.js';
import { openAiChatStream } from './stream.js';

type StreamReader = {
  read(): Promise<{ done: boolean; value?: Uint8Array }>;
  cancel(reason?: unknown): Promise<unknown>;
  releaseLock(): void;
};

type ChatProxyStreamSessionInput = {
  downstreamFormat: DownstreamFormat;
  modelName: string;
  successfulUpstreamPath: string;
  onParsedPayload?: (payload: unknown) => void;
  writeLines: (lines: string[]) => void;
  writeRaw: (chunk: string) => void;
};

type ResponseSink = {
  end(): void;
};

type ChatProxyStreamResult = {
  status: 'completed' | 'failed';
  errorMessage: string | null;
};

export function createChatProxyStreamSession(input: ChatProxyStreamSessionInput) {
  const downstreamTransformer = input.downstreamFormat === 'claude'
    ? anthropicMessagesTransformer
    : {
      createStreamContext: openAiChatStream.createContext,
      transformStreamEvent: openAiChatStream.normalizeEvent,
      serializeStreamEvent: openAiChatStream.serializeEvent,
      serializeDone: openAiChatStream.serializeDone,
      pullSseEvents: openAiChatStream.pullSseEvents,
    };
  const streamContext = downstreamTransformer.createStreamContext(input.modelName);
  const claudeContext = anthropicMessagesTransformer.createDownstreamContext();
  const chatAggregateState = input.downstreamFormat === 'openai'
    ? createOpenAiChatAggregateState()
    : null;
  let finalized = false;
  let terminalResult: ChatProxyStreamResult = {
    status: 'completed',
    errorMessage: null,
  };

  const extractFailureMessage = (payload: unknown, fallback = 'upstream stream failed'): string => {
    if (payload && typeof payload === 'object' && !Array.isArray(payload)) {
      const record = payload as Record<string, unknown>;
      if (record.error && typeof record.error === 'object' && !Array.isArray(record.error)) {
        const message = (record.error as Record<string, unknown>).message;
        if (typeof message === 'string' && message.trim()) return message.trim();
      }
      if (typeof record.message === 'string' && record.message.trim()) return record.message.trim();
      if (record.response && typeof record.response === 'object' && !Array.isArray(record.response)) {
        const responseError = (record.response as Record<string, unknown>).error;
        if (responseError && typeof responseError === 'object' && !Array.isArray(responseError)) {
          const message = (responseError as Record<string, unknown>).message;
          if (typeof message === 'string' && message.trim()) return message.trim();
        }
      }
    }
    return fallback;
  };

  const markFailed = (payload: unknown, fallbackMessage?: string) => {
    terminalResult = {
      status: 'failed',
      errorMessage: extractFailureMessage(payload, fallbackMessage),
    };
  };

  const finalize = () => {
    if (finalized) return;
    finalized = true;

    // For native Anthropic streams, EOF without message_stop is not a clean
    // completion. Forward the partial stream as-is instead of fabricating an
    // end_turn/message_stop pair that makes clients think the run finished.
    if (input.downstreamFormat === 'claude' && !claudeContext.doneSent) {
      return;
    }

    if (
      input.downstreamFormat === 'openai'
      && terminalResult.status !== 'failed'
      && chatAggregateState
      && chatAggregateState.choices.size > 0
    ) {
      const needsTerminalFinishChunk = Array.from(chatAggregateState.choices.values())
        .some((choice) => !choice.finishReason);
      if (needsTerminalFinishChunk) {
        const terminalChunk = openAiChatOutbound.buildSyntheticChunks(
          finalizeOpenAiChatAggregate(chatAggregateState, {
            id: streamContext.id,
            model: streamContext.model,
            created: streamContext.created,
            content: '',
            reasoningContent: '',
            finishReason: 'stop',
            toolCalls: [],
          }),
        ).slice(-1)[0];
        if (terminalChunk) {
          input.writeLines([`data: ${JSON.stringify(terminalChunk)}\n\n`]);
        }
      }
    }

    input.writeLines(downstreamTransformer.serializeDone(streamContext, claudeContext));
  };

  const handleEventBlock = async (eventBlock: ParsedSseEvent): Promise<boolean> => {
    if (eventBlock.data === '[DONE]') {
      finalize();
      return true;
    }

    let parsedPayload: unknown = null;
    if (input.downstreamFormat === 'claude') {
      const consumed = anthropicMessagesTransformer.consumeSseEventBlock(
        eventBlock,
        streamContext,
        claudeContext,
        input.modelName,
      );
      parsedPayload = consumed.parsedPayload;
      if (parsedPayload && typeof parsedPayload === 'object') {
        input.onParsedPayload?.(parsedPayload);
      }
      if (consumed.handled) {
        input.writeLines(consumed.lines);
        return consumed.done;
      }
    } else {
      try {
        parsedPayload = JSON.parse(eventBlock.data);
      } catch {
        parsedPayload = null;
      }
      if (parsedPayload && typeof parsedPayload === 'object') {
        input.onParsedPayload?.(parsedPayload);
      }
    }

    if (parsedPayload && typeof parsedPayload === 'object') {
      const payloadType = typeof (parsedPayload as Record<string, unknown>).type === 'string'
        ? String((parsedPayload as Record<string, unknown>).type)
        : '';
      if (payloadType === 'response.failed' || payloadType === 'error') {
        markFailed(parsedPayload);
      }
      const normalizedEvent = downstreamTransformer.transformStreamEvent(parsedPayload, streamContext, input.modelName);
      if (input.downstreamFormat === 'openai' && chatAggregateState) {
        applyOpenAiChatStreamEvent(chatAggregateState, normalizedEvent);
      }
      input.writeLines(downstreamTransformer.serializeStreamEvent(normalizedEvent, streamContext, claudeContext));
      return input.downstreamFormat === 'claude' && claudeContext.doneSent;
    }

    if (input.downstreamFormat === 'openai') {
      input.writeRaw(`data: ${eventBlock.data}\n\n`);
      return false;
    }

    input.writeLines(anthropicMessagesTransformer.serializeStreamEvent({
      contentDelta: eventBlock.data,
    }, streamContext, claudeContext));
    return claudeContext.doneSent;
  };

  return {
    consumeUpstreamFinalPayload(payload: unknown, fallbackText: string, response?: ResponseSink): ChatProxyStreamResult {
      if (payload && typeof payload === 'object') {
        input.onParsedPayload?.(payload);
      }
      if (payload && typeof payload === 'object' && !Array.isArray(payload)) {
        const payloadType = typeof (payload as Record<string, unknown>).type === 'string'
          ? String((payload as Record<string, unknown>).type)
          : '';
        if (payloadType === 'response.failed' || payloadType === 'error') {
          markFailed(payload);
        }
      }
      if (input.downstreamFormat === 'openai') {
        const normalizedFinal = openAiChatOutbound.normalizeFinal(payload, input.modelName, fallbackText);
        streamContext.id = normalizedFinal.id;
        streamContext.model = normalizedFinal.model;
        streamContext.created = normalizedFinal.created;
        input.writeLines(
          openAiChatOutbound
            .buildSyntheticChunks(normalizedFinal)
            .map((chunk) => `data: ${JSON.stringify(chunk)}\n\n`),
        );
      } else {
        input.writeLines(
          anthropicMessagesTransformer.serializeUpstreamFinalAsStream(
            payload,
            input.modelName,
            fallbackText,
            streamContext,
            claudeContext,
          ),
        );
      }
      finalize();
      response?.end();
      return terminalResult;
    },
    async run(reader: StreamReader | null | undefined, response: ResponseSink): Promise<ChatProxyStreamResult> {
      const lifecycle = createProxyStreamLifecycle<ParsedSseEvent>({
        reader,
        response,
        pullEvents: (buffer) => downstreamTransformer.pullSseEvents(buffer),
        handleEvent: handleEventBlock,
        onEof: finalize,
      });
      await lifecycle.run();
      return terminalResult;
    },
  };
}
