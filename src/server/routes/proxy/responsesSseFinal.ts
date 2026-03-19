import { openAiResponsesTransformer } from '../../transformers/openai/responses/index.js';
import { mergeProxyUsage, parseProxyUsage } from '../../services/proxyUsageParser.js';

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object';
}

function parseResponsesSsePayload(data: string): Record<string, unknown> | null {
  try {
    const parsed = JSON.parse(data);
    return isRecord(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function getResponsesFailureMessage(payload: Record<string, unknown>): string {
  if (isRecord(payload.error) && typeof payload.error.message === 'string' && payload.error.message.trim()) {
    return payload.error.message.trim();
  }
  if (typeof payload.message === 'string' && payload.message.trim()) {
    return payload.message.trim();
  }
  return 'upstream stream failed';
}

function hasCompleteFinalResponsesPayload(payload: Record<string, unknown>): boolean {
  return (
    payload.object === 'response.compaction'
    || Array.isArray(payload.output)
    || Object.prototype.hasOwnProperty.call(payload, 'output_text')
  );
}

export async function collectResponsesFinalPayloadFromSse(
  upstream: { text(): Promise<string> },
  modelName: string,
): Promise<{ payload: Record<string, unknown>; rawText: string }> {
  const rawText = await upstream.text();
  const { events } = openAiResponsesTransformer.pullSseEvents(rawText);
  const streamContext = openAiResponsesTransformer.createStreamContext(modelName);
  const aggregateState = openAiResponsesTransformer.aggregator.createState(modelName);
  let usage = {
    promptTokens: 0,
    completionTokens: 0,
    totalTokens: 0,
    cacheReadTokens: 0,
    cacheCreationTokens: 0,
    promptTokensIncludeCache: null as boolean | null,
  };
  let completedPayload: Record<string, unknown> | null = null;

  const captureCompletedPayloadFromEvent = (
    eventType: string,
    payload: Record<string, unknown>,
  ) => {
    if (completedPayload) return;
    if (eventType === 'response.failed' || eventType === 'response.incomplete' || eventType === 'error') {
      throw new Error(getResponsesFailureMessage(payload));
    }
    if (eventType !== 'response.completed') {
      return;
    }
    if (isRecord(payload.response) && hasCompleteFinalResponsesPayload(payload.response)) {
      completedPayload = payload.response;
      return;
    }
    if (hasCompleteFinalResponsesPayload(payload)) {
      completedPayload = payload;
    }
  };

  const captureCompletedPayloadFromLines = (lines: string[]) => {
    if (completedPayload) return;
    const parsed = openAiResponsesTransformer.pullSseEvents(lines.join(''));
    for (const event of parsed.events) {
      if (event.data === '[DONE]') continue;
      const payload = parseResponsesSsePayload(event.data);
      if (!payload) continue;
      const payloadType = typeof payload.type === 'string' ? payload.type : '';
      captureCompletedPayloadFromEvent(payloadType || event.event, payload);
      if (completedPayload) {
        return;
      }
    }
  };

  for (const event of events) {
    if (event.data === '[DONE]') continue;
    const payload = parseResponsesSsePayload(event.data);
    if (!payload) continue;

    const payloadType = typeof payload.type === 'string' ? payload.type : '';
    const eventType = payloadType || event.event;
    usage = mergeProxyUsage(usage, parseProxyUsage(payload));
    captureCompletedPayloadFromEvent(eventType, payload);
    if (completedPayload) {
      continue;
    }
    const normalizedEvent = openAiResponsesTransformer.transformStreamEvent(payload, streamContext, modelName);
    captureCompletedPayloadFromLines(openAiResponsesTransformer.aggregator.serialize({
      state: aggregateState,
      streamContext,
      event: normalizedEvent,
      usage,
    }));
  }

  if (!completedPayload) {
    captureCompletedPayloadFromLines(openAiResponsesTransformer.aggregator.complete(
      aggregateState,
      streamContext,
      usage,
    ));
  }

  if (completedPayload) {
    return {
      payload: completedPayload,
      rawText,
    };
  }

  throw new Error('stream disconnected before response.completed');
}
