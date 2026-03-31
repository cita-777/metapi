import { openAiResponsesTransformer } from '../../transformers/openai/responses/index.js';
import { mergeProxyUsage, parseProxyUsage } from '../../services/proxyUsageParser.js';
import { readRuntimeResponseText } from '../../proxy-core/executors/types.js';

type ResponsesTerminalStatus = 'completed' | 'incomplete';

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object';
}

function asTrimmedString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
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

function hasMeaningfulMessageContent(content: unknown): boolean {
  if (!Array.isArray(content)) return false;
  return content.some((part) => {
    if (!isRecord(part)) return false;
    const partType = typeof part.type === 'string' ? part.type.trim().toLowerCase() : '';
    if (partType === 'output_text' || partType === 'text') {
      return typeof part.text === 'string' && part.text.length > 0;
    }
    return true;
  });
}

function hasMeaningfulResponsesOutput(output: unknown): boolean {
  if (!Array.isArray(output)) return false;
  return output.some((item) => {
    if (!isRecord(item)) return false;
    const itemType = typeof item.type === 'string' ? item.type.trim().toLowerCase() : '';
    if (itemType === 'message') {
      return hasMeaningfulMessageContent(item.content);
    }
    if (itemType === 'reasoning') {
      return (
        (Array.isArray(item.summary) && item.summary.length > 0)
        || (typeof item.encrypted_content === 'string' && item.encrypted_content.trim().length > 0)
      );
    }
    return itemType.length > 0;
  });
}

function hasCompleteFinalResponsesPayload(payload: Record<string, unknown>): boolean {
  return (
    payload.object === 'response.compaction'
    || Array.isArray(payload.output)
    || Object.prototype.hasOwnProperty.call(payload, 'output_text')
  );
}

function hasMeaningfulFinalResponsesPayload(payload: Record<string, unknown>): boolean {
  if (payload.object === 'response.compaction') {
    return Array.isArray(payload.output) && payload.output.length > 0;
  }
  if (typeof payload.output_text === 'string' && payload.output_text.length > 0) {
    return true;
  }
  return hasMeaningfulResponsesOutput(payload.output);
}

function collectResponsesOutputText(payload: Record<string, unknown>): string {
  const output = Array.isArray(payload.output) ? payload.output : [];
  const parts: string[] = [];

  for (const item of output) {
    if (!isRecord(item)) continue;
    if (asTrimmedString(item.type).toLowerCase() !== 'message') continue;
    const content = Array.isArray(item.content) ? item.content : [];
    for (const part of content) {
      if (!isRecord(part)) continue;
      const partType = asTrimmedString(part.type).toLowerCase();
      const text = typeof part.text === 'string' ? part.text : '';
      if ((partType === 'output_text' || partType === 'text') && text) {
        parts.push(text);
      }
    }
  }

  return parts.join('');
}

function rememberStreamResponseEnvelope(
  streamContext: ReturnType<typeof openAiResponsesTransformer.createStreamContext>,
  payload: Record<string, unknown>,
): void {
  const responsePayload = isRecord(payload.response) ? payload.response : payload;
  if (typeof responsePayload.id === 'string' && responsePayload.id.trim().length > 0) {
    streamContext.id = responsePayload.id;
  }
  if (typeof responsePayload.model === 'string' && responsePayload.model.trim().length > 0) {
    streamContext.model = responsePayload.model;
  }
  const createdAt = (
    typeof responsePayload.created_at === 'number' && Number.isFinite(responsePayload.created_at)
      ? responsePayload.created_at
      : (typeof responsePayload.created === 'number' && Number.isFinite(responsePayload.created)
        ? responsePayload.created
        : null)
  );
  if (createdAt !== null) {
    streamContext.created = createdAt;
  }
}

function ensureResponseId(rawId: string): string {
  const trimmed = rawId.trim() || `resp_${Date.now()}`;
  return trimmed.startsWith('resp_') ? trimmed : `resp_${trimmed}`;
}

function buildUsagePayload(usage: ReturnType<typeof parseProxyUsage>): Record<string, unknown> {
  const payload: Record<string, unknown> = {
    input_tokens: usage.promptTokens,
    output_tokens: usage.completionTokens,
    total_tokens: usage.totalTokens,
  };
  const inputDetails: Record<string, unknown> = {};
  if ((usage.cacheReadTokens || 0) > 0) inputDetails.cached_tokens = usage.cacheReadTokens;
  if ((usage.cacheCreationTokens || 0) > 0) inputDetails.cache_creation_tokens = usage.cacheCreationTokens;
  if (Object.keys(inputDetails).length > 0) payload.input_tokens_details = inputDetails;
  return payload;
}

function cloneAggregateOutputItem(
  item: unknown,
  terminalStatus: ResponsesTerminalStatus,
): Record<string, unknown> | null {
  if (!isRecord(item)) return null;
  const next = structuredClone(item);
  const currentStatus = asTrimmedString(next.status).toLowerCase();
  next.status = currentStatus && currentStatus !== 'in_progress'
    ? currentStatus
    : terminalStatus;
  return next;
}

function materializeTerminalPayloadFromAggregate(
  aggregateState: ReturnType<typeof openAiResponsesTransformer.aggregator.createState>,
  streamContext: ReturnType<typeof openAiResponsesTransformer.createStreamContext>,
  usage: ReturnType<typeof parseProxyUsage>,
  terminalStatus: ResponsesTerminalStatus,
): Record<string, unknown> {
  const output = aggregateState.outputItems
    .map((item) => cloneAggregateOutputItem(item, terminalStatus))
    .filter((item): item is Record<string, unknown> => !!item);
  const usagePayload = buildUsagePayload(usage);
  const usageWithExtras = Object.keys(aggregateState.usageExtras).length > 0
    ? { ...usagePayload, ...structuredClone(aggregateState.usageExtras) }
    : usagePayload;

  return {
    id: ensureResponseId(
      asTrimmedString(aggregateState.responseId)
      || asTrimmedString(streamContext.id)
      || asTrimmedString(aggregateState.modelName),
    ),
    object: 'response',
    created_at: (
      typeof aggregateState.createdAt === 'number' && Number.isFinite(aggregateState.createdAt)
        ? aggregateState.createdAt
        : streamContext.created
    ) || Math.floor(Date.now() / 1000),
    status: terminalStatus,
    model: asTrimmedString(streamContext.model) || asTrimmedString(aggregateState.modelName),
    output,
    output_text: collectResponsesOutputText({ output }),
    usage: usageWithExtras,
  };
}

function enrichTerminalPayload(
  payload: Record<string, unknown>,
  aggregateState: ReturnType<typeof openAiResponsesTransformer.aggregator.createState>,
  streamContext: ReturnType<typeof openAiResponsesTransformer.createStreamContext>,
  usage: ReturnType<typeof parseProxyUsage>,
  terminalStatus: ResponsesTerminalStatus,
): Record<string, unknown> {
  const next = structuredClone(payload);
  const materialized = materializeTerminalPayloadFromAggregate(
    aggregateState,
    streamContext,
    usage,
    terminalStatus,
  );

  if (!hasMeaningfulResponsesOutput(next.output) && materialized && hasMeaningfulResponsesOutput(materialized.output)) {
    next.output = materialized.output;
  }

  const currentOutputText = typeof next.output_text === 'string' ? next.output_text : '';
  if (!currentOutputText) {
    const derivedOutputText = collectResponsesOutputText(next)
      || (materialized && typeof materialized.output_text === 'string' ? materialized.output_text : '');
    if (derivedOutputText) {
      next.output_text = derivedOutputText;
    }
  }

  if (materialized && next.usage === undefined && materialized.usage !== undefined) {
    next.usage = materialized.usage;
  }

  return next;
}

function mergeMissingResponsesTerminalFields(
  payload: Record<string, unknown>,
  fallbackPayload: Record<string, unknown> | null,
): Record<string, unknown> {
  if (!fallbackPayload) return payload;
  const merged = { ...payload };
  if (merged.output === undefined && fallbackPayload.output !== undefined) {
    merged.output = fallbackPayload.output;
  }
  if (
    (typeof merged.output_text !== 'string' || merged.output_text.length === 0)
    && typeof fallbackPayload.output_text === 'string'
    && fallbackPayload.output_text.length > 0
  ) {
    merged.output_text = fallbackPayload.output_text;
  }
  if (merged.object === undefined && fallbackPayload.object !== undefined) {
    merged.object = fallbackPayload.object;
  }
  if (merged.created_at === undefined && fallbackPayload.created_at !== undefined) {
    merged.created_at = fallbackPayload.created_at;
  }
  if (merged.usage === undefined && fallbackPayload.usage !== undefined) {
    merged.usage = fallbackPayload.usage;
  }
  return merged;
}

export function looksLikeResponsesSseText(rawText: string): boolean {
  const { events, rest } = openAiResponsesTransformer.pullSseEvents(rawText);
  if (events.length === 0 || rest.trim().length > 0) return false;
  return events.some((event) => {
    if (event.data === '[DONE]') return true;
    if (event.event === 'error' || event.event.startsWith('response.')) return true;
    const payload = parseResponsesSsePayload(event.data);
    const payloadType = typeof payload?.type === 'string' ? payload.type : '';
    return payloadType === 'error' || payloadType.startsWith('response.');
  });
}

export function createSingleChunkStreamReader(rawText: string): {
  read(): Promise<{ done: boolean; value?: Uint8Array }>;
  cancel(reason?: unknown): Promise<unknown>;
  releaseLock(): void;
} {
  const chunk = Buffer.from(rawText, 'utf8');
  let done = false;
  return {
    async read() {
      if (done) return { done: true };
      done = true;
      return { done: false, value: chunk };
    },
    async cancel() {
      done = true;
      return undefined;
    },
    releaseLock() {},
  };
}

export function collectResponsesFinalPayloadFromSseText(
  rawText: string,
  modelName: string,
): { payload: Record<string, unknown>; rawText: string } {
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
  let terminalStatus: ResponsesTerminalStatus = 'completed';

  const captureCompletedPayloadFromEvent = (
    eventType: string,
    payload: Record<string, unknown>,
  ) => {
    if (completedPayload) return;
    if (eventType === 'response.failed' || eventType === 'error') {
      throw new Error(getResponsesFailureMessage(payload));
    }
    if (eventType !== 'response.completed' && eventType !== 'response.incomplete') {
      return;
    }
    terminalStatus = eventType === 'response.incomplete' ? 'incomplete' : 'completed';
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
    rememberStreamResponseEnvelope(streamContext, payload);
    usage = mergeProxyUsage(usage, parseProxyUsage(payload));
    captureCompletedPayloadFromEvent(eventType, payload);
    if (completedPayload) {
      continue;
    }
    const normalizedEvent = openAiResponsesTransformer.transformStreamEvent(
      payload,
      streamContext,
      modelName,
    );
    captureCompletedPayloadFromLines(openAiResponsesTransformer.aggregator.serialize({
      state: aggregateState,
      streamContext,
      event: normalizedEvent,
      usage,
    }));
  }

  if (
    completedPayload
    && !hasMeaningfulFinalResponsesPayload(completedPayload)
    && hasMeaningfulResponsesOutput(aggregateState.outputItems)
  ) {
    completedPayload = mergeMissingResponsesTerminalFields(
      completedPayload,
      materializeTerminalPayloadFromAggregate(
        aggregateState,
        streamContext,
        usage,
        terminalStatus,
      ),
    );
  }

  if (completedPayload) {
    completedPayload = mergeMissingResponsesTerminalFields(
      completedPayload,
      materializeTerminalPayloadFromAggregate(
        aggregateState,
        streamContext,
        usage,
        terminalStatus,
      ),
    );
  }

  if (!completedPayload) {
    const materialized = materializeTerminalPayloadFromAggregate(
      aggregateState,
      streamContext,
      usage,
      terminalStatus,
    );
    if (materialized) {
      completedPayload = materialized;
    }
  }

  if (completedPayload) {
    return {
      payload: enrichTerminalPayload(
        completedPayload,
        aggregateState,
        streamContext,
        usage,
        terminalStatus,
      ),
      rawText,
    };
  }

  throw new Error('stream disconnected before terminal responses event');
}

export async function collectResponsesFinalPayloadFromSse(
  upstream: { text(): Promise<string>; headers?: { get(name: string): string | null } },
  modelName: string,
): Promise<{ payload: Record<string, unknown>; rawText: string }> {
  const rawText = typeof upstream.headers?.get === 'function'
    ? await readRuntimeResponseText(upstream as Parameters<typeof readRuntimeResponseText>[0])
    : await upstream.text();
  return collectResponsesFinalPayloadFromSseText(rawText, modelName);
}
