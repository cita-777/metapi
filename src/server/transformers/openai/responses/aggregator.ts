import { type StreamTransformContext } from '../../shared/normalized.js';
import type { OpenAiResponsesStreamEvent } from './stream.js';

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function asTrimmedString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function cloneRecord(value: unknown): Record<string, unknown> | null {
  if (!isRecord(value)) return null;
  return { ...value };
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

function ensureOutputItemId(rawId: string, prefix: string, index: number): string {
  const trimmed = rawId.trim();
  if (trimmed) return trimmed;
  return `${prefix}_${index}`;
}

function serializeSse(event: string, payload: unknown): string {
  return `event: ${event}\ndata: ${JSON.stringify(payload)}\n\n`;
}

function serializeDone(): string {
  return 'data: [DONE]\n\n';
}

type ResponsesUsageSummary = {
  promptTokens: number;
  completionTokens: number;
  totalTokens: number;
  cacheReadTokens?: number;
  cacheCreationTokens?: number;
  promptTokensIncludeCache?: boolean | null;
};

type AggregateOutputItem = Record<string, unknown>;
type AggregateOutputMetaCarrier = AggregateOutputItem & { [key: symbol]: true | undefined };

const outputTextDoneMarker = Symbol('responses.output_text.done');
const contentPartDoneMarker = Symbol('responses.content_part.done');
const reasoningSummaryTextDoneMarker = Symbol('responses.reasoning_summary_text.done');
const reasoningSummaryPartDoneMarker = Symbol('responses.reasoning_summary_part.done');
const functionCallArgumentsDoneMarker = Symbol('responses.function_call_arguments.done');
const customToolInputDoneMarker = Symbol('responses.custom_tool_call_input.done');
const outputItemDoneMarker = Symbol('responses.output_item.done');

export type OpenAiResponsesAggregateState = {
  modelName: string;
  responseId: string | null;
  createdAt: number | null;
  outputItems: Array<AggregateOutputItem | undefined>;
  outputIndexById: Record<string, number>;
  messageIndex: number | null;
  reasoningIndexById: Record<string, number>;
  functionIndexById: Record<string, number>;
  customToolIndexById: Record<string, number>;
  imageGenerationIndexById: Record<string, number>;
  usageExtras: Record<string, unknown>;
  completed: boolean;
  failed: boolean;
  incomplete: boolean;
};

export function createOpenAiResponsesAggregateState(modelName: string): OpenAiResponsesAggregateState {
  return {
    modelName,
    responseId: null,
    createdAt: null,
    outputItems: [],
    outputIndexById: {},
    messageIndex: null,
    reasoningIndexById: {},
    functionIndexById: {},
    customToolIndexById: {},
    imageGenerationIndexById: {},
    usageExtras: {},
    completed: false,
    failed: false,
    incomplete: false,
  };
}

function markTerminalMarker(item: AggregateOutputItem, marker: symbol): void {
  (item as AggregateOutputMetaCarrier)[marker] = true;
}

function hasTerminalMarker(item: AggregateOutputItem, marker: symbol): boolean {
  return (item as AggregateOutputMetaCarrier)[marker] === true;
}

function mergeUsageExtras(
  state: OpenAiResponsesAggregateState,
  usagePayload: unknown,
): void {
  if (!isRecord(usagePayload)) return;
  for (const [key, value] of Object.entries(usagePayload)) {
    if (key === 'input_tokens' || key === 'output_tokens' || key === 'total_tokens') continue;
    state.usageExtras[key] = cloneJson(value);
  }
}

function rememberOutputId(state: OpenAiResponsesAggregateState, index: number, item: AggregateOutputItem) {
  const itemId = asTrimmedString(item.id);
  if (itemId) {
    state.outputIndexById[itemId] = index;
  }
  const itemType = asTrimmedString(item.type).toLowerCase();
  const callId = asTrimmedString(item.call_id);
  if (itemType === 'function_call') {
    if (callId) state.functionIndexById[callId] = index;
    if (itemId) state.functionIndexById[itemId] = index;
  }
  if (itemType === 'custom_tool_call') {
    if (callId) state.customToolIndexById[callId] = index;
    if (itemId) state.customToolIndexById[itemId] = index;
  }
  if (itemType === 'image_generation_call' && itemId) {
    state.imageGenerationIndexById[itemId] = index;
  }
  if (itemType === 'reasoning' && itemId) {
    state.reasoningIndexById[itemId] = index;
  }
  if (itemType === 'message' && state.messageIndex === null) {
    state.messageIndex = index;
  }
}

function preserveTerminalMarkers(source: AggregateOutputItem | undefined, target: AggregateOutputItem): void {
  if (!isRecord(source)) return;

  const itemMarkers = [
    outputItemDoneMarker,
    functionCallArgumentsDoneMarker,
    customToolInputDoneMarker,
  ];
  for (const marker of itemMarkers) {
    if (hasTerminalMarker(source, marker)) {
      markTerminalMarker(target, marker);
    }
  }

  const sourceContent = Array.isArray(source.content) ? source.content : [];
  const targetContent = Array.isArray(target.content) ? target.content : [];
  for (let index = 0; index < Math.min(sourceContent.length, targetContent.length); index += 1) {
    const sourcePart = sourceContent[index];
    const targetPart = targetContent[index];
    if (!isRecord(sourcePart) || !isRecord(targetPart)) continue;
    if (hasTerminalMarker(sourcePart, outputTextDoneMarker)) {
      markTerminalMarker(targetPart, outputTextDoneMarker);
    }
    if (hasTerminalMarker(sourcePart, contentPartDoneMarker)) {
      markTerminalMarker(targetPart, contentPartDoneMarker);
    }
  }

  const sourceSummary = Array.isArray(source.summary) ? source.summary : [];
  const targetSummary = Array.isArray(target.summary) ? target.summary : [];
  for (let index = 0; index < Math.min(sourceSummary.length, targetSummary.length); index += 1) {
    const sourcePart = sourceSummary[index];
    const targetPart = targetSummary[index];
    if (!isRecord(sourcePart) || !isRecord(targetPart)) continue;
    if (hasTerminalMarker(sourcePart, reasoningSummaryTextDoneMarker)) {
      markTerminalMarker(targetPart, reasoningSummaryTextDoneMarker);
    }
    if (hasTerminalMarker(sourcePart, reasoningSummaryPartDoneMarker)) {
      markTerminalMarker(targetPart, reasoningSummaryPartDoneMarker);
    }
  }
}

function isTerminalStatus(value: unknown): boolean {
  const status = asTrimmedString(value).toLowerCase();
  return status === 'completed' || status === 'failed' || status === 'incomplete';
}

function isOutputItemType(item: unknown, expectedType: string): boolean {
  return isRecord(item) && asTrimmedString(item.type).toLowerCase() === expectedType;
}

function resolveCompatibleOutputIndex(
  state: OpenAiResponsesAggregateState,
  expectedType: string,
  rawIndex: unknown,
  ...candidateIds: Array<unknown>
): number {
  const resolved = resolveOutputIndex(state, rawIndex, ...candidateIds);
  const existing = state.outputItems[resolved];
  if (!existing || isOutputItemType(existing, expectedType)) return resolved;
  return state.outputItems.length;
}

function snapshotOutputItemForAdded(item: AggregateOutputItem): AggregateOutputItem {
  const next = cloneJson(item);
  const itemType = asTrimmedString(next.type).toLowerCase();

  if (itemType === 'message') {
    next.content = [];
  } else if (itemType === 'reasoning') {
    next.summary = [];
  } else if (itemType === 'function_call') {
    next.arguments = '';
  } else if (itemType === 'custom_tool_call') {
    next.input = '';
  } else if (itemType === 'image_generation_call') {
    next.result = null;
    next.partial_images = [];
  }

  next.status = 'in_progress';
  return next;
}

function serializeOutputItemAdded(index: number, item: AggregateOutputItem): string {
  return serializeSse('response.output_item.added', {
    type: 'response.output_item.added',
    output_index: index,
    item: snapshotOutputItemForAdded(item),
  });
}

function snapshotPartForAdded(part: AggregateOutputItem): AggregateOutputItem {
  const next = cloneJson(part);
  const partType = asTrimmedString(next.type).toLowerCase();
  if (
    (partType === 'output_text' || partType === 'text' || partType === 'summary_text')
    && typeof next.text === 'string'
  ) {
    next.text = '';
  }
  return next;
}

function serializeContentPartAdded(
  outputIndex: number,
  itemId: string,
  contentIndex: number,
  part: AggregateOutputItem,
): string {
  return serializeSse('response.content_part.added', {
    type: 'response.content_part.added',
    output_index: outputIndex,
    item_id: itemId,
    content_index: contentIndex,
    part: snapshotPartForAdded(part),
  });
}

function serializeReasoningSummaryPartAdded(
  outputIndex: number,
  itemId: string,
  summaryIndex: number,
  part: AggregateOutputItem,
): string {
  return serializeSse('response.reasoning_summary_part.added', {
    type: 'response.reasoning_summary_part.added',
    item_id: itemId,
    output_index: outputIndex,
    summary_index: summaryIndex,
    part: snapshotPartForAdded(part),
  });
}

function setOutputItem(
  state: OpenAiResponsesAggregateState,
  index: number,
  item: AggregateOutputItem,
): AggregateOutputItem {
  const existing = isRecord(state.outputItems[index]) ? state.outputItems[index] as AggregateOutputItem : undefined;
  const current = cloneRecord(state.outputItems[index]) || {};
  const incoming = cloneJson(item);
  const next = {
    ...current,
    ...incoming,
  };
  if (Array.isArray(current.summary) && (!Array.isArray(incoming.summary) || incoming.summary.length <= 0)) {
    next.summary = current.summary;
  }
  if (Array.isArray(current.content) && (!Array.isArray(incoming.content) || incoming.content.length <= 0)) {
    next.content = current.content;
  }
  if (
    Array.isArray(current.partial_images)
    && (!Array.isArray(incoming.partial_images) || incoming.partial_images.length <= 0)
  ) {
    next.partial_images = current.partial_images;
  }
  preserveTerminalMarkers(existing, next);
  state.outputItems[index] = next;
  rememberOutputId(state, index, next);
  return next;
}

function ensureOutputItem(
  state: OpenAiResponsesAggregateState,
  index: number,
  factory: () => AggregateOutputItem,
): AggregateOutputItem {
  const existing = state.outputItems[index];
  if (existing) return existing;
  return setOutputItem(state, index, factory());
}

function resolveOutputIndex(
  state: OpenAiResponsesAggregateState,
  rawIndex: unknown,
  ...candidateIds: Array<unknown>
): number {
  if (typeof rawIndex === 'number' && Number.isFinite(rawIndex)) {
    return Math.max(0, Math.trunc(rawIndex));
  }
  for (const rawId of candidateIds) {
    const itemId = asTrimmedString(rawId);
    if (itemId && state.outputIndexById[itemId] !== undefined) {
      return state.outputIndexById[itemId];
    }
  }
  return state.outputItems.length;
}

function ensureMessageItem(
  state: OpenAiResponsesAggregateState,
  indexHint?: number,
  itemIdRaw?: unknown,
): { index: number; item: AggregateOutputItem; created: boolean } {
  const preferredIndex = state.messageIndex ?? indexHint ?? 0;
  const itemId = asTrimmedString(itemIdRaw);
  const index = resolveCompatibleOutputIndex(state, 'message', preferredIndex);
  const created = !state.outputItems[index];
  const item = ensureOutputItem(state, index, () => ({
    id: ensureOutputItemId(itemId, 'msg', index),
    type: 'message',
    role: 'assistant',
    status: 'in_progress',
    content: [],
  }));
  if (itemId) {
    item.id = ensureOutputItemId(itemId, 'msg', index);
    rememberOutputId(state, index, item);
  }
  if (!Array.isArray(item.content)) item.content = [];
  state.messageIndex = index;
  return { index, item, created };
}

function ensureMessageOutputTextPart(
  state: OpenAiResponsesAggregateState,
  indexHint?: number,
  itemIdRaw?: unknown,
): {
  index: number;
  item: AggregateOutputItem;
  part: AggregateOutputItem;
  created: boolean;
  itemCreated: boolean;
  partCreated: boolean;
} {
  const { index, item, created: itemCreated } = ensureMessageItem(state, indexHint, itemIdRaw);
  const content = Array.isArray(item.content) ? item.content as AggregateOutputItem[] : [];
  if (!Array.isArray(item.content)) item.content = content;
  let part = content[0];
  const partCreated = !isRecord(part) || asTrimmedString(part.type).toLowerCase() !== 'output_text';
  if (partCreated) {
    part = { type: 'output_text', text: '' };
    content[0] = part;
  }
  return { index, item, part, created: itemCreated || partCreated, itemCreated, partCreated };
}

function ensureReasoningItem(
  state: OpenAiResponsesAggregateState,
  itemIdRaw: unknown,
  indexHint?: unknown,
): { index: number; item: AggregateOutputItem; created: boolean } {
  const itemId = asTrimmedString(itemIdRaw);
  const existingIndex = itemId
    ? state.reasoningIndexById[itemId]
    : Object.values(state.reasoningIndexById)[0];
  const index = existingIndex !== undefined
    ? resolveCompatibleOutputIndex(state, 'reasoning', existingIndex, itemId)
    : resolveCompatibleOutputIndex(state, 'reasoning', indexHint, itemId);
  const created = !state.outputItems[index];
  const item = ensureOutputItem(state, index, () => ({
    id: ensureOutputItemId(itemId, 'rs', index),
    type: 'reasoning',
    status: 'in_progress',
    summary: [],
  }));
  if (!Array.isArray(item.summary)) item.summary = [];
  return { index, item, created };
}

function ensureReasoningSummaryPart(
  state: OpenAiResponsesAggregateState,
  itemIdRaw: unknown,
  summaryIndexRaw: unknown,
  indexHint?: unknown,
): {
  item: AggregateOutputItem;
  summary: AggregateOutputItem;
  index: number;
  summaryIndex: number;
  created: boolean;
  itemCreated: boolean;
  partCreated: boolean;
} {
  const reasoningState = ensureReasoningItem(state, itemIdRaw, indexHint);
  const summaryIndex = typeof summaryIndexRaw === 'number' && Number.isFinite(summaryIndexRaw)
    ? Math.max(0, Math.trunc(summaryIndexRaw))
    : 0;
  const summary = Array.isArray(reasoningState.item.summary) ? reasoningState.item.summary as AggregateOutputItem[] : [];
  if (!Array.isArray(reasoningState.item.summary)) reasoningState.item.summary = summary;
  let part = summary[summaryIndex];
  const partCreated = !isRecord(part);
  if (!isRecord(part)) {
    part = { type: 'summary_text', text: '' };
    summary[summaryIndex] = part;
  }
  return {
    item: reasoningState.item,
    summary: part,
    index: reasoningState.index,
    summaryIndex,
    created: reasoningState.created || partCreated,
    itemCreated: reasoningState.created,
    partCreated,
  };
}

function ensureFunctionCallItem(
  state: OpenAiResponsesAggregateState,
  callIdRaw: unknown,
  nameRaw: unknown,
  indexHint?: number,
): { index: number; item: AggregateOutputItem; created: boolean } {
  const callId = asTrimmedString(callIdRaw);
  const name = asTrimmedString(nameRaw);
  const existingIndex = callId ? state.functionIndexById[callId] : undefined;
  const index = existingIndex !== undefined
    ? resolveCompatibleOutputIndex(state, 'function_call', existingIndex, callId)
    : resolveCompatibleOutputIndex(state, 'function_call', indexHint, callId);
  const created = !state.outputItems[index];
  const item = ensureOutputItem(state, index, () => ({
    id: ensureOutputItemId(callId, 'fc', index),
    type: 'function_call',
    status: 'in_progress',
    call_id: ensureOutputItemId(callId, 'call', index),
    name,
    arguments: '',
  }));
  if (callId) item.call_id = ensureOutputItemId(callId, 'call', index);
  if (name) item.name = name;
  if (typeof item.arguments !== 'string') item.arguments = '';
  return { index, item, created };
}

function ensureCustomToolItem(
  state: OpenAiResponsesAggregateState,
  itemIdRaw: unknown,
  callIdRaw: unknown,
  nameRaw: unknown,
  indexHint?: number,
): { index: number; item: AggregateOutputItem; created: boolean } {
  const itemId = asTrimmedString(itemIdRaw);
  const callId = asTrimmedString(callIdRaw);
  const name = asTrimmedString(nameRaw);
  const existingIndex = (callId && state.customToolIndexById[callId] !== undefined)
    ? state.customToolIndexById[callId]
    : (itemId && state.customToolIndexById[itemId] !== undefined ? state.customToolIndexById[itemId] : undefined);
  const index = existingIndex !== undefined
    ? resolveCompatibleOutputIndex(state, 'custom_tool_call', existingIndex, itemId, callId)
    : resolveCompatibleOutputIndex(state, 'custom_tool_call', indexHint, itemId, callId);
  const created = !state.outputItems[index];
  const item = ensureOutputItem(state, index, () => ({
    id: ensureOutputItemId(itemId, 'ct', index),
    type: 'custom_tool_call',
    status: 'in_progress',
    call_id: ensureOutputItemId(callId || itemId, 'call', index),
    name,
    input: '',
  }));
  if (callId || itemId) item.call_id = ensureOutputItemId(callId || itemId, 'call', index);
  if (name) item.name = name;
  if (typeof item.input !== 'string') item.input = '';
  return { index, item, created };
}

function ensureImageGenerationItem(
  state: OpenAiResponsesAggregateState,
  itemIdRaw: unknown,
  indexHint?: number,
): { index: number; item: AggregateOutputItem; created: boolean } {
  const itemId = asTrimmedString(itemIdRaw);
  const existingIndex = itemId ? state.imageGenerationIndexById[itemId] : undefined;
  const index = existingIndex !== undefined
    ? resolveCompatibleOutputIndex(state, 'image_generation_call', existingIndex, itemId)
    : resolveCompatibleOutputIndex(state, 'image_generation_call', indexHint, itemId);
  const created = !state.outputItems[index];
  const item = ensureOutputItem(state, index, () => ({
    id: ensureOutputItemId(itemId, 'img', index),
    type: 'image_generation_call',
    status: 'in_progress',
    result: null,
    partial_images: [],
  }));
  if (!Array.isArray(item.partial_images)) item.partial_images = [];
  return { index, item, created };
}

function buildUsagePayload(usage: ResponsesUsageSummary): Record<string, unknown> {
  const payload: Record<string, unknown> = {
    input_tokens: usage.promptTokens,
    output_tokens: usage.completionTokens,
    total_tokens: usage.totalTokens,
  };
  const inputDetails: Record<string, unknown> = {};
  if ((usage.cacheReadTokens || 0) > 0) inputDetails.cached_tokens = usage.cacheReadTokens;
  if ((usage.cacheCreationTokens || 0) > 0) inputDetails.cache_creation_tokens = usage.cacheCreationTokens;
  if (Object.keys(inputDetails).length > 0) payload.input_tokens_details = inputDetails;
  return {
    ...payload,
  };
}

function collectOutputText(state: OpenAiResponsesAggregateState): string {
  const parts: string[] = [];
  for (const item of state.outputItems) {
    if (!isRecord(item)) continue;
    if (asTrimmedString(item.type).toLowerCase() !== 'message') continue;
    const content = Array.isArray(item.content) ? item.content : [];
    for (const part of content) {
      if (!isRecord(part)) continue;
      const type = asTrimmedString(part.type).toLowerCase();
      if ((type === 'output_text' || type === 'text') && typeof part.text === 'string' && part.text) {
        parts.push(part.text);
      }
    }
  }
  return parts.join('');
}

function hydrateStateFromTerminalResponseOutput(
  state: OpenAiResponsesAggregateState,
  responsePayload: Record<string, unknown> | null | undefined,
): void {
  if (!isRecord(responsePayload) || !Array.isArray(responsePayload.output)) return;

  for (let index = 0; index < responsePayload.output.length; index += 1) {
    const item = responsePayload.output[index];
    if (!isRecord(item)) continue;
    const itemType = asTrimmedString(item.type).toLowerCase();
    if (!itemType) continue;
    const resolvedIndex = resolveCompatibleOutputIndex(
      state,
      itemType,
      index,
      item.id,
      item.call_id,
    );
    setOutputItem(state, resolvedIndex, cloneJson(item));
  }
}

function materializeResponse(
  state: OpenAiResponsesAggregateState,
  streamContext: StreamTransformContext,
  usage: ResponsesUsageSummary,
  responseTemplate?: Record<string, unknown> | null,
  statusOverride?: 'completed' | 'failed' | 'incomplete',
): Record<string, unknown> {
  const base = cloneRecord(responseTemplate) || {};
  const responseId = ensureResponseId(
    asTrimmedString(base.id)
    || state.responseId
    || streamContext.id
    || state.modelName,
  );
  const createdAt = (
    typeof base.created_at === 'number' && Number.isFinite(base.created_at)
      ? base.created_at
      : (typeof base.created === 'number' && Number.isFinite(base.created) ? base.created : null)
  ) ?? state.createdAt ?? Math.floor(Date.now() / 1000);
  const aggregatedOutput = state.outputItems
    .filter((item): item is AggregateOutputItem => isRecord(item))
    .map((item) => {
      const status = asTrimmedString(item.status).toLowerCase();
      return {
        ...item,
        status: status && status !== 'in_progress'
          ? status
          : (state.failed ? 'failed' : state.incomplete ? 'incomplete' : 'completed'),
      };
    });
  const output = aggregatedOutput.length > 0
    ? aggregatedOutput
    : (Array.isArray(base.output) ? cloneJson(base.output) : []);
  const outputText = collectOutputText(state)
    || (typeof base.output_text === 'string' ? base.output_text : '');

  return {
    ...base,
    id: responseId,
    object: 'response',
    created_at: createdAt,
    status: statusOverride ?? (state.failed ? 'failed' : state.incomplete ? 'incomplete' : 'completed'),
    model: asTrimmedString(base.model) || streamContext.model || state.modelName,
    output,
    output_text: outputText,
    usage: buildUsagePayload(usage),
    ...Object.keys(state.usageExtras).length > 0 ? { usage: { ...buildUsagePayload(usage), ...state.usageExtras } } : {},
  };
}

function serializeOriginalResponsesEvent(eventType: string, payload: Record<string, unknown>): string[] {
  return [serializeSse(eventType, payload)];
}

function mergeImageGenerationFields(
  item: AggregateOutputItem,
  payload: Record<string, unknown>,
): void {
  const passthroughKeys = [
    'background',
    'output_format',
    'quality',
    'size',
    'revised_prompt',
    'mime_type',
  ] as const;

  for (const key of passthroughKeys) {
    if (payload[key] !== undefined) {
      item[key] = cloneJson(payload[key]);
    }
  }
}

function computeNovelDelta(existingText: string, incomingDelta: string): string {
  const replayWindowMinLength = 24;
  if (!incomingDelta) return '';
  if (!existingText) return incomingDelta;
  if (existingText.endsWith(incomingDelta)) {
    return incomingDelta.length >= replayWindowMinLength ? '' : incomingDelta;
  }
  if (incomingDelta.startsWith(existingText)) {
    return incomingDelta.slice(existingText.length);
  }
  if (
    incomingDelta.length >= replayWindowMinLength
    && existingText.includes(incomingDelta)
  ) {
    return '';
  }

  const maxOverlap = Math.min(existingText.length, incomingDelta.length);
  for (let overlap = maxOverlap; overlap > 0; overlap -= 1) {
    if (existingText.slice(-overlap) === incomingDelta.slice(0, overlap)) {
      return incomingDelta.slice(overlap);
    }
  }
  return incomingDelta;
}

function applyOriginalResponsesPayload(
  state: OpenAiResponsesAggregateState,
  eventType: string,
  payload: Record<string, unknown>,
  streamContext: StreamTransformContext,
  usage: ResponsesUsageSummary,
): string[] {
  switch (eventType) {
    case 'response.output_item.added':
    case 'response.output_item.done': {
      const outputIndex = resolveOutputIndex(state, payload.output_index, (payload.item as Record<string, unknown> | undefined)?.id);
      const item = cloneRecord(payload.item) || {};
      if (Object.keys(item).length > 0) {
        const itemType = asTrimmedString(item.type).toLowerCase();
        if (itemType === 'reasoning') {
          const reasoningState = ensureReasoningItem(state, item.id, outputIndex);
          const preservedSummary = (
            (!Array.isArray(item.summary) || item.summary.length === 0) && Array.isArray(reasoningState.item.summary)
          )
            ? reasoningState.item.summary
            : null;
          const next = {
            ...reasoningState.item,
            ...item,
          };
          if (eventType === 'response.output_item.done' && !asTrimmedString(next.status)) {
            next.status = 'completed';
          }
          if (preservedSummary) {
            next.summary = preservedSummary;
          }
          const stored = setOutputItem(state, reasoningState.index, next);
          if (preservedSummary) {
            stored.summary = preservedSummary;
          }
          if (eventType === 'response.output_item.done') {
            markTerminalMarker(stored, outputItemDoneMarker);
          }
          return [
            ...(eventType === 'response.output_item.done' ? buildMissingSubordinateDoneEventsForItem(stored, reasoningState.index) : []),
            ...serializeOriginalResponsesEvent(eventType, {
              ...payload,
              output_index: reasoningState.index,
              item: state.outputItems[reasoningState.index] ?? payload.item,
            }),
          ];
        }
        const existing = isRecord(state.outputItems[outputIndex]) ? cloneRecord(state.outputItems[outputIndex]) || {} : {};
        const next = {
          ...existing,
          ...item,
        };
        if (eventType === 'response.output_item.done' && !asTrimmedString(next.status)) {
          next.status = 'completed';
        }
        const preservedContent = (
          (!Array.isArray(item.content) || item.content.length === 0) && Array.isArray(existing.content)
        )
          ? existing.content
          : null;
        const preservedSummary = (
          (!Array.isArray(item.summary) || item.summary.length === 0) && Array.isArray(existing.summary)
        )
          ? existing.summary
          : null;
        const preservedPartialImages = (
          (!Array.isArray(item.partial_images) || item.partial_images.length === 0) && Array.isArray(existing.partial_images)
        )
          ? existing.partial_images
          : null;
        if (preservedContent) next.content = preservedContent;
        if (preservedSummary) next.summary = preservedSummary;
        if (preservedPartialImages) next.partial_images = preservedPartialImages;
        const stored = setOutputItem(state, outputIndex, next);
        if (preservedContent) stored.content = preservedContent;
        if (preservedSummary) stored.summary = preservedSummary;
        if (preservedPartialImages) stored.partial_images = preservedPartialImages;
        if (eventType === 'response.output_item.done') {
          markTerminalMarker(stored, outputItemDoneMarker);
        }
      }
      const stored = state.outputItems[outputIndex];
      return [
        ...(eventType === 'response.output_item.done' && isRecord(stored)
          ? buildMissingSubordinateDoneEventsForItem(stored, outputIndex)
          : []),
        ...serializeOriginalResponsesEvent(eventType, {
          ...payload,
          item: state.outputItems[outputIndex] ?? payload.item,
        }),
      ];
    }
    case 'response.content_part.added':
    case 'response.content_part.done': {
      const lines: string[] = [];
      const requestedOutputIndex = resolveCompatibleOutputIndex(state, 'message', payload.output_index, payload.item_id);
      const contentIndex = typeof payload.content_index === 'number' && Number.isFinite(payload.content_index)
        ? Math.max(0, Math.trunc(payload.content_index))
        : 0;
      const messageState = ensureMessageItem(state, requestedOutputIndex, payload.item_id);
      const message = messageState.item;
      if (messageState.created) {
        lines.push(serializeOutputItemAdded(messageState.index, message));
      }
      const content = Array.isArray(message.content) ? message.content as AggregateOutputItem[] : [];
      if (!Array.isArray(message.content)) message.content = content;
      const existingPart = isRecord(content[contentIndex]) ? content[contentIndex] as AggregateOutputItem : null;
      const incomingPart = cloneRecord(payload.part);
      const partCreated = !existingPart && !!incomingPart;
      if (incomingPart) {
        content[contentIndex] = existingPart
          ? {
            ...existingPart,
            ...incomingPart,
          }
          : incomingPart;
      }
      const part = isRecord(content[contentIndex]) ? content[contentIndex] as AggregateOutputItem : existingPart;
      if (eventType === 'response.content_part.done' && partCreated && part) {
        lines.push(serializeContentPartAdded(messageState.index, asTrimmedString(message.id), contentIndex, part));
      }
      if (eventType === 'response.content_part.done' && part) {
        markTerminalMarker(part, contentPartDoneMarker);
      }
      return [
        ...lines,
        ...serializeOriginalResponsesEvent(eventType, {
          ...payload,
          output_index: messageState.index,
          item_id: asTrimmedString(message.id) || payload.item_id,
        }),
      ];
    }
    case 'response.output_text.delta':
    case 'response.output_text.done': {
      const lines: string[] = [];
      const outputIndex = resolveCompatibleOutputIndex(state, 'message', payload.output_index, payload.item_id);
      const textPart = ensureMessageOutputTextPart(state, outputIndex, payload.item_id);
      if (textPart.itemCreated) {
        lines.push(serializeOutputItemAdded(textPart.index, textPart.item));
      }
      if (textPart.partCreated) {
        lines.push(serializeContentPartAdded(textPart.index, asTrimmedString(textPart.item.id), 0, textPart.part));
      }
      if (eventType === 'response.output_text.done') {
        textPart.part.text = typeof payload.text === 'string' ? payload.text : String(payload.text ?? '');
        markTerminalMarker(textPart.part, outputTextDoneMarker);
      } else {
        textPart.part.text = `${typeof textPart.part.text === 'string' ? textPart.part.text : ''}${typeof payload.delta === 'string' ? payload.delta : ''}`;
      }
      return [
        ...lines,
        ...serializeOriginalResponsesEvent(eventType, {
          ...payload,
          output_index: textPart.index,
          item_id: asTrimmedString(textPart.item.id) || payload.item_id,
        }),
      ];
    }
    case 'response.function_call_arguments.delta':
    case 'response.function_call_arguments.done': {
      const lines: string[] = [];
      const entry = ensureFunctionCallItem(
        state,
        payload.call_id ?? payload.item_id,
        payload.name,
        resolveCompatibleOutputIndex(state, 'function_call', payload.output_index, payload.item_id, payload.call_id),
      );
      if (entry.created) {
        lines.push(serializeOutputItemAdded(entry.index, entry.item));
      }
      if (eventType === 'response.function_call_arguments.done') {
        entry.item.arguments = typeof payload.arguments === 'string' ? payload.arguments : String(payload.arguments ?? '');
        markTerminalMarker(entry.item, functionCallArgumentsDoneMarker);
      } else {
        entry.item.arguments = `${typeof entry.item.arguments === 'string' ? entry.item.arguments : ''}${typeof payload.delta === 'string' ? payload.delta : ''}`;
      }
      return [
        ...lines,
        ...serializeOriginalResponsesEvent(eventType, {
          ...payload,
          output_index: entry.index,
          item_id: asTrimmedString(entry.item.id) || payload.item_id,
          call_id: asTrimmedString(entry.item.call_id) || payload.call_id,
          ...(asTrimmedString(entry.item.name) ? { name: entry.item.name } : {}),
        }),
      ];
    }
    case 'response.custom_tool_call_input.delta':
    case 'response.custom_tool_call_input.done': {
      const lines: string[] = [];
      const entry = ensureCustomToolItem(
        state,
        payload.item_id,
        payload.call_id,
        payload.name,
        resolveCompatibleOutputIndex(state, 'custom_tool_call', payload.output_index, payload.item_id, payload.call_id),
      );
      if (entry.created) {
        lines.push(serializeOutputItemAdded(entry.index, entry.item));
      }
      if (eventType === 'response.custom_tool_call_input.done') {
        entry.item.input = typeof payload.input === 'string' ? payload.input : String(payload.input ?? '');
        markTerminalMarker(entry.item, customToolInputDoneMarker);
      } else {
        entry.item.input = `${typeof entry.item.input === 'string' ? entry.item.input : ''}${typeof payload.delta === 'string' ? payload.delta : ''}`;
      }
      return [
        ...lines,
        ...serializeOriginalResponsesEvent(eventType, {
          ...payload,
          output_index: entry.index,
          item_id: asTrimmedString(entry.item.id) || payload.item_id,
          call_id: asTrimmedString(entry.item.call_id) || payload.call_id,
          ...(asTrimmedString(entry.item.name) ? { name: entry.item.name } : {}),
        }),
      ];
    }
    case 'response.reasoning_summary_part.added':
    case 'response.reasoning_summary_part.done': {
      const lines: string[] = [];
      const summaryState = ensureReasoningSummaryPart(state, payload.item_id, payload.summary_index, payload.output_index);
      if (summaryState.itemCreated) {
        lines.push(serializeOutputItemAdded(summaryState.index, summaryState.item));
      }
      if (summaryState.partCreated && eventType === 'response.reasoning_summary_part.done') {
        lines.push(serializeReasoningSummaryPartAdded(
          summaryState.index,
          asTrimmedString(summaryState.item.id),
          summaryState.summaryIndex,
          summaryState.summary,
        ));
      }
      const part = cloneRecord(payload.part);
      if (part) {
        const summary = Array.isArray(summaryState.item.summary) ? summaryState.item.summary as AggregateOutputItem[] : [];
        summary[summaryState.summaryIndex] = {
          ...summaryState.summary,
          ...part,
        };
        summaryState.item.summary = summary;
        if (eventType === 'response.reasoning_summary_part.done') {
          markTerminalMarker(summary[summaryState.summaryIndex] as AggregateOutputItem, reasoningSummaryPartDoneMarker);
        }
      } else if (eventType === 'response.reasoning_summary_part.done') {
        markTerminalMarker(summaryState.summary, reasoningSummaryPartDoneMarker);
      }
      return [
        ...lines,
        ...serializeOriginalResponsesEvent(eventType, {
          ...payload,
          output_index: summaryState.index,
          item_id: asTrimmedString(summaryState.item.id) || payload.item_id,
        }),
      ];
    }
    case 'response.reasoning_summary_text.delta':
    case 'response.reasoning_summary_text.done': {
      const lines: string[] = [];
      const summaryState = ensureReasoningSummaryPart(state, payload.item_id, payload.summary_index, payload.output_index);
      if (summaryState.itemCreated) {
        lines.push(serializeOutputItemAdded(summaryState.index, summaryState.item));
      }
      if (summaryState.partCreated) {
        lines.push(serializeReasoningSummaryPartAdded(
          summaryState.index,
          asTrimmedString(summaryState.item.id),
          summaryState.summaryIndex,
          summaryState.summary,
        ));
      }
      if (eventType === 'response.reasoning_summary_text.done') {
        summaryState.summary.text = typeof payload.text === 'string' ? payload.text : String(payload.text ?? '');
        markTerminalMarker(summaryState.summary, reasoningSummaryTextDoneMarker);
      } else {
        summaryState.summary.text = `${typeof summaryState.summary.text === 'string' ? summaryState.summary.text : ''}${typeof payload.delta === 'string' ? payload.delta : ''}`;
      }
      return [
        ...lines,
        ...serializeOriginalResponsesEvent(eventType, {
          ...payload,
          output_index: summaryState.index,
          item_id: asTrimmedString(summaryState.item.id) || payload.item_id,
        }),
      ];
    }
    case 'response.image_generation_call.generating':
    case 'response.image_generation_call.in_progress':
    case 'response.image_generation_call.partial_image':
    case 'response.image_generation_call.completed': {
      const lines: string[] = [];
      const entry = ensureImageGenerationItem(
        state,
        payload.item_id,
        resolveCompatibleOutputIndex(state, 'image_generation_call', payload.output_index, payload.item_id),
      );
      if (entry.created) {
        lines.push(serializeOutputItemAdded(entry.index, entry.item));
      }
      if (eventType === 'response.image_generation_call.partial_image') {
        const partialImages = Array.isArray(entry.item.partial_images) ? entry.item.partial_images as AggregateOutputItem[] : [];
        partialImages.push({
          partial_image_index: payload.partial_image_index,
          partial_image_b64: payload.partial_image_b64,
        });
        entry.item.partial_images = partialImages;
      }
      mergeImageGenerationFields(entry.item, payload);
      if (payload.result !== undefined) {
        entry.item.result = payload.result;
      }
      if (eventType === 'response.image_generation_call.completed') {
        entry.item.status = 'completed';
      }
      return [
        ...lines,
        ...serializeOriginalResponsesEvent(eventType, {
          ...payload,
          output_index: entry.index,
          item_id: asTrimmedString(entry.item.id) || payload.item_id,
        }),
      ];
    }
    case 'response.completed': {
      mergeUsageExtras(state, payload.response && isRecord(payload.response) ? payload.response.usage : payload.usage);
      const responsePayload = cloneRecord(payload.response);
      hydrateStateFromTerminalResponseOutput(state, responsePayload);
      const terminalLines = buildSyntheticTerminalItemDoneEvents(state, 'completed');
      state.completed = true;
      const materialized = materializeResponse(state, streamContext, usage, responsePayload, 'completed');
      return [
        ...terminalLines,
        serializeSse('response.completed', { ...payload, response: materialized }),
      ];
    }
    case 'response.failed': {
      mergeUsageExtras(state, payload.response && isRecord(payload.response) ? payload.response.usage : payload.usage);
      const responsePayload = cloneRecord(payload.response);
      hydrateStateFromTerminalResponseOutput(state, responsePayload);
      const terminalLines = buildSyntheticTerminalItemDoneEvents(state, 'failed');
      state.failed = true;
      const materialized = materializeResponse(state, streamContext, usage, responsePayload, 'failed');
      return [
        ...terminalLines,
        serializeSse('response.failed', { ...payload, response: materialized }),
      ];
    }
    case 'response.incomplete': {
      mergeUsageExtras(state, payload.response && isRecord(payload.response) ? payload.response.usage : payload.usage);
      const responsePayload = cloneRecord(payload.response);
      hydrateStateFromTerminalResponseOutput(state, responsePayload);
      const terminalLines = buildSyntheticTerminalItemDoneEvents(state, 'incomplete');
      state.incomplete = true;
      const materialized = materializeResponse(state, streamContext, usage, responsePayload, 'incomplete');
      return [
        ...terminalLines,
        serializeSse('response.incomplete', { ...payload, response: materialized }),
      ];
    }
    default:
      mergeUsageExtras(state, payload.usage);
      return serializeOriginalResponsesEvent(eventType, payload);
  }
}

function buildSyntheticMessageEvents(
  state: OpenAiResponsesAggregateState,
  delta: string,
): string[] {
  const textPartState = ensureMessageOutputTextPart(state);
  const { index } = textPartState;
  const lines: string[] = [];
  const currentText = typeof textPartState.part.text === 'string' ? textPartState.part.text : '';
  const novelDelta = computeNovelDelta(currentText, delta);
  if (textPartState.itemCreated) {
    lines.push(serializeOutputItemAdded(index, textPartState.item));
  }
  if (textPartState.partCreated) {
    lines.push(serializeContentPartAdded(index, asTrimmedString(textPartState.item.id), 0, textPartState.part));
  }
  if (novelDelta) {
    textPartState.part.text = `${currentText}${novelDelta}`;
    lines.push(serializeSse('response.output_text.delta', {
      type: 'response.output_text.delta',
      output_index: index,
      item_id: textPartState.item.id,
      delta: novelDelta,
    }));
  }
  return lines;
}

function buildSyntheticReasoningEvents(
  state: OpenAiResponsesAggregateState,
  delta?: string,
  reasoningSignature?: string,
): string[] {
  const lines: string[] = [];
  const signature = asTrimmedString(reasoningSignature);
  const reasoningState = (signature || delta)
    ? ensureReasoningItem(state, '', state.outputItems.length)
    : null;
  let emittedOutputItemAdded = false;

  const emitOutputItemAdded = (entry: { index: number; item: AggregateOutputItem; created: boolean } | null) => {
    if (!entry?.created || emittedOutputItemAdded) return;
    lines.push(serializeOutputItemAdded(entry.index, entry.item));
    emittedOutputItemAdded = true;
  };

  if (reasoningState && signature) {
    reasoningState.item.encrypted_content = signature;
  }

  emitOutputItemAdded(reasoningState);

  if (!delta) {
    return lines;
  }

  const summaryState = ensureReasoningSummaryPart(
    state,
    reasoningState?.item.id ?? '',
    0,
    reasoningState?.index ?? state.outputItems.length,
  );
  const itemId = asTrimmedString(summaryState.item.id);
  const currentText = typeof summaryState.summary.text === 'string' ? summaryState.summary.text : '';
  const novelDelta = computeNovelDelta(currentText, delta);
  emitOutputItemAdded(summaryState);
  if (summaryState.partCreated) {
    lines.push(serializeReasoningSummaryPartAdded(summaryState.index, itemId, 0, summaryState.summary));
  }
  if (novelDelta) {
    summaryState.summary.text = `${currentText}${novelDelta}`;
    lines.push(serializeSse('response.reasoning_summary_text.delta', {
      type: 'response.reasoning_summary_text.delta',
      item_id: itemId,
      output_index: summaryState.index,
      summary_index: 0,
      delta: novelDelta,
    }));
  }
  return lines;
}

function buildSyntheticToolEvents(
  state: OpenAiResponsesAggregateState,
  event: OpenAiResponsesStreamEvent,
): string[] {
  const lines: string[] = [];
  if (!Array.isArray(event.toolCallDeltas)) return lines;
  for (const toolDelta of event.toolCallDeltas) {
    const entry = ensureFunctionCallItem(state, toolDelta.id, toolDelta.name, toolDelta.index);
    if (entry.created) {
      lines.push(serializeOutputItemAdded(entry.index, entry.item));
    }
    if (toolDelta.argumentsDelta !== undefined && toolDelta.argumentsDelta.length > 0) {
      entry.item.arguments = `${typeof entry.item.arguments === 'string' ? entry.item.arguments : ''}${toolDelta.argumentsDelta}`;
      lines.push(serializeSse('response.function_call_arguments.delta', {
        type: 'response.function_call_arguments.delta',
        item_id: entry.item.id,
        call_id: entry.item.call_id,
        output_index: entry.index,
        name: entry.item.name,
        delta: toolDelta.argumentsDelta,
      }));
    }
  }
  return lines;
}

function buildMissingSubordinateDoneEventsForItem(
  item: AggregateOutputItem,
  index: number,
): string[] {
  const lines: string[] = [];
  const itemType = asTrimmedString(item.type).toLowerCase();
  const itemId = ensureOutputItemId(asTrimmedString(item.id), 'out', index);
  item.id = itemId;

  if (itemType === 'message') {
    const content = Array.isArray(item.content) ? item.content as AggregateOutputItem[] : [];
    for (let contentIndex = 0; contentIndex < content.length; contentIndex += 1) {
      const part = content[contentIndex];
      if (!isRecord(part)) continue;
      const partType = asTrimmedString(part.type).toLowerCase();
      const text = typeof part.text === 'string' ? part.text : String(part.text ?? '');
      if ((partType === 'output_text' || partType === 'text') && !hasTerminalMarker(part, outputTextDoneMarker)) {
        lines.push(serializeSse('response.output_text.done', {
          type: 'response.output_text.done',
          output_index: index,
          item_id: itemId,
          text,
        }));
        markTerminalMarker(part, outputTextDoneMarker);
      }
      if (!hasTerminalMarker(part, contentPartDoneMarker)) {
        lines.push(serializeSse('response.content_part.done', {
          type: 'response.content_part.done',
          output_index: index,
          item_id: itemId,
          content_index: contentIndex,
          part: cloneJson(part),
        }));
        markTerminalMarker(part, contentPartDoneMarker);
      }
    }
  } else if (itemType === 'reasoning') {
    const summary = Array.isArray(item.summary) ? item.summary as AggregateOutputItem[] : [];
    for (let summaryIndex = 0; summaryIndex < summary.length; summaryIndex += 1) {
      const part = summary[summaryIndex];
      if (!isRecord(part)) continue;
      const text = typeof part.text === 'string' ? part.text : String(part.text ?? '');
      if (!hasTerminalMarker(part, reasoningSummaryTextDoneMarker)) {
        lines.push(serializeSse('response.reasoning_summary_text.done', {
          type: 'response.reasoning_summary_text.done',
          item_id: itemId,
          output_index: index,
          summary_index: summaryIndex,
          text,
        }));
        markTerminalMarker(part, reasoningSummaryTextDoneMarker);
      }
      if (!hasTerminalMarker(part, reasoningSummaryPartDoneMarker)) {
        lines.push(serializeSse('response.reasoning_summary_part.done', {
          type: 'response.reasoning_summary_part.done',
          item_id: itemId,
          output_index: index,
          summary_index: summaryIndex,
          part: cloneJson(part),
        }));
        markTerminalMarker(part, reasoningSummaryPartDoneMarker);
      }
    }
  } else if (itemType === 'function_call') {
    const callId = asTrimmedString(item.call_id) || itemId;
    const name = asTrimmedString(item.name);
    const argumentsText = typeof item.arguments === 'string' ? item.arguments : String(item.arguments ?? '');
    if (!hasTerminalMarker(item, functionCallArgumentsDoneMarker)) {
      lines.push(serializeSse('response.function_call_arguments.done', {
        type: 'response.function_call_arguments.done',
        item_id: itemId,
        call_id: callId,
        output_index: index,
        ...(name ? { name } : {}),
        arguments: argumentsText,
      }));
      markTerminalMarker(item, functionCallArgumentsDoneMarker);
    }
  } else if (itemType === 'custom_tool_call') {
    const callId = asTrimmedString(item.call_id) || itemId;
    const name = asTrimmedString(item.name);
    const inputText = typeof item.input === 'string' ? item.input : String(item.input ?? '');
    if (!hasTerminalMarker(item, customToolInputDoneMarker)) {
      lines.push(serializeSse('response.custom_tool_call_input.done', {
        type: 'response.custom_tool_call_input.done',
        item_id: itemId,
        call_id: callId,
        output_index: index,
        ...(name ? { name } : {}),
        input: inputText,
      }));
      markTerminalMarker(item, customToolInputDoneMarker);
    }
  }

  return lines;
}

function buildSyntheticTerminalItemDoneEvents(
  state: OpenAiResponsesAggregateState,
  status: 'completed' | 'failed' | 'incomplete',
): string[] {
  const lines: string[] = [];

  for (let index = 0; index < state.outputItems.length; index += 1) {
    const item = state.outputItems[index];
    if (!isRecord(item)) continue;

    const currentStatus = asTrimmedString(item.status).toLowerCase();
    const itemTerminal = isTerminalStatus(currentStatus);
    lines.push(...buildMissingSubordinateDoneEventsForItem(item, index));

    if (!hasTerminalMarker(item, outputItemDoneMarker)) {
      if (!itemTerminal) {
        item.status = status;
      }
      lines.push(serializeSse('response.output_item.done', {
        type: 'response.output_item.done',
        output_index: index,
        item: cloneJson(item),
      }));
      markTerminalMarker(item, outputItemDoneMarker);
    }
  }

  return lines;
}

export function serializeConvertedResponsesEvents(input: {
  state: OpenAiResponsesAggregateState;
  streamContext: StreamTransformContext;
  event: OpenAiResponsesStreamEvent;
  usage: ResponsesUsageSummary;
}): string[] {
  const { state, streamContext, event, usage } = input;
  mergeUsageExtras(state, event.responsesPayload && isRecord(event.responsesPayload) ? event.responsesPayload.usage : undefined);

  if (event.responsesEventType && event.responsesPayload) {
    return applyOriginalResponsesPayload(
      state,
      event.responsesEventType,
      event.responsesPayload,
      streamContext,
      usage,
    );
  }

  const lines: string[] = [];
  if (event.contentDelta) {
    lines.push(...buildSyntheticMessageEvents(state, event.contentDelta));
  }
  if (event.reasoningDelta || event.reasoningSignature) {
    lines.push(...buildSyntheticReasoningEvents(state, event.reasoningDelta, event.reasoningSignature));
  }
  lines.push(...buildSyntheticToolEvents(state, event));
  return lines;
}

export function completeResponsesStream(
  state: OpenAiResponsesAggregateState,
  streamContext: StreamTransformContext,
  usage: ResponsesUsageSummary,
): string[] {
  if (state.failed || state.completed || state.incomplete) {
    return [serializeDone()];
  }
  const lines = buildSyntheticTerminalItemDoneEvents(state, 'completed');
  state.completed = true;
  return [
    ...lines,
    serializeSse('response.completed', {
      type: 'response.completed',
      response: materializeResponse(state, streamContext, usage, null, 'completed'),
    }),
    serializeDone(),
  ];
}

export function failResponsesStream(
  state: OpenAiResponsesAggregateState,
  streamContext: StreamTransformContext,
  usage: ResponsesUsageSummary,
  payload: unknown,
): string[] {
  if (state.failed) {
    return [serializeDone()];
  }
  const lines = buildSyntheticTerminalItemDoneEvents(state, 'failed');
  state.failed = true;
  const errorPayload = cloneRecord(payload);
  const message = (
    isRecord(errorPayload?.error) && typeof errorPayload.error.message === 'string'
      ? errorPayload.error.message
      : (typeof errorPayload?.message === 'string' ? errorPayload.message : 'upstream stream failed')
  );
  return [
    ...lines,
    serializeSse('response.failed', {
      type: 'response.failed',
      response: materializeResponse(state, streamContext, usage, cloneRecord(errorPayload?.response), 'failed'),
      error: {
        message,
        type: 'upstream_error',
      },
    }),
    serializeDone(),
  ];
}

export function incompleteResponsesStream(
  state: OpenAiResponsesAggregateState,
  streamContext: StreamTransformContext,
  usage: ResponsesUsageSummary,
  payload: unknown,
): string[] {
  if (state.failed || state.completed || state.incomplete) {
    return [serializeDone()];
  }
  const lines = buildSyntheticTerminalItemDoneEvents(state, 'incomplete');
  state.incomplete = true;
  const incompletePayload = cloneRecord(payload);
  return [
    ...lines,
    serializeSse('response.incomplete', {
      ...incompletePayload,
      response: materializeResponse(state, streamContext, usage, cloneRecord(incompletePayload?.response), 'incomplete'),
    }),
    serializeDone(),
  ];
}
