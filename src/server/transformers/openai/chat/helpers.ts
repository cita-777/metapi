import type {
  OpenAiChatChoice,
  OpenAiChatChoiceDelta,
  OpenAiChatNormalizedFinalResponse,
  OpenAiChatNormalizedStreamEvent,
  OpenAiChatRequestMetadata,
  OpenAiChatToolCall,
  OpenAiChatUsageDetails,
} from './model.js';
import { fromTransformerMetadataRecord } from '../../shared/normalized.js';
import { extractInlineThinkTags } from '../../shared/thinkTagParser.js';

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return isRecord(value) ? value : null;
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

function toStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value
    .map((item) => {
      if (typeof item === 'string') return item.trim();
      if (isRecord(item)) {
        const direct = typeof item.url === 'string'
          ? item.url
          : typeof item.uri === 'string'
            ? item.uri
            : '';
        return direct.trim();
      }
      return '';
    })
    .filter((item) => item.length > 0);
}

function toFiniteNumber(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string' && value.trim().length > 0) {
    const numeric = Number(value);
    if (Number.isFinite(numeric)) return numeric;
  }
  return undefined;
}

function toNumericRecord(value: unknown): Record<string, number> | undefined {
  if (!isRecord(value)) return undefined;
  const entries = Object.entries(value)
    .map(([key, raw]) => {
      const numeric = toFiniteNumber(raw);
      if (!Number.isFinite(numeric)) return null;
      return [key, numeric] as const;
    })
    .filter((entry): entry is readonly [string, number] => !!entry);
  if (entries.length <= 0) return undefined;
  return Object.fromEntries(entries);
}

function stableKey(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableKey(item)).join(',')}]`;
  }
  if (isRecord(value)) {
    const entries = Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, nested]) => `${JSON.stringify(key)}:${stableKey(nested)}`);
    return `{${entries.join(',')}}`;
  }
  return JSON.stringify(value);
}

function annotationUrl(annotation: Record<string, unknown>): string {
  const urlCitation = asRecord(annotation.url_citation) ?? asRecord(annotation.urlCitation);
  const direct = typeof annotation.url === 'string' ? annotation.url : '';
  const nested = urlCitation && typeof urlCitation.url === 'string' ? urlCitation.url : '';
  return (direct || nested).trim();
}

function extractTextPart(value: unknown): string {
  if (typeof value === 'string') return value;
  if (!isRecord(value)) return '';

  if (typeof value.text === 'string') return value.text;
  if (typeof value.output_text === 'string') return value.output_text;
  if (typeof value.content === 'string') return value.content;
  if (typeof value.reasoning_content === 'string') return value.reasoning_content;
  if (typeof value.reasoning === 'string') return value.reasoning;

  if (Array.isArray(value.content)) {
    return value.content.map((item) => extractTextPart(item)).join('');
  }

  if (Array.isArray(value.parts)) {
    return value.parts.map((item) => extractTextPart(item)).join('');
  }

  return '';
}

function joinNonEmpty(parts: string[]): string {
  return parts.map((item) => item.trim()).filter((item) => item.length > 0).join('\n\n');
}

function extractTextAndReasoning(value: unknown): { content: string; reasoning: string } {
  if (typeof value === 'string') return extractInlineThinkTags(value);
  if (Array.isArray(value)) {
    const contentParts: string[] = [];
    const reasoningParts: string[] = [];

    for (const item of value) {
      if (!isRecord(item)) {
        if (typeof item === 'string') {
          const parsed = extractInlineThinkTags(item);
          if (parsed.content) contentParts.push(parsed.content);
          if (parsed.reasoning) reasoningParts.push(parsed.reasoning);
        }
        continue;
      }

      const type = typeof item.type === 'string' ? item.type : '';
      if ((type === 'reasoning' || type === 'thinking') && typeof item.text === 'string') {
        reasoningParts.push(item.text);
        continue;
      }
      if ((type === 'reasoning' || type === 'thinking') && typeof item.reasoning === 'string') {
        reasoningParts.push(item.reasoning);
        continue;
      }
      const parsed = extractInlineThinkTags(extractTextPart(item));
      if (parsed.content) contentParts.push(parsed.content);
      if (parsed.reasoning) reasoningParts.push(parsed.reasoning);
    }

    return {
      content: contentParts.join(''),
      reasoning: reasoningParts.join(''),
    };
  }

  if (!isRecord(value)) return { content: '', reasoning: '' };
  const parsed = extractInlineThinkTags(extractTextPart(value.content ?? value));
  return {
    content: parsed.content,
    reasoning: joinNonEmpty([
      typeof value.reasoning_content === 'string' ? value.reasoning_content : '',
      typeof value.reasoning === 'string' ? value.reasoning : '',
      parsed.reasoning,
    ]),
  };
}

function collectToolCalls(value: unknown): OpenAiChatToolCall[] {
  if (!Array.isArray(value)) return [];
  const toolCalls: OpenAiChatToolCall[] = [];

  for (const item of value) {
    if (!isRecord(item)) continue;
    const functionPart = isRecord(item.function) ? item.function : null;
    if (!functionPart) continue;
    const name = typeof functionPart.name === 'string' ? functionPart.name : '';
    const id = typeof item.id === 'string' ? item.id : '';
    const args = typeof functionPart.arguments === 'string' ? functionPart.arguments : '';
    if (!id && !name && !args) continue;
    toolCalls.push({
      id,
      name,
      arguments: args,
    });
  }

  return toolCalls;
}

function collectToolCallDeltas(value: unknown): OpenAiChatChoiceDelta['toolCallDeltas'] {
  if (!Array.isArray(value)) return undefined;
  const deltas = value
    .map((item, itemIndex) => {
      if (!isRecord(item)) return null;
      const functionPart = isRecord(item.function) ? item.function : {};
      const index = toFiniteNumber(item.index);
      const delta = {
        index: index !== undefined ? Math.max(0, Math.trunc(index)) : itemIndex,
        id: typeof item.id === 'string' && item.id.trim() ? item.id : undefined,
        name: typeof functionPart.name === 'string' && functionPart.name.trim() ? functionPart.name : undefined,
        argumentsDelta: typeof functionPart.arguments === 'string' ? functionPart.arguments : undefined,
      };
      if (!delta.id && !delta.name && !delta.argumentsDelta) return null;
      return delta;
    })
    .filter((item): item is NonNullable<typeof item> => !!item);

  return deltas.length > 0 ? deltas : undefined;
}

export function dedupeAnnotations(input: unknown): Array<Record<string, unknown>> {
  if (!Array.isArray(input)) return [];
  const seen = new Set<string>();
  const result: Array<Record<string, unknown>> = [];

  for (const item of input) {
    if (!isRecord(item)) continue;
    const key = annotationUrl(item) || stableKey(item);
    if (!key || seen.has(key)) continue;
    seen.add(key);
    result.push(item);
  }

  return result;
}

export function dedupeCitations(input: unknown): string[] {
  const citations = new Set<string>();

  for (const citation of toStringArray(input)) {
    citations.add(citation);
  }

  if (Array.isArray(input)) {
    for (const item of input) {
      if (!isRecord(item)) continue;
      const nestedUrl = annotationUrl(item);
      if (nestedUrl) citations.add(nestedUrl);
    }
  }

  return Array.from(citations);
}

export function extractChoiceAnnotations(choice: unknown): Array<Record<string, unknown>> {
  if (!isRecord(choice)) return [];
  const choiceMessage = asRecord(choice.message);
  const choiceDelta = asRecord(choice.delta);
  return dedupeAnnotations([
    ...(Array.isArray(choice.annotations) ? choice.annotations : []),
    ...(Array.isArray(choiceMessage?.annotations) ? choiceMessage.annotations : []),
    ...(Array.isArray(choiceDelta?.annotations) ? choiceDelta.annotations : []),
  ]);
}

export function extractChoiceCitations(
  choice: unknown,
  sharedCitations: Iterable<string> = [],
): string[] {
  const citations = new Set<string>(sharedCitations);
  for (const annotation of extractChoiceAnnotations(choice)) {
    const url = annotationUrl(annotation);
    if (url) citations.add(url);
  }
  if (isRecord(choice)) {
    for (const citation of dedupeCitations(choice.citations)) citations.add(citation);
  }
  return Array.from(citations);
}

export function extractChatChoices(payload: unknown): OpenAiChatChoice[] {
  const record = asRecord(payload);
  if (!record || !Array.isArray(record.choices)) return [];

  const sharedCitations = dedupeCitations(record.citations);
  const choices: OpenAiChatChoice[] = [];

  for (const [index, choice] of record.choices.entries()) {
    const choiceRecord = asRecord(choice);
    if (!choiceRecord) continue;
    const message = asRecord(choiceRecord.message) ?? asRecord(choiceRecord.delta) ?? {};
    const parsed = extractTextAndReasoning(message.content ?? message);
    const toolCalls = collectToolCalls(message.tool_calls);
    const annotations = extractChoiceAnnotations(choiceRecord);
    const citations = extractChoiceCitations(choiceRecord, sharedCitations);
    const finishReason = typeof choiceRecord.finish_reason === 'string' && choiceRecord.finish_reason.length > 0
      ? choiceRecord.finish_reason
      : (toolCalls.length > 0 ? 'tool_calls' : 'stop');

    choices.push({
      index: toFiniteNumber(choiceRecord.index) !== undefined ? Math.max(0, Math.trunc(toFiniteNumber(choiceRecord.index)!)) : index,
      ...(message.role === 'assistant' ? { role: 'assistant' as const } : {}),
      content: parsed.content || (toolCalls.length > 0 ? '' : ''),
      reasoningContent: typeof message.reasoning_content === 'string'
        ? message.reasoning_content
        : parsed.reasoning,
      toolCalls,
      finishReason,
      ...(annotations.length > 0 ? { annotations } : {}),
      ...(citations.length > 0 ? { citations } : {}),
    });
  }

  return choices.sort((left, right) => left.index - right.index);
}

export function extractChatChoiceEvents(payload: unknown): OpenAiChatChoiceDelta[] {
  const record = asRecord(payload);
  if (!record || !Array.isArray(record.choices)) return [];

  const sharedCitations = dedupeCitations(record.citations);
  const choiceEvents: OpenAiChatChoiceDelta[] = [];

  for (const [index, choice] of record.choices.entries()) {
    const choiceRecord = asRecord(choice);
    if (!choiceRecord) continue;
    const delta = asRecord(choiceRecord.delta) ?? {};
    const parsed = extractTextAndReasoning(delta.content ?? delta);
    const toolCallDeltas = collectToolCallDeltas(delta.tool_calls);
    const annotations = extractChoiceAnnotations(choiceRecord);
    const citations = extractChoiceCitations(choiceRecord, sharedCitations);
    const choiceIndex = toFiniteNumber(choiceRecord.index) !== undefined
      ? Math.max(0, Math.trunc(toFiniteNumber(choiceRecord.index)!))
      : index;

    choiceEvents.push({
      index: choiceIndex,
      ...(delta.role === 'assistant' ? { role: 'assistant' as const } : {}),
      ...(parsed.content ? { contentDelta: parsed.content } : {}),
      ...((typeof delta.reasoning_content === 'string' ? delta.reasoning_content : parsed.reasoning)
        ? { reasoningDelta: (typeof delta.reasoning_content === 'string' ? delta.reasoning_content : parsed.reasoning) }
        : {}),
      ...(toolCallDeltas ? { toolCallDeltas } : {}),
      finishReason: typeof choiceRecord.finish_reason === 'string' ? choiceRecord.finish_reason : null,
      ...(annotations.length > 0 ? { annotations } : {}),
      ...(citations.length > 0 ? { citations } : {}),
    });
  }

  return choiceEvents;
}

function extractAnnotationsFromPayload(payload: Record<string, unknown>): Array<Record<string, unknown>> {
  const collected: Array<Record<string, unknown>> = [];
  const append = (value: unknown) => {
    for (const item of dedupeAnnotations(value)) {
      collected.push(item);
    }
  };

  append(payload.annotations);

  const choices = Array.isArray(payload.choices) ? payload.choices : [];
  for (const choice of choices) {
    const choiceRecord = asRecord(choice);
    if (!choiceRecord) continue;
    append(asRecord(choiceRecord.message)?.annotations);
    append(asRecord(choiceRecord.delta)?.annotations);
  }

  return dedupeAnnotations(collected);
}

function extractCitationsFromPayload(
  payload: Record<string, unknown>,
  annotations: Array<Record<string, unknown>>,
): string[] {
  const citations = new Set<string>();

  for (const citation of dedupeCitations(payload.citations)) {
    citations.add(citation);
  }

  const transformerMetadata = fromTransformerMetadataRecord(
    payload.transformer_metadata ?? payload.transformerMetadata,
  );
  if (transformerMetadata) {
    for (const citation of dedupeCitations(transformerMetadata.citations)) {
      citations.add(citation);
    }
  }

  for (const annotation of annotations) {
    const url = annotationUrl(annotation);
    if (url) citations.add(url);
  }

  return Array.from(citations);
}

export function extractChatUsageDetails(payload: Record<string, unknown>): OpenAiChatUsageDetails | undefined {
  const usage = asRecord(payload.usage) ?? asRecord(asRecord(payload.response)?.usage);
  if (!usage) return undefined;

  const promptDetails = toNumericRecord(
    usage.prompt_tokens_details
    ?? usage.promptTokensDetails
    ?? usage.input_tokens_details,
  );
  const completionDetails = toNumericRecord(
    usage.completion_tokens_details
    ?? usage.completionTokensDetails
    ?? usage.output_tokens_details,
  );
  if (!promptDetails && !completionDetails) return undefined;

  return {
    ...(promptDetails ? { prompt_tokens_details: promptDetails } : {}),
    ...(completionDetails ? { completion_tokens_details: completionDetails } : {}),
  };
}

export function mergeChatUsageDetails(
  base: OpenAiChatUsageDetails | undefined,
  next: OpenAiChatUsageDetails | undefined,
): OpenAiChatUsageDetails | undefined {
  if (!base && !next) return undefined;

  const mergeNumericMaps = (
    left: Record<string, number> | undefined,
    right: Record<string, number> | undefined,
  ): Record<string, number> | undefined => {
    if (!left && !right) return undefined;
    return Object.fromEntries(
      Array.from(new Set([...Object.keys(left || {}), ...Object.keys(right || {})]))
        .map((key) => [key, Math.max(left?.[key] || 0, right?.[key] || 0)]),
    );
  };

  return {
    ...(mergeNumericMaps(base?.prompt_tokens_details, next?.prompt_tokens_details)
      ? { prompt_tokens_details: mergeNumericMaps(base?.prompt_tokens_details, next?.prompt_tokens_details)! }
      : {}),
    ...(mergeNumericMaps(base?.completion_tokens_details, next?.completion_tokens_details)
      ? { completion_tokens_details: mergeNumericMaps(base?.completion_tokens_details, next?.completion_tokens_details)! }
      : {}),
  };
}

export function extractUsagePayload(payload: Record<string, unknown>): Record<string, unknown> | undefined {
  const usage = asRecord(payload.usage) ?? asRecord(asRecord(payload.response)?.usage);
  if (!usage) return undefined;
  const mappedUsage = cloneJson(usage);

  const promptTokens = mappedUsage.prompt_tokens ?? mappedUsage.input_tokens;
  const completionTokens = mappedUsage.completion_tokens ?? mappedUsage.output_tokens;
  if (promptTokens !== undefined) mappedUsage.prompt_tokens = promptTokens;
  if (completionTokens !== undefined) mappedUsage.completion_tokens = completionTokens;
  delete mappedUsage.input_tokens;
  delete mappedUsage.output_tokens;

  const promptDetails = mappedUsage.prompt_tokens_details ?? mappedUsage.input_tokens_details;
  const completionDetails = mappedUsage.completion_tokens_details ?? mappedUsage.output_tokens_details;
  if (promptDetails !== undefined) mappedUsage.prompt_tokens_details = cloneJson(promptDetails);
  if (completionDetails !== undefined) mappedUsage.completion_tokens_details = cloneJson(completionDetails);
  delete mappedUsage.input_tokens_details;
  delete mappedUsage.output_tokens_details;

  return mappedUsage;
}

export function extractChatResponseExtras(payload: unknown): Pick<
  OpenAiChatNormalizedFinalResponse,
  'annotations' | 'citations' | 'usageDetails' | 'usagePayload'
> & Pick<OpenAiChatNormalizedStreamEvent, 'annotations' | 'citations' | 'usageDetails' | 'usagePayload'> {
  const record = asRecord(payload);
  if (!record) return {};

  const annotations = extractAnnotationsFromPayload(record);
  const citations = extractCitationsFromPayload(record, annotations);
  const usageDetails = extractChatUsageDetails(record);
  const usagePayload = extractUsagePayload(record);

  return {
    ...(annotations.length > 0 ? { annotations } : {}),
    ...(citations.length > 0 ? { citations } : {}),
    ...(usageDetails ? { usageDetails } : {}),
    ...(usagePayload ? { usagePayload } : {}),
  };
}

export function extractChatRequestMetadata(body: unknown): OpenAiChatRequestMetadata | undefined {
  const raw = asRecord(body);
  if (!raw) return undefined;

  const streamOptions = asRecord(raw.stream_options) ?? asRecord(raw.streamOptions);
  const modalities = Array.isArray(raw.modalities)
    ? raw.modalities.filter((item): item is string => typeof item === 'string' && item.trim().length > 0)
    : undefined;
  const audio = asRecord(raw.audio) as OpenAiChatRequestMetadata['audio'] | null;
  const reasoningBudget = toFiniteNumber(raw.reasoning_budget);
  const topLogprobs = toFiniteNumber(raw.top_logprobs);
  const logitBias = toNumericRecord(raw.logit_bias);
  const metadata: OpenAiChatRequestMetadata = {
    ...(modalities && modalities.length > 0 ? { modalities } : {}),
    ...(audio ? { audio } : {}),
    ...(typeof raw.reasoning_effort === 'string' ? { reasoningEffort: raw.reasoning_effort } : {}),
    ...(reasoningBudget !== undefined ? { reasoningBudget } : {}),
    ...(typeof raw.reasoning_summary === 'string' ? { reasoningSummary: raw.reasoning_summary } : {}),
    ...(typeof raw.service_tier === 'string' ? { serviceTier: raw.service_tier } : {}),
    ...(topLogprobs !== undefined ? { topLogprobs } : {}),
    ...(logitBias ? { logitBias } : {}),
    ...(typeof raw.prompt_cache_key === 'string' ? { promptCacheKey: raw.prompt_cache_key } : {}),
    ...(typeof raw.safety_identifier === 'string' ? { safetyIdentifier: raw.safety_identifier } : {}),
    ...(typeof raw.verbosity === 'string' ? { verbosity: raw.verbosity } : {}),
    ...(raw.response_format !== undefined ? { responseFormat: raw.response_format } : {}),
    ...(streamOptions && streamOptions.include_usage !== undefined
      ? { streamOptionsIncludeUsage: Boolean(streamOptions.include_usage) }
      : {}),
  };

  return Object.keys(metadata).length > 0 ? metadata : undefined;
}
