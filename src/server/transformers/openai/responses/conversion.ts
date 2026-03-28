import {
  normalizeResponsesInputForCompatibility,
  normalizeResponsesMessageContentBlocks,
  normalizeResponsesMessageItem,
} from './normalization.js';
import {
  decodeResponsesMcpCompatToolCall,
  isResponsesMcpItem,
  toResponsesMcpCompatToolCall,
} from './mcpCompatibility.js';
import { normalizeInputFileBlock, toOpenAiChatFileBlock } from '../../shared/inputFile.js';
import { buildShortToolNameMap, getShortToolName } from '../../shared/toolNameShortener.js';

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object';
}

function asTrimmedString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function toFiniteNumber(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

function toFiniteIntegerLike(value: unknown): number | null {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return Math.trunc(value);
  }
  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (!trimmed) return null;
    const parsed = Number(trimmed);
    return Number.isFinite(parsed) ? Math.trunc(parsed) : null;
  }
  return null;
}

function toBooleanLike(value: unknown): boolean | undefined {
  if (typeof value === 'boolean') return value;
  if (typeof value === 'string') {
    const trimmed = value.trim().toLowerCase();
    if (trimmed === 'true') return true;
    if (trimmed === 'false') return false;
  }
  return undefined;
}

function safeJsonStringify(value: unknown): string {
  try {
    return JSON.stringify(value);
  } catch {
    return '';
  }
}

function cloneRecord(value: unknown): Record<string, unknown> | null {
  if (!isRecord(value)) return null;
  return { ...value };
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

function normalizeOptionalTrimmedString(value: unknown): string | undefined {
  const trimmed = asTrimmedString(value);
  return trimmed || undefined;
}

function normalizeIncludeList(value: unknown): unknown {
  if (typeof value === 'string') {
    const trimmed = value.trim();
    return trimmed ? [trimmed] : [];
  }

  if (!Array.isArray(value)) return value;

  return value
    .map((item) => (typeof item === 'string' ? item.trim() : ''))
    .filter((item) => item.length > 0);
}

function hasExplicitInclude(body: Record<string, unknown>): boolean {
  return Object.prototype.hasOwnProperty.call(body, 'include');
}

function applyDefaultResponsesInclude(body: Record<string, unknown>): void {
  if (hasExplicitInclude(body)) {
    body.include = normalizeIncludeList(body.include);
    return;
  }

  body.include = ['reasoning.encrypted_content'];
}

function normalizeTextConfig(
  rawText: unknown,
  fallbackVerbosity?: unknown,
): Record<string, unknown> | undefined {
  const textConfig = cloneRecord(rawText) || {};
  const verbosity = (
    normalizeOptionalTrimmedString(textConfig.verbosity)
    ?? normalizeOptionalTrimmedString(fallbackVerbosity)
  );
  if (verbosity) {
    textConfig.verbosity = verbosity;
  }
  return Object.keys(textConfig).length > 0 ? textConfig : undefined;
}

function normalizeStreamOptions(rawStreamOptions: unknown): unknown {
  const streamOptions = cloneRecord(rawStreamOptions);
  if (!streamOptions) return rawStreamOptions;

  const includeObfuscation = toBooleanLike(streamOptions.include_obfuscation);
  if (includeObfuscation !== undefined) {
    streamOptions.include_obfuscation = includeObfuscation;
  }

  return streamOptions;
}

function normalizeResponsesRequestFieldParity(
  body: Record<string, unknown>,
  options?: {
    verbositySource?: unknown;
    defaultEncryptedReasoningInclude?: boolean;
  },
): Record<string, unknown> {
  const normalized: Record<string, unknown> = { ...body };

  const safetyIdentifier = normalizeOptionalTrimmedString(normalized.safety_identifier);
  if (safetyIdentifier) normalized.safety_identifier = safetyIdentifier;

  const maxToolCalls = toFiniteIntegerLike(normalized.max_tool_calls);
  if (maxToolCalls !== null) normalized.max_tool_calls = maxToolCalls;

  const promptCacheKey = normalizeOptionalTrimmedString(normalized.prompt_cache_key);
  if (promptCacheKey) normalized.prompt_cache_key = promptCacheKey;

  const promptCacheRetention = normalizeOptionalTrimmedString(normalized.prompt_cache_retention);
  if (promptCacheRetention) normalized.prompt_cache_retention = promptCacheRetention;

  const background = toBooleanLike(normalized.background);
  if (background !== undefined) normalized.background = background;

  const user = normalizeOptionalTrimmedString(normalized.user);
  if (user) normalized.user = user;

  const previousResponseId = normalizeOptionalTrimmedString(normalized.previous_response_id);
  if (previousResponseId) normalized.previous_response_id = previousResponseId;

  const truncation = normalizeOptionalTrimmedString(normalized.truncation);
  if (truncation) normalized.truncation = truncation;

  const serviceTier = normalizeOptionalTrimmedString(normalized.service_tier);
  if (serviceTier) normalized.service_tier = serviceTier;

  const topLogprobs = toFiniteIntegerLike(normalized.top_logprobs);
  if (topLogprobs !== null) normalized.top_logprobs = topLogprobs;

  if (normalized.include !== undefined) {
    normalized.include = normalizeIncludeList(normalized.include);
  }
  if (options?.defaultEncryptedReasoningInclude) {
    applyDefaultResponsesInclude(normalized);
  }

  if (normalized.stream_options !== undefined) {
    normalized.stream_options = normalizeStreamOptions(normalized.stream_options);
  }

  const textConfig = normalizeTextConfig(normalized.text, options?.verbositySource);
  if (textConfig) {
    normalized.text = textConfig;
  }

  if (!isRecord(normalized.reasoning)) {
    const reasoning: Record<string, unknown> = {};
    const effort = normalizeOptionalTrimmedString((normalized as Record<string, unknown>).reasoning_effort);
    if (effort) reasoning.effort = effort;
    const budgetTokens = toFiniteIntegerLike((normalized as Record<string, unknown>).reasoning_budget);
    if (budgetTokens !== null) reasoning.budget_tokens = budgetTokens;
    const summary = normalizeOptionalTrimmedString((normalized as Record<string, unknown>).reasoning_summary);
    if (summary) reasoning.summary = summary;
    if (Object.keys(reasoning).length > 0) normalized.reasoning = reasoning;
  }
  delete normalized.reasoning_effort;
  delete normalized.reasoning_budget;
  delete normalized.reasoning_summary;

  return normalized;
}

function parseJsonString(raw: string): unknown {
  const trimmed = raw.trim();
  if (!trimmed) return {};
  try {
    return JSON.parse(trimmed);
  } catch {
    return { value: raw };
  }
}

export function extractTextContent(value: unknown): string {
  if (typeof value === 'string') return value;
  if (Array.isArray(value)) {
    return value
      .map((item) => extractTextContent(item))
      .filter((item) => item.length > 0)
      .join('\n');
  }
  if (!isRecord(value)) return '';

  const direct = asTrimmedString(
    value.text
    ?? value.content
    ?? value.input_text
    ?? value.output_text
    ?? value.reasoning
    ?? value.reasoning_content
    ?? value.thinking,
  );
  if (direct) return direct;

  if (Array.isArray(value.parts)) return extractTextContent(value.parts);
  if (Array.isArray(value.content)) return extractTextContent(value.content);
  if (Array.isArray(value.output)) return extractTextContent(value.output);
  return '';
}

function normalizeOpenAiToolArguments(raw: unknown): string {
  if (typeof raw === 'string') return raw;
  if (raw === undefined || raw === null) return '';
  if (typeof raw === 'number' || typeof raw === 'boolean') return String(raw);
  if (Array.isArray(raw) || isRecord(raw)) return safeJsonStringify(raw);
  return '';
}

function normalizeToolOutput(raw: unknown): string | Array<string | Record<string, unknown>> {
  const normalizedContent = toOpenAiMessageContent(raw);
  const hasNormalizedContent = typeof normalizedContent === 'string'
    ? normalizedContent.trim().length > 0
    : Array.isArray(normalizedContent) && normalizedContent.length > 0;
  if (hasNormalizedContent) return normalizedContent;
  if (raw === undefined || raw === null) return '';
  if (typeof raw === 'string') return raw;
  if (typeof raw === 'number' || typeof raw === 'boolean') return String(raw);
  if (Array.isArray(raw) || isRecord(raw)) return safeJsonStringify(raw);
  return '';
}

function toResponsesInputMessageFromText(text: string): Record<string, unknown> {
  return {
    type: 'message',
    role: 'user',
    content: [{ type: 'input_text', text }],
  };
}

function collectOpenAiToolNames(body: Record<string, unknown>): string[] {
  const names: string[] = [];
  const pushName = (value: unknown) => {
    const name = asTrimmedString(value);
    if (name) names.push(name);
  };

  const rawTools = Array.isArray(body.tools) ? body.tools : [];
  for (const item of rawTools) {
    if (!isRecord(item)) continue;
    const type = asTrimmedString(item.type).toLowerCase();
    if (type === 'function' && isRecord(item.function)) {
      pushName(item.function.name);
      continue;
    }
    if (type === 'function') {
      pushName(item.name);
    }
  }

  const toolChoice = isRecord(body.tool_choice) ? body.tool_choice : null;
  if (toolChoice && asTrimmedString(toolChoice.type).toLowerCase() === 'function') {
    pushName(isRecord(toolChoice.function) ? toolChoice.function.name : toolChoice.name);
  }

  const rawMessages = Array.isArray(body.messages) ? body.messages : [];
  for (const message of rawMessages) {
    if (!isRecord(message) || asTrimmedString(message.role).toLowerCase() !== 'assistant') continue;
    const toolCalls = Array.isArray(message.tool_calls) ? message.tool_calls : [];
    for (const toolCall of toolCalls) {
      if (!isRecord(toolCall)) continue;
      const functionPart = isRecord(toolCall.function) ? toolCall.function : null;
      pushName(functionPart?.name ?? toolCall.name);
    }
  }

  return names;
}

function convertOpenAiToolsToResponses(
  rawTools: unknown,
  toolNameMap: Record<string, string>,
): unknown {
  if (!Array.isArray(rawTools)) return rawTools;

  const converted = rawTools
    .map((item) => {
      if (!isRecord(item)) return null;

      const type = asTrimmedString(item.type).toLowerCase();
      if (type === 'function' && isRecord(item.function)) {
        const fn = item.function;
        const name = asTrimmedString(fn.name);
        if (!name) return null;

        const mapped: Record<string, unknown> = {
          type: 'function',
          name: getShortToolName(name, toolNameMap),
        };
        const description = asTrimmedString(fn.description);
        if (description) mapped.description = description;
        if (fn.parameters !== undefined) mapped.parameters = fn.parameters;
        if (fn.strict !== undefined) mapped.strict = fn.strict;
        return mapped;
      }

      if (type === 'function' && asTrimmedString(item.name)) {
        return {
          ...item,
          name: getShortToolName(asTrimmedString(item.name), toolNameMap),
        };
      }

      if (type === 'image_generation') {
        return item;
      }

      if (type === 'custom' && asTrimmedString(item.name)) {
        return item;
      }

      return null;
    })
    .filter((item): item is Record<string, unknown> => !!item);

  return converted;
}

function convertOpenAiToolChoiceToResponses(
  rawToolChoice: unknown,
  toolNameMap: Record<string, string>,
): unknown {
  if (rawToolChoice === undefined) return undefined;
  if (typeof rawToolChoice === 'string') return rawToolChoice;
  if (!isRecord(rawToolChoice)) return rawToolChoice;

  const type = asTrimmedString(rawToolChoice.type).toLowerCase();
  if (type === 'function' && isRecord(rawToolChoice.function)) {
    const name = asTrimmedString(rawToolChoice.function.name);
    if (!name) return 'required';
    return { type: 'function', name: getShortToolName(name, toolNameMap) };
  }

  return rawToolChoice;
}

function normalizeResponsesBodyForCompatibility(
  body: Record<string, unknown>,
): Record<string, unknown> {
  const nextInput = normalizeResponsesInputForCompatibility(body.input);
  if (nextInput === body.input) return body;
  return {
    ...body,
    input: nextInput,
  };
}

const RESPONSES_TOOL_CALL_INPUT_TYPES = new Set([
  'function_call',
  'custom_tool_call',
]);

const RESPONSES_TOOL_CALL_OUTPUT_TYPES = new Set([
  'function_call_output',
  'custom_tool_call_output',
]);

function stripOrphanedResponsesToolOutputs(input: unknown): unknown {
  if (!Array.isArray(input)) return input;

  const seenToolCallIds = new Set<string>();
  const sanitized: unknown[] = [];

  for (const item of input) {
    if (!isRecord(item)) {
      sanitized.push(item);
      continue;
    }

    const type = asTrimmedString(item.type).toLowerCase();
    if (RESPONSES_TOOL_CALL_INPUT_TYPES.has(type)) {
      const callId = asTrimmedString(item.call_id ?? item.id);
      if (callId) seenToolCallIds.add(callId);
      sanitized.push(item);
      continue;
    }

    if (RESPONSES_TOOL_CALL_OUTPUT_TYPES.has(type)) {
      const callId = asTrimmedString(item.call_id ?? item.id);
      if (!callId || !seenToolCallIds.has(callId)) continue;
      sanitized.push(item);
      continue;
    }

    sanitized.push(item);
  }

  return sanitized;
}

export function normalizeResponsesMessageContent(role: string, content: unknown): Array<Record<string, unknown>> {
  return normalizeResponsesMessageContentBlocks(role, content);
}

const RESPONSES_COMPATIBILITY_FILTER_FIELDS = new Set([
  'max_completion_tokens',
  'messages',
  'prompt',
  'response_format',
  'verbosity',
]);

export function sanitizeResponsesBodyForProxy(
  body: Record<string, unknown>,
  modelName: string,
  stream: boolean,
  options?: { defaultEncryptedReasoningInclude?: boolean },
): Record<string, unknown> {
  let normalized = normalizeResponsesBodyForCompatibility({
    ...body,
    model: modelName,
    stream,
  });

  if (normalized.input === undefined) {
    if (Array.isArray((normalized as Record<string, unknown>).messages)) {
      normalized = normalizeResponsesBodyForCompatibility(
        convertOpenAiBodyToResponsesBody(normalized, modelName, stream),
      );
    } else {
      const prompt = asTrimmedString((normalized as Record<string, unknown>).prompt);
      if (prompt) {
        normalized = {
          ...normalized,
          input: [toResponsesInputMessageFromText(prompt)],
        };
      }
    }
  }

  normalized = normalizeResponsesRequestFieldParity(normalized, {
    verbositySource: body.verbosity,
    defaultEncryptedReasoningInclude: options?.defaultEncryptedReasoningInclude,
  });

  const sanitized: Record<string, unknown> = { ...normalized };
  for (const key of RESPONSES_COMPATIBILITY_FILTER_FIELDS) {
    delete sanitized[key];
  }

  const maxOutputTokens = toFiniteNumber(normalized.max_output_tokens);
  if (maxOutputTokens !== null && maxOutputTokens > 0) {
    sanitized.max_output_tokens = Math.trunc(maxOutputTokens);
  } else {
    const maxCompletionTokens = toFiniteNumber(normalized.max_completion_tokens);
    if (maxCompletionTokens !== null && maxCompletionTokens > 0) {
      sanitized.max_output_tokens = Math.trunc(maxCompletionTokens);
    }
  }

  sanitized.model = modelName;
  sanitized.stream = stream;
  return sanitized;
}

export function convertOpenAiBodyToResponsesBody(
  openaiBody: Record<string, unknown>,
  modelName: string,
  stream: boolean,
): Record<string, unknown> {
  const rawMessages = Array.isArray(openaiBody.messages) ? openaiBody.messages : [];
  const systemContents: string[] = [];
  const inputItems: Array<Record<string, unknown>> = [];
  const toolNameMap = buildShortToolNameMap(collectOpenAiToolNames(openaiBody));

  for (const item of rawMessages) {
    if (!isRecord(item)) continue;
    const role = asTrimmedString(item.role).toLowerCase() || 'user';

    if (role === 'system' || role === 'developer') {
      const content = extractTextContent(item.content).trim();
      if (content) systemContents.push(content);
      continue;
    }

    if (role === 'assistant') {
      const reasoningContent = extractTextContent(
        item.reasoning_content
        ?? item.reasoning
        ?? item.thinking,
      ).trim();
      const reasoningSignature = asTrimmedString(item.reasoning_signature);
      if (reasoningContent || reasoningSignature) {
        const reasoningItem: Record<string, unknown> = {
          type: 'reasoning',
        };
        if (reasoningContent) {
          reasoningItem.summary = [{
            type: 'summary_text',
            text: reasoningContent,
          }];
        }
        if (reasoningSignature) {
          reasoningItem.encrypted_content = reasoningSignature;
        }
        inputItems.push(reasoningItem);
      }

      const normalizedContent = normalizeResponsesMessageContent('assistant', item.content);
      if (normalizedContent.length > 0) {
        inputItems.push({
          type: 'message',
          role: 'assistant',
          content: normalizedContent,
        });
      }

      const rawToolCalls = Array.isArray(item.tool_calls) ? item.tool_calls : [];
      for (let index = 0; index < rawToolCalls.length; index += 1) {
        const toolCall = rawToolCalls[index];
        if (!isRecord(toolCall)) continue;
        const functionPart = isRecord(toolCall.function) ? toolCall.function : {};
        const mcpItem = decodeResponsesMcpCompatToolCall(
          functionPart.name ?? toolCall.name,
          functionPart.arguments ?? toolCall.arguments,
        );
        if (mcpItem) {
          inputItems.push(mcpItem);
          continue;
        }
        const callId = asTrimmedString(toolCall.id) || `call_${Date.now()}_${index}`;
        const name = (
          asTrimmedString(functionPart.name)
          || asTrimmedString(toolCall.name)
          || `tool_${index}`
        );
        const argumentsValue = normalizeOpenAiToolArguments(
          functionPart.arguments ?? toolCall.arguments,
        );

        inputItems.push({
          type: 'function_call',
          call_id: callId,
          name: getShortToolName(name, toolNameMap),
          arguments: argumentsValue,
        });
      }
      continue;
    }

    if (role === 'tool') {
      const callId = asTrimmedString(item.tool_call_id) || asTrimmedString(item.id);
      if (!callId) continue;
      inputItems.push({
        type: 'function_call_output',
        call_id: callId,
        output: normalizeToolOutput(item.content),
      });
      continue;
    }

    const normalizedContent = normalizeResponsesMessageContent('user', item.content);
    if (normalizedContent.length <= 0) continue;
    inputItems.push({
      type: 'message',
      role: 'user',
      content: normalizedContent,
    });
  }

  const maxOutputTokens = (
    toFiniteNumber(openaiBody.max_output_tokens)
    ?? toFiniteNumber(openaiBody.max_completion_tokens)
    ?? toFiniteNumber(openaiBody.max_tokens)
    ?? 4096
  );

  const body: Record<string, unknown> = {
    model: modelName,
    stream,
    max_output_tokens: maxOutputTokens,
    input: inputItems,
  };

  if (systemContents.length > 0) {
    body.instructions = systemContents.join('\n\n');
  }

  const temperature = toFiniteNumber(openaiBody.temperature);
  if (temperature !== null) body.temperature = temperature;

  const topP = toFiniteNumber(openaiBody.top_p);
  if (topP !== null) body.top_p = topP;

  if (openaiBody.metadata !== undefined) body.metadata = openaiBody.metadata;
  if (openaiBody.modalities !== undefined) body.modalities = cloneJsonValue(openaiBody.modalities);
  if (openaiBody.audio !== undefined) body.audio = cloneJsonValue(openaiBody.audio);
  if (openaiBody.reasoning !== undefined) body.reasoning = openaiBody.reasoning;
  if (openaiBody.reasoning_effort !== undefined) body.reasoning_effort = openaiBody.reasoning_effort;
  if (openaiBody.reasoning_budget !== undefined) body.reasoning_budget = openaiBody.reasoning_budget;
  if (openaiBody.reasoning_summary !== undefined) body.reasoning_summary = openaiBody.reasoning_summary;
  if (openaiBody.parallel_tool_calls !== undefined) body.parallel_tool_calls = openaiBody.parallel_tool_calls;
  if (openaiBody.tools !== undefined) body.tools = convertOpenAiToolsToResponses(openaiBody.tools, toolNameMap);
  if (openaiBody.safety_identifier !== undefined) body.safety_identifier = openaiBody.safety_identifier;
  if (openaiBody.max_tool_calls !== undefined) body.max_tool_calls = openaiBody.max_tool_calls;
  if (openaiBody.prompt_cache_key !== undefined) body.prompt_cache_key = openaiBody.prompt_cache_key;
  if (openaiBody.prompt_cache_retention !== undefined) {
    body.prompt_cache_retention = openaiBody.prompt_cache_retention;
  }
  if (openaiBody.background !== undefined) body.background = openaiBody.background;
  if (openaiBody.user !== undefined) body.user = openaiBody.user;
  if (openaiBody.include !== undefined) body.include = cloneJsonValue(openaiBody.include);
  if (openaiBody.previous_response_id !== undefined) body.previous_response_id = openaiBody.previous_response_id;
  if (openaiBody.truncation !== undefined) body.truncation = openaiBody.truncation;
  if (openaiBody.service_tier !== undefined) body.service_tier = openaiBody.service_tier;
  if (openaiBody.top_logprobs !== undefined) body.top_logprobs = openaiBody.top_logprobs;
  if (openaiBody.stream_options !== undefined) body.stream_options = openaiBody.stream_options;
  if (openaiBody.response_format !== undefined) {
    const existingTextConfig = cloneRecord(body.text) || {};
    existingTextConfig.format = cloneJsonValue(openaiBody.response_format);
    body.text = existingTextConfig;
  }

  const textConfig = normalizeTextConfig(body.text, openaiBody.verbosity);
  if (textConfig) {
    body.text = textConfig;
  }

  const responsesToolChoice = convertOpenAiToolChoiceToResponses(openaiBody.tool_choice, toolNameMap);
  if (responsesToolChoice !== undefined) body.tool_choice = responsesToolChoice;
  if (Array.isArray(body.tools) && body.tools.length === 0) {
    delete body.tool_choice;
  }

  return normalizeResponsesBodyForCompatibility(
    normalizeResponsesRequestFieldParity(body, { verbositySource: openaiBody.verbosity }),
  );
}

type OpenAiToolCall = {
  id: string;
  type: 'function';
  function: {
    name: string;
    arguments: string;
  };
};

function toOpenAiToolCall(item: Record<string, unknown>, fallbackIndex: number): OpenAiToolCall | null {
  const callId = (
    asTrimmedString(item.call_id)
    || asTrimmedString(item.id)
    || `call_${Date.now()}_${fallbackIndex}`
  );
  const name = asTrimmedString(item.name);
  if (!name) return null;

  return {
    id: callId,
    type: 'function',
    function: {
      name,
      arguments: normalizeOpenAiToolArguments(item.arguments ?? item.input),
    },
  };
}

function normalizeOpenAiContentBlock(item: Record<string, unknown>): string | Record<string, unknown> | null {
  const type = asTrimmedString(item.type).toLowerCase();
  if (!type) {
    const text = extractTextContent(item).trim();
    return text ? { type: 'text', text } : null;
  }

  if (
    type === 'input_text'
    || type === 'output_text'
    || type === 'text'
    || type === 'summary_text'
    || type === 'reasoning_text'
  ) {
    const text = extractTextContent(item).trim();
    return text ? { type: 'text', text } : null;
  }

  if (type === 'input_image') {
    const imageUrl = item.image_url ?? item.url;
    if (imageUrl === undefined) return null;
    return {
      type: 'image_url',
      image_url: imageUrl,
    };
  }

  if (type === 'input_audio' && item.input_audio !== undefined) {
    return {
      type: 'input_audio',
      input_audio: item.input_audio,
    };
  }

  if (type === 'input_file' || type === 'file') {
    const fileBlock = normalizeInputFileBlock(item);
    return fileBlock ? toOpenAiChatFileBlock(fileBlock) : null;
  }

  if (type === 'reasoning' || type === 'thinking' || type === 'redacted_reasoning') {
    const text = extractTextContent(item).trim();
    return text ? { type: 'text', text } : null;
  }

  return item;
}

function toOpenAiMessageContent(content: unknown): string | Array<string | Record<string, unknown>> {
  if (typeof content === 'string') return content;
  if (!Array.isArray(content)) {
    if (isRecord(content)) {
      const single = normalizeOpenAiContentBlock(content);
      if (!single) return '';
      return typeof single === 'string' ? single : [single];
    }
    return '';
  }

  const blocks = content
    .map((item) => {
      if (typeof item === 'string') return item.trim() ? item : null;
      if (!isRecord(item)) return null;
      return normalizeOpenAiContentBlock(item);
    })
    .filter((item): item is string | Record<string, unknown> => !!item);

  if (blocks.length === 1 && typeof blocks[0] === 'string') {
    return blocks[0];
  }
  return blocks;
}

function convertResponsesToolsToOpenAi(rawTools: unknown): unknown {
  if (!Array.isArray(rawTools)) return rawTools;

  return rawTools
    .map((item) => {
      if (!isRecord(item)) return item;
      const type = asTrimmedString(item.type).toLowerCase();

      if (type === 'custom' || type === 'image_generation') return item;
      if (type !== 'function') return item;
      if (isRecord(item.function) && asTrimmedString(item.function.name)) return item;

      const name = asTrimmedString(item.name);
      if (!name) return null;

      const fn: Record<string, unknown> = { name };
      const description = asTrimmedString(item.description);
      if (description) fn.description = description;
      if (item.parameters !== undefined) fn.parameters = item.parameters;
      if (item.strict !== undefined) fn.strict = item.strict;

      return {
        type: 'function',
        function: fn,
      };
    })
    .filter((item): item is Record<string, unknown> => !!item);
}

function convertResponsesToolChoiceToOpenAi(rawToolChoice: unknown): unknown {
  if (rawToolChoice === undefined) return undefined;
  if (typeof rawToolChoice === 'string') return rawToolChoice;
  if (!isRecord(rawToolChoice)) return rawToolChoice;

  const type = asTrimmedString(rawToolChoice.type).toLowerCase();
  if (type === 'tool') {
    const name = asTrimmedString(rawToolChoice.name);
    if (!name) return 'required';
    return {
      type: 'function',
      function: { name },
    };
  }
  if (type === 'function') {
    if (isRecord(rawToolChoice.function) && asTrimmedString(rawToolChoice.function.name)) {
      return rawToolChoice;
    }

    const name = asTrimmedString(rawToolChoice.name);
    if (!name) return 'required';
    return {
      type: 'function',
      function: { name },
    };
  }

  if (type === 'auto' || type === 'none' || type === 'required') {
    return type;
  }

  return rawToolChoice;
}

export function convertResponsesBodyToOpenAiBody(
  body: Record<string, unknown>,
  modelName: string,
  stream: boolean,
  options?: { defaultEncryptedReasoningInclude?: boolean },
): Record<string, unknown> {
  const normalizedBody = normalizeResponsesBodyForCompatibility(
    normalizeResponsesRequestFieldParity(body, {
      defaultEncryptedReasoningInclude: options?.defaultEncryptedReasoningInclude,
    }),
  );
  const messages: Array<Record<string, unknown>> = [];
  const input = stripOrphanedResponsesToolOutputs(normalizedBody.input);
  let functionCallIndex = 0;
  let pendingToolCalls: OpenAiToolCall[] = [];

  const flushPendingToolCalls = () => {
    if (pendingToolCalls.length <= 0) return;
    messages.push({
      role: 'assistant',
      content: '',
      tool_calls: pendingToolCalls,
    });
    pendingToolCalls = [];
  };

  const pushToolOutputMessage = (callIdRaw: unknown, outputRaw: unknown) => {
    const toolCallId = asTrimmedString(callIdRaw);
    if (!toolCallId) return;
    messages.push({
      role: 'tool',
      tool_call_id: toolCallId,
      content: normalizeToolOutput(outputRaw),
    });
  };

  const processInputItem = (item: unknown) => {
    if (typeof item === 'string') {
      flushPendingToolCalls();
      const text = item.trim();
      if (text) messages.push({ role: 'user', content: text });
      return;
    }

    if (!isRecord(item)) return;

    const itemType = asTrimmedString(item.type).toLowerCase();
    if (itemType.startsWith('mcp_') && isResponsesMcpItem(item)) {
      const toolCall = toResponsesMcpCompatToolCall(item, `call_${Date.now()}_${functionCallIndex}`);
      if (toolCall) {
        pendingToolCalls.push(toolCall as OpenAiToolCall);
        functionCallIndex += 1;
        return;
      }
    }

    if (itemType === 'function_call' || itemType === 'custom_tool_call') {
      const toolCall = toOpenAiToolCall(item, functionCallIndex);
      functionCallIndex += 1;
      if (toolCall) pendingToolCalls.push(toolCall);
      return;
    }

    if (itemType === 'function_call_output' || itemType === 'custom_tool_call_output') {
      flushPendingToolCalls();
      pushToolOutputMessage(item.call_id ?? item.id, item.output ?? item.content);
      return;
    }

    if (itemType === 'reasoning') {
      flushPendingToolCalls();
      const reasoningContent = toOpenAiMessageContent(item.summary ?? item.content ?? item);
      const reasoningSignature = asTrimmedString(item.encrypted_content);
      const hasReasoningContent = typeof reasoningContent === 'string'
        ? reasoningContent.trim().length > 0
        : Array.isArray(reasoningContent) && reasoningContent.length > 0;
      if (!hasReasoningContent && !reasoningSignature) return;

      const message: Record<string, unknown> = {
        role: 'assistant',
        content: reasoningContent,
      };
      if (reasoningSignature) {
        message.reasoning_signature = reasoningSignature;
      }
      messages.push(message);
      return;
    }

    flushPendingToolCalls();
    const role = asTrimmedString(item.role).toLowerCase() || 'user';
    const normalizedRole = role === 'developer' ? 'system' : role;
    const content = toOpenAiMessageContent(item.content ?? item.input ?? item);

    if (normalizedRole === 'tool') {
      pushToolOutputMessage(item.tool_call_id ?? item.call_id ?? item.id, item.content);
      return;
    }

    const hasContent = typeof content === 'string'
      ? content.trim().length > 0
      : Array.isArray(content) && content.length > 0;
    if (!hasContent) return;

    const message: Record<string, unknown> = {
      role: normalizedRole,
      content,
    };
    const phase = asTrimmedString(item.phase);
    if (phase) message.phase = phase;
    messages.push(message);
  };

  if (typeof input === 'string') {
    const text = input.trim();
    if (text) messages.push({ role: 'user', content: text });
  } else if (Array.isArray(input)) {
    for (const item of input) processInputItem(item);
  } else if (isRecord(input)) {
    processInputItem(input);
  }
  flushPendingToolCalls();

  const instructions = asTrimmedString(normalizedBody.instructions);
  if (instructions) {
    messages.unshift({ role: 'system', content: instructions });
  }

  const payload: Record<string, unknown> = {
    model: modelName,
    stream,
    messages,
  };

  if (typeof normalizedBody.temperature === 'number' && Number.isFinite(normalizedBody.temperature)) {
    payload.temperature = normalizedBody.temperature;
  }
  if (typeof normalizedBody.top_p === 'number' && Number.isFinite(normalizedBody.top_p)) {
    payload.top_p = normalizedBody.top_p;
  }
  if (typeof normalizedBody.max_output_tokens === 'number' && Number.isFinite(normalizedBody.max_output_tokens)) {
    payload.max_tokens = normalizedBody.max_output_tokens;
  }
  if (normalizedBody.metadata !== undefined) payload.metadata = cloneJsonValue(normalizedBody.metadata);
  if (normalizedBody.modalities !== undefined) payload.modalities = cloneJsonValue(normalizedBody.modalities);
  if (normalizedBody.audio !== undefined) payload.audio = cloneJsonValue(normalizedBody.audio);
  if (normalizedBody.parallel_tool_calls !== undefined) payload.parallel_tool_calls = normalizedBody.parallel_tool_calls;
  if (normalizedBody.tools !== undefined) payload.tools = convertResponsesToolsToOpenAi(normalizedBody.tools);
  if (normalizedBody.tool_choice !== undefined) payload.tool_choice = convertResponsesToolChoiceToOpenAi(normalizedBody.tool_choice);
  if (Array.isArray(payload.tools) && payload.tools.length === 0) {
    delete payload.tool_choice;
  }
  if (normalizedBody.safety_identifier !== undefined) payload.safety_identifier = normalizedBody.safety_identifier;
  if (normalizedBody.max_tool_calls !== undefined) payload.max_tool_calls = normalizedBody.max_tool_calls;
  if (normalizedBody.prompt_cache_key !== undefined) payload.prompt_cache_key = normalizedBody.prompt_cache_key;
  if (normalizedBody.prompt_cache_retention !== undefined) payload.prompt_cache_retention = normalizedBody.prompt_cache_retention;
  if (normalizedBody.background !== undefined) payload.background = normalizedBody.background;
  if (normalizedBody.user !== undefined) payload.user = normalizedBody.user;
  if (normalizedBody.include !== undefined) payload.include = cloneJsonValue(normalizedBody.include);
  if (normalizedBody.previous_response_id !== undefined) payload.previous_response_id = normalizedBody.previous_response_id;
  if (normalizedBody.truncation !== undefined) payload.truncation = normalizedBody.truncation;
  if (normalizedBody.reasoning !== undefined) payload.reasoning = cloneJsonValue(normalizedBody.reasoning);
  if (normalizedBody.service_tier !== undefined) payload.service_tier = normalizedBody.service_tier;
  if (normalizedBody.top_logprobs !== undefined) payload.top_logprobs = normalizedBody.top_logprobs;
  if (normalizedBody.stream_options !== undefined) payload.stream_options = normalizedBody.stream_options;
  if (isRecord(normalizedBody.text) && normalizedBody.text.format !== undefined) {
    payload.response_format = cloneJsonValue(normalizedBody.text.format);
  }
  if (isRecord(normalizedBody.text) && asTrimmedString(normalizedBody.text.verbosity)) {
    payload.verbosity = asTrimmedString(normalizedBody.text.verbosity);
  }

  return payload;
}

export { normalizeResponsesInputForCompatibility };
