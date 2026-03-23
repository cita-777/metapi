import {
  decodeAnthropicReasoningSignature,
} from './reasoningTransport.js';
import { toOpenAiChatFileBlock } from './inputFile.js';
import {
  consumeThinkTaggedText,
  createThinkTagParserState,
  extractInlineThinkTags,
  type ThinkTagParserState,
} from './thinkTagParser.js';

export type DownstreamFormat = 'openai' | 'claude';

export type ParsedSseEvent = {
  event: string;
  data: string;
};

export type StreamTransformContext = {
  id: string;
  model: string;
  created: number;
  roleSent: boolean;
  doneSent: boolean;
  toolCalls: Record<number, { id?: string; name?: string; arguments?: string }>;
  thinkTagParser: ThinkTagParserState;
};

export type ClaudeDownstreamContext = {
  messageStarted: boolean;
  contentBlockStarted: boolean;
  doneSent: boolean;
  textBlockIndex: number | null;
  nextContentBlockIndex: number;
  toolBlocks: Record<number, {
    contentIndex: number;
    id: string;
    name: string;
    open: boolean;
  }>;
};

export type NormalizedStreamEvent = {
  role?: 'assistant';
  contentDelta?: string;
  reasoningDelta?: string;
  reasoningSignature?: string;
  redactedReasoningContent?: string;
  toolCallDeltas?: Array<{
    index: number;
    id?: string;
    name?: string;
    argumentsDelta?: string;
  }>;
  finishReason?: string | null;
  done?: boolean;
};

export type NormalizedFinalResponse = {
  id: string;
  model: string;
  created: number;
  content: string;
  reasoningContent: string;
  reasoningSignature?: string;
  redactedReasoningContent?: string;
  finishReason: string;
  toolCalls: Array<{
    id: string;
    name: string;
    arguments: string;
  }>;
};

export type ParsedDownstreamChatRequest = {
  requestedModel: string;
  isStream: boolean;
  upstreamBody: Record<string, unknown>;
  claudeOriginalBody?: Record<string, unknown>;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object';
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

function asTrimmedString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function pickFiniteNumber(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}

function ensureIntegerTimestamp(value: unknown, fallback: number): number {
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0) return fallback;
  return Math.trunc(n);
}

function joinNonEmpty(parts: string[]): string {
  return parts.map((item) => item.trim()).filter((item) => item.length > 0).join('\n\n');
}

function textFromPart(part: unknown): string {
  if (typeof part === 'string') return part;
  if (!isRecord(part)) return '';

  if (typeof part.text === 'string') return part.text;
  if (typeof part.content === 'string') return part.content;
  if (typeof part.output_text === 'string') return part.output_text;
  if (typeof part.completion === 'string') return part.completion;
  if (typeof part.partial_json === 'string') return part.partial_json;

  if (Array.isArray(part.content)) {
    return part.content.map((item) => textFromPart(item)).join('');
  }

  if (isRecord(part.delta)) {
    const fromDelta = textFromPart(part.delta);
    if (fromDelta) return fromDelta;
  }

  return '';
}

function extractTextAndReasoning(value: unknown): { content: string; reasoning: string } {
  if (typeof value === 'string') return extractInlineThinkTags(value);
  if (Array.isArray(value)) {
    const contentParts: string[] = [];
    const reasoningParts: string[] = [];
    for (const item of value) {
      if (typeof item === 'string') {
        const parsedString = extractInlineThinkTags(item);
        if (parsedString.content) contentParts.push(parsedString.content);
        if (parsedString.reasoning) reasoningParts.push(parsedString.reasoning);
        continue;
      }
      if (!isRecord(item)) continue;
      const type = typeof item.type === 'string' ? item.type : '';

      if (type === 'thinking' && typeof item.thinking === 'string') {
        reasoningParts.push(item.thinking);
        continue;
      }
      if (type === 'thinking_delta' && typeof item.text === 'string') {
        reasoningParts.push(item.text);
        continue;
      }
      if (typeof item.thought === 'boolean' && item.thought && typeof item.text === 'string') {
        reasoningParts.push(item.text);
        continue;
      }

      const parsedText = extractInlineThinkTags(textFromPart(item));
      if (parsedText.content) contentParts.push(parsedText.content);
      if (parsedText.reasoning) reasoningParts.push(parsedText.reasoning);
    }

    return {
      content: contentParts.join(''),
      reasoning: reasoningParts.join(''),
    };
  }

  if (!isRecord(value)) return { content: '', reasoning: '' };

  if (Array.isArray(value.parts)) {
    return extractTextAndReasoning(value.parts);
  }

  const directReasoning = joinNonEmpty([
    typeof value.reasoning_content === 'string' ? value.reasoning_content : '',
    typeof value.reasoning === 'string' ? value.reasoning : '',
    typeof value.thinking === 'string' ? value.thinking : '',
  ]);
  const parsedText = extractInlineThinkTags(textFromPart(value));

  return {
    content: parsedText.content,
    reasoning: joinNonEmpty([directReasoning, parsedText.reasoning]),
  };
}

function extractStreamingTextAndReasoning(
  value: unknown,
  thinkTagParser: ThinkTagParserState,
): { content: string; reasoning: string } {
  const parsed = extractTextAndReasoning(value);
  if (!parsed.content) {
    return parsed;
  }

  const streamed = consumeThinkTaggedText(thinkTagParser, parsed.content);
  return {
    content: streamed.content,
    reasoning: [parsed.reasoning, streamed.reasoning]
      .filter((part) => part.length > 0)
      .join(''),
  };
}

export function normalizeStopReason(raw: unknown): string | null {
  const value = typeof raw === 'string' ? raw.trim().toLowerCase() : '';
  if (!value) return null;

  if (value === 'failed' || value === 'error') {
    return 'error';
  }

  if (
    value === 'end_turn'
    || value === 'stop'
    || value === 'end'
    || value === 'eos'
    || value === 'finished'
    || value === 'completed'
    || value === 'stop_sequence'
  ) {
    return 'stop';
  }

  if (
    value === 'incomplete'
    || value === 'max_tokens'
    || value === 'length'
    || value === 'max_output_tokens'
    || value === 'max_tokens_exceeded'
    || value.includes('max')
  ) {
    return 'length';
  }

  if (value === 'tool_use' || value === 'tool_calls' || value.includes('tool')) {
    return 'tool_calls';
  }

  return null;
}

export function toClaudeStopReason(finishReason: string | null | undefined): string {
  const value = normalizeStopReason(finishReason);
  if (value === 'length') return 'max_tokens';
  if (value === 'tool_calls') return 'tool_use';
  return 'end_turn';
}

export function createStreamTransformContext(modelName: string): StreamTransformContext {
  return {
    id: `chatcmpl-meta-${Date.now()}`,
    model: modelName,
    created: Math.floor(Date.now() / 1000),
    roleSent: false,
    doneSent: false,
    toolCalls: {},
    thinkTagParser: createThinkTagParserState(),
  };
}

export function createClaudeDownstreamContext(): ClaudeDownstreamContext {
  return {
    messageStarted: false,
    contentBlockStarted: false,
    doneSent: false,
    textBlockIndex: null,
    nextContentBlockIndex: 0,
    toolBlocks: {},
  };
}

function buildClaudeMessageId(sourceId: string): string {
  if (sourceId.startsWith('msg_')) return sourceId;
  const sanitized = sourceId.replace(/[^A-Za-z0-9_-]/g, '_');
  return `msg_${sanitized || Date.now()}`;
}

function serializeSse(event: string, data: unknown): string {
  const payload = typeof data === 'string' ? data : JSON.stringify(data);
  if (event) {
    return `event: ${event}\ndata: ${payload}\n\n`;
  }
  return `data: ${payload}\n\n`;
}

function extractAssistantContent(choice: any): string {
  const messageContent = choice?.message?.content;
  const parsedMessage = extractTextAndReasoning(messageContent).content;
  if (parsedMessage) return parsedMessage;

  const content = extractTextAndReasoning(choice?.content).content;
  if (content) return content;

  if (typeof choice?.text === 'string' && choice.text.length > 0) {
    return extractInlineThinkTags(choice.text).content;
  }
  if (typeof choice?.completion === 'string' && choice.completion.length > 0) {
    return extractInlineThinkTags(choice.completion).content;
  }
  if (typeof choice?.output_text === 'string' && choice.output_text.length > 0) {
    return extractInlineThinkTags(choice.output_text).content;
  }
  if (typeof choice?.delta?.content === 'string' && choice.delta.content.length > 0) {
    return extractInlineThinkTags(choice.delta.content).content;
  }

  return '';
}

function extractAssistantReasoning(choice: any): string {
  const message = choice?.message || {};
  const direct = [
    message.reasoning_content,
    message.reasoning,
    choice?.reasoning_content,
    choice?.reasoning,
  ].find((item) => typeof item === 'string' && item.length > 0);

  if (typeof direct === 'string') return direct;

  const parsed = extractTextAndReasoning(message.content);
  if (parsed.reasoning) return parsed.reasoning;

  const nested = extractTextAndReasoning(choice?.content).reasoning;
  if (nested) return nested;

  if (typeof choice?.delta?.content === 'string' && choice.delta.content.length > 0) {
    const parsedDelta = extractInlineThinkTags(choice.delta.content);
    if (parsedDelta.reasoning) return parsedDelta.reasoning;
  }

  return '';
}

function parseClaudeMessageContent(content: unknown): string {
  return extractTextAndReasoning(content).content;
}

function buildOpenAiImageUrlBlock(url: string): Record<string, unknown> {
  return {
    type: 'image_url',
    image_url: { url },
  };
}

function buildOpenAiFileBlock(input: {
  fileData?: string;
  fileUrl?: string;
  filename?: string;
  mimeType?: string;
}): Record<string, unknown> | null {
  const fileData = typeof input.fileData === 'string' ? input.fileData.trim() : '';
  const fileUrl = typeof input.fileUrl === 'string' ? input.fileUrl.trim() : '';
  const filename = typeof input.filename === 'string' ? input.filename.trim() : '';
  const mimeType = typeof input.mimeType === 'string' ? input.mimeType.trim() : '';
  if (!fileData && !fileUrl) return null;

  const file: Record<string, unknown> = {};
  if (fileData) file.file_data = fileData;
  if (fileUrl && !fileData) file.file_url = fileUrl;
  if (filename) file.filename = filename;
  if (mimeType) file.mime_type = mimeType;
  return {
    type: 'file',
    file,
  };
}

function convertClaudeContentBlockToOpenAi(block: Record<string, unknown>): Record<string, unknown> | null {
  const blockType = typeof block.type === 'string' ? block.type : '';

  if (blockType === 'text') {
    const text = parseClaudeMessageContent(block);
    return text ? { type: 'text', text } : null;
  }

  if (blockType === 'image') {
    const source = isRecord(block.source) ? block.source : null;
    const sourceType = typeof source?.type === 'string' ? source.type : '';
    if (sourceType === 'url' && typeof source?.url === 'string' && source.url.trim()) {
      return buildOpenAiImageUrlBlock(source.url.trim());
    }
    if (
      sourceType === 'base64'
      && typeof source?.media_type === 'string'
      && source.media_type.trim()
      && typeof source?.data === 'string'
      && source.data.trim()
    ) {
      return buildOpenAiImageUrlBlock(`data:${source.media_type.trim()};base64,${source.data.trim()}`);
    }
    return null;
  }

  if (blockType === 'document') {
    const source = isRecord(block.source) ? block.source : null;
    const sourceType = typeof source?.type === 'string' ? source.type : '';
    return buildOpenAiFileBlock({
      fileData: sourceType === 'base64' && typeof source?.data === 'string' ? source.data : undefined,
      fileUrl: sourceType === 'url' && typeof source?.url === 'string' ? source.url : undefined,
      filename: typeof block.title === 'string' ? block.title : undefined,
      mimeType: typeof source?.media_type === 'string' ? source.media_type : undefined,
    });
  }

  const text = parseClaudeMessageContent(block);
  return text ? { type: 'text', text } : null;
}

function buildOpenAiMessageContent(
  contentBlocks: Array<Record<string, unknown>>,
): string | Array<Record<string, unknown>> | undefined {
  if (contentBlocks.length <= 0) return undefined;
  if (contentBlocks.every((block) => block.type === 'text' && typeof block.text === 'string')) {
    return contentBlocks
      .map((block) => String(block.text).trim())
      .filter(Boolean)
      .join('\n\n');
  }
  return contentBlocks;
}

function parseResponsesOutputText(payload: Record<string, unknown>): string {
  const direct = typeof payload.output_text === 'string' ? payload.output_text : '';
  if (direct) return direct;

  const output = Array.isArray(payload.output) ? payload.output : [];
  const parts: string[] = [];
  for (const item of output) {
    if (!isRecord(item)) continue;
    const parsed = extractTextAndReasoning(item.content ?? item);
    if (parsed.content) parts.push(parsed.content);
  }

  return parts.join('\n\n');
}

function parseResponsesReasoning(payload: Record<string, unknown>): {
  reasoningContent: string;
  reasoningSignature?: string;
} {
  const output = Array.isArray(payload.output) ? payload.output : [];
  const reasoningParts: string[] = [];
  let reasoningSignature = '';

  for (const item of output) {
    if (!isRecord(item)) continue;
    if (asTrimmedString(item.type).toLowerCase() !== 'reasoning') continue;

    const parsed = extractTextAndReasoning(item.summary ?? item.content ?? item);
    const text = joinNonEmpty([parsed.content, parsed.reasoning]);
    if (text) reasoningParts.push(text);

    const encrypted = asTrimmedString(item.encrypted_content);
    if (!reasoningSignature && encrypted) {
      reasoningSignature = encrypted;
    }
  }

  return {
    reasoningContent: joinNonEmpty(reasoningParts),
    ...(reasoningSignature ? { reasoningSignature } : {}),
  };
}

function stringifyUnknownValue(value: unknown): string {
  if (typeof value === 'string') return value;
  if (value === undefined || value === null) return '';
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  if (Array.isArray(value) || isRecord(value)) {
    try {
      return JSON.stringify(value);
    } catch {
      return '';
    }
  }
  return '';
}

function parseJsonLike(value: string): unknown {
  const trimmed = value.trim();
  if (!trimmed) return {};
  try {
    return JSON.parse(trimmed);
  } catch {
    return { value };
  }
}

function collectToolCallsFromOpenAiChoice(choice: any): Array<{ id: string; name: string; arguments: string }> {
  const message = isRecord(choice?.message) ? choice.message : {};
  const rawToolCalls = Array.isArray((message as any).tool_calls)
    ? (message as any).tool_calls
    : (Array.isArray(choice?.tool_calls) ? choice.tool_calls : []);

  const toolCalls: Array<{ id: string; name: string; arguments: string }> = [];
  for (let index = 0; index < rawToolCalls.length; index += 1) {
    const rawToolCall = rawToolCalls[index];
    if (!isRecord(rawToolCall)) continue;
    const fn = isRecord(rawToolCall.function) ? rawToolCall.function : {};
    const id = (
      typeof rawToolCall.id === 'string' && rawToolCall.id.trim().length > 0
        ? rawToolCall.id.trim()
        : `call_${index}`
    );
    const name = (
      typeof fn.name === 'string' && fn.name.trim().length > 0
        ? fn.name.trim()
        : (typeof rawToolCall.name === 'string' ? rawToolCall.name.trim() : '')
    );
    const argumentsText = (
      typeof fn.arguments === 'string'
        ? fn.arguments
        : stringifyUnknownValue(fn.arguments ?? rawToolCall.arguments)
    );
    toolCalls.push({
      id,
      name,
      arguments: argumentsText,
    });
  }

  return toolCalls;
}

function collectToolCallsFromClaudeContent(content: unknown): Array<{ id: string; name: string; arguments: string }> {
  const contentItems = Array.isArray(content) ? content : [];
  const toolCalls: Array<{ id: string; name: string; arguments: string }> = [];

  for (let index = 0; index < contentItems.length; index += 1) {
    const block = contentItems[index];
    if (!isRecord(block)) continue;
    if (block.type !== 'tool_use') continue;

    const id = (
      typeof block.id === 'string' && block.id.trim().length > 0
        ? block.id.trim()
        : `toolu_${index}`
    );
    const name = typeof block.name === 'string' ? block.name.trim() : '';
    const argumentsText = stringifyUnknownValue(block.input);
    toolCalls.push({
      id,
      name,
      arguments: argumentsText,
    });
  }

  return toolCalls;
}

function collectToolCallsFromResponsesPayload(payload: Record<string, unknown>): Array<{ id: string; name: string; arguments: string }> {
  const output = Array.isArray(payload.output) ? payload.output : [];
  const toolCalls: Array<{ id: string; name: string; arguments: string }> = [];

  for (let index = 0; index < output.length; index += 1) {
    const item = output[index];
    if (!isRecord(item)) continue;
    if (item.type !== 'function_call') continue;

    const id = (
      typeof item.call_id === 'string' && item.call_id.trim().length > 0
        ? item.call_id.trim()
        : (typeof item.id === 'string' && item.id.trim().length > 0 ? item.id.trim() : `call_${index}`)
    );
    const name = typeof item.name === 'string' ? item.name.trim() : '';
    const argumentsText = (
      typeof item.arguments === 'string'
        ? item.arguments
        : stringifyUnknownValue(item.arguments)
    );
    toolCalls.push({
      id,
      name,
      arguments: argumentsText,
    });
  }

  return toolCalls;
}

function formatAnthropicBase64DataUrl(mimeType: string, data: string): string {
  return `data:${mimeType};base64,${data}`;
}

function parseAnthropicBase64Source(
  source: unknown,
): { mimeType: string; data: string } | null {
  if (!isRecord(source)) return null;
  const sourceType = asTrimmedString(source.type).toLowerCase();
  if (sourceType !== 'base64') return null;
  const mimeType = (
    asTrimmedString(source.media_type)
    || asTrimmedString(source.mime_type)
    || asTrimmedString(source.mediaType)
    || asTrimmedString(source.mimeType)
    || 'application/octet-stream'
  );
  const data = asTrimmedString(source.data);
  if (!data) return null;
  return { mimeType, data };
}

function parseAnthropicUrlSource(
  source: unknown,
): { url: string; mimeType: string | null } | null {
  if (!isRecord(source)) return null;
  const sourceType = asTrimmedString(source.type).toLowerCase();
  if (sourceType !== 'url') return null;
  const url = asTrimmedString(source.url);
  if (!url) return null;
  const mimeType = (
    asTrimmedString(source.media_type)
    || asTrimmedString(source.mime_type)
    || asTrimmedString(source.mediaType)
    || asTrimmedString(source.mimeType)
    || null
  );
  return { url, mimeType };
}

function toOpenAiContentBlockFromClaudeBlock(
  block: Record<string, unknown>,
): Record<string, unknown> | null {
  const blockType = asTrimmedString(block.type).toLowerCase();

  if (blockType === 'text') {
    const text = asTrimmedString(block.text);
    return text ? { type: 'text', text } : null;
  }

  if (blockType !== 'image' && blockType !== 'document') {
    return null;
  }

  const title = asTrimmedString(block.title);
  const base64Source = parseAnthropicBase64Source(block.source);
  const urlSource = parseAnthropicUrlSource(block.source);
  const mimeType = (base64Source?.mimeType || urlSource?.mimeType || '').toLowerCase();
  const treatAsImage = blockType === 'image' || mimeType.startsWith('image/');

  if (treatAsImage) {
    const imageUrl = base64Source
      ? formatAnthropicBase64DataUrl(base64Source.mimeType, base64Source.data)
      : (urlSource?.url || '');
    return imageUrl
      ? {
        type: 'image_url',
        image_url: { url: imageUrl },
      }
      : null;
  }

  if (base64Source) {
    return toOpenAiChatFileBlock({
      fileData: base64Source.data,
      filename: title || undefined,
      mimeType: base64Source.mimeType,
    });
  }

  if (urlSource) {
    return toOpenAiChatFileBlock({
      fileUrl: urlSource.url,
      filename: title || undefined,
      mimeType: urlSource.mimeType,
    });
  }

  return null;
}

function collapseOpenAiContentBlocks(
  blocks: Array<Record<string, unknown>>,
): string | Array<Record<string, unknown>> | null {
  if (blocks.length <= 0) return null;
  const textOnly = blocks.every((block) => block.type === 'text' && typeof block.text === 'string');
  if (!textOnly) return blocks;

  const text = blocks
    .map((block) => (typeof block.text === 'string' ? block.text : ''))
    .join('\n\n')
    .trim();
  return text || null;
}

function pickPositiveInteger(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value) && value > 0) {
    return Math.trunc(value);
  }
  if (typeof value === 'string') {
    const parsed = Number.parseInt(value, 10);
    if (Number.isFinite(parsed) && parsed > 0) return parsed;
  }
  return undefined;
}

function convertClaudeToolsToOpenAiChat(rawTools: unknown): unknown {
  if (!Array.isArray(rawTools)) return rawTools;

  return rawTools.map((item) => {
    if (!isRecord(item)) return item;

    const type = asTrimmedString(item.type).toLowerCase();
    if (type === 'function' || type === 'custom' || type === 'image_generation') {
      return item;
    }

    const name = asTrimmedString(item.name);
    if (!name) return item;

    return {
      type: 'function',
      function: {
        name,
        ...(asTrimmedString(item.description)
          ? { description: asTrimmedString(item.description) }
          : {}),
        parameters: isRecord(item.input_schema)
          ? item.input_schema
          : (isRecord(item.parameters) ? item.parameters : { type: 'object' }),
      },
    };
  });
}

function convertClaudeToolChoiceToOpenAiChat(rawToolChoice: unknown): unknown {
  if (rawToolChoice === undefined) return undefined;
  if (typeof rawToolChoice === 'string') {
    const normalized = rawToolChoice.trim().toLowerCase();
    if (normalized === 'any') return 'required';
    return normalized || rawToolChoice;
  }
  if (!isRecord(rawToolChoice)) return rawToolChoice;

  const type = asTrimmedString(rawToolChoice.type).toLowerCase();
  if (type === 'auto' || type === 'none') return type;
  if (type === 'any' || type === 'required') return 'required';
  if (type === 'function' && isRecord(rawToolChoice.function)) {
    const name = asTrimmedString(rawToolChoice.function.name);
    return name
      ? {
        type: 'function',
        function: { name },
      }
      : 'required';
  }
  if (type !== 'tool') return rawToolChoice;

  const name = asTrimmedString(
    rawToolChoice.name
    ?? (isRecord(rawToolChoice.tool) ? rawToolChoice.tool.name : undefined),
  );
  return name
    ? {
      type: 'function',
      function: { name },
    }
    : 'required';
}

function extractClaudeReasoningRequest(
  body: Record<string, unknown>,
): { reasoningEffort?: string; reasoningBudget?: number } {
  const thinking = isRecord(body.thinking) ? body.thinking : null;
  const outputConfig = isRecord(body.output_config) ? body.output_config : null;
  const reasoningEffort = asTrimmedString(outputConfig?.effort).toLowerCase();
  const reasoningBudget = pickPositiveInteger(
    thinking?.budget_tokens
    ?? thinking?.budgetTokens,
  );

  return {
    ...(reasoningEffort ? { reasoningEffort } : {}),
    ...(reasoningBudget !== undefined ? { reasoningBudget } : {}),
  };
}

export function convertClaudeRequestToOpenAiBody(body: Record<string, unknown>): {
  model: string;
  stream: boolean;
  messages: Array<Record<string, unknown>>;
  payload: Record<string, unknown>;
} {
  const model = typeof body.model === 'string' ? body.model.trim() : '';
  const stream = body.stream === true;

  const messages: Array<Record<string, unknown>> = [];

  const convertToolResultContent = (content: unknown): string | Array<Record<string, unknown>> | null => {
    const blocks: Array<Record<string, unknown>> = [];

    const appendContentBlock = (item: unknown) => {
      if (isRecord(item)) {
        const block = toOpenAiContentBlockFromClaudeBlock(item);
        if (block) {
          blocks.push(block);
          return;
        }
      }
      const text = parseClaudeMessageContent(item);
      if (text) {
        blocks.push({ type: 'text', text });
      }
    };

    const valueToProcess = (isRecord(content) && Array.isArray(content.content))
      ? (content.content as unknown[])
      : content;

    if (Array.isArray(valueToProcess)) {
      for (const item of valueToProcess) {
        appendContentBlock(item);
      }
    } else {
      appendContentBlock(valueToProcess);
    }

    if (blocks.length <= 0) return null;
    const collapsed = collapseOpenAiContentBlocks(blocks);
    if (!collapsed) return null;
    if (typeof collapsed === 'string' && collapsed.length === 0) return null;
    return collapsed;
  };

  const appendMessage = (role: string, content: unknown) => {
    const text = parseClaudeMessageContent(content);
    if (!text) return;
    messages.push({ role, content: text });
  };

  const appendToolResultMessage = (toolUseId: unknown, content: unknown) => {
    const toolCallId = typeof toolUseId === 'string' ? toolUseId.trim() : '';
    if (!toolCallId) return;

    const contentPayload = convertToolResultContent(content);
    if (!contentPayload) return;

    messages.push({
      role: 'tool',
      tool_call_id: toolCallId,
      content: contentPayload,
    });
  };

  const system = body.system;
  if (typeof system === 'string') {
    appendMessage('system', system);
  } else if (Array.isArray(system)) {
    const merged = system.map((item) => parseClaudeMessageContent(item)).filter((item) => item.length > 0).join('\n\n');
    if (merged) appendMessage('system', merged);
  }

  const rawMessages = Array.isArray(body.messages) ? body.messages : [];
  for (const message of rawMessages) {
    if (!isRecord(message)) continue;
    const role = typeof message.role === 'string' ? message.role : 'user';
    const mappedRole = role === 'assistant' || role === 'system' ? role : 'user';
    const content = message.content;

    if (!Array.isArray(content)) {
      appendMessage(mappedRole, content);
      continue;
    }

    // Claude tool blocks need explicit OpenAI mapping:
    // - assistant.tool_use  -> assistant.tool_calls
    // - user.tool_result    -> tool messages with tool_call_id
    const contentBlocks: Array<Record<string, unknown>> = [];
    const toolCalls: Array<Record<string, unknown>> = [];
    const reasoningParts: string[] = [];

    const flushContentAsMessage = () => {
      const contentPayload = collapseOpenAiContentBlocks(contentBlocks);
      contentBlocks.length = 0;
      if (contentPayload === null) return;
      messages.push({ role: mappedRole, content: contentPayload });
    };

    for (const block of content) {
      if (!isRecord(block)) continue;
      const blockType = typeof block.type === 'string' ? block.type : '';

      if (blockType === 'tool_result') {
        appendToolResultMessage(block.tool_use_id, block.content);
        continue;
      }

      if (mappedRole === 'assistant' && blockType === 'tool_use') {
        const id = typeof block.id === 'string' && block.id.trim().length > 0
          ? block.id.trim()
          : `call_${toolCalls.length}`;
        const name = typeof block.name === 'string' ? block.name.trim() : '';
        const rawInput = block.input;
        const args = (
          typeof rawInput === 'string'
            ? rawInput
            : stringifyUnknownValue(rawInput) || '{}'
        );

        const fn: Record<string, unknown> = { arguments: args };
        if (name) fn.name = name;

        toolCalls.push({
          id,
          type: 'function',
          function: fn,
        });
        continue;
      }

      const extracted = extractTextAndReasoning(block);
      if (mappedRole === 'assistant' && extracted.reasoning) {
        reasoningParts.push(extracted.reasoning);
      }

      const contentBlock = toOpenAiContentBlockFromClaudeBlock(block);
      if (contentBlock) {
        contentBlocks.push(contentBlock);
        continue;
      }

      const text = extracted.content || parseClaudeMessageContent(block);
      if (text) {
        contentBlocks.push({
          type: 'text',
          text,
        });
      }
    }

    const merged = collapseOpenAiContentBlocks(contentBlocks);
    if (toolCalls.length > 0) {
      const assistantMessage: Record<string, unknown> = {
        role: 'assistant',
        tool_calls: toolCalls,
      };
      assistantMessage.content = merged || '';
      const reasoningContent = joinNonEmpty(reasoningParts);
      if (reasoningContent) assistantMessage.reasoning_content = reasoningContent;
      messages.push(assistantMessage);
    } else if (merged !== null || (mappedRole === 'assistant' && reasoningParts.length > 0)) {
      const nextMessage: Record<string, unknown> = {
        role: mappedRole,
        content: merged ?? '',
      };
      if (mappedRole === 'assistant') {
        const reasoningContent = joinNonEmpty(reasoningParts);
        if (reasoningContent) nextMessage.reasoning_content = reasoningContent;
      }
      messages.push({
        ...nextMessage,
      });
    }
  }

  const payload: Record<string, unknown> = {
    model,
    stream,
    messages,
  };

  const temperature = pickFiniteNumber(body.temperature);
  if (temperature !== undefined) payload.temperature = temperature;

  const topP = pickFiniteNumber(body.top_p);
  if (topP !== undefined) payload.top_p = topP;

  if (isRecord(body.metadata)) payload.metadata = body.metadata;

  const maxTokens = pickFiniteNumber(body.max_tokens);
  if (maxTokens !== undefined) {
    payload.max_tokens = maxTokens;
  } else {
    payload.max_tokens = 4096;
  }

  if (Array.isArray(body.stop_sequences) && body.stop_sequences.length > 0) {
    payload.stop = body.stop_sequences;
  }

  const reasoningRequest = extractClaudeReasoningRequest(body);
  if (reasoningRequest.reasoningEffort) payload.reasoning_effort = reasoningRequest.reasoningEffort;
  if (reasoningRequest.reasoningBudget !== undefined) payload.reasoning_budget = reasoningRequest.reasoningBudget;

  if (body.tools !== undefined) payload.tools = convertClaudeToolsToOpenAiChat(body.tools);
  if (body.tool_choice !== undefined) payload.tool_choice = convertClaudeToolChoiceToOpenAiChat(body.tool_choice);

  return { model, stream, messages, payload };
}

export function parseDownstreamChatRequest(
  body: unknown,
  format: DownstreamFormat,
): { value?: ParsedDownstreamChatRequest; error?: { statusCode: number; payload: unknown } } {
  const raw = isRecord(body) ? body : {};

  if (format === 'claude') {
    const converted = convertClaudeRequestToOpenAiBody(raw);
    if (!converted.model) {
      return {
        error: {
          statusCode: 400,
          payload: { error: { message: 'model is required', type: 'invalid_request_error' } },
        },
      };
    }

    if (converted.messages.length <= 0) {
      return {
        error: {
          statusCode: 400,
          payload: { error: { message: 'messages is required', type: 'invalid_request_error' } },
        },
      };
    }

    return {
      value: {
        requestedModel: converted.model,
        isStream: converted.stream,
        upstreamBody: converted.payload,
        claudeOriginalBody: raw,
      },
    };
  }

  const model = typeof raw.model === 'string' ? raw.model.trim() : '';
  if (!model) {
    return {
      error: {
        statusCode: 400,
        payload: { error: { message: 'model is required', type: 'invalid_request_error' } },
      },
    };
  }

  const hasMessages = Array.isArray(raw.messages) && raw.messages.length > 0;
  if (!hasMessages) {
    const hint = raw.input !== undefined
      ? 'messages is required for /v1/chat/completions. For Responses payload, use /v1/responses.'
      : 'messages is required';
    return {
      error: {
        statusCode: 400,
        payload: { error: { message: hint, type: 'invalid_request_error' } },
      },
    };
  }

  return {
    value: {
      requestedModel: model,
      isStream: raw.stream === true,
      upstreamBody: raw,
    },
  };
}

export function normalizeUpstreamFinalResponse(
  payload: unknown,
  fallbackModel: string,
  fallbackText = '',
): NormalizedFinalResponse {
  const now = Math.floor(Date.now() / 1000);
  const fallbackId = `chatcmpl-meta-${Date.now()}`;

  if (isRecord(payload) && Array.isArray(payload.choices)) {
    const choice = payload.choices[0] ?? {};
    const content = extractAssistantContent(choice) || extractAssistantContent(payload);
    const reasoning = extractAssistantReasoning(choice) || extractAssistantReasoning(payload);
    const toolCalls = collectToolCallsFromOpenAiChoice(choice);
    return {
      id: isNonEmptyString(payload.id) ? payload.id : fallbackId,
      model: isNonEmptyString(payload.model) ? payload.model : fallbackModel,
      created: ensureIntegerTimestamp(payload.created, now),
      content: content || (toolCalls.length > 0 ? '' : fallbackText),
      reasoningContent: reasoning,
      finishReason: toolCalls.length > 0
        ? 'tool_calls'
        : (normalizeStopReason(choice?.finish_reason ?? payload.stop_reason) || 'stop'),
      toolCalls,
    };
  }

  if (isRecord(payload) && typeof payload.type === 'string' && payload.type === 'message') {
    const toolCalls = collectToolCallsFromClaudeContent(payload.content);
    return {
      id: isNonEmptyString(payload.id) ? payload.id : fallbackId,
      model: isNonEmptyString(payload.model) ? payload.model : fallbackModel,
      created: now,
      content: parseClaudeMessageContent(payload.content) || (toolCalls.length > 0 ? '' : fallbackText),
      reasoningContent: extractTextAndReasoning(payload.content).reasoning,
      finishReason: toolCalls.length > 0 ? 'tool_calls' : (normalizeStopReason(payload.stop_reason) || 'stop'),
      toolCalls,
    };
  }

  if (isRecord(payload) && ((payload as any).object === 'response' || Array.isArray((payload as any).output))) {
    const toolCalls = collectToolCallsFromResponsesPayload(payload);
    const responsesReasoning = parseResponsesReasoning(payload);
    return {
      id: isNonEmptyString(payload.id) ? payload.id : fallbackId,
      model: isNonEmptyString(payload.model) ? payload.model : fallbackModel,
      created: ensureIntegerTimestamp((payload as any).created_at ?? payload.created, now),
      content: parseResponsesOutputText(payload) || (toolCalls.length > 0 ? '' : fallbackText),
      reasoningContent: responsesReasoning.reasoningContent,
      ...(responsesReasoning.reasoningSignature ? { reasoningSignature: responsesReasoning.reasoningSignature } : {}),
      finishReason: toolCalls.length > 0
        ? 'tool_calls'
        : (normalizeStopReason(payload.finish_reason ?? payload.status) || 'stop'),
      toolCalls,
    };
  }

  if (isRecord(payload) && Array.isArray(payload.candidates)) {
    const candidate = payload.candidates[0] || {};
    const parsedCandidate = extractTextAndReasoning(candidate?.content?.parts || candidate?.content);
    return {
      id: isNonEmptyString((payload as any).responseId) ? (payload as any).responseId : fallbackId,
      model: isNonEmptyString((payload as any).modelVersion)
        ? (payload as any).modelVersion
        : fallbackModel,
      created: now,
      content: parsedCandidate.content || fallbackText,
      reasoningContent: parsedCandidate.reasoning,
      finishReason: normalizeStopReason(candidate?.finishReason || (payload as any).finishReason) || 'stop',
      toolCalls: [],
    };
  }

  if (typeof payload === 'string' && payload.trim()) {
    return {
      id: fallbackId,
      model: fallbackModel,
      created: now,
      content: payload,
      reasoningContent: '',
      finishReason: 'stop',
      toolCalls: [],
    };
  }

  return {
    id: fallbackId,
    model: fallbackModel,
    created: now,
    content: fallbackText,
    reasoningContent: '',
    finishReason: 'stop',
    toolCalls: [],
  };
}

export function normalizeUpstreamStreamEvent(
  payload: unknown,
  context: StreamTransformContext,
  fallbackModel: string,
): NormalizedStreamEvent {
  if (!isRecord(payload)) return {};

  if (Array.isArray(payload.choices)) {
    if (isNonEmptyString(payload.id)) context.id = payload.id;
    if (isNonEmptyString(payload.model)) context.model = payload.model;
    context.created = ensureIntegerTimestamp(payload.created, context.created);

    const choice = payload.choices[0] ?? {};
    const delta = isRecord(choice?.delta) ? choice.delta : {};
    const deltaParsed = extractStreamingTextAndReasoning(delta.content ?? delta, context.thinkTagParser);
    const messageParsed = extractStreamingTextAndReasoning(choice?.message?.content ?? '', context.thinkTagParser);

    const rawContentDelta =
      deltaParsed.content
      || messageParsed.content
      || '';

    const reasoningDelta =
      (typeof (delta as any).reasoning_content === 'string' ? (delta as any).reasoning_content : '')
      || (typeof (delta as any).reasoning === 'string' ? (delta as any).reasoning : '')
      || deltaParsed.reasoning
      || messageParsed.reasoning
      || '';
    const reasoningSignature = isNonEmptyString((delta as any).reasoning_signature)
      ? (delta as any).reasoning_signature
      : undefined;

    // Some upstream providers (e.g. certain OpenAI-compatible aggregators) emit thinking
    // tokens with the same text duplicated in both delta.content and delta.reasoning_content.
    // When the two values are identical it means content is just echoing the reasoning —
    // suppress it so internal thinking is never leaked to downstream consumers.
    const contentDelta = (reasoningDelta && rawContentDelta === reasoningDelta)
      ? ''
      : rawContentDelta;

    const rawToolCalls = Array.isArray((delta as any).tool_calls)
      ? ((delta as any).tool_calls as unknown[])
      : [];
    const toolCallDeltas = rawToolCalls
      .map((item, itemIndex) => {
        if (!isRecord(item)) return null;
        const functionPart = isRecord(item.function) ? item.function : {};
        const index = (
          typeof item.index === 'number' && Number.isFinite(item.index)
            ? Math.max(0, Math.trunc(item.index))
            : itemIndex
        );
        const id = typeof item.id === 'string' && item.id.trim().length > 0
          ? item.id
          : undefined;
        const name = typeof functionPart.name === 'string' && functionPart.name.trim().length > 0
          ? functionPart.name
          : undefined;
        const argumentsDelta = typeof functionPart.arguments === 'string'
          ? functionPart.arguments
          : undefined;

        if (!id && !name && argumentsDelta === undefined) return null;
        return {
          index,
          id,
          name,
          argumentsDelta,
        };
      })
      .filter((item): item is NonNullable<typeof item> => !!item);

    return {
      role: (delta as any).role === 'assistant' ? 'assistant' : undefined,
      contentDelta: contentDelta || undefined,
      reasoningDelta: reasoningDelta || undefined,
      reasoningSignature,
      toolCallDeltas: toolCallDeltas.length > 0 ? toolCallDeltas : undefined,
      finishReason: normalizeStopReason(choice?.finish_reason),
    };
  }

  const type = typeof payload.type === 'string' ? payload.type : '';
  if (type.startsWith('response.output_text')) {
    const parsed = extractStreamingTextAndReasoning(payload.delta, context.thinkTagParser);
    return {
      contentDelta: parsed.content || undefined,
      reasoningDelta: parsed.reasoning || undefined,
    };
  }

  if (type === 'response.reasoning_summary_text.delta') {
    const deltaText = typeof payload.delta === 'string'
      ? payload.delta
      : extractTextAndReasoning(payload.delta).content;
    return {
      reasoningDelta: deltaText || undefined,
    };
  }

  if (type === 'response.failed' || type === 'response.incomplete' || type === 'error') {
    const responsePayload = isRecord((payload as any).response) ? (payload as any).response : null;
    const finishReason = normalizeStopReason(
      (responsePayload as any)?.status
      ?? (payload as any).status
      ?? (payload as any).type,
    ) || 'error';
    return {
      finishReason,
      done: true,
    };
  }

  if (type === 'response.output_item.added' && isRecord((payload as any).item)) {
    const item = (payload as any).item as Record<string, unknown>;
    if (item.type === 'reasoning' && isNonEmptyString(item.encrypted_content)) {
      return {
        reasoningSignature: item.encrypted_content,
      };
    }
    if (item.type === 'function_call') {
      const outputIndex = (
        typeof (payload as any).output_index === 'number' && Number.isFinite((payload as any).output_index)
          ? Math.max(0, Math.trunc((payload as any).output_index))
          : 0
      );
      const toolCallId = (
        isNonEmptyString(item.call_id) ? item.call_id
          : (isNonEmptyString(item.id) ? item.id : undefined)
      );
      const toolName = isNonEmptyString(item.name) ? item.name : undefined;
      return {
        toolCallDeltas: [{
          index: outputIndex,
          id: toolCallId,
          name: toolName,
        }],
      };
    }
  }

  if (type === 'response.function_call_arguments.delta' || type === 'response.function_call_arguments.done') {
    const outputIndex = (
      typeof (payload as any).output_index === 'number' && Number.isFinite((payload as any).output_index)
        ? Math.max(0, Math.trunc((payload as any).output_index))
        : 0
    );
    const toolCallId = (
      isNonEmptyString((payload as any).call_id) ? (payload as any).call_id
        : (isNonEmptyString((payload as any).item_id) ? (payload as any).item_id : undefined)
    );
    const toolName = isNonEmptyString((payload as any).name) ? (payload as any).name : undefined;
    const rawArguments = (
      type === 'response.function_call_arguments.done'
        ? (typeof (payload as any).arguments === 'string' ? (payload as any).arguments : undefined)
        : (
          typeof payload.delta === 'string'
            ? payload.delta
            : (typeof (payload as any).arguments === 'string' ? (payload as any).arguments : undefined)
        )
    );
    let argumentsDelta = rawArguments;
    if (type === 'response.function_call_arguments.done' && typeof rawArguments === 'string') {
      const existingArguments = context.toolCalls[outputIndex]?.arguments || '';
      if (existingArguments && rawArguments.startsWith(existingArguments)) {
        const missingSuffix = rawArguments.slice(existingArguments.length);
        argumentsDelta = missingSuffix.length > 0 ? missingSuffix : undefined;
      } else if (existingArguments === rawArguments) {
        argumentsDelta = undefined;
      }
    }

    const knownTool = context.toolCalls[outputIndex] || {};
    const shouldBackfillId = !!toolCallId && !knownTool.id;
    const shouldBackfillName = !!toolName && !knownTool.name;
    if (argumentsDelta === undefined && !shouldBackfillId && !shouldBackfillName) {
      return {};
    }

    return {
      toolCallDeltas: [{
        index: outputIndex,
        id: toolCallId,
        name: toolName,
        argumentsDelta,
      }],
    };
  }

  if (type === 'response.completed' && isRecord((payload as any).response)) {
    const responsePayload = (payload as any).response as Record<string, unknown>;
    if (isNonEmptyString(responsePayload.id)) context.id = responsePayload.id;
    if (isNonEmptyString(responsePayload.model)) context.model = responsePayload.model;
    return {
      finishReason: normalizeStopReason(responsePayload.status) || 'stop',
      done: true,
    };
  }

  const message = isRecord(payload.message) ? payload.message : null;

  if (message) {
    if (isNonEmptyString(message.id)) context.id = message.id;
    if (isNonEmptyString(message.model)) context.model = message.model;
  }
  if (!context.model) context.model = fallbackModel;

  if (type === 'message_start') {
    return { role: 'assistant' };
  }

  if (type === 'content_block_start') {
    const index = (
      typeof (payload as any).index === 'number' && Number.isFinite((payload as any).index)
        ? Math.max(0, Math.trunc((payload as any).index))
        : 0
    );
    const contentBlock = isRecord(payload.content_block) ? payload.content_block : {};
    if (contentBlock.type === 'tool_use') {
      const id = typeof contentBlock.id === 'string' && contentBlock.id.trim().length > 0
        ? contentBlock.id
        : undefined;
      const name = typeof contentBlock.name === 'string' && contentBlock.name.trim().length > 0
        ? contentBlock.name
        : undefined;
      let argumentsDelta: string | undefined;
      const rawInput = contentBlock.input;
      if (typeof rawInput === 'string') {
        argumentsDelta = rawInput;
      } else if (Array.isArray(rawInput) || isRecord(rawInput)) {
        try {
          const serialized = JSON.stringify(rawInput);
          if (serialized && serialized !== '{}' && serialized !== '[]') {
            argumentsDelta = serialized;
          }
        } catch {}
      }

      return {
        toolCallDeltas: [{
          index,
          id,
          name,
          argumentsDelta,
        }],
      };
    }

    const parsed = extractStreamingTextAndReasoning(payload.content_block, context.thinkTagParser);
    return {
      contentDelta: parsed.content || undefined,
      reasoningDelta: parsed.reasoning || undefined,
    };
  }

  if (type === 'content_block_delta') {
    const delta = isRecord(payload.delta) ? payload.delta : {};
    const deltaType = typeof delta.type === 'string' ? delta.type : '';
    const parsed = extractStreamingTextAndReasoning(delta, context.thinkTagParser);

    if (deltaType === 'input_json_delta') {
      const index = (
        typeof (payload as any).index === 'number' && Number.isFinite((payload as any).index)
          ? Math.max(0, Math.trunc((payload as any).index))
          : 0
      );
      const partialJson = typeof (delta as any).partial_json === 'string'
        ? (delta as any).partial_json
        : undefined;
      return {
        toolCallDeltas: [{
          index,
          argumentsDelta: partialJson,
        }],
      };
    }

    if (deltaType === 'thinking_delta') {
      return {
        reasoningDelta: parsed.content || parsed.reasoning || undefined,
      };
    }

    return {
      contentDelta: parsed.content || undefined,
      reasoningDelta: parsed.reasoning || undefined,
    };
  }

  if (type === 'message_delta') {
    const delta = isRecord(payload.delta) ? payload.delta : {};
    return {
      finishReason: normalizeStopReason(delta.stop_reason ?? payload.stop_reason),
    };
  }

  if (type === 'message_stop') {
    return { done: true };
  }

  if (Array.isArray(payload.candidates)) {
    const candidate = payload.candidates[0] || {};
    const parsed = extractStreamingTextAndReasoning(
      (candidate as any).content?.parts || (candidate as any).content,
      context.thinkTagParser,
    );

    if (isNonEmptyString((payload as any).modelVersion)) {
      context.model = (payload as any).modelVersion;
    } else if (!context.model) {
      context.model = fallbackModel;
    }

    return {
      contentDelta: parsed.content || undefined,
      reasoningDelta: parsed.reasoning || undefined,
      finishReason: normalizeStopReason((candidate as any).finishReason || (payload as any).finishReason),
    };
  }

  const fallback = extractStreamingTextAndReasoning(payload, context.thinkTagParser);
  return {
    contentDelta: fallback.content || undefined,
    reasoningDelta: fallback.reasoning || undefined,
  };
}

function buildOpenAiStreamChunk(
  context: StreamTransformContext,
  event: NormalizedStreamEvent,
): Record<string, unknown> | null {
  const normalizedContentDelta = event.contentDelta || '';
  const normalizedReasoningDelta = event.reasoningDelta || '';
  const delta: Record<string, unknown> = {};
  const isInitialAssistantRoleOnlyEvent = (
    !context.roleSent
    && event.role === 'assistant'
    && !normalizedContentDelta
    && !normalizedReasoningDelta
  );

  if (!context.roleSent && (event.role === 'assistant' || normalizedContentDelta || normalizedReasoningDelta)) {
    delta.role = 'assistant';
    context.roleSent = true;
  } else if (event.role === 'assistant') {
    delta.role = 'assistant';
    context.roleSent = true;
  }

  if (normalizedContentDelta) {
    delta.content = normalizedContentDelta;
  }

  if (normalizedReasoningDelta) {
    delta.reasoning_content = normalizedReasoningDelta;
  }

  if (Array.isArray(event.toolCallDeltas) && event.toolCallDeltas.length > 0) {
    const toolCalls = event.toolCallDeltas.map((toolDelta) => {
      const index = Number.isFinite(toolDelta.index) ? Math.max(0, Math.trunc(toolDelta.index)) : 0;
      const existing = context.toolCalls[index] || {};
      const id = toolDelta.id || existing.id || `call_meta_${index}`;
      const name = toolDelta.name || existing.name || '';
      const nextArguments = `${existing.arguments || ''}${toolDelta.argumentsDelta ?? ''}`;
      context.toolCalls[index] = {
        id,
        name: name || existing.name,
        arguments: nextArguments,
      };

      const fn: Record<string, unknown> = {};
      if (name) fn.name = name;
      if (toolDelta.argumentsDelta !== undefined) fn.arguments = toolDelta.argumentsDelta;

      return {
        index,
        id,
        type: 'function',
        function: fn,
      };
    });

    if (toolCalls.length > 0) {
      delta.tool_calls = toolCalls;
    }
  }

  // Some OpenAI-compatible clients (e.g. OpenWebUI) expect starter chunk to include empty content.
  if (isInitialAssistantRoleOnlyEvent) {
    delta.content = '';
  }

  const finishReason = event.finishReason || null;
  const hasDelta = Object.keys(delta).length > 0;
  if (!hasDelta && !finishReason) return null;

  return {
    id: context.id,
    object: 'chat.completion.chunk',
    created: context.created,
    model: context.model,
    choices: [{
      index: 0,
      delta,
      finish_reason: finishReason,
    }],
  };
}

function ensureClaudeStartEvents(
  context: StreamTransformContext,
  claudeContext: ClaudeDownstreamContext,
): string[] {
  if (claudeContext.messageStarted) return [];

  claudeContext.messageStarted = true;
  const payload = {
    type: 'message_start',
    message: {
      id: buildClaudeMessageId(context.id),
      type: 'message',
      role: 'assistant',
      model: context.model,
      content: [],
      stop_reason: null,
      stop_sequence: null,
      usage: {
        input_tokens: 0,
        output_tokens: 0,
      },
    },
  };

  return [serializeSse('message_start', payload)];
}

function ensureClaudeTextBlockStart(
  claudeContext: ClaudeDownstreamContext,
): string[] {
  if (claudeContext.contentBlockStarted && claudeContext.textBlockIndex !== null) return [];
  const contentIndex = claudeContext.nextContentBlockIndex;
  claudeContext.nextContentBlockIndex += 1;
  claudeContext.contentBlockStarted = true;
  claudeContext.textBlockIndex = contentIndex;

  return [serializeSse('content_block_start', {
    type: 'content_block_start',
    index: contentIndex,
    content_block: {
      type: 'text',
      text: '',
    },
  })];
}

function closeClaudeTextBlock(
  claudeContext: ClaudeDownstreamContext,
): string[] {
  if (!claudeContext.contentBlockStarted || claudeContext.textBlockIndex === null) return [];

  const contentIndex = claudeContext.textBlockIndex;
  claudeContext.contentBlockStarted = false;
  claudeContext.textBlockIndex = null;
  return [serializeSse('content_block_stop', {
    type: 'content_block_stop',
    index: contentIndex,
  })];
}

function normalizeToolContentIndex(raw: unknown): number {
  if (typeof raw === 'number' && Number.isFinite(raw)) {
    return Math.max(0, Math.trunc(raw));
  }
  return 0;
}

function ensureClaudeToolBlockStart(
  claudeContext: ClaudeDownstreamContext,
  toolDelta: NonNullable<NormalizedStreamEvent['toolCallDeltas']>[number],
): { events: string[]; contentIndex: number } {
  const toolSlot = normalizeToolContentIndex(toolDelta.index);
  let state = claudeContext.toolBlocks[toolSlot];
  if (!state) {
    const fallbackId = `toolu_meta_${toolSlot}`;
    const fallbackName = `tool_${toolSlot}`;
    state = {
      contentIndex: claudeContext.nextContentBlockIndex,
      id: toolDelta.id || fallbackId,
      name: toolDelta.name || fallbackName,
      open: false,
    };
    claudeContext.nextContentBlockIndex += 1;
    claudeContext.toolBlocks[toolSlot] = state;
  } else {
    if (toolDelta.id && state.id !== toolDelta.id) {
      state.id = toolDelta.id;
    }
    if (toolDelta.name && state.name !== toolDelta.name) {
      state.name = toolDelta.name;
    }
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

  return {
    events,
    contentIndex: state.contentIndex,
  };
}

function closeClaudeToolBlocks(
  claudeContext: ClaudeDownstreamContext,
): string[] {
  const openBlocks = Object.values(claudeContext.toolBlocks)
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
  return events;
}

function buildClaudeDoneEvents(
  context: StreamTransformContext,
  claudeContext: ClaudeDownstreamContext,
  finishReason?: string | null,
): string[] {
  if (claudeContext.doneSent) return [];

  const events: string[] = [];
  events.push(...ensureClaudeStartEvents(context, claudeContext));

  events.push(...closeClaudeTextBlock(claudeContext));
  events.push(...closeClaudeToolBlocks(claudeContext));

  events.push(serializeSse('message_delta', {
    type: 'message_delta',
    delta: {
      stop_reason: toClaudeStopReason(finishReason),
      stop_sequence: null,
    },
    usage: {
      output_tokens: 0,
    },
  }));
  events.push(serializeSse('message_stop', { type: 'message_stop' }));

  claudeContext.doneSent = true;
  return events;
}

export function serializeNormalizedStreamEvent(
  downstreamFormat: DownstreamFormat,
  event: NormalizedStreamEvent,
  context: StreamTransformContext,
  claudeContext: ClaudeDownstreamContext,
): string[] {
  if (downstreamFormat === 'openai') {
    const chunk = buildOpenAiStreamChunk(context, event);
    return chunk ? [serializeSse('', chunk)] : [];
  }

  const events: string[] = [];
  if (event.role === 'assistant' || event.contentDelta || event.reasoningDelta) {
    events.push(...ensureClaudeStartEvents(context, claudeContext));
  }

  const mergedText = joinNonEmpty([
    event.reasoningDelta || '',
    event.contentDelta || '',
  ]);

  if (Array.isArray(event.toolCallDeltas) && event.toolCallDeltas.length > 0) {
    events.push(...closeClaudeTextBlock(claudeContext));
    for (const toolDelta of event.toolCallDeltas) {
      const toolBlock = ensureClaudeToolBlockStart(claudeContext, toolDelta);
      events.push(...toolBlock.events);

      if (toolDelta.argumentsDelta !== undefined && toolDelta.argumentsDelta.length > 0) {
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

  if (mergedText) {
    events.push(...closeClaudeToolBlocks(claudeContext));
    events.push(...ensureClaudeTextBlockStart(claudeContext));
    events.push(serializeSse('content_block_delta', {
      type: 'content_block_delta',
      index: claudeContext.textBlockIndex ?? 0,
      delta: {
        type: 'text_delta',
        text: mergedText,
      },
    }));
  }

  if (event.done || event.finishReason) {
    events.push(...buildClaudeDoneEvents(context, claudeContext, event.finishReason));
  }

  return events;
}

export function serializeStreamDone(
  downstreamFormat: DownstreamFormat,
  context: StreamTransformContext,
  claudeContext: ClaudeDownstreamContext,
): string[] {
  if (context.doneSent) return [];
  context.doneSent = true;

  if (downstreamFormat === 'openai') {
    return [serializeSse('', '[DONE]')];
  }

  return buildClaudeDoneEvents(context, claudeContext, 'stop');
}

function toOpenAiToolCalls(
  toolCalls: Array<{ id: string; name: string; arguments: string }>,
): Array<Record<string, unknown>> {
  return toolCalls.map((toolCall, index) => ({
    index,
    id: toolCall.id || `call_${index}`,
    type: 'function',
    function: {
      name: toolCall.name || '',
      arguments: toolCall.arguments || '',
    },
  }));
}

export function serializeFinalResponse(
  downstreamFormat: DownstreamFormat,
  normalized: NormalizedFinalResponse,
  usage: { promptTokens: number; completionTokens: number; totalTokens: number },
): Record<string, unknown> {
  const toolCalls = Array.isArray(normalized.toolCalls) ? normalized.toolCalls : [];
  const rawReasoningSignature = typeof normalized.reasoningSignature === 'string'
    ? normalized.reasoningSignature.trim()
    : '';
  const taggedReasoningSignature = rawReasoningSignature.startsWith('metapi:');
  const claudeReasoningSignature = decodeAnthropicReasoningSignature(rawReasoningSignature)
    ?? (rawReasoningSignature && !taggedReasoningSignature ? rawReasoningSignature : null);

  if (downstreamFormat === 'claude') {
    const contentBlocks: Array<Record<string, unknown>> = [];
    if (normalized.reasoningContent) {
      const thinkingBlock: Record<string, unknown> = {
        type: 'thinking',
        thinking: normalized.reasoningContent,
      };
      if (claudeReasoningSignature) {
        thinkingBlock.signature = claudeReasoningSignature;
      }
      contentBlocks.push(thinkingBlock);
    }
    if (normalized.redactedReasoningContent) {
      contentBlocks.push({
        type: 'redacted_thinking',
        data: normalized.redactedReasoningContent,
      });
    }
    if (normalized.content) {
      contentBlocks.push({
        type: 'text',
        text: normalized.content,
      });
    }
    for (let index = 0; index < toolCalls.length; index += 1) {
      const toolCall = toolCalls[index];
      contentBlocks.push({
        type: 'tool_use',
        id: toolCall.id || `toolu_${index}`,
        name: toolCall.name || `tool_${index}`,
        input: parseJsonLike(toolCall.arguments || ''),
      });
    }

    const content = contentBlocks.length > 0
      ? contentBlocks
      : [{ type: 'text', text: '' }];

    return {
      id: buildClaudeMessageId(normalized.id),
      type: 'message',
      role: 'assistant',
      model: normalized.model,
      content,
      stop_reason: toClaudeStopReason(normalized.finishReason),
      stop_sequence: null,
      usage: {
        input_tokens: usage.promptTokens,
        output_tokens: usage.completionTokens,
      },
    };
  }

  const message: Record<string, unknown> = {
    role: 'assistant',
    content: normalized.content,
  };
  if (normalized.reasoningContent) {
    message.reasoning_content = normalized.reasoningContent;
  }
  if (rawReasoningSignature) {
    message.reasoning_signature = rawReasoningSignature;
  }
  if (toolCalls.length > 0) {
    message.tool_calls = toOpenAiToolCalls(toolCalls);
    if (!normalized.content) message.content = '';
  }

  const finishReason = (
    toolCalls.length > 0
      ? 'tool_calls'
      : (normalizeStopReason(normalized.finishReason) || 'stop')
  );

  return {
    id: normalized.id,
    object: 'chat.completion',
    created: normalized.created,
    model: normalized.model,
    choices: [{
      index: 0,
      message,
      finish_reason: finishReason,
    }],
    usage: {
      prompt_tokens: usage.promptTokens,
      completion_tokens: usage.completionTokens,
      total_tokens: usage.totalTokens,
    },
  };
}

export function buildSyntheticOpenAiChunks(normalized: NormalizedFinalResponse): Array<Record<string, unknown>> {
  const toolCalls = Array.isArray(normalized.toolCalls) ? normalized.toolCalls : [];
  const finishReason = (
    toolCalls.length > 0
      ? 'tool_calls'
      : (normalizeStopReason(normalized.finishReason) || 'stop')
  );

  const startDelta: Record<string, unknown> = {
    role: 'assistant',
  };
  if (normalized.content) {
    startDelta.content = normalized.content;
  } else {
    startDelta.content = '';
  }
  if (normalized.reasoningContent) {
    startDelta.reasoning_content = normalized.reasoningContent;
  }
  if (typeof normalized.reasoningSignature === 'string' && normalized.reasoningSignature.trim()) {
    startDelta.reasoning_signature = normalized.reasoningSignature.trim();
  }
  if (toolCalls.length > 0) {
    startDelta.tool_calls = toOpenAiToolCalls(toolCalls);
  }

  const startChunk: Record<string, unknown> = {
    id: normalized.id,
    object: 'chat.completion.chunk',
    created: normalized.created,
    model: normalized.model,
    choices: [{
      index: 0,
      delta: startDelta,
      finish_reason: null,
    }],
  };

  const endChunk = {
    id: normalized.id,
    object: 'chat.completion.chunk',
    created: normalized.created,
    model: normalized.model,
    choices: [{
      index: 0,
      delta: {},
      finish_reason: finishReason,
    }],
  };

  return [startChunk, endChunk];
}

export function pullSseEventsWithDone(buffer: string): { events: ParsedSseEvent[]; rest: string } {
  const normalized = buffer.replace(/\r\n/g, '\n');
  const events: ParsedSseEvent[] = [];
  let rest = normalized;

  while (true) {
    const boundary = rest.indexOf('\n\n');
    if (boundary < 0) break;

    const block = rest.slice(0, boundary);
    rest = rest.slice(boundary + 2);

    if (!block.trim()) continue;

    const lines = block.split('\n');
    let eventName = '';
    const dataLines: string[] = [];

    for (const line of lines) {
      if (line.startsWith('event:')) {
        eventName = line.slice(6).trim();
        continue;
      }
      if (line.startsWith('data:')) {
        dataLines.push(line.slice(5).trimStart());
      }
    }

    if (dataLines.length <= 0) continue;

    events.push({
      event: eventName,
      data: dataLines.join('\n').trim(),
    });
  }

  return { events, rest };
}
