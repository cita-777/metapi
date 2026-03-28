import { normalizeInputFileBlock, toResponsesInputFileBlock } from '../../shared/inputFile.js';

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function asTrimmedString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

const RESPONSES_TOOL_CALL_ITEM_TYPES = new Set([
  'function_call',
  'custom_tool_call',
]);

const RESPONSES_TOOL_OUTPUT_ITEM_TYPES = new Set([
  'function_call_output',
  'custom_tool_call_output',
]);

const ALLOWED_RESPONSES_INPUT_STATUSES = new Set([
  'in_progress',
  'completed',
  'incomplete',
]);

function normalizeResponsesInputStatus(value: unknown): string | undefined {
  const normalized = asTrimmedString(value).toLowerCase();
  if (!normalized) return undefined;
  if (normalized === 'failed') return 'incomplete';
  return ALLOWED_RESPONSES_INPUT_STATUSES.has(normalized) ? normalized : undefined;
}

function withNormalizedResponsesInputStatus(item: Record<string, unknown>): Record<string, unknown> {
  const normalizedStatus = normalizeResponsesInputStatus(item.status);
  if (normalizedStatus) {
    return {
      ...item,
      status: normalizedStatus,
    };
  }

  if (!Object.prototype.hasOwnProperty.call(item, 'status')) {
    return item;
  }

  const { status: _status, ...rest } = item;
  return rest;
}

function firstNonEmptyTrimmedString(...values: unknown[]): string {
  for (const value of values) {
    const normalized = asTrimmedString(value);
    if (normalized) return normalized;
  }
  return '';
}

function firstMeaningfulValue(...values: unknown[]): unknown {
  for (const value of values) {
    if (typeof value === 'string') {
      if (value.trim()) return value;
      continue;
    }
    if (value !== undefined && value !== null) return value;
  }
  return undefined;
}

function toTextBlockType(role: string): 'input_text' | 'output_text' {
  return role === 'assistant' ? 'output_text' : 'input_text';
}

function normalizeImageUrlValue(value: unknown): string | Record<string, unknown> | null {
  if (typeof value === 'string' && value.trim().length > 0) return value;
  if (!isRecord(value)) return null;
  const url = asTrimmedString(value.url);
  if (url) return { ...value, url };
  const imageUrl = asTrimmedString(value.image_url);
  if (imageUrl) return imageUrl;
  return Object.keys(value).length > 0 ? value : null;
}

function normalizeAudioInputValue(value: unknown): Record<string, unknown> | null {
  if (!isRecord(value)) return null;
  const data = asTrimmedString(value.data);
  const format = asTrimmedString(value.format);
  if (!data && !format) return Object.keys(value).length > 0 ? value : null;
  return {
    ...value,
    ...(data ? { data } : {}),
    ...(format ? { format } : {}),
  };
}

function normalizeResponsesContentItem(
  item: unknown,
  role: string,
): Record<string, unknown> | null {
  if (typeof item === 'string') {
    const text = item.trim();
    return text ? { type: toTextBlockType(role), text } : null;
  }

  if (!isRecord(item)) return null;

  const type = asTrimmedString(item.type).toLowerCase();
  if (!type) {
    const text = firstNonEmptyTrimmedString(item.text, item.content, item.output_text);
    return text ? { type: toTextBlockType(role), text } : null;
  }

  if (type === 'input_text' || type === 'output_text' || type === 'text') {
    const text = firstNonEmptyTrimmedString(item.text, item.content, item.output_text);
    if (!text) return null;
    return {
      ...item,
      type: type === 'text' ? toTextBlockType(role) : type,
      text,
    };
  }

  if (type === 'input_image' || type === 'image_url') {
    const imageUrl = normalizeImageUrlValue(item.image_url) ?? normalizeImageUrlValue(item.url);
    if (!imageUrl) return null;
    return {
      ...item,
      type: 'input_image',
      image_url: imageUrl,
    };
  }

  if (type === 'input_audio') {
    const inputAudio = normalizeAudioInputValue(item.input_audio);
    if (!inputAudio) return null;
    return {
      ...item,
      type: 'input_audio',
      input_audio: inputAudio,
    };
  }

  if (type === 'file' || type === 'input_file') {
    const fileBlock = normalizeInputFileBlock(item);
    return fileBlock ? toResponsesInputFileBlock(fileBlock) : null;
  }

  if (RESPONSES_TOOL_CALL_ITEM_TYPES.has(type) || RESPONSES_TOOL_OUTPUT_ITEM_TYPES.has(type)) {
    return item;
  }

  return item;
}

export function normalizeResponsesMessageContent(
  content: unknown,
  role: string,
): unknown {
  if (Array.isArray(content)) {
    const normalized = content
      .map((item) => normalizeResponsesContentItem(item, role))
      .filter((item): item is Record<string, unknown> => !!item);
    return normalized.length > 0 ? normalized : content;
  }

  const single = normalizeResponsesContentItem(content, role);
  if (single) return [single];
  return content;
}

function toResponsesInputMessageFromText(text: string): Record<string, unknown> {
  return {
    type: 'message',
    role: 'user',
    content: [{ type: 'input_text', text }],
  };
}

function normalizeResponsesToolLifecycleItem(item: Record<string, unknown>): Record<string, unknown> | null {
  const type = asTrimmedString(item.type).toLowerCase();
  if (!RESPONSES_TOOL_CALL_ITEM_TYPES.has(type) && !RESPONSES_TOOL_OUTPUT_ITEM_TYPES.has(type)) {
    return withNormalizedResponsesInputStatus(item);
  }

  const callId = asTrimmedString(item.call_id ?? item.id);
  if (!callId) return null;

  const normalized: Record<string, unknown> = {
    ...item,
    call_id: callId,
  };

  if (typeof item.id === 'string') {
    const id = asTrimmedString(item.id);
    if (id) normalized.id = id;
    else delete normalized.id;
  }

  if (RESPONSES_TOOL_CALL_ITEM_TYPES.has(type)) {
    if (Object.prototype.hasOwnProperty.call(item, 'name')) {
      const name = asTrimmedString(item.name);
      if (!name) return null;
      normalized.name = name;
    }
  }

  return withNormalizedResponsesInputStatus(normalized);
}

function sanitizeResponsesInputToolLifecycle(items: unknown[]): unknown[] {
  const sanitized: unknown[] = [];

  for (const item of items) {
    if (!isRecord(item)) {
      sanitized.push(item);
      continue;
    }

    const type = asTrimmedString(item.type).toLowerCase();
    if (RESPONSES_TOOL_CALL_ITEM_TYPES.has(type)) {
      const normalized = normalizeResponsesToolLifecycleItem(item);
      if (!normalized) continue;
      sanitized.push(normalized);
      continue;
    }

    if (RESPONSES_TOOL_OUTPUT_ITEM_TYPES.has(type)) {
      const normalized = normalizeResponsesToolLifecycleItem(item);
      if (!normalized) continue;
      sanitized.push(normalized);
      continue;
    }

    sanitized.push(item);
  }

  return sanitized;
}

export function normalizeResponsesMessageItem(item: Record<string, unknown>): Record<string, unknown> {
  const type = asTrimmedString(item.type).toLowerCase();
  if (RESPONSES_TOOL_CALL_ITEM_TYPES.has(type) || RESPONSES_TOOL_OUTPUT_ITEM_TYPES.has(type)) {
    return normalizeResponsesToolLifecycleItem(item) ?? item;
  }

  const role = asTrimmedString(item.role).toLowerCase() || 'user';
  const normalizedContent = normalizeResponsesMessageContent(
    firstMeaningfulValue(item.content, item.text),
    role,
  );

  if (type === 'message') {
    return withNormalizedResponsesInputStatus({
      ...item,
      role,
      content: normalizedContent,
    });
  }

  if (asTrimmedString(item.role)) {
    return withNormalizedResponsesInputStatus({
      ...item,
      type: 'message',
      role,
      content: normalizedContent,
    });
  }

  if (typeof item.content === 'string' || typeof item.text === 'string') {
    const text = firstNonEmptyTrimmedString(item.content, item.text);
    return text ? toResponsesInputMessageFromText(text) : item;
  }

  return withNormalizedResponsesInputStatus(item);
}

export function normalizeResponsesInputForCompatibility(input: unknown): unknown {
  if (typeof input === 'string') {
    const normalized = input.trim();
    if (!normalized) return input;
    return [toResponsesInputMessageFromText(normalized)];
  }

  if (Array.isArray(input)) {
    const normalized = input.flatMap((item) => {
      if (typeof item === 'string') {
        const normalized = item.trim();
        return normalized ? [toResponsesInputMessageFromText(normalized)] : [];
      }
      if (!isRecord(item)) return [item];
      return [normalizeResponsesMessageItem(item)];
    });
    return sanitizeResponsesInputToolLifecycle(normalized);
  }

  if (isRecord(input)) {
    return sanitizeResponsesInputToolLifecycle([normalizeResponsesMessageItem(input)]);
  }

  return input;
}

export function normalizeResponsesMessageContentBlocks(
  role: string,
  content: unknown,
): Array<Record<string, unknown>> {
  const normalized = normalizeResponsesMessageItem({
    type: 'message',
    role,
    content,
  });

  if (isRecord(normalized) && Array.isArray(normalized.content)) {
    return normalized.content.filter((item): item is Record<string, unknown> => isRecord(item));
  }

  return [];
}
