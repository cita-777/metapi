import { normalizeInputFileBlock, toAnthropicDocumentBlock } from '../../shared/inputFile.js';
import {
  decodeAnthropicReasoningSignature,
} from '../../shared/reasoningTransport.js';

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object';
}

const VALID_ANTHROPIC_TOOL_CHOICE_TYPES = new Set(['auto', 'none', 'any', 'tool']);
const VALID_ANTHROPIC_THINKING_TYPES = new Set(['enabled', 'disabled', 'adaptive']);
const VALID_ANTHROPIC_EFFORTS = new Set(['low', 'medium', 'high', 'max']);
const MAX_ANTHROPIC_CACHE_CONTROL_BREAKPOINTS = 4;
const ADAPTIVE_ANTHROPIC_CACHE_CONTROL_BLOCK_WINDOW = 20;

function asTrimmedString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function toFiniteNumber(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

function safeJsonStringify(value: unknown): string {
  try {
    return JSON.stringify(value);
  } catch {
    return '';
  }
}

function cloneJsonValue<T>(value: T): T | undefined {
  try {
    return JSON.parse(JSON.stringify(value)) as T;
  } catch {
    return undefined;
  }
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

function toPositiveInteger(value: unknown): number | null {
  const numberValue = toFiniteNumber(value);
  if (numberValue === null || numberValue <= 0) return null;
  return Math.trunc(numberValue);
}

function sanitizeCacheControl(value: unknown): Record<string, unknown> | undefined {
  if (!isRecord(value)) return undefined;
  const type = asTrimmedString(value.type).toLowerCase();
  if (type !== 'ephemeral') return undefined;
  return { type };
}

function sanitizeAnthropicOutputConfig(
  value: unknown,
  options: { allowEffort?: boolean } = {},
): { value?: Record<string, unknown>; error?: string } {
  if (!isRecord(value)) return {};
  const allowEffort = options.allowEffort === true;

  const next: Record<string, unknown> = {};
  if ('effort' in value) {
    const effort = asTrimmedString(value.effort).toLowerCase();
    if (!effort) {
      // Ignore blank effort and continue preserving other output_config fields.
    } else if (!allowEffort) {
      // Ignore effort outside adaptive thinking; upstream only applies it there.
    } else if (!VALID_ANTHROPIC_EFFORTS.has(effort)) {
      return { error: 'output_config.effort must be one of: low, medium, high, max' };
    } else {
      next.effort = effort;
    }
  }

  for (const [key, entry] of Object.entries(value)) {
    if (key === 'effort') continue;
    next[key] = entry;
  }

  return Object.keys(next).length > 0 ? { value: next } : {};
}

function sanitizeAnthropicToolChoiceValue(
  value: unknown,
): { value?: Record<string, unknown>; error?: string } {
  if (value === undefined) return {};

  if (typeof value === 'string') {
    const normalized = asTrimmedString(value).toLowerCase();
    if (!normalized) return {};
    if (normalized === 'required') return { value: { type: 'any' } };
    if (normalized === 'tool') {
      return { error: 'tool_choice.name is required when type is tool' };
    }
    if (!VALID_ANTHROPIC_TOOL_CHOICE_TYPES.has(normalized)) {
      return { error: 'tool_choice.type must be one of: auto, none, any, tool' };
    }
    return { value: { type: normalized } };
  }

  if (!isRecord(value)) {
    return { error: 'tool_choice must be an object or string' };
  }

  const type = asTrimmedString(value.type).toLowerCase();
  if (!VALID_ANTHROPIC_TOOL_CHOICE_TYPES.has(type)) {
    return { error: 'tool_choice.type must be one of: auto, none, any, tool' };
  }

  const next: Record<string, unknown> = { ...value, type };
  if (type === 'tool') {
    const name = asTrimmedString(value.name ?? (isRecord(value.tool) ? value.tool.name : undefined));
    if (!name) {
      return { error: 'tool_choice.name is required when type is tool' };
    }
    next.name = name;
    delete next.tool;
  } else {
    delete next.name;
    delete next.tool;
  }

  return { value: next };
}

function sanitizeAnthropicThinkingConfig(
  value: unknown,
): { value?: Record<string, unknown>; error?: string } {
  if (!isRecord(value)) return {};

  const type = asTrimmedString(value.type).toLowerCase();
  if (!type) return {};
  if (!VALID_ANTHROPIC_THINKING_TYPES.has(type)) {
    return { error: 'thinking.type must be one of: enabled, disabled, adaptive' };
  }

  if (type === 'enabled') {
    const budgetTokens = toPositiveInteger(value.budget_tokens ?? value.budgetTokens);
    if (!budgetTokens) {
      return { error: 'budget_tokens is required and must be positive when thinking.type is enabled' };
    }
    return {
      value: {
        type,
        budget_tokens: budgetTokens,
      },
    };
  }

  if (type === 'adaptive') {
    const budgetTokens = toPositiveInteger(value.budget_tokens ?? value.budgetTokens);
    if (budgetTokens) {
      return {
        value: {
          type: 'enabled',
          budget_tokens: budgetTokens,
        },
      };
    }
  }

  return { value: { type } };
}

function normalizeOpenAiToolArguments(raw: unknown): string {
  if (typeof raw === 'string') return raw;
  if (raw === undefined || raw === null) return '';
  if (typeof raw === 'number' || typeof raw === 'boolean') return String(raw);
  if (Array.isArray(raw) || isRecord(raw)) {
    return safeJsonStringify(raw);
  }
  return '';
}

export function normalizeAnthropicToolInput(raw: unknown): unknown {
  if (raw === undefined || raw === null) return {};
  if (isRecord(raw) || Array.isArray(raw)) return raw;
  if (typeof raw === 'string') return parseJsonString(raw);
  if (typeof raw === 'number' || typeof raw === 'boolean') return raw;
  return {};
}

function normalizeTextCandidate(value: unknown): string {
  if (typeof value === 'string') return value;
  if (!isRecord(value)) return '';
  return asTrimmedString(value.text ?? value.content ?? value.output_text);
}

function ensureAnthropicToolChoiceRecord(value: unknown): Record<string, unknown> | undefined {
  if (isRecord(value)) return value;
  if (typeof value === 'string') {
    const normalized = value.trim().toLowerCase();
    if (!normalized) return undefined;
    return { type: normalized };
  }
  return undefined;
}

function sanitizeToolReferenceBlock(item: Record<string, unknown>): Record<string, unknown> | null {
  const toolName = asTrimmedString(item.tool_name ?? item.toolName ?? item.name);
  if (!toolName) return null;
  const next: Record<string, unknown> = {
    ...item,
    type: 'tool_reference',
    tool_name: toolName,
  };
  delete next.toolName;
  if ('name' in next) delete next.name;
  return next;
}

function normalizeToolMessageContent(raw: unknown): string | Array<Record<string, unknown>> {
  if (raw === undefined || raw === null) return '';
  if (typeof raw === 'string') return raw;
  if (typeof raw === 'number' || typeof raw === 'boolean') return String(raw);

  if (Array.isArray(raw)) {
    const structuredBlocks = raw
      .map((item) => {
        if (typeof item === 'string') return toAnthropicTextBlock(item);
        if (!isRecord(item)) return null;
        const type = asTrimmedString(item.type).toLowerCase();
        if (type === 'tool_reference') return sanitizeToolReferenceBlock(item);
        if (type === 'text' || type === 'input_text' || type === 'output_text') {
          return toAnthropicTextBlock(normalizeTextCandidate(item));
        }
        if (type === 'image_url' || type === 'input_image') {
          return toAnthropicImageBlock(item);
        }
        if (type === 'file' || type === 'input_file') {
          const fileBlock = normalizeInputFileBlock(item);
          return fileBlock ? toAnthropicDocumentBlock(fileBlock) : null;
        }
        return null;
      })
      .filter((item): item is Record<string, unknown> => item !== null);
    if (structuredBlocks.length > 0) return structuredBlocks;

    const textParts = raw
      .map((item) => {
        if (typeof item === 'string') return item;
        if (!isRecord(item)) return '';
        return normalizeTextCandidate(item);
      })
      .filter((item) => item.length > 0);
    if (textParts.length > 0) return textParts.join('\n');
    return safeJsonStringify(raw);
  }

  if (isRecord(raw)) {
    const type = asTrimmedString(raw.type).toLowerCase();
    if (type === 'image_url' || type === 'input_image') {
      const imageBlock = toAnthropicImageBlock(raw);
      return imageBlock ? [imageBlock] : '';
    }
    if (type === 'file' || type === 'input_file') {
      const fileBlock = normalizeInputFileBlock(raw);
      if (!fileBlock) return '';
      const documentBlock = toAnthropicDocumentBlock(fileBlock);
      return documentBlock ? [documentBlock] : '';
    }
    const text = normalizeTextCandidate(raw);
    return text || safeJsonStringify(raw);
  }

  return '';
}

function maybeParseDataUrlImage(url: string): Record<string, unknown> | null {
  const match = /^data:(image\/[a-zA-Z0-9.+-]+);base64,(.+)$/i.exec(url);
  if (!match) return null;
  return {
    type: 'image',
    source: {
      type: 'base64',
      media_type: match[1],
      data: match[2],
    },
  };
}

function toAnthropicImageBlock(item: Record<string, unknown>): Record<string, unknown> | null {
  const rawImageUrl = item.image_url ?? item.url;
  if (typeof rawImageUrl === 'string' && rawImageUrl.trim()) {
    const parsed = maybeParseDataUrlImage(rawImageUrl.trim());
    if (parsed) return parsed;
    return {
      type: 'image',
      source: {
        type: 'url',
        url: rawImageUrl.trim(),
      },
    };
  }

  if (isRecord(rawImageUrl)) {
    const nestedUrl = asTrimmedString(rawImageUrl.url ?? rawImageUrl.image_url);
    if (!nestedUrl) return null;
    const parsed = maybeParseDataUrlImage(nestedUrl);
    if (parsed) return parsed;
    return {
      type: 'image',
      source: {
        type: 'url',
        url: nestedUrl,
      },
    };
  }

  return null;
}

function toAnthropicTextBlock(text: string): Record<string, unknown> | null {
  const normalized = text.trim();
  return normalized ? { type: 'text', text: normalized } : null;
}

function resolveAnthropicThinkingSignature(item: Record<string, unknown>): string | null | undefined {
  const rawSignature = asTrimmedString(item.signature ?? item.reasoning_signature);
  if (!rawSignature) return undefined;
  const decodedTaggedSignature = decodeAnthropicReasoningSignature(rawSignature);
  if (decodedTaggedSignature !== null) {
    return decodedTaggedSignature;
  }
  if (item.reasoning_signature !== undefined || rawSignature.startsWith('metapi:')) {
    return null;
  }
  return rawSignature;
}

function sanitizeAnthropicContentBlock(item: Record<string, unknown>): Record<string, unknown> | null {
  const type = asTrimmedString(item.type).toLowerCase();
  if (!type) {
    return toAnthropicTextBlock(normalizeTextCandidate(item));
  }

  if (type === 'text' || type === 'input_text' || type === 'output_text') {
    const textBlock = toAnthropicTextBlock(normalizeTextCandidate(item));
    if (!textBlock) return null;
    const next: Record<string, unknown> = { ...item, ...textBlock, type: 'text' };
    const cacheControl = sanitizeCacheControl(item.cache_control);
    if (cacheControl) next.cache_control = cacheControl;
    else delete next.cache_control;
    return next;
  }

  if (type === 'image_url' || type === 'input_image') {
    return toAnthropicImageBlock(item);
  }

  if (type === 'file' || type === 'input_file') {
    const fileBlock = normalizeInputFileBlock(item);
    return fileBlock ? toAnthropicDocumentBlock(fileBlock) : null;
  }

  if (type === 'thinking' || type === 'redacted_thinking' || type === 'reasoning') {
    const text = asTrimmedString(item.thinking ?? item.text ?? item.content ?? item.data);
    const signature = type === 'redacted_thinking' ? undefined : resolveAnthropicThinkingSignature(item);
    if (signature === null) return null;
    const hasThinkingCarrier = type !== 'redacted_thinking' && signature !== undefined;
    if (!text && !hasThinkingCarrier) return null;
    const next: Record<string, unknown> = { ...item };
    if (type === 'redacted_thinking') {
      next.type = 'redacted_thinking';
      next.data = text;
      delete next.thinking;
    } else {
      next.type = type === 'reasoning' ? 'thinking' : type;
      next.thinking = text;
      if (signature) {
        next.signature = signature;
      } else {
        delete next.signature;
      }
    }
    delete next.cache_control;
    delete next.text;
    delete next.content;
    delete next.reasoning_signature;
    return next;
  }

  if (type === 'tool_result') {
    const toolUseId = asTrimmedString(item.tool_use_id ?? item.toolUseId);
    const content = normalizeToolMessageContent(item.content ?? item.result);
    if (!toolUseId || (typeof content === 'string' ? !content : content.length <= 0)) return null;
    const next: Record<string, unknown> = {
      type: 'tool_result',
      tool_use_id: toolUseId,
      content,
    };
    const cacheControl = sanitizeCacheControl(item.cache_control);
    if (cacheControl) next.cache_control = cacheControl;
    return next;
  }

  if (type === 'tool_use') {
    const id = asTrimmedString(item.id);
    const name = asTrimmedString(item.name ?? item.toolName);
    if (!id || !name) return null;
    const next: Record<string, unknown> = {
      type: 'tool_use',
      id,
      name,
      input: normalizeAnthropicToolInput(item.input ?? item.arguments ?? item.argumentsText),
    };
    const cacheControl = sanitizeCacheControl(item.cache_control);
    if (cacheControl) next.cache_control = cacheControl;
    return next;
  }

  if (type === 'tool_reference') {
    return sanitizeToolReferenceBlock(item);
  }

  return { ...item };
}

function isCacheableAnthropicMessageBlock(item: Record<string, unknown>): boolean {
  const type = asTrimmedString(item.type).toLowerCase();
  if (type === 'thinking' || type === 'redacted_thinking') return false;
  if (type === 'text' || type === 'input_text' || type === 'output_text') {
    return normalizeTextCandidate(item).trim().length > 0;
  }
  return true;
}

function clearAnthropicCacheControls(body: Record<string, unknown>) {
  if (Array.isArray(body.tools)) {
    body.tools = body.tools.map((tool) => {
      if (!isRecord(tool)) return tool;
      const next = { ...tool };
      delete next.cache_control;
      return next;
    });
  }

  if (Array.isArray(body.system)) {
    body.system = body.system.map((entry) => {
      if (!isRecord(entry)) return entry;
      const next = { ...entry };
      delete next.cache_control;
      return next;
    });
  }

  const rawMessages = Array.isArray(body.messages) ? body.messages : [];
  body.messages = rawMessages.map((message) => {
    if (!isRecord(message)) return message;
    const next = { ...message };
    if (Array.isArray(next.content)) {
      next.content = next.content.map((item) => {
        if (!isRecord(item)) return item;
        const block = { ...item };
        delete block.cache_control;
        return block;
      });
    }
    return next;
  });
}

function normalizeAnthropicMessageContents(body: Record<string, unknown>) {
  const rawMessages = Array.isArray(body.messages) ? body.messages : [];
  body.messages = rawMessages.map((message) => {
    if (!isRecord(message) || Array.isArray(message.content)) return message;
    if (typeof message.content !== 'string' || message.content.length === 0) return message;
    return {
      ...message,
      content: [
        {
          type: 'text',
          text: message.content,
        },
      ],
    };
  });
}

function normalizeAnthropicSystemPrompts(body: Record<string, unknown>) {
  if (Array.isArray(body.system)) return;
  if (typeof body.system !== 'string' || body.system.length === 0) return;
  body.system = [
    {
      type: 'text',
      text: body.system,
    },
  ];
}

function ensureStructuralAnthropicCacheControls(body: Record<string, unknown>): number {
  let count = 0;

  if (Array.isArray(body.tools) && body.tools.length > 0) {
    const lastIndex = body.tools.length - 1;
    const lastTool = body.tools[lastIndex];
    if (isRecord(lastTool)) {
      body.tools[lastIndex] = {
        ...lastTool,
        cache_control: { type: 'ephemeral' },
      };
      count += 1;
    }
  }

  if (Array.isArray(body.system) && body.system.length > 0) {
    const lastIndex = body.system.length - 1;
    const lastPrompt = body.system[lastIndex];
    if (isRecord(lastPrompt)) {
      body.system[lastIndex] = {
        ...lastPrompt,
        cache_control: { type: 'ephemeral' },
      };
      count += 1;
    }
  }

  return count;
}

type AnthropicCacheRef = {
  get value(): Record<string, unknown>;
  set value(next: Record<string, unknown>);
};

function collectAnthropicCacheableMessageRefs(body: Record<string, unknown>): AnthropicCacheRef[] {
  const refs: AnthropicCacheRef[] = [];
  const messages = Array.isArray(body.messages) ? body.messages : [];

  messages.forEach((message, messageIndex) => {
    if (!isRecord(message) || !Array.isArray(message.content)) return;
    message.content.forEach((item, contentIndex) => {
      if (!isRecord(item) || !isCacheableAnthropicMessageBlock(item)) return;
      refs.push({
        get value() {
          const currentMessages = Array.isArray(body.messages) ? body.messages : [];
          const currentMessage = currentMessages[messageIndex];
          if (!isRecord(currentMessage) || !Array.isArray(currentMessage.content)) return item;
          const currentItem = currentMessage.content[contentIndex];
          return isRecord(currentItem) ? currentItem : item;
        },
        set value(next: Record<string, unknown>) {
          const currentMessages = Array.isArray(body.messages) ? [...body.messages] : [];
          const currentMessage = currentMessages[messageIndex];
          if (!isRecord(currentMessage) || !Array.isArray(currentMessage.content)) return;
          const nextContent = [...currentMessage.content];
          nextContent[contentIndex] = next;
          currentMessages[messageIndex] = {
            ...currentMessage,
            content: nextContent,
          };
          body.messages = currentMessages;
        },
      });
    });
  });

  return refs;
}

function addEphemeralCacheControl(item: Record<string, unknown>): Record<string, unknown> {
  return {
    ...item,
    cache_control: { type: 'ephemeral' },
  };
}

function sanitizeUnsupportedAnthropicCacheControls(body: Record<string, unknown>) {
  const rawMessages = Array.isArray(body.messages) ? body.messages : [];
  body.messages = rawMessages.map((message) => {
    if (!isRecord(message) || !Array.isArray(message.content)) return message;
    return {
      ...message,
      content: message.content.map((item) => {
        if (!isRecord(item)) return item;
        if (isCacheableAnthropicMessageBlock(item)) return item;
        const next = { ...item };
        delete next.cache_control;
        return next;
      }),
    };
  });
}

function optimizeAnthropicCacheControls(body: Record<string, unknown>) {
  normalizeAnthropicMessageContents(body);
  normalizeAnthropicSystemPrompts(body);
  clearAnthropicCacheControls(body);

  const structuralAnchors = ensureStructuralAnthropicCacheControls(body);
  const remaining = Math.max(0, MAX_ANTHROPIC_CACHE_CONTROL_BREAKPOINTS - structuralAnchors);
  if (remaining <= 0) {
    sanitizeUnsupportedAnthropicCacheControls(body);
    return;
  }

  const refs = collectAnthropicCacheableMessageRefs(body);
  if (refs.length <= 0) {
    sanitizeUnsupportedAnthropicCacheControls(body);
    return;
  }

  const desiredMessageAnchors = refs.length >= ADAPTIVE_ANTHROPIC_CACHE_CONTROL_BLOCK_WINDOW ? 2 : 1;
  const targetAnchors = Math.min(desiredMessageAnchors, remaining);
  const usedIndexes = new Set<number>();

  const applyAnchor = (index: number) => {
    if (index < 0 || index >= refs.length || usedIndexes.has(index)) return;
    usedIndexes.add(index);
    refs[index].value = addEphemeralCacheControl(refs[index].value);
  };

  applyAnchor(refs.length - 1);

  if (targetAnchors > 1) {
    const targetIndex = Math.max(refs.length - 1 - ADAPTIVE_ANTHROPIC_CACHE_CONTROL_BLOCK_WINDOW, 0);
    let chosen = -1;
    for (let index = targetIndex; index >= 0; index -= 1) {
      if (!usedIndexes.has(index)) {
        chosen = index;
        break;
      }
    }
    if (chosen < 0) {
      for (let index = targetIndex + 1; index < refs.length; index += 1) {
        if (!usedIndexes.has(index)) {
          chosen = index;
          break;
        }
      }
    }
    applyAnchor(chosen);
  }

  sanitizeUnsupportedAnthropicCacheControls(body);
}

function convertOpenAiContentToAnthropicBlocks(content: unknown): Array<Record<string, unknown>> {
  if (typeof content === 'string') {
    const textBlock = toAnthropicTextBlock(content);
    return textBlock ? [textBlock] : [];
  }

  if (!Array.isArray(content)) {
    if (isRecord(content)) {
      const single = sanitizeAnthropicContentBlock(content);
      return single ? [single] : [];
    }
    return [];
  }

  return content
    .map((item) => {
      if (typeof item === 'string') return toAnthropicTextBlock(item);
      if (!isRecord(item)) return null;
      return sanitizeAnthropicContentBlock(item);
    })
    .filter((item): item is Record<string, unknown> => !!item);
}

export function sanitizeAnthropicMessagesBody(
  body: Record<string, unknown>,
  options: { autoOptimizeCacheControls?: boolean } = {},
): Record<string, unknown> {
  const sanitized: Record<string, unknown> = { ...body };
  const autoOptimizeCacheControls = options.autoOptimizeCacheControls !== false;
  const hasTemperature = toFiniteNumber(sanitized.temperature) !== null;
  const hasTopP = toFiniteNumber(sanitized.top_p) !== null;
  if (hasTemperature && hasTopP) {
    delete sanitized.top_p;
  }

  const thinkingResult = sanitizeAnthropicThinkingConfig(sanitized.thinking);
  if (thinkingResult.value) {
    sanitized.thinking = thinkingResult.value;
  } else {
    delete sanitized.thinking;
  }

  const allowOutputConfigEffort = isRecord(sanitized.thinking)
    && asTrimmedString(sanitized.thinking.type).toLowerCase() === 'adaptive';
  const outputConfigResult = sanitizeAnthropicOutputConfig(
    sanitized.output_config ?? sanitized.outputConfig,
    { allowEffort: allowOutputConfigEffort },
  );
  if (outputConfigResult.value) {
    sanitized.output_config = outputConfigResult.value;
  } else {
    delete sanitized.output_config;
  }
  delete sanitized.outputConfig;

  const toolChoiceResult = sanitizeAnthropicToolChoiceValue(sanitized.tool_choice ?? sanitized.toolChoice);
  if (toolChoiceResult.value) {
    sanitized.tool_choice = toolChoiceResult.value;
  } else {
    delete sanitized.tool_choice;
  }
  delete sanitized.toolChoice;

  const rawMessages = Array.isArray(sanitized.messages) ? sanitized.messages : [];
  if (rawMessages.length > 0) {
    sanitized.messages = rawMessages.map((message) => {
      if (!isRecord(message)) return message;
      const next = { ...message };
      if (Array.isArray(next.content)) {
        next.content = next.content
          .map((item) => (isRecord(item) ? sanitizeAnthropicContentBlock(item) : item))
          .filter((item) => item !== null);
      }
      return next;
    });
  }

  if (autoOptimizeCacheControls) {
    optimizeAnthropicCacheControls(sanitized);
  } else {
    sanitizeUnsupportedAnthropicCacheControls(sanitized);
  }

  return sanitized;
}

function resolveOpenAiReasoningSettings(
  openaiBody: Record<string, unknown>,
): { thinking?: Record<string, unknown>; outputConfig?: Record<string, unknown> } {
  const explicitReasoning = isRecord(openaiBody.reasoning) ? openaiBody.reasoning : null;
  const reasoningEffort = asTrimmedString(
    openaiBody.reasoning_effort
    ?? explicitReasoning?.effort
    ?? explicitReasoning?.reasoning_effort,
  ).toLowerCase();
  const reasoningBudget = toPositiveInteger(
    openaiBody.reasoning_budget
    ?? explicitReasoning?.budget_tokens
    ?? explicitReasoning?.max_tokens,
  );

  const result: { thinking?: Record<string, unknown>; outputConfig?: Record<string, unknown> } = {};

  if (reasoningBudget) {
    result.thinking = {
      type: 'enabled',
      budget_tokens: reasoningBudget,
    };
  } else if (reasoningEffort && VALID_ANTHROPIC_EFFORTS.has(reasoningEffort)) {
    result.thinking = { type: 'adaptive' };
  }

  if (reasoningEffort && VALID_ANTHROPIC_EFFORTS.has(reasoningEffort)) {
    result.outputConfig = { effort: reasoningEffort };
  }

  return result;
}

export function convertOpenAiToolsToAnthropic(rawTools: unknown): unknown {
  if (!Array.isArray(rawTools)) return rawTools;

  const converted = rawTools
    .map((item) => {
      if (!isRecord(item)) return null;

      const type = asTrimmedString(item.type).toLowerCase();
      if (type === 'function' && isRecord(item.function)) {
        const fn = item.function;
        const name = asTrimmedString(fn.name);
        if (!name) return null;

        const mapped: Record<string, unknown> = { name };
        const description = asTrimmedString(fn.description);
        if (description) mapped.description = description;
        if (fn.parameters !== undefined) mapped.input_schema = fn.parameters;
        if (item.cache_control !== undefined) mapped.cache_control = item.cache_control;
        return mapped;
      }

      if (asTrimmedString(item.name) && item.input_schema !== undefined) {
        return item;
      }

      return null;
    })
    .filter((item): item is Record<string, unknown> => !!item);

  return converted.length > 0 ? converted : rawTools;
}

export function convertOpenAiToolChoiceToAnthropic(rawToolChoice: unknown): unknown {
  if (rawToolChoice === undefined) return undefined;

  let mappedValue: unknown = rawToolChoice;
  if (typeof rawToolChoice === 'string') {
    const normalized = rawToolChoice.trim().toLowerCase();
    if (normalized === 'required') mappedValue = { type: 'any' };
    else if (normalized === 'none') mappedValue = { type: 'none' };
    else if (normalized === 'auto') mappedValue = { type: 'auto' };
    else if (normalized === 'any') mappedValue = { type: 'any' };
    else mappedValue = rawToolChoice;
  }

  if (isRecord(rawToolChoice)) {
    const type = asTrimmedString(rawToolChoice.type).toLowerCase();
    if (type === 'function' && isRecord(rawToolChoice.function)) {
      const name = asTrimmedString(rawToolChoice.function.name);
      mappedValue = name ? { type: 'tool', name } : undefined;
    } else {
      mappedValue = rawToolChoice;
    }
  }

  if (mappedValue === undefined) return undefined;
  const toolChoiceResult = sanitizeAnthropicToolChoiceValue(mappedValue);
  return toolChoiceResult.value;
}

export function convertOpenAiBodyToAnthropicMessagesBody(
  openaiBody: Record<string, unknown>,
  modelName: string,
  stream: boolean,
): Record<string, unknown> {
  const rawMessages = Array.isArray(openaiBody.messages) ? openaiBody.messages : [];
  const systemContents: string[] = [];
  const messages: Array<{
    role: 'user' | 'assistant';
    content: string | Array<Record<string, unknown>>;
  }> = [];

  const appendAssistantMessage = (item: Record<string, unknown>) => {
    const role = asTrimmedString(item.role).toLowerCase() || 'assistant';
    if (role !== 'assistant') return;

    const contentBlocks = convertOpenAiContentToAnthropicBlocks(item.content);
    const reasoningCarrier = sanitizeAnthropicContentBlock({
      type: 'thinking',
      thinking: asTrimmedString(item.reasoning_content ?? item.reasoning),
      reasoning_signature: item.reasoning_signature,
      signature: item.signature,
    });
    if (reasoningCarrier) {
      contentBlocks.unshift(reasoningCarrier);
    }

    const rawToolCalls = Array.isArray(item.tool_calls) ? item.tool_calls : [];
    for (let index = 0; index < rawToolCalls.length; index += 1) {
      const toolCall = rawToolCalls[index];
      if (!isRecord(toolCall)) continue;
      const functionPart = isRecord(toolCall.function) ? toolCall.function : {};
      const id = asTrimmedString(toolCall.id) || `toolu_${Date.now()}_${index}`;
      const name = (
        asTrimmedString(functionPart.name)
        || asTrimmedString(toolCall.name)
        || `tool_${index}`
      );
      contentBlocks.push({
        type: 'tool_use',
        id,
        name,
        input: normalizeAnthropicToolInput(functionPart.arguments ?? toolCall.arguments),
      });
    }

    if (contentBlocks.length <= 0) return;
    if (contentBlocks.length === 1 && contentBlocks[0].type === 'text') {
      const singleText = asTrimmedString(contentBlocks[0].text);
      if (singleText) {
        messages.push({ role: 'assistant', content: singleText });
      }
      return;
    }

    messages.push({
      role: 'assistant',
      content: contentBlocks,
    });
  };

  for (let messageIndex = 0; messageIndex < rawMessages.length; messageIndex += 1) {
    const item = rawMessages[messageIndex];
    if (!isRecord(item)) continue;
    const role = asTrimmedString(item.role).toLowerCase() || 'user';

    if (role === 'system' || role === 'developer') {
      const contentBlocks = convertOpenAiContentToAnthropicBlocks(item.content);
      const text = contentBlocks
        .filter((block) => block.type === 'text' && typeof block.text === 'string')
        .map((block) => block.text as string)
        .filter(Boolean)
        .join('\n\n');
      if (text) systemContents.push(text);
      continue;
    }

    if (role === 'tool') {
      const toolResultBlocks: Array<Record<string, unknown>> = [];
      let cursor = messageIndex;
      while (cursor < rawMessages.length) {
        const toolCandidate = rawMessages[cursor];
        if (!isRecord(toolCandidate)) break;
        const toolRole = asTrimmedString(toolCandidate.role).toLowerCase();
        if (toolRole !== 'tool') break;

        const toolUseId = (
          asTrimmedString(toolCandidate.tool_call_id)
          || asTrimmedString(toolCandidate.id)
        );
        const toolResultContent = normalizeToolMessageContent(toolCandidate.content);
        const hasToolResultContent = typeof toolResultContent === 'string'
          ? toolResultContent.trim().length > 0
          : toolResultContent.length > 0;
        if (toolUseId && hasToolResultContent) {
          toolResultBlocks.push({
            type: 'tool_result',
            tool_use_id: toolUseId,
            content: toolResultContent,
          });
        }
        cursor += 1;
      }

      if (toolResultBlocks.length > 0 && cursor < rawMessages.length) {
        const nextItem = rawMessages[cursor];
        if (isRecord(nextItem) && asTrimmedString(nextItem.role).toLowerCase() === 'user') {
          const userBlocks = convertOpenAiContentToAnthropicBlocks(nextItem.content);
          toolResultBlocks.push(...userBlocks);
          cursor += 1;
        }
      }

      if (toolResultBlocks.length > 0) {
        messages.push({
          role: 'user',
          content: toolResultBlocks,
        });
      }

      messageIndex = cursor - 1;
      continue;
    }

    if (role === 'assistant') {
      appendAssistantMessage(item);
      continue;
    }

    const contentBlocks = convertOpenAiContentToAnthropicBlocks(item.content);
    if (contentBlocks.length <= 0) continue;

    if (contentBlocks.length === 1 && contentBlocks[0].type === 'text') {
      const singleText = asTrimmedString(contentBlocks[0].text);
      if (singleText) {
        messages.push({ role: 'user', content: singleText });
      }
      continue;
    }

    messages.push({
      role: 'user',
      content: contentBlocks,
    });
  }

  const body: Record<string, unknown> = {
    model: modelName,
    stream,
    messages,
    max_tokens: toFiniteNumber(openaiBody.max_tokens) ?? 4096,
  };

  const openAiMetadata = openaiBody.metadata;
  if (isRecord(openAiMetadata)) {
    const clonedMetadata = cloneJsonValue(openAiMetadata);
    if (isRecord(clonedMetadata) && 'user_id' in clonedMetadata) {
      body.metadata = clonedMetadata;
    }
  }

  if (systemContents.length > 0) {
    body.system = systemContents.join('\n\n');
  }

  const temperature = toFiniteNumber(openaiBody.temperature);
  if (temperature !== null) body.temperature = temperature;

  const topP = toFiniteNumber(openaiBody.top_p);
  if (topP !== null) body.top_p = topP;

  if (Array.isArray(openaiBody.stop) && openaiBody.stop.length > 0) {
    body.stop_sequences = openaiBody.stop;
  }

  if (openaiBody.tools !== undefined) body.tools = convertOpenAiToolsToAnthropic(openaiBody.tools);

  const parallelToolCalls = openaiBody.parallel_tool_calls;
  let anthropicToolChoice = convertOpenAiToolChoiceToAnthropic(openaiBody.tool_choice);
  if (parallelToolCalls === false) {
    const choiceRecord = ensureAnthropicToolChoiceRecord(anthropicToolChoice) ?? { type: 'auto' };
    choiceRecord.disable_parallel_tool_use = true;
    anthropicToolChoice = choiceRecord;
  }

  if (anthropicToolChoice !== undefined) {
    body.tool_choice = anthropicToolChoice;
  }

  const reasoningSettings = resolveOpenAiReasoningSettings(openaiBody);
  if (reasoningSettings.thinking) body.thinking = reasoningSettings.thinking;
  if (reasoningSettings.outputConfig) body.output_config = reasoningSettings.outputConfig;

  return sanitizeAnthropicMessagesBody(body, { autoOptimizeCacheControls: false });
}

export function validateAnthropicMessagesBody(
  body: Record<string, unknown>,
  options: { autoOptimizeCacheControls?: boolean } = {},
): { sanitizedBody?: Record<string, unknown>; error?: { statusCode: number; payload: unknown } } {
  const thinkingResult = sanitizeAnthropicThinkingConfig(body.thinking);
  if (thinkingResult.error) {
    return {
      error: {
        statusCode: 400,
        payload: { error: { message: thinkingResult.error, type: 'invalid_request_error' } },
      },
    };
  }

  const allowOutputConfigEffort = !!thinkingResult.value && thinkingResult.value.type === 'adaptive';
  const outputConfigResult = sanitizeAnthropicOutputConfig(
    body.output_config ?? body.outputConfig,
    { allowEffort: allowOutputConfigEffort },
  );
  if (outputConfigResult.error) {
    return {
      error: {
        statusCode: 400,
        payload: { error: { message: outputConfigResult.error, type: 'invalid_request_error' } },
      },
    };
  }

  const toolChoiceResult = sanitizeAnthropicToolChoiceValue(body.tool_choice ?? body.toolChoice);
  if (toolChoiceResult.error) {
    return {
      error: {
        statusCode: 400,
        payload: { error: { message: toolChoiceResult.error, type: 'invalid_request_error' } },
      },
    };
  }

  return { sanitizedBody: sanitizeAnthropicMessagesBody(body, options) };
}
