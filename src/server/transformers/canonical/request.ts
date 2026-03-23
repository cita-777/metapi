import {
  canonicalAttachmentFromInputFileBlock,
  canonicalAttachmentToNormalizedInputFile,
  type CanonicalAttachment,
} from './attachments.js';
import { normalizeCanonicalReasoningRequest } from './reasoning.js';
import type { CanonicalTool, CanonicalToolChoice } from './tools.js';
import type {
  CanonicalContentPart,
  CanonicalCliProfile,
  CanonicalContinuation,
  CanonicalMessage,
  CanonicalMessageRole,
  CanonicalOperation,
  CanonicalReasoningRequest,
  CanonicalRequestEnvelope,
  CanonicalSurface,
} from './types.js';
import { toOpenAiChatFileBlock } from '../shared/inputFile.js';

export type CreateCanonicalRequestEnvelopeInput = {
  operation?: CanonicalOperation;
  surface: CanonicalSurface;
  cliProfile?: CanonicalCliProfile;
  requestedModel: string;
  stream?: boolean;
  messages?: CanonicalMessage[];
  reasoning?: CanonicalReasoningRequest;
  tools?: CanonicalTool[];
  toolChoice?: CanonicalToolChoice;
  continuation?: CanonicalContinuation;
  metadata?: Record<string, unknown>;
  passthrough?: Record<string, unknown>;
  attachments?: CanonicalAttachment[];
};

function asTrimmedString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
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

function safeJsonStringify(value: unknown): string {
  try {
    return JSON.stringify(value);
  } catch {
    return '';
  }
}

function normalizeCanonicalContinuation(
  continuation: CanonicalContinuation | undefined,
): CanonicalContinuation | undefined {
  if (!continuation) return undefined;

  const normalized: CanonicalContinuation = {
    ...(asTrimmedString(continuation.sessionId) ? { sessionId: asTrimmedString(continuation.sessionId) } : {}),
    ...(asTrimmedString(continuation.previousResponseId)
      ? { previousResponseId: asTrimmedString(continuation.previousResponseId) }
      : {}),
    ...(asTrimmedString(continuation.promptCacheKey)
      ? { promptCacheKey: asTrimmedString(continuation.promptCacheKey) }
      : {}),
    ...(asTrimmedString(continuation.turnState) ? { turnState: asTrimmedString(continuation.turnState) } : {}),
  };

  return Object.keys(normalized).length > 0 ? normalized : undefined;
}

export function createCanonicalRequestEnvelope(
  input: CreateCanonicalRequestEnvelopeInput,
): CanonicalRequestEnvelope {
  const requestedModel = asTrimmedString(input.requestedModel);
  if (!requestedModel) {
    throw new Error('canonical request requires requestedModel');
  }

  return {
    operation: input.operation ?? 'generate',
    surface: input.surface,
    cliProfile: input.cliProfile ?? 'generic',
    requestedModel,
    stream: input.stream === true,
    messages: Array.isArray(input.messages) ? input.messages : [],
    ...(input.reasoning ? { reasoning: input.reasoning } : {}),
    ...(Array.isArray(input.tools) && input.tools.length > 0 ? { tools: input.tools } : {}),
    ...(input.toolChoice !== undefined ? { toolChoice: input.toolChoice } : {}),
    ...(normalizeCanonicalContinuation(input.continuation)
      ? { continuation: normalizeCanonicalContinuation(input.continuation) }
      : {}),
    ...(input.metadata ? { metadata: input.metadata } : {}),
    ...(input.passthrough ? { passthrough: input.passthrough } : {}),
  };
}

type CanonicalRequestFromOpenAiBodyInput = {
  body: Record<string, unknown>;
  surface: CanonicalSurface;
  cliProfile?: CanonicalCliProfile;
  operation?: CanonicalOperation;
  metadata?: Record<string, unknown>;
  passthrough?: Record<string, unknown>;
  continuation?: CanonicalContinuation;
};

function normalizeRole(value: unknown): CanonicalMessageRole {
  const role = asTrimmedString(value).toLowerCase();
  switch (role) {
    case 'system':
    case 'developer':
    case 'assistant':
    case 'tool':
      return role;
    default:
      return 'user';
  }
}

function openAiContentToCanonicalParts(content: unknown): CanonicalContentPart[] {
  if (typeof content === 'string') {
    return content ? [{ type: 'text', text: content }] : [];
  }

  if (!Array.isArray(content)) return [];

  const parts: CanonicalContentPart[] = [];
  for (const item of content) {
    if (typeof item === 'string') {
      if (item) parts.push({ type: 'text', text: item });
      continue;
    }
    if (!isRecord(item)) continue;

    const type = asTrimmedString(item.type).toLowerCase();
    if (type === 'text' || type === 'input_text' || type === 'output_text') {
      const text = asTrimmedString(item.text);
      if (text) parts.push({ type: 'text', text });
      continue;
    }
    if (type === 'reasoning' || type === 'thinking' || type === 'redacted_reasoning') {
      const text = asTrimmedString(item.text ?? item.reasoning ?? item.thinking);
      if (text) parts.push({ type: 'text', text, thought: true });
      continue;
    }
    if (type === 'image_url' && isRecord(item.image_url)) {
      const url = asTrimmedString(item.image_url.url);
      if (url) parts.push({ type: 'image', url });
      continue;
    }
    if (type === 'input_image' && isRecord(item.image_url)) {
      const url = asTrimmedString(item.image_url.url);
      if (url) parts.push({ type: 'image', url });
      continue;
    }
    if (type === 'input_file' || type === 'file') {
      const attachment = canonicalAttachmentFromInputFileBlock(item);
      if (attachment) {
        parts.push({
          type: 'file',
          ...(attachment.fileId ? { fileId: attachment.fileId } : {}),
          ...(attachment.fileUrl ? { fileUrl: attachment.fileUrl } : {}),
          ...(attachment.fileData ? { fileData: attachment.fileData } : {}),
          ...(attachment.mimeType !== undefined ? { mimeType: attachment.mimeType } : {}),
          ...(attachment.filename ? { filename: attachment.filename } : {}),
        });
      }
      continue;
    }
  }

  return parts;
}

function parseToolChoice(rawToolChoice: unknown): CanonicalToolChoice | undefined {
  if (typeof rawToolChoice === 'string') {
    const normalized = rawToolChoice.trim().toLowerCase();
    if (normalized === 'auto' || normalized === 'none' || normalized === 'required') return normalized;
    if (normalized === 'any') return 'required';
    return undefined;
  }

  if (!isRecord(rawToolChoice)) return undefined;
  const type = asTrimmedString(rawToolChoice.type).toLowerCase();
  if (type === 'auto' || type === 'none') return type;
  if (type === 'any' || type === 'required') return 'required';
  if (type === 'function') {
    const name = asTrimmedString(
      (isRecord(rawToolChoice.function) ? rawToolChoice.function.name : undefined)
      ?? rawToolChoice.name,
    );
    return name ? { type: 'tool', name } : undefined;
  }
  if (type !== 'tool') return undefined;

  const name = asTrimmedString(
    rawToolChoice.name
    ?? (isRecord(rawToolChoice.tool) ? rawToolChoice.tool.name : undefined),
  );
  return name ? { type: 'tool', name } : undefined;
}

function parseTools(rawTools: unknown): CanonicalTool[] | undefined {
  if (!Array.isArray(rawTools)) return undefined;

  const tools = rawTools
    .flatMap((item) => {
      if (!isRecord(item)) return [];
      const itemType = asTrimmedString(item.type).toLowerCase();

      if (itemType === 'function' && isRecord(item.function)) {
        const name = asTrimmedString(item.function.name);
        if (!name) return [];
        return [{
          name,
          ...(asTrimmedString(item.function.description)
            ? { description: asTrimmedString(item.function.description) }
            : {}),
          ...(typeof item.function.strict === 'boolean' ? { strict: item.function.strict } : {}),
          ...(isRecord(item.function.parameters) ? { inputSchema: cloneJsonValue(item.function.parameters) } : {}),
        }];
      }

      if ((itemType === '' || itemType === 'tool') && asTrimmedString(item.name)) {
        return [{
          name: asTrimmedString(item.name),
          ...(asTrimmedString(item.description)
            ? { description: asTrimmedString(item.description) }
            : {}),
          ...(typeof item.strict === 'boolean' ? { strict: item.strict } : {}),
          ...(isRecord(item.input_schema)
            ? { inputSchema: cloneJsonValue(item.input_schema) }
            : (isRecord(item.inputSchema) ? { inputSchema: cloneJsonValue(item.inputSchema) } : {})),
        }];
      }

      if (Array.isArray(item.functionDeclarations)) {
        return item.functionDeclarations.flatMap((declaration) => {
          if (!isRecord(declaration)) return [];
          const name = asTrimmedString(declaration.name);
          if (!name) return [];
          return [{
            name,
            ...(asTrimmedString(declaration.description)
              ? { description: asTrimmedString(declaration.description) }
              : {}),
            ...(isRecord(declaration.parametersJsonSchema)
              ? { inputSchema: cloneJsonValue(declaration.parametersJsonSchema) }
              : (isRecord(declaration.parameters) ? { inputSchema: cloneJsonValue(declaration.parameters) } : {})),
          }];
        });
      }

      return [];
    });

  return tools.length > 0 ? tools : undefined;
}

export function canonicalRequestFromOpenAiBody(
  input: CanonicalRequestFromOpenAiBodyInput,
): CanonicalRequestEnvelope {
  const body = input.body;
  const metadata = isRecord(input.metadata)
    ? input.metadata
    : (isRecord(body.metadata) ? cloneJsonValue(body.metadata) : undefined);
  const messages: CanonicalMessage[] = [];
  const rawMessages = Array.isArray(body.messages) ? body.messages : [];

  for (const rawMessage of rawMessages) {
    if (!isRecord(rawMessage)) continue;
    const role = normalizeRole(rawMessage.role);

    if (role === 'tool') {
      const toolCallId = asTrimmedString(rawMessage.tool_call_id ?? rawMessage.id);
      const resultText = typeof rawMessage.content === 'string'
        ? rawMessage.content
        : safeJsonStringify(rawMessage.content ?? '');
      messages.push({
        role: 'tool',
        parts: [{
          type: 'tool_result',
          toolCallId: toolCallId || 'tool',
          ...(resultText ? { resultText } : {}),
        }],
      });
      continue;
    }

    const parts = openAiContentToCanonicalParts(rawMessage.content);
    const toolCalls = Array.isArray(rawMessage.tool_calls) ? rawMessage.tool_calls : [];
    for (const toolCall of toolCalls) {
      if (!isRecord(toolCall)) continue;
      const fn = isRecord(toolCall.function) ? toolCall.function : {};
      const id = asTrimmedString(toolCall.id);
      const name = asTrimmedString(toolCall.name ?? fn.name);
      const argumentsJson = typeof fn.arguments === 'string'
        ? fn.arguments
        : safeJsonStringify(fn.arguments ?? toolCall.arguments ?? {});
      if (!name) continue;
      parts.push({
        type: 'tool_call',
        id: id || `tool_${parts.length}`,
        name,
        argumentsJson,
      });
    }

    messages.push({
      role,
      parts,
    });
  }

  const reasoningResult = normalizeCanonicalReasoningRequest({
    include: body.include,
    reasoning: body.reasoning,
    reasoning_effort: body.reasoning_effort,
    reasoning_budget: body.reasoning_budget,
    reasoning_summary: body.reasoning_summary,
  });

  const continuation: CanonicalContinuation = {
    ...(normalizeCanonicalContinuation(input.continuation) ?? {}),
    ...(asTrimmedString(body.previous_response_id)
      ? { previousResponseId: asTrimmedString(body.previous_response_id) }
      : {}),
    ...(asTrimmedString(body.prompt_cache_key)
      ? { promptCacheKey: asTrimmedString(body.prompt_cache_key) }
      : {}),
  };

  return createCanonicalRequestEnvelope({
    operation: input.operation ?? 'generate',
    surface: input.surface,
    cliProfile: input.cliProfile ?? 'generic',
    requestedModel: asTrimmedString(body.model),
    stream: body.stream === true,
    messages,
    ...(reasoningResult.reasoning ? { reasoning: reasoningResult.reasoning } : {}),
    ...(parseTools(body.tools) ? { tools: parseTools(body.tools) } : {}),
    ...(parseToolChoice(body.tool_choice) !== undefined ? { toolChoice: parseToolChoice(body.tool_choice) } : {}),
    ...(Object.keys(continuation).length > 0 ? { continuation } : {}),
    ...(metadata ? { metadata } : {}),
    ...((reasoningResult.metadata || input.passthrough)
      ? {
        passthrough: {
          ...(input.passthrough ?? {}),
          ...(reasoningResult.metadata ? { transformerMetadata: reasoningResult.metadata } : {}),
        },
      }
      : {}),
  });
}

function canonicalPartsToOpenAiContent(
  role: CanonicalMessageRole,
  parts: CanonicalContentPart[],
): { content: string | Array<Record<string, unknown>>; reasoning?: string; toolCalls?: Array<Record<string, unknown>> } {
  const contentBlocks: Array<Record<string, unknown>> = [];
  const toolCalls: Array<Record<string, unknown>> = [];
  const visibleText: string[] = [];
  const reasoningText: string[] = [];

  for (const part of parts) {
    if (part.type === 'text') {
      if (part.thought === true) {
        reasoningText.push(part.text);
      } else {
        visibleText.push(part.text);
      }
      continue;
    }
    if (part.type === 'image') {
      const url = asTrimmedString(part.url ?? part.dataUrl);
      if (url) {
        contentBlocks.push({
          type: 'image_url',
          image_url: { url },
        });
      }
      continue;
    }
    if (part.type === 'file') {
      const normalizedFile = canonicalAttachmentToNormalizedInputFile({
        kind: 'file',
        ...(part.fileId ? { fileId: part.fileId } : {}),
        ...(part.fileUrl ? { fileUrl: part.fileUrl } : {}),
        ...(part.fileData ? { fileData: part.fileData } : {}),
        ...(part.filename ? { filename: part.filename } : {}),
        ...(part.mimeType !== undefined ? { mimeType: part.mimeType } : {}),
      });
      contentBlocks.push(toOpenAiChatFileBlock(normalizedFile));
      continue;
    }
    if (part.type === 'tool_call') {
      toolCalls.push({
        id: part.id,
        type: 'function',
        function: {
          name: part.name,
          arguments: part.argumentsJson,
        },
      });
      continue;
    }
    if (part.type === 'tool_result' && role !== 'tool') {
      const text = part.resultText ?? safeJsonStringify(part.resultJson ?? '');
      if (text) {
        visibleText.push(text);
      }
    }
  }

  if (contentBlocks.length <= 0) {
    return {
      content: visibleText.join(''),
      ...(reasoningText.length > 0 ? { reasoning: reasoningText.join('') } : {}),
      ...(toolCalls.length > 0 ? { toolCalls } : {}),
    };
  }

  if (visibleText.length > 0) {
    contentBlocks.unshift({
      type: 'text',
      text: visibleText.join(''),
    });
  }

  return {
    content: contentBlocks,
    ...(reasoningText.length > 0 ? { reasoning: reasoningText.join('') } : {}),
    ...(toolCalls.length > 0 ? { toolCalls } : {}),
  };
}

function canonicalToolChoiceToOpenAi(toolChoice: CanonicalToolChoice | undefined): unknown {
  if (!toolChoice) return undefined;
  if (toolChoice === 'auto' || toolChoice === 'none') return toolChoice;
  if (toolChoice === 'required') return 'required';
  return {
    type: 'function',
    function: {
      name: toolChoice.name,
    },
  };
}

export function canonicalRequestToOpenAiChatBody(
  request: CanonicalRequestEnvelope,
): Record<string, unknown> {
  const messages: Array<Record<string, unknown>> = [];

  for (const message of request.messages) {
    if (message.role === 'tool') {
      for (const part of message.parts) {
        if (part.type !== 'tool_result') continue;
        messages.push({
          role: 'tool',
          tool_call_id: part.toolCallId,
          content: part.resultText ?? safeJsonStringify(part.resultJson ?? ''),
        });
      }
      continue;
    }

    const converted = canonicalPartsToOpenAiContent(message.role, message.parts);
    const nextMessage: Record<string, unknown> = {
      role: message.role,
      content: converted.content,
    };
    if (message.role === 'assistant' && converted.reasoning) {
      nextMessage.reasoning_content = converted.reasoning;
    }
    if (message.role === 'assistant' && converted.toolCalls && converted.toolCalls.length > 0) {
      nextMessage.tool_calls = converted.toolCalls;
      if (typeof nextMessage.content !== 'string' && (nextMessage.content as Array<unknown>).length <= 0) {
        nextMessage.content = '';
      }
    }
    messages.push(nextMessage);
  }

  const body: Record<string, unknown> = {
    model: request.requestedModel,
    stream: request.stream,
    messages,
  };

  if (request.reasoning?.effort) body.reasoning_effort = request.reasoning.effort;
  if (request.reasoning?.budgetTokens !== undefined) body.reasoning_budget = request.reasoning.budgetTokens;
  if (request.reasoning?.summary) body.reasoning_summary = request.reasoning.summary;
  const transformerMetadata = isRecord(request.passthrough?.transformerMetadata)
    ? request.passthrough.transformerMetadata as Record<string, unknown>
    : null;
  const passthroughInclude = Array.isArray(transformerMetadata?.include)
    ? (transformerMetadata.include as unknown[])
      .filter((item): item is string => typeof item === 'string' && item.trim().length > 0)
      .map((item) => item.trim())
    : [];
  const mergedInclude = [
    ...(request.reasoning?.includeEncryptedContent ? ['reasoning.encrypted_content'] : []),
    ...passthroughInclude,
  ].filter((item, index, all) => all.indexOf(item) === index);
  if (mergedInclude.length > 0) body.include = mergedInclude;
  if (request.metadata !== undefined) body.metadata = cloneJsonValue(request.metadata);
  if (request.continuation?.promptCacheKey) body.prompt_cache_key = request.continuation.promptCacheKey;
  if (request.continuation?.previousResponseId) body.previous_response_id = request.continuation.previousResponseId;
  if (Array.isArray(request.tools) && request.tools.length > 0) {
    body.tools = request.tools.map((tool) => ({
      type: 'function',
      function: {
        name: tool.name,
        ...(tool.description ? { description: tool.description } : {}),
        ...(typeof tool.strict === 'boolean' ? { strict: tool.strict } : {}),
        parameters: cloneJsonValue(tool.inputSchema ?? { type: 'object' }),
      },
    }));
  }
  const toolChoice = canonicalToolChoiceToOpenAi(request.toolChoice);
  if (toolChoice !== undefined) body.tool_choice = toolChoice;

  if (isRecord(request.passthrough)) {
    for (const [key, value] of Object.entries(request.passthrough)) {
      if (key === 'transformerMetadata' || body[key] !== undefined) continue;
      body[key] = cloneJsonValue(value);
    }
  }

  return body;
}

export * from './attachments.js';
export * from './reasoning.js';
export * from './tools.js';
export * from './types.js';
