import { normalizeInputFileBlock, toResponsesInputFileBlock } from '../../shared/inputFile.js';

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object';
}

function asTrimmedString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
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
    const text = asTrimmedString(item.text ?? item.content ?? item.output_text);
    return text ? { type: toTextBlockType(role), text } : null;
  }

  if (type === 'input_text' || type === 'output_text' || type === 'text') {
    const text = asTrimmedString(item.text ?? item.content ?? item.output_text);
    if (!text) return null;
    return {
      ...item,
      type: type === 'text' ? toTextBlockType(role) : type,
      text,
    };
  }

  if (type === 'input_image' || type === 'image_url') {
    const imageUrl = normalizeImageUrlValue(item.image_url ?? item.url);
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

  if (type === 'function_call' || type === 'function_call_output') {
    return item;
  }

  return item;
}

export function normalizeResponsesMessageContent(content: unknown, role: string): unknown {
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

export function normalizeResponsesMessageItem(item: Record<string, unknown>): Record<string, unknown> {
  const type = asTrimmedString(item.type).toLowerCase();
  if (type === 'function_call' || type === 'function_call_output') {
    return item;
  }

  const role = asTrimmedString(item.role).toLowerCase() || 'user';
  const normalizedContent = normalizeResponsesMessageContent(item.content ?? item.text, role);

  if (type === 'message') {
    return {
      ...item,
      role,
      content: normalizedContent,
    };
  }

  if (asTrimmedString(item.role)) {
    return {
      type: 'message',
      role,
      content: normalizedContent,
    };
  }

  if (typeof item.content === 'string') {
    const text = item.content.trim();
    return text ? toResponsesInputMessageFromText(text) : item;
  }

  return item;
}

export function normalizeResponsesInputForCompatibility(input: unknown): unknown {
  if (typeof input === 'string') {
    const normalized = input.trim();
    if (!normalized) return input;
    return [toResponsesInputMessageFromText(normalized)];
  }

  if (Array.isArray(input)) {
    return input.map((item) => {
      if (typeof item === 'string') {
        const normalized = item.trim();
        return normalized ? toResponsesInputMessageFromText(normalized) : item;
      }
      if (!isRecord(item)) return item;
      return normalizeResponsesMessageItem(item);
    });
  }

  if (isRecord(input)) {
    return [normalizeResponsesMessageItem(input)];
  }

  return input;
}

export function buildResponsesCompatibilityBodies(
  body: Record<string, unknown>,
): Record<string, unknown>[] {
  const candidates: Record<string, unknown>[] = [];
  const seen = new Set<string>();
  try {
    const originalKey = JSON.stringify(body);
    if (originalKey) seen.add(originalKey);
  } catch {
    // ignore non-serializable bodies
  }

  const push = (next: Record<string, unknown> | null) => {
    if (!next) return;
    let key = '';
    try {
      key = JSON.stringify(next);
    } catch {
      return;
    }
    if (!key || seen.has(key)) return;
    seen.add(key);
    candidates.push(next);
  };

  push(stripResponsesMetadata(body));
  const coreModel = typeof body.model === 'string' ? body.model.trim() : '';
  if (coreModel && body.input !== undefined) {
    const richCandidate: Record<string, unknown> = {
      model: coreModel,
      input: body.input,
      stream: body.stream === true,
    };
    const maxOutputTokens = toFiniteNumber(body.max_output_tokens);
    if (maxOutputTokens !== null && maxOutputTokens > 0) {
      richCandidate.max_output_tokens = Math.trunc(maxOutputTokens);
    }
    const temperature = toFiniteNumber(body.temperature);
    if (temperature !== null) richCandidate.temperature = temperature;
    const topP = toFiniteNumber(body.top_p);
    if (topP !== null) richCandidate.top_p = topP;
    const instructions = getExplicitResponsesInstructions(body);
    if (instructions !== null) richCandidate.instructions = instructions;

    const passthroughFields = [
      'reasoning',
      'safety_identifier',
      'max_tool_calls',
      'prompt_cache_key',
      'prompt_cache_retention',
      'background',
      'top_logprobs',
    ] as const;
    for (const key of passthroughFields) {
      if (body[key] === undefined) continue;
      richCandidate[key] = cloneJsonValue(body[key]);
    }
    push(richCandidate);
  }
  push(buildStrictResponsesBody(body));
  return candidates;
}

export function buildResponsesCompatibilityHeaderCandidates(
  headers: Record<string, string>,
  stream: boolean,
): Record<string, string>[] {
  const candidates: Record<string, string>[] = [];
  const seen = new Set<string>();
  const push = (next: Record<string, string>) => {
    const normalizedEntries = Object.entries(next)
      .filter(([, value]) => typeof value === 'string' && value.trim().length > 0)
      .map(([key, value]) => [key.toLowerCase(), value] as const)
      .sort(([a], [b]) => a.localeCompare(b));
    const key = JSON.stringify(normalizedEntries);
    if (!key || seen.has(key)) return;
    seen.add(key);
    candidates.push(Object.fromEntries(normalizedEntries));
  };

  push(headers);

  const minimal: Record<string, string> = {};
  for (const [rawKey, rawValue] of Object.entries(headers)) {
    const key = rawKey.toLowerCase();
    if (
      key === 'authorization'
      || key === 'x-api-key'
      || key === 'content-type'
      || key === 'accept'
    ) {
      minimal[key] = rawValue;
    }
  }
  if (!minimal['content-type']) minimal['content-type'] = 'application/json';
  if (stream && !minimal.accept) minimal.accept = 'text/event-stream';
  push(minimal);

  return candidates;
}

export function shouldRetryResponsesCompatibility(input: {
  endpoint: string;
  status: number;
  rawErrText: string;
}): boolean {
  if (input.endpoint !== 'responses') return false;
  if (input.status !== 400) return false;
  const parsedError = parseUpstreamErrorShape(input.rawErrText);
  const type = parsedError.type.trim().toLowerCase();
  const code = parsedError.code.trim().toLowerCase();
  const message = parsedError.message.trim().toLowerCase();
  const compact = `${type} ${code} ${message}`.trim();
  const rawCompact = (input.rawErrText || '').toLowerCase();

  if (
    compact.includes('invalid_api_key')
    || compact.includes('authentication')
    || compact.includes('unauthorized')
    || compact.includes('forbidden')
    || compact.includes('insufficient_quota')
    || compact.includes('rate_limit')
  ) {
    return false;
  }

  if (type === 'upstream_error' || code === 'upstream_error') return true;
  if (message === 'upstream_error' || message === 'upstream request failed') return true;
  if (rawCompact.includes('upstream_error')) return true;

  return true;
}

export function shouldDowngradeResponsesChatToMessages(
  endpointPath: string,
  status: number,
  upstreamErrorText: string,
): boolean {
  if (!endpointPath.includes('/chat/completions')) return false;
  if (status < 400 || status >= 500) return false;
  return /messages\s+is\s+required/i.test(upstreamErrorText);
}

function extractTextFromResponsesContent(content: unknown): string {
  if (typeof content === 'string') return content.trim();
  if (!Array.isArray(content)) return '';
  return content
    .map((item) => {
      if (!isRecord(item)) return '';
      return asTrimmedString(item.text ?? item.content ?? item.output_text);
    })
    .filter((item) => item.length > 0)
    .join('\n');
}

function safeJsonStringify(value: unknown): string {
  try {
    return JSON.stringify(value);
  } catch {
    return '';
  }
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

function normalizeToolMessageContent(raw: unknown): string {
  if (raw === undefined || raw === null) return '';
  if (typeof raw === 'string') return raw;
  if (typeof raw === 'number' || typeof raw === 'boolean') return String(raw);
  if (Array.isArray(raw)) {
    const normalized = normalizeResponsesMessageContent(raw, 'user');
    const text = extractTextFromResponsesContent(normalized);
    return text || safeJsonStringify(raw);
  }
  if (isRecord(raw)) {
    const normalized = normalizeResponsesMessageContent(raw, 'user');
    const text = extractTextFromResponsesContent(normalized);
    return text || safeJsonStringify(raw);
  }
  return '';
}

function toFiniteNumber(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
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

function parseUpstreamErrorShape(rawText: string): {
  type: string;
  code: string;
  message: string;
} {
  try {
    const parsed = JSON.parse(rawText) as Record<string, unknown>;
    const error = (parsed.error && typeof parsed.error === 'object')
      ? parsed.error as Record<string, unknown>
      : parsed;
    return {
      type: typeof error.type === 'string' ? error.type.trim().toLowerCase() : '',
      code: typeof error.code === 'string' ? error.code.trim().toLowerCase() : '',
      message: typeof error.message === 'string' ? error.message.trim() : '',
    };
  } catch {
    return { type: '', code: '', message: '' };
  }
}

function getExplicitResponsesInstructions(body: Record<string, unknown>): string | null {
  if (!Object.prototype.hasOwnProperty.call(body, 'instructions')) return null;
  return typeof body.instructions === 'string' ? body.instructions.trim() : '';
}

function stripResponsesMetadata(
  body: Record<string, unknown>,
): Record<string, unknown> | null {
  if (!Object.prototype.hasOwnProperty.call(body, 'metadata')) return null;
  const next = { ...body };
  delete next.metadata;
  return next;
}

function buildCoreResponsesBody(
  body: Record<string, unknown>,
): Record<string, unknown> | null {
  const model = typeof body.model === 'string' ? body.model.trim() : '';
  if (!model) return null;
  if (body.input === undefined) return null;

  const core: Record<string, unknown> = {
    model,
    input: body.input,
    stream: body.stream === true,
  };

  const maxOutputTokens = toFiniteNumber(body.max_output_tokens);
  if (maxOutputTokens !== null && maxOutputTokens > 0) {
    core.max_output_tokens = Math.trunc(maxOutputTokens);
  }

  const temperature = toFiniteNumber(body.temperature);
  if (temperature !== null) core.temperature = temperature;

  const topP = toFiniteNumber(body.top_p);
  if (topP !== null) core.top_p = topP;

  const instructions = getExplicitResponsesInstructions(body);
  if (instructions !== null) core.instructions = instructions;

  const passthroughFields = [
    'reasoning',
    'safety_identifier',
    'max_tool_calls',
    'prompt_cache_key',
    'prompt_cache_retention',
    'background',
    'top_logprobs',
  ] as const;
  for (const key of passthroughFields) {
    if (body[key] === undefined) continue;
    core[key] = cloneJsonValue(body[key]);
  }

  return core;
}

function buildStrictResponsesBody(
  body: Record<string, unknown>,
): Record<string, unknown> | null {
  const model = typeof body.model === 'string' ? body.model.trim() : '';
  if (!model) return null;
  if (body.input === undefined) return null;

  const explicitInstructions = getExplicitResponsesInstructions(body);

  return {
    model,
    input: body.input,
    stream: body.stream === true,
    ...(explicitInstructions !== null
      ? { instructions: explicitInstructions }
      : {}),
  };
}

const ALLOWED_RESPONSES_FIELDS = new Set([
  'model',
  'input',
  'instructions',
  'max_output_tokens',
  'max_completion_tokens',
  'temperature',
  'top_p',
  'truncation',
  'tools',
  'tool_choice',
  'parallel_tool_calls',
  'metadata',
  'reasoning',
  'store',
  'stream',
  'user',
  'previous_response_id',
  'text',
  'audio',
  'include',
  'response_format',
  'service_tier',
  'stop',
  'n',
]);

export function convertOpenAiBodyToResponsesBody(
  openaiBody: Record<string, unknown>,
  modelName: string,
  stream: boolean,
): Record<string, unknown> {
  const rawMessages = Array.isArray(openaiBody.messages) ? openaiBody.messages : [];
  const systemContents: string[] = [];
  const inputItems: Array<Record<string, unknown>> = [];

  for (const item of rawMessages) {
    if (!isRecord(item)) continue;
    const role = asTrimmedString(item.role).toLowerCase() || 'user';

    if (role === 'system' || role === 'developer') {
      const normalized = normalizeResponsesMessageContent(item.content, 'user');
      const content = extractTextFromResponsesContent(normalized).trim();
      if (content) systemContents.push(content);
      continue;
    }

    if (role === 'assistant') {
      const normalizedAssistantContent = normalizeResponsesMessageContent(item.content, 'assistant');
      if (Array.isArray(normalizedAssistantContent) && normalizedAssistantContent.length > 0) {
        inputItems.push({
          type: 'message',
          role: 'assistant',
          content: normalizedAssistantContent,
        });
      }

      const rawToolCalls = Array.isArray(item.tool_calls) ? item.tool_calls : [];
      for (let index = 0; index < rawToolCalls.length; index += 1) {
        const toolCall = rawToolCalls[index];
        if (!isRecord(toolCall)) continue;
        const functionPart = isRecord(toolCall.function) ? toolCall.function : {};
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
          name,
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
        output: normalizeToolMessageContent(item.content),
      });
      continue;
    }

    const normalizedUserContent = normalizeResponsesMessageContent(item.content, 'user');
    if (Array.isArray(normalizedUserContent) && normalizedUserContent.length > 0) {
      inputItems.push({
        type: 'message',
        role: 'user',
        content: normalizedUserContent,
      });
    }
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
  if (openaiBody.reasoning !== undefined) body.reasoning = openaiBody.reasoning;
  if (openaiBody.parallel_tool_calls !== undefined) body.parallel_tool_calls = openaiBody.parallel_tool_calls;
  if (openaiBody.tools !== undefined) body.tools = openaiBody.tools;
  if (openaiBody.tool_choice !== undefined) body.tool_choice = openaiBody.tool_choice;

  return {
    ...body,
    input: normalizeResponsesInputForCompatibility(body.input),
  };
}

export function sanitizeResponsesBodyForProxy(
  body: Record<string, unknown>,
  modelName: string,
  stream: boolean,
): Record<string, unknown> {
  let normalized: Record<string, unknown> = {
    ...body,
    model: modelName,
    stream,
  };

  if (normalized.input === undefined) {
    if (Array.isArray((normalized as Record<string, unknown>).messages)) {
      normalized = convertOpenAiBodyToResponsesBody(normalized, modelName, stream);
    } else {
      const prompt = asTrimmedString((normalized as Record<string, unknown>).prompt);
      if (prompt) {
        normalized = {
          ...normalized,
          input: [toResponsesInputMessageFromText(prompt)],
        };
      }
    }
  } else {
    normalized = {
      ...normalized,
      input: normalizeResponsesInputForCompatibility(normalized.input),
    };
  }

  const sanitized: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(normalized)) {
    if (!ALLOWED_RESPONSES_FIELDS.has(key)) continue;
    if (key === 'max_completion_tokens') continue;
    sanitized[key] = value;
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
