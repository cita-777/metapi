import { TextDecoder, TextEncoder } from 'node:util';
import { resolveGeminiThinkingConfigFromRequest } from '../../transformers/gemini/generate-content/convert.js';

// Dummy sentinel used when no real thoughtSignature is available but thinking
// mode is enabled. Gemini accepts any base64 string and won't reject this.
const DUMMY_THOUGHT_SIGNATURE = 'c2tpcF90aG91Z2h0X3NpZ25hdHVyZV92YWxpZGF0b3I=';

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function asTrimmedString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function parseDataUrl(url: string): { mimeType: string; data: string } | null {
  if (!url.startsWith('data:')) return null;
  const [, rest] = url.split('data:', 2);
  const [meta, data] = rest.split(',', 2);
  if (!meta || !data) return null;
  const [mimeType] = meta.split(';', 1);
  return {
    mimeType: mimeType || 'application/octet-stream',
    data,
  };
}

function normalizeFunctionResponseResult(value: unknown): unknown {
  if (typeof value !== 'string') return value;
  const trimmed = value.trim();
  if (!trimmed) return value;
  try {
    return JSON.parse(trimmed);
  } catch {
    return value;
  }
}

function convertContentToGeminiParts(content: unknown): Array<Record<string, unknown>> {
  if (typeof content === 'string') {
    const trimmed = content.trim();
    return trimmed ? [{ text: trimmed }] : [];
  }

  if (isRecord(content)) {
    if (typeof content.text === 'string') {
      const trimmed = content.text.trim();
      return trimmed ? [{ text: trimmed }] : [];
    }
    return [];
  }

  if (!Array.isArray(content)) return [];

  const parts: Array<Record<string, unknown>> = [];
  for (const item of content) {
    if (!isRecord(item)) continue;
    const type = asTrimmedString(item.type).toLowerCase();
    if (type === 'text') {
      const text = asTrimmedString(item.text);
      if (text) parts.push({ text });
      continue;
    }
    if (type === 'image_url') {
      const imageUrl = asTrimmedString(item.image_url && isRecord(item.image_url) ? item.image_url.url : item.url);
      const parsed = imageUrl ? parseDataUrl(imageUrl) : null;
      if (parsed) {
        parts.push({
          inlineData: {
            mime_type: parsed.mimeType,
            data: parsed.data,
          },
        });
      }
      continue;
    }
    if (type === 'input_audio') {
      const data = asTrimmedString(item.data);
      if (data) {
        parts.push({
          inlineData: {
            mime_type: 'audio/wav',
            data,
          },
        });
      }
    }
  }
  return parts;
}

function buildGeminiTools(tools: unknown): Array<Record<string, unknown>> | undefined {
  if (!Array.isArray(tools)) return undefined;
  const declarations = tools
    .filter((item) => isRecord(item))
    .flatMap((item) => {
      if (asTrimmedString(item.type) !== 'function' || !isRecord(item.function)) return [];
      const fn = item.function as Record<string, unknown>;
      const name = asTrimmedString(fn.name);
      if (!name) return [];
      return [{
        name,
        ...(asTrimmedString(fn.description) ? { description: asTrimmedString(fn.description) } : {}),
        parametersJsonSchema: isRecord(fn.parameters) ? fn.parameters : { type: 'object', properties: {} },
      }];
    });

  if (declarations.length <= 0) return undefined;
  return [{ functionDeclarations: declarations }];
}

function buildGeminiToolConfig(toolChoice: unknown): Record<string, unknown> | undefined {
  if (typeof toolChoice === 'string') {
    const normalized = toolChoice.trim().toLowerCase();
    if (normalized === 'none') {
      return { functionCallingConfig: { mode: 'NONE' } };
    }
    if (normalized === 'required') {
      return { functionCallingConfig: { mode: 'ANY' } };
    }
    return { functionCallingConfig: { mode: 'AUTO' } };
  }
  return undefined;
}

export function buildGeminiGenerateContentRequestFromOpenAi(input: {
  body: Record<string, unknown>;
  modelName: string;
  instructions?: string;
}) {
  const request: Record<string, unknown> = {
    contents: [],
  };

  const messages = Array.isArray(input.body.messages) ? input.body.messages : [];
  const toolNameById = new Map<string, string>();
  for (const message of messages) {
    if (!isRecord(message) || asTrimmedString(message.role) !== 'assistant') continue;
    const toolCalls = Array.isArray(message.tool_calls) ? message.tool_calls : [];
    for (const toolCall of toolCalls) {
      if (!isRecord(toolCall) || !isRecord(toolCall.function)) continue;
      const id = asTrimmedString(toolCall.id);
      const name = asTrimmedString(toolCall.function.name);
      if (id && name) {
        toolNameById.set(id, name);
      }
    }
  }

  // Detect if thinking mode is enabled (needed for dummy signature fallback)
  const hasThinkingEnabled = !!resolveGeminiThinkingConfigFromRequest(input.modelName, input.body);

  // Collect thoughtSignatures from assistant tool_calls for injection.
  // OpenAI format stores signatures in provider_specific_fields or encoded in tool call IDs.
  const thoughtSignatureById = new Map<string, string>();
  for (const message of messages) {
    if (!isRecord(message) || asTrimmedString(message.role) !== 'assistant') continue;
    const toolCalls = Array.isArray(message.tool_calls) ? message.tool_calls : [];
    for (const toolCall of toolCalls) {
      if (!isRecord(toolCall)) continue;
      const id = asTrimmedString(toolCall.id);
      if (!id) continue;
      // Check provider_specific_fields first
      const providerFields = isRecord(toolCall.provider_specific_fields) ? toolCall.provider_specific_fields : null;
      if (providerFields && typeof providerFields.thought_signature === 'string') {
        thoughtSignatureById.set(id, providerFields.thought_signature);
      }
    }
  }

  const systemParts: Array<Record<string, unknown>> = [];
  if (typeof input.instructions === 'string' && input.instructions.trim()) {
    systemParts.push({ text: input.instructions.trim() });
  }

  for (const message of messages) {
    if (!isRecord(message)) continue;
    const role = asTrimmedString(message.role).toLowerCase();
    if (role === 'system' || role === 'developer') {
      systemParts.push(...convertContentToGeminiParts(message.content));
      continue;
    }
    if (role === 'tool') {
      const toolCallId = asTrimmedString(message.tool_call_id);
      const name = toolNameById.get(toolCallId) || 'unknown';
      const result = normalizeFunctionResponseResult(message.content);
      request.contents = [
        ...(Array.isArray(request.contents) ? request.contents : []),
        {
          role: 'user',
          parts: [{
            functionResponse: {
              name,
              response: {
                result,
              },
            },
          }],
        },
      ];
      continue;
    }

    const textParts = convertContentToGeminiParts(message.content);
    const fcParts: Array<Record<string, unknown>> = [];
    const toolCalls = Array.isArray(message.tool_calls) ? message.tool_calls : [];
    for (const toolCall of toolCalls) {
      if (!isRecord(toolCall) || !isRecord(toolCall.function)) continue;
      const name = asTrimmedString(toolCall.function.name);
      if (!name) continue;
      const rawArguments = toolCall.function.arguments;
      let args: unknown = {};
      if (typeof rawArguments === 'string' && rawArguments.trim()) {
        try {
          args = JSON.parse(rawArguments);
        } catch {
          args = { raw: rawArguments };
        }
      } else if (isRecord(rawArguments)) {
        args = rawArguments;
      }
      const fcPart: Record<string, unknown> = {
        functionCall: { name, args },
      };
      // Inject thoughtSignature if available from provider_specific_fields.
      // If no signature is found, use a dummy sentinel so Gemini doesn't reject
      // the request outright. Gemini 3+ requires thoughtSignature on all
      // functionCall parts when thinking is enabled.
      // Ref: https://ai.google.dev/gemini-api/docs/thought-signatures
      const id = asTrimmedString(toolCall.id);
      const signature = thoughtSignatureById.get(id);
      if (signature) {
        fcPart.thoughtSignature = signature;
      } else if (hasThinkingEnabled) {
        fcPart.thoughtSignature = DUMMY_THOUGHT_SIGNATURE;
      }
      fcParts.push(fcPart);
    }

    const geminiRole = role === 'assistant' ? 'model' : 'user';

    // Gemini requires that parts WITH thoughtSignature and parts WITHOUT
    // are not mixed in the same message. Split if needed.
    // Ref: https://ai.google.dev/gemini-api/docs/thought-signatures
    const hasSigned = fcParts.some((p) => 'thoughtSignature' in p);
    if (hasSigned && textParts.length > 0 && fcParts.length > 0) {
      // Emit text parts first, then functionCall parts in a separate message
      request.contents = [
        ...(Array.isArray(request.contents) ? request.contents : []),
        { role: geminiRole, parts: textParts },
        { role: geminiRole, parts: fcParts },
      ];
    } else {
      const allParts = [...textParts, ...fcParts];
      if (allParts.length <= 0) continue;
      request.contents = [
        ...(Array.isArray(request.contents) ? request.contents : []),
        { role: geminiRole, parts: allParts },
      ];
    }
  }

  if (systemParts.length > 0) {
    request.systemInstruction = {
      role: 'user',
      parts: systemParts,
    };
  }

  const generationConfig: Record<string, unknown> = {};
  const maxOutputTokens = Number(
    input.body.max_output_tokens
    ?? input.body.max_completion_tokens
    ?? input.body.max_tokens
    ?? 0,
  );
  if (Number.isFinite(maxOutputTokens) && maxOutputTokens > 0) {
    generationConfig.maxOutputTokens = Math.trunc(maxOutputTokens);
  }
  const temperature = Number(input.body.temperature);
  if (Number.isFinite(temperature)) generationConfig.temperature = temperature;
  const topP = Number(input.body.top_p);
  if (Number.isFinite(topP)) generationConfig.topP = topP;
  const topK = Number(input.body.top_k);
  if (Number.isFinite(topK)) generationConfig.topK = topK;
  if (Array.isArray(input.body.stop) && input.body.stop.length > 0) {
    generationConfig.stopSequences = input.body.stop.filter((item): item is string => typeof item === 'string' && item.trim().length > 0);
  }
  const thinkingConfig = resolveGeminiThinkingConfigFromRequest(input.modelName, input.body);
  if (thinkingConfig) {
    generationConfig.thinkingConfig = thinkingConfig;
  }
  if (Object.keys(generationConfig).length > 0) {
    request.generationConfig = generationConfig;
  }

  const geminiTools = buildGeminiTools(input.body.tools);
  if (geminiTools) {
    request.tools = geminiTools;
  }
  const toolConfig = buildGeminiToolConfig(input.body.tool_choice);
  if (toolConfig) {
    request.toolConfig = toolConfig;
  }

  return request;
}

export function wrapGeminiCliRequest(input: {
  modelName: string;
  projectId: string;
  request: Record<string, unknown>;
}) {
  const { model, ...requestPayload } = input.request;
  return {
    project: input.projectId,
    model: input.modelName,
    request: requestPayload,
  };
}

export function unwrapGeminiCliPayload<T>(payload: T): unknown {
  if (!isRecord(payload)) return payload;
  if (payload.response !== undefined) {
    return payload.response;
  }
  return payload;
}

function rewriteGeminiCliSseEventBlock(block: string): string {
  const lines = block.split(/\r?\n/g);
  return lines.map((line) => {
    if (!line.startsWith('data:')) return line;
    const data = line.slice(5).trim();
    if (!data || data === '[DONE]') return line;
    try {
      const parsed = JSON.parse(data);
      return `data: ${JSON.stringify(unwrapGeminiCliPayload(parsed))}`;
    } catch {
      return line;
    }
  }).join('\n');
}

export function createGeminiCliStreamReader(reader: {
  read(): Promise<{ done: boolean; value?: Uint8Array }>;
  cancel(reason?: unknown): Promise<unknown>;
  releaseLock(): void;
}) {
  const decoder = new TextDecoder();
  const encoder = new TextEncoder();
  const outputQueue: Uint8Array[] = [];
  let buffer = '';
  let done = false;

  async function fillQueue() {
    while (outputQueue.length <= 0 && !done) {
      const result = await reader.read();
      if (result.done) {
        done = true;
        const tail = decoder.decode();
        if (tail) buffer += tail;
        if (buffer.trim()) {
          outputQueue.push(encoder.encode(`${rewriteGeminiCliSseEventBlock(buffer)}\n\n`));
          buffer = '';
        }
        break;
      }
      if (!result.value) continue;
      buffer += decoder.decode(result.value, { stream: true });
      let separatorIndex = buffer.indexOf('\n\n');
      while (separatorIndex >= 0) {
        const block = buffer.slice(0, separatorIndex);
        buffer = buffer.slice(separatorIndex + 2);
        outputQueue.push(encoder.encode(`${rewriteGeminiCliSseEventBlock(block)}\n\n`));
        separatorIndex = buffer.indexOf('\n\n');
      }
    }
  }

  return {
    async read() {
      await fillQueue();
      if (outputQueue.length > 0) {
        return { done: false, value: outputQueue.shift() };
      }
      return { done: true, value: undefined };
    },
    cancel(reason?: unknown) {
      return reader.cancel(reason);
    },
    releaseLock() {
      reader.releaseLock();
    },
  };
}
