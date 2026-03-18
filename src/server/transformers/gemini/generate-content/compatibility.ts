import type { NormalizedFinalResponse } from '../../shared/normalized.js';
import { extractReasoningMetadataFromGeminiRequest } from './convert.js';

type GeminiRecord = Record<string, unknown>;

function isRecord(value: unknown): value is GeminiRecord {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function asTrimmedString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function parseJsonIfPossible(value: string): unknown {
  const trimmed = value.trim();
  if (!trimmed) return {};
  try {
    return JSON.parse(trimmed);
  } catch {
    return { raw: value };
  }
}

function buildDataUrl(part: GeminiRecord): string | null {
  const inlineData = isRecord(part.inlineData) ? part.inlineData : null;
  if (!inlineData) return null;
  const mimeType = asTrimmedString(inlineData.mime_type ?? inlineData.mimeType) || 'application/octet-stream';
  const data = asTrimmedString(inlineData.data);
  if (!data) return null;
  return `data:${mimeType};base64,${data}`;
}

function toOpenAiContent(contentParts: GeminiRecord[]): string | Array<Record<string, unknown>> {
  const blocks: Array<Record<string, unknown>> = [];
  let textContent = '';

  for (const part of contentParts) {
    if (typeof part.text === 'string' && part.text.length > 0) {
      if (part.thought === true) continue;
      textContent += part.text;
      continue;
    }

    const dataUrl = buildDataUrl(part);
    if (dataUrl) {
      blocks.push({
        type: 'image_url',
        image_url: { url: dataUrl },
      });
    }
  }

  if (blocks.length <= 0) {
    return textContent;
  }

  if (textContent) {
    blocks.unshift({
      type: 'text',
      text: textContent,
    });
  }
  return blocks;
}

function extractToolDeclarations(tools: unknown): Array<Record<string, unknown>> | undefined {
  if (!Array.isArray(tools)) return undefined;
  const next = tools.flatMap((tool) => {
    if (!isRecord(tool) || !Array.isArray(tool.functionDeclarations)) return [];
    return tool.functionDeclarations.flatMap((declaration) => {
      if (!isRecord(declaration)) return [];
      const name = asTrimmedString(declaration.name);
      if (!name) return [];
      return [{
        type: 'function',
        function: {
          name,
          ...(asTrimmedString(declaration.description)
            ? { description: asTrimmedString(declaration.description) }
            : {}),
          parameters: isRecord(declaration.parametersJsonSchema)
            ? declaration.parametersJsonSchema
            : (isRecord(declaration.parameters) ? declaration.parameters : { type: 'object', properties: {} }),
        },
      }];
    });
  });
  return next.length > 0 ? next : undefined;
}

function extractToolChoice(toolConfig: unknown): string | undefined {
  const functionCallingConfig = (
    isRecord(toolConfig) && isRecord(toolConfig.functionCallingConfig)
      ? toolConfig.functionCallingConfig
      : null
  );
  const mode = asTrimmedString(functionCallingConfig?.mode).toUpperCase();
  if (mode === 'NONE') return 'none';
  if (mode === 'ANY' || mode === 'VALIDATED') return 'required';
  if (mode === 'AUTO') return 'auto';
  return undefined;
}

function buildGeminiMessages(body: GeminiRecord): Array<Record<string, unknown>> {
  const messages: Array<Record<string, unknown>> = [];

  if (isRecord(body.systemInstruction) && Array.isArray(body.systemInstruction.parts)) {
    const content = toOpenAiContent(
      body.systemInstruction.parts.filter((part): part is GeminiRecord => isRecord(part)),
    );
    const hasContent = typeof content === 'string' ? content.length > 0 : content.length > 0;
    if (hasContent) {
      messages.push({
        role: 'system',
        content,
      });
    }
  }

  const contents = Array.isArray(body.contents) ? body.contents : [];
  for (const contentItem of contents) {
    if (!isRecord(contentItem)) continue;
    const role = asTrimmedString(contentItem.role) === 'model' ? 'assistant' : 'user';
    const parts = Array.isArray(contentItem.parts)
      ? contentItem.parts.filter((part): part is GeminiRecord => isRecord(part))
      : [];

    const toolCalls = parts
      .map((part, index) => {
        const functionCall = isRecord(part.functionCall) ? part.functionCall : null;
        const name = asTrimmedString(functionCall?.name);
        if (!functionCall || !name) return null;
        return {
          id: asTrimmedString(functionCall.id) || `call_${index}`,
          type: 'function',
          function: {
            name,
            arguments: JSON.stringify(functionCall.args ?? {}),
          },
        };
      })
      .filter((item): item is NonNullable<typeof item> => !!item);

    const functionResponses = parts
      .map((part) => (isRecord(part.functionResponse) ? part.functionResponse : null))
      .filter((item): item is GeminiRecord => !!item);

    if (functionResponses.length > 0) {
      for (let index = 0; index < functionResponses.length; index += 1) {
        const functionResponse = functionResponses[index] as GeminiRecord;
        const toolName = asTrimmedString(functionResponse.name) || `tool_${index}`;
        const toolResponse = functionResponse.response;
        messages.push({
          role: 'tool',
          tool_call_id: toolName,
          content: JSON.stringify(toolResponse ?? {}),
        });
      }
      continue;
    }

    const openAiParts = parts.filter((part) => !part.functionCall && !part.functionResponse);
    const content = toOpenAiContent(openAiParts);
    const hasContent = typeof content === 'string' ? content.length > 0 : content.length > 0;
    if (!hasContent && toolCalls.length <= 0) continue;

    const message: Record<string, unknown> = {
      role,
    };
    if (hasContent) {
      message.content = content;
    }
    if (toolCalls.length > 0) {
      message.tool_calls = toolCalls;
      if (!hasContent) message.content = '';
    }
    messages.push(message);
  }

  return messages;
}

export function buildOpenAiBodyFromGeminiRequest(input: {
  body: GeminiRecord;
  modelName: string;
  stream: boolean;
}): Record<string, unknown> {
  const openAiBody: Record<string, unknown> = {
    model: input.modelName,
    stream: input.stream,
    messages: buildGeminiMessages(input.body),
  };

  const generationConfig = isRecord(input.body.generationConfig) ? input.body.generationConfig : null;
  const maxTokens = Number(
    generationConfig?.maxOutputTokens
    ?? input.body.max_output_tokens
    ?? input.body.max_completion_tokens
    ?? input.body.max_tokens
    ?? 0,
  );
  if (Number.isFinite(maxTokens) && maxTokens > 0) {
    openAiBody.max_tokens = Math.trunc(maxTokens);
  }
  const temperature = Number(generationConfig?.temperature);
  if (Number.isFinite(temperature)) openAiBody.temperature = temperature;
  const topP = Number(generationConfig?.topP);
  if (Number.isFinite(topP)) openAiBody.top_p = topP;
  if (Array.isArray(generationConfig?.stopSequences) && generationConfig!.stopSequences.length > 0) {
    openAiBody.stop = generationConfig!.stopSequences;
  }

  const tools = extractToolDeclarations(input.body.tools);
  if (tools) {
    openAiBody.tools = tools;
  }
  const toolChoice = extractToolChoice(input.body.toolConfig);
  if (toolChoice) {
    openAiBody.tool_choice = toolChoice;
  }

  const reasoning = extractReasoningMetadataFromGeminiRequest(input.body);
  if (reasoning) {
    openAiBody.reasoning = {
      effort: reasoning.reasoningEffort,
      budget_tokens: reasoning.reasoningBudget,
    };
    openAiBody.reasoning_effort = reasoning.reasoningEffort;
  }

  return openAiBody;
}

function mapFinishReason(finishReason: string): string {
  const normalized = finishReason.trim().toLowerCase();
  if (!normalized) return 'STOP';
  if (normalized === 'stop' || normalized === 'completed' || normalized === 'tool_calls') return 'STOP';
  if (normalized === 'length' || normalized === 'max_tokens' || normalized === 'max_output_tokens') return 'MAX_TOKENS';
  if (normalized === 'content_filter' || normalized === 'safety') return 'SAFETY';
  return normalized.toUpperCase().replace(/[^A-Z0-9_]+/g, '_');
}

function buildUsageMetadata(usage?: {
  promptTokens?: number | null;
  completionTokens?: number | null;
  totalTokens?: number | null;
}): Record<string, number> | undefined {
  if (!usage) return undefined;
  const metadata: Record<string, number> = {};
  if (typeof usage.promptTokens === 'number' && Number.isFinite(usage.promptTokens)) {
    metadata.promptTokenCount = usage.promptTokens;
  }
  if (typeof usage.completionTokens === 'number' && Number.isFinite(usage.completionTokens)) {
    metadata.candidatesTokenCount = usage.completionTokens;
  }
  if (typeof usage.totalTokens === 'number' && Number.isFinite(usage.totalTokens)) {
    metadata.totalTokenCount = usage.totalTokens;
  }
  return Object.keys(metadata).length > 0 ? metadata : undefined;
}

export function serializeNormalizedFinalToGemini(input: {
  normalized: NormalizedFinalResponse;
  usage?: {
    promptTokens?: number | null;
    completionTokens?: number | null;
    totalTokens?: number | null;
  };
}): Record<string, unknown> {
  const parts: Array<Record<string, unknown>> = [];

  if (input.normalized.reasoningContent) {
    parts.push({
      text: input.normalized.reasoningContent,
      thought: true,
    });
  }
  if (input.normalized.content) {
    parts.push({
      text: input.normalized.content,
    });
  }
  for (const toolCall of input.normalized.toolCalls) {
    parts.push({
      functionCall: {
        ...(toolCall.id ? { id: toolCall.id } : {}),
        name: toolCall.name,
        args: parseJsonIfPossible(toolCall.arguments),
      },
    });
  }

  const response: Record<string, unknown> = {
    responseId: input.normalized.id || '',
    modelVersion: input.normalized.model || '',
    candidates: [
      {
        index: 0,
        content: {
          role: 'model',
          parts,
        },
        finishReason: mapFinishReason(input.normalized.finishReason),
      },
    ],
  };

  const usageMetadata = buildUsageMetadata(input.usage);
  if (usageMetadata) {
    response.usageMetadata = usageMetadata;
  }

  return response;
}
