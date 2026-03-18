import { canonicalRequestFromOpenAiBody } from '../../canonical/request.js';
import type { CanonicalContentPart, CanonicalRequestEnvelope } from '../../canonical/types.js';
import type { ProtocolBuildContext, ProtocolParseContext } from '../../contracts.js';
function normalizeBaseUrl(baseUrl: string): string {
  return (baseUrl || '').replace(/\/+$/, '');
}

function baseIncludesVersion(baseUrl: string): boolean {
  return /\/v\d+(?:beta)?(?:\/|$)/i.test(baseUrl);
}

function asTrimmedString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

export function resolveGeminiNativeBaseUrl(baseUrl: string, apiVersion: string): string {
  const normalized = normalizeBaseUrl(baseUrl);
  if (baseIncludesVersion(normalized)) return normalized;
  return `${normalized}/${apiVersion}`;
}

export function resolveGeminiModelsUrl(
  baseUrl: string,
  apiVersion: string,
  apiKey: string,
): string {
  const base = resolveGeminiNativeBaseUrl(baseUrl, apiVersion);
  const separator = base.includes('?') ? '&' : '?';
  return `${base}/models${separator}key=${encodeURIComponent(apiKey)}`;
}

export function resolveGeminiGenerateContentUrl(
  baseUrl: string,
  apiVersion: string,
  modelActionPath: string,
  apiKey: string,
  search: string,
): string {
  const base = resolveGeminiNativeBaseUrl(baseUrl, apiVersion);
  const normalizedAction = modelActionPath.replace(/^\/+/, '');
  const params = new URLSearchParams(search.startsWith('?') ? search.slice(1) : search);
  params.set('key', apiKey);
  const query = params.toString();
  return `${base}/${normalizedAction}${query ? `?${query}` : ''}`;
}

export function resolveGeminiProxyApiVersion(params: { geminiApiVersion?: unknown } | null | undefined): string {
  return asTrimmedString(params?.geminiApiVersion) || 'v1beta';
}

export function parseGeminiProxyRequestPath(input: {
  rawUrl?: string | null;
  params?: { geminiApiVersion?: unknown } | null;
}): {
  apiVersion: string;
  modelActionPath: string;
  requestedModel: string;
  isStreamAction: boolean;
} {
  const apiVersion = resolveGeminiProxyApiVersion(input.params);
  const rawUrl = asTrimmedString(input.rawUrl);
  const withoutQuery = rawUrl.split('?')[0] || rawUrl;
  const normalizedVersion = apiVersion.replace(/^\/+/, '');
  const geminiPrefix = `/gemini/${normalizedVersion}/`;
  const aliasPrefix = `/${normalizedVersion}/`;

  let modelActionPath = withoutQuery.replace(/^\/+/, '');
  if (withoutQuery.startsWith(geminiPrefix)) {
    modelActionPath = withoutQuery.slice(geminiPrefix.length);
  } else if (withoutQuery.startsWith(aliasPrefix)) {
    modelActionPath = withoutQuery.slice(aliasPrefix.length);
  }

  const requestedModel = modelActionPath.replace(/^models\//, '').split(':')[0].trim();
  return {
    apiVersion,
    modelActionPath,
    requestedModel,
    isStreamAction: modelActionPath.endsWith(':streamGenerateContent'),
  };
}

import { geminiGenerateContentInbound } from './inbound.js';
import { geminiGenerateContentOutbound } from './outbound.js';
import { geminiGenerateContentStream } from './stream.js';
import { createGeminiGenerateContentAggregateState, applyGeminiGenerateContentAggregate } from './aggregator.js';
import { geminiGenerateContentUsage } from './usage.js';
import { reasoningEffortToGeminiThinkingConfig, geminiThinkingConfigToReasoning } from './convert.js';
import { buildOpenAiBodyFromGeminiRequest, serializeNormalizedFinalToGemini } from './compatibility.js';

function parseJsonString(raw: string): unknown {
  const trimmed = raw.trim();
  if (!trimmed) return {};
  try {
    return JSON.parse(trimmed);
  } catch {
    return { raw };
  }
}

function parseDataUrl(value: string): { mimeType: string; data: string } | null {
  const match = /^data:([^;,]+);base64,(.+)$/i.exec(value.trim());
  if (!match) return null;
  return {
    mimeType: match[1],
    data: match[2],
  };
}

function canonicalPartToGeminiPart(part: CanonicalContentPart): Record<string, unknown> | null {
  if (part.type === 'text') {
    return {
      text: part.text,
      ...(part.thought === true ? { thought: true } : {}),
    };
  }

  if (part.type === 'image') {
    const source = typeof part.dataUrl === 'string' && part.dataUrl.trim()
      ? part.dataUrl
      : (typeof part.url === 'string' ? part.url : '');
    if (!source) return null;

    const dataUrl = parseDataUrl(source);
    if (dataUrl) {
      return {
        inlineData: {
          mimeType: dataUrl.mimeType,
          data: dataUrl.data,
        },
      };
    }

    return {
      fileData: {
        fileUri: source,
        ...(part.mimeType ? { mimeType: part.mimeType } : {}),
      },
    };
  }

  if (part.type === 'file') {
    if (part.fileData) {
      return {
        inlineData: {
          mimeType: part.mimeType || 'application/octet-stream',
          data: part.fileData,
        },
      };
    }

    const fileUri = part.fileUrl || part.fileId;
    if (!fileUri) return null;
    return {
      fileData: {
        fileUri,
        ...(part.mimeType ? { mimeType: part.mimeType } : {}),
      },
    };
  }

  if (part.type === 'tool_call') {
    return {
      functionCall: {
        id: part.id,
        name: part.name,
        args: parseJsonString(part.argumentsJson),
      },
    };
  }

  if (part.type === 'tool_result') {
    return {
      functionResponse: {
        name: part.toolCallId,
        response: part.resultJson ?? parseJsonString(part.resultText ?? ''),
      },
    };
  }

  return null;
}

function buildGeminiRequestFromCanonical(request: CanonicalRequestEnvelope): Record<string, unknown> {
  const contents: Array<Record<string, unknown>> = [];
  const systemParts: Array<Record<string, unknown>> = [];

  for (const message of request.messages) {
    if (message.role === 'system' || message.role === 'developer') {
      systemParts.push(
        ...message.parts
          .map((part) => canonicalPartToGeminiPart(part))
          .filter((part): part is Record<string, unknown> => !!part),
      );
      continue;
    }

    const parts = message.parts
      .map((part) => canonicalPartToGeminiPart(part))
      .filter((part): part is Record<string, unknown> => !!part);

    if (parts.length <= 0) continue;

    if (message.role === 'tool') {
      contents.push({
        role: 'user',
        parts,
      });
      continue;
    }

    contents.push({
      role: message.role === 'assistant' ? 'model' : 'user',
      parts,
    });
  }

  const payload: Record<string, unknown> = {
    contents,
  };

  if (systemParts.length > 0) {
    payload.systemInstruction = {
      role: 'user',
      parts: systemParts,
    };
  }

  const generationConfig: Record<string, unknown> = {};
  if (request.reasoning?.budgetTokens !== undefined) {
    generationConfig.thinkingConfig = {
      thinkingBudget: request.reasoning.budgetTokens,
    };
  } else if (request.reasoning?.effort) {
    generationConfig.thinkingConfig = reasoningEffortToGeminiThinkingConfig(
      request.requestedModel,
      request.reasoning.effort,
    );
  }
  if (Object.keys(generationConfig).length > 0) {
    payload.generationConfig = generationConfig;
  }

  if (Array.isArray(request.tools) && request.tools.length > 0) {
    payload.tools = [{
      functionDeclarations: request.tools.map((tool) => ({
        name: tool.name,
        ...(tool.description ? { description: tool.description } : {}),
        ...(tool.inputSchema ? { parameters: tool.inputSchema } : {}),
      })),
    }];
  }

  if (request.toolChoice) {
    if (request.toolChoice === 'none') {
      payload.toolConfig = { functionCallingConfig: { mode: 'NONE' } };
    } else if (request.toolChoice === 'auto') {
      payload.toolConfig = { functionCallingConfig: { mode: 'AUTO' } };
    } else if (request.toolChoice === 'required') {
      payload.toolConfig = { functionCallingConfig: { mode: 'ANY' } };
    } else {
      payload.toolConfig = {
        functionCallingConfig: {
          mode: 'ANY',
          allowedFunctionNames: [request.toolChoice.name],
        },
      };
    }
  }

  return payload;
}

export const geminiGenerateContentTransformer = {
  protocol: 'gemini/generate-content' as const,
  inbound: geminiGenerateContentInbound,
  outbound: geminiGenerateContentOutbound,
  stream: geminiGenerateContentStream,
  aggregator: {
    createState: createGeminiGenerateContentAggregateState,
    apply: applyGeminiGenerateContentAggregate,
  },
  usage: geminiGenerateContentUsage,
  convert: {
    reasoningEffortToGeminiThinkingConfig,
    geminiThinkingConfigToReasoning,
  },
  compatibility: {
    buildOpenAiBodyFromGeminiRequest,
    serializeNormalizedFinalToGemini,
  },
  parseProxyRequestPath: parseGeminiProxyRequestPath,
  resolveProxyApiVersion: resolveGeminiProxyApiVersion,
  resolveBaseUrl: resolveGeminiNativeBaseUrl,
  resolveModelsUrl: resolveGeminiModelsUrl,
  resolveActionUrl: resolveGeminiGenerateContentUrl,
  parseRequest(
    body: unknown,
    ctx?: ProtocolParseContext,
  ): { value?: CanonicalRequestEnvelope; error?: { statusCode: number; payload: unknown } } {
    const rawBody = isRecord(body) ? body : {};
    const requestedModel = asTrimmedString(rawBody.model ?? ctx?.metadata?.requestedModel);
    if (!requestedModel) {
      return {
        error: {
          statusCode: 400,
          payload: {
            error: {
              message: 'model is required',
              type: 'invalid_request_error',
            },
          },
        },
      };
    }

    const stream = rawBody.stream === true || ctx?.metadata?.stream === true;
    const normalizedBody = geminiGenerateContentInbound.normalizeRequest(rawBody, requestedModel);
    const openAiBody = buildOpenAiBodyFromGeminiRequest({
      body: normalizedBody,
      modelName: requestedModel,
      stream,
    });

    return {
      value: canonicalRequestFromOpenAiBody({
        body: openAiBody,
        surface: 'gemini-generate-content',
        cliProfile: ctx?.cliProfile,
        operation: ctx?.operation,
        metadata: ctx?.metadata,
        passthrough: ctx?.passthrough,
        continuation: ctx?.continuation,
      }),
    };
  },
  buildProtocolRequest(
    request: CanonicalRequestEnvelope,
    _ctx?: ProtocolBuildContext,
  ): Record<string, unknown> {
    return buildGeminiRequestFromCanonical(request);
  },
};

export {
  geminiGenerateContentInbound,
  geminiGenerateContentOutbound,
  geminiGenerateContentStream,
  createGeminiGenerateContentAggregateState,
  applyGeminiGenerateContentAggregate,
  geminiGenerateContentUsage,
  reasoningEffortToGeminiThinkingConfig,
  geminiThinkingConfigToReasoning,
  buildOpenAiBodyFromGeminiRequest,
  serializeNormalizedFinalToGemini,
};
