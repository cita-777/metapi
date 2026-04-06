import { createHash, randomUUID } from 'node:crypto';
import { Response } from 'undici';
import { geminiGenerateContentTransformer } from '../../transformers/gemini/generate-content/index.js';
import type { RuntimeDispatchInput, RuntimeExecutor, RuntimeResponse } from './types.js';
import {
  asTrimmedString,
  materializeErrorResponse,
  performFetch,
  readRuntimeResponseText,
  withRequestBody,
} from './types.js';

const ANTIGRAVITY_RUNTIME_BASE_URLS = [
  'https://daily-cloudcode-pa.googleapis.com',
  'https://daily-cloudcode-pa.sandbox.googleapis.com',
] as const;

function antigravityRequestType(modelName: string): 'image_gen' | 'agent' {
  return modelName.includes('image') ? 'image_gen' : 'agent';
}

function generateAntigravityProjectId(): string {
  const adjectives = ['useful', 'bright', 'swift', 'calm', 'bold'];
  const nouns = ['signal', 'river', 'rocket', 'forest', 'bridge'];
  const adjective = adjectives[Math.floor(Math.random() * adjectives.length)] || 'useful';
  const noun = nouns[Math.floor(Math.random() * nouns.length)] || 'signal';
  const suffix = Math.floor(100000 + Math.random() * 900000);
  return `${adjective}-${noun}-${suffix}`;
}

function extractFirstUserText(value: unknown): string {
  if (!Array.isArray(value)) return '';
  for (const content of value) {
    if (!content || typeof content !== 'object' || Array.isArray(content)) continue;
    const record = content as Record<string, unknown>;
    if (asTrimmedString(record.role) !== 'user') continue;
    const parts = Array.isArray(record.parts) ? record.parts : [];
    for (const part of parts) {
      if (!part || typeof part !== 'object' || Array.isArray(part)) continue;
      const text = asTrimmedString((part as Record<string, unknown>).text);
      if (text) return text;
    }
  }
  return '';
}

function generateStableAntigravitySessionId(payload: Record<string, unknown>): string {
  const firstUserText = extractFirstUserText(
    payload.request && typeof payload.request === 'object' && !Array.isArray(payload.request)
      ? (payload.request as Record<string, unknown>).contents
      : undefined,
  );
  if (!firstUserText) {
    return `-${BigInt(`0x${randomUUID().replace(/-/g, '').slice(0, 16)}`).toString()}`;
  }
  const digest = createHash('sha256').update(firstUserText).digest('hex').slice(0, 16);
  const bigint = BigInt(`0x${digest}`) & BigInt('0x7fffffffffffffff');
  return `-${bigint.toString()}`;
}

function renameParametersJsonSchema(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => renameParametersJsonSchema(item));
  }
  if (!value || typeof value !== 'object') return value;

  const input = value as Record<string, unknown>;
  const output: Record<string, unknown> = {};
  for (const [key, entry] of Object.entries(input)) {
    const nextKey = key === 'parametersJsonSchema' ? 'parameters' : key;
    output[nextKey] = renameParametersJsonSchema(entry);
  }
  return output;
}

function deleteNestedMaxOutputTokens(payload: Record<string, unknown>): void {
  const request = payload.request;
  if (!request || typeof request !== 'object' || Array.isArray(request)) return;
  const generationConfig = (request as Record<string, unknown>).generationConfig;
  if (!generationConfig || typeof generationConfig !== 'object' || Array.isArray(generationConfig)) return;
  delete (generationConfig as Record<string, unknown>).maxOutputTokens;
}

function buildAntigravityRuntimeBody(
  originalBody: Record<string, unknown>,
  modelName: string,
  action?: NonNullable<RuntimeDispatchInput['request']['runtime']>['action'],
): Record<string, unknown> {
  const payload = renameParametersJsonSchema(structuredClone(originalBody)) as Record<string, unknown>;
  if (action === 'countTokens') {
    return payload;
  }
  const requestType = antigravityRequestType(modelName);
  const projectId = asTrimmedString(payload.project) || generateAntigravityProjectId();

  payload.model = modelName;
  payload.project = projectId;
  payload.userAgent = 'antigravity';
  payload.requestType = requestType;
  payload.requestId = requestType === 'image_gen'
    ? `image_gen/${Date.now()}/${randomUUID()}/12`
    : `agent-${randomUUID()}`;

  const request = payload.request;
  if (request && typeof request === 'object' && !Array.isArray(request)) {
    delete (request as Record<string, unknown>).safetySettings;
    if (requestType !== 'image_gen') {
      (request as Record<string, unknown>).sessionId = generateStableAntigravitySessionId(payload);
    }
    if (modelName.includes('claude')) {
      const toolConfig = (
        (request as Record<string, unknown>).toolConfig
        && typeof (request as Record<string, unknown>).toolConfig === 'object'
        && !Array.isArray((request as Record<string, unknown>).toolConfig)
      )
        ? (request as Record<string, unknown>).toolConfig as Record<string, unknown>
        : (((request as Record<string, unknown>).toolConfig = {}) as Record<string, unknown>);
      toolConfig.functionCallingConfig = { mode: 'VALIDATED' };
    } else {
      deleteNestedMaxOutputTokens(payload);
    }
  }

  return payload;
}

function antigravityShouldRetryNoCapacity(
  status: number,
  responseText: string,
): boolean {
  return status === 503 && responseText.toLowerCase().includes('no capacity available');
}

function antigravityNoCapacityRetryDelay(attempt: number): number {
  return Math.min((attempt + 1) * 250, 2000);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function unwrapAntigravityAggregatePayload(payload: unknown): unknown {
  if (!isRecord(payload)) return payload;
  return payload.response !== undefined ? payload.response : payload;
}

function antigravityUsesStreamEndpoint(request: RuntimeDispatchInput['request']): boolean {
  return request.runtime?.action === 'streamGenerateContent'
    || request.path.includes(':streamGenerateContent');
}

function antigravityShouldAggregateStreamResponse(request: RuntimeDispatchInput['request']): boolean {
  return antigravityUsesStreamEndpoint(request) && request.runtime?.stream !== true;
}

async function materializeAntigravitySuccessResponse(
  response: RuntimeResponse,
  aggregateStreamResponse: boolean,
): Promise<RuntimeResponse> {
  if (!aggregateStreamResponse) return response;

  const rawText = await readRuntimeResponseText(response);
  const contentType = response.headers.get('content-type');
  const parsed = geminiGenerateContentTransformer.stream.parseGeminiStreamPayload(rawText, contentType);
  const aggregateState = geminiGenerateContentTransformer.stream.createAggregateState();

  for (const event of parsed.events) {
    geminiGenerateContentTransformer.stream.applyAggregate(
      aggregateState,
      unwrapAntigravityAggregatePayload(event),
    );
  }
  if (parsed.rest.trim()) {
    const trailingPayload = geminiGenerateContentTransformer.stream.parseGeminiStreamPayload(
      `${parsed.rest}\n\n`,
      'text/event-stream',
    );
    for (const event of trailingPayload.events) {
      geminiGenerateContentTransformer.stream.applyAggregate(
        aggregateState,
        unwrapAntigravityAggregatePayload(event),
      );
    }
  }

  const headers = new Headers(response.headers);
  headers.set('content-type', 'application/json; charset=utf-8');
  headers.delete('content-encoding');
  headers.delete('content-length');

  return new Response(
    JSON.stringify(geminiGenerateContentTransformer.stream.serializeAggregateJsonPayload(aggregateState)),
    {
      status: response.status,
      headers,
    },
  );
}

async function waitMs(ms: number): Promise<void> {
  if (ms <= 0) return;
  await new Promise((resolve) => setTimeout(resolve, ms));
}

export const antigravityExecutor: RuntimeExecutor = {
  async dispatch(input: RuntimeDispatchInput) {
    const modelName = asTrimmedString(input.request.runtime?.modelName) || asTrimmedString(input.request.body.model);
    const runtimeBody = buildAntigravityRuntimeBody(
      input.request.body,
      modelName,
      input.request.runtime?.action,
    );
    const baseAttempts = 3;
    const useStreamEndpoint = antigravityUsesStreamEndpoint(input.request);
    const aggregateStreamResponse = antigravityShouldAggregateStreamResponse(input.request);
    let lastResponse: RuntimeResponse | null = null;

    attemptLoop:
    for (let attempt = 0; attempt < baseAttempts; attempt += 1) {
      for (const baseUrl of ANTIGRAVITY_RUNTIME_BASE_URLS) {
        const requestUrl = `${baseUrl}${input.request.path}`;
        const minimalHeaders: Record<string, string> = {
          Authorization: input.request.headers.Authorization || input.request.headers.authorization || '',
          'Content-Type': 'application/json',
          Accept: useStreamEndpoint ? 'text/event-stream' : 'application/json',
          'User-Agent': 'antigravity/1.19.6 darwin/arm64',
        };
        let response: RuntimeResponse;
        try {
          response = await performFetch(
            input,
            withRequestBody(input.request, runtimeBody, minimalHeaders),
            requestUrl,
          );
        } catch (error) {
          if (baseUrl !== ANTIGRAVITY_RUNTIME_BASE_URLS[ANTIGRAVITY_RUNTIME_BASE_URLS.length - 1]) {
            continue;
          }
          if (attempt + 1 < baseAttempts) {
            continue attemptLoop;
          }
          throw error;
        }
        if (response.ok) {
          return materializeAntigravitySuccessResponse(response, aggregateStreamResponse);
        }

        const errorResponse = await materializeErrorResponse(response);
        const errorText = await errorResponse.text().catch(() => '');
        lastResponse = new Response(errorText, {
          status: errorResponse.status,
          headers: errorResponse.headers,
        });

        if (errorResponse.status === 429) {
          continue;
        }

        if (antigravityShouldRetryNoCapacity(errorResponse.status, errorText)) {
          if (baseUrl !== ANTIGRAVITY_RUNTIME_BASE_URLS[ANTIGRAVITY_RUNTIME_BASE_URLS.length - 1]) {
            continue;
          }
          if (attempt + 1 < baseAttempts) {
            await waitMs(antigravityNoCapacityRetryDelay(attempt));
            continue attemptLoop;
          }
        }

        return lastResponse;
      }
    }

    if (lastResponse) return lastResponse;

    const fallbackResponse = await performFetch(input, withRequestBody(input.request, runtimeBody, {
      Authorization: input.request.headers.Authorization || input.request.headers.authorization || '',
      'Content-Type': 'application/json',
      Accept: useStreamEndpoint ? 'text/event-stream' : 'application/json',
      'User-Agent': 'antigravity/1.19.6 darwin/arm64',
    }));
    if (fallbackResponse.ok) {
      return materializeAntigravitySuccessResponse(fallbackResponse, aggregateStreamResponse);
    }
    return fallbackResponse;
  },
};
