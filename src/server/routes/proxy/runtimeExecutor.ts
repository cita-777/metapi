import { createHash, randomUUID } from 'node:crypto';
import { fetch, type RequestInit as UndiciRequestInit } from 'undici';
import type { BuiltEndpointRequest } from './endpointFlow.js';
import { buildUpstreamUrl } from './upstreamUrl.js';

const ANTIGRAVITY_RUNTIME_BASE_URLS = [
  'https://daily-cloudcode-pa.googleapis.com',
  'https://daily-cloudcode-pa.sandbox.googleapis.com',
] as const;

type RuntimeDispatchInput = {
  siteUrl: string;
  request: BuiltEndpointRequest;
  targetUrl?: string;
  buildInit: (requestUrl: string, request: BuiltEndpointRequest) => Promise<UndiciRequestInit> | UndiciRequestInit;
};

function asTrimmedString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function withRequestBody(
  request: BuiltEndpointRequest,
  body: Record<string, unknown>,
  headers?: Record<string, string>,
): BuiltEndpointRequest {
  return {
    ...request,
    headers: headers ? { ...headers } : { ...request.headers },
    body,
  };
}

async function performFetch(
  input: RuntimeDispatchInput,
  request: BuiltEndpointRequest,
  requestUrl = input.targetUrl || buildUpstreamUrl(input.siteUrl, request.path),
): Promise<Awaited<ReturnType<typeof fetch>>> {
  const init = await input.buildInit(requestUrl, request);
  return fetch(requestUrl, init);
}

async function materializeErrorResponse(
  response: Awaited<ReturnType<typeof fetch>>,
): Promise<Awaited<ReturnType<typeof fetch>>> {
  if (response.ok) return response;
  const text = await response.text().catch(() => '');
  return new Response(text, {
    status: response.status,
    headers: response.headers,
  }) as unknown as Awaited<ReturnType<typeof fetch>>;
}

function parseGeminiCliPreviewFallbackOrder(modelName: string): string[] {
  switch (modelName.trim()) {
    case 'gemini-2.5-pro':
      return [];
    case 'gemini-2.5-flash':
      return [];
    case 'gemini-2.5-flash-lite':
      return [];
    default:
      return [];
  }
}

function replaceGeminiCliModelInUserAgent(userAgent: string | undefined, modelName: string): string | undefined {
  const raw = asTrimmedString(userAgent);
  if (!raw) return undefined;
  return raw.replace(/^GeminiCLI\/([^/]+)\/[^ ]+ /i, `GeminiCLI/$1/${modelName} `);
}

function buildGeminiCliAttemptRequest(request: BuiltEndpointRequest, modelName: string): BuiltEndpointRequest {
  const body = structuredClone(request.body);
  const action = request.runtime?.action;
  if (action === 'countTokens') {
    delete body.model;
    delete body.project;
  } else {
    body.model = modelName;
  }
  const headers = { ...request.headers };
  const nextUserAgent = replaceGeminiCliModelInUserAgent(
    headers['User-Agent'] || headers['user-agent'],
    modelName,
  );
  if (nextUserAgent) {
    headers['User-Agent'] = nextUserAgent;
    delete headers['user-agent'];
  }
  return withRequestBody(request, body, headers);
}

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
  action?: NonNullable<BuiltEndpointRequest['runtime']>['action'],
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
  if (status !== 503) return false;
  return responseText.toLowerCase().includes('no capacity available');
}

function antigravityNoCapacityRetryDelay(attempt: number): number {
  const delay = Math.min((attempt + 1) * 250, 2000);
  return delay;
}

async function waitMs(ms: number): Promise<void> {
  if (ms <= 0) return;
  await new Promise((resolve) => setTimeout(resolve, ms));
}

async function dispatchGeminiCliRuntimeRequest(
  input: RuntimeDispatchInput,
): Promise<Awaited<ReturnType<typeof fetch>>> {
  const baseModel = asTrimmedString(input.request.runtime?.modelName) || asTrimmedString(input.request.body.model);
  const models = [baseModel, ...parseGeminiCliPreviewFallbackOrder(baseModel)].filter(Boolean);
  let lastResponse: Awaited<ReturnType<typeof fetch>> | null = null;

  for (const modelName of models.length > 0 ? models : [baseModel || 'unknown']) {
    const attemptRequest = buildGeminiCliAttemptRequest(input.request, modelName);
    const response = await performFetch(input, attemptRequest);
    if (response.ok) return response;

    if (response.status === 429) {
      lastResponse = await materializeErrorResponse(response);
      continue;
    }

    return materializeErrorResponse(response);
  }

  return lastResponse || performFetch(input, input.request);
}

async function dispatchCodexRuntimeRequest(
  input: RuntimeDispatchInput,
): Promise<Awaited<ReturnType<typeof fetch>>> {
  return performFetch(input, input.request);
}

async function dispatchClaudeRuntimeRequest(
  input: RuntimeDispatchInput,
): Promise<Awaited<ReturnType<typeof fetch>>> {
  return performFetch(input, input.request);
}

async function dispatchAntigravityRuntimeRequest(
  input: RuntimeDispatchInput,
): Promise<Awaited<ReturnType<typeof fetch>>> {
  const modelName = asTrimmedString(input.request.runtime?.modelName) || asTrimmedString(input.request.body.model);
  const runtimeBody = buildAntigravityRuntimeBody(
    input.request.body,
    modelName,
    input.request.runtime?.action,
  );
  const baseAttempts = 3;
  let lastResponse: Awaited<ReturnType<typeof fetch>> | null = null;

  attemptLoop:
  for (let attempt = 0; attempt < baseAttempts; attempt += 1) {
    for (const baseUrl of ANTIGRAVITY_RUNTIME_BASE_URLS) {
      const requestUrl = `${baseUrl}${input.request.path}`;
      const minimalHeaders: Record<string, string> = {
        Authorization: input.request.headers.Authorization || input.request.headers.authorization || '',
        'Content-Type': 'application/json',
        Accept: input.request.runtime?.stream ? 'text/event-stream' : 'application/json',
        'User-Agent': 'antigravity/1.19.6 darwin/arm64',
      };
      let response: Awaited<ReturnType<typeof fetch>>;
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
      if (response.ok) return response;

      const errorResponse = await materializeErrorResponse(response);
      const errorText = await errorResponse.text().catch(() => '');
      lastResponse = new Response(errorText, {
        status: errorResponse.status,
        headers: errorResponse.headers,
      }) as unknown as Awaited<ReturnType<typeof fetch>>;

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

  return lastResponse || performFetch(input, withRequestBody(input.request, runtimeBody, {
    Authorization: input.request.headers.Authorization || input.request.headers.authorization || '',
    'Content-Type': 'application/json',
    Accept: input.request.runtime?.stream ? 'text/event-stream' : 'application/json',
    'User-Agent': 'antigravity/1.19.6 darwin/arm64',
  }));
}

export async function dispatchRuntimeRequest(
  input: RuntimeDispatchInput,
): Promise<Awaited<ReturnType<typeof fetch>>> {
  const executor = input.request.runtime?.executor || 'default';
  if (executor === 'codex') {
    return dispatchCodexRuntimeRequest(input);
  }
  if (executor === 'claude') {
    return dispatchClaudeRuntimeRequest(input);
  }
  if (executor === 'gemini-cli') {
    return dispatchGeminiCliRuntimeRequest(input);
  }
  if (executor === 'antigravity') {
    return dispatchAntigravityRuntimeRequest(input);
  }
  return performFetch(input, input.request);
}
