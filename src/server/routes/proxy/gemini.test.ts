import Fastify, { type FastifyInstance } from 'fastify';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

const fetchMock = vi.fn();
const selectChannelMock = vi.fn();
const selectNextChannelMock = vi.fn();
const recordSuccessMock = vi.fn();
const recordFailureMock = vi.fn();
const explainSelectionMock = vi.fn();
const invalidateTokenRouterCacheMock = vi.fn();
const authorizeDownstreamTokenMock = vi.fn();
const consumeManagedKeyRequestMock = vi.fn();
const isModelAllowedByPolicyOrAllowedRoutesMock = vi.fn();
const dbInsertValuesMock = vi.fn((_values?: unknown) => ({
  run: () => undefined,
}));
const dbInsertMock = vi.fn((_table?: unknown) => ({
  values: (values: unknown) => dbInsertValuesMock(values),
}));

vi.mock('undici', () => ({
  fetch: (...args: unknown[]) => fetchMock(...args),
}));

vi.mock('../../services/tokenRouter.js', () => ({
  tokenRouter: {
    selectChannel: (...args: unknown[]) => selectChannelMock(...args),
    selectNextChannel: (...args: unknown[]) => selectNextChannelMock(...args),
    recordSuccess: (...args: unknown[]) => recordSuccessMock(...args),
    recordFailure: (...args: unknown[]) => recordFailureMock(...args),
    explainSelection: (...args: unknown[]) => explainSelectionMock(...args),
  },
  invalidateTokenRouterCache: (...args: unknown[]) => invalidateTokenRouterCacheMock(...args),
}));

vi.mock('../../services/downstreamApiKeyService.js', () => ({
  authorizeDownstreamToken: (...args: unknown[]) => authorizeDownstreamTokenMock(...args),
  consumeManagedKeyRequest: (...args: unknown[]) => consumeManagedKeyRequestMock(...args),
  isModelAllowedByPolicyOrAllowedRoutes: (...args: unknown[]) => isModelAllowedByPolicyOrAllowedRoutesMock(...args),
}));

vi.mock('../../db/index.js', () => ({
  db: {
    insert: (arg: unknown) => dbInsertMock(arg),
  },
  schema: {
    proxyLogs: {},
  },
}));

function parseSsePayloads(body: string): Array<Record<string, unknown>> {
  return body
    .replace(/\r\n/g, '\n')
    .split('\n\n')
    .map((block) => block.trim())
    .filter(Boolean)
    .map((block) => block
      .split('\n')
      .filter((line) => line.startsWith('data:'))
      .map((line) => line.slice(5).trimStart())
      .join('\n'),
    )
    .filter((data) => data && data !== '[DONE]')
    .map((data) => JSON.parse(data) as Record<string, unknown>);
}

function readWorkspaceFile(relativePath: string): string {
  return readFileSync(path.resolve(process.cwd(), relativePath), 'utf8');
}

describe('gemini transformer-owned path parsing', () => {
  it('keeps apiVersion and modelActionPath parsing in transformer helpers', async () => {
    const geminiRoute = readWorkspaceFile('src/server/routes/proxy/gemini.ts');

    expect(geminiRoute).not.toContain('function resolveGeminiApiVersion(');
    expect(geminiRoute).not.toContain('function extractGeminiModelActionPath(');

    const { geminiGenerateContentTransformer } = await import('../../transformers/gemini/generate-content/index.js');
    expect(geminiGenerateContentTransformer.parseProxyRequestPath({
      rawUrl: '/gemini/v1/models/gemini-2.5-flash:streamGenerateContent?alt=sse',
      params: { geminiApiVersion: 'v1' },
    })).toEqual({
      apiVersion: 'v1',
      modelActionPath: 'models/gemini-2.5-flash:streamGenerateContent',
      requestedModel: 'gemini-2.5-flash',
      isStreamAction: true,
    });
  });
});

describe('gemini native proxy routes', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    const { proxyRoutes } = await import('./router.js');
    app = Fastify();
    await app.register(proxyRoutes);
  });

  beforeEach(() => {
    fetchMock.mockReset();
    selectChannelMock.mockReset();
    selectNextChannelMock.mockReset();
    recordSuccessMock.mockReset();
    recordFailureMock.mockReset();
    explainSelectionMock.mockReset();
    authorizeDownstreamTokenMock.mockReset();
    consumeManagedKeyRequestMock.mockReset();
    isModelAllowedByPolicyOrAllowedRoutesMock.mockReset();
    dbInsertMock.mockClear();
    dbInsertValuesMock.mockClear();

    authorizeDownstreamTokenMock.mockResolvedValue({
      ok: true,
      source: 'global',
      token: 'sk-managed-gemini',
      policy: {},
    });

    selectChannelMock.mockReturnValue({
      channel: { id: 11, routeId: 22 },
      site: { id: 44, name: 'gemini-site', url: 'https://generativelanguage.googleapis.com', platform: 'gemini' },
      account: { id: 33, username: 'demo-user' },
      tokenName: 'default',
      tokenValue: 'gemini-key',
      actualModel: 'gemini-2.5-flash',
    });
    selectNextChannelMock.mockReturnValue(null);
    recordSuccessMock.mockResolvedValue(undefined);
    recordFailureMock.mockResolvedValue(undefined);
    explainSelectionMock.mockResolvedValue({ selectedChannelId: 11 });
    isModelAllowedByPolicyOrAllowedRoutesMock.mockResolvedValue(true);
  });

  afterAll(async () => {
    await app.close();
  });

  it('accepts x-goog-api-key on /v1beta/models and returns gemini model list shape', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      models: [
        { name: 'models/gemini-2.5-flash', displayName: 'Gemini 2.5 Flash' },
      ],
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'GET',
      url: '/v1beta/models',
      headers: {
        'x-goog-api-key': 'sk-managed-gemini',
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      models: [
        {
          name: 'models/gemini-2.5-flash',
          displayName: 'Gemini 2.5 Flash',
        },
      ],
    });
  });

  it('falls back to the next channel for listModels when first Gemini channel fails', async () => {
    selectNextChannelMock.mockReturnValue({
      channel: { id: 12, routeId: 22 },
      site: { id: 45, name: 'gemini-site-2', url: 'https://generativelanguage.googleapis.com', platform: 'gemini' },
      account: { id: 34, username: 'demo-user-2' },
      tokenName: 'fallback',
      tokenValue: 'gemini-key-2',
      actualModel: 'gemini-2.5-flash',
    });

    fetchMock
      .mockResolvedValueOnce(new Response(JSON.stringify({
        error: { message: 'first channel failed' },
      }), {
        status: 500,
        headers: { 'content-type': 'application/json' },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        models: [
          { name: 'models/gemini-2.5-flash', displayName: 'Gemini 2.5 Flash' },
        ],
      }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }));

    const response = await app.inject({
      method: 'GET',
      url: '/v1beta/models',
      headers: {
        'x-goog-api-key': 'sk-managed-gemini',
      },
    });

    expect(response.statusCode).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(recordFailureMock).toHaveBeenCalledWith(11);
    const [firstUrl] = fetchMock.mock.calls[0] as [string, RequestInit];
    const [secondUrl] = fetchMock.mock.calls[1] as [string, RequestInit];
    expect(firstUrl).toContain('key=gemini-key');
    expect(secondUrl).toContain('key=gemini-key-2');
  });

  it('forwards native generateContent requests through the gemini route group', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      candidates: [
        {
          content: {
            parts: [{ text: 'hello from gemini' }],
            role: 'model',
          },
          finishReason: 'STOP',
        },
      ],
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1beta/models/gemini-2.5-flash:generateContent',
      headers: {
        'x-goog-api-key': 'sk-managed-gemini',
      },
      payload: {
        contents: [
          {
            role: 'user',
            parts: [{ text: 'hello' }],
          },
        ],
      },
    });

    expect(response.statusCode).toBe(200);
    const [targetUrl, requestInit] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(targetUrl).toContain('/v1beta/models/gemini-2.5-flash:generateContent');
    expect(targetUrl).toContain('key=gemini-key');
    expect(JSON.parse(String(requestInit.body))).toEqual({
      contents: [
        {
          role: 'user',
          parts: [{ text: 'hello' }],
        },
      ],
    });
    expect(response.json()).toEqual({
      responseId: '',
      modelVersion: '',
      candidates: [
        {
          index: 0,
          content: {
            parts: [{ text: 'hello from gemini' }],
            role: 'model',
          },
          finishReason: 'STOP',
        },
      ],
    });
  });

  it('filters Gemini native model list by downstream managed-key policy', async () => {
    authorizeDownstreamTokenMock.mockResolvedValue({
      ok: true,
      source: 'managed',
      token: 'sk-managed-gemini',
      key: { id: 91 },
      policy: { supportedModels: ['gemini-2.5-flash'], allowedRouteIds: [], siteWeightMultipliers: {} },
    });
    isModelAllowedByPolicyOrAllowedRoutesMock.mockImplementation(async (modelName: string) => modelName === 'gemini-2.5-flash');
    explainSelectionMock.mockImplementation(async (modelName: string) => (
      modelName === 'gemini-2.5-flash'
        ? { selectedChannelId: 11 }
        : { selectedChannelId: undefined }
    ));
    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      models: [
        { name: 'models/gemini-2.5-flash', displayName: 'Gemini 2.5 Flash' },
        { name: 'models/gemini-2.0-flash', displayName: 'Gemini 2.0 Flash' },
      ],
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'GET',
      url: '/v1beta/models',
      headers: {
        authorization: 'Bearer sk-managed-gemini',
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      models: [
        {
          name: 'models/gemini-2.5-flash',
          displayName: 'Gemini 2.5 Flash',
        },
      ],
    });
    expect(isModelAllowedByPolicyOrAllowedRoutesMock).toHaveBeenCalledWith('gemini-2.5-flash', { supportedModels: ['gemini-2.5-flash'], allowedRouteIds: [], siteWeightMultipliers: {} });
    expect(isModelAllowedByPolicyOrAllowedRoutesMock).toHaveBeenCalledWith('gemini-2.0-flash', { supportedModels: ['gemini-2.5-flash'], allowedRouteIds: [], siteWeightMultipliers: {} });
  });

  it('writes a proxy log row for successful native generateContent requests', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      candidates: [
        {
          content: {
            parts: [{ text: 'hello from gemini' }],
            role: 'model',
          },
          finishReason: 'STOP',
        },
      ],
      usageMetadata: {
        promptTokenCount: 10,
        candidatesTokenCount: 5,
        totalTokenCount: 15,
      },
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1beta/models/gemini-2.5-flash:generateContent',
      headers: {
        'x-goog-api-key': 'sk-managed-gemini',
      },
      payload: {
        contents: [
          {
            role: 'user',
            parts: [{ text: 'hello' }],
          },
        ],
      },
    });

    expect(response.statusCode).toBe(200);
    expect(recordSuccessMock).toHaveBeenCalledWith(11, expect.any(Number), 0);
    expect(dbInsertMock).toHaveBeenCalledTimes(1);
    expect(dbInsertValuesMock).toHaveBeenCalledWith(expect.objectContaining({
      routeId: 22,
      channelId: 11,
      accountId: 33,
      modelRequested: 'gemini-2.5-flash',
      modelActual: 'gemini-2.5-flash',
      status: 'success',
      httpStatus: 200,
      retryCount: 0,
      promptTokens: 10,
      completionTokens: 5,
      totalTokens: 15,
      errorMessage: '[downstream:/v1beta/models/gemini-2.5-flash:generateContent] [upstream:/v1beta/models/gemini-2.5-flash:generateContent]',
      createdAt: expect.any(String),
    }));
  });

  it('forwards explicit gemini version paths through transformer-owned parsing helpers', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      candidates: [
        {
          content: {
            parts: [{ text: 'hello from v1 gemini' }],
            role: 'model',
          },
          finishReason: 'STOP',
        },
      ],
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/gemini/v1/models/gemini-2.5-flash:generateContent?alt=json',
      headers: {
        'x-goog-api-key': 'sk-managed-gemini',
      },
      payload: {
        contents: [
          {
            role: 'user',
            parts: [{ text: 'hello' }],
          },
        ],
      },
    });

    expect(response.statusCode).toBe(200);
    const [targetUrl, requestInit] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(targetUrl).toContain('/v1/models/gemini-2.5-flash:generateContent');
    expect(targetUrl).toContain('alt=json');
    expect(targetUrl).toContain('key=gemini-key');
    expect(JSON.parse(String(requestInit.body))).toEqual({
      contents: [
        {
          role: 'user',
          parts: [{ text: 'hello' }],
        },
      ],
    });
    expect(response.json().candidates?.[0]?.content?.parts?.[0]?.text).toBe('hello from v1 gemini');
  });

  it('preserves structured Gemini-native fields instead of narrowing them to a bare passthrough shell', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      candidates: [
        {
          content: {
            parts: [{ text: 'ok' }],
            role: 'model',
          },
          finishReason: 'STOP',
        },
      ],
      usageMetadata: {
        promptTokenCount: 10,
        candidatesTokenCount: 5,
        totalTokenCount: 15,
        cachedContentTokenCount: 2,
        thoughtsTokenCount: 1,
      },
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1beta/models/gemini-2.5-flash:generateContent',
      headers: {
        'x-goog-api-key': 'sk-managed-gemini',
      },
      payload: {
        systemInstruction: {
          parts: [{ text: 'be concise' }],
        },
        cachedContent: 'cached/abc123',
        safetySettings: [{ category: 'HARM_CATEGORY_HARASSMENT', threshold: 'BLOCK_NONE' }],
        generationConfig: {
          responseModalities: ['TEXT'],
          responseMimeType: 'application/json',
          temperature: 0.2,
          topP: 0.8,
          topK: 20,
          maxOutputTokens: 256,
          thinkingConfig: { thinkingBudget: 512 },
          imageConfig: { aspectRatio: '1:1' },
        },
        tools: [
          {
            functionDeclarations: [
              {
                name: 'lookup_weather',
                description: 'look up weather',
              },
            ],
          },
        ],
        contents: [
          {
            role: 'user',
            parts: [{ text: 'weather in shanghai' }],
          },
        ],
      },
    });

    expect(response.statusCode).toBe(200);
    const [, requestInit] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(JSON.parse(String(requestInit.body))).toEqual({
      systemInstruction: {
        parts: [{ text: 'be concise' }],
      },
      cachedContent: 'cached/abc123',
      safetySettings: [{ category: 'HARM_CATEGORY_HARASSMENT', threshold: 'BLOCK_NONE' }],
      generationConfig: {
        responseModalities: ['TEXT'],
        responseMimeType: 'application/json',
        temperature: 0.2,
        topP: 0.8,
        topK: 20,
        maxOutputTokens: 256,
        thinkingConfig: { thinkingBudget: 512 },
        imageConfig: { aspectRatio: '1:1' },
      },
      tools: [
        {
          functionDeclarations: [
            {
              name: 'lookup_weather',
              description: 'look up weather',
            },
          ],
        },
      ],
      contents: [
        {
          role: 'user',
          parts: [{ text: 'weather in shanghai' }],
        },
      ],
    });
  });

  it('keeps non-sse json-array streaming payloads on the wire as raw chunk responses', async () => {
    const upstreamPayload = [
      {
        promptFeedback: { blockReason: 'BLOCK_REASON_UNSPECIFIED' },
        candidates: [
          {
            content: {
              role: 'model',
              parts: [
                {
                  functionCall: { id: 'tool-1', name: 'lookup_weather', args: { city: 'Shanghai' } },
                  thoughtSignature: 'sig-tool-1',
                },
              ],
            },
            groundingMetadata: { source: 'web' },
          },
        ],
      },
      {
        serverContent: { modelTurn: { parts: [{ text: 'tool result received' }] } },
        candidates: [
          {
            content: { role: 'model', parts: [{ text: 'second', thoughtSignature: 'sig-1' }] },
            citationMetadata: { citations: [{ startIndex: 0, endIndex: 5 }] },
            finishReason: 'STOP',
          },
        ],
        usageMetadata: {
          promptTokenCount: 11,
          candidatesTokenCount: 6,
          totalTokenCount: 17,
          cachedContentTokenCount: 2,
          thoughtsTokenCount: 3,
        },
      },
    ];

    fetchMock.mockResolvedValue(new Response(JSON.stringify(upstreamPayload), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1beta/models/gemini-2.5-flash:streamGenerateContent',
      headers: {
        'x-goog-api-key': 'sk-managed-gemini',
      },
      payload: {
        contents: [
          {
            role: 'user',
            parts: [{ text: 'hello' }],
          },
        ],
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual(upstreamPayload);
  });

  it('derives gemini-3 thinkingLevel from OpenAI-style reasoning inputs in the runtime request path', async () => {
    selectChannelMock.mockReturnValue({
      channel: { id: 11, routeId: 22 },
      site: { id: 44, name: 'gemini-site', url: 'https://generativelanguage.googleapis.com', platform: 'gemini' },
      account: { id: 33, username: 'demo-user' },
      tokenName: 'default',
      tokenValue: 'gemini-key',
      actualModel: 'gemini-3-pro',
    });

    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      candidates: [
        {
          content: {
            parts: [{ text: 'ok' }],
            role: 'model',
          },
          finishReason: 'STOP',
        },
      ],
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1beta/models/gemini-3-pro:generateContent',
      headers: {
        'x-goog-api-key': 'sk-managed-gemini',
      },
      payload: {
        reasoning_effort: 'high',
        contents: [
          {
            role: 'user',
            parts: [{ text: 'hello' }],
          },
        ],
      },
    });

    expect(response.statusCode).toBe(200);
    const [, requestInit] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(JSON.parse(String(requestInit.body))).toEqual({
      contents: [
        {
          role: 'user',
          parts: [{ text: 'hello' }],
        },
      ],
      generationConfig: {
        thinkingConfig: { thinkingLevel: 'high', includeThoughts: true },
      },
    });
  });

  it('streams SSE payloads as raw upstream events without reserializing tool-calling chunks', async () => {
    const encoder = new TextEncoder();
    const upstreamBody = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode('data: {"promptFeedback":{"blockReason":"BLOCK_REASON_UNSPECIFIED"},"candidates":[{"content":{"role":"model","parts":[{"functionCall":{"id":"tool-1","name":"lookup_weather","args":{"city":"Shanghai"}},"thoughtSignature":"sig-tool-1"}]},"groundingMetadata":{"source":"web"}}]}\r\n\r\n'));
        controller.enqueue(encoder.encode('data: {"serverContent":{"modelTurn":{"parts":[{"text":"tool result received"}]}},"candidates":[{"content":{"role":"model","parts":[{"text":"second","thoughtSignature":"sig-1"}]},"citationMetadata":{"citations":[{"startIndex":0,"endIndex":5}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":11,"candidatesTokenCount":6,"totalTokenCount":17,"cachedContentTokenCount":2,"thoughtsTokenCount":3}}\r\n\r\n'));
        controller.enqueue(encoder.encode('data: [DONE]\r\n\r\n'));
        controller.close();
      },
    });

    fetchMock.mockResolvedValue(new Response(upstreamBody, {
      status: 200,
      headers: { 'content-type': 'text/event-stream; charset=utf-8' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=sse',
      headers: {
        'x-goog-api-key': 'sk-managed-gemini',
      },
      payload: {
        contents: [
          {
            role: 'user',
            parts: [{ text: 'hello' }],
          },
        ],
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.headers['content-type']).toContain('text/event-stream');
    const events = parseSsePayloads(response.body);

    expect(events).toHaveLength(2);
    expect(events[0]).toMatchObject({
      promptFeedback: { blockReason: 'BLOCK_REASON_UNSPECIFIED' },
      candidates: [
        {
          content: {
            parts: [
              {
                functionCall: { id: 'tool-1', name: 'lookup_weather', args: { city: 'Shanghai' } },
                thoughtSignature: 'sig-tool-1',
              },
            ],
          },
          groundingMetadata: { source: 'web' },
        },
      ],
    });
    expect(events[0]).not.toHaveProperty('responseId');
    expect(events[0]).not.toHaveProperty('modelVersion');
    expect(events[0].candidates?.[0]).not.toHaveProperty('finishReason');
    expect(events[1]).toMatchObject({
      serverContent: {
        modelTurn: {
          parts: [{ text: 'tool result received' }],
        },
      },
      usageMetadata: {
        promptTokenCount: 11,
        candidatesTokenCount: 6,
        totalTokenCount: 17,
        cachedContentTokenCount: 2,
        thoughtsTokenCount: 3,
      },
      candidates: [
        {
          finishReason: 'STOP',
          content: {
            parts: [{ text: 'second', thoughtSignature: 'sig-1' }],
          },
          citationMetadata: { citations: [{ startIndex: 0, endIndex: 5 }] },
        },
      ],
    });
    expect(response.body).toContain('\r\n\r\n');
    expect(response.body).toContain('data: [DONE]\r\n\r\n');
  });

  it('falls back to the next channel when first Gemini channel returns 400 before any bytes are written', async () => {
    selectNextChannelMock.mockReturnValue({
      channel: { id: 12, routeId: 22 },
      site: { id: 45, name: 'gemini-site-2', url: 'https://generativelanguage.googleapis.com', platform: 'gemini' },
      account: { id: 34, username: 'demo-user-2' },
      tokenName: 'fallback',
      tokenValue: 'gemini-key-2',
      actualModel: 'gemini-2.5-flash',
    });

    fetchMock
      .mockResolvedValueOnce(new Response(JSON.stringify({
        error: { message: 'bad request on first channel' },
      }), {
        status: 400,
        headers: { 'content-type': 'application/json' },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        candidates: [
          {
            content: { role: 'model', parts: [{ text: 'ok from fallback' }] },
            finishReason: 'STOP',
          },
        ],
      }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1beta/models/gemini-2.5-flash:generateContent',
      headers: {
        'x-goog-api-key': 'sk-managed-gemini',
      },
      payload: {
        contents: [{ role: 'user', parts: [{ text: 'hello' }] }],
      },
    });

    expect(response.statusCode).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(recordFailureMock).toHaveBeenCalledWith(11);
    const [firstUrl] = fetchMock.mock.calls[0] as [string, RequestInit];
    const [secondUrl] = fetchMock.mock.calls[1] as [string, RequestInit];
    expect(firstUrl).toContain('key=gemini-key');
    expect(secondUrl).toContain('key=gemini-key-2');
    expect(response.json().candidates?.[0]?.content?.parts?.[0]?.text).toContain('ok from fallback');
  });

  it('falls back to the next channel when first Gemini channel returns 403 before any bytes are written', async () => {
    selectNextChannelMock.mockReturnValue({
      channel: { id: 12, routeId: 22 },
      site: { id: 45, name: 'gemini-site-2', url: 'https://generativelanguage.googleapis.com', platform: 'gemini' },
      account: { id: 34, username: 'demo-user-2' },
      tokenName: 'fallback',
      tokenValue: 'gemini-key-2',
      actualModel: 'gemini-2.5-flash',
    });

    fetchMock
      .mockResolvedValueOnce(new Response(JSON.stringify({
        error: { message: 'forbidden on first channel' },
      }), {
        status: 403,
        headers: { 'content-type': 'application/json' },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        candidates: [
          {
            content: { role: 'model', parts: [{ text: 'ok from fallback' }] },
            finishReason: 'STOP',
          },
        ],
      }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1beta/models/gemini-2.5-flash:generateContent',
      headers: {
        'x-goog-api-key': 'sk-managed-gemini',
      },
      payload: {
        contents: [{ role: 'user', parts: [{ text: 'hello' }] }],
      },
    });

    expect(response.statusCode).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(recordFailureMock).toHaveBeenCalledWith(11);
  });

  it('falls back to the next channel when first Gemini channel returns 500 before any bytes are written', async () => {
    selectNextChannelMock.mockReturnValue({
      channel: { id: 12, routeId: 22 },
      site: { id: 45, name: 'gemini-site-2', url: 'https://generativelanguage.googleapis.com', platform: 'gemini' },
      account: { id: 34, username: 'demo-user-2' },
      tokenName: 'fallback',
      tokenValue: 'gemini-key-2',
      actualModel: 'gemini-2.5-flash',
    });

    fetchMock
      .mockResolvedValueOnce(new Response('upstream crash', {
        status: 500,
        headers: { 'content-type': 'text/plain' },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        candidates: [
          {
            content: { role: 'model', parts: [{ text: 'ok from fallback' }] },
            finishReason: 'STOP',
          },
        ],
      }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1beta/models/gemini-2.5-flash:generateContent',
      headers: {
        'x-goog-api-key': 'sk-managed-gemini',
      },
      payload: {
        contents: [{ role: 'user', parts: [{ text: 'hello' }] }],
      },
    });

    expect(response.statusCode).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(recordFailureMock).toHaveBeenCalledWith(11);
  });

  it('falls back to the next channel when first Gemini channel throws before any bytes are written', async () => {
    selectNextChannelMock.mockReturnValue({
      channel: { id: 12, routeId: 22 },
      site: { id: 45, name: 'gemini-site-2', url: 'https://generativelanguage.googleapis.com', platform: 'gemini' },
      account: { id: 34, username: 'demo-user-2' },
      tokenName: 'fallback',
      tokenValue: 'gemini-key-2',
      actualModel: 'gemini-2.5-flash',
    });

    fetchMock
      .mockRejectedValueOnce(new Error('socket hang up'))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        candidates: [
          {
            content: { role: 'model', parts: [{ text: 'ok from fallback' }] },
            finishReason: 'STOP',
          },
        ],
      }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1beta/models/gemini-2.5-flash:generateContent',
      headers: {
        'x-goog-api-key': 'sk-managed-gemini',
      },
      payload: {
        contents: [{ role: 'user', parts: [{ text: 'hello' }] }],
      },
    });

    expect(response.statusCode).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(recordFailureMock).toHaveBeenCalledWith(11);
  });

  it('falls back to the next channel for SSE requests before any bytes are written', async () => {
    selectNextChannelMock.mockReturnValue({
      channel: { id: 12, routeId: 22 },
      site: { id: 45, name: 'gemini-site-2', url: 'https://generativelanguage.googleapis.com', platform: 'gemini' },
      account: { id: 34, username: 'demo-user-2' },
      tokenName: 'fallback',
      tokenValue: 'gemini-key-2',
      actualModel: 'gemini-2.5-flash',
    });

    const encoder = new TextEncoder();
    const upstreamBody = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode('data: {"responseId":"resp-fallback","candidates":[{"content":{"role":"model","parts":[{"text":"hello from fallback sse"}]},"finishReason":"STOP"}]}\r\n\r\n'));
        controller.close();
      },
    });

    fetchMock
      .mockResolvedValueOnce(new Response(JSON.stringify({
        error: { message: 'upstream unavailable' },
      }), {
        status: 500,
        headers: { 'content-type': 'application/json' },
      }))
      .mockResolvedValueOnce(new Response(upstreamBody, {
        status: 200,
        headers: { 'content-type': 'text/event-stream; charset=utf-8' },
      }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=sse',
      headers: {
        'x-goog-api-key': 'sk-managed-gemini',
      },
      payload: {
        contents: [{ role: 'user', parts: [{ text: 'hello' }] }],
      },
    });

    expect(response.statusCode).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(recordFailureMock).toHaveBeenCalledWith(11);
    expect(response.body).toContain('hello from fallback sse');
  });

  it('writes failed and successful proxy log rows for Gemini-native stream retries', async () => {
    selectNextChannelMock.mockReturnValue({
      channel: { id: 12, routeId: 22 },
      site: { id: 45, name: 'gemini-site-2', url: 'https://generativelanguage.googleapis.com', platform: 'gemini' },
      account: { id: 34, username: 'demo-user-2' },
      tokenName: 'fallback',
      tokenValue: 'gemini-key-2',
      actualModel: 'gemini-2.5-flash',
    });

    const encoder = new TextEncoder();
    const upstreamBody = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode('data: {"responseId":"resp-fallback","candidates":[{"content":{"role":"model","parts":[{"text":"hello from fallback sse"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":11,"candidatesTokenCount":6,"totalTokenCount":17}}\r\n\r\n'));
        controller.close();
      },
    });

    fetchMock
      .mockResolvedValueOnce(new Response(JSON.stringify({
        error: { message: 'upstream unavailable' },
      }), {
        status: 500,
        headers: { 'content-type': 'application/json' },
      }))
      .mockResolvedValueOnce(new Response(upstreamBody, {
        status: 200,
        headers: { 'content-type': 'text/event-stream; charset=utf-8' },
      }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=sse',
      headers: {
        'x-goog-api-key': 'sk-managed-gemini',
      },
      payload: {
        contents: [{ role: 'user', parts: [{ text: 'hello' }] }],
      },
    });

    expect(response.statusCode).toBe(200);
    expect(dbInsertMock).toHaveBeenCalledTimes(2);
    expect(dbInsertValuesMock).toHaveBeenNthCalledWith(1, expect.objectContaining({
      channelId: 11,
      status: 'failed',
      httpStatus: 500,
      retryCount: 0,
      errorMessage: '[downstream:/v1beta/models/gemini-2.5-flash:streamGenerateContent] [upstream:/v1beta/models/gemini-2.5-flash:streamGenerateContent] {\"error\":{\"message\":\"upstream unavailable\"}}',
    }));
    expect(dbInsertValuesMock).toHaveBeenNthCalledWith(2, expect.objectContaining({
      channelId: 12,
      status: 'success',
      httpStatus: 200,
      retryCount: 1,
      promptTokens: 11,
      completionTokens: 6,
      totalTokens: 17,
      errorMessage: '[downstream:/v1beta/models/gemini-2.5-flash:streamGenerateContent] [upstream:/v1beta/models/gemini-2.5-flash:streamGenerateContent]',
    }));
    expect(recordSuccessMock).toHaveBeenCalledWith(12, expect.any(Number), 0);
  });
});
