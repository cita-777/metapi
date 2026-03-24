import Fastify, { type FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { config } from '../../config.js';
import { resetUpstreamEndpointRuntimeState } from './upstreamEndpoint.js';

const fetchMock = vi.fn();
const selectChannelMock = vi.fn();
const selectNextChannelMock = vi.fn();
const recordSuccessMock = vi.fn();
const recordFailureMock = vi.fn();
const refreshModelsAndRebuildRoutesMock = vi.fn();
const reportProxyAllFailedMock = vi.fn();
const reportTokenExpiredMock = vi.fn();
const estimateProxyCostMock = vi.fn(async (_arg?: any) => 0);
const buildProxyBillingDetailsMock = vi.fn(async (_arg?: any) => null);
const fetchModelPricingCatalogMock = vi.fn(async (_arg?: any): Promise<any> => null);
const resolveProxyUsageWithSelfLogFallbackMock = vi.fn(async ({ usage }: any) => ({
  ...usage,
  estimatedCostFromQuota: 0,
  recoveredFromSelfLog: false,
}));
const dbInsertMock = vi.fn((_arg?: any) => ({
  values: () => ({
    run: () => undefined,
  }),
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
  },
}));

vi.mock('../../services/modelService.js', () => ({
  refreshModelsAndRebuildRoutes: (...args: unknown[]) => refreshModelsAndRebuildRoutesMock(...args),
}));

vi.mock('../../services/alertService.js', () => ({
  reportProxyAllFailed: (...args: unknown[]) => reportProxyAllFailedMock(...args),
  reportTokenExpired: (...args: unknown[]) => reportTokenExpiredMock(...args),
}));

vi.mock('../../services/alertRules.js', () => ({
  isTokenExpiredError: () => false,
}));

vi.mock('../../services/modelPricingService.js', () => ({
  estimateProxyCost: (arg: any) => estimateProxyCostMock(arg),
  buildProxyBillingDetails: (arg: any) => buildProxyBillingDetailsMock(arg),
  fetchModelPricingCatalog: (arg: any) => fetchModelPricingCatalogMock(arg),
}));

vi.mock('../../services/proxyRetryPolicy.js', () => ({
  shouldRetryProxyRequest: () => false,
}));

vi.mock('../../services/proxyUsageFallbackService.js', () => ({
  resolveProxyUsageWithSelfLogFallback: (arg: any) => resolveProxyUsageWithSelfLogFallbackMock(arg),
}));

vi.mock('../../db/index.js', () => ({
  db: {
    insert: (arg: any) => dbInsertMock(arg),
  },
  hasProxyLogBillingDetailsColumn: async () => false,
  hasProxyLogClientColumns: async () => false,
  hasProxyLogDownstreamApiKeyIdColumn: async () => false,
  schema: {
    proxyLogs: {},
  },
}));

describe('chat proxy stream behavior', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    const { chatProxyRoute, claudeMessagesProxyRoute } = await import('./chat.js');
    const { responsesProxyRoute } = await import('./responses.js');
    app = Fastify();
    await app.register(chatProxyRoute);
    await app.register(claudeMessagesProxyRoute);
    await app.register(responsesProxyRoute);
  });

  beforeEach(() => {
    fetchMock.mockReset();
    selectChannelMock.mockReset();
    selectNextChannelMock.mockReset();
    recordSuccessMock.mockReset();
    recordFailureMock.mockReset();
    refreshModelsAndRebuildRoutesMock.mockReset();
    reportProxyAllFailedMock.mockReset();
    reportTokenExpiredMock.mockReset();
    estimateProxyCostMock.mockClear();
    buildProxyBillingDetailsMock.mockClear();
    fetchModelPricingCatalogMock.mockReset();
    resolveProxyUsageWithSelfLogFallbackMock.mockClear();
    dbInsertMock.mockClear();
    resetUpstreamEndpointRuntimeState();

    selectChannelMock.mockReturnValue({
      channel: { id: 11, routeId: 22 },
      site: { name: 'demo-site', url: 'https://upstream.example.com' },
      account: { id: 33, username: 'demo-user' },
      tokenName: 'default',
      tokenValue: 'sk-demo',
      actualModel: 'upstream-gpt',
    });
    selectNextChannelMock.mockReturnValue(null);
    fetchModelPricingCatalogMock.mockResolvedValue(null);
    (config as any).codexHeaderDefaults = {
      userAgent: '',
      betaFeatures: '',
    };
    (config as any).payloadRules = {
      default: [],
      defaultRaw: [],
      override: [],
      overrideRaw: [],
      filter: [],
    };
    config.proxyEmptyContentFailEnabled = false;
    config.proxyErrorKeywords = [];
  });

  afterAll(async () => {
    await app.close();
  });

  it('converts non-SSE upstream streaming responses into SSE events', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      id: 'chatcmpl-demo',
      object: 'chat.completion',
      created: 1_706_000_000,
      model: 'upstream-gpt',
      choices: [{
        index: 0,
        message: { role: 'assistant', content: 'hello from upstream' },
        finish_reason: 'stop',
      }],
      usage: { prompt_tokens: 11, completion_tokens: 7, total_tokens: 18 },
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      payload: {
        model: 'gpt-4o-mini',
        stream: true,
        messages: [{ role: 'user', content: 'hi' }],
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.headers['content-type']).toContain('text/event-stream');
    expect(response.body).toContain('data: ');
    expect(response.body).toContain('"chat.completion.chunk"');
    expect(response.body).toContain('hello from upstream');
    expect(response.body).toContain('data: [DONE]');
  });

  it('returns upstream_error for empty non-stream chat responses when empty-content failure is enabled', async () => {
    config.proxyEmptyContentFailEnabled = true;

    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      id: 'chatcmpl-empty',
      object: 'chat.completion',
      created: 1_706_000_000,
      model: 'upstream-gpt',
      choices: [{
        index: 0,
        message: { role: 'assistant', content: '' },
        finish_reason: 'stop',
      }],
      usage: { prompt_tokens: 6, completion_tokens: 0, total_tokens: 6 },
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      payload: {
        model: 'gpt-4o-mini',
        messages: [{ role: 'user', content: 'hi' }],
      },
    });

    expect(response.statusCode).toBe(502);
    expect(response.json()?.error?.type).toBe('upstream_error');
    expect(response.json()?.error?.message).toContain('empty content');
    expect(recordSuccessMock).not.toHaveBeenCalled();
    expect(recordFailureMock).toHaveBeenCalledTimes(1);
  });

  it('returns HTTP upstream_error instead of hijacking when streamed chat requests receive empty non-SSE payloads', async () => {
    config.proxyEmptyContentFailEnabled = true;

    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      id: 'chatcmpl-empty-stream',
      object: 'chat.completion',
      created: 1_706_000_000,
      model: 'upstream-gpt',
      choices: [{
        index: 0,
        message: { role: 'assistant', content: '' },
        finish_reason: 'stop',
      }],
      usage: { prompt_tokens: 4, completion_tokens: 0, total_tokens: 4 },
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      payload: {
        model: 'gpt-4o-mini',
        stream: true,
        messages: [{ role: 'user', content: 'hi' }],
      },
    });

    expect(response.statusCode).toBe(502);
    expect(response.headers['content-type']).not.toContain('text/event-stream');
    expect(response.json()?.error?.type).toBe('upstream_error');
    expect(recordSuccessMock).not.toHaveBeenCalled();
    expect(recordFailureMock).toHaveBeenCalledTimes(1);
  });

  it('returns clear 400 when /v1/chat/completions receives responses-style input without messages', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      payload: {
        model: 'claude-haiku-4-5-20251001',
        input: 'hello',
      },
    });

    expect(response.statusCode).toBe(400);
    const body = response.json();
    expect(body?.error?.type).toBe('invalid_request_error');
    expect(body?.error?.message).toContain('/v1/responses');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('sets anti-buffering SSE headers for streamed chat responses', async () => {
    const encoder = new TextEncoder();
    const upstreamBody = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode('data: {"choices":[{"delta":{"content":"hello"}}]}\n\n'));
        controller.enqueue(encoder.encode('data: [DONE]\n\n'));
        controller.close();
      },
    });

    fetchMock.mockResolvedValue(new Response(upstreamBody, {
      status: 200,
      headers: { 'content-type': 'text/event-stream; charset=utf-8' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      payload: {
        model: 'gpt-4o-mini',
        stream: true,
        messages: [{ role: 'user', content: 'hello' }],
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.headers['content-type']).toContain('text/event-stream');
    expect(response.headers['cache-control']).toContain('no-transform');
    expect(response.headers['x-accel-buffering']).toBe('no');
    expect(response.body).toContain('"chat.completion.chunk"');
    expect(response.body).toContain('"delta":{"role":"assistant","content":"hello"}');
    expect(response.body).toContain('data: [DONE]');
  });

  it('normalizes inline think tags into reasoning_content for /v1/chat/completions streams', async () => {
    const encoder = new TextEncoder();
    const upstreamBody = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode('data: {"id":"chatcmpl-think","model":"upstream-gpt","choices":[{"delta":{"role":"assistant"},"finish_reason":null}]}\n\n'));
        controller.enqueue(encoder.encode('data: {"id":"chatcmpl-think","model":"upstream-gpt","choices":[{"delta":{"content":"<think>plan quietly</think>"},"finish_reason":null}]}\n\n'));
        controller.enqueue(encoder.encode('data: {"id":"chatcmpl-think","model":"upstream-gpt","choices":[{"delta":{"content":"visible answer"},"finish_reason":null}]}\n\n'));
        controller.enqueue(encoder.encode('data: {"id":"chatcmpl-think","model":"upstream-gpt","choices":[{"delta":{},"finish_reason":"stop"}]}\n\n'));
        controller.enqueue(encoder.encode('data: [DONE]\n\n'));
        controller.close();
      },
    });

    fetchMock.mockResolvedValue(new Response(upstreamBody, {
      status: 200,
      headers: { 'content-type': 'text/event-stream; charset=utf-8' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      payload: {
        model: 'gpt-4o-mini',
        stream: true,
        messages: [{ role: 'user', content: 'show your work and answer' }],
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.body).toContain('"reasoning_content":"plan quietly"');
    expect(response.body).toContain('"content":"visible answer"');
    expect(response.body).not.toContain('<think>');
    expect(response.body).not.toContain('</think>');
    expect(response.body).toContain('data: [DONE]');
  });

  it('tracks split inline think tags across SSE chunks for /v1/chat/completions streams', async () => {
    const encoder = new TextEncoder();
    const upstreamBody = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode('data: {"id":"chatcmpl-think-split","model":"upstream-gpt","choices":[{"delta":{"role":"assistant"},"finish_reason":null}]}\n\n'));
        controller.enqueue(encoder.encode('data: {"id":"chatcmpl-think-split","model":"upstream-gpt","choices":[{"delta":{"content":"<thin"},"finish_reason":null}]}\n\n'));
        controller.enqueue(encoder.encode('data: {"id":"chatcmpl-think-split","model":"upstream-gpt","choices":[{"delta":{"content":"k>plan "},"finish_reason":null}]}\n\n'));
        controller.enqueue(encoder.encode('data: {"id":"chatcmpl-think-split","model":"upstream-gpt","choices":[{"delta":{"content":"quietly</th"},"finish_reason":null}]}\n\n'));
        controller.enqueue(encoder.encode('data: {"id":"chatcmpl-think-split","model":"upstream-gpt","choices":[{"delta":{"content":"ink>visible "},"finish_reason":null}]}\n\n'));
        controller.enqueue(encoder.encode('data: {"id":"chatcmpl-think-split","model":"upstream-gpt","choices":[{"delta":{"content":"answer"},"finish_reason":null}]}\n\n'));
        controller.enqueue(encoder.encode('data: {"id":"chatcmpl-think-split","model":"upstream-gpt","choices":[{"delta":{},"finish_reason":"stop"}]}\n\n'));
        controller.enqueue(encoder.encode('data: [DONE]\n\n'));
        controller.close();
      },
    });

    fetchMock.mockResolvedValue(new Response(upstreamBody, {
      status: 200,
      headers: { 'content-type': 'text/event-stream; charset=utf-8' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      payload: {
        model: 'gpt-4o-mini',
        stream: true,
        messages: [{ role: 'user', content: 'show your work and answer' }],
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.body).toContain('"reasoning_content":"plan "');
    expect(response.body).toContain('"reasoning_content":"quietly"');
    expect(response.body).toContain('"content":"visible "');
    expect(response.body).toContain('"content":"answer"');
    expect(response.body).not.toContain('<think>');
    expect(response.body).not.toContain('</think>');
    expect(response.body).not.toContain('<thin');
    expect(response.body).not.toContain('quietly</th');
    expect(response.body).not.toContain('ink>visible');
    expect(response.body).toContain('data: [DONE]');
  });

  it('synthesizes a terminal finish chunk when /v1/chat/completions upstream EOFs after visible content', async () => {
    const encoder = new TextEncoder();
    const upstreamBody = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode('data: {"id":"chatcmpl-eof","model":"upstream-gpt","choices":[{"delta":{"role":"assistant"},"finish_reason":null}]}\n\n'));
        controller.enqueue(encoder.encode('data: {"id":"chatcmpl-eof","model":"upstream-gpt","choices":[{"delta":{"content":"tail before eof"},"finish_reason":null}]}\n\n'));
        controller.close();
      },
    });

    fetchMock.mockResolvedValue(new Response(upstreamBody, {
      status: 200,
      headers: { 'content-type': 'text/event-stream; charset=utf-8' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      payload: {
        model: 'gpt-4o-mini',
        stream: true,
        messages: [{ role: 'user', content: 'finish cleanly' }],
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.body).toContain('tail before eof');
    expect(response.body).toContain('"finish_reason":"stop"');
    expect(response.body).toContain('data: [DONE]');
  });

  it('normalizes anthropic-style SSE events into OpenAI chunks for clients like OpenWebUI', async () => {
    const encoder = new TextEncoder();
    const upstreamBody = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode('event: message_start\ndata: {"type":"message_start","message":{"id":"msg_123","model":"claude-opus-4-6"}}\n\n'));
        controller.enqueue(encoder.encode('event: content_block_delta\ndata: {"type":"content_block_delta","delta":{"type":"text_delta","text":"hello"}}\n\n'));
        controller.enqueue(encoder.encode('event: message_delta\ndata: {"type":"message_delta","delta":{"stop_reason":"end_turn"}}\n\n'));
        controller.enqueue(encoder.encode('event: message_stop\ndata: {"type":"message_stop"}\n\n'));
        controller.close();
      },
    });

    fetchMock.mockResolvedValue(new Response(upstreamBody, {
      status: 200,
      headers: { 'content-type': 'text/event-stream; charset=utf-8' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      payload: {
        model: 'claude-opus-4-6',
        stream: true,
        messages: [{ role: 'user', content: 'who are you' }],
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.headers['content-type']).toContain('text/event-stream');
    expect(response.body).toContain('"chat.completion.chunk"');
    expect(response.body).toContain('"delta":{"content":"hello"}');
    expect(response.body).toContain('"finish_reason":"stop"');
    expect(response.body).toContain('data: [DONE]');
  });

  it('emits OpenAI-compatible assistant starter chunk for anthropic message_start events', async () => {
    const encoder = new TextEncoder();
    const upstreamBody = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode('event: message_start\ndata: {"type":"message_start","message":{"id":"msg_compat","model":"claude-opus-4-6"}}\n\n'));
        controller.enqueue(encoder.encode('event: content_block_delta\ndata: {"type":"content_block_delta","delta":{"type":"text_delta","text":"compat"}}\n\n'));
        controller.enqueue(encoder.encode('event: message_stop\ndata: {"type":"message_stop"}\n\n'));
        controller.close();
      },
    });

    fetchMock.mockResolvedValue(new Response(upstreamBody, {
      status: 200,
      headers: { 'content-type': 'text/event-stream; charset=utf-8' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      payload: {
        model: 'claude-opus-4-6',
        stream: true,
        messages: [{ role: 'user', content: 'compat test' }],
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.body).toContain('"delta":{"role":"assistant","content":""}');
    expect(response.body).toContain('"delta":{"content":"compat"}');
    expect(response.body).toContain('data: [DONE]');
  });

  it('converts OpenAI non-stream responses into Claude message format on /v1/messages', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      id: 'chatcmpl-upstream',
      object: 'chat.completion',
      created: 1_706_000_001,
      model: 'claude-opus-4-6',
      choices: [{
        index: 0,
        message: { role: 'assistant', content: 'hello from claude format' },
        finish_reason: 'stop',
      }],
      usage: { prompt_tokens: 120, completion_tokens: 16, total_tokens: 136 },
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/messages',
      payload: {
        model: 'claude-opus-4-6',
        max_tokens: 256,
        messages: [{ role: 'user', content: 'hello' }],
      },
    });

    expect(response.statusCode).toBe(200);
    const body = response.json();
    expect(body.type).toBe('message');
    expect(body.role).toBe('assistant');
    expect(body.model).toBe('claude-opus-4-6');
    expect(body.content?.[0]?.type).toBe('text');
    expect(body.content?.[0]?.text).toContain('hello from claude format');
    expect(body.stop_reason).toBe('end_turn');
  });

  it('converts OpenAI SSE chunks into Claude stream events on /v1/messages', async () => {
    const encoder = new TextEncoder();
    const upstreamBody = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode('data: {"id":"chatcmpl-1","model":"claude-opus-4-6","choices":[{"delta":{"role":"assistant"},"finish_reason":null}]}\n\n'));
        controller.enqueue(encoder.encode('data: {"id":"chatcmpl-1","model":"claude-opus-4-6","choices":[{"delta":{"content":"hello"},"finish_reason":null}]}\n\n'));
        controller.enqueue(encoder.encode('data: {"id":"chatcmpl-1","model":"claude-opus-4-6","choices":[{"delta":{},"finish_reason":"stop"}]}\n\n'));
        controller.enqueue(encoder.encode('data: [DONE]\n\n'));
        controller.close();
      },
    });

    fetchMock.mockResolvedValue(new Response(upstreamBody, {
      status: 200,
      headers: { 'content-type': 'text/event-stream; charset=utf-8' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/messages',
      payload: {
        model: 'claude-opus-4-6',
        stream: true,
        max_tokens: 256,
        messages: [{ role: 'user', content: 'hello' }],
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.headers['content-type']).toContain('text/event-stream');
    expect(response.body).toContain('event: message_start');
    expect(response.body).toContain('event: content_block_delta');
    expect(response.body).toContain('\"text\":\"hello\"');
    expect(response.body).toContain('event: message_stop');
  });

  it('converts OpenAI tool_calls SSE into Claude tool_use stream events on /v1/messages', async () => {
    const encoder = new TextEncoder();
    const upstreamBody = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode('data: {"id":"chatcmpl-tool","model":"claude-opus-4-6","choices":[{"delta":{"role":"assistant"},"finish_reason":null}]}\n\n'));
        controller.enqueue(encoder.encode('data: {"id":"chatcmpl-tool","model":"claude-opus-4-6","choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_glob","type":"function","function":{"name":"Glob","arguments":""}}]},"finish_reason":null}]}\n\n'));
        controller.enqueue(encoder.encode('data: {"id":"chatcmpl-tool","model":"claude-opus-4-6","choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\\"pattern\\":\\"README*\\"}"}}]},"finish_reason":"tool_calls"}]}\n\n'));
        controller.enqueue(encoder.encode('data: [DONE]\n\n'));
        controller.close();
      },
    });

    fetchMock.mockResolvedValue(new Response(upstreamBody, {
      status: 200,
      headers: { 'content-type': 'text/event-stream; charset=utf-8' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/messages',
      payload: {
        model: 'claude-opus-4-6',
        stream: true,
        max_tokens: 256,
        messages: [{ role: 'user', content: 'find readme files' }],
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.headers['content-type']).toContain('text/event-stream');
    expect(response.body).toContain('event: content_block_start');
    expect(response.body).toContain('"type":"tool_use"');
    expect(response.body).toContain('"name":"Glob"');
    expect(response.body).toContain('"type":"input_json_delta"');
    expect(response.body).toContain('"partial_json":"{\\"pattern\\":\\"README*\\"}"');
    expect(response.body).toContain('"stop_reason":"tool_use"');
  });

  it('keeps final content when upstream chunk carries both delta and finish_reason on /v1/messages', async () => {
    const encoder = new TextEncoder();
    const upstreamBody = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode('data: {"id":"chatcmpl-2","model":"claude-opus-4-6","choices":[{"delta":{"role":"assistant"},"finish_reason":null}]}\n\n'));
        controller.enqueue(encoder.encode('data: {"id":"chatcmpl-2","model":"claude-opus-4-6","choices":[{"delta":{"content":"tail-token"},"finish_reason":"stop"}]}\n\n'));
        controller.enqueue(encoder.encode('data: [DONE]\n\n'));
        controller.close();
      },
    });

    fetchMock.mockResolvedValue(new Response(upstreamBody, {
      status: 200,
      headers: { 'content-type': 'text/event-stream; charset=utf-8' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/messages',
      payload: {
        model: 'claude-opus-4-6',
        stream: true,
        max_tokens: 256,
        messages: [{ role: 'user', content: 'hello' }],
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.body).toContain('event: content_block_delta');
    expect(response.body).toContain('\"text\":\"tail-token\"');
    expect(response.body).toContain('event: message_stop');
  });

  it('preserves Claude-specific payload fields and forwards claude headers on /v1/messages', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      id: 'msg_headers',
      type: 'message',
      model: 'claude-opus-4-6',
      content: [{ type: 'text', text: 'ok' }],
      stop_reason: 'end_turn',
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/messages',
      headers: {
        'anthropic-beta': 'code-2025-09-30',
        'x-claude-client': 'claude-code',
      },
      payload: {
        model: 'claude-opus-4-6',
        max_tokens: 256,
        messages: [{ role: 'user', content: 'hello' }],
        metadata: { session_id: 'abc123' },
        thinking: { type: 'enabled', budget_tokens: 1024 },
      },
    });

    expect(response.statusCode).toBe(200);

    const [_targetUrl, options] = fetchMock.mock.calls[0] as [string, any];
    expect(options.headers['anthropic-beta']).toContain('claude-code-20250219');
    expect(options.headers['anthropic-beta']).toContain('code-2025-09-30');
    expect(options.headers['x-claude-client']).toBe('claude-code');

    const forwardedBody = JSON.parse(options.body);
    expect(forwardedBody.metadata).toEqual({ session_id: 'abc123' });
    expect(forwardedBody.thinking).toEqual({ type: 'enabled', budget_tokens: 1024 });
  });

  it('stops forwarding extra SSE events after message_stop on /v1/messages', async () => {
    const encoder = new TextEncoder();
    const upstreamBody = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode('event: message_start\ndata: {"type":"message_start","message":{"id":"msg_stop_early","model":"claude-opus-4-6"}}\n\n'));
        controller.enqueue(encoder.encode('event: content_block_delta\ndata: {"type":"content_block_delta","delta":{"type":"text_delta","text":"hello"}}\n\n'));
        controller.enqueue(encoder.encode('event: message_delta\ndata: {"type":"message_delta","delta":{"stop_reason":"end_turn"}}\n\n'));
        controller.enqueue(encoder.encode('event: message_stop\ndata: {"type":"message_stop"}\n\n'));
        controller.enqueue(encoder.encode('event: ping\ndata: {"type":"ping"}\n\n'));
        controller.enqueue(encoder.encode('data: [DONE]\n\n'));
        controller.close();
      },
    });

    fetchMock.mockResolvedValue(new Response(upstreamBody, {
      status: 200,
      headers: { 'content-type': 'text/event-stream; charset=utf-8' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/messages',
      payload: {
        model: 'claude-opus-4-6',
        stream: true,
        max_tokens: 256,
        messages: [{ role: 'user', content: 'hello' }],
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.body).toContain('event: message_stop');
    expect(response.body).not.toContain('event: ping');
  });

  it('does not synthesize message_stop when anthropic upstream EOFs before terminal event on /v1/messages', async () => {
    const encoder = new TextEncoder();
    const upstreamBody = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode('event: message_start\ndata: {"type":"message_start","message":{"id":"msg_eof_early","model":"claude-opus-4-6"}}\n\n'));
        controller.enqueue(encoder.encode('event: content_block_start\ndata: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}\n\n'));
        controller.enqueue(encoder.encode('event: content_block_delta\ndata: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hello"}}\n\n'));
        controller.close();
      },
    });

    fetchMock.mockResolvedValue(new Response(upstreamBody, {
      status: 200,
      headers: { 'content-type': 'text/event-stream; charset=utf-8' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/messages',
      payload: {
        model: 'claude-opus-4-6',
        stream: true,
        max_tokens: 256,
        messages: [{ role: 'user', content: 'hello' }],
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.body).toContain('event: message_start');
    expect(response.body).toContain('event: content_block_delta');
    expect(response.body).not.toContain('event: message_stop');
    expect(response.body).not.toContain('"stop_reason":"end_turn"');
  });

  it('normalizes Claude thinking adaptive type for legacy upstreams on /v1/messages', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      id: 'msg_headers_adaptive',
      type: 'message',
      model: 'claude-opus-4-6',
      content: [{ type: 'text', text: 'ok' }],
      stop_reason: 'end_turn',
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/messages',
      payload: {
        model: 'claude-opus-4-6',
        max_tokens: 256,
        messages: [{ role: 'user', content: 'hello' }],
        thinking: { type: 'adaptive', budget_tokens: 1024 },
      },
    });

    expect(response.statusCode).toBe(200);

    const [_targetUrl, options] = fetchMock.mock.calls[0] as [string, any];
    const forwardedBody = JSON.parse(options.body);
    expect(forwardedBody.thinking).toEqual({ type: 'enabled', budget_tokens: 1024 });
  });

  it('retries /v1/messages with normalized Claude body when upstream says messages is required', async () => {
    fetchMock
      .mockResolvedValueOnce(new Response(JSON.stringify({
        error: {
          type: '<nil>',
          message: 'messages is required',
        },
      }), {
        status: 400,
        headers: { 'content-type': 'application/json' },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        id: 'msg_retry_ok',
        type: 'message',
        model: 'claude-opus-4-6',
        content: [{ type: 'text', text: 'ok after normalized fallback' }],
        stop_reason: 'end_turn',
      }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/messages',
      payload: {
        model: 'claude-opus-4-6',
        max_tokens: 256,
        messages: [
          {
            role: 'user',
            content: [
              { type: 'text', text: 'hello' },
            ],
          },
        ],
      },
    });

    expect(response.statusCode).toBe(200);
    expect(fetchMock.mock.calls.length).toBe(2);

    const [_firstUrl, firstOptions] = fetchMock.mock.calls[0] as [string, any];
    const [_secondUrl, secondOptions] = fetchMock.mock.calls[1] as [string, any];
    const firstBody = JSON.parse(firstOptions.body);
    const secondBody = JSON.parse(secondOptions.body);

    expect(Array.isArray(firstBody.messages)).toBe(true);
    expect(Array.isArray(secondBody.messages)).toBe(true);
    expect(Array.isArray(secondBody.messages[0]?.content)).toBe(true);
    expect(secondBody.messages[0]?.content).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          type: 'text',
          text: expect.stringContaining('hello'),
        }),
      ]),
    );
  });

  it('keeps native Claude file blocks when retrying /v1/messages with normalized body', async () => {
    fetchMock
      .mockResolvedValueOnce(new Response(JSON.stringify({
        error: {
          type: '<nil>',
          message: 'messages is required',
        },
      }), {
        status: 400,
        headers: { 'content-type': 'application/json' },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        id: 'msg_retry_file_ok',
        type: 'message',
        model: 'claude-opus-4-6',
        content: [{ type: 'text', text: 'ok after normalized fallback' }],
        stop_reason: 'end_turn',
      }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/messages',
      payload: {
        model: 'claude-opus-4-6',
        max_tokens: 256,
        messages: [
          {
            role: 'user',
            content: [
              { type: 'text', text: 'summarize this file' },
              {
                type: 'file',
                file: {
                  filename: 'brief.pdf',
                  file_data: 'JVBERi0xLjc=',
                },
              },
            ],
          },
        ],
      },
    });

    expect(response.statusCode).toBe(200);
    expect(fetchMock.mock.calls.length).toBe(2);

    const [_firstUrl, firstOptions] = fetchMock.mock.calls[0] as [string, any];
    const [_secondUrl, secondOptions] = fetchMock.mock.calls[1] as [string, any];
    const firstBody = JSON.parse(firstOptions.body);
    const secondBody = JSON.parse(secondOptions.body);

    expect(firstBody.messages[0]?.content).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          type: 'document',
          title: 'brief.pdf',
        }),
      ]),
    );
    expect(secondBody.messages[0]?.content).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          type: 'document',
          title: 'brief.pdf',
        }),
      ]),
    );
  });

  it('downgrades to next endpoint when normalized Claude fallback still returns messages is required', async () => {
    fetchMock
      .mockResolvedValueOnce(new Response(JSON.stringify({
        error: {
          type: '<nil>',
          message: 'messages is required',
        },
      }), {
        status: 400,
        headers: { 'content-type': 'application/json' },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        error: {
          type: '<nil>',
          message: 'messages is required',
        },
      }), {
        status: 400,
        headers: { 'content-type': 'application/json' },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        id: 'chatcmpl_downgraded_ok',
        object: 'chat.completion',
        model: 'upstream-gpt',
        choices: [{
          index: 0,
          message: { role: 'assistant', content: 'ok after endpoint downgrade' },
          finish_reason: 'stop',
        }],
      }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/messages',
      payload: {
        model: 'claude-opus-4-6',
        max_tokens: 256,
        messages: [{ role: 'user', content: 'hello' }],
      },
    });

    expect(response.statusCode).toBe(200);
    expect(fetchMock.mock.calls.length).toBe(3);
    const [firstUrl] = fetchMock.mock.calls[0] as [string, any];
    const [secondUrl] = fetchMock.mock.calls[1] as [string, any];
    const [thirdUrl] = fetchMock.mock.calls[2] as [string, any];
    expect(firstUrl).toContain('/v1/messages');
    expect(secondUrl).toContain('/v1/messages');
    expect(thirdUrl).toContain('/v1/chat/completions');
    expect(response.json()?.type).toBe('message');
  });

  it('passes through Claude tool_use SSE events on /v1/messages for CLI tool execution', async () => {
    const encoder = new TextEncoder();
    const upstreamBody = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode('event: message_start\ndata: {"type":"message_start","message":{"id":"msg_tool_1","model":"claude-opus-4-6","role":"assistant","content":[],"stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":0}}}\n\n'));
        controller.enqueue(encoder.encode('event: content_block_start\ndata: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_1","name":"Glob","input":{}}}\n\n'));
        controller.enqueue(encoder.encode('event: content_block_delta\ndata: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\\"pattern\\":\\"README*\\"}"}}\n\n'));
        controller.enqueue(encoder.encode('event: content_block_stop\ndata: {"type":"content_block_stop","index":0}\n\n'));
        controller.enqueue(encoder.encode('event: message_delta\ndata: {"type":"message_delta","delta":{"stop_reason":"tool_use","stop_sequence":null},"usage":{"output_tokens":6}}\n\n'));
        controller.enqueue(encoder.encode('event: message_stop\ndata: {"type":"message_stop"}\n\n'));
        controller.close();
      },
    });

    fetchMock.mockResolvedValue(new Response(upstreamBody, {
      status: 200,
      headers: { 'content-type': 'text/event-stream; charset=utf-8' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/messages',
      payload: {
        model: 'claude-opus-4-6',
        stream: true,
        max_tokens: 256,
        messages: [{ role: 'user', content: 'find readme files' }],
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.headers['content-type']).toContain('text/event-stream');
    expect(response.body).toContain('event: content_block_start');
    expect(response.body).toContain('"type":"tool_use"');
    expect(response.body).toContain('"name":"Glob"');
    expect(response.body).toContain('"partial_json":"{\\"pattern\\":\\"README*\\"}"');
    expect(response.body).toContain('event: message_stop');
  });

  it('serves /v1/responses via protocol translation when upstream is OpenAI-compatible', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      id: 'resp_123',
      object: 'response',
      output_text: 'hello from responses',
      usage: { input_tokens: 10, output_tokens: 5, total_tokens: 15 },
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/responses',
      payload: {
        model: 'gpt-5.2',
        input: 'hello',
      },
    });

    expect(response.statusCode).toBe(200);
    const body = response.json();
    expect(body.object).toBe('response');
    expect(body.output_text).toContain('hello from responses');

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [targetUrl, options] = fetchMock.mock.calls[0] as [string, any];
    expect(targetUrl).toContain('/v1/responses');
    const forwarded = JSON.parse(options.body);
    expect(forwarded.model).toBe('upstream-gpt');
    expect(forwarded.input).toEqual([
      {
        type: 'message',
        role: 'user',
        content: [{ type: 'input_text', text: 'hello' }],
      },
    ]);
  });

  it('continues downgrade to /v1/messages when /v1/chat/completions returns messages is required for /v1/responses', async () => {
    fetchMock
      .mockResolvedValueOnce(new Response(JSON.stringify({
        error: {
          message: 'openai_error',
          type: 'bad_response_status_code',
          code: 'bad_response_status_code',
        },
      }), {
        status: 404,
        headers: { 'content-type': 'application/json' },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        error: {
          message: 'messages is required',
          type: 'upstream_error',
          code: null,
        },
      }), {
        status: 400,
        headers: { 'content-type': 'application/json' },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        id: 'msg_responses_retry_messages',
        type: 'message',
        model: 'upstream-gpt',
        content: [{ type: 'text', text: 'ok from messages fallback' }],
        stop_reason: 'end_turn',
        usage: { input_tokens: 5, output_tokens: 2, total_tokens: 7 },
      }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/responses',
      payload: {
        model: 'gpt-5.2',
        input: 'hello',
      },
    });

    expect(response.statusCode).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(3);

    const [firstUrl] = fetchMock.mock.calls[0] as [string, any];
    const [secondUrl] = fetchMock.mock.calls[1] as [string, any];
    const [thirdUrl] = fetchMock.mock.calls[2] as [string, any];
    expect(firstUrl).toContain('/v1/responses');
    expect(secondUrl).toContain('/v1/chat/completions');
    expect(thirdUrl).toContain('/v1/messages');

    const body = response.json();
    expect(body.object).toBe('response');
    expect(body.output_text).toContain('ok from messages fallback');
  });

  it('canonicalizes native /v1/responses SSE payloads instead of passing them through raw', async () => {
    const encoder = new TextEncoder();
    const upstreamBody = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode('event: response.output_text.delta\ndata: {"type":"response.output_text.delta","delta":"hello"}\n\n'));
        controller.enqueue(encoder.encode('data: [DONE]\n\n'));
        controller.close();
      },
    });

    fetchMock.mockResolvedValue(new Response(upstreamBody, {
      status: 200,
      headers: { 'content-type': 'text/event-stream; charset=utf-8' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/responses',
      payload: {
        model: 'gpt-5.2',
        input: 'hello',
        stream: true,
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.headers['content-type']).toContain('text/event-stream');
    expect(response.body).toContain('response.output_text.delta');
    expect(response.body).toContain('response.output_text.done');
    expect(response.body).toContain('response.output_item.done');
    expect(response.body).toContain('response.completed');
    expect(response.body).toContain('[DONE]');
  });

  it('converts chat-completions SSE to Responses stream events for /v1/responses clients', async () => {
    fetchModelPricingCatalogMock.mockResolvedValue({
      models: [
        {
          modelName: 'upstream-gpt',
          supportedEndpointTypes: ['/v1/chat/completions'],
        },
      ],
      groupRatio: {},
    });

    const encoder = new TextEncoder();
    const upstreamBody = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode('data: {"id":"chatcmpl-r1","model":"upstream-gpt","choices":[{"delta":{"role":"assistant"},"finish_reason":null}]}\n\n'));
        controller.enqueue(encoder.encode('data: {"id":"chatcmpl-r1","model":"upstream-gpt","choices":[{"delta":{"content":"hello"},"finish_reason":null}]}\n\n'));
        controller.enqueue(encoder.encode('data: {"id":"chatcmpl-r1","model":"upstream-gpt","choices":[{"delta":{},"finish_reason":"stop"}]}\n\n'));
        controller.enqueue(encoder.encode('data: [DONE]\n\n'));
        controller.close();
      },
    });

    fetchMock.mockResolvedValue(new Response(upstreamBody, {
      status: 200,
      headers: { 'content-type': 'text/event-stream; charset=utf-8' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/responses',
      payload: {
        model: 'gpt-5.2',
        input: 'hello',
        stream: true,
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.headers['content-type']).toContain('text/event-stream');
    expect(response.body).toContain('response.output_item.added');
    expect(response.body).toContain('response.output_text.delta');
    expect(response.body).toContain('response.completed');
    expect(response.body).toContain('[DONE]');
  });

  it('converts chat tool_calls SSE to Responses function_call events on /v1/responses', async () => {
    fetchModelPricingCatalogMock.mockResolvedValue({
      models: [
        {
          modelName: 'upstream-gpt',
          supportedEndpointTypes: ['/v1/chat/completions'],
        },
      ],
      groupRatio: {},
    });

    const encoder = new TextEncoder();
    const upstreamBody = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode('data: {"id":"chatcmpl-r2","model":"upstream-gpt","choices":[{"delta":{"role":"assistant"},"finish_reason":null}]}\n\n'));
        controller.enqueue(encoder.encode('data: {"id":"chatcmpl-r2","model":"upstream-gpt","choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_abc","type":"function","function":{"name":"Glob","arguments":""}}]},"finish_reason":null}]}\n\n'));
        controller.enqueue(encoder.encode('data: {"id":"chatcmpl-r2","model":"upstream-gpt","choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\\"pattern\\":\\"README*\\"}"}}]},"finish_reason":"tool_calls"}]}\n\n'));
        controller.enqueue(encoder.encode('data: [DONE]\n\n'));
        controller.close();
      },
    });

    fetchMock.mockResolvedValue(new Response(upstreamBody, {
      status: 200,
      headers: { 'content-type': 'text/event-stream; charset=utf-8' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/responses',
      payload: {
        model: 'gpt-5.2',
        input: 'find readme',
        stream: true,
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.body).toContain('"type":"function_call"');
    expect(response.body).toContain('response.function_call_arguments.delta');
    expect(response.body).toContain('"name":"Glob"');
    expect(response.body).toContain('"delta":"{\\"pattern\\":\\"README*\\"}"');
    expect(response.body).toContain('response.completed');
  });

  it('emits response.failed without synthetic response.completed when upstream stream fails on /v1/responses', async () => {
    fetchModelPricingCatalogMock.mockResolvedValue({
      models: [
        {
          modelName: 'upstream-gpt',
          supportedEndpointTypes: ['/v1/chat/completions'],
        },
      ],
      groupRatio: {},
    });

    const encoder = new TextEncoder();
    const upstreamBody = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode('data: {"id":"chatcmpl-r3","model":"upstream-gpt","choices":[{"delta":{"role":"assistant"},"finish_reason":null}]}\n\n'));
        controller.enqueue(encoder.encode('event: error\ndata: {"type":"error","error":{"message":"upstream stream failed","type":"upstream_error"}}\n\n'));
        controller.enqueue(encoder.encode('data: [DONE]\n\n'));
        controller.close();
      },
    });

    fetchMock.mockResolvedValue(new Response(upstreamBody, {
      status: 200,
      headers: { 'content-type': 'text/event-stream; charset=utf-8' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/responses',
      payload: {
        model: 'gpt-5.2',
        input: 'hello',
        stream: true,
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.body).toContain('response.failed');
    expect(response.body).toContain('"status":"failed"');
    expect(response.body).not.toContain('response.completed');
    expect(response.body).toContain('[DONE]');
  });

  it('preserves Responses-specific payload fields and forwards openai headers on /v1/responses', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      id: 'resp_passthrough',
      object: 'response',
      status: 'completed',
      model: 'upstream-gpt',
      output_text: 'ok',
      output: [],
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/responses',
      headers: {
        'openai-beta': 'responses-2025-03-11',
        'x-stainless-lang': 'typescript',
        originator: 'codex_cli_rs',
      },
      payload: {
        model: 'gpt-5.2',
        input: 'hello',
        metadata: { session_id: 'abc123' },
        reasoning: { effort: 'high' },
      },
    });

    expect(response.statusCode).toBe(200);

    const [_targetUrl, options] = fetchMock.mock.calls[0] as [string, any];
    expect(options.headers['openai-beta']).toBe('responses-2025-03-11');
    expect(options.headers['x-stainless-lang']).toBe('typescript');
    expect(options.headers.originator).toBe('codex_cli_rs');

    const forwardedBody = JSON.parse(options.body);
    expect(forwardedBody.metadata).toEqual({ session_id: 'abc123' });
    expect(forwardedBody.reasoning).toEqual({ effort: 'high' });
    expect(forwardedBody.include).toEqual(['reasoning.encrypted_content']);
  });

  it('retries /v1/responses without metadata when upstream returns empty upstream_error', async () => {
    fetchMock
      .mockResolvedValueOnce(new Response(JSON.stringify({
        error: {
          message: '',
          type: 'upstream_error',
        },
      }), {
        status: 400,
        headers: { 'content-type': 'application/json' },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        id: 'resp_retry_without_metadata',
        object: 'response',
        status: 'completed',
        model: 'upstream-gpt',
        output_text: 'ok after stripping metadata',
        output: [],
      }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/responses',
      payload: {
        model: 'gpt-5.2',
        input: 'hello',
        metadata: { trace_id: 'req-1' },
      },
    });

    expect(response.statusCode).toBe(200);
    const body = response.json();
    expect(body.output_text).toContain('ok after stripping metadata');

    expect(fetchMock).toHaveBeenCalledTimes(2);
    const [firstUrl, firstOptions] = fetchMock.mock.calls[0] as [string, any];
    const [secondUrl, secondOptions] = fetchMock.mock.calls[1] as [string, any];
    expect(firstUrl).toContain('/v1/responses');
    expect(secondUrl).toContain('/v1/responses');

    const firstBody = JSON.parse(firstOptions.body);
    const secondBody = JSON.parse(secondOptions.body);
    expect(firstBody.metadata).toEqual({ trace_id: 'req-1' });
    expect(secondBody.metadata).toBeUndefined();
  });

  it('retries /v1/responses with core body when upstream returns empty upstream_error', async () => {
    fetchMock
      .mockResolvedValueOnce(new Response(JSON.stringify({
        error: {
          message: '',
          type: 'upstream_error',
        },
      }), {
        status: 400,
        headers: { 'content-type': 'application/json' },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        id: 'resp_retry_core_body',
        object: 'response',
        status: 'completed',
        model: 'upstream-gpt',
        output_text: 'ok after core retry',
        output: [],
      }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/responses',
      payload: {
        model: 'gpt-5.2',
        input: 'hello',
        store: true,
      },
    });

    expect(response.statusCode).toBe(200);
    const body = response.json();
    expect(body.output_text).toContain('ok after core retry');

    expect(fetchMock).toHaveBeenCalledTimes(2);
    const [_firstUrl, firstOptions] = fetchMock.mock.calls[0] as [string, any];
    const [_secondUrl, secondOptions] = fetchMock.mock.calls[1] as [string, any];
    const firstBody = JSON.parse(firstOptions.body);
    const secondBody = JSON.parse(secondOptions.body);
    expect(firstBody.store).toBe(true);
    expect(secondBody.store).toBeUndefined();
    expect(secondBody.input).toEqual([
      {
        type: 'message',
        role: 'user',
        content: [{ type: 'input_text', text: 'hello' }],
      },
    ]);
  });

  it('retries /v1/responses when upstream_error message is literal upstream_error and falls back to strict body', async () => {
    fetchMock
      .mockResolvedValueOnce(new Response(JSON.stringify({
        error: {
          message: 'upstream_error',
          type: 'upstream_error',
        },
      }), {
        status: 400,
        headers: { 'content-type': 'application/json' },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        error: {
          message: 'upstream_error',
          type: 'upstream_error',
        },
      }), {
        status: 400,
        headers: { 'content-type': 'application/json' },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        id: 'resp_retry_strict_body',
        object: 'response',
        status: 'completed',
        model: 'upstream-gpt',
        output_text: 'ok after strict retry',
        output: [],
      }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/responses',
      payload: {
        model: 'gpt-5.2',
        input: 'hello',
        temperature: 0.7,
      },
    });

    expect(response.statusCode).toBe(200);
    const body = response.json();
    expect(body.output_text).toContain('ok after strict retry');

    expect(fetchMock).toHaveBeenCalledTimes(3);
    const [, firstOptions] = fetchMock.mock.calls[0] as [string, any];
    const [, secondOptions] = fetchMock.mock.calls[1] as [string, any];
    const [, thirdOptions] = fetchMock.mock.calls[2] as [string, any];
    const firstBody = JSON.parse(firstOptions.body);
    const secondBody = JSON.parse(secondOptions.body);
    const thirdBody = JSON.parse(thirdOptions.body);
    expect(firstBody.temperature).toBe(0.7);
    expect(secondBody.temperature).toBe(0.7);
    expect(thirdBody.temperature).toBeUndefined();
    expect(thirdBody).toEqual({
      model: 'upstream-gpt',
      input: [
        {
          type: 'message',
          role: 'user',
          content: [{ type: 'input_text', text: 'hello' }],
        },
      ],
      stream: false,
    });
  });

  it('retries generic 400 /v1/responses with minimal headers for strict compatibility fallback', async () => {
    fetchMock
      .mockResolvedValueOnce(new Response(JSON.stringify({
        error: {
          message: 'request validation failed',
          type: 'invalid_request_error',
        },
      }), {
        status: 400,
        headers: { 'content-type': 'application/json' },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        error: {
          message: 'request validation failed',
          type: 'invalid_request_error',
        },
      }), {
        status: 400,
        headers: { 'content-type': 'application/json' },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        error: {
          message: 'request validation failed',
          type: 'invalid_request_error',
        },
      }), {
        status: 400,
        headers: { 'content-type': 'application/json' },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        id: 'resp_retry_minimal_headers',
        object: 'response',
        status: 'completed',
        model: 'upstream-gpt',
        output_text: 'ok after minimal headers retry',
        output: [],
      }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/responses',
      headers: {
        'openai-beta': 'responses-2025-03-11',
      },
      payload: {
        model: 'gpt-5.2',
        input: 'hello',
        user: 'user-123',
      },
    });

    expect(response.statusCode).toBe(200);
    const body = response.json();
    expect(body.output_text).toContain('ok after minimal headers retry');

    expect(fetchMock).toHaveBeenCalledTimes(4);
    const [, firstOptions] = fetchMock.mock.calls[0] as [string, any];
    const [, secondOptions] = fetchMock.mock.calls[1] as [string, any];
    const [, thirdOptions] = fetchMock.mock.calls[2] as [string, any];
    const [, fourthOptions] = fetchMock.mock.calls[3] as [string, any];

    expect(firstOptions.headers['openai-beta']).toBe('responses-2025-03-11');
    expect(secondOptions.headers['openai-beta']).toBe('responses-2025-03-11');
    expect(thirdOptions.headers['openai-beta']).toBe('responses-2025-03-11');
    expect(fourthOptions.headers['openai-beta']).toBeUndefined();

    const firstBody = JSON.parse(firstOptions.body);
    const secondBody = JSON.parse(secondOptions.body);
    const thirdBody = JSON.parse(thirdOptions.body);
    const fourthBody = JSON.parse(fourthOptions.body);
    expect(firstBody.user).toBe('user-123');
    expect(secondBody.user).toBeUndefined();
    expect(thirdBody.user).toBeUndefined();
    expect(secondBody.include).toEqual(['reasoning.encrypted_content']);
    expect(thirdBody.include).toBeUndefined();
    expect(fourthBody.user).toBeUndefined();
  });

  it('returns concise Cloudflare host error on /v1/responses 502 html failures', async () => {
    const html = '<!DOCTYPE html><html><head><title>qaq.al | 502: Bad gateway</title></head><body>Cloudflare Ray ID: 9d6f7c889ffbc8eb</body></html>';
    fetchMock.mockImplementation(() => Promise.resolve(new Response(html, {
      status: 502,
      headers: { 'content-type': 'text/html; charset=UTF-8' },
    })));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/responses',
      payload: {
        model: 'gpt-5.2',
        input: 'hello',
      },
    });

    expect(response.statusCode).toBe(502);
    const body = response.json();
    expect(body.error?.type).toBe('upstream_error');
    expect(body.error?.message).toContain('[upstream:');
    expect(body.error?.message).toContain('Cloudflare 502: Bad gateway');
    expect(body.error?.message).not.toContain('<!DOCTYPE html>');
  });

  it('downgrades /v1/responses to /v1/chat/completions when upstream returns 400 upstream_error', async () => {
    fetchMock
      .mockResolvedValueOnce(new Response(JSON.stringify({
        error: {
          message: '',
          type: 'upstream_error',
        },
      }), {
        status: 400,
        headers: { 'content-type': 'application/json' },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        id: 'chatcmpl-fallback-upstream-error',
        object: 'chat.completion',
        model: 'upstream-gpt',
        choices: [{
          index: 0,
          message: { role: 'assistant', content: 'ok via chat fallback from upstream_error' },
          finish_reason: 'stop',
        }],
        usage: { prompt_tokens: 4, completion_tokens: 2, total_tokens: 6 },
      }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/responses',
      payload: {
        model: 'gpt-5.2',
        input: 'hello',
      },
    });

    expect(response.statusCode).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    const [firstUrl] = fetchMock.mock.calls[0] as [string, any];
    const [secondUrl] = fetchMock.mock.calls[1] as [string, any];
    expect(firstUrl).toContain('/v1/responses');
    expect(secondUrl).toContain('/v1/chat/completions');

    const body = response.json();
    expect(body.object).toBe('response');
    expect(body.output_text).toContain('ok via chat fallback from upstream_error');
  });

  it('downgrades /v1/responses to /v1/chat/completions when upstream responses endpoint returns 502', async () => {
    fetchMock
      .mockResolvedValueOnce(new Response(
        '<!DOCTYPE html><html><head><title>qaq.al | 502: Bad gateway</title></head><body>Cloudflare</body></html>',
        {
          status: 502,
          headers: { 'content-type': 'text/html; charset=UTF-8' },
        },
      ))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        id: 'chatcmpl-fallback-502',
        object: 'chat.completion',
        model: 'upstream-gpt',
        choices: [{
          index: 0,
          message: { role: 'assistant', content: 'ok via chat fallback' },
          finish_reason: 'stop',
        }],
        usage: { prompt_tokens: 3, completion_tokens: 2, total_tokens: 5 },
      }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/responses',
      payload: {
        model: 'gpt-5.2',
        input: 'hello',
      },
    });

    expect(response.statusCode).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    const [firstUrl] = fetchMock.mock.calls[0] as [string, any];
    const [secondUrl] = fetchMock.mock.calls[1] as [string, any];
    expect(firstUrl).toContain('/v1/responses');
    expect(secondUrl).toContain('/v1/chat/completions');
    const body = response.json();
    expect(body.object).toBe('response');
    expect(body.output_text).toContain('ok via chat fallback');
  });

  it('retries /v1/chat/completions with minimal JSON headers on unsupported media type', async () => {
    fetchMock
      .mockResolvedValueOnce(new Response(JSON.stringify({
        error: {
          message: "Unsupported Media Type: Only 'application/json' is allowed",
          type: 'invalid_request_error',
        },
      }), {
        status: 415,
        headers: { 'content-type': 'application/json' },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        id: 'chatcmpl-media-type-retry',
        object: 'chat.completion',
        created: 1_706_123_456,
        model: 'upstream-gpt',
        choices: [{
          index: 0,
          message: { role: 'assistant', content: 'ok after header retry' },
          finish_reason: 'stop',
        }],
        usage: { prompt_tokens: 7, completion_tokens: 3, total_tokens: 10 },
      }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      headers: {
        'openai-beta': 'responses-2025-03-11',
      },
      payload: {
        model: 'gpt-5.2',
        messages: [{ role: 'user', content: 'hello' }],
      },
    });

    expect(response.statusCode).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    const [firstUrl, firstOptions] = fetchMock.mock.calls[0] as [string, any];
    const [secondUrl, secondOptions] = fetchMock.mock.calls[1] as [string, any];
    expect(firstUrl).toContain('/v1/chat/completions');
    expect(secondUrl).toContain('/v1/chat/completions');
    expect(firstOptions.headers['openai-beta']).toBe('responses-2025-03-11');
    expect(secondOptions.headers['openai-beta']).toBeUndefined();
    expect(secondOptions.headers['content-type']).toBe('application/json');
    expect(secondOptions.headers.accept).toBe('application/json');
  });

  it('sets stream accept header for /v1/responses when downstream omits accept', async () => {
    const encoder = new TextEncoder();
    const upstreamBody = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode('event: response.completed\ndata: {"type":"response.completed","response":{"id":"resp_accept","model":"upstream-gpt","status":"completed","usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}\n\n'));
        controller.enqueue(encoder.encode('data: [DONE]\n\n'));
        controller.close();
      },
    });

    fetchMock.mockResolvedValue(new Response(upstreamBody, {
      status: 200,
      headers: { 'content-type': 'text/event-stream; charset=utf-8' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/responses',
      payload: {
        model: 'gpt-5.2',
        input: 'hello',
        stream: true,
      },
    });

    expect(response.statusCode).toBe(200);

    const [_targetUrl, options] = fetchMock.mock.calls[0] as [string, any];
    expect(options.headers.accept).toBe('text/event-stream');
  });

  it('deduplicates cumulative text chunks when /v1/responses is converted from /v1/messages stream', async () => {
    fetchModelPricingCatalogMock.mockResolvedValue({
      models: [
        {
          modelName: 'upstream-gpt',
          supportedEndpointTypes: ['/v1/messages'],
        },
      ],
      groupRatio: {},
    });

    const fullText = "I'm Claude, an AI assistant made by Anthropic.";
    const encoder = new TextEncoder();
    const upstreamBody = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode('event: message_start\ndata: {"type":"message_start","message":{"id":"msg_dup_1","model":"upstream-gpt"}}\n\n'));
        controller.enqueue(encoder.encode(`event: content_block_delta\ndata: {"type":"content_block_delta","delta":{"type":"text_delta","text":${JSON.stringify(fullText)}}}\n\n`));
        controller.enqueue(encoder.encode(`event: content_block_delta\ndata: {"type":"content_block_delta","delta":{"type":"text_delta","text":${JSON.stringify(fullText)}}}\n\n`));
        controller.enqueue(encoder.encode(`event: content_block_delta\ndata: {"type":"content_block_delta","delta":{"type":"text_delta","text":${JSON.stringify(fullText)}}}\n\n`));
        controller.enqueue(encoder.encode('event: message_stop\ndata: {"type":"message_stop"}\n\n'));
        controller.enqueue(encoder.encode('data: [DONE]\n\n'));
        controller.close();
      },
    });

    fetchMock.mockResolvedValue(new Response(upstreamBody, {
      status: 200,
      headers: { 'content-type': 'text/event-stream; charset=utf-8' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/responses',
      payload: {
        model: 'claude-sonnet-4-6',
        stream: true,
        input: 'whoru',
      },
    });

    expect(response.statusCode).toBe(200);
    const deltaMatches = response.body.match(/event: response\.output_text\.delta/g) || [];
    expect(deltaMatches.length).toBe(1);
    const textMatches = response.body.match(/I'm Claude, an AI assistant made by Anthropic\./g) || [];
    expect(textMatches.length).toBeGreaterThan(0);
    expect(textMatches.length).toBeLessThanOrEqual(6);
  });

  it('deduplicates overlapping text windows when /v1/responses is converted from /v1/messages stream', async () => {
    fetchModelPricingCatalogMock.mockResolvedValue({
      models: [
        {
          modelName: 'upstream-gpt',
          supportedEndpointTypes: ['/v1/messages'],
        },
      ],
      groupRatio: {},
    });

    const encoder = new TextEncoder();
    const upstreamBody = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode('event: message_start\ndata: {"type":"message_start","message":{"id":"msg_overlap_1","model":"upstream-gpt"}}\n\n'));
        controller.enqueue(encoder.encode('event: content_block_delta\ndata: {"type":"content_block_delta","delta":{"type":"text_delta","text":"The user asked \\"whoru\\" which is a common"}}\n\n'));
        controller.enqueue(encoder.encode('event: content_block_delta\ndata: {"type":"content_block_delta","delta":{"type":"text_delta","text":"which is a common internet slang"}}\n\n'));
        controller.enqueue(encoder.encode('event: content_block_delta\ndata: {"type":"content_block_delta","delta":{"type":"text_delta","text":" internet slang and shorthand for who are you."}}\n\n'));
        controller.enqueue(encoder.encode('event: message_stop\ndata: {"type":"message_stop"}\n\n'));
        controller.enqueue(encoder.encode('data: [DONE]\n\n'));
        controller.close();
      },
    });

    fetchMock.mockResolvedValue(new Response(upstreamBody, {
      status: 200,
      headers: { 'content-type': 'text/event-stream; charset=utf-8' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/responses',
      payload: {
        model: 'claude-sonnet-4-6',
        stream: true,
        input: 'whoru',
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.body).toContain('"delta":" internet slang"');
    expect(response.body).not.toContain('"delta":"which is a common internet slang"');
    expect(response.body).toContain('"text":"The user asked \\"whoru\\" which is a common internet slang and shorthand for who are you."');
  });

  it('preserves function_call/function_call_output when /v1/responses falls back to /v1/chat/completions', async () => {
    fetchModelPricingCatalogMock.mockResolvedValue({
      models: [
        {
          modelName: 'upstream-gpt',
          supportedEndpointTypes: ['/v1/chat/completions'],
        },
      ],
      groupRatio: {},
    });

    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      id: 'chatcmpl_responses_fallback_chat',
      object: 'chat.completion',
      created: 1_706_000_111,
      model: 'upstream-gpt',
      choices: [{
        index: 0,
        message: { role: 'assistant', content: 'ok' },
        finish_reason: 'stop',
      }],
      usage: { prompt_tokens: 9, completion_tokens: 3, total_tokens: 12 },
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/responses',
      payload: {
        model: 'gpt-5.2',
        input: [
          {
            type: 'message',
            role: 'user',
            content: [{ type: 'input_text', text: 'find readme' }],
          },
          {
            type: 'function_call',
            call_id: 'call_abc',
            name: 'Glob',
            arguments: '{"pattern":"README*"}',
          },
          {
            type: 'function_call_output',
            call_id: 'call_abc',
            output: '{"matches":1}',
          },
        ],
        tools: [{
          type: 'function',
          name: 'Glob',
          description: 'Search files',
          parameters: {
            type: 'object',
            properties: { pattern: { type: 'string' } },
            required: ['pattern'],
          },
          strict: true,
        }],
        tool_choice: {
          type: 'function',
          name: 'Glob',
        },
      },
    });

    expect(response.statusCode).toBe(200);

    const [targetUrl, options] = fetchMock.mock.calls[0] as [string, any];
    expect(targetUrl).toContain('/v1/chat/completions');

    const forwarded = JSON.parse(options.body);
    expect(Array.isArray(forwarded.messages)).toBe(true);

    const assistantWithToolCall = forwarded.messages.find((item: any) =>
      item?.role === 'assistant'
      && Array.isArray(item?.tool_calls)
      && item.tool_calls.length > 0,
    );
    expect(assistantWithToolCall).toBeTruthy();
    expect(assistantWithToolCall.tool_calls[0].id).toBe('call_abc');
    expect(assistantWithToolCall.tool_calls[0].function?.name).toBe('Glob');
    expect(assistantWithToolCall.tool_calls[0].function?.arguments).toContain('README*');

    const toolMessage = forwarded.messages.find((item: any) => item?.role === 'tool');
    expect(toolMessage).toBeTruthy();
    expect(toolMessage.tool_call_id).toBe('call_abc');
    expect(toolMessage.content).toContain('matches');

    expect(forwarded.tools?.[0]?.function?.name).toBe('Glob');
    expect(forwarded.tool_choice?.function?.name).toBe('Glob');
  });


  it('preserves function_call/function_call_output when /v1/responses falls back to /v1/messages', async () => {
    fetchModelPricingCatalogMock.mockResolvedValue({
      models: [
        {
          modelName: 'upstream-gpt',
          supportedEndpointTypes: ['anthropic'],
        },
      ],
      groupRatio: {},
    });

    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      id: 'msg_responses_fallback_messages',
      type: 'message',
      model: 'upstream-gpt',
      content: [{ type: 'text', text: 'ok' }],
      stop_reason: 'end_turn',
      usage: { input_tokens: 8, output_tokens: 2, total_tokens: 10 },
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/responses',
      payload: {
        model: 'gpt-5.2',
        input: [
          {
            type: 'message',
            role: 'user',
            content: [{ type: 'input_text', text: 'find readme' }],
          },
          {
            type: 'function_call',
            call_id: 'call_abc',
            name: 'Glob',
            arguments: '{"pattern":"README*"}',
          },
          {
            type: 'function_call_output',
            call_id: 'call_abc',
            output: '{"matches":1}',
          },
        ],
      },
    });

    expect(response.statusCode).toBe(200);

    const [targetUrl, options] = fetchMock.mock.calls[0] as [string, any];
    expect(targetUrl).toContain('/v1/messages');

    const forwarded = JSON.parse(options.body);
    expect(Array.isArray(forwarded.messages)).toBe(true);

    const assistantMessage = forwarded.messages.find((item: any) => item?.role === 'assistant');
    expect(Array.isArray(assistantMessage?.content)).toBe(true);
    expect(assistantMessage.content.some((part: any) => part?.type === 'tool_use')).toBe(true);

    const userToolResultMessage = forwarded.messages.find((item: any) =>
      item?.role === 'user'
      && Array.isArray(item?.content)
      && item.content.some((part: any) => part?.type === 'tool_result'),
    );
    expect(userToolResultMessage).toBeTruthy();
    expect(userToolResultMessage.content[0].tool_use_id).toBe('call_abc');
  });

  it('routes /v1/responses to /v1/messages when upstream catalog is anthropic-only', async () => {
    fetchModelPricingCatalogMock.mockResolvedValue({
      models: [
        {
          modelName: 'upstream-gpt',
          supportedEndpointTypes: ['anthropic'],
        },
      ],
      groupRatio: {},
    });

    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      id: 'msg_900',
      type: 'message',
      model: 'upstream-gpt',
      content: [{ type: 'text', text: 'hello from anthropic messages upstream' }],
      stop_reason: 'end_turn',
      usage: { input_tokens: 7, output_tokens: 3, total_tokens: 10 },
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/responses',
      payload: {
        model: 'claude-haiku-4-5-20251001',
        input: 'hello',
      },
    });

    expect(response.statusCode).toBe(200);
    const body = response.json();
    expect(body.object).toBe('response');
    expect(body.output_text).toContain('hello from anthropic messages upstream');

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [targetUrl] = fetchMock.mock.calls[0] as [string, any];
    expect(targetUrl).toContain('/v1/messages');
  });

  it('does not stick generic /v1/responses traffic to /v1/messages after a fallback success', async () => {
    selectChannelMock.mockReturnValue({
      channel: { id: 11, routeId: 22 },
      site: { name: 'generic-site', url: 'https://upstream.example.com', platform: 'new-api' },
      account: { id: 33, username: 'demo-user' },
      tokenName: 'default',
      tokenValue: 'sk-demo',
      actualModel: 'upstream-gpt',
    });

    fetchMock
      .mockResolvedValueOnce(new Response(JSON.stringify({
        error: { message: 'Gateway time-out', type: 'upstream_error' },
      }), {
        status: 504,
        headers: { 'content-type': 'application/json' },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        error: { message: 'Bad gateway', type: 'upstream_error' },
      }), {
        status: 502,
        headers: { 'content-type': 'application/json' },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        id: 'msg_fallback_1',
        type: 'message',
        model: 'upstream-gpt',
        content: [{ type: 'text', text: 'ok via messages fallback' }],
        stop_reason: 'end_turn',
        usage: { input_tokens: 7, output_tokens: 3, total_tokens: 10 },
      }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        id: 'resp_recovered_1',
        object: 'response',
        model: 'upstream-gpt',
        status: 'completed',
        output_text: 'ok via recovered responses',
        usage: { input_tokens: 6, output_tokens: 2, total_tokens: 8 },
      }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }));

    const firstResponse = await app.inject({
      method: 'POST',
      url: '/v1/responses',
      payload: {
        model: 'gpt-5.4',
        input: 'hello',
      },
    });

    expect(firstResponse.statusCode).toBe(200);
    expect(firstResponse.json().output_text).toContain('ok via messages fallback');

    const secondResponse = await app.inject({
      method: 'POST',
      url: '/v1/responses',
      payload: {
        model: 'gpt-5.4',
        input: 'hello again',
      },
    });

    expect(secondResponse.statusCode).toBe(200);
    expect(secondResponse.json().output_text).toContain('ok via recovered responses');
    expect(fetchMock).toHaveBeenCalledTimes(4);

    const [firstUrl] = fetchMock.mock.calls[0] as [string, any];
    const [secondUrl] = fetchMock.mock.calls[1] as [string, any];
    const [thirdUrl] = fetchMock.mock.calls[2] as [string, any];
    const [fourthUrl] = fetchMock.mock.calls[3] as [string, any];
    expect(firstUrl).toContain('/v1/responses');
    expect(secondUrl).toContain('/v1/chat/completions');
    expect(thirdUrl).toContain('/v1/messages');
    expect(fourthUrl).toContain('/v1/responses');
  });

  it('prefers native /v1/responses for claude-family /v1/responses requests that explicitly ask for encrypted reasoning', async () => {
    selectChannelMock.mockReturnValue({
      channel: { id: 11, routeId: 22 },
      site: { name: 'generic-site', url: 'https://upstream.example.com', platform: 'new-api' },
      account: { id: 33, username: 'demo-user' },
      tokenName: 'default',
      tokenValue: 'sk-demo',
      actualModel: 'upstream-gpt',
    });

    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      id: 'resp_reasoning_1',
      object: 'response',
      model: 'upstream-gpt',
      output_text: 'hello from responses upstream',
      output: [
        {
          id: 'msg_reasoning_1',
          type: 'message',
          role: 'assistant',
          status: 'completed',
          content: [{ type: 'output_text', text: 'hello from responses upstream' }],
        },
      ],
      status: 'completed',
      usage: { input_tokens: 7, output_tokens: 3, total_tokens: 10 },
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/responses',
      payload: {
        model: 'claude-haiku-4-5-20251001',
        input: 'hello',
        include: ['reasoning.encrypted_content'],
      },
    });

    expect(response.statusCode).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [targetUrl] = fetchMock.mock.calls[0] as [string, any];
    expect(targetUrl).toContain('/v1/responses');
  });

  it('returns upstream_error for empty non-stream /v1/responses payloads when empty-content failure is enabled', async () => {
    config.proxyEmptyContentFailEnabled = true;

    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      id: 'resp-empty',
      object: 'response',
      model: 'gpt-5.4',
      status: 'completed',
      output: [],
      output_text: '',
      usage: { input_tokens: 3, output_tokens: 0, total_tokens: 3 },
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/responses',
      payload: {
        model: 'gpt-5.4',
        input: 'hello',
      },
    });

    expect(response.statusCode).toBe(502);
    expect(response.json()?.error?.type).toBe('upstream_error');
    expect(response.json()?.error?.message).toContain('empty content');
    expect(recordSuccessMock).not.toHaveBeenCalled();
    expect(recordFailureMock).toHaveBeenCalledTimes(1);
  });

  it('returns HTTP upstream_error instead of hijacking when streamed /v1/responses receives empty non-SSE payloads', async () => {
    config.proxyEmptyContentFailEnabled = true;

    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      id: 'resp-empty-stream',
      object: 'response',
      model: 'gpt-5.4',
      status: 'completed',
      output: [],
      output_text: '',
      usage: { input_tokens: 2, output_tokens: 0, total_tokens: 2 },
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/responses',
      payload: {
        model: 'gpt-5.4',
        input: 'hello',
        stream: true,
      },
    });

    expect(response.statusCode).toBe(502);
    expect(response.headers['content-type']).not.toContain('text/event-stream');
    expect(response.json()?.error?.type).toBe('upstream_error');
    expect(recordSuccessMock).not.toHaveBeenCalled();
    expect(recordFailureMock).toHaveBeenCalledTimes(1);
  });

  it('prefers native /v1/responses for claude-family /v1/responses requests that include input_file file_url', async () => {
    selectChannelMock.mockReturnValue({
      channel: { id: 11, routeId: 22 },
      site: { name: 'generic-site', url: 'https://upstream.example.com', platform: 'new-api' },
      account: { id: 33, username: 'demo-user' },
      tokenName: 'default',
      tokenValue: 'sk-demo',
      actualModel: 'upstream-gpt',
    });

    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      id: 'resp_file_url_1',
      object: 'response',
      model: 'upstream-gpt',
      output_text: 'hello from responses upstream',
      output: [
        {
          id: 'msg_file_url_1',
          type: 'message',
          role: 'assistant',
          status: 'completed',
          content: [{ type: 'output_text', text: 'hello from responses upstream' }],
        },
      ],
      status: 'completed',
      usage: { input_tokens: 7, output_tokens: 3, total_tokens: 10 },
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/responses',
      payload: {
        model: 'claude-haiku-4-5-20251001',
        input: [
          {
            type: 'message',
            role: 'user',
            content: [
              { type: 'input_text', text: 'read this remote file' },
              {
                type: 'input_file',
                filename: 'remote.pdf',
                file_url: 'https://example.com/remote.pdf',
              },
            ],
          },
        ],
      },
    });

    expect(response.statusCode).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [targetUrl, options] = fetchMock.mock.calls[0] as [string, any];
    expect(targetUrl).toContain('/v1/responses');
    const forwardedBody = JSON.parse(options.body);
    expect(forwardedBody.input[0].content[1]).toEqual({
      type: 'input_file',
      filename: 'remote.pdf',
      file_url: 'https://example.com/remote.pdf',
    });
  });

  it('converts input_file file_url into Claude document url blocks for claude-only upstreams', async () => {
    selectChannelMock.mockReturnValue({
      channel: { id: 11, routeId: 22 },
      site: { name: 'claude-site', url: 'https://upstream.example.com', platform: 'claude' },
      account: { id: 33, username: 'demo-user' },
      tokenName: 'default',
      tokenValue: 'sk-demo',
      actualModel: 'upstream-claude',
    });
    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      id: 'msg_file_url_1',
      type: 'message',
      role: 'assistant',
      model: 'upstream-claude',
      content: [{ type: 'text', text: 'hello from claude messages' }],
      stop_reason: 'end_turn',
      usage: { input_tokens: 7, output_tokens: 3 },
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/responses',
      payload: {
        model: 'claude-haiku-4-5-20251001',
        input: [
          {
            type: 'message',
            role: 'user',
            content: [
              { type: 'input_text', text: 'read this remote file' },
              {
                type: 'input_file',
                filename: 'remote.pdf',
                file_url: 'https://example.com/remote.pdf',
              },
            ],
          },
        ],
      },
    });

    expect(response.statusCode).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [targetUrl, options] = fetchMock.mock.calls[0] as [string, any];
    expect(targetUrl).toContain('/v1/messages');
    const forwardedBody = JSON.parse(options.body);
    expect(forwardedBody.messages[0].content[1]).toMatchObject({
      type: 'document',
      title: 'remote.pdf',
      source: {
        type: 'url',
        url: 'https://example.com/remote.pdf',
      },
    });
  });

  it('does not let remote document url success poison later inline document endpoint preference', async () => {
    selectChannelMock.mockReturnValue({
      channel: { id: 11, routeId: 22 },
      site: { name: 'generic-site', url: 'https://upstream.example.com', platform: 'new-api' },
      account: { id: 33, username: 'demo-user' },
      tokenName: 'default',
      tokenValue: 'sk-demo',
      actualModel: 'upstream-gpt',
    });
    fetchMock.mockImplementation(async (target: unknown) => {
      const url = String(target);
      if (url.includes('/v1/responses')) {
        return new Response(JSON.stringify({
          id: 'resp_file_url_runtime_1',
          object: 'response',
          model: 'upstream-gpt',
          output_text: 'hello from responses upstream',
          output: [
            {
              id: 'msg_file_url_runtime_1',
              type: 'message',
              role: 'assistant',
              content: [{ type: 'output_text', text: 'hello from responses upstream' }],
            },
          ],
          status: 'completed',
          usage: { input_tokens: 7, output_tokens: 3, total_tokens: 10 },
        }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }
      if (url.includes('/v1/messages')) {
        return new Response(JSON.stringify({
          id: 'msg_inline_runtime_1',
          type: 'message',
          role: 'assistant',
          model: 'upstream-gpt',
          content: [{ type: 'text', text: 'hello from messages upstream' }],
          stop_reason: 'end_turn',
          usage: { input_tokens: 7, output_tokens: 3 },
        }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }
      throw new Error(`unexpected target url: ${url}`);
    });

    const remoteResponse = await app.inject({
      method: 'POST',
      url: '/v1/responses',
      payload: {
        model: 'claude-haiku-4-5-20251001',
        input: [
          {
            type: 'message',
            role: 'user',
            content: [
              { type: 'input_text', text: 'read this remote file' },
              {
                type: 'input_file',
                filename: 'remote.pdf',
                file_url: 'https://example.com/remote.pdf',
              },
            ],
          },
        ],
      },
    });

    expect(remoteResponse.statusCode).toBe(200);
    expect(String(fetchMock.mock.calls[0]?.[0])).toContain('/v1/responses');

    const inlineResponse = await app.inject({
      method: 'POST',
      url: '/v1/responses',
      payload: {
        model: 'claude-haiku-4-5-20251001',
        input: [
          {
            type: 'message',
            role: 'user',
            content: [
              { type: 'input_text', text: 'read this inline file' },
              {
                type: 'input_file',
                filename: 'brief.pdf',
                file_data: 'data:application/pdf;base64,JVBERi0xLjQK',
              },
            ],
          },
        ],
      },
    });

    expect(inlineResponse.statusCode).toBe(200);
    expect(String(fetchMock.mock.calls[1]?.[0])).toContain('/v1/messages');
  });

  it('prefers native /v1/responses for claude-family /v1/responses requests that opt into reasoning without injecting a generic default include', async () => {
    selectChannelMock.mockReturnValue({
      channel: { id: 11, routeId: 22 },
      site: { name: 'generic-site', url: 'https://upstream.example.com', platform: 'new-api' },
      account: { id: 33, username: 'demo-user' },
      tokenName: 'default',
      tokenValue: 'sk-demo',
      actualModel: 'upstream-gpt',
    });

    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      id: 'resp_reasoning_2',
      object: 'response',
      model: 'upstream-gpt',
      output_text: 'hello from responses upstream',
      output: [
        {
          id: 'msg_reasoning_2',
          type: 'message',
          role: 'assistant',
          status: 'completed',
          content: [{ type: 'output_text', text: 'hello from responses upstream' }],
        },
      ],
      status: 'completed',
      usage: { input_tokens: 7, output_tokens: 3, total_tokens: 10 },
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/responses',
      payload: {
        model: 'claude-haiku-4-5-20251001',
        input: 'hello',
        reasoning: {
          effort: 'high',
          summary: 'auto',
        },
      },
    });

    expect(response.statusCode).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [targetUrl, options] = fetchMock.mock.calls[0] as [string, any];
    expect(targetUrl).toContain('/v1/responses');
    const forwardedBody = JSON.parse(options.body);
    expect(forwardedBody.include).toBeUndefined();
  });

  it('keeps generic claude-family /v1/responses requests on the default messages-first order when codex headers are absent', async () => {
    selectChannelMock.mockReturnValue({
      channel: { id: 11, routeId: 22 },
      site: { name: 'generic-site', url: 'https://upstream.example.com', platform: 'new-api' },
      account: { id: 33, username: 'demo-user' },
      tokenName: 'default',
      tokenValue: 'sk-demo',
      actualModel: 'upstream-gpt',
    });

    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      id: 'msg_default_messages_first',
      type: 'message',
      model: 'upstream-gpt',
      content: [{ type: 'text', text: 'messages endpoint selected by default' }],
      stop_reason: 'end_turn',
      usage: { input_tokens: 7, output_tokens: 3, total_tokens: 10 },
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/responses',
      payload: {
        model: 'claude-haiku-4-5-20251001',
        input: 'hello',
      },
    });

    expect(response.statusCode).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [targetUrl] = fetchMock.mock.calls[0] as [string, any];
    expect(targetUrl).toContain('/v1/messages');
  });

  it('defaults encrypted reasoning include and prefers native /v1/responses for claude-family codex-surface requests even without reasoning config', async () => {
    selectChannelMock.mockReturnValue({
      channel: { id: 11, routeId: 22 },
      site: { name: 'generic-site', url: 'https://upstream.example.com', platform: 'new-api' },
      account: { id: 33, username: 'demo-user' },
      tokenName: 'default',
      tokenValue: 'sk-demo',
      actualModel: 'upstream-gpt',
    });

    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      id: 'resp_reasoning_default',
      object: 'response',
      model: 'upstream-gpt',
      output_text: 'hello from responses upstream',
      output: [
        {
          id: 'msg_reasoning_default',
          type: 'message',
          role: 'assistant',
          status: 'completed',
          content: [{ type: 'output_text', text: 'hello from responses upstream' }],
        },
      ],
      status: 'completed',
      usage: { input_tokens: 7, output_tokens: 3, total_tokens: 10 },
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/responses',
      headers: {
        'openai-beta': 'responses-2025-03-11',
        'x-stainless-lang': 'typescript',
        originator: 'codex_cli_rs',
      },
      payload: {
        model: 'claude-haiku-4-5-20251001',
        input: 'hello',
      },
    });

    expect(response.statusCode).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [targetUrl, options] = fetchMock.mock.calls[0] as [string, any];
    expect(targetUrl).toContain('/v1/responses');
    const forwardedBody = JSON.parse(options.body);
    expect(forwardedBody.include).toEqual(['reasoning.encrypted_content']);
  });

  it('keeps explicit empty include on claude-family codex-surface responses requests and stays on the default messages-first order', async () => {
    selectChannelMock.mockReturnValue({
      channel: { id: 11, routeId: 22 },
      site: { name: 'generic-site', url: 'https://upstream.example.com', platform: 'new-api' },
      account: { id: 33, username: 'demo-user' },
      tokenName: 'default',
      tokenValue: 'sk-demo',
      actualModel: 'upstream-gpt',
    });

    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      id: 'msg_explicit_empty_include',
      type: 'message',
      model: 'upstream-gpt',
      content: [{ type: 'text', text: 'messages endpoint selected because include stayed empty' }],
      stop_reason: 'end_turn',
      usage: { input_tokens: 7, output_tokens: 3, total_tokens: 10 },
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/responses',
      headers: {
        'openai-beta': 'responses-2025-03-11',
        'x-stainless-lang': 'typescript',
        originator: 'codex_cli_rs',
      },
      payload: {
        model: 'claude-haiku-4-5-20251001',
        input: 'hello',
        reasoning: {
          effort: 'high',
          summary: 'auto',
        },
        include: [],
      },
    });

    expect(response.statusCode).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [targetUrl] = fetchMock.mock.calls[0] as [string, any];
    expect(targetUrl).toContain('/v1/messages');
  });

  it('keeps explicit custom include on claude-family codex-surface responses requests and stays on the default messages-first order', async () => {
    selectChannelMock.mockReturnValue({
      channel: { id: 11, routeId: 22 },
      site: { name: 'generic-site', url: 'https://upstream.example.com', platform: 'new-api' },
      account: { id: 33, username: 'demo-user' },
      tokenName: 'default',
      tokenValue: 'sk-demo',
      actualModel: 'upstream-gpt',
    });

    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      id: 'msg_explicit_custom_include',
      type: 'message',
      model: 'upstream-gpt',
      content: [{ type: 'text', text: 'messages endpoint selected because custom include stayed explicit' }],
      stop_reason: 'end_turn',
      usage: { input_tokens: 7, output_tokens: 3, total_tokens: 10 },
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/responses',
      headers: {
        'openai-beta': 'responses-2025-03-11',
        'x-stainless-lang': 'typescript',
        originator: 'codex_cli_rs',
      },
      payload: {
        model: 'claude-haiku-4-5-20251001',
        input: 'hello',
        reasoning: {
          effort: 'high',
          summary: 'auto',
        },
        include: ['message.input_image.image_url'],
      },
    });

    expect(response.statusCode).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [targetUrl] = fetchMock.mock.calls[0] as [string, any];
    expect(targetUrl).toContain('/v1/messages');
  });

  it('forces anyrouter platform to prefer /v1/messages even when catalog says openai', async () => {
    selectChannelMock.mockReturnValue({
      channel: { id: 11, routeId: 22 },
      site: { name: 'anyrouter-site', url: 'https://anyrouter.example.com', platform: 'anyrouter' },
      account: { id: 33, username: 'demo-user' },
      tokenName: 'default',
      tokenValue: 'sk-demo',
      actualModel: 'upstream-gpt',
    });
    fetchModelPricingCatalogMock.mockResolvedValue({
      models: [
        {
          modelName: 'upstream-gpt',
          supportedEndpointTypes: ['openai'],
        },
      ],
      groupRatio: {},
    });

    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      id: 'msg_anyrouter',
      type: 'message',
      model: 'upstream-gpt',
      content: [{ type: 'text', text: 'anyrouter prefers messages' }],
      stop_reason: 'end_turn',
      usage: { input_tokens: 6, output_tokens: 2, total_tokens: 8 },
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      payload: {
        model: 'claude-haiku-4-5-20251001',
        stream: false,
        messages: [{ role: 'user', content: 'hello' }],
      },
    });

    expect(response.statusCode).toBe(200);
    const body = response.json();
    expect(body?.choices?.[0]?.message?.content).toContain('anyrouter prefers messages');

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [targetUrl] = fetchMock.mock.calls[0] as [string, any];
    expect(targetUrl).toContain('/v1/messages');
  });

  it('prefers /v1/messages on openai platform for claude-family models on /v1/chat/completions', async () => {
    fetchModelPricingCatalogMock.mockResolvedValue({
      models: [
        {
          modelName: 'claude-opus-4-6',
          supportedEndpointTypes: ['/v1/chat/completions', 'openai'],
        },
      ],
      groupRatio: {},
    });

    selectChannelMock.mockReturnValue({
      channel: { id: 11, routeId: 22 },
      site: { name: 'openai-site', url: 'https://api.openai.com', platform: 'openai' },
      account: { id: 33, username: 'demo-user' },
      tokenName: 'default',
      tokenValue: 'sk-openai',
      actualModel: 'claude-opus-4-6',
    });

    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      id: 'msg_openai_platform_claude',
      type: 'message',
      model: 'claude-opus-4-6',
      content: [{ type: 'text', text: 'messages endpoint selected' }],
      stop_reason: 'end_turn',
      usage: { input_tokens: 6, output_tokens: 2, total_tokens: 8 },
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      payload: {
        model: 'claude-opus-4-6',
        stream: false,
        messages: [{ role: 'user', content: 'hello' }],
      },
    });

    expect(response.statusCode).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [targetUrl] = fetchMock.mock.calls[0] as [string, any];
    expect(targetUrl).toContain('/v1/messages');
  });

  it('falls back from /v1/messages to /v1/chat/completions on openai platform when messages endpoint is unavailable', async () => {
    selectChannelMock.mockReturnValue({
      channel: { id: 11, routeId: 22 },
      site: { name: 'openai-site', url: 'https://api.openai.com', platform: 'openai' },
      account: { id: 33, username: 'demo-user' },
      tokenName: 'default',
      tokenValue: 'sk-openai',
      actualModel: 'claude-opus-4-6',
    });

    fetchMock
      .mockResolvedValueOnce(new Response(JSON.stringify({
        error: { message: 'Not Found', type: 'not_found_error' },
      }), {
        status: 404,
        headers: { 'content-type': 'application/json' },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        id: 'chatcmpl_openai_fallback_chat',
        object: 'chat.completion',
        created: 1_706_000_777,
        model: 'claude-opus-4-6',
        choices: [{
          index: 0,
          message: { role: 'assistant', content: 'fallback to chat completed' },
          finish_reason: 'stop',
        }],
        usage: { prompt_tokens: 5, completion_tokens: 3, total_tokens: 8 },
      }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      payload: {
        model: 'claude-opus-4-6',
        stream: false,
        messages: [{ role: 'user', content: 'hello' }],
      },
    });

    expect(response.statusCode).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    const [firstUrl] = fetchMock.mock.calls[0] as [string, any];
    const [secondUrl] = fetchMock.mock.calls[1] as [string, any];
    expect(firstUrl).toContain('/v1/messages');
    expect(secondUrl).toContain('/v1/chat/completions');
  });

  it('falls back to /v1/responses for /v1/chat/completions when messages/chat endpoints return 502', async () => {
    selectChannelMock.mockReturnValue({
      channel: { id: 11, routeId: 22 },
      site: { name: 'generic-site', url: 'https://generic.example.com', platform: 'new-api' },
      account: { id: 33, username: 'demo-user' },
      tokenName: 'default',
      tokenValue: 'sk-generic',
      actualModel: 'claude-haiku-4-5-20251001',
    });

    fetchMock
      .mockResolvedValueOnce(new Response(
        '<!DOCTYPE html><html><head><title>502 Bad Gateway</title></head><body>Cloudflare</body></html>',
        {
          status: 502,
          headers: { 'content-type': 'text/html; charset=UTF-8' },
        },
      ))
      .mockResolvedValueOnce(new Response(
        '<!DOCTYPE html><html><head><title>502 Bad Gateway</title></head><body>Cloudflare</body></html>',
        {
          status: 502,
          headers: { 'content-type': 'text/html; charset=UTF-8' },
        },
      ))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        id: 'resp_anyrouter_fallback',
        object: 'response',
        model: 'claude-haiku-4-5-20251001',
        status: 'completed',
        output_text: 'ok via responses fallback after 502',
        usage: { input_tokens: 5, output_tokens: 2, total_tokens: 7 },
      }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      payload: {
        model: 'claude-haiku-4-5-20251001',
        stream: false,
        messages: [{ role: 'user', content: 'hello' }],
      },
    });

    expect(response.statusCode).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(3);

    const [firstUrl] = fetchMock.mock.calls[0] as [string, any];
    const [secondUrl] = fetchMock.mock.calls[1] as [string, any];
    const [thirdUrl] = fetchMock.mock.calls[2] as [string, any];
    expect(firstUrl).toContain('/v1/messages');
    expect(secondUrl).toContain('/v1/chat/completions');
    expect(thirdUrl).toContain('/v1/responses');

    const body = response.json();
    expect(body?.choices?.[0]?.message?.content).toContain('ok via responses fallback after 502');
  });

  it('continues to /v1/responses when /v1/messages dispatch is denied for /v1/chat/completions', async () => {
    selectChannelMock.mockReturnValue({
      channel: { id: 11, routeId: 22 },
      site: { name: 'generic-site', url: 'https://generic.example.com', platform: 'new-api' },
      account: { id: 33, username: 'demo-user' },
      tokenName: 'default',
      tokenValue: 'sk-generic',
      actualModel: 'gpt-5.2-codex',
    });

    fetchMock
      .mockResolvedValueOnce(new Response(JSON.stringify({
        error: { message: 'Unsupported endpoint /v1/chat/completions', type: 'unsupported_endpoint' },
      }), {
        status: 400,
        headers: { 'content-type': 'application/json' },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        error: { message: 'This group does not allow /v1/messages dispatch', type: 'forbidden' },
      }), {
        status: 403,
        headers: { 'content-type': 'application/json' },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        id: 'resp_dispatch_denied_fallback',
        object: 'response',
        model: 'gpt-5.2-codex',
        status: 'completed',
        output_text: 'ok via responses after messages dispatch denied',
        usage: { input_tokens: 5, output_tokens: 2, total_tokens: 7 },
      }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      payload: {
        model: 'gpt-5.2-codex',
        stream: false,
        messages: [{ role: 'user', content: 'hello' }],
      },
    });

    expect(response.statusCode).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(3);
    const [firstUrl] = fetchMock.mock.calls[0] as [string, any];
    const [secondUrl] = fetchMock.mock.calls[1] as [string, any];
    const [thirdUrl] = fetchMock.mock.calls[2] as [string, any];
    expect(firstUrl).toContain('/v1/chat/completions');
    expect(secondUrl).toContain('/v1/messages');
    expect(thirdUrl).toContain('/v1/responses');
    expect(response.json()?.choices?.[0]?.message?.content).toContain('ok via responses');
  });

  it('prefers /v1/responses immediately after explicit legacy protocol rejection on /v1/chat/completions', async () => {
    selectChannelMock.mockReturnValue({
      channel: { id: 11, routeId: 22 },
      site: { name: 'generic-site', url: 'https://generic.example.com', platform: 'sub2api' },
      account: { id: 33, username: 'demo-user' },
      tokenName: 'default',
      tokenValue: 'sk-generic',
      actualModel: 'gpt-5.2-codex',
    });

    fetchMock
      .mockResolvedValueOnce(new Response(JSON.stringify({
        error: {
          message: 'Unsupported legacy protocol: /v1/chat/completions is not supported. Please use /v1/responses.',
          type: 'upstream_error',
        },
      }), {
        status: 400,
        headers: { 'content-type': 'application/json' },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        id: 'resp_legacy_protocol_preferred',
        object: 'response',
        model: 'gpt-5.2-codex',
        status: 'completed',
        output_text: 'ok via direct responses preference',
        usage: { input_tokens: 5, output_tokens: 2, total_tokens: 7 },
      }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      payload: {
        model: 'gpt-5.2-codex',
        stream: false,
        messages: [{ role: 'user', content: 'hello' }],
      },
    });

    expect(response.statusCode).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    const [firstUrl] = fetchMock.mock.calls[0] as [string, any];
    const [secondUrl] = fetchMock.mock.calls[1] as [string, any];
    expect(firstUrl).toContain('/v1/chat/completions');
    expect(secondUrl).toContain('/v1/responses');
    expect(secondUrl).not.toContain('/v1/messages');
    expect(response.json()?.choices?.[0]?.message?.content).toContain('ok via direct responses preference');
  });

  it('keeps messages-first semantics for claude-family models on generic upstreams', async () => {
    selectChannelMock.mockReturnValue({
      channel: { id: 11, routeId: 22 },
      site: { name: 'generic-site', url: 'https://generic.example.com', platform: 'new-api' },
      account: { id: 33, username: 'demo-user' },
      tokenName: 'default',
      tokenValue: 'sk-generic',
      actualModel: 'claude-haiku-4-5-20251001',
    });

    fetchMock
      .mockResolvedValueOnce(new Response(JSON.stringify({
        error: { message: 'This group does not allow /v1/messages dispatch', type: 'forbidden' },
      }), {
        status: 403,
        headers: { 'content-type': 'application/json' },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        error: {
          message: 'Unsupported legacy protocol: /v1/chat/completions is not supported. Please use /v1/responses.',
          type: 'upstream_error',
        },
      }), {
        status: 400,
        headers: { 'content-type': 'application/json' },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        id: 'resp_claude_generic_messages_first',
        object: 'response',
        model: 'claude-haiku-4-5-20251001',
        status: 'completed',
        output_text: 'ok via responses after preserving messages-first order',
        usage: { input_tokens: 5, output_tokens: 2, total_tokens: 7 },
      }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      payload: {
        model: 'claude-haiku-4-5-20251001',
        stream: false,
        messages: [{ role: 'user', content: 'hello' }],
      },
    });

    expect(response.statusCode).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(3);
    const [firstUrl] = fetchMock.mock.calls[0] as [string, any];
    const [secondUrl] = fetchMock.mock.calls[1] as [string, any];
    const [thirdUrl] = fetchMock.mock.calls[2] as [string, any];
    expect(firstUrl).toContain('/v1/messages');
    expect(secondUrl).toContain('/v1/chat/completions');
    expect(thirdUrl).toContain('/v1/responses');
    expect(response.json()?.choices?.[0]?.message?.content).toContain('ok via responses');
  });

  it('forces openai platform to use /v1/chat/completions for claude downstream requests', async () => {
    selectChannelMock.mockReturnValue({
      channel: { id: 11, routeId: 22 },
      site: { name: 'openai-site', url: 'https://api.openai.com', platform: 'openai' },
      account: { id: 33, username: 'demo-user' },
      tokenName: 'default',
      tokenValue: 'sk-openai',
      actualModel: 'gpt-4o-mini',
    });

    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      id: 'chatcmpl-openai-for-claude-downstream',
      object: 'chat.completion',
      created: 1_706_000_003,
      model: 'gpt-4o-mini',
      choices: [{
        index: 0,
        message: { role: 'assistant', content: 'openai endpoint selected' },
        finish_reason: 'stop',
      }],
      usage: { prompt_tokens: 4, completion_tokens: 3, total_tokens: 7 },
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/messages',
      payload: {
        model: 'gpt-4o-mini',
        max_tokens: 128,
        messages: [{ role: 'user', content: 'hello' }],
      },
    });

    expect(response.statusCode).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [targetUrl] = fetchMock.mock.calls[0] as [string, any];
    expect(targetUrl).toContain('/v1/chat/completions');
    expect(targetUrl).not.toContain('/v1/messages');
  });

  it('preserves claude tool_use/tool_result when claude downstream is routed to openai chat endpoint', async () => {
    selectChannelMock.mockReturnValue({
      channel: { id: 11, routeId: 22 },
      site: { name: 'openai-site', url: 'https://api.openai.com', platform: 'openai' },
      account: { id: 33, username: 'demo-user' },
      tokenName: 'default',
      tokenValue: 'sk-openai',
      actualModel: 'gpt-4o-mini',
    });

    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      id: 'chatcmpl-openai-tools',
      object: 'chat.completion',
      created: 1_706_000_006,
      model: 'gpt-4o-mini',
      choices: [{
        index: 0,
        message: { role: 'assistant', content: 'tool payload received' },
        finish_reason: 'stop',
      }],
      usage: { prompt_tokens: 10, completion_tokens: 3, total_tokens: 13 },
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/messages',
      payload: {
        model: 'gpt-4o-mini',
        max_tokens: 256,
        messages: [
          {
            role: 'assistant',
            content: [
              {
                type: 'tool_use',
                id: 'toolu_abc',
                name: 'Glob',
                input: { pattern: 'README*' },
              },
            ],
          },
          {
            role: 'user',
            content: [
              {
                type: 'tool_result',
                tool_use_id: 'toolu_abc',
                content: [{ type: 'text', text: '{\"matches\":1}' }],
              },
              {
                type: 'text',
                text: 'continue',
              },
            ],
          },
        ],
      },
    });

    expect(response.statusCode).toBe(200);

    const [_targetUrl, options] = fetchMock.mock.calls[0] as [string, any];
    const forwardedBody = JSON.parse(options.body);
    const forwardedMessages = Array.isArray(forwardedBody.messages) ? forwardedBody.messages : [];

    const assistantWithToolCalls = forwardedMessages.find((item: any) =>
      item?.role === 'assistant'
      && Array.isArray(item?.tool_calls)
      && item.tool_calls.length > 0,
    );
    expect(assistantWithToolCalls).toBeTruthy();
    expect(assistantWithToolCalls.tool_calls[0].id).toBe('toolu_abc');
    expect(assistantWithToolCalls.tool_calls[0].function?.name).toBe('Glob');
    expect(assistantWithToolCalls.tool_calls[0].function?.arguments).toContain('README*');

    const toolMessage = forwardedMessages.find((item: any) => item?.role === 'tool');
    expect(toolMessage).toBeTruthy();
    expect(toolMessage.tool_call_id).toBe('toolu_abc');
    expect(toolMessage.content).toContain('matches');
  });

  it('maps claude tool config and thinking budget before routing claude downstream requests to openai chat endpoint', async () => {
    selectChannelMock.mockReturnValue({
      channel: { id: 11, routeId: 22 },
      site: { name: 'openai-site', url: 'https://api.openai.com', platform: 'openai' },
      account: { id: 33, username: 'demo-user' },
      tokenName: 'default',
      tokenValue: 'sk-openai',
      actualModel: 'gpt-4o-mini',
    });

    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      id: 'chatcmpl-openai-config-mapped',
      object: 'chat.completion',
      created: 1_706_000_007,
      model: 'gpt-4o-mini',
      choices: [{
        index: 0,
        message: { role: 'assistant', content: 'tool config mapped' },
        finish_reason: 'stop',
      }],
      usage: { prompt_tokens: 9, completion_tokens: 3, total_tokens: 12 },
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/messages',
      payload: {
        model: 'gpt-4o-mini',
        max_tokens: 256,
        metadata: { user_id: 'user-1' },
        thinking: { type: 'enabled', budget_tokens: 1024 },
        tools: [{
          name: 'Glob',
          description: 'Search files',
          input_schema: {
            type: 'object',
            properties: {
              pattern: { type: 'string' },
            },
            required: ['pattern'],
          },
        }],
        tool_choice: {
          type: 'tool',
          name: 'Glob',
        },
        messages: [{ role: 'user', content: 'hello' }],
      },
    });

    expect(response.statusCode).toBe(200);

    const [_targetUrl, options] = fetchMock.mock.calls[0] as [string, any];
    const forwardedBody = JSON.parse(options.body);
    expect(forwardedBody.metadata).toEqual({ user_id: 'user-1' });
    expect(forwardedBody.reasoning_budget).toBe(1024);
    expect(forwardedBody.tools).toEqual([{
      type: 'function',
      function: {
        name: 'Glob',
        description: 'Search files',
        parameters: {
          type: 'object',
          properties: {
            pattern: { type: 'string' },
          },
          required: ['pattern'],
        },
      },
    }]);
    expect(forwardedBody.tool_choice).toEqual({
      type: 'function',
      function: {
        name: 'Glob',
      },
    });
  });

  it('forces claude platform to use /v1/messages with x-api-key auth for openai downstream requests', async () => {
    selectChannelMock.mockReturnValue({
      channel: { id: 11, routeId: 22 },
      site: { name: 'claude-site', url: 'https://api.anthropic.com', platform: 'claude' },
      account: { id: 33, username: 'demo-user' },
      tokenName: 'default',
      tokenValue: 'sk-claude',
      actualModel: 'claude-sonnet-4-5-20250929',
    });

    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      id: 'msg_claude_upstream',
      type: 'message',
      model: 'claude-sonnet-4-5-20250929',
      content: [{ type: 'text', text: 'claude endpoint selected' }],
      stop_reason: 'end_turn',
      usage: { input_tokens: 5, output_tokens: 2, total_tokens: 7 },
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      payload: {
        model: 'claude-sonnet-4-5-20250929',
        stream: false,
        messages: [{ role: 'user', content: 'hello' }],
      },
    });

    expect(response.statusCode).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [targetUrl, options] = fetchMock.mock.calls[0] as [string, any];
    expect(targetUrl).toContain('/v1/messages');
    expect(options.headers['x-api-key']).toBe('sk-claude');
    expect(options.headers['anthropic-version']).toBeTruthy();
    expect(options.headers.Authorization).toBeUndefined();
  });

  it('preserves openai tool context when /v1/chat/completions is routed to /v1/messages upstream', async () => {
    selectChannelMock.mockReturnValue({
      channel: { id: 11, routeId: 22 },
      site: { name: 'claude-site', url: 'https://api.anthropic.com', platform: 'claude' },
      account: { id: 33, username: 'demo-user' },
      tokenName: 'default',
      tokenValue: 'sk-claude',
      actualModel: 'claude-sonnet-4-5-20250929',
    });

    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      id: 'msg_claude_tool_context',
      type: 'message',
      model: 'claude-sonnet-4-5-20250929',
      content: [{ type: 'text', text: 'ok' }],
      stop_reason: 'end_turn',
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      payload: {
        model: 'claude-sonnet-4-5-20250929',
        stream: false,
        tools: [{
          type: 'function',
          function: {
            name: 'Glob',
            description: 'Search files',
            parameters: {
              type: 'object',
              properties: {
                pattern: { type: 'string' },
              },
              required: ['pattern'],
            },
          },
        }],
        tool_choice: {
          type: 'function',
          function: {
            name: 'Glob',
          },
        },
        messages: [
          {
            role: 'assistant',
            tool_calls: [{
              id: 'call_abc',
              type: 'function',
              function: {
                name: 'Glob',
                arguments: '{"pattern":"README*"}',
              },
            }],
          },
          {
            role: 'tool',
            tool_call_id: 'call_abc',
            content: '{"matches":1}',
          },
          {
            role: 'user',
            content: 'continue',
          },
        ],
      },
    });

    expect(response.statusCode).toBe(200);

    const [_targetUrl, options] = fetchMock.mock.calls[0] as [string, any];
    const forwardedBody = JSON.parse(options.body);
    expect(Array.isArray(forwardedBody.messages)).toBe(true);

    const assistantMessage = forwardedBody.messages.find((item: any) => item?.role === 'assistant');
    expect(Array.isArray(assistantMessage?.content)).toBe(true);
    expect(assistantMessage.content.some((part: any) => part?.type === 'tool_use')).toBe(true);

    const userToolResultMessage = forwardedBody.messages.find((item: any) =>
      item?.role === 'user'
      && Array.isArray(item?.content)
      && item.content.some((part: any) => part?.type === 'tool_result'),
    );
    expect(userToolResultMessage).toBeTruthy();
    expect(userToolResultMessage.content[0].tool_use_id).toBe('call_abc');

    expect(forwardedBody.tools?.[0]?.name).toBe('Glob');
    expect(forwardedBody.tools?.[0]?.input_schema?.properties?.pattern?.type).toBe('string');
    expect(forwardedBody.tool_choice).toEqual({ type: 'tool', name: 'Glob' });
  });

  it('groups consecutive tool messages into one anthropic user turn when routing /v1/chat/completions to /v1/messages', async () => {
    selectChannelMock.mockReturnValue({
      channel: { id: 11, routeId: 22 },
      site: { name: 'claude-site', url: 'https://api.anthropic.com', platform: 'claude' },
      account: { id: 33, username: 'demo-user' },
      tokenName: 'default',
      tokenValue: 'sk-claude',
      actualModel: 'claude-sonnet-4-5-20250929',
    });

    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      id: 'msg_claude_grouped_tool_results',
      type: 'message',
      model: 'claude-sonnet-4-5-20250929',
      content: [{ type: 'text', text: 'ok' }],
      stop_reason: 'end_turn',
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      payload: {
        model: 'claude-sonnet-4-5-20250929',
        stream: false,
        messages: [
          {
            role: 'assistant',
            tool_calls: [
              {
                id: 'call_one',
                type: 'function',
                function: { name: 'Glob', arguments: '{"pattern":"README*"}' },
              },
              {
                id: 'call_two',
                type: 'function',
                function: { name: 'Read', arguments: '{"file":"README.md"}' },
              },
            ],
          },
          { role: 'tool', tool_call_id: 'call_one', content: '{"matches":["README.md"]}' },
          { role: 'tool', tool_call_id: 'call_two', content: '{"content":"hello"}' },
          { role: 'user', content: 'continue' },
        ],
      },
    });

    expect(response.statusCode).toBe(200);

    const [_targetUrl, options] = fetchMock.mock.calls[0] as [string, any];
    const forwardedBody = JSON.parse(options.body);
    expect(Array.isArray(forwardedBody.messages)).toBe(true);

    const userMessages = forwardedBody.messages.filter((item: any) => item?.role === 'user');
    expect(userMessages.length).toBe(1);
    expect(Array.isArray(userMessages[0]?.content)).toBe(true);
    expect(userMessages[0].content.filter((part: any) => part?.type === 'tool_result').length).toBe(2);
    expect(userMessages[0].content.some((part: any) => part?.type === 'tool_result' && part?.tool_use_id === 'call_one')).toBe(true);
    expect(userMessages[0].content.some((part: any) => part?.type === 'tool_result' && part?.tool_use_id === 'call_two')).toBe(true);
    expect(userMessages[0].content.some((part: any) => part?.type === 'text' && part?.text === 'continue')).toBe(true);
  });

  it('converts /v1/responses function_call SSE to OpenAI tool_calls on /v1/chat/completions', async () => {
    fetchModelPricingCatalogMock.mockResolvedValue({
      models: [
        {
          modelName: 'upstream-gpt',
          supportedEndpointTypes: ['/v1/responses'],
        },
      ],
      groupRatio: {},
    });

    const encoder = new TextEncoder();
    const upstreamBody = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode('event: response.created\ndata: {"type":"response.created","response":{"id":"resp_123","model":"upstream-gpt","created_at":1706000000,"status":"in_progress","output":[]}}\n\n'));
        controller.enqueue(encoder.encode('event: response.output_item.added\ndata: {"type":"response.output_item.added","output_index":0,"item":{"type":"function_call","id":"fc_1","call_id":"call_abc","name":"Glob"}}\n\n'));
        controller.enqueue(encoder.encode('event: response.function_call_arguments.delta\ndata: {"type":"response.function_call_arguments.delta","output_index":0,"call_id":"call_abc","delta":"{\\"pattern\\":\\"README*\\"}"}\n\n'));
        controller.enqueue(encoder.encode('event: response.completed\ndata: {"type":"response.completed","response":{"id":"resp_123","model":"upstream-gpt","status":"completed","usage":{"input_tokens":5,"output_tokens":3,"total_tokens":8}}}\n\n'));
        controller.enqueue(encoder.encode('data: [DONE]\n\n'));
        controller.close();
      },
    });

    fetchMock.mockResolvedValue(new Response(upstreamBody, {
      status: 200,
      headers: { 'content-type': 'text/event-stream; charset=utf-8' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      payload: {
        model: 'claude-haiku-4-5-20251001',
        stream: true,
        messages: [{ role: 'user', content: 'find readme' }],
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.body).toContain('"tool_calls"');
    expect(response.body).toContain('"id":"call_abc"');
    expect(response.body).toContain('"name":"Glob"');
    expect(response.body).toContain('\\"pattern\\":\\"README*\\"');
  });

  it('uses response.function_call_arguments.done when upstream omits delta on /v1/chat/completions', async () => {
    fetchModelPricingCatalogMock.mockResolvedValue({
      models: [
        {
          modelName: 'upstream-gpt',
          supportedEndpointTypes: ['/v1/responses'],
        },
      ],
      groupRatio: {},
    });

    const encoder = new TextEncoder();
    const upstreamBody = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode('event: response.created\ndata: {"type":"response.created","response":{"id":"resp_done_only","model":"upstream-gpt","created_at":1706000000,"status":"in_progress","output":[]}}\n\n'));
        controller.enqueue(encoder.encode('event: response.output_item.added\ndata: {"type":"response.output_item.added","output_index":0,"item":{"type":"function_call","id":"fc_1","call_id":"call_done_only","name":"Glob"}}\n\n'));
        controller.enqueue(encoder.encode('event: response.function_call_arguments.done\ndata: {"type":"response.function_call_arguments.done","output_index":0,"call_id":"call_done_only","arguments":"{\\"pattern\\":\\"README*\\"}"}\n\n'));
        controller.enqueue(encoder.encode('event: response.completed\ndata: {"type":"response.completed","response":{"id":"resp_done_only","model":"upstream-gpt","status":"completed","usage":{"input_tokens":5,"output_tokens":3,"total_tokens":8}}}\n\n'));
        controller.enqueue(encoder.encode('data: [DONE]\n\n'));
        controller.close();
      },
    });

    fetchMock.mockResolvedValue(new Response(upstreamBody, {
      status: 200,
      headers: { 'content-type': 'text/event-stream; charset=utf-8' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      payload: {
        model: 'claude-haiku-4-5-20251001',
        stream: true,
        messages: [{ role: 'user', content: 'find readme' }],
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.body).toContain('"tool_calls"');
    expect(response.body).toContain('"id":"call_done_only"');
    expect(response.body).toContain('"name":"Glob"');
    expect(response.body).toContain('\\"pattern\\":\\"README*\\"');
  });

  it('does not duplicate tool arguments when upstream sends both delta and done on /v1/chat/completions', async () => {
    fetchModelPricingCatalogMock.mockResolvedValue({
      models: [
        {
          modelName: 'upstream-gpt',
          supportedEndpointTypes: ['/v1/responses'],
        },
      ],
      groupRatio: {},
    });

    const encoder = new TextEncoder();
    const upstreamBody = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode('event: response.created\ndata: {"type":"response.created","response":{"id":"resp_delta_done","model":"upstream-gpt","created_at":1706000000,"status":"in_progress","output":[]}}\n\n'));
        controller.enqueue(encoder.encode('event: response.output_item.added\ndata: {"type":"response.output_item.added","output_index":0,"item":{"type":"function_call","id":"fc_1","call_id":"call_delta_done","name":"Glob"}}\n\n'));
        controller.enqueue(encoder.encode('event: response.function_call_arguments.delta\ndata: {"type":"response.function_call_arguments.delta","output_index":0,"call_id":"call_delta_done","delta":"{\\"pattern\\":\\"README*\\"}"}\n\n'));
        controller.enqueue(encoder.encode('event: response.function_call_arguments.done\ndata: {"type":"response.function_call_arguments.done","output_index":0,"call_id":"call_delta_done","arguments":"{\\"pattern\\":\\"README*\\"}"}\n\n'));
        controller.enqueue(encoder.encode('event: response.completed\ndata: {"type":"response.completed","response":{"id":"resp_delta_done","model":"upstream-gpt","status":"completed","usage":{"input_tokens":5,"output_tokens":3,"total_tokens":8}}}\n\n'));
        controller.enqueue(encoder.encode('data: [DONE]\n\n'));
        controller.close();
      },
    });

    fetchMock.mockResolvedValue(new Response(upstreamBody, {
      status: 200,
      headers: { 'content-type': 'text/event-stream; charset=utf-8' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      payload: {
        model: 'claude-haiku-4-5-20251001',
        stream: true,
        messages: [{ role: 'user', content: 'find readme' }],
      },
    });

    expect(response.statusCode).toBe(200);
    const matches = response.body.match(/\\"pattern\\":\\"README\*\\"/g) || [];
    expect(matches.length).toBe(1);
  });

  it('emits finish_reason error when /v1/chat/completions receives response.failed from /v1/responses upstream', async () => {
    fetchModelPricingCatalogMock.mockResolvedValue({
      models: [
        {
          modelName: 'upstream-gpt',
          supportedEndpointTypes: ['/v1/responses'],
        },
      ],
      groupRatio: {},
    });

    const encoder = new TextEncoder();
    const upstreamBody = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode('event: response.created\ndata: {"type":"response.created","response":{"id":"resp_fail_1","model":"upstream-gpt","created_at":1706000000,"status":"in_progress","output":[]}}\n\n'));
        controller.enqueue(encoder.encode('event: response.failed\ndata: {"type":"response.failed","response":{"id":"resp_fail_1","model":"upstream-gpt","status":"failed","error":{"message":"tool execution failed"}}}\n\n'));
        controller.enqueue(encoder.encode('data: [DONE]\n\n'));
        controller.close();
      },
    });

    fetchMock.mockResolvedValue(new Response(upstreamBody, {
      status: 200,
      headers: { 'content-type': 'text/event-stream; charset=utf-8' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      payload: {
        model: 'claude-haiku-4-5-20251001',
        stream: true,
        messages: [{ role: 'user', content: 'find readme' }],
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.body).toContain('"finish_reason":"error"');
    expect(response.body).toContain('[DONE]');
    expect(recordSuccessMock).not.toHaveBeenCalled();
    expect(recordFailureMock).toHaveBeenCalledTimes(1);
  });

  it('preserves non-stream function_call output when /v1/chat/completions falls back to /v1/responses', async () => {
    fetchModelPricingCatalogMock.mockResolvedValue({
      models: [
        {
          modelName: 'upstream-gpt',
          supportedEndpointTypes: ['/v1/responses'],
        },
      ],
      groupRatio: {},
    });

    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      id: 'resp_tool_nonstream',
      object: 'response',
      model: 'upstream-gpt',
      status: 'completed',
      output: [{
        type: 'function_call',
        id: 'fc_1',
        call_id: 'call_abc',
        name: 'Glob',
        arguments: '{"pattern":"README*"}',
      }],
      output_text: '',
      usage: { input_tokens: 3, output_tokens: 2, total_tokens: 5 },
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      payload: {
        model: 'claude-haiku-4-5-20251001',
        stream: false,
        messages: [{ role: 'user', content: 'find readme' }],
      },
    });

    expect(response.statusCode).toBe(200);
    const body = response.json();
    expect(body?.choices?.[0]?.message?.tool_calls?.[0]?.id).toBe('call_abc');
    expect(body?.choices?.[0]?.message?.tool_calls?.[0]?.function?.name).toBe('Glob');
    expect(body?.choices?.[0]?.message?.tool_calls?.[0]?.function?.arguments).toContain('README*');
    expect(body?.choices?.[0]?.finish_reason).toBe('tool_calls');
  });

  it('preserves openai tool context when /v1/chat/completions is routed to /v1/responses upstream', async () => {
    fetchModelPricingCatalogMock.mockResolvedValue({
      models: [
        {
          modelName: 'upstream-gpt',
          supportedEndpointTypes: ['/v1/responses'],
        },
      ],
      groupRatio: {},
    });

    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      id: 'resp_tool_forward',
      object: 'response',
      model: 'upstream-gpt',
      status: 'completed',
      output: [],
      output_text: 'ok',
      usage: { input_tokens: 3, output_tokens: 2, total_tokens: 5 },
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      payload: {
        model: 'gpt-4o-mini',
        stream: false,
        tools: [{
          type: 'function',
          function: {
            name: 'Glob',
            parameters: {
              type: 'object',
              properties: { pattern: { type: 'string' } },
              required: ['pattern'],
            },
          },
        }],
        tool_choice: {
          type: 'function',
          function: { name: 'Glob' },
        },
        messages: [
          {
            role: 'assistant',
            tool_calls: [{
              id: 'call_abc',
              type: 'function',
              function: {
                name: 'Glob',
                arguments: '{"pattern":"README*"}',
              },
            }],
          },
          {
            role: 'tool',
            tool_call_id: 'call_abc',
            content: '{"matches":1}',
          },
          {
            role: 'user',
            content: 'continue',
          },
        ],
      },
    });

    expect(response.statusCode).toBe(200);

    const [targetUrl, options] = fetchMock.mock.calls[0] as [string, any];
    expect(targetUrl).toContain('/v1/responses');

    const forwardedBody = JSON.parse(options.body);
    expect(Array.isArray(forwardedBody.input)).toBe(true);
    expect(forwardedBody.input.some((item: any) => item?.type === 'function_call')).toBe(true);
    expect(forwardedBody.input.some((item: any) => item?.type === 'function_call_output')).toBe(true);
    expect(forwardedBody.tools?.[0]?.name).toBe('Glob');
    expect(forwardedBody.tool_choice).toEqual({ type: 'function', name: 'Glob' });
  });

  it('routes gemini platform to OpenAI-compatible upstream endpoint path', async () => {
    selectChannelMock.mockReturnValue({
      channel: { id: 11, routeId: 22 },
      site: { name: 'gemini-site', url: 'https://generativelanguage.googleapis.com', platform: 'gemini' },
      account: { id: 33, username: 'demo-user' },
      tokenName: 'default',
      tokenValue: 'gemini-key',
      actualModel: 'gemini-2.5-flash',
    });

    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      id: 'chatcmpl-gemini-openai-compat',
      object: 'chat.completion',
      created: 1_706_000_004,
      model: 'gemini-2.5-flash',
      choices: [{
        index: 0,
        message: { role: 'assistant', content: 'gemini endpoint selected' },
        finish_reason: 'stop',
      }],
      usage: { prompt_tokens: 6, completion_tokens: 4, total_tokens: 10 },
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      payload: {
        model: 'gemini-2.5-flash',
        stream: false,
        messages: [{ role: 'user', content: 'hello' }],
      },
    });

    expect(response.statusCode).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [targetUrl, options] = fetchMock.mock.calls[0] as [string, any];
    expect(targetUrl).toContain('/v1beta/openai/chat/completions');
    expect(options.headers.Authorization).toBe('Bearer gemini-key');
  });

  it('chooses /v1/messages upstream when catalog indicates messages-only endpoint support', async () => {
    fetchModelPricingCatalogMock.mockResolvedValue({
      models: [
        {
          modelName: 'upstream-gpt',
          supportedEndpointTypes: ['/v1/messages'],
        },
      ],
      groupRatio: {},
    });

    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      id: 'msg_100',
      type: 'message',
      model: 'upstream-gpt',
      content: [{ type: 'text', text: 'hello from messages only' }],
      stop_reason: 'end_turn',
      usage: { input_tokens: 8, output_tokens: 4, total_tokens: 12 },
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      payload: {
        model: 'claude-haiku-4-5-20251001',
        stream: false,
        messages: [{ role: 'user', content: 'hello' }],
      },
    });

    expect(response.statusCode).toBe(200);
    const body = response.json();
    expect(body?.choices?.[0]?.message?.content).toContain('hello from messages only');

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [targetUrl] = fetchMock.mock.calls[0] as [string, any];
    expect(targetUrl).toContain('/v1/messages');
  });

  it('prefers Messages endpoint for claude-family models when catalog uses generic openai/anthropic labels', async () => {
    fetchModelPricingCatalogMock.mockResolvedValue({
      models: [
        {
          modelName: 'upstream-gpt',
          supportedEndpointTypes: ['anthropic', 'openai'],
        },
      ],
      groupRatio: {},
    });

    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      id: 'msg-claude-first',
      type: 'message',
      model: 'upstream-gpt',
      content: [{ type: 'text', text: 'hello from messages endpoint' }],
      stop_reason: 'end_turn',
      usage: { input_tokens: 5, output_tokens: 3, total_tokens: 8 },
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      payload: {
        model: 'claude-haiku-4-5-20251001',
        stream: false,
        messages: [{ role: 'user', content: 'hello' }],
      },
    });

    expect(response.statusCode).toBe(200);
    const body = response.json();
    expect(body?.choices?.[0]?.message?.content).toContain('hello from messages endpoint');

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [targetUrl] = fetchMock.mock.calls[0] as [string, any];
    expect(targetUrl).toContain('/v1/messages');
  });

  it('falls back to /v1/messages when catalog only declares openai and chat endpoint fails', async () => {
    fetchModelPricingCatalogMock.mockResolvedValue({
      models: [
        {
          modelName: 'upstream-gpt',
          supportedEndpointTypes: ['openai'],
        },
      ],
      groupRatio: {},
    });

    fetchMock
      .mockResolvedValueOnce(new Response(JSON.stringify({
        error: {
          message: 'openai_error',
          type: 'bad_response_status_code',
          code: 'bad_response_status_code',
        },
      }), {
        status: 400,
        headers: { 'content-type': 'application/json' },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        id: 'msg_fallback_500',
        type: 'message',
        model: 'upstream-gpt',
        content: [{ type: 'text', text: 'fallback to messages from openai-only catalog' }],
        stop_reason: 'end_turn',
        usage: { input_tokens: 12, output_tokens: 7, total_tokens: 19 },
      }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      payload: {
        model: 'gpt-4o-mini',
        stream: false,
        messages: [{ role: 'user', content: 'hello' }],
      },
    });

    expect(response.statusCode).toBe(200);
    const body = response.json();
    expect(body?.choices?.[0]?.message?.content).toContain('fallback to messages from openai-only catalog');

    expect(fetchMock).toHaveBeenCalledTimes(2);
    const [firstUrl] = fetchMock.mock.calls[0] as [string, any];
    const [secondUrl] = fetchMock.mock.calls[1] as [string, any];
    expect(firstUrl).toContain('/v1/chat/completions');
    expect(secondUrl).toContain('/v1/messages');
  });

  it('downgrades endpoint when upstream returns convert_request_failed/not implemented', async () => {
    fetchModelPricingCatalogMock.mockResolvedValue({
      models: [
        {
          modelName: 'upstream-gpt',
          supportedEndpointTypes: ['/v1/chat/completions', '/v1/messages'],
        },
      ],
      groupRatio: {},
    });

    fetchMock
      .mockResolvedValueOnce(new Response(JSON.stringify({
        error: {
          message: 'not implemented (request id: abc123)',
          type: 'new_api_error',
          code: 'convert_request_failed',
        },
      }), {
        status: 400,
        headers: { 'content-type': 'application/json' },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        id: 'msg_200',
        type: 'message',
        model: 'upstream-gpt',
        content: [{ type: 'text', text: 'fallback from messages' }],
        stop_reason: 'end_turn',
        usage: { input_tokens: 11, output_tokens: 6, total_tokens: 17 },
      }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      payload: {
        model: 'gpt-4o-mini',
        stream: false,
        messages: [{ role: 'user', content: 'hello' }],
      },
    });

    expect(response.statusCode).toBe(200);
    const body = response.json();
    expect(body?.choices?.[0]?.message?.content).toContain('fallback from messages');

    expect(fetchMock).toHaveBeenCalledTimes(2);
    const [firstUrl] = fetchMock.mock.calls[0] as [string, any];
    const [secondUrl] = fetchMock.mock.calls[1] as [string, any];
    expect(firstUrl).toContain('/v1/chat/completions');
    expect(secondUrl).toContain('/v1/messages');
  });

  it('downgrades endpoint when upstream returns openai_error bad_response_status_code', async () => {
    fetchModelPricingCatalogMock.mockResolvedValue({
      models: [
        {
          modelName: 'upstream-gpt',
          supportedEndpointTypes: ['/v1/chat/completions', '/v1/messages'],
        },
      ],
      groupRatio: {},
    });

    fetchMock
      .mockResolvedValueOnce(new Response(JSON.stringify({
        error: {
          message: 'openai_error',
          type: 'bad_response_status_code',
          code: 'bad_response_status_code',
        },
      }), {
        status: 400,
        headers: { 'content-type': 'application/json' },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        id: 'msg_300',
        type: 'message',
        model: 'upstream-gpt',
        content: [{ type: 'text', text: 'fallback from bad_response_status_code' }],
        stop_reason: 'end_turn',
        usage: { input_tokens: 9, output_tokens: 5, total_tokens: 14 },
      }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      payload: {
        model: 'gpt-4o-mini',
        stream: false,
        messages: [{ role: 'user', content: 'hello' }],
      },
    });

    expect(response.statusCode).toBe(200);
    const body = response.json();
    expect(body?.choices?.[0]?.message?.content).toContain('fallback from bad_response_status_code');

    expect(fetchMock).toHaveBeenCalledTimes(2);
    const [firstUrl] = fetchMock.mock.calls[0] as [string, any];
    const [secondUrl] = fetchMock.mock.calls[1] as [string, any];
    expect(firstUrl).toContain('/v1/chat/completions');
    expect(secondUrl).toContain('/v1/messages');
  });
});
