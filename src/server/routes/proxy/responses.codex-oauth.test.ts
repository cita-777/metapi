import { zstdCompressSync } from 'node:zlib';
import Fastify, { type FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { config } from '../../config.js';
import { resetCodexHttpSessionQueue } from '../../proxy-core/runtime/codexHttpSessionQueue.js';
import { resetCodexSessionResponseStore } from '../../proxy-core/runtime/codexSessionResponseStore.js';

const fetchMock = vi.fn();
const selectChannelMock = vi.fn();
const selectNextChannelMock = vi.fn();
const selectPreferredChannelMock = vi.fn();
const recordSuccessMock = vi.fn();
const recordFailureMock = vi.fn();
const refreshModelsAndRebuildRoutesMock = vi.fn();
const reportProxyAllFailedMock = vi.fn();
const reportTokenExpiredMock = vi.fn();
const resolveProxyUsageWithSelfLogFallbackMock = vi.fn(async ({ usage }: any) => ({
  ...usage,
  estimatedCostFromQuota: 0,
  recoveredFromSelfLog: false,
}));
const refreshOauthAccessTokenSingleflightMock = vi.fn();
const recordOauthQuotaResetHintMock = vi.fn();
const insertedProxyLogs: Record<string, unknown>[] = [];
const originalProxyEmptyContentFailEnabled = config.proxyEmptyContentFailEnabled;
const originalProxyStickySessionEnabled = config.proxyStickySessionEnabled;
const originalProxySessionChannelConcurrencyLimit = config.proxySessionChannelConcurrencyLimit;
const originalProxySessionChannelQueueWaitMs = config.proxySessionChannelQueueWaitMs;
const dbInsertMock = vi.fn((_arg?: any) => ({
  values: (values: Record<string, unknown>) => {
    insertedProxyLogs.push(values);
    return {
      run: () => undefined,
    };
  },
}));

vi.mock('undici', async () => {
  const actual = await vi.importActual<typeof import('undici')>('undici');
  return {
    ...actual,
    fetch: (...args: unknown[]) => fetchMock(...args),
  };
});

vi.mock('../../services/tokenRouter.js', () => ({
  tokenRouter: {
    selectChannel: (...args: unknown[]) => selectChannelMock(...args),
    selectNextChannel: (...args: unknown[]) => selectNextChannelMock(...args),
    selectPreferredChannel: (...args: unknown[]) => selectPreferredChannelMock(...args),
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
  isTokenExpiredError: ({ status }: { status?: number }) => status === 401,
}));

vi.mock('../../services/modelPricingService.js', () => ({
  estimateProxyCost: async () => 0,
  buildProxyBillingDetails: async () => null,
  fetchModelPricingCatalog: async () => null,
}));

vi.mock('../../services/proxyRetryPolicy.js', () => ({
  shouldRetryProxyRequest: () => false,
  shouldAbortSameSiteEndpointFallback: () => false,
  RETRYABLE_TIMEOUT_PATTERNS: [/(request timed out|connection timed out|read timeout|\btimed out\b)/i],
}));

vi.mock('../../services/proxyUsageFallbackService.js', () => ({
  resolveProxyUsageWithSelfLogFallback: (arg: any) => resolveProxyUsageWithSelfLogFallbackMock(arg),
}));

vi.mock('../../services/oauth/refreshSingleflight.js', () => ({
  refreshOauthAccessTokenSingleflight: (...args: unknown[]) => refreshOauthAccessTokenSingleflightMock(...args),
}));

vi.mock('../../services/oauth/quota.js', () => ({
  recordOauthQuotaResetHint: (...args: unknown[]) => recordOauthQuotaResetHintMock(...args),
}));

vi.mock('../../db/index.js', () => ({
  db: {
    insert: (arg: any) => dbInsertMock(arg),
    select: () => ({
      from: () => ({
        where: () => ({
          orderBy: () => ({
            all: async () => [],
          }),
        }),
      }),
    }),
    update: () => ({
      set: () => ({
        where: () => ({
          run: async () => undefined,
        }),
      }),
    }),
  },
  hasProxyLogBillingDetailsColumn: async () => false,
  hasProxyLogClientColumns: async () => false,
  hasProxyLogDownstreamApiKeyIdColumn: async () => false,
  hasProxyLogStreamTimingColumns: async () => false,
  schema: {
    proxyLogs: {},
    siteApiEndpoints: {
      id: {},
      siteId: {},
      sortOrder: {},
    },
  },
}));

describe('responses proxy codex oauth refresh', () => {
  let app: FastifyInstance;

  const createDeferred = <T>() => {
    let resolve!: (value: T | PromiseLike<T>) => void;
    let reject!: (reason?: unknown) => void;
    const promise = new Promise<T>((res, rej) => {
      resolve = res;
      reject = rej;
    });
    return { promise, resolve, reject };
  };

  const waitFor = async (predicate: () => boolean, timeoutMs = 1000) => {
    const startedAt = Date.now();
    while (!predicate()) {
      if ((Date.now() - startedAt) >= timeoutMs) {
        throw new Error('Timed out waiting for test condition');
      }
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
  };

  const createSseResponse = (chunks: string[], status = 200) => {
    const encoder = new TextEncoder();
    return new Response(new ReadableStream<Uint8Array>({
      start(controller) {
        for (const chunk of chunks) {
          controller.enqueue(encoder.encode(chunk));
        }
        controller.close();
      },
    }), {
      status,
      headers: { 'content-type': 'text/event-stream; charset=utf-8' },
    });
  };

  const createCompressedSseResponse = (chunks: string[], status = 200) => new Response(
    zstdCompressSync(Buffer.from(chunks.join(''))),
    {
      status,
      headers: {
        'content-encoding': 'zstd',
        'content-type': 'text/event-stream; charset=utf-8',
      },
    },
  );

  beforeAll(async () => {
    const { responsesProxyRoute } = await import('./responses.js');
    app = Fastify();
    await app.register(responsesProxyRoute);
  });

  beforeEach(() => {
    resetCodexHttpSessionQueue();
    resetCodexSessionResponseStore();
    config.proxyEmptyContentFailEnabled = false;
    config.proxyStickySessionEnabled = originalProxyStickySessionEnabled;
    config.proxySessionChannelConcurrencyLimit = originalProxySessionChannelConcurrencyLimit;
    config.proxySessionChannelQueueWaitMs = originalProxySessionChannelQueueWaitMs;
    fetchMock.mockReset();
    selectChannelMock.mockReset();
    selectNextChannelMock.mockReset();
    selectPreferredChannelMock.mockReset();
    recordSuccessMock.mockReset();
    recordFailureMock.mockReset();
    refreshModelsAndRebuildRoutesMock.mockReset();
    reportProxyAllFailedMock.mockReset();
    reportTokenExpiredMock.mockReset();
    resolveProxyUsageWithSelfLogFallbackMock.mockClear();
    refreshOauthAccessTokenSingleflightMock.mockReset();
    recordOauthQuotaResetHintMock.mockReset();
    dbInsertMock.mockClear();
    insertedProxyLogs.length = 0;

    selectChannelMock.mockReturnValue({
      channel: { id: 11, routeId: 22 },
      site: { name: 'codex-site', url: 'https://chatgpt.com/backend-api/codex', platform: 'codex' },
      account: {
        id: 33,
        username: 'codex-user@example.com',
        extraConfig: JSON.stringify({
          credentialMode: 'session',
          oauth: {
            provider: 'codex',
            accountId: 'chatgpt-account-123',
            email: 'codex-user@example.com',
            planType: 'plus',
          },
        }),
      },
      tokenName: 'default',
      tokenValue: 'expired-access-token',
      actualModel: 'gpt-5.2-codex',
    });
    selectPreferredChannelMock.mockReturnValue(null);
    selectNextChannelMock.mockReturnValue(null);
    selectPreferredChannelMock.mockReturnValue(null);
    refreshOauthAccessTokenSingleflightMock.mockResolvedValue({
      accessToken: 'fresh-access-token',
      accountId: 33,
      accountKey: 'chatgpt-account-123',
    });
  });

  afterAll(async () => {
    config.proxyEmptyContentFailEnabled = originalProxyEmptyContentFailEnabled;
    config.proxyStickySessionEnabled = originalProxyStickySessionEnabled;
    config.proxySessionChannelConcurrencyLimit = originalProxySessionChannelConcurrencyLimit;
    config.proxySessionChannelQueueWaitMs = originalProxySessionChannelQueueWaitMs;
    if (app) {
      await app.close();
    }
  });

  it('refreshes codex oauth token and retries the same responses request on 401', async () => {
    fetchMock
      .mockResolvedValueOnce(new Response(JSON.stringify({
        error: { message: 'expired token', type: 'invalid_request_error' },
      }), {
        status: 401,
        headers: { 'content-type': 'application/json' },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        id: 'resp_codex_refreshed',
        object: 'response',
        model: 'gpt-5.2-codex',
        status: 'completed',
        output_text: 'ok after codex token refresh',
        usage: { input_tokens: 4, output_tokens: 2, total_tokens: 6 },
      }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/responses',
      headers: {
        'user-agent': 'CodexClient/1.0',
        'Chatgpt-Account-Id': 'spoofed-account',
      },
      payload: {
        model: 'gpt-5.2-codex',
        input: 'hello codex',
      },
    });

    expect(response.statusCode).toBe(200);
    expect(refreshOauthAccessTokenSingleflightMock).toHaveBeenCalledWith(33);
    expect(fetchMock).toHaveBeenCalledTimes(2);

    const [firstUrl, firstOptions] = fetchMock.mock.calls[0] as [string, any];
    const [secondUrl, secondOptions] = fetchMock.mock.calls[1] as [string, any];
    expect(firstUrl).toBe('https://chatgpt.com/backend-api/codex/responses');
    expect(secondUrl).toBe('https://chatgpt.com/backend-api/codex/responses');
    expect(firstOptions.headers.Authorization).toBe('Bearer expired-access-token');
    expect(secondOptions.headers.Authorization).toBe('Bearer fresh-access-token');
    expect(secondOptions.headers.Originator || secondOptions.headers.originator).toBe('codex_cli_rs');
    expect(secondOptions.headers['Chatgpt-Account-Id'] || secondOptions.headers['chatgpt-account-id']).toBe('chatgpt-account-123');
    expect(secondOptions.headers.Version || secondOptions.headers.version).toBe('0.101.0');
    expect(String(secondOptions.headers.Session_id || secondOptions.headers.session_id || '')).toMatch(/^[0-9a-f-]{36}$/i);
    expect(secondOptions.headers.Conversation_id || secondOptions.headers.conversation_id).toBeUndefined();
    expect(secondOptions.headers['User-Agent'] || secondOptions.headers['user-agent']).toBe('CodexClient/1.0');
    expect(secondOptions.headers.Accept || secondOptions.headers.accept).toBe('text/event-stream');
    expect(secondOptions.headers.Connection || secondOptions.headers.connection).toBe('Keep-Alive');
    expect(response.json()?.output_text).toContain('ok after codex token refresh');
  });

  it('refreshes codex oauth token and retries the same responses request on 403', async () => {
    fetchMock
      .mockResolvedValueOnce(new Response(JSON.stringify({
        error: { message: 'forbidden account mismatch', type: 'invalid_request_error' },
      }), {
        status: 403,
        headers: { 'content-type': 'application/json' },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        id: 'resp_codex_refreshed_403',
        object: 'response',
        model: 'gpt-5.2-codex',
        status: 'completed',
        output_text: 'ok after codex forbidden refresh',
        usage: { input_tokens: 4, output_tokens: 2, total_tokens: 6 },
      }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/responses',
      headers: {
        'user-agent': 'CodexClient/1.0',
      },
      payload: {
        model: 'gpt-5.2-codex',
        input: 'hello codex',
      },
    });

    expect(response.statusCode).toBe(200);
    expect(refreshOauthAccessTokenSingleflightMock).toHaveBeenCalledWith(33);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    const [, secondOptions] = fetchMock.mock.calls[1] as [string, any];
    expect(secondOptions.headers.Authorization).toBe('Bearer fresh-access-token');
    expect(response.json()?.output_text).toContain('ok after codex forbidden refresh');
  });

  it('does not refresh codex oauth token on non-auth 403 responses', async () => {
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({
      error: { message: 'quota exceeded for workspace', type: 'usage_limit_reached' },
    }), {
      status: 403,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/responses',
      payload: {
        model: 'gpt-5.2-codex',
        input: 'hello codex',
      },
    });

    expect(response.statusCode).toBe(403);
    expect(refreshOauthAccessTokenSingleflightMock).not.toHaveBeenCalled();
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(response.json()).toMatchObject({
      error: {
        message: expect.stringContaining('quota exceeded for workspace'),
      },
    });
  });

  it('retries oauth responses requests with a normalized upstream URL after refresh', async () => {
    selectChannelMock.mockReturnValue({
      channel: { id: 11, routeId: 22 },
      site: { name: 'openai-site', url: 'https://gateway.example.com/v1/', platform: 'openai' },
      account: {
        id: 33,
        username: 'oauth-user@example.com',
        extraConfig: JSON.stringify({
          credentialMode: 'session',
          oauth: {
            provider: 'codex',
            accountId: 'chatgpt-account-123',
            email: 'oauth-user@example.com',
            planType: 'plus',
          },
        }),
      },
      tokenName: 'default',
      tokenValue: 'expired-access-token',
      actualModel: 'gpt-4.1-mini',
    });

    fetchMock
      .mockResolvedValueOnce(new Response(JSON.stringify({
        error: { message: 'expired token', type: 'invalid_request_error' },
      }), {
        status: 401,
        headers: { 'content-type': 'application/json' },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        id: 'resp_openai_refreshed',
        object: 'response',
        model: 'gpt-4.1-mini',
        status: 'completed',
        output_text: 'ok after refresh',
        usage: { input_tokens: 4, output_tokens: 2, total_tokens: 6 },
      }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/responses',
      payload: {
        model: 'gpt-4.1-mini',
        input: 'hello oauth',
      },
    });

    expect(response.statusCode).toBe(200);
    expect(refreshOauthAccessTokenSingleflightMock).toHaveBeenCalledWith(33);
    expect(fetchMock).toHaveBeenCalledTimes(2);

    const [firstUrl, firstOptions] = fetchMock.mock.calls[0] as [string, any];
    const [secondUrl, secondOptions] = fetchMock.mock.calls[1] as [string, any];
    expect(firstUrl).toBe('https://gateway.example.com/v1/responses');
    expect(secondUrl).toBe('https://gateway.example.com/v1/responses');
    expect(firstOptions.headers.Authorization).toBe('Bearer expired-access-token');
    expect(secondOptions.headers.Authorization).toBe('Bearer fresh-access-token');
    expect(response.json()?.output_text).toBe('ok after refresh');
  });

  it('sends an explicit empty instructions field to codex responses when downstream body has no system prompt', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      id: 'resp_codex_no_system',
      object: 'response',
      model: 'gpt-5.2-codex',
      status: 'completed',
      output_text: 'ok without system prompt',
      usage: { input_tokens: 4, output_tokens: 2, total_tokens: 6 },
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/responses',
      payload: {
        model: 'gpt-5.2-codex',
        input: 'hello codex',
      },
    });

    expect(response.statusCode).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(1);

    const [, options] = fetchMock.mock.calls[0] as [string, any];
    const forwardedBody = JSON.parse(options.body);
    expect(forwardedBody.instructions).toBe('');
    expect(forwardedBody.prompt_cache_key).toBeUndefined();
    expect(forwardedBody.stream).toBe(true);
    expect(forwardedBody.input).toEqual([
      {
        type: 'message',
        role: 'user',
        content: [{ type: 'input_text', text: 'hello codex' }],
      },
    ]);
  });

  it('preserves explicit prompt_cache_key for codex responses requests without converting it into codex session headers', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      id: 'resp_codex_with_cache_key',
      object: 'response',
      model: 'gpt-5.2-codex',
      status: 'completed',
      output_text: 'ok with cache key',
      usage: { input_tokens: 4, output_tokens: 2, total_tokens: 6 },
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/responses',
      payload: {
        model: 'gpt-5.2-codex',
        prompt_cache_key: 'codex-cache-123',
        input: 'hello codex',
      },
    });

    expect(response.statusCode).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(1);

    const [, options] = fetchMock.mock.calls[0] as [string, any];
    const forwardedBody = JSON.parse(options.body);
    expect(String(options.headers.Session_id || options.headers.session_id || '')).toMatch(/^[0-9a-f-]{36}$/i);
    expect(options.headers.Conversation_id || options.headers.conversation_id).toBeUndefined();
    expect(forwardedBody.prompt_cache_key).toBe('codex-cache-123');
  });

  it('infers previous_response_id for codex tool-output follow-up turns on the same downstream session', async () => {
    fetchMock
      .mockResolvedValueOnce(new Response(JSON.stringify({
        id: 'resp_codex_prev_1',
        object: 'response',
        model: 'gpt-5.2-codex',
        status: 'completed',
        output_text: 'tool call issued',
        usage: { input_tokens: 4, output_tokens: 2, total_tokens: 6 },
      }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        id: 'resp_codex_prev_2',
        object: 'response',
        model: 'gpt-5.2-codex',
        status: 'completed',
        output_text: 'tool result accepted',
        usage: { input_tokens: 5, output_tokens: 2, total_tokens: 7 },
      }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }));

    const headers = {
      session_id: 'session-http-prev-1',
      'user-agent': 'CodexClient/1.0',
    };

    const firstResponse = await app.inject({
      method: 'POST',
      url: '/v1/responses',
      headers,
      payload: {
        model: 'gpt-5.2-codex',
        input: 'start codex tool flow',
      },
    });
    expect(firstResponse.statusCode).toBe(200);

    const secondResponse = await app.inject({
      method: 'POST',
      url: '/v1/responses',
      headers,
      payload: {
        model: 'gpt-5.2-codex',
        input: [
          {
            id: 'tool_out_1',
            type: 'function_call_output',
            call_id: 'call_1',
            output: '{"ok":true}',
          },
        ],
      },
    });

    expect(secondResponse.statusCode).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(2);

    const [, secondOptions] = fetchMock.mock.calls[1] as [string, any];
    const secondBody = JSON.parse(secondOptions.body);
    expect(secondBody.previous_response_id).toBe('resp_codex_prev_1');
    expect(secondBody.input).toEqual([
      {
        id: 'tool_out_1',
        type: 'function_call_output',
        call_id: 'call_1',
        output: '{"ok":true}',
      },
    ]);
  });

  it('drops stale previous_response_id and retries codex responses requests once', async () => {
    fetchMock
      .mockResolvedValueOnce(new Response(JSON.stringify({
        error: {
          message: 'previous_response_not_found',
          code: 'previous_response_not_found',
          type: 'invalid_request_error',
        },
      }), {
        status: 400,
        headers: { 'content-type': 'application/json' },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        id: 'resp_codex_prev_recovered',
        object: 'response',
        model: 'gpt-5.2-codex',
        status: 'completed',
        output_text: 'recovered after dropping stale previous_response_id',
        usage: { input_tokens: 5, output_tokens: 2, total_tokens: 7 },
      }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/responses',
      headers: {
        session_id: 'session-http-prev-recovery',
      },
      payload: {
        model: 'gpt-5.2-codex',
        previous_response_id: 'resp_stale',
        input: [
          {
            id: 'tool_out_retry_1',
            type: 'function_call_output',
            call_id: 'call_retry_1',
            output: '{"retry":true}',
          },
        ],
      },
    });

    expect(response.statusCode).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(2);

    const [, firstOptions] = fetchMock.mock.calls[0] as [string, any];
    const [, secondOptions] = fetchMock.mock.calls[1] as [string, any];
    const firstBody = JSON.parse(firstOptions.body);
    const secondBody = JSON.parse(secondOptions.body);

    expect(firstBody.previous_response_id).toBe('resp_stale');
    expect(secondBody.previous_response_id).toBeUndefined();
    expect(secondBody.input).toEqual(firstBody.input);
  });

  it('strips generic downstream headers before forwarding codex responses upstream', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      id: 'resp_codex_header_filter',
      object: 'response',
      model: 'gpt-5.2-codex',
      status: 'completed',
      output_text: 'ok with filtered headers',
      usage: { input_tokens: 4, output_tokens: 2, total_tokens: 6 },
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/responses',
      headers: {
        'openai-beta': 'responses-2025-03-11',
        'x-openai-client-user-agent': '{"client":"openclaw"}',
        origin: 'https://openclaw.example',
        referer: 'https://openclaw.example/app',
        'user-agent': 'OpenClaw/1.0',
        version: '0.202.0',
        session_id: 'session-from-client',
      },
      payload: {
        model: 'gpt-5.2-codex',
        input: 'hello codex',
      },
    });

    expect(response.statusCode).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(1);

    const [, options] = fetchMock.mock.calls[0] as [string, any];
    expect(options.headers.Version || options.headers.version).toBe('0.202.0');
    expect(options.headers.Session_id || options.headers.session_id).toBe('session-from-client');
    expect(options.headers['User-Agent'] || options.headers['user-agent']).toBe('OpenClaw/1.0');
    expect(options.headers['openai-beta']).toBeUndefined();
    expect(options.headers['x-openai-client-user-agent']).toBeUndefined();
    expect(options.headers.origin).toBeUndefined();
    expect(options.headers.referer).toBeUndefined();
  });

  it('serializes concurrent codex HTTP responses requests that share the same session id', async () => {
    const firstUpstream = createDeferred<Response>();
    fetchMock
      .mockImplementationOnce(() => firstUpstream.promise)
      .mockResolvedValueOnce(new Response(JSON.stringify({
        id: 'resp_codex_serial_2',
        object: 'response',
        model: 'gpt-5.2-codex',
        status: 'completed',
        output_text: 'second request finished',
        usage: { input_tokens: 4, output_tokens: 2, total_tokens: 6 },
      }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }));

    const firstResponsePromise = app.inject({
      method: 'POST',
      url: '/v1/responses',
      headers: {
        session_id: 'session-http-serial-1',
      },
      payload: {
        model: 'gpt-5.2-codex',
        input: 'first request',
      },
    });

    await waitFor(() => fetchMock.mock.calls.length === 1);

    const secondResponsePromise = app.inject({
      method: 'POST',
      url: '/v1/responses',
      headers: {
        session_id: 'session-http-serial-1',
      },
      payload: {
        model: 'gpt-5.2-codex',
        input: 'second request',
      },
    });

    await new Promise((resolve) => setTimeout(resolve, 0));
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(fetchMock).toHaveBeenCalledTimes(1);

    firstUpstream.resolve(new Response(JSON.stringify({
      id: 'resp_codex_serial_1',
      object: 'response',
      model: 'gpt-5.2-codex',
      status: 'completed',
      output_text: 'first request finished',
      usage: { input_tokens: 4, output_tokens: 2, total_tokens: 6 },
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const firstResponse = await firstResponsePromise;
    expect(firstResponse.statusCode).toBe(200);
    expect(firstResponse.json()).toMatchObject({
      output_text: 'first request finished',
    });

    await waitFor(() => fetchMock.mock.calls.length === 2);

    const secondResponse = await secondResponsePromise;
    expect(secondResponse.statusCode).toBe(200);
    expect(secondResponse.json()).toMatchObject({
      output_text: 'second request finished',
    });

    const [, firstOptions] = fetchMock.mock.calls[0] as [string, any];
    const [, secondOptions] = fetchMock.mock.calls[1] as [string, any];
    expect(firstOptions.headers.Session_id || firstOptions.headers.session_id).toBe('session-http-serial-1');
    expect(secondOptions.headers.Session_id || secondOptions.headers.session_id).toBe('session-http-serial-1');
  });

  it('does not gate codex responses requests without a downstream session id behind the session lease queue', async () => {
    config.proxyStickySessionEnabled = true;
    config.proxySessionChannelConcurrencyLimit = 1;
    config.proxySessionChannelQueueWaitMs = 20;

    const firstUpstream = createDeferred<Response>();
    fetchMock
      .mockImplementationOnce(() => firstUpstream.promise)
      .mockResolvedValueOnce(new Response(JSON.stringify({
        id: 'resp_codex_parallel_2',
        object: 'response',
        model: 'gpt-5.2-codex',
        status: 'completed',
        output_text: 'second request finished',
        usage: { input_tokens: 4, output_tokens: 2, total_tokens: 6 },
      }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }));

    const firstResponsePromise = app.inject({
      method: 'POST',
      url: '/v1/responses',
      payload: {
        model: 'gpt-5.2-codex',
        input: 'first request',
      },
    });

    await waitFor(() => fetchMock.mock.calls.length === 1);

    const secondResponsePromise = app.inject({
      method: 'POST',
      url: '/v1/responses',
      payload: {
        model: 'gpt-5.2-codex',
        input: 'second request',
      },
    });

    await waitFor(() => fetchMock.mock.calls.length === 2);

    firstUpstream.resolve(new Response(JSON.stringify({
      id: 'resp_codex_parallel_1',
      object: 'response',
      model: 'gpt-5.2-codex',
      status: 'completed',
      output_text: 'first request finished',
      usage: { input_tokens: 4, output_tokens: 2, total_tokens: 6 },
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const [firstResponse, secondResponse] = await Promise.all([
      firstResponsePromise,
      secondResponsePromise,
    ]);
    expect(firstResponse.statusCode).toBe(200);
    expect(secondResponse.statusCode).toBe(200);
  });

  it('records codex usage_limit_reached reset hints on upstream 429 failures', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      error: {
        type: 'usage_limit_reached',
        resets_at: 1773800400,
        message: 'quota exceeded',
      },
    }), {
      status: 429,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/responses',
      payload: {
        model: 'gpt-5.2-codex',
        input: 'hello codex',
      },
    });

    expect(response.statusCode).toBe(429);
    expect(recordOauthQuotaResetHintMock).toHaveBeenCalledWith({
      accountId: 33,
      statusCode: 429,
      errorText: JSON.stringify({
        error: {
          type: 'usage_limit_reached',
          resets_at: 1773800400,
          message: 'quota exceeded',
        },
      }),
    });
  });

  it('forces codex upstream responses requests to stream and aggregates the SSE payload for non-stream downstream callers', async () => {
    fetchMock.mockResolvedValue(createSseResponse([
      'event: response.created\n',
      'data: {"type":"response.created","response":{"id":"resp_codex_stream","model":"gpt-5.4","created_at":1706000000,"status":"in_progress","output":[]}}\n\n',
      'event: response.output_item.added\n',
      'data: {"type":"response.output_item.added","output_index":0,"item":{"id":"msg_codex_stream","type":"message","role":"assistant","status":"in_progress","content":[]}}\n\n',
      'event: response.output_text.delta\n',
      'data: {"type":"response.output_text.delta","output_index":0,"item_id":"msg_codex_stream","delta":"pong"}\n\n',
      'event: response.completed\n',
      'data: {"type":"response.completed","response":{"id":"resp_codex_stream","model":"gpt-5.4","status":"completed","usage":{"input_tokens":3,"output_tokens":1,"total_tokens":4}}}\n\n',
      'data: [DONE]\n\n',
    ]));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/responses',
      payload: {
        model: 'gpt-5.4',
        input: 'hello codex',
      },
    });

    expect(response.statusCode).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(1);

    const [, options] = fetchMock.mock.calls[0] as [string, any];
    const forwardedBody = JSON.parse(options.body);
    expect(forwardedBody.stream).toBe(true);
    expect(forwardedBody.instructions).toBe('');
    expect(forwardedBody.store).toBe(false);
    expect(forwardedBody.max_output_tokens).toBeUndefined();

    expect(response.json()).toMatchObject({
      id: 'resp_codex_stream',
      model: 'gpt-5.4',
      status: 'completed',
      output_text: 'pong',
      usage: {
        input_tokens: 3,
        output_tokens: 1,
        total_tokens: 4,
      },
    });
  });

  it('rebinds sticky channels after websocket transport fast-path successes', async () => {
    config.proxyStickySessionEnabled = true;

    const selected = {
      channel: { id: 11, routeId: 22 },
      site: { name: 'codex-site', url: 'https://chatgpt.com/backend-api/codex', platform: 'codex' },
      account: {
        id: 33,
        username: 'codex-user@example.com',
        extraConfig: JSON.stringify({
          credentialMode: 'session',
          oauth: {
            provider: 'codex',
            accountId: 'chatgpt-account-123',
            email: 'codex-user@example.com',
            planType: 'plus',
          },
        }),
      },
      tokenName: 'default',
      tokenValue: 'expired-access-token',
      actualModel: 'gpt-5.2-codex',
    };
    selectChannelMock.mockReturnValue(selected);
    selectPreferredChannelMock.mockReturnValue(selected);

    const stickyHeaders = {
      'x-metapi-responses-websocket-transport': '1',
      session_id: 'session-sticky-fast-path-1',
    };
    const ssePayload = createSseResponse([
      'event: response.created\n',
      'data: {"type":"response.created","response":{"id":"resp_codex_fast_path","model":"gpt-5.4","created_at":1706000000,"status":"in_progress","output":[]}}\n\n',
      'event: response.completed\n',
      'data: {"type":"response.completed","response":{"id":"resp_codex_fast_path","model":"gpt-5.4","status":"completed","usage":{"input_tokens":3,"output_tokens":1,"total_tokens":4}}}\n\n',
      'data: [DONE]\n\n',
    ]);
    fetchMock.mockResolvedValue(ssePayload);

    const firstResponse = await app.inject({
      method: 'POST',
      url: '/v1/responses',
      headers: stickyHeaders,
      payload: {
        model: 'gpt-5.4',
        input: 'hello codex',
        stream: true,
      },
    });

    expect(firstResponse.statusCode).toBe(200);
    expect(firstResponse.body).toContain('event: response.completed');
    expect(selectPreferredChannelMock).not.toHaveBeenCalled();

    const secondResponse = await app.inject({
      method: 'POST',
      url: '/v1/responses',
      headers: stickyHeaders,
      payload: {
        model: 'gpt-5.4',
        input: 'hello again',
        stream: true,
      },
    });

    expect(secondResponse.statusCode).toBe(200);
    expect(selectPreferredChannelMock).toHaveBeenCalledTimes(1);
    expect(selectPreferredChannelMock.mock.calls[0]?.[0]).toBe('gpt-5.4');
    expect(selectPreferredChannelMock.mock.calls[0]?.[1]).toBe(11);
  });

  it('decodes zstd-compressed codex responses SSE before relaying native downstream streams', async () => {
    fetchMock.mockResolvedValue(createCompressedSseResponse([
      'event: response.created\n',
      'data: {"type":"response.created","response":{"id":"resp_codex_zstd_stream","model":"gpt-5.4","created_at":1706000000,"status":"in_progress","output":[]}}\n\n',
      'event: response.output_item.added\n',
      'data: {"type":"response.output_item.added","output_index":0,"item":{"id":"msg_codex_zstd_stream","type":"message","role":"assistant","status":"in_progress","content":[]}}\n\n',
      'event: response.output_text.delta\n',
      'data: {"type":"response.output_text.delta","output_index":0,"item_id":"msg_codex_zstd_stream","delta":"你好，来自 zstd responses SSE"}\n\n',
      'event: response.completed\n',
      'data: {"type":"response.completed","response":{"id":"resp_codex_zstd_stream","model":"gpt-5.4","status":"completed","usage":{"input_tokens":3,"output_tokens":1,"total_tokens":4}}}\n\n',
      'data: [DONE]\n\n',
    ]));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/responses',
      payload: {
        model: 'gpt-5.4',
        input: 'hello codex',
        stream: true,
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.body).toContain('event: response.output_text.delta');
    expect(response.body).toContain('你好，来自 zstd responses SSE');
    expect(response.body).not.toContain('(�/�');
    expect(response.body).toContain('data: [DONE]');
  });

  it('preserves codex-required instructions and store fields across responses compatibility retries', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      error: { message: 'upstream_error', type: 'upstream_error' },
    }), {
      status: 400,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/responses',
      payload: {
        model: 'gpt-5.2-codex',
        input: 'hello codex',
        metadata: { trace: 'compatibility-retry' },
      },
    });

    expect(response.statusCode).toBe(400);
    expect(fetchMock.mock.calls.length).toBeGreaterThanOrEqual(2);

    const [, firstOptions] = fetchMock.mock.calls[0] as [string, any];
    const [, secondOptions] = fetchMock.mock.calls[1] as [string, any];
    const firstBody = JSON.parse(firstOptions.body);
    const secondBody = JSON.parse(secondOptions.body);

    expect(firstBody.instructions).toBe('');
    expect(firstBody.store).toBe(false);
    expect(firstBody.stream).toBe(true);
    expect(firstBody.max_output_tokens).toBeUndefined();
    expect(secondBody.instructions).toBe('');
    expect(secondBody.store).toBe(false);
    expect(secondBody.stream).toBe(true);
    expect(secondBody.max_output_tokens).toBeUndefined();
  });

  it('does not record success when a streaming responses request ends with response.failed', async () => {
    fetchMock.mockResolvedValue(createSseResponse([
      'event: response.created\n',
      'data: {"type":"response.created","response":{"id":"resp_codex_failed","model":"gpt-5.4","created_at":1706000000,"status":"in_progress","output":[]}}\n\n',
      'event: response.failed\n',
      'data: {"type":"response.failed","response":{"id":"resp_codex_failed","model":"gpt-5.4","status":"failed","error":{"message":"tool execution failed"}}}\n\n',
      'data: [DONE]\n\n',
    ]));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/responses',
      payload: {
        model: 'gpt-5.4',
        input: 'hello codex',
        stream: true,
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.body).toContain('response.failed');
    expect(response.body).not.toContain('response.completed');
    expect(recordSuccessMock).not.toHaveBeenCalled();
    expect(recordFailureMock).toHaveBeenCalledTimes(1);
    expect(insertedProxyLogs.at(-1)).toMatchObject({
      status: 'failed',
      httpStatus: 200,
    });
    expect(String(insertedProxyLogs.at(-1)?.errorMessage || '')).toContain('tool execution failed');
  });

  it('does not record success when a native responses stream closes before response.completed', async () => {
    fetchMock.mockResolvedValue(createSseResponse([
      'event: response.created\n',
      'data: {"type":"response.created","response":{"id":"resp_codex_truncated","model":"gpt-5.4","created_at":1706000000,"status":"in_progress","output":[]}}\n\n',
      'event: response.output_item.added\n',
      'data: {"type":"response.output_item.added","output_index":0,"item":{"id":"msg_codex_truncated","type":"message","role":"assistant","status":"in_progress","content":[]}}\n\n',
      'event: response.output_text.delta\n',
      'data: {"type":"response.output_text.delta","output_index":0,"item_id":"msg_codex_truncated","delta":"partial"}\n\n',
      'data: [DONE]\n\n',
    ]));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/responses',
      payload: {
        model: 'gpt-5.4',
        input: 'hello codex',
        stream: true,
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.body).toContain('event: response.failed');
    expect(response.body).not.toContain('event: response.completed');
    expect(recordSuccessMock).not.toHaveBeenCalled();
    expect(recordFailureMock).toHaveBeenCalledTimes(1);
    expect(insertedProxyLogs.at(-1)).toMatchObject({
      status: 'failed',
      httpStatus: 200,
    });
    expect(String(insertedProxyLogs.at(-1)?.errorMessage || '')).toContain('stream closed before response.completed');
  });

  it('does not record success when a native responses stream completes with empty content and empty usage while empty-content failure is enabled', async () => {
    config.proxyEmptyContentFailEnabled = true;

    fetchMock.mockResolvedValue(createSseResponse([
      'event: response.created\n',
      'data: {"type":"response.created","response":{"id":"resp_codex_empty","model":"gpt-5.4","created_at":1706000000,"status":"in_progress","output":[]}}\n\n',
      'event: response.completed\n',
      'data: {"type":"response.completed","response":{"id":"resp_codex_empty","model":"gpt-5.4","status":"completed","output":[],"usage":{"input_tokens":0,"output_tokens":0,"total_tokens":0}}}\n\n',
      'data: [DONE]\n\n',
    ]));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/responses',
      payload: {
        model: 'gpt-5.4',
        input: 'hello codex',
        stream: true,
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.body).toContain('event: response.failed');
    expect(response.body).not.toContain('event: response.completed');
    expect(recordSuccessMock).not.toHaveBeenCalled();
    expect(recordFailureMock).toHaveBeenCalledTimes(1);
    expect(insertedProxyLogs.at(-1)).toMatchObject({
      status: 'failed',
      httpStatus: 200,
    });
    expect(String(insertedProxyLogs.at(-1)?.errorMessage || '')).toContain('empty content');
  });

  it('does not record success when a native responses stream completes with prompt tokens only and no output', async () => {
    config.proxyEmptyContentFailEnabled = true;

    fetchMock.mockResolvedValue(createSseResponse([
      'event: response.created\n',
      'data: {"type":"response.created","response":{"id":"resp_codex_prompt_only","model":"gpt-5.4","created_at":1706000000,"status":"in_progress","output":[]}}\n\n',
      'event: response.completed\n',
      'data: {"type":"response.completed","response":{"id":"resp_codex_prompt_only","model":"gpt-5.4","status":"completed","output":[],"output_text":"","usage":{"input_tokens":5,"output_tokens":0,"total_tokens":5}}}\n\n',
      'data: [DONE]\n\n',
    ]));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/responses',
      payload: {
        model: 'gpt-5.4',
        input: 'hello codex',
        stream: true,
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.body).toContain('event: response.failed');
    expect(response.body).not.toContain('event: response.completed');
    expect(recordSuccessMock).not.toHaveBeenCalled();
    expect(recordFailureMock).toHaveBeenCalledTimes(1);
    expect(insertedProxyLogs.at(-1)).toMatchObject({
      status: 'failed',
      httpStatus: 200,
    });
    expect(String(insertedProxyLogs.at(-1)?.errorMessage || '')).toContain('empty content');
  });

  it('does not retry or mark failure after converting a non-stream upstream payload into SSE when post-stream usage accounting fails', async () => {
    resolveProxyUsageWithSelfLogFallbackMock.mockRejectedValueOnce(new Error('usage accounting failed'));
    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      id: 'resp_nonstream_final',
      object: 'response',
      model: 'gpt-5.4',
      status: 'completed',
      output: [
        {
          id: 'msg_nonstream_final',
          type: 'message',
          role: 'assistant',
          status: 'completed',
          content: [
            {
              type: 'output_text',
              text: 'pong',
            },
          ],
        },
      ],
      output_text: 'pong',
      usage: { input_tokens: 3, output_tokens: 1, total_tokens: 4 },
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/responses',
      payload: {
        model: 'gpt-5.4',
        input: 'hello codex',
        stream: true,
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.body).toContain('event: response.completed');
    expect(response.body).toContain('"output_text":"pong"');
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(recordFailureMock).not.toHaveBeenCalled();
    expect(recordSuccessMock).toHaveBeenCalledTimes(1);
  });

  it('does not retry or mark failure after streaming SSE success when post-stream usage accounting fails', async () => {
    resolveProxyUsageWithSelfLogFallbackMock.mockRejectedValueOnce(new Error('usage accounting failed'));
    fetchMock.mockResolvedValue(createSseResponse([
      'event: response.created\n',
      'data: {"type":"response.created","response":{"id":"resp_codex_stream_ok","model":"gpt-5.4","created_at":1706000000,"status":"in_progress","output":[]}}\n\n',
      'event: response.output_item.added\n',
      'data: {"type":"response.output_item.added","output_index":0,"item":{"id":"msg_codex_stream_ok","type":"message","role":"assistant","status":"in_progress","content":[]}}\n\n',
      'event: response.output_text.delta\n',
      'data: {"type":"response.output_text.delta","output_index":0,"item_id":"msg_codex_stream_ok","delta":"pong"}\n\n',
      'event: response.completed\n',
      'data: {"type":"response.completed","response":{"id":"resp_codex_stream_ok","model":"gpt-5.4","status":"completed","usage":{"input_tokens":3,"output_tokens":1,"total_tokens":4}}}\n\n',
      'data: [DONE]\n\n',
    ]));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/responses',
      payload: {
        model: 'gpt-5.4',
        input: 'hello codex',
        stream: true,
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.body).toContain('event: response.completed');
    expect(response.body).toContain('"id":"resp_codex_stream_ok"');
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(recordFailureMock).not.toHaveBeenCalled();
    expect(recordSuccessMock).toHaveBeenCalledTimes(1);
  });

  it('replays raw codex SSE when upstream mislabels a streaming responses body as application/json', async () => {
    fetchMock.mockResolvedValue(new Response([
      'event: response.created\n',
      'data: {"type":"response.created","response":{"id":"resp_codex_stream_header_miss","model":"gpt-5.4","created_at":1706000000,"status":"in_progress","output":[]}}\n\n',
      'event: response.output_item.added\n',
      'data: {"type":"response.output_item.added","output_index":0,"item":{"id":"msg_codex_stream_header_miss","type":"message","role":"assistant","status":"in_progress","content":[]}}\n\n',
      'event: response.output_text.delta\n',
      'data: {"type":"response.output_text.delta","output_index":0,"item_id":"msg_codex_stream_header_miss","delta":"pong"}\n\n',
      'event: response.completed\n',
      'data: {"type":"response.completed","response":{"id":"resp_codex_stream_header_miss","model":"gpt-5.4","status":"completed","usage":{"input_tokens":3,"output_tokens":1,"total_tokens":4}}}\n\n',
      'data: [DONE]\n\n',
    ].join(''), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/responses',
      payload: {
        model: 'gpt-5.4',
        input: 'hello codex',
        stream: true,
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.body).toContain('event: response.output_text.delta');
    expect(response.body).toContain('"delta":"pong"');
    expect(response.body).not.toContain('"output_text":"event: response.created');
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(recordFailureMock).not.toHaveBeenCalled();
    expect(recordSuccessMock).toHaveBeenCalledTimes(1);
  });
});
