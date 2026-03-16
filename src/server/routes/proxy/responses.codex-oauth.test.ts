import Fastify, { type FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

const fetchMock = vi.fn();
const selectChannelMock = vi.fn();
const selectNextChannelMock = vi.fn();
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
const refreshCodexAccessTokenMock = vi.fn();
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
  isTokenExpiredError: ({ status }: { status?: number }) => status === 401,
}));

vi.mock('../../services/modelPricingService.js', () => ({
  estimateProxyCost: async () => 0,
  buildProxyBillingDetails: async () => null,
  fetchModelPricingCatalog: async () => null,
}));

vi.mock('../../services/proxyRetryPolicy.js', () => ({
  shouldRetryProxyRequest: () => false,
}));

vi.mock('../../services/proxyUsageFallbackService.js', () => ({
  resolveProxyUsageWithSelfLogFallback: (arg: any) => resolveProxyUsageWithSelfLogFallbackMock(arg),
}));

vi.mock('../../services/oauth/service.js', async () => {
  const actual = await vi.importActual<typeof import('../../services/oauth/service.js')>('../../services/oauth/service.js');
  return {
    ...actual,
    refreshCodexOauthAccessToken: (...args: unknown[]) => refreshCodexAccessTokenMock(...args),
  };
});

vi.mock('../../db/index.js', () => ({
  db: {
    insert: (arg: any) => dbInsertMock(arg),
  },
  hasProxyLogDownstreamApiKeyIdColumn: async () => false,
  schema: {
    proxyLogs: {},
  },
}));

describe('responses proxy codex oauth refresh', () => {
  let app: FastifyInstance;

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

  beforeAll(async () => {
    const { responsesProxyRoute } = await import('./responses.js');
    app = Fastify();
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
    resolveProxyUsageWithSelfLogFallbackMock.mockClear();
    refreshCodexAccessTokenMock.mockReset();
    dbInsertMock.mockClear();

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
    selectNextChannelMock.mockReturnValue(null);
    refreshCodexAccessTokenMock.mockResolvedValue({
      accessToken: 'fresh-access-token',
      accountId: 33,
      accountKey: 'chatgpt-account-123',
    });
  });

  afterAll(async () => {
    await app.close();
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
      payload: {
        model: 'gpt-5.2-codex',
        input: 'hello codex',
      },
    });

    expect(response.statusCode).toBe(200);
    expect(refreshCodexAccessTokenMock).toHaveBeenCalledWith(33);
    expect(fetchMock).toHaveBeenCalledTimes(2);

    const [firstUrl, firstOptions] = fetchMock.mock.calls[0] as [string, any];
    const [secondUrl, secondOptions] = fetchMock.mock.calls[1] as [string, any];
    expect(firstUrl).toBe('https://chatgpt.com/backend-api/codex/responses');
    expect(secondUrl).toBe('https://chatgpt.com/backend-api/codex/responses');
    expect(firstOptions.headers.Authorization).toBe('Bearer expired-access-token');
    expect(secondOptions.headers.Authorization).toBe('Bearer fresh-access-token');
    expect(secondOptions.headers.Originator || secondOptions.headers.originator).toBe('codex_cli_rs');
    expect(secondOptions.headers['Chatgpt-Account-Id'] || secondOptions.headers['chatgpt-account-id']).toBe('chatgpt-account-123');
    expect(response.json()?.output_text).toContain('ok after codex token refresh');
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
    expect(forwardedBody.stream).toBe(true);
    expect(forwardedBody.input).toEqual([
      {
        type: 'message',
        role: 'user',
        content: [{ type: 'input_text', text: 'hello codex' }],
      },
    ]);
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
    expect(secondBody.instructions).toBe('');
    expect(secondBody.store).toBe(false);
    expect(secondBody.stream).toBe(true);
  });
});
