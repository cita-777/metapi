import Fastify, { type FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { config } from '../../config.js';
import { resetUpstreamEndpointRuntimeState } from '../../services/upstreamEndpointRuntimeMemory.js';

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
  shouldAbortSameSiteEndpointFallback: () => false,
  RETRYABLE_TIMEOUT_PATTERNS: [/(request timed out|connection timed out|read timeout|\btimed out\b)/i],
}));

vi.mock('../../services/proxyUsageFallbackService.js', () => ({
  resolveProxyUsageWithSelfLogFallback: (arg: any) => resolveProxyUsageWithSelfLogFallbackMock(arg),
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

describe('responses proxy compact upstream routing', () => {
  let app: FastifyInstance;
  const originalResponsesCompactFallbackToResponsesEnabled = config.responsesCompactFallbackToResponsesEnabled;

  beforeAll(async () => {
    const { responsesProxyRoute } = await import('./responses.js');
    app = Fastify();
    await app.register(responsesProxyRoute);
  });

  beforeEach(() => {
    resetUpstreamEndpointRuntimeState();
    config.responsesCompactFallbackToResponsesEnabled = false;
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

    selectChannelMock.mockReturnValue({
      channel: { id: 11, routeId: 22 },
      site: { id: 44, name: 'demo-site', url: 'https://api.openai.com', platform: 'openai' },
      account: { id: 33, username: 'demo-user' },
      tokenName: 'default',
      tokenValue: 'sk-demo',
      actualModel: 'upstream-gpt',
    });
    selectNextChannelMock.mockReturnValue(null);
    fetchModelPricingCatalogMock.mockResolvedValue(null);
  });

  afterAll(async () => {
    config.responsesCompactFallbackToResponsesEnabled = originalResponsesCompactFallbackToResponsesEnabled;
    if (app) {
      await app.close();
    }
  });

  it('forwards compact requests to the upstream /v1/responses/compact path first', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      id: 'resp_123',
      object: 'response',
      output_text: 'hello from compact',
      usage: { input_tokens: 10, output_tokens: 5, total_tokens: 15 },
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/responses/compact',
      payload: {
        model: 'gpt-5.2',
        input: 'hello',
      },
    });

    expect(response.statusCode).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [targetUrl] = fetchMock.mock.calls[0] as [string, any];
    expect(targetUrl).toContain('/v1/responses/compact');
  });

  it('keeps native compact as the default even for generic openai-compatible upstreams', async () => {
    selectChannelMock.mockReturnValue({
      channel: { id: 11, routeId: 22 },
      site: { id: 44, name: 'generic-openai-site', url: 'https://upstream.example.com', platform: 'openai' },
      account: { id: 33, username: 'demo-user' },
      tokenName: 'default',
      tokenValue: 'sk-demo',
      actualModel: 'upstream-gpt',
    });
    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      error: {
        message: 'Invalid URL (POST /v1/responses/compact)',
        type: 'invalid_request_error',
      },
    }), {
      status: 404,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/responses/compact',
      payload: {
        model: 'gpt-5.2',
        input: 'hello',
      },
    });

    expect(response.statusCode).toBe(404);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [targetUrl] = fetchMock.mock.calls[0] as [string, any];
    expect(targetUrl).toContain('/v1/responses/compact');
  });

  it('optionally falls back from compact to ordinary responses when compact is explicitly unsupported', async () => {
    config.responsesCompactFallbackToResponsesEnabled = true;
    selectChannelMock.mockReturnValue({
      channel: { id: 11, routeId: 22 },
      site: { id: 44, name: 'generic-openai-site', url: 'https://upstream.example.com', platform: 'openai' },
      account: { id: 33, username: 'demo-user' },
      tokenName: 'default',
      tokenValue: 'sk-demo',
      actualModel: 'upstream-gpt',
    });
    fetchMock
      .mockResolvedValueOnce(new Response(JSON.stringify({
        error: {
          message: 'Invalid URL (POST /v1/responses/compact)',
          type: 'invalid_request_error',
        },
      }), {
        status: 404,
        headers: { 'content-type': 'application/json' },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        id: 'resp_123',
        object: 'response',
        output_text: 'hello from fallback',
        usage: { input_tokens: 10, output_tokens: 5, total_tokens: 15 },
      }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/responses/compact',
      payload: {
        model: 'gpt-5.2',
        input: 'hello',
      },
    });

    expect(response.statusCode).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(String(fetchMock.mock.calls[0]?.[0] || '')).toContain('/v1/responses/compact');
    expect(String(fetchMock.mock.calls[1]?.[0] || '')).toContain('/v1/responses');
    expect(String(fetchMock.mock.calls[1]?.[0] || '')).not.toContain('/compact');
    expect(response.json()).toMatchObject({
      object: 'response.compaction',
    });
  });

  it('does not fall back for unrelated unsupported errors that do not mention compact', async () => {
    config.responsesCompactFallbackToResponsesEnabled = true;
    selectChannelMock.mockReturnValue({
      channel: { id: 11, routeId: 22 },
      site: { id: 44, name: 'generic-openai-site', url: 'https://upstream.example.com', platform: 'openai' },
      account: { id: 33, username: 'demo-user' },
      tokenName: 'default',
      tokenValue: 'sk-demo',
      actualModel: 'upstream-gpt',
    });
    fetchMock
      .mockResolvedValueOnce(new Response(JSON.stringify({
        error: {
          message: 'Model not supported for this account',
          type: 'invalid_request_error',
        },
      }), {
        status: 422,
        headers: { 'content-type': 'application/json' },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        id: 'resp_ignored',
        object: 'response',
        output_text: 'should not fallback',
        usage: { input_tokens: 10, output_tokens: 5, total_tokens: 15 },
      }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/responses/compact',
      payload: {
        model: 'gpt-5.2',
        input: 'hello',
      },
    });

    expect(response.statusCode).toBe(422);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(String(fetchMock.mock.calls[0]?.[0] || '')).toContain('/v1/responses/compact');
  });

  it('strips stream fields when forwarding compact requests to codex upstreams', async () => {
    selectChannelMock.mockReturnValue({
      channel: { id: 11, routeId: 22 },
      site: { id: 44, name: 'codex-site', url: 'https://chatgpt.com/backend-api/codex', platform: 'codex' },
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
      tokenValue: 'sk-demo',
      actualModel: 'gpt-5.4',
    });
    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      id: 'cmp_123',
      object: 'response.compaction',
      input_tokens: 4,
      output_tokens: 2,
      total_tokens: 6,
      output: [
        {
          id: 'rs_123',
          type: 'compaction',
          encrypted_content: 'enc-compact-payload',
        },
      ],
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/responses/compact',
      payload: {
        model: 'gpt-5.4',
        input: 'hello',
        stream_options: { include_obfuscation: true },
      },
    });

    expect(response.statusCode).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [targetUrl, options] = fetchMock.mock.calls[0] as [string, any];
    expect(targetUrl).toContain('/responses/compact');
    const forwardedBody = JSON.parse(String(options.body));
    expect(forwardedBody.stream).toBeUndefined();
    expect(forwardedBody.stream_options).toBeUndefined();
    expect(forwardedBody.instructions).toBe('');
    expect(forwardedBody.store).toBe(false);
    expect(options.headers.Accept || options.headers.accept).toBe('application/json');
  });

  it('preserves native response.compaction payloads instead of coercing them into object=response', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      id: 'cmp_123',
      object: 'response.compaction',
      input_tokens: 1234,
      output_tokens: 321,
      total_tokens: 1555,
      output: [
        {
          id: 'rs_123',
          type: 'compaction',
          encrypted_content: 'enc-compact-payload',
        },
      ],
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/responses/compact',
      payload: {
        model: 'gpt-5.2',
        input: 'hello',
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      id: 'cmp_123',
      object: 'response.compaction',
      input_tokens: 1234,
      output_tokens: 321,
      total_tokens: 1555,
      output: [
        {
          id: 'rs_123',
          type: 'compaction',
          encrypted_content: 'enc-compact-payload',
        },
      ],
    });
  });

  it('preserves native response.compaction payloads when the upstream compact surface closes via SSE', async () => {
    fetchMock.mockResolvedValue(new Response([
      'event: response.output_item.added',
      `data: ${JSON.stringify({
        type: 'response.output_item.added',
        output_index: 0,
        item: {
          id: 'rs_123',
          type: 'compaction',
          encrypted_content: 'enc-compact-payload',
        },
      })}`,
      '',
      'event: response.completed',
      `data: ${JSON.stringify({
        type: 'response.completed',
        response: {
          id: 'cmp_123',
          object: 'response.compaction',
          created_at: 1700000000,
          output: [
            {
              id: 'rs_123',
              type: 'compaction',
              encrypted_content: 'enc-compact-payload',
            },
          ],
          usage: {
            input_tokens: 1234,
            output_tokens: 321,
            total_tokens: 1555,
          },
        },
      })}`,
      '',
      'data: [DONE]',
      '',
    ].join('\n'), {
      status: 200,
      headers: { 'content-type': 'text/event-stream' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/responses/compact',
      payload: {
        model: 'gpt-5.2',
        input: 'hello',
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      id: 'cmp_123',
      object: 'response.compaction',
      created_at: 1700000000,
      output: [
        {
          id: 'rs_123',
          type: 'compaction',
          encrypted_content: 'enc-compact-payload',
        },
      ],
      usage: {
        input_tokens: 1234,
        output_tokens: 321,
        total_tokens: 1555,
      },
    });
  });

  it('collects final payloads when non-stream compact upstreams still respond with SSE final payloads directly', async () => {
    fetchMock.mockResolvedValue(new Response([
      'event: response.completed',
      'data: {"id":"cmp_sse_123","object":"response.compaction","input_tokens":12,"output_tokens":3,"total_tokens":15,"output":[{"id":"rs_123","type":"compaction","encrypted_content":"enc-from-sse"}]}',
      '',
      'data: [DONE]',
      '',
    ].join('\n'), {
      status: 200,
      headers: { 'content-type': 'text/event-stream; charset=utf-8' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/responses/compact',
      payload: {
        model: 'gpt-5.2',
        input: 'hello',
      },
    });

    expect(response.statusCode).toBe(200);
    const body = response.json();
    expect(body).toMatchObject({
      id: 'cmp_sse_123',
      object: 'response.compaction',
      input_tokens: 12,
      output_tokens: 3,
      total_tokens: 15,
      output: [
        {
          id: 'rs_123',
          type: 'compaction',
          encrypted_content: 'enc-from-sse',
        },
      ],
      usage: {
        input_tokens: 12,
        output_tokens: 3,
        total_tokens: 15,
      },
    });
    expect(body.created_at).toEqual(expect.any(Number));
  });
});
