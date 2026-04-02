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
const estimateProxyCostMock = vi.fn(async () => 0);
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
}));

vi.mock('../../services/proxyRetryPolicy.js', () => ({
  shouldRetryProxyRequest: () => false,
  shouldAbortSameSiteEndpointFallback: () => false,
  RETRYABLE_TIMEOUT_PATTERNS: [/(request timed out|connection timed out|read timeout|\btimed out\b)/i],
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

describe('/v1/search route', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    const { searchProxyRoute } = await import('./search.js');
    app = Fastify();
    await app.register(searchProxyRoute);
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
    dbInsertMock.mockClear();

    selectChannelMock.mockReturnValue({
      channel: { id: 11, routeId: 22 },
      site: { id: 44, name: 'demo-site', url: 'https://upstream.example.com', platform: 'openai' },
      account: { id: 33, username: 'demo-user' },
      tokenName: 'default',
      tokenValue: 'sk-demo',
      actualModel: '__search',
    });
    selectNextChannelMock.mockReturnValue(null);
  });

  afterAll(async () => {
    if (app) {
      await app.close();
    }
  });

  it('defaults model to __search and forwards to the upstream /v1/search endpoint', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      object: 'search.result',
      data: [{ title: 'AxonHub' }],
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/search',
      headers: {
        authorization: 'Bearer sk-demo',
      },
      payload: {
        query: 'axonhub',
      },
    });

    expect(response.statusCode).toBe(200);
    expect(selectChannelMock).toHaveBeenCalledWith('__search', expect.anything());
    const [targetUrl, requestInit] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(targetUrl).toBe('https://upstream.example.com/v1/search');
    expect(JSON.parse(String(requestInit.body))).toEqual({
      query: 'axonhub',
      max_results: 10,
      model: '__search',
    });
  });

  it('keeps returning a successful search response when channel success bookkeeping fails', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      object: 'search.result',
      data: [{ title: 'AxonHub' }],
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));
    recordSuccessMock.mockRejectedValueOnce(new Error('record success failed'));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/search',
      headers: {
        authorization: 'Bearer sk-demo',
      },
      payload: {
        query: 'axonhub',
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      object: 'search.result',
      data: [{ title: 'AxonHub' }],
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(selectNextChannelMock).not.toHaveBeenCalled();
  });

  it('rejects max_results outside the allowed range', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/v1/search',
      headers: {
        authorization: 'Bearer sk-demo',
      },
      payload: {
        query: 'axonhub',
        max_results: 21,
      },
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({
      error: {
        message: 'max_results must be an integer between 1 and 20',
        type: 'invalid_request_error',
      },
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('rejects max_results below the allowed range', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/v1/search',
      headers: {
        authorization: 'Bearer sk-demo',
      },
      payload: {
        query: 'axonhub',
        max_results: 0,
      },
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({
      error: {
        message: 'max_results must be an integer between 1 and 20',
        type: 'invalid_request_error',
      },
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('rejects streaming search requests', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/v1/search',
      headers: {
        authorization: 'Bearer sk-demo',
      },
      payload: {
        query: 'axonhub',
        stream: true,
      },
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({
      error: {
        message: 'search does not support streaming',
        type: 'invalid_request_error',
      },
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
