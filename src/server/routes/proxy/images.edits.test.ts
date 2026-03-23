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

function buildMultipartBody(boundary: string) {
  return Buffer.from(
    `--${boundary}\r\n`
      + `Content-Disposition: form-data; name="model"\r\n\r\n`
      + `gpt-image-1\r\n`
      + `--${boundary}\r\n`
      + `Content-Disposition: form-data; name="prompt"\r\n\r\n`
      + `edit this\r\n`
      + `--${boundary}\r\n`
      + `Content-Disposition: form-data; name="image"; filename="cat.png"\r\n`
      + `Content-Type: image/png\r\n\r\n`
      + `pngdata\r\n`
      + `--${boundary}--\r\n`,
  );
}

describe('/v1/images/edits route', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    const { imagesProxyRoute } = await import('./images.js');
    app = Fastify();
    await app.register(imagesProxyRoute);
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
      actualModel: 'upstream-gpt-image',
    });
    selectNextChannelMock.mockReturnValue(null);
  });

  afterAll(async () => {
    await app.close();
  });

  it('accepts multipart image edit requests and forwards them to /v1/images/edits', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      created: 1,
      data: [{ b64_json: 'iVBORw0KGgo=' }],
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const boundary = 'metapi-boundary';
    const response = await app.inject({
      method: 'POST',
      url: '/v1/images/edits',
      headers: {
        authorization: 'Bearer sk-demo',
        'content-type': `multipart/form-data; boundary=${boundary}`,
      },
      payload: buildMultipartBody(boundary),
    });

    expect(response.statusCode).toBe(200);
    const [targetUrl] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(targetUrl).toBe('https://upstream.example.com/v1/images/edits');
  });

  it('retries the next channel when image generation JSON is malformed', async () => {
    selectNextChannelMock.mockReturnValueOnce({
      channel: { id: 12, routeId: 23 },
      site: { id: 45, name: 'fallback-site', url: 'https://fallback.example.com', platform: 'openai' },
      account: { id: 34, username: 'fallback-user' },
      tokenName: 'fallback',
      tokenValue: 'sk-fallback',
      actualModel: 'fallback-gpt-image',
    });
    fetchMock
      .mockResolvedValueOnce(new Response('not-json', {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        created: 2,
        data: [{ b64_json: 'ZmFsbGJhY2s=' }],
      }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/images/generations',
      headers: {
        authorization: 'Bearer sk-demo',
      },
      payload: {
        model: 'gpt-image-1',
        prompt: 'draw a cat',
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      created: 2,
      data: [{ b64_json: 'ZmFsbGJhY2s=' }],
    });
    expect(selectNextChannelMock).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('keeps returning a successful image edit response when post-success accounting fails', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      created: 1,
      data: [{ b64_json: 'iVBORw0KGgo=' }],
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));
    estimateProxyCostMock.mockRejectedValueOnce(new Error('cost failed'));

    const boundary = 'metapi-boundary-accounting';
    const response = await app.inject({
      method: 'POST',
      url: '/v1/images/edits',
      headers: {
        authorization: 'Bearer sk-demo',
        'content-type': `multipart/form-data; boundary=${boundary}`,
      },
      payload: buildMultipartBody(boundary),
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      created: 1,
      data: [{ b64_json: 'iVBORw0KGgo=' }],
    });
    expect(selectNextChannelMock).not.toHaveBeenCalled();
    expect(recordFailureMock).not.toHaveBeenCalled();
  });

  it('returns explicit not-supported error for /v1/images/variations', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/v1/images/variations',
      payload: {
        model: 'gpt-image-1',
      },
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toEqual({
      error: {
        message: 'Image variations are not supported',
        type: 'invalid_request_error',
      },
    });
  });
});
