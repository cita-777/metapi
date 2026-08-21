import Fastify, { type FastifyInstance } from 'fastify';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const fetchMock = vi.fn();
const selectChannelMock = vi.fn();
const insertProxyLogMock = vi.fn();

vi.mock('undici', async () => {
  const actual = await vi.importActual<typeof import('undici')>('undici');
  return { ...actual, fetch: (...args: unknown[]) => fetchMock(...args) };
});
vi.mock('../../proxy-core/firstByteTimeout.js', () => ({
  fetchWithObservedFirstByte: async (runner: (signal?: AbortSignal) => Promise<Response>) => runner(),
  getObservedResponseMeta: () => ({ firstByteLatencyMs: 3 }),
}));

vi.mock('../../proxy-core/channelSelection.js', () => ({
  buildForcedChannelUnavailableMessage: () => 'no channel',
  canRetryChannelSelection: () => false,
  getTesterForcedChannelId: () => null,
  selectProxyChannelForAttempt: (...args: unknown[]) => selectChannelMock(...args),
}));

vi.mock('../../services/tokenRouter.js', () => ({
  tokenRouter: {
    recordSuccess: vi.fn(),
    recordFailure: vi.fn(),
  },
}));

vi.mock('../../services/siteApiEndpointService.js', () => ({
  SiteApiEndpointRequestError: class SiteApiEndpointRequestError extends Error {
    status: number;
    firstByteLatencyMs: number | null;
    constructor(message: string, options: { status?: number; firstByteLatencyMs?: number | null } = {}) {
      super(message);
      this.status = options.status || 0;
      this.firstByteLatencyMs = options.firstByteLatencyMs ?? null;
    }
  },
  runWithSiteApiEndpointPool: async (site: { url: string }, callback: (target: { baseUrl: string }) => Promise<unknown>) => (
    callback({ baseUrl: site.url })
  ),
}));

vi.mock('../../services/alertService.js', () => ({
  reportProxyAllFailed: vi.fn(),
  reportTokenExpired: vi.fn(),
}));
vi.mock('../../services/proxyLogStore.js', () => ({ insertProxyLog: (...args: unknown[]) => insertProxyLogMock(...args) }));
vi.mock('../../services/proxyUsageFallbackService.js', () => ({
  resolveProxyUsageWithSelfLogFallback: async (input: { usage: unknown }) => ({ ...(input.usage as object), usageSource: 'upstream' }),
}));
vi.mock('./proxyBilling.js', () => ({ resolveProxyLogBilling: async () => ({ estimatedCost: 0, billingDetails: null }) }));
vi.mock('./downstreamPolicy.js', () => ({
  ensureModelAllowedForDownstreamKey: async () => true,
  getDownstreamRoutingPolicy: () => ({}),
  recordDownstreamCostUsage: vi.fn(),
}));
vi.mock('../../services/siteProxy.js', () => ({ withSiteRecordProxyRequestInit: (_site: unknown, init: RequestInit) => init }));
vi.mock('../../services/accountExtraConfig.js', () => ({ getProxyUrlFromExtraConfig: () => undefined }));

describe('/v1/rerank route', () => {
  let app: FastifyInstance;

  beforeEach(async () => {
    fetchMock.mockReset();
    selectChannelMock.mockReset();
    insertProxyLogMock.mockReset();
    if (!app) {
      const { rerankProxyRoute } = await import('./rerank.js');
      app = Fastify();
      await app.register(rerankProxyRoute);
    }
    selectChannelMock.mockResolvedValue({
      channel: { id: 11, routeId: 22 },
      site: { id: 1, name: 'coding-site', url: 'https://ark.cn-beijing.volces.com/api/coding/v3', platform: 'openai' },
      account: { id: 2, username: 'user', extraConfig: null },
      tokenName: 'default',
      tokenValue: 'sk-upstream',
      actualModel: 'bge-reranker-v2-m3',
    });
  });

  it('rejects requests without model', async () => {
    const response = await app.inject({ method: 'POST', url: '/v1/rerank', payload: { query: 'hello', documents: ['world'] } });
    expect(response.statusCode).toBe(400);
  });

  it('forwards rerank requests to the configured upstream endpoint', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ results: [{ index: 0, relevance_score: 0.9 }] }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/rerank',
      payload: { model: 'bge-reranker-v2-m3', query: 'hello', documents: ['world'] },
    });

    expect(response.statusCode).toBe(200);
    expect(fetchMock.mock.calls[0]?.[0]).toBe('https://ark.cn-beijing.volces.com/api/coding/v3/rerank');
    const init = fetchMock.mock.calls[0]?.[1] as RequestInit;
    expect(JSON.parse(String(init.body))).toMatchObject({ model: 'bge-reranker-v2-m3', query: 'hello' });
    expect(insertProxyLogMock).toHaveBeenCalledWith(expect.objectContaining({ status: 'success' }));
  });
});
