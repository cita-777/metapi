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
const saveProxyVideoTaskMock = vi.fn();
const getProxyVideoTaskByPublicIdMock = vi.fn();
const deleteProxyVideoTaskByPublicIdMock = vi.fn();
const refreshProxyVideoTaskSnapshotMock = vi.fn();

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
  RETRYABLE_TIMEOUT_PATTERNS: [/(request timed out|connection timed out|read timeout|\btimed out\b)/i],
}));

vi.mock('../../services/proxyVideoTaskStore.js', () => ({
  saveProxyVideoTask: (...args: unknown[]) => saveProxyVideoTaskMock(...args),
  getProxyVideoTaskByPublicId: (...args: unknown[]) => getProxyVideoTaskByPublicIdMock(...args),
  deleteProxyVideoTaskByPublicId: (...args: unknown[]) => deleteProxyVideoTaskByPublicIdMock(...args),
  refreshProxyVideoTaskSnapshot: (...args: unknown[]) => refreshProxyVideoTaskSnapshotMock(...args),
}));

vi.mock('../../db/index.js', () => ({
  db: {
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
  schema: {
    siteApiEndpoints: {
      id: {},
      siteId: {},
      sortOrder: {},
    },
  },
}));

describe('/v1/videos routes', () => {
  let app: FastifyInstance;

  const buildMultipartBody = (boundary: string) => Buffer.from(
    `--${boundary}\r\n`
      + `Content-Disposition: form-data; name="model"\r\n\r\n`
      + `sora-2\r\n`
      + `--${boundary}\r\n`
      + `Content-Disposition: form-data; name="prompt"\r\n\r\n`
      + `a cat walking\r\n`
      + `--${boundary}\r\n`
      + `Content-Disposition: form-data; name="input_reference"; filename="cat.png"\r\n`
      + `Content-Type: image/png\r\n\r\n`
      + `pngdata\r\n`
      + `--${boundary}--\r\n`,
  );

  beforeAll(async () => {
    const { videosProxyRoute } = await import('./videos.js');
    app = Fastify();
    await app.register(videosProxyRoute);
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
    saveProxyVideoTaskMock.mockReset();
    getProxyVideoTaskByPublicIdMock.mockReset();
    deleteProxyVideoTaskByPublicIdMock.mockReset();
    refreshProxyVideoTaskSnapshotMock.mockReset();

    selectChannelMock.mockReturnValue({
      channel: { id: 11, routeId: 22 },
      site: { id: 44, name: 'demo-site', url: 'https://upstream.example.com', platform: 'openai' },
      account: { id: 33, username: 'demo-user' },
      tokenName: 'default',
      tokenValue: 'sk-demo',
      actualModel: 'sora-2',
    });
    selectNextChannelMock.mockReturnValue(null);
  });

  afterAll(async () => {
    if (app) {
      await app.close();
    }
  });

  it('creates an upstream video task and stores a local public id mapping', async () => {
    saveProxyVideoTaskMock.mockResolvedValue({
      publicId: 'vid_local_123',
      upstreamVideoId: 'vid_upstream_123',
    });
    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      id: 'vid_upstream_123',
      object: 'video',
      status: 'queued',
      model: 'sora-2',
      prompt: 'a cat walking',
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/videos',
      payload: {
        model: 'sora-2',
        prompt: 'a cat walking',
      },
    });

    expect(response.statusCode).toBe(200);
    expect(saveProxyVideoTaskMock).toHaveBeenCalledWith(expect.objectContaining({
      upstreamVideoId: 'vid_upstream_123',
      requestedModel: 'sora-2',
      actualModel: 'sora-2',
      lastUpstreamStatus: 200,
      statusSnapshot: expect.objectContaining({
        id: 'vid_upstream_123',
        status: 'queued',
      }),
    }));
    expect(response.json()).toMatchObject({
      id: 'vid_local_123',
      object: 'video',
      status: 'queued',
    });
  });

  it('accepts multipart video create requests', async () => {
    saveProxyVideoTaskMock.mockResolvedValue({
      publicId: 'vid_local_456',
      upstreamVideoId: 'vid_upstream_456',
    });
    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      id: 'vid_upstream_456',
      object: 'video',
      status: 'queued',
      model: 'sora-2',
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const boundary = 'metapi-video-boundary';
    const response = await app.inject({
      method: 'POST',
      url: '/v1/videos',
      headers: {
        'content-type': `multipart/form-data; boundary=${boundary}`,
      },
      payload: buildMultipartBody(boundary),
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      id: 'vid_local_456',
      object: 'video',
      status: 'queued',
    });
  });

  it('resolves local video ids back to the upstream task on GET', async () => {
    getProxyVideoTaskByPublicIdMock.mockResolvedValue({
      publicId: 'vid_local_123',
      upstreamVideoId: 'vid_upstream_123',
      siteUrl: 'https://upstream.example.com',
      tokenValue: 'sk-demo',
    });
    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      id: 'vid_upstream_123',
      object: 'video',
      status: 'running',
      model: 'sora-2',
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'GET',
      url: '/v1/videos/vid_local_123',
    });

    expect(response.statusCode).toBe(200);
    const [targetUrl] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(targetUrl).toBe('https://upstream.example.com/v1/videos/vid_upstream_123');
    expect(refreshProxyVideoTaskSnapshotMock).toHaveBeenCalledWith('vid_local_123', expect.objectContaining({
      lastUpstreamStatus: 200,
      statusSnapshot: expect.objectContaining({
        id: 'vid_upstream_123',
        status: 'running',
      }),
    }));
    expect(response.json()).toMatchObject({
      id: 'vid_local_123',
      object: 'video',
      status: 'running',
    });
  });

  it('deletes the upstream task and local mapping on DELETE', async () => {
    getProxyVideoTaskByPublicIdMock.mockResolvedValue({
      publicId: 'vid_local_123',
      upstreamVideoId: 'vid_upstream_123',
      siteUrl: 'https://upstream.example.com',
      tokenValue: 'sk-demo',
    });
    fetchMock.mockResolvedValue(new Response(null, { status: 204 }));

    const response = await app.inject({
      method: 'DELETE',
      url: '/v1/videos/vid_local_123',
    });

    expect(response.statusCode).toBe(204);
    expect(deleteProxyVideoTaskByPublicIdMock).toHaveBeenCalledWith('vid_local_123');
  });
});
