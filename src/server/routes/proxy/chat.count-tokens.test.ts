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
const startSurfaceProxyDebugTraceMock = vi.fn();
const safeUpdateSurfaceProxyDebugSelectionMock = vi.fn();
const safeUpdateSurfaceProxyDebugCandidatesMock = vi.fn();
const safeInsertSurfaceProxyDebugAttemptMock = vi.fn();
const safeFinalizeSurfaceProxyDebugTraceMock = vi.fn();
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

vi.mock('../../services/proxyDebugTraceRuntime.js', () => ({
  startSurfaceProxyDebugTrace: (...args: unknown[]) => startSurfaceProxyDebugTraceMock(...args),
  safeUpdateSurfaceProxyDebugSelection: (...args: unknown[]) => safeUpdateSurfaceProxyDebugSelectionMock(...args),
  safeUpdateSurfaceProxyDebugCandidates: (...args: unknown[]) => safeUpdateSurfaceProxyDebugCandidatesMock(...args),
  safeInsertSurfaceProxyDebugAttempt: (...args: unknown[]) => safeInsertSurfaceProxyDebugAttemptMock(...args),
  safeFinalizeSurfaceProxyDebugTrace: (...args: unknown[]) => safeFinalizeSurfaceProxyDebugTraceMock(...args),
  safeUpdateSurfaceProxyDebugAttempt: vi.fn(),
  reserveSurfaceProxyDebugAttemptBase: () => 0,
  buildSurfaceProxyDebugResponseHeaders: () => ({}),
  captureSurfaceProxyDebugSuccessResponseBody: async () => null,
  parseSurfaceProxyDebugTextPayload: (raw: string) => raw,
}));

vi.mock('../../services/oauth/quota.js', () => ({
  recordOauthQuotaResetHint: async () => undefined,
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

describe('claude count_tokens proxy route', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    const { claudeMessagesProxyRoute } = await import('./chat.js');
    app = Fastify();
    await app.register(claudeMessagesProxyRoute);
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
    startSurfaceProxyDebugTraceMock.mockReset();
    safeUpdateSurfaceProxyDebugSelectionMock.mockReset();
    safeUpdateSurfaceProxyDebugCandidatesMock.mockReset();
    safeInsertSurfaceProxyDebugAttemptMock.mockReset();
    safeFinalizeSurfaceProxyDebugTraceMock.mockReset();
    dbInsertMock.mockClear();

    startSurfaceProxyDebugTraceMock.mockResolvedValue({
      traceId: 701,
      options: {
        enabled: true,
        captureHeaders: true,
        captureBodies: true,
        captureStreamChunks: false,
        targetSessionId: '',
        targetClientKind: '',
        targetModel: '',
        retentionHours: 24,
        maxBodyBytes: 262144,
      },
    });

    selectChannelMock.mockReturnValue({
      channel: { id: 11, routeId: 22 },
      site: { name: 'claude-site', url: 'https://api.anthropic.com', platform: 'claude' },
      account: { id: 33, username: 'claude-user@example.com' },
      tokenName: 'default',
      tokenValue: 'sk-claude',
      actualModel: 'claude-opus-4-6',
    });
    selectNextChannelMock.mockReturnValue(null);
  });

  afterAll(async () => {
    if (app) {
      await app.close();
    }
  });

  it('forwards /v1/messages/count_tokens to the claude count_tokens upstream path', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      input_tokens: 42,
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/messages/count_tokens',
      payload: {
        model: 'claude-opus-4-6',
        tools: [
          { name: 'lookup', input_schema: { type: 'object' } },
        ],
        messages: [
          {
            role: 'user',
            content: [{ type: 'text', text: 'count these tokens' }],
          },
        ],
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ input_tokens: 42 });
    expect(fetchMock).toHaveBeenCalledTimes(1);

    const [targetUrl, options] = fetchMock.mock.calls[0] as [string, any];
    expect(targetUrl).toBe('https://api.anthropic.com/v1/messages/count_tokens?beta=true');
    expect(options.headers['anthropic-version']).toBe('2023-06-01');
    expect(options.headers['anthropic-beta']).toContain('claude-code-20250219');
    expect(options.headers['Accept-Encoding']).toBe('gzip, deflate, br, zstd');
    expect(startSurfaceProxyDebugTraceMock).toHaveBeenCalledWith(expect.objectContaining({
      downstreamPath: '/v1/messages/count_tokens',
      requestedModel: 'claude-opus-4-6',
    }));
    expect(safeInsertSurfaceProxyDebugAttemptMock).toHaveBeenCalled();
    expect(safeFinalizeSurfaceProxyDebugTraceMock).toHaveBeenCalledWith(
      expect.objectContaining({ traceId: 701 }),
      expect.objectContaining({
        finalStatus: 'success',
        finalUpstreamPath: '/v1/messages/count_tokens?beta=true',
      }),
    );

    const forwardedBody = JSON.parse(String(options.body));
    expect(forwardedBody.model).toBe('claude-opus-4-6');
    expect(forwardedBody.messages).toEqual([
      {
        role: 'user',
        content: [{ type: 'text', text: 'count these tokens', cache_control: { type: 'ephemeral' } }],
      },
    ]);
  });

  it('supports /v1/messages/count_tokens for openai-platform gateways that expose Claude messages endpoints', async () => {
    selectChannelMock.mockReturnValue({
      channel: { id: 12, routeId: 23 },
      site: { name: 'gateway-site', url: 'https://gateway.example.com', platform: 'openai' },
      account: { id: 34, username: 'gateway-user@example.com' },
      tokenName: 'default',
      tokenValue: 'sk-gateway',
      actualModel: 'claude-sonnet-4-5-20250929',
    });
    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      input_tokens: 9,
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/messages/count_tokens',
      payload: {
        model: 'claude-sonnet-4-5-20250929',
        messages: [
          {
            role: 'user',
            content: [{ type: 'text', text: 'count through a compatible gateway' }],
          },
        ],
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ input_tokens: 9 });
    expect(fetchMock).toHaveBeenCalledTimes(1);

    const [targetUrl, options] = fetchMock.mock.calls[0] as [string, any];
    expect(targetUrl).toBe('https://gateway.example.com/v1/messages/count_tokens?beta=true');
    expect(options.headers['x-api-key']).toBe('sk-gateway');
    expect(options.headers['anthropic-version']).toBe('2023-06-01');
  });
});
