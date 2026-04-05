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
const estimateProxyCostMock = vi.fn(async (_arg?: any) => 0);
const buildProxyBillingDetailsMock = vi.fn(async (_arg?: any) => null);
const fetchModelPricingCatalogMock = vi.fn(async (_arg?: any): Promise<any> => null);
const resolveProxyUsageWithSelfLogFallbackMock = vi.fn(async ({ usage }: any) => ({
  ...usage,
  estimatedCostFromQuota: 0,
  recoveredFromSelfLog: false,
}));
const dbValuesMock = vi.fn((_arg?: any) => ({
  run: () => undefined,
}));
const dbInsertMock = vi.fn((_arg?: any) => ({
  values: (arg: any) => dbValuesMock(arg),
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
  schema: {
    proxyLogs: {},
    siteApiEndpoints: {
      id: {},
      siteId: {},
      sortOrder: {},
    },
  },
  hasProxyLogBillingDetailsColumn: async () => false,
  hasProxyLogClientColumns: async () => false,
  hasProxyLogDownstreamApiKeyIdColumn: async () => false,
  hasProxyLogStreamTimingColumns: async () => false,
}));

describe('downstream client context route logging', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    const { claudeMessagesProxyRoute } = await import('./chat.js');
    const { responsesProxyRoute } = await import('./responses.js');
    app = Fastify();
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
    dbValuesMock.mockClear();

    selectChannelMock.mockReturnValue({
      channel: { id: 11, routeId: 22 },
      site: { id: 44, name: 'demo-site', url: 'https://upstream.example.com', platform: 'openai' },
      account: { id: 33, username: 'demo-user' },
      tokenName: 'default',
      tokenValue: 'sk-demo',
      actualModel: 'upstream-gpt',
    });
    selectNextChannelMock.mockReturnValue(null);
    fetchModelPricingCatalogMock.mockResolvedValue(null);
  });

  afterAll(async () => {
    if (app) {
      await app.close();
    }
  });

  it('includes Codex client and session metadata in /v1/responses failure logs', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      error: {
        message: 'bad request',
        type: 'upstream_error',
      },
    }), {
      status: 400,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/responses',
      headers: {
        originator: 'codex_cli_rs',
        Session_id: 'codex-session-123',
      },
      payload: {
        model: 'gpt-5.2',
        input: 'hello',
      },
    });

    expect(response.statusCode).toBe(400);
    expect(dbValuesMock).toHaveBeenCalled();
    const insertedLog = dbValuesMock.mock.calls.at(-1)?.[0];
    expect(insertedLog.errorMessage).toContain('[client:codex]');
    expect(insertedLog.errorMessage).toContain('[session:codex-session-123]');
    expect(insertedLog.errorMessage).toContain('[downstream:/v1/responses]');
  });

  it('reuses the same Codex detection on /v1/responses/compact failure logs', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      error: {
        message: 'compact failed',
        type: 'upstream_error',
      },
    }), {
      status: 400,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/responses/compact',
      headers: {
        'x-stainless-lang': 'typescript',
        Session_id: 'codex-session-compact',
      },
      payload: {
        model: 'gpt-5.2',
        input: 'hello',
      },
    });

    expect(response.statusCode).toBe(400);
    expect(dbValuesMock).toHaveBeenCalled();
    const insertedLog = dbValuesMock.mock.calls.at(-1)?.[0];
    expect(insertedLog.errorMessage).toContain('[client:codex]');
    expect(insertedLog.errorMessage).toContain('[session:codex-session-compact]');
    expect(insertedLog.errorMessage).toContain('[downstream:/v1/responses/compact]');
  });

  it('includes Claude Code client and session metadata in /v1/messages failure logs', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      error: {
        message: 'messages failed',
        type: 'upstream_error',
      },
    }), {
      status: 400,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/messages',
      payload: {
        model: 'claude-opus-4-6',
        max_tokens: 256,
        messages: [{ role: 'user', content: 'hello' }],
        metadata: {
          user_id: 'user_20836b5653ed68aa981604f502c0a491397f6053826a93c953423632578d38ad_account__session_f25958b8-e75c-455d-8b40-f006d87cc2a4',
        },
      },
    });

    expect(response.statusCode).toBe(400);
    expect(dbValuesMock).toHaveBeenCalled();
    const insertedLog = dbValuesMock.mock.calls.at(-1)?.[0];
    expect(insertedLog.errorMessage).toContain('[client:claude_code]');
    expect(insertedLog.errorMessage).toContain('[session:f25958b8-e75c-455d-8b40-f006d87cc2a4]');
    expect(insertedLog.errorMessage).toContain('[downstream:/v1/messages]');
  });

  it('keeps claude-cli header-based /v1/messages requests on the Claude Code family even when metadata.user_id is absent', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      error: {
        message: 'messages failed',
        type: 'upstream_error',
      },
    }), {
      status: 400,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/messages',
      headers: {
        'user-agent': 'claude-cli/2.1.63 (external, cli)',
        'anthropic-beta': 'claude-code-20250219,oauth-2025-04-20',
        'anthropic-version': '2023-06-01',
        'x-app': 'cli',
        'x-stainless-lang': 'js',
      },
      payload: {
        model: 'claude-opus-4-6',
        max_tokens: 256,
        messages: [{ role: 'user', content: 'hello' }],
      },
    });

    expect(response.statusCode).toBe(400);
    expect(dbValuesMock).toHaveBeenCalled();
    const insertedLog = dbValuesMock.mock.calls.at(-1)?.[0];
    expect(insertedLog.errorMessage).toContain('[client:claude_code]');
    expect(insertedLog.errorMessage).toContain('[downstream:/v1/messages]');
    expect(insertedLog.errorMessage).not.toContain('[client:codex]');
  });

  it('keeps invalid Claude metadata.user_id requests generic in failure logs', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      error: {
        message: 'messages failed',
        type: 'upstream_error',
      },
    }), {
      status: 400,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/v1/messages',
      payload: {
        model: 'claude-opus-4-6',
        max_tokens: 256,
        messages: [{ role: 'user', content: 'hello' }],
        metadata: {
          user_id: 'user_123',
        },
      },
    });

    expect(response.statusCode).toBe(400);
    expect(dbValuesMock).toHaveBeenCalled();
    const insertedLog = dbValuesMock.mock.calls.at(-1)?.[0];
    expect(insertedLog.errorMessage).toContain('[downstream:/v1/messages]');
    expect(insertedLog.errorMessage).not.toContain('[client:');
    expect(insertedLog.errorMessage).not.toContain('[session:');
  });
});
