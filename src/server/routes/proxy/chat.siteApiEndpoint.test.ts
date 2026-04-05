import Fastify, { type FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { asc, eq } from 'drizzle-orm';
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
const insertProxyLogMock = vi.fn();

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

vi.mock('../../services/proxyLogStore.js', () => ({
  insertProxyLog: (...args: unknown[]) => insertProxyLogMock(...args),
}));

type DbModule = typeof import('../../db/index.js');

describe('chat proxy site api endpoint rotation', () => {
  let app: FastifyInstance;
  let db: DbModule['db'];
  let schema: DbModule['schema'];
  let dataDir = '';

  beforeAll(async () => {
    dataDir = mkdtempSync(join(tmpdir(), 'metapi-chat-site-api-endpoint-'));
    process.env.DATA_DIR = dataDir;

    await import('../../db/migrate.js');
    const dbModule = await import('../../db/index.js');
    const routesModule = await import('./chat.js');
    db = dbModule.db;
    schema = dbModule.schema;

    app = Fastify();
    await app.register(routesModule.chatProxyRoute);
  });

  beforeEach(async () => {
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
    insertProxyLogMock.mockReset();
    resetUpstreamEndpointRuntimeState();

    await db.delete(schema.proxyLogs).run();
    await db.delete(schema.routeChannels).run();
    await db.delete(schema.tokenRoutes).run();
    await db.delete(schema.tokenModelAvailability).run();
    await db.delete(schema.modelAvailability).run();
    await db.delete(schema.accountTokens).run();
    await db.delete(schema.accounts).run();
    await db.delete(schema.siteApiEndpoints).run();
    await db.delete(schema.sites).run();

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
    (config as any).disableCrossProtocolFallback = false;
    config.proxyEmptyContentFailEnabled = false;
    config.proxyErrorKeywords = [];
  });

  afterAll(async () => {
    if (app) {
      await app.close();
    }
    delete process.env.DATA_DIR;
  });

  it('rotates to the next configured ai endpoint for retryable /v1/chat/completions failures', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'nihao-panel',
      url: 'https://console.example.com',
      platform: 'openai',
      status: 'active',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'nihao-user',
      accessToken: '',
      apiToken: 'sk-nihao',
      status: 'active',
      checkinEnabled: false,
      extraConfig: JSON.stringify({ credentialMode: 'apikey' }),
    }).returning().get();

    await db.insert(schema.siteApiEndpoints).values([
      {
        siteId: site.id,
        url: 'https://api-a.example.com',
        enabled: true,
        sortOrder: 0,
      },
      {
        siteId: site.id,
        url: 'https://api-b.example.com',
        enabled: true,
        sortOrder: 1,
      },
    ]).run();

    selectChannelMock.mockReturnValue({
      channel: { id: 11, routeId: 22 },
      site,
      account,
      tokenName: 'default',
      tokenValue: 'sk-nihao',
      actualModel: 'gpt-4o-mini',
    });
    selectNextChannelMock.mockReturnValue(null);

    fetchMock
      .mockResolvedValueOnce(new Response('bad gateway', { status: 502 }))
      .mockResolvedValueOnce(new Response('bad gateway via responses', { status: 502 }))
      .mockResolvedValueOnce(new Response('bad gateway via messages', { status: 502 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        id: 'chatcmpl-ok',
        object: 'chat.completion',
        created: 1_706_000_000,
        model: 'gpt-4o-mini',
        choices: [{
          index: 0,
          message: { role: 'assistant', content: 'ok via api-b' },
          finish_reason: 'stop',
        }],
        usage: { prompt_tokens: 1, completion_tokens: 2, total_tokens: 3 },
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

    expect(response.statusCode).toBe(200);
    expect(response.json()?.choices?.[0]?.message?.content).toBe('ok via api-b');
    expect(fetchMock).toHaveBeenCalledTimes(4);
    expect(String(fetchMock.mock.calls[0]?.[0] || '')).toBe('https://api-a.example.com/v1/chat/completions');
    expect(String(fetchMock.mock.calls[1]?.[0] || '')).toBe('https://api-a.example.com/v1/responses');
    expect(String(fetchMock.mock.calls[2]?.[0] || '')).toBe('https://api-a.example.com/v1/messages');
    expect(String(fetchMock.mock.calls[3]?.[0] || '')).toBe('https://api-b.example.com/v1/chat/completions');
    expect(selectNextChannelMock).not.toHaveBeenCalled();
    expect(recordFailureMock).not.toHaveBeenCalled();
    expect(recordSuccessMock).toHaveBeenCalledTimes(1);

    const storedEndpoints = await db.select().from(schema.siteApiEndpoints)
      .where(eq(schema.siteApiEndpoints.siteId, site.id))
      .orderBy(asc(schema.siteApiEndpoints.sortOrder), asc(schema.siteApiEndpoints.id))
      .all();
    expect(storedEndpoints[0]).toMatchObject({
      url: 'https://api-a.example.com',
      lastFailureReason: 'HTTP 502: [upstream:/v1/messages] Upstream returned HTTP 502: bad gateway via messages',
    });
    expect(storedEndpoints[0]?.cooldownUntil).toBeTruthy();
    expect(storedEndpoints[1]?.lastSelectedAt).toBeTruthy();
  });
});
