import { beforeEach, describe, expect, it, vi } from 'vitest';

const formatUtcSqlDateTimeMock = vi.fn();
const composeProxyLogMessageMock = vi.fn();
const insertProxyLogMock = vi.fn();

vi.mock('../../services/localTimeService.js', () => ({
  formatUtcSqlDateTime: (...args: unknown[]) => formatUtcSqlDateTimeMock(...args),
}));

vi.mock('../../services/siteProxy.js', () => ({
  resolveChannelProxyUrl: vi.fn(),
  withSiteRecordProxyRequestInit: vi.fn(),
}));

vi.mock('../../services/tokenRouter.js', () => ({
  tokenRouter: {
    recordFailure: vi.fn(),
    recordSuccess: vi.fn(),
  },
}));

vi.mock('../../services/proxyUsageFallbackService.js', () => ({
  resolveProxyUsageWithSelfLogFallback: vi.fn(),
}));

vi.mock('../../services/alertService.js', () => ({
  reportProxyAllFailed: vi.fn(),
  reportTokenExpired: vi.fn(),
}));

vi.mock('../../services/alertRules.js', () => ({
  isTokenExpiredError: vi.fn(() => false),
}));

vi.mock('../../services/proxyRetryPolicy.js', () => ({
  shouldRetryProxyRequest: vi.fn(() => false),
}));

vi.mock('../../routes/proxy/logPathMeta.js', () => ({
  composeProxyLogMessage: (...args: unknown[]) => composeProxyLogMessageMock(...args),
}));

vi.mock('../../routes/proxy/proxyBilling.js', () => ({
  resolveProxyLogBilling: vi.fn(),
}));

vi.mock('../../services/proxyLogStore.js', () => ({
  insertProxyLog: (...args: unknown[]) => insertProxyLogMock(...args),
}));

vi.mock('../../services/runtimeDispatch.js', () => ({
  dispatchRuntimeRequest: vi.fn(),
}));

vi.mock('../orchestration/upstreamRequest.js', () => ({
  buildUpstreamUrl: vi.fn(),
}));

vi.mock('../../services/oauth/quota.js', () => ({
  recordOauthQuotaResetHint: vi.fn(),
}));

vi.mock('../../services/oauth/refreshSingleflight.js', () => ({
  refreshOauthAccessTokenSingleflight: vi.fn(),
}));

vi.mock('../../services/proxyChannelCoordinator.js', () => ({
  proxyChannelCoordinator: {
    buildStickySessionKey: vi.fn(),
    getStickyChannelId: vi.fn(),
    bindStickyChannel: vi.fn(),
    clearStickyChannel: vi.fn(),
    acquireChannelLease: vi.fn(),
  },
}));

vi.mock('../executors/types.js', () => ({
  readRuntimeResponseText: vi.fn(),
}));

vi.mock('../channelSelection.js', () => ({
  selectProxyChannelForAttempt: vi.fn(),
}));

describe('shared surface usage source logging', () => {
  beforeEach(() => {
    formatUtcSqlDateTimeMock.mockReset();
    composeProxyLogMessageMock.mockReset();
    insertProxyLogMock.mockReset();
  });

  it('forwards usage source through the failure toolkit log wrapper', async () => {
    formatUtcSqlDateTimeMock.mockReturnValue('2026-04-05 21:00:00');
    composeProxyLogMessageMock.mockReturnValue('normalized error');
    insertProxyLogMock.mockResolvedValue(undefined);

    const { createSurfaceFailureToolkit } = await import('./sharedSurface.js');
    const toolkit = createSurfaceFailureToolkit({
      warningScope: 'responses',
      downstreamPath: '/v1/responses',
      maxRetries: 2,
      clientContext: {
        clientKind: 'codex',
        sessionId: 'turn-1',
        traceHint: 'trace-1',
      },
      downstreamApiKeyId: null,
    });

    await toolkit.log({
      selected: {
        channel: { id: 11, routeId: 22 },
        account: { id: 33, username: 'oauth-user' },
        site: { name: 'Codex OAuth' },
        actualModel: 'upstream-model',
      },
      modelRequested: 'gpt-5.2',
      status: 'success',
      httpStatus: 200,
      latencyMs: 320,
      errorMessage: null,
      retryCount: 0,
      promptTokens: 12,
      completionTokens: 4,
      totalTokens: 16,
      usageSource: 'self-log',
      upstreamPath: '/v1/messages',
    });

    expect(composeProxyLogMessageMock).toHaveBeenCalledWith(expect.objectContaining({
      downstreamPath: '/v1/responses',
      upstreamPath: '/v1/messages',
      usageSource: 'self-log',
      sessionId: 'turn-1',
      traceHint: 'trace-1',
    }));
    expect(insertProxyLogMock).toHaveBeenCalledWith(expect.objectContaining({
      status: 'success',
      errorMessage: 'normalized error',
    }));
  });
});
