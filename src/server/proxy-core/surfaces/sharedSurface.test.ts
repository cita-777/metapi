import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { EMPTY_DOWNSTREAM_ROUTING_POLICY } from '../../services/downstreamPolicyTypes.js';

const selectChannelMock = vi.fn();
const selectNextChannelMock = vi.fn();
const selectPreferredChannelMock = vi.fn();
const recordFailureMock = vi.fn();
const refreshModelsAndRebuildRoutesMock = vi.fn();
const composeProxyLogMessageMock = vi.fn();
const formatUtcSqlDateTimeMock = vi.fn();
const insertProxyLogMock = vi.fn();
const resolveChannelProxyUrlMock = vi.fn();
const withSiteRecordProxyRequestInitMock = vi.fn();
const dispatchRuntimeRequestMock = vi.fn();
const reportProxyAllFailedMock = vi.fn();
const reportTokenExpiredMock = vi.fn();
const isTokenExpiredErrorMock = vi.fn();
const shouldRetryProxyRequestMock = vi.fn();
const recordOauthQuotaResetHintMock = vi.fn();
const recordSuccessMock = vi.fn();
const resolveProxyUsageWithSelfLogFallbackMock = vi.fn();
const resolveProxyLogBillingMock = vi.fn();
const refreshOauthAccessTokenSingleflightMock = vi.fn();
const getStickyChannelIdMock = vi.fn();
const bindStickyChannelMock = vi.fn();
const clearStickyChannelMock = vi.fn();
const acquireChannelLeaseMock = vi.fn();
const buildStickySessionKeyMock = vi.fn();
const consoleWarnMock = vi.spyOn(console, 'warn').mockImplementation(() => {});
const consoleErrorMock = vi.spyOn(console, 'error').mockImplementation(() => {});

vi.mock('../../services/tokenRouter.js', () => ({
  tokenRouter: {
    selectChannel: (...args: unknown[]) => selectChannelMock(...args),
    selectNextChannel: (...args: unknown[]) => selectNextChannelMock(...args),
    selectPreferredChannel: (...args: unknown[]) => selectPreferredChannelMock(...args),
    recordFailure: (...args: unknown[]) => recordFailureMock(...args),
    recordSuccess: (...args: unknown[]) => recordSuccessMock(...args),
  },
}));

vi.mock('../../services/proxyChannelCoordinator.js', () => ({
  proxyChannelCoordinator: {
    getStickyChannelId: (...args: unknown[]) => getStickyChannelIdMock(...args),
    bindStickyChannel: (...args: unknown[]) => bindStickyChannelMock(...args),
    clearStickyChannel: (...args: unknown[]) => clearStickyChannelMock(...args),
    acquireChannelLease: (...args: unknown[]) => acquireChannelLeaseMock(...args),
    buildStickySessionKey: (...args: unknown[]) => buildStickySessionKeyMock(...args),
  },
}));

vi.mock('../../services/modelService.js', () => ({
  refreshModelsAndRebuildRoutes: (...args: unknown[]) => refreshModelsAndRebuildRoutesMock(...args),
}));

vi.mock('../../routes/proxy/logPathMeta.js', () => ({
  composeProxyLogMessage: (...args: unknown[]) => composeProxyLogMessageMock(...args),
}));

vi.mock('../../services/localTimeService.js', () => ({
  formatUtcSqlDateTime: (...args: unknown[]) => formatUtcSqlDateTimeMock(...args),
}));

vi.mock('../../services/proxyLogStore.js', () => ({
  insertProxyLog: (...args: unknown[]) => insertProxyLogMock(...args),
}));

vi.mock('../../services/siteProxy.js', () => ({
  resolveChannelProxyUrl: (...args: unknown[]) => resolveChannelProxyUrlMock(...args),
  withSiteRecordProxyRequestInit: (...args: unknown[]) => withSiteRecordProxyRequestInitMock(...args),
}));

vi.mock('../../routes/proxy/runtimeExecutor.js', () => ({
  dispatchRuntimeRequest: (...args: unknown[]) => dispatchRuntimeRequestMock(...args),
}));

vi.mock('../../services/alertService.js', () => ({
  reportProxyAllFailed: (...args: unknown[]) => reportProxyAllFailedMock(...args),
  reportTokenExpired: (...args: unknown[]) => reportTokenExpiredMock(...args),
}));

vi.mock('../../services/alertRules.js', () => ({
  isTokenExpiredError: (...args: unknown[]) => isTokenExpiredErrorMock(...args),
}));

vi.mock('../../services/proxyRetryPolicy.js', () => ({
  shouldRetryProxyRequest: (...args: unknown[]) => shouldRetryProxyRequestMock(...args),
  shouldAbortSameSiteEndpointFallback: () => false,
}));

vi.mock('../../services/oauth/quota.js', () => ({
  recordOauthQuotaResetHint: (...args: unknown[]) => recordOauthQuotaResetHintMock(...args),
}));

vi.mock('../../services/proxyUsageFallbackService.js', () => ({
  resolveProxyUsageWithSelfLogFallback: (...args: unknown[]) => resolveProxyUsageWithSelfLogFallbackMock(...args),
}));

vi.mock('../../routes/proxy/proxyBilling.js', () => ({
  resolveProxyLogBilling: (...args: unknown[]) => resolveProxyLogBillingMock(...args),
}));

vi.mock('../../services/oauth/refreshSingleflight.js', () => ({
  refreshOauthAccessTokenSingleflight: (...args: unknown[]) => refreshOauthAccessTokenSingleflightMock(...args),
}));

describe('selectSurfaceChannelForAttempt', () => {
  afterAll(() => {
    consoleWarnMock.mockRestore();
    consoleErrorMock.mockRestore();
  });

  beforeEach(() => {
    selectChannelMock.mockReset();
    selectNextChannelMock.mockReset();
    selectPreferredChannelMock.mockReset();
    recordFailureMock.mockReset();
    refreshModelsAndRebuildRoutesMock.mockReset();
    composeProxyLogMessageMock.mockReset();
    formatUtcSqlDateTimeMock.mockReset();
    insertProxyLogMock.mockReset();
    resolveChannelProxyUrlMock.mockReset();
    withSiteRecordProxyRequestInitMock.mockReset();
    dispatchRuntimeRequestMock.mockReset();
    reportProxyAllFailedMock.mockReset();
    reportTokenExpiredMock.mockReset();
    isTokenExpiredErrorMock.mockReset();
    shouldRetryProxyRequestMock.mockReset();
    recordOauthQuotaResetHintMock.mockReset();
    recordSuccessMock.mockReset();
    resolveProxyUsageWithSelfLogFallbackMock.mockReset();
    resolveProxyLogBillingMock.mockReset();
    refreshOauthAccessTokenSingleflightMock.mockReset();
    getStickyChannelIdMock.mockReset();
    bindStickyChannelMock.mockReset();
    clearStickyChannelMock.mockReset();
    acquireChannelLeaseMock.mockReset();
    buildStickySessionKeyMock.mockReset();
    consoleWarnMock.mockClear();
    consoleErrorMock.mockClear();
  });

  it('refreshes models and retries selectChannel on the first attempt when no channel is available', async () => {
    const selected = { channel: { id: 11 } };
    selectChannelMock
      .mockResolvedValueOnce(null)
      .mockResolvedValueOnce(selected);

    const { selectSurfaceChannelForAttempt } = await import('./sharedSurface.js');
    const result = await selectSurfaceChannelForAttempt({
      requestedModel: 'gpt-5.2',
      downstreamPolicy: EMPTY_DOWNSTREAM_ROUTING_POLICY,
      excludeChannelIds: [],
      retryCount: 0,
    });

    expect(result).toBe(selected);
    expect(selectChannelMock).toHaveBeenCalledTimes(2);
    expect(selectNextChannelMock).not.toHaveBeenCalled();
    expect(refreshModelsAndRebuildRoutesMock).toHaveBeenCalledTimes(1);
  });

  it('uses selectNextChannel on retry attempts without refreshing models', async () => {
    const selected = { channel: { id: 22 } };
    selectNextChannelMock.mockResolvedValueOnce(selected);

    const { selectSurfaceChannelForAttempt } = await import('./sharedSurface.js');
    const result = await selectSurfaceChannelForAttempt({
      requestedModel: 'gpt-5.2',
      downstreamPolicy: EMPTY_DOWNSTREAM_ROUTING_POLICY,
      excludeChannelIds: [11],
      retryCount: 1,
    });

    expect(result).toBe(selected);
    expect(selectChannelMock).not.toHaveBeenCalled();
    expect(selectNextChannelMock).toHaveBeenCalledWith(
      'gpt-5.2',
      [11],
      EMPTY_DOWNSTREAM_ROUTING_POLICY,
    );
    expect(refreshModelsAndRebuildRoutesMock).not.toHaveBeenCalled();
  });

  it('prefers the sticky session channel on the first attempt when it is still eligible', async () => {
    const selected = { channel: { id: 55 } };
    getStickyChannelIdMock.mockReturnValueOnce(55);
    selectPreferredChannelMock.mockResolvedValueOnce(selected);

    const { selectSurfaceChannelForAttempt } = await import('./sharedSurface.js');
    const result = await selectSurfaceChannelForAttempt({
      requestedModel: 'gpt-5.2',
      downstreamPolicy: EMPTY_DOWNSTREAM_ROUTING_POLICY,
      excludeChannelIds: [],
      retryCount: 0,
      stickySessionKey: 'sticky-session',
    });

    expect(result).toBe(selected);
    expect(selectPreferredChannelMock).toHaveBeenCalledWith(
      'gpt-5.2',
      55,
      EMPTY_DOWNSTREAM_ROUTING_POLICY,
      [],
    );
    expect(selectChannelMock).not.toHaveBeenCalled();
    expect(clearStickyChannelMock).not.toHaveBeenCalled();
  });

  it('uses the forced tester channel before sticky or automatic selection', async () => {
    const selected = { channel: { id: 88 } };
    selectPreferredChannelMock.mockResolvedValueOnce(selected);

    const { selectSurfaceChannelForAttempt } = await import('./sharedSurface.js');
    const result = await selectSurfaceChannelForAttempt({
      requestedModel: 'gpt-5.2',
      downstreamPolicy: EMPTY_DOWNSTREAM_ROUTING_POLICY,
      excludeChannelIds: [],
      retryCount: 0,
      stickySessionKey: 'sticky-session',
      forcedChannelId: 88,
    });

    expect(result).toBe(selected);
    expect(selectPreferredChannelMock).toHaveBeenCalledWith(
      'gpt-5.2',
      88,
      EMPTY_DOWNSTREAM_ROUTING_POLICY,
      [],
    );
    expect(getStickyChannelIdMock).not.toHaveBeenCalled();
    expect(selectChannelMock).not.toHaveBeenCalled();
    expect(selectNextChannelMock).not.toHaveBeenCalled();
    expect(refreshModelsAndRebuildRoutesMock).not.toHaveBeenCalled();
  });

  it('does not refresh or fall back when the forced tester channel is unavailable', async () => {
    selectPreferredChannelMock.mockResolvedValueOnce(null);

    const { selectSurfaceChannelForAttempt } = await import('./sharedSurface.js');
    const result = await selectSurfaceChannelForAttempt({
      requestedModel: 'gpt-5.2',
      downstreamPolicy: EMPTY_DOWNSTREAM_ROUTING_POLICY,
      excludeChannelIds: [],
      retryCount: 0,
      forcedChannelId: 91,
    });

    expect(result).toBeNull();
    expect(selectPreferredChannelMock).toHaveBeenCalledWith(
      'gpt-5.2',
      91,
      EMPTY_DOWNSTREAM_ROUTING_POLICY,
      [],
    );
    expect(selectChannelMock).not.toHaveBeenCalled();
    expect(selectNextChannelMock).not.toHaveBeenCalled();
    expect(refreshModelsAndRebuildRoutesMock).not.toHaveBeenCalled();
  });

  it('refreshes and retries the sticky preferred channel before clearing a stale binding', async () => {
    const selected = { channel: { id: 22 } };
    getStickyChannelIdMock.mockReturnValueOnce(55);
    selectPreferredChannelMock
      .mockResolvedValueOnce(null)
      .mockResolvedValueOnce(null);
    selectChannelMock.mockResolvedValueOnce(selected);

    const { selectSurfaceChannelForAttempt } = await import('./sharedSurface.js');
    const result = await selectSurfaceChannelForAttempt({
      requestedModel: 'gpt-5.2',
      downstreamPolicy: EMPTY_DOWNSTREAM_ROUTING_POLICY,
      excludeChannelIds: [],
      retryCount: 0,
      stickySessionKey: 'sticky-session',
    });

    expect(result).toBe(selected);
    expect(refreshModelsAndRebuildRoutesMock).toHaveBeenCalledTimes(1);
    expect(selectPreferredChannelMock).toHaveBeenCalledTimes(2);
    expect(clearStickyChannelMock).toHaveBeenCalledWith('sticky-session', 55);
    expect(selectChannelMock).toHaveBeenCalledWith('gpt-5.2', EMPTY_DOWNSTREAM_ROUTING_POLICY);
  });

  it('keeps the sticky binding when route refresh recovers the preferred channel', async () => {
    const selected = { channel: { id: 55 } };
    getStickyChannelIdMock.mockReturnValueOnce(55);
    selectPreferredChannelMock
      .mockResolvedValueOnce(null)
      .mockResolvedValueOnce(selected);

    const { selectSurfaceChannelForAttempt } = await import('./sharedSurface.js');
    const result = await selectSurfaceChannelForAttempt({
      requestedModel: 'gpt-5.2',
      downstreamPolicy: EMPTY_DOWNSTREAM_ROUTING_POLICY,
      excludeChannelIds: [],
      retryCount: 0,
      stickySessionKey: 'sticky-session',
    });

    expect(result).toBe(selected);
    expect(refreshModelsAndRebuildRoutesMock).toHaveBeenCalledTimes(1);
    expect(selectPreferredChannelMock).toHaveBeenCalledTimes(2);
    expect(clearStickyChannelMock).not.toHaveBeenCalled();
    expect(selectChannelMock).not.toHaveBeenCalled();
  });

  it('logs refresh failures and still retries selection once on the first attempt', async () => {
    const selected = { channel: { id: 33 } };
    selectChannelMock
      .mockResolvedValueOnce(null)
      .mockResolvedValueOnce(selected);
    refreshModelsAndRebuildRoutesMock.mockRejectedValueOnce(new Error('refresh failed'));

    const { selectSurfaceChannelForAttempt } = await import('./sharedSurface.js');
    const result = await selectSurfaceChannelForAttempt({
      requestedModel: 'gpt-5.2',
      downstreamPolicy: EMPTY_DOWNSTREAM_ROUTING_POLICY,
      excludeChannelIds: [],
      retryCount: 0,
    });

    expect(result).toBe(selected);
    expect(selectChannelMock).toHaveBeenCalledTimes(2);
    expect(consoleWarnMock).toHaveBeenCalledWith(
      '[proxy/surface] failed to refresh routes after empty selection',
      expect.any(Error),
    );
  });

  it('writes proxy logs through the shared log formatter and store', async () => {
    composeProxyLogMessageMock.mockReturnValue('normalized error');
    formatUtcSqlDateTimeMock.mockReturnValue('2026-03-21 22:00:00');
    insertProxyLogMock.mockResolvedValue(undefined);

    const { writeSurfaceProxyLog } = await import('./sharedSurface.js');
    await writeSurfaceProxyLog({
      warningScope: 'chat',
      selected: {
        channel: { id: 11, routeId: 22 },
        account: { id: 33 },
        actualModel: 'upstream-model',
      },
      modelRequested: 'gpt-5.2',
      status: 'failed',
      httpStatus: 502,
      latencyMs: 1200,
      errorMessage: 'upstream failed',
      retryCount: 1,
      downstreamPath: '/v1/chat/completions',
      promptTokens: 10,
      completionTokens: 5,
      totalTokens: 15,
      estimatedCost: 0.42,
      billingDetails: { source: 'test' },
      upstreamPath: '/v1/responses',
      usageSource: 'self-log',
      clientContext: {
        clientKind: 'codex',
        clientAppId: 'app-id',
        clientAppName: 'App',
        clientConfidence: 'high',
        sessionId: 'sess-1',
        traceHint: 'trace-1',
      },
      downstreamApiKeyId: 44,
    });

    expect(composeProxyLogMessageMock).toHaveBeenCalledWith({
      clientKind: 'codex',
      sessionId: 'sess-1',
      traceHint: 'trace-1',
      downstreamPath: '/v1/chat/completions',
      upstreamPath: '/v1/responses',
      usageSource: 'self-log',
      errorMessage: 'upstream failed',
    });
    expect(insertProxyLogMock).toHaveBeenCalledWith({
      routeId: 22,
      channelId: 11,
      accountId: 33,
      downstreamApiKeyId: 44,
      modelRequested: 'gpt-5.2',
      modelActual: 'upstream-model',
      status: 'failed',
      httpStatus: 502,
      isStream: null,
      firstByteLatencyMs: null,
      latencyMs: 1200,
      promptTokens: 10,
      completionTokens: 5,
      totalTokens: 15,
      estimatedCost: 0.42,
      billingDetails: { source: 'test' },
      clientFamily: 'codex',
      clientAppId: 'app-id',
      clientAppName: 'App',
      clientConfidence: 'high',
      errorMessage: 'normalized error',
      retryCount: 1,
      createdAt: '2026-03-21 22:00:00',
    });
  });

  it('builds runtime dispatch requests with site proxy initialization', async () => {
    const site = { url: 'https://upstream.example.com' };
    const request = {
      endpoint: 'responses',
      path: '/v1/responses',
      headers: { authorization: 'Bearer test' },
      body: { model: 'gpt-5.2', input: 'hello' },
      runtime: { executor: 'default' },
    };
    resolveChannelProxyUrlMock.mockReturnValue('http://proxy.example.com');
    withSiteRecordProxyRequestInitMock.mockImplementation(async (_site, init, proxyUrl) => ({
      ...init,
      proxyUrl,
    }));
    dispatchRuntimeRequestMock.mockResolvedValue('ok');

    const { createSurfaceDispatchRequest } = await import('./sharedSurface.js');
    const dispatchRequest = createSurfaceDispatchRequest({
      site,
      accountExtraConfig: '{"proxyUrl":"http://proxy.example.com"}',
    });
    const result = await dispatchRequest(request, 'https://target.example.com/v1/responses');

    expect(result).toBe('ok');
    expect(resolveChannelProxyUrlMock).toHaveBeenCalledWith(
      site,
      '{"proxyUrl":"http://proxy.example.com"}',
    );
    expect(dispatchRuntimeRequestMock).toHaveBeenCalledTimes(1);
    const dispatchArg = dispatchRuntimeRequestMock.mock.calls[0]?.[0];
    expect(dispatchArg.siteUrl).toBe('https://upstream.example.com');
    expect(dispatchArg.targetUrl).toBe('https://target.example.com/v1/responses');
    expect(dispatchArg.request).toBe(request);
    return dispatchArg.buildInit('https://target.example.com/v1/responses', {
      headers: { authorization: 'Bearer test' },
      body: { model: 'gpt-5.2', input: 'hello' },
    }).then((init: Record<string, unknown>) => {
      expect(withSiteRecordProxyRequestInitMock).toHaveBeenCalledWith(site, {
        method: 'POST',
        headers: { authorization: 'Bearer test' },
        body: JSON.stringify({ model: 'gpt-5.2', input: 'hello' }),
      }, 'http://proxy.example.com');
      expect(init).toEqual({
        method: 'POST',
        headers: { authorization: 'Bearer test' },
        body: JSON.stringify({ model: 'gpt-5.2', input: 'hello' }),
        proxyUrl: 'http://proxy.example.com',
      });
    });
  });

  it('retries retryable upstream HTTP failures through the shared failure toolkit', async () => {
    composeProxyLogMessageMock.mockReturnValue('normalized error');
    formatUtcSqlDateTimeMock.mockReturnValue('2026-03-21 22:00:00');
    insertProxyLogMock.mockResolvedValue(undefined);
    shouldRetryProxyRequestMock.mockReturnValue(true);
    isTokenExpiredErrorMock.mockReturnValue(false);
    recordOauthQuotaResetHintMock.mockResolvedValue(null);

    const { createSurfaceFailureToolkit } = await import('./sharedSurface.js');
    const toolkit = createSurfaceFailureToolkit({
      warningScope: 'chat',
      downstreamPath: '/v1/chat/completions',
      maxRetries: 2,
      clientContext: null,
      downstreamApiKeyId: 44,
    });

    const result = await toolkit.handleUpstreamFailure({
      selected: {
        channel: { id: 11, routeId: 22 },
        account: { id: 33, username: 'oauth-user' },
        site: { name: 'Codex OAuth' },
        actualModel: 'upstream-model',
      },
      requestedModel: 'gpt-5.2',
      modelName: 'upstream-model',
      status: 429,
      errText: 'quota exceeded',
      rawErrText: '{"error":"quota exceeded"}',
      latencyMs: 1200,
      retryCount: 0,
    });

    expect(result).toEqual({ action: 'retry' });
    expect(recordFailureMock).toHaveBeenCalledWith(11, {
      status: 429,
      errorText: '{"error":"quota exceeded"}',
      modelName: 'upstream-model',
    });
    expect(recordOauthQuotaResetHintMock).toHaveBeenCalledWith({
      accountId: 33,
      statusCode: 429,
      errorText: '{"error":"quota exceeded"}',
    });
    expect(reportProxyAllFailedMock).not.toHaveBeenCalled();
    expect(insertProxyLogMock).toHaveBeenCalledWith(expect.objectContaining({
      channelId: 11,
      accountId: 33,
      downstreamApiKeyId: 44,
      modelRequested: 'gpt-5.2',
      modelActual: 'upstream-model',
      status: 'failed',
      httpStatus: 429,
      latencyMs: 1200,
      errorMessage: 'normalized error',
      retryCount: 0,
    }));
  });

  it('keeps retryable failures on the retry path even when quota hint recording fails', async () => {
    composeProxyLogMessageMock.mockReturnValue('normalized error');
    formatUtcSqlDateTimeMock.mockReturnValue('2026-03-21 22:00:00');
    insertProxyLogMock.mockResolvedValue(undefined);
    shouldRetryProxyRequestMock.mockReturnValue(true);
    isTokenExpiredErrorMock.mockReturnValue(false);
    recordOauthQuotaResetHintMock.mockRejectedValue(new Error('hint failed'));

    const { createSurfaceFailureToolkit } = await import('./sharedSurface.js');
    const toolkit = createSurfaceFailureToolkit({
      warningScope: 'chat',
      downstreamPath: '/v1/chat/completions',
      maxRetries: 2,
      clientContext: null,
      downstreamApiKeyId: null,
    });

    await expect(toolkit.handleUpstreamFailure({
      selected: {
        channel: { id: 11, routeId: 22 },
        account: { id: 33, username: 'oauth-user' },
        site: { name: 'Codex OAuth' },
        actualModel: 'upstream-model',
      },
      requestedModel: 'gpt-5.2',
      modelName: 'upstream-model',
      status: 429,
      errText: 'quota exceeded',
      rawErrText: '{"error":"quota exceeded"}',
      latencyMs: 1200,
      retryCount: 0,
    })).resolves.toEqual({ action: 'retry' });
  });

  it('returns a terminal upstream error response and reports token expiration when retries stop', async () => {
    composeProxyLogMessageMock.mockReturnValue('normalized error');
    formatUtcSqlDateTimeMock.mockReturnValue('2026-03-21 22:00:00');
    insertProxyLogMock.mockResolvedValue(undefined);
    shouldRetryProxyRequestMock.mockReturnValue(false);
    isTokenExpiredErrorMock.mockReturnValue(true);
    recordOauthQuotaResetHintMock.mockResolvedValue(null);

    const { createSurfaceFailureToolkit } = await import('./sharedSurface.js');
    const toolkit = createSurfaceFailureToolkit({
      warningScope: 'responses',
      downstreamPath: '/v1/responses',
      maxRetries: 2,
      clientContext: null,
      downstreamApiKeyId: null,
    });

    const result = await toolkit.handleUpstreamFailure({
      selected: {
        channel: { id: 11, routeId: 22 },
        account: { id: 33, username: 'oauth-user' },
        site: { name: 'Codex OAuth' },
        actualModel: 'upstream-model',
      },
      requestedModel: 'gpt-5.2',
      modelName: 'upstream-model',
      status: 401,
      errText: 'expired token',
      rawErrText: 'expired token',
      latencyMs: 900,
      retryCount: 2,
    });

    expect(result).toEqual({
      action: 'respond',
      status: 401,
      payload: {
        error: {
          message: 'expired token',
          type: 'upstream_error',
        },
      },
    });
    expect(reportTokenExpiredMock).toHaveBeenCalledWith({
      accountId: 33,
      username: 'oauth-user',
      siteName: 'Codex OAuth',
      detail: 'HTTP 401',
    });
    expect(reportProxyAllFailedMock).toHaveBeenCalledWith({
      model: 'gpt-5.2',
      reason: 'upstream returned HTTP 401',
    });
  });

  it('returns terminal failures even when final alerting throws', async () => {
    composeProxyLogMessageMock.mockReturnValue('normalized error');
    formatUtcSqlDateTimeMock.mockReturnValue('2026-03-21 22:00:00');
    insertProxyLogMock.mockResolvedValue(undefined);
    shouldRetryProxyRequestMock.mockReturnValue(false);
    isTokenExpiredErrorMock.mockReturnValue(true);
    recordOauthQuotaResetHintMock.mockResolvedValue(null);
    reportTokenExpiredMock.mockRejectedValue(new Error('token alert failed'));

    const { createSurfaceFailureToolkit } = await import('./sharedSurface.js');
    const toolkit = createSurfaceFailureToolkit({
      warningScope: 'responses',
      downstreamPath: '/v1/responses',
      maxRetries: 2,
      clientContext: null,
      downstreamApiKeyId: null,
    });

    await expect(toolkit.handleUpstreamFailure({
      selected: {
        channel: { id: 11, routeId: 22 },
        account: { id: 33, username: 'oauth-user' },
        site: { name: 'Codex OAuth' },
        actualModel: 'upstream-model',
      },
      requestedModel: 'gpt-5.2',
      modelName: 'upstream-model',
      status: 401,
      errText: 'expired token',
      rawErrText: 'expired token',
      latencyMs: 900,
      retryCount: 2,
    })).resolves.toEqual({
      action: 'respond',
      status: 401,
      payload: {
        error: {
          message: 'expired token',
          type: 'upstream_error',
        },
      },
    });
  });

  it('handles detected proxy failures through the shared failure toolkit', async () => {
    composeProxyLogMessageMock.mockReturnValue('normalized error');
    formatUtcSqlDateTimeMock.mockReturnValue('2026-03-21 22:00:00');
    insertProxyLogMock.mockResolvedValue(undefined);
    shouldRetryProxyRequestMock.mockReturnValue(false);

    const { createSurfaceFailureToolkit } = await import('./sharedSurface.js');
    const toolkit = createSurfaceFailureToolkit({
      warningScope: 'chat',
      downstreamPath: '/v1/chat/completions',
      maxRetries: 2,
      clientContext: null,
      downstreamApiKeyId: null,
    });

    const result = await toolkit.handleDetectedFailure({
      selected: {
        channel: { id: 11, routeId: 22 },
        account: { id: 33, username: 'oauth-user' },
        site: { name: 'Codex OAuth' },
        actualModel: 'upstream-model',
      },
      requestedModel: 'gpt-5.2',
      modelName: 'upstream-model',
      failure: {
        status: 500,
        reason: 'upstream failure',
      },
      latencyMs: 700,
      retryCount: 2,
      promptTokens: 12,
      completionTokens: 4,
      totalTokens: 16,
      upstreamPath: '/v1/responses',
    });

    expect(result).toEqual({
      action: 'respond',
      status: 500,
      payload: {
        error: {
          message: 'upstream failure',
          type: 'upstream_error',
        },
      },
    });
    expect(recordFailureMock).toHaveBeenCalledWith(11, {
      status: 500,
      errorText: 'upstream failure',
      modelName: 'upstream-model',
    });
    expect(reportProxyAllFailedMock).toHaveBeenCalledWith({
      model: 'gpt-5.2',
      reason: 'upstream failure',
    });
    expect(recordOauthQuotaResetHintMock).not.toHaveBeenCalled();
  });

  it('returns a terminal 502 for exhausted network failures through the shared failure toolkit', async () => {
    composeProxyLogMessageMock.mockReturnValue('normalized error');
    formatUtcSqlDateTimeMock.mockReturnValue('2026-03-21 22:00:00');
    insertProxyLogMock.mockResolvedValue(undefined);

    const { createSurfaceFailureToolkit } = await import('./sharedSurface.js');
    const toolkit = createSurfaceFailureToolkit({
      warningScope: 'responses',
      downstreamPath: '/v1/responses',
      maxRetries: 2,
      clientContext: null,
      downstreamApiKeyId: null,
    });

    const result = await toolkit.handleExecutionError({
      selected: {
        channel: { id: 11, routeId: 22 },
        account: { id: 33, username: 'oauth-user' },
        site: { name: 'Codex OAuth' },
        actualModel: 'upstream-model',
      },
      requestedModel: 'gpt-5.2',
      modelName: 'upstream-model',
      errorMessage: 'socket hang up',
      latencyMs: 650,
      retryCount: 2,
    });

    expect(result).toEqual({
      action: 'respond',
      status: 502,
      payload: {
        error: {
          message: 'Upstream error: socket hang up',
          type: 'upstream_error',
        },
      },
    });
    expect(recordFailureMock).toHaveBeenCalledWith(11, {
      errorText: 'socket hang up',
      modelName: 'upstream-model',
    });
    expect(reportProxyAllFailedMock).toHaveBeenCalledWith({
      model: 'gpt-5.2',
      reason: 'socket hang up',
    });
  });

  it('records stream failures with error text even without a runtime status code', async () => {
    composeProxyLogMessageMock.mockReturnValue('normalized error');
    formatUtcSqlDateTimeMock.mockReturnValue('2026-03-21 22:00:00');
    insertProxyLogMock.mockResolvedValue(undefined);

    const { createSurfaceFailureToolkit } = await import('./sharedSurface.js');
    const toolkit = createSurfaceFailureToolkit({
      warningScope: 'responses',
      downstreamPath: '/v1/responses',
      maxRetries: 2,
      clientContext: null,
      downstreamApiKeyId: null,
    });

    await toolkit.recordStreamFailure({
      selected: {
        channel: { id: 11, routeId: 22 },
        account: { id: 33, username: 'oauth-user' },
        site: { name: 'Codex OAuth' },
        actualModel: 'upstream-model',
      },
      requestedModel: 'gpt-5.2',
      modelName: 'upstream-model',
      errorMessage: 'stream exploded',
      latencyMs: 450,
      retryCount: 1,
    });

    expect(recordFailureMock).toHaveBeenCalledWith(11, {
      errorText: 'stream exploded',
      modelName: 'upstream-model',
    });
  });

  it('refreshes oauth tokens through the shared recover helper and retries the rebuilt request', async () => {
    const refreshedResponse = {
      ok: true,
      status: 200,
      text: vi.fn(),
    };
    const selected = {
      account: {
        id: 33,
        accessToken: 'old-access-token',
        extraConfig: '{"oauth":{"refreshToken":"refresh"}}',
      },
      tokenValue: 'old-access-token',
    };
    const ctx = {
      request: {
        endpoint: 'responses' as const,
        path: '/v1/responses',
        headers: { authorization: 'Bearer old-access-token' },
        body: { model: 'gpt-5.2' },
      },
      response: {
        ok: false,
        status: 401,
        text: vi.fn(),
      },
      rawErrText: 'expired token',
    };
    refreshOauthAccessTokenSingleflightMock.mockResolvedValue({
      accessToken: 'new-access-token',
      extraConfig: '{"oauth":{"refreshToken":"refresh-next"}}',
    });
    const dispatchRequest = vi.fn().mockResolvedValue(refreshedResponse);

    const { trySurfaceOauthRefreshRecovery } = await import('./sharedSurface.js');
    const result = await trySurfaceOauthRefreshRecovery({
      ctx,
      selected,
      siteUrl: 'https://upstream.example.com',
      buildRequest: () => ({
        endpoint: 'responses',
        path: '/v1/responses',
        headers: { authorization: `Bearer ${selected.tokenValue}` },
        body: { model: 'gpt-5.2' },
      }),
      dispatchRequest,
    });

    expect(refreshOauthAccessTokenSingleflightMock).toHaveBeenCalledWith(33);
    expect(selected.tokenValue).toBe('new-access-token');
    expect(selected.account.accessToken).toBe('new-access-token');
    expect(selected.account.extraConfig).toBe('{"oauth":{"refreshToken":"refresh-next"}}');
    expect(dispatchRequest).toHaveBeenCalledWith(expect.objectContaining({
      headers: { authorization: 'Bearer new-access-token' },
    }), 'https://upstream.example.com/v1/responses');
    expect(result).toEqual({
      request: {
        endpoint: 'responses',
        path: '/v1/responses',
        headers: { authorization: 'Bearer new-access-token' },
        body: { model: 'gpt-5.2' },
      },
      targetUrl: 'https://upstream.example.com/v1/responses',
      upstream: refreshedResponse,
      upstreamPath: '/v1/responses',
    });
  });

  it('updates the recover context with the refreshed failure response when oauth refresh retry still fails', async () => {
    const refreshedResponse = {
      ok: false,
      status: 403,
      text: vi.fn().mockResolvedValue('account mismatch'),
    };
    const ctx = {
      request: {
        endpoint: 'responses' as const,
        path: '/v1/responses',
        headers: { authorization: 'Bearer old-access-token' },
        body: { model: 'gpt-5.2' },
      },
      response: {
        ok: false,
        status: 401,
        text: vi.fn(),
      },
      rawErrText: 'expired token',
    };
    const selected = {
      account: {
        id: 33,
        accessToken: 'old-access-token',
        extraConfig: '{"oauth":{"refreshToken":"refresh"}}',
      },
      tokenValue: 'old-access-token',
    };
    refreshOauthAccessTokenSingleflightMock.mockResolvedValue({
      accessToken: 'new-access-token',
      extraConfig: '{"oauth":{"refreshToken":"refresh-next"}}',
    });

    const { trySurfaceOauthRefreshRecovery } = await import('./sharedSurface.js');
    const result = await trySurfaceOauthRefreshRecovery({
      ctx,
      selected,
      siteUrl: 'https://upstream.example.com',
      buildRequest: () => ({
        endpoint: 'responses',
        path: '/v1/responses',
        headers: { authorization: `Bearer ${selected.tokenValue}` },
        body: { model: 'gpt-5.2' },
      }),
      dispatchRequest: vi.fn().mockResolvedValue(refreshedResponse),
    });

    expect(result).toBeNull();
    expect(ctx.request.headers).toEqual({ authorization: 'Bearer new-access-token' });
    expect(ctx.response).toBe(refreshedResponse);
    expect(ctx.rawErrText).toBe('account mismatch');
  });

  it('records shared success bookkeeping with usage fallback, billing, and success logging', async () => {
    resolveProxyUsageWithSelfLogFallbackMock.mockResolvedValue({
      promptTokens: 20,
      completionTokens: 8,
      totalTokens: 28,
      recoveredFromSelfLog: true,
      estimatedCostFromQuota: 0.42,
      selfLogBillingMeta: null,
      usageSource: 'self-log',
    });
    resolveProxyLogBillingMock.mockResolvedValue({
      estimatedCost: 0.42,
      billingDetails: { source: 'pricing-test' },
    });
    const logSuccess = vi.fn().mockResolvedValue(undefined);
    const recordDownstreamCost = vi.fn();

    const { recordSurfaceSuccess } = await import('./sharedSurface.js');
    const result = await recordSurfaceSuccess({
      selected: {
        channel: { id: 11, routeId: 22 },
        account: { id: 33, username: 'oauth-user' },
        site: { id: 44, url: 'https://upstream.example.com', name: 'Codex OAuth' },
        tokenValue: 'live-token',
        tokenName: 'default',
        actualModel: 'upstream-model',
      },
      requestedModel: 'gpt-5.2',
      modelName: 'upstream-model',
      parsedUsage: {
        promptTokens: 10,
        completionTokens: 5,
        totalTokens: 15,
      },
      requestStartedAtMs: 1000,
      latencyMs: 250,
      retryCount: 1,
      upstreamPath: '/v1/responses',
      logSuccess,
      recordDownstreamCost,
    });

    expect(resolveProxyUsageWithSelfLogFallbackMock).toHaveBeenCalledWith({
      site: { id: 44, url: 'https://upstream.example.com', name: 'Codex OAuth' },
      account: { id: 33, username: 'oauth-user' },
      tokenValue: 'live-token',
      tokenName: 'default',
      modelName: 'upstream-model',
      requestStartedAtMs: 1000,
      requestEndedAtMs: 1250,
      localLatencyMs: 250,
      upstreamUsagePresent: true,
      usage: {
        promptTokens: 10,
        completionTokens: 5,
        totalTokens: 15,
      },
    });
    expect(resolveProxyLogBillingMock).toHaveBeenCalledWith({
      site: { id: 44, url: 'https://upstream.example.com', name: 'Codex OAuth' },
      account: { id: 33, username: 'oauth-user' },
      modelName: 'upstream-model',
      parsedUsage: {
        promptTokens: 10,
        completionTokens: 5,
        totalTokens: 15,
      },
      resolvedUsage: {
        promptTokens: 20,
        completionTokens: 8,
        totalTokens: 28,
        recoveredFromSelfLog: true,
        estimatedCostFromQuota: 0.42,
        selfLogBillingMeta: null,
        usageSource: 'self-log',
      },
    });
    expect(recordSuccessMock).toHaveBeenCalledWith(11, 250, 0.42, 'upstream-model');
    expect(recordDownstreamCost).toHaveBeenCalledWith(0.42);
    expect(logSuccess).toHaveBeenCalledWith({
      selected: {
        channel: { id: 11, routeId: 22 },
        account: { id: 33, username: 'oauth-user' },
        site: { id: 44, url: 'https://upstream.example.com', name: 'Codex OAuth' },
        tokenValue: 'live-token',
        tokenName: 'default',
        actualModel: 'upstream-model',
      },
      modelRequested: 'gpt-5.2',
      status: 'success',
      httpStatus: 200,
      isStream: null,
      firstByteLatencyMs: null,
      latencyMs: 250,
      errorMessage: null,
      retryCount: 1,
      promptTokens: 20,
      completionTokens: 8,
      totalTokens: 28,
      usageSource: 'self-log',
      estimatedCost: 0.42,
      billingDetails: { source: 'pricing-test' },
      upstreamPath: '/v1/responses',
    });
    expect(result).toEqual({
      resolvedUsage: {
        promptTokens: 20,
        completionTokens: 8,
        totalTokens: 28,
        recoveredFromSelfLog: true,
        estimatedCostFromQuota: 0.42,
        selfLogBillingMeta: null,
        usageSource: 'self-log',
      },
      estimatedCost: 0.42,
      billingDetails: { source: 'pricing-test' },
    });
  });

  it('logs unknown usage as null tokens while preserving success bookkeeping', async () => {
    resolveProxyUsageWithSelfLogFallbackMock.mockResolvedValue({
      promptTokens: 0,
      completionTokens: 0,
      totalTokens: 0,
      recoveredFromSelfLog: false,
      estimatedCostFromQuota: 0,
      selfLogBillingMeta: null,
      usageSource: 'unknown',
    });
    resolveProxyLogBillingMock.mockResolvedValue({
      estimatedCost: 0,
      billingDetails: null,
    });
    const logSuccess = vi.fn().mockResolvedValue(undefined);

    const { recordSurfaceSuccess } = await import('./sharedSurface.js');
    await recordSurfaceSuccess({
      selected: {
        channel: { id: 11, routeId: 22 },
        account: { id: 33, username: 'oauth-user' },
        site: { id: 44, url: 'https://upstream.example.com', platform: 'new-api', name: 'Upstream' },
        tokenValue: 'live-token',
        tokenName: 'default',
        actualModel: 'upstream-model',
      },
      requestedModel: 'gpt-5.2',
      modelName: 'upstream-model',
      parsedUsage: {
        promptTokens: 0,
        completionTokens: 0,
        totalTokens: 0,
      },
      requestStartedAtMs: 1000,
      latencyMs: 250,
      retryCount: 0,
      upstreamPath: '/v1/chat/completions',
      logSuccess,
    });

    expect(resolveProxyUsageWithSelfLogFallbackMock).toHaveBeenCalledWith(expect.objectContaining({
      upstreamUsagePresent: false,
    }));
    expect(logSuccess).toHaveBeenCalledWith(expect.objectContaining({
      promptTokens: null,
      completionTokens: null,
      totalTokens: null,
      usageSource: 'unknown',
    }));
  });

  it('treats success metrics as best-effort when requested', async () => {
    resolveProxyUsageWithSelfLogFallbackMock.mockRejectedValueOnce(new Error('billing failed'));
    const logSuccess = vi.fn().mockResolvedValue(undefined);
    const recordDownstreamCost = vi.fn();

    const { recordSurfaceSuccess } = await import('./sharedSurface.js');
    const result = await recordSurfaceSuccess({
      selected: {
        channel: { id: 11, routeId: 22 },
        account: { id: 33, username: 'oauth-user' },
        site: { id: 44, url: 'https://upstream.example.com', name: 'Codex OAuth' },
        tokenValue: 'live-token',
        tokenName: 'default',
        actualModel: 'upstream-model',
      },
      requestedModel: 'gpt-5.2',
      modelName: 'upstream-model',
      parsedUsage: {
        promptTokens: 10,
        completionTokens: 5,
        totalTokens: 15,
      },
      requestStartedAtMs: 1000,
      latencyMs: 250,
      retryCount: 1,
      upstreamPath: '/v1/responses',
      logSuccess,
      recordDownstreamCost,
      bestEffortMetrics: {
        errorLabel: '[proxy/chat] failed to record success metrics',
      },
    });

    expect(consoleErrorMock).toHaveBeenCalledWith(
      '[proxy/chat] failed to record success metrics',
      expect.any(Error),
    );
    expect(recordSuccessMock).toHaveBeenCalledWith(11, 250, 0, 'upstream-model');
    expect(recordDownstreamCost).toHaveBeenCalledWith(0);
    expect(logSuccess).toHaveBeenCalledWith(expect.objectContaining({
      promptTokens: 10,
      completionTokens: 5,
      totalTokens: 15,
      estimatedCost: 0,
      billingDetails: null,
    }));
    expect(result).toEqual({
      resolvedUsage: {
        promptTokens: 10,
        completionTokens: 5,
        totalTokens: 15,
        recoveredFromSelfLog: false,
        estimatedCostFromQuota: 0,
        selfLogBillingMeta: null,
        usageSource: 'upstream',
      },
      estimatedCost: 0,
      billingDetails: null,
    });
  });
});
