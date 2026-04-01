import { beforeEach, describe, expect, it, vi } from 'vitest';

const resolveUpstreamEndpointCandidatesMock = vi.fn();
const buildUpstreamEndpointRequestMock = vi.fn();
const dispatchRuntimeRequestMock = vi.fn();
const resolveChannelProxyUrlMock = vi.fn();
const withSiteRecordProxyRequestInitMock = vi.fn();

vi.mock('../routes/proxy/upstreamEndpoint.js', () => ({
  resolveUpstreamEndpointCandidates: (...args: unknown[]) => resolveUpstreamEndpointCandidatesMock(...args),
  buildUpstreamEndpointRequest: (...args: unknown[]) => buildUpstreamEndpointRequestMock(...args),
}));

vi.mock('../routes/proxy/runtimeExecutor.js', () => ({
  dispatchRuntimeRequest: (...args: unknown[]) => dispatchRuntimeRequestMock(...args),
}));

vi.mock('./siteProxy.js', () => ({
  resolveChannelProxyUrl: (...args: unknown[]) => resolveChannelProxyUrlMock(...args),
  withSiteRecordProxyRequestInit: (...args: unknown[]) => withSiteRecordProxyRequestInitMock(...args),
}));

describe('probeRuntimeModel', () => {
  const site = {
    id: 1,
    name: 'probe-site',
    url: 'https://probe.example.com',
    platform: 'new-api',
    status: 'active',
  } as any;

  const account = {
    id: 1,
    siteId: 1,
    username: 'probe-user',
    accessToken: '',
    apiToken: 'sk-probe',
    status: 'active',
    extraConfig: null,
  } as any;

  beforeEach(() => {
    vi.resetModules();
    resolveUpstreamEndpointCandidatesMock.mockReset();
    buildUpstreamEndpointRequestMock.mockReset();
    dispatchRuntimeRequestMock.mockReset();
    resolveChannelProxyUrlMock.mockReset();
    withSiteRecordProxyRequestInitMock.mockReset();

    buildUpstreamEndpointRequestMock.mockReturnValue({
      path: '/v1/chat/completions',
      headers: { 'content-type': 'application/json' },
      body: { model: 'gpt-5.4' },
      runtime: {
        executor: 'default',
        modelName: 'gpt-5.4',
        stream: false,
      },
    });
    resolveChannelProxyUrlMock.mockReturnValue(null);
    withSiteRecordProxyRequestInitMock.mockImplementation(async (_site: unknown, init: RequestInit) => init);
  });

  it('returns an inconclusive result instead of throwing when endpoint resolution fails', async () => {
    resolveUpstreamEndpointCandidatesMock.mockRejectedValue(new Error('resolution failed'));

    const { probeRuntimeModel } = await import('./runtimeModelProbe.js');
    const result = await probeRuntimeModel({
      site,
      account,
      modelName: 'gpt-5.4',
      timeoutMs: 10,
    });

    expect(result.status).toBe('inconclusive');
    expect(result.reason).toContain('resolution failed');
    expect(result.latencyMs).not.toBeNull();
  });

  it('uses the remaining timeout budget for the runtime request phase', async () => {
    resolveUpstreamEndpointCandidatesMock.mockImplementation(async () => {
      await new Promise((resolve) => setTimeout(resolve, 15));
      return ['chat'];
    });
    dispatchRuntimeRequestMock.mockImplementation(async (input: {
      buildInit: (requestUrl: string, request: Record<string, unknown>) => Promise<RequestInit>;
      request: Record<string, unknown>;
      targetUrl?: string;
    }) => {
      const init = await input.buildInit(input.targetUrl || 'https://probe.example.com/v1/chat/completions', input.request);
      const signal = init.signal as AbortSignal | undefined;
      await new Promise<void>((resolve, reject) => {
        const timer = setTimeout(resolve, 40);
        signal?.addEventListener('abort', () => {
          clearTimeout(timer);
          reject(signal.reason ?? new Error('aborted'));
        }, { once: true });
      });
      return new Response(JSON.stringify({ ok: true }), { status: 200 });
    });

    const { probeRuntimeModel } = await import('./runtimeModelProbe.js');
    const startedAt = Date.now();
    const result = await probeRuntimeModel({
      site,
      account,
      modelName: 'gpt-5.4',
      timeoutMs: 30,
    });
    const elapsedMs = Date.now() - startedAt;

    expect(result.status).toBe('inconclusive');
    expect(result.latencyMs).not.toBeNull();
    expect(elapsedMs).toBeLessThan(200);
  });
});
