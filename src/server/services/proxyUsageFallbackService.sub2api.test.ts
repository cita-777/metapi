import { beforeEach, describe, expect, it, vi } from 'vitest';

const { fetchMock, fetchJsonWithShieldCookieRetryMock } = vi.hoisted(() => ({
  fetchMock: vi.fn(),
  fetchJsonWithShieldCookieRetryMock: vi.fn(),
}));

vi.mock('undici', () => ({
  fetch: (...args: unknown[]) => fetchMock(...args),
}));

vi.mock('./platforms/newApiShield.js', () => ({
  buildNewApiCookieCandidates: () => [],
  fetchJsonWithShieldCookieRetry: (...args: unknown[]) => fetchJsonWithShieldCookieRetryMock(...args),
}));

vi.mock('./siteProxy.js', () => ({
  withExplicitProxyRequestInit: (_proxyUrl: string | null | undefined, init: RequestInit) => init,
  withSiteRecordProxyRequestInit: (_site: unknown, init: RequestInit) => init,
}));

import {
  resolveProxyUsageWithSelfLogFallback,
  shouldLookupSelfLog,
} from './proxyUsageFallbackService.js';

describe('proxyUsageFallbackService sub2api', () => {
  beforeEach(() => {
    fetchMock.mockReset();
    fetchJsonWithShieldCookieRetryMock.mockReset();
    fetchJsonWithShieldCookieRetryMock.mockResolvedValue({ data: null });
  });

  it('always enables usage lookup for sub2api to recover exact billing cost', () => {
    expect(shouldLookupSelfLog('sub2api', {
      promptTokens: 70354,
      completionTokens: 1148,
      totalTokens: 71502,
    })).toBe(true);
  });

  it('recovers exact cost from sub2api /api/v1/usage and matches by api key value', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      code: 0,
      message: 'success',
      data: {
        items: [
          {
            id: 1001,
            model: 'gpt-5.4',
            input_tokens: 512,
            output_tokens: 32,
            cache_creation_tokens: 0,
            cache_read_tokens: 0,
            total_cost: 0.001088,
            actual_cost: 0.001088,
            duration_ms: 23000,
            created_at: '2026-03-07T06:12:30.000Z',
            api_key: {
              id: 91,
              key: 'sk-wrong',
              name: 'wrong-key',
            },
          },
          {
            id: 1002,
            model: 'gpt-5.4',
            input_tokens: 70354,
            output_tokens: 1148,
            cache_creation_tokens: 0,
            cache_read_tokens: 0,
            total_cost: 0.143004,
            actual_cost: 0.143004,
            duration_ms: 23000,
            created_at: '2026-03-07T06:12:29.000Z',
            api_key: {
              id: 92,
              key: 'sk-route',
              name: 'upstream-key-name',
            },
          },
        ],
        total: 2,
        page: 1,
        page_size: 20,
        pages: 1,
      },
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const result = await resolveProxyUsageWithSelfLogFallback({
      site: {
        url: 'https://sub2api.example.com',
        platform: 'sub2api',
      },
      account: {
        accessToken: 'jwt-access-token',
        apiToken: 'sk-account-level',
      },
      tokenValue: 'sk-route',
      tokenName: 'local-token-name',
      modelName: 'gpt-5.4',
      requestStartedAtMs: Date.parse('2026-03-07T06:12:07.000Z'),
      requestEndedAtMs: Date.parse('2026-03-07T06:12:30.000Z'),
      localLatencyMs: 23000,
      usage: {
        promptTokens: 0,
        completionTokens: 0,
        totalTokens: 0,
      },
    });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(String(fetchMock.mock.calls[0]?.[0] || '')).toContain('/api/v1/usage?');
    expect(String(fetchMock.mock.calls[0]?.[0] || '')).toContain('model=gpt-5.4');
    expect(fetchMock.mock.calls[0]?.[1]).toMatchObject({
      method: 'GET',
      headers: {
        Authorization: 'Bearer jwt-access-token',
      },
    });
    expect(result).toMatchObject({
      promptTokens: 70354,
      completionTokens: 1148,
      totalTokens: 71502,
      recoveredFromSelfLog: true,
      estimatedCostFromQuota: 0.143004,
    });
  });

  it('treats explicit zero upstream usage as upstream instead of unknown', async () => {
    const result = await resolveProxyUsageWithSelfLogFallback({
      site: {
        url: 'https://newapi.example.com',
        platform: 'new-api',
      },
      account: {
        accessToken: 'jwt-access-token',
      },
      modelName: 'gpt-5.4',
      requestStartedAtMs: Date.parse('2026-03-07T06:12:07.000Z'),
      requestEndedAtMs: Date.parse('2026-03-07T06:12:30.000Z'),
      localLatencyMs: 23000,
      upstreamUsagePresent: true,
      usage: {
        promptTokens: 0,
        completionTokens: 0,
        totalTokens: 0,
      },
    });

    expect(result).toMatchObject({
      promptTokens: 0,
      completionTokens: 0,
      totalTokens: 0,
      recoveredFromSelfLog: false,
      usageSource: 'upstream',
    });
    expect(fetchMock).not.toHaveBeenCalled();
    expect(fetchJsonWithShieldCookieRetryMock).not.toHaveBeenCalled();
  });
});
