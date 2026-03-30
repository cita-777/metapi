import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fetch } from 'undici';
import type { BuiltEndpointRequest } from './endpointFlow.js';

vi.mock('undici', () => ({
  fetch: vi.fn(),
}));

vi.mock('../../services/siteProxy.js', () => ({
  withSiteProxyRequestInit: async (_targetUrl: string, init: RequestInit) => init,
}));

const fetchMock = vi.mocked(fetch);

function requestFor(path: string): BuiltEndpointRequest {
  return {
    endpoint: 'responses',
    path,
    headers: { 'content-type': 'application/json' },
    body: { model: 'gpt-5.2', input: 'hello' },
  };
}

function toUndiciResponse(response: Response): Awaited<ReturnType<typeof fetch>> {
  return response as unknown as Awaited<ReturnType<typeof fetch>>;
}

describe('executeEndpointFlow', () => {
  let executeEndpointFlow: (input: any) => Promise<any>;

  beforeEach(async () => {
    if (!executeEndpointFlow) {
      ({ executeEndpointFlow } = await import('./endpointFlow.js'));
    }
  });

  beforeEach(() => {
    fetchMock.mockReset();
  });

  it('returns the first successful upstream response', async () => {
    fetchMock.mockResolvedValueOnce(toUndiciResponse(new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    })));

    const result = await executeEndpointFlow({
      siteUrl: 'https://example.com',
      endpointCandidates: ['responses'],
      buildRequest: () => requestFor('/v1/responses'),
    });

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.upstreamPath).toBe('/v1/responses');
    }
    expect(fetchMock.mock.calls[0]?.[0]).toBe('https://example.com/v1/responses');
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('uses the injected dispatchRequest hook instead of the default fetch path', async () => {
    const dispatchRequest = vi.fn(async () => toUndiciResponse(new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    })));

    const result = await executeEndpointFlow({
      siteUrl: 'https://example.com',
      endpointCandidates: ['responses'],
      buildRequest: () => requestFor('/v1/responses'),
      dispatchRequest,
    });

    expect(result.ok).toBe(true);
    expect(dispatchRequest).toHaveBeenCalledTimes(1);
    expect(dispatchRequest.mock.calls[0]?.[1]).toBe('https://example.com/v1/responses');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('avoids duplicated /v1 when base url already ends with /v1', async () => {
    fetchMock.mockResolvedValueOnce(toUndiciResponse(new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    })));

    await executeEndpointFlow({
      siteUrl: 'https://api.example.com/v1',
      endpointCandidates: ['chat'],
      buildRequest: () => ({ ...requestFor('/v1/chat/completions'), endpoint: 'chat' }),
    });

    expect(fetchMock.mock.calls[0]?.[0]).toBe('https://api.example.com/v1/chat/completions');
  });

  it('avoids duplicated /v1 when base url already ends with /api/v1', async () => {
    fetchMock.mockResolvedValueOnce(toUndiciResponse(new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    })));

    await executeEndpointFlow({
      siteUrl: 'https://openrouter.ai/api/v1',
      endpointCandidates: ['chat'],
      buildRequest: () => ({ ...requestFor('/v1/chat/completions'), endpoint: 'chat' }),
    });

    expect(fetchMock.mock.calls[0]?.[0]).toBe('https://openrouter.ai/api/v1/chat/completions');
  });

  it('keeps url well-formed when base url includes query/hash', async () => {
    fetchMock.mockResolvedValueOnce(toUndiciResponse(new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    })));

    await executeEndpointFlow({
      siteUrl: 'https://api.example.com/v1?foo=1#keep',
      endpointCandidates: ['chat'],
      buildRequest: () => ({ ...requestFor('/v1/chat/completions'), endpoint: 'chat' }),
    });

    expect(fetchMock.mock.calls[0]?.[0]).toBe('https://api.example.com/v1/chat/completions?foo=1#keep');
  });

  it('downgrades to next endpoint when policy allows', async () => {
    fetchMock
      .mockResolvedValueOnce(toUndiciResponse(new Response(JSON.stringify({
        error: { message: 'unsupported endpoint', type: 'invalid_request_error' },
      }), {
        status: 404,
        headers: { 'content-type': 'application/json' },
      })))
      .mockResolvedValueOnce(toUndiciResponse(new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })));

    const downgradedPaths: string[] = [];
    const result = await executeEndpointFlow({
      siteUrl: 'https://example.com',
      endpointCandidates: ['responses', 'chat'],
      buildRequest: (endpoint) => endpoint === 'responses'
        ? requestFor('/v1/responses')
        : { ...requestFor('/v1/chat/completions'), endpoint },
      shouldDowngrade: () => true,
      onDowngrade: (ctx) => {
        downgradedPaths.push(ctx.request.path);
      },
    });

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.upstreamPath).toBe('/v1/chat/completions');
    }
    expect(downgradedPaths).toEqual(['/v1/responses']);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('does not downgrade to the next endpoint when cross protocol fallback is disabled', async () => {
    fetchMock
      .mockResolvedValueOnce(toUndiciResponse(new Response(JSON.stringify({
        error: { message: 'unsupported endpoint', type: 'invalid_request_error' },
      }), {
        status: 404,
        headers: { 'content-type': 'application/json' },
      })))
      .mockResolvedValueOnce(toUndiciResponse(new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })));

    const onDowngrade = vi.fn();
    const result = await executeEndpointFlow({
      siteUrl: 'https://example.com',
      endpointCandidates: ['responses', 'chat'],
      buildRequest: (endpoint) => endpoint === 'responses'
        ? requestFor('/v1/responses')
        : { ...requestFor('/v1/chat/completions'), endpoint },
      shouldDowngrade: () => true,
      disableCrossProtocolFallback: true,
      onDowngrade,
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.status).toBe(404);
      expect(result.errText).toContain('/v1/responses');
    }
    expect(onDowngrade).not.toHaveBeenCalled();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('emits attempt callbacks for failed and successful endpoint probes', async () => {
    fetchMock
      .mockResolvedValueOnce(toUndiciResponse(new Response(JSON.stringify({
        error: { message: 'unsupported endpoint', type: 'invalid_request_error' },
      }), {
        status: 404,
        headers: { 'content-type': 'application/json' },
      })))
      .mockResolvedValueOnce(toUndiciResponse(new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })));

    const onAttemptFailure = vi.fn();
    const onAttemptSuccess = vi.fn();

    const result = await executeEndpointFlow({
      siteUrl: 'https://example.com',
      endpointCandidates: ['responses', 'chat'],
      buildRequest: (endpoint) => endpoint === 'responses'
        ? requestFor('/v1/responses')
        : { ...requestFor('/v1/chat/completions'), endpoint },
      shouldDowngrade: () => true,
      onAttemptFailure,
      onAttemptSuccess,
    });

    expect(result.ok).toBe(true);
    expect(onAttemptFailure).toHaveBeenCalledTimes(1);
    expect(onAttemptFailure.mock.calls[0]?.[0]?.request?.path).toBe('/v1/responses');
    expect(onAttemptSuccess).toHaveBeenCalledTimes(1);
    expect(onAttemptSuccess.mock.calls[0]?.[0]?.request?.path).toBe('/v1/chat/completions');
  });

  it('accepts recovered response from tryRecover hook', async () => {
    fetchMock.mockResolvedValueOnce(toUndiciResponse(new Response(JSON.stringify({
      error: { message: 'upstream_error', type: 'upstream_error' },
    }), {
      status: 400,
      headers: { 'content-type': 'application/json' },
    })));

    const recovered = toUndiciResponse(new Response(JSON.stringify({ ok: 'recovered' }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const result = await executeEndpointFlow({
      siteUrl: 'https://example.com',
      endpointCandidates: ['responses'],
      buildRequest: () => requestFor('/v1/responses'),
      tryRecover: async () => ({
        upstream: recovered,
        upstreamPath: '/v1/responses',
      }),
    });

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.upstreamPath).toBe('/v1/responses');
    }
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('uses recovered request metadata for success callbacks', async () => {
    fetchMock.mockResolvedValueOnce(toUndiciResponse(new Response(JSON.stringify({
      error: { message: 'upstream_error', type: 'upstream_error' },
    }), {
      status: 400,
      headers: { 'content-type': 'application/json' },
    })));

    const recovered = toUndiciResponse(new Response(JSON.stringify({ ok: 'recovered' }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));
    const onAttemptSuccess = vi.fn();

    await executeEndpointFlow({
      siteUrl: 'https://example.com',
      endpointCandidates: ['responses'],
      buildRequest: () => requestFor('/v1/responses'),
      tryRecover: async () => ({
        upstream: recovered,
        upstreamPath: '/v1/messages',
        request: { ...requestFor('/v1/messages'), endpoint: 'messages' },
      }),
      onAttemptSuccess,
    });

    expect(onAttemptSuccess).toHaveBeenCalledTimes(1);
    expect(onAttemptSuccess.mock.calls[0]?.[0]?.request?.path).toBe('/v1/messages');
    expect(onAttemptSuccess.mock.calls[0]?.[0]?.targetUrl).toBe('https://example.com/v1/messages');
  });

  it('does not let attempt hook failures change routing', async () => {
    fetchMock
      .mockResolvedValueOnce(toUndiciResponse(new Response(JSON.stringify({
        error: { message: 'unsupported endpoint', type: 'invalid_request_error' },
      }), {
        status: 404,
        headers: { 'content-type': 'application/json' },
      })))
      .mockResolvedValueOnce(toUndiciResponse(new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })));

    const result = await executeEndpointFlow({
      siteUrl: 'https://example.com',
      endpointCandidates: ['responses', 'chat'],
      buildRequest: (endpoint) => endpoint === 'responses'
        ? requestFor('/v1/responses')
        : { ...requestFor('/v1/chat/completions'), endpoint },
      shouldDowngrade: () => true,
      onAttemptFailure: async () => {
        throw new Error('failure hook should be ignored');
      },
      onAttemptSuccess: async () => {
        throw new Error('success hook should be ignored');
      },
    });

    expect(result.ok).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('uses proxyUrl for the default fetch path when no dispatch hook is provided', async () => {
    fetchMock.mockResolvedValueOnce(toUndiciResponse(new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    })));

    await executeEndpointFlow({
      siteUrl: 'https://example.com',
      proxyUrl: 'https://proxy.internal/base',
      endpointCandidates: ['responses'],
      buildRequest: () => requestFor('/v1/responses'),
    });

    expect(fetchMock.mock.calls[0]?.[0]).toBe('https://proxy.internal/base/v1/responses');
  });
  it('normalizes proxyUrl with versioned base paths instead of duplicating path segments', async () => {
    fetchMock.mockResolvedValueOnce(toUndiciResponse(new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    })));

    await executeEndpointFlow({
      siteUrl: 'https://example.com',
      proxyUrl: 'https://proxy.internal/api/v1?mode=relay#frag',
      endpointCandidates: ['responses'],
      buildRequest: () => requestFor('/v1/responses'),
    });

    expect(fetchMock.mock.calls[0]?.[0]).toBe('https://proxy.internal/api/v1/responses?mode=relay#frag');
  });
  it('returns normalized final error when all endpoints fail', async () => {
    fetchMock.mockResolvedValueOnce(toUndiciResponse(new Response(JSON.stringify({
      error: { message: 'upstream_error', type: 'upstream_error' },
    }), {
      status: 400,
      headers: { 'content-type': 'application/json' },
    })));

    const result = await executeEndpointFlow({
      siteUrl: 'https://example.com',
      endpointCandidates: ['responses'],
      buildRequest: () => requestFor('/v1/responses'),
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.status).toBe(400);
      expect(result.errText).toContain('[upstream:/v1/responses]');
      expect(result.errText).toContain('Upstream returned HTTP 400');
    }
  });
});
