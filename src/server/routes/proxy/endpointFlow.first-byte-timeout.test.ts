import { describe, expect, it } from 'vitest';

import type { BuiltEndpointRequest } from './endpointFlow.js';

function requestFor(path: string): BuiltEndpointRequest {
  return {
    endpoint: 'responses',
    path,
    headers: { 'content-type': 'application/json' },
    body: { model: 'gpt-5.2', input: 'hello' },
  };
}

function buildDelayedResponse(bodyText: string, delayMs: number, status = 200): Response {
  const encoder = new TextEncoder();
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      setTimeout(() => {
        controller.enqueue(encoder.encode(bodyText));
        controller.close();
      }, delayMs);
    },
  });
  return new Response(body, {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

describe('executeEndpointFlow first-byte timeout', () => {
  it('falls through to the next endpoint candidate when the current endpoint times out before any output', async () => {
    const { executeEndpointFlow } = await import('./endpointFlow.js');
    const dispatchRequest = async (request: BuiltEndpointRequest) => (
      request.path === '/v1/responses'
        ? buildDelayedResponse(JSON.stringify({ ok: false }), 60, 200)
        : new Response(JSON.stringify({ ok: true }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        })
    ) as unknown as Awaited<ReturnType<typeof import('undici').fetch>>;

    const failures: string[] = [];
    const result = await executeEndpointFlow({
      siteUrl: 'https://example.com',
      endpointCandidates: ['responses', 'chat'],
      buildRequest: (endpoint: 'responses' | 'chat') => endpoint === 'responses'
        ? requestFor('/v1/responses')
        : { ...requestFor('/v1/chat/completions'), endpoint },
      dispatchRequest,
      firstByteTimeoutMs: 10,
      onAttemptFailure: (ctx: { errText: string }) => {
        failures.push(ctx.errText);
      },
    });

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.upstreamPath).toBe('/v1/chat/completions');
    }
    expect(failures).toHaveLength(1);
    expect(failures[0]).toContain('first byte timeout');
  });
});
