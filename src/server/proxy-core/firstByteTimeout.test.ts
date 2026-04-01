import { describe, expect, it } from 'vitest';

import {
  fetchWithObservedFirstByte,
  getObservedResponseMeta,
  isObservedFirstByteTimeoutResponse,
} from './firstByteTimeout.js';

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
    headers: { 'content-type': 'text/plain; charset=utf-8' },
  });
}

describe('fetchWithObservedFirstByte', () => {
  it('replays the first chunk and records first-byte latency when upstream responds in time', async () => {
    const response = await fetchWithObservedFirstByte(
      async () => buildDelayedResponse('hello world', 5),
      {
        firstByteTimeoutMs: 100,
        startedAtMs: Date.now(),
      },
    );

    expect(response.status).toBe(200);
    expect(await response.text()).toBe('hello world');

    const meta = getObservedResponseMeta(response);
    expect(meta?.timedOutBeforeFirstByte).toBe(false);
    expect(meta?.firstByteLatencyMs).not.toBeNull();
    expect((meta?.firstByteLatencyMs || 0)).toBeGreaterThanOrEqual(0);
    expect((meta?.firstByteLatencyMs || 0)).toBeLessThan(100);
  });

  it('returns a synthetic timeout response when upstream sends no first byte before the deadline', async () => {
    const response = await fetchWithObservedFirstByte(
      async () => buildDelayedResponse('too late', 80),
      {
        firstByteTimeoutMs: 10,
        startedAtMs: Date.now(),
      },
    );

    expect(response.status).toBe(408);
    expect(await response.text()).toContain('first byte timeout');
    expect(isObservedFirstByteTimeoutResponse(response)).toBe(true);

    const meta = getObservedResponseMeta(response);
    expect(meta?.timedOutBeforeFirstByte).toBe(true);
    expect(meta?.firstByteLatencyMs).toBeNull();
  });
});
