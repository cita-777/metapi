import { describe, expect, it } from 'vitest';
import { reserveSurfaceProxyDebugAttemptBase } from './proxyDebugTraceRuntime.js';

describe('reserveSurfaceProxyDebugAttemptBase', () => {
  it('allocates monotonic attempt bases on the same trace session', () => {
    const session = {
      traceId: 801,
      options: {
        enabled: true,
        captureHeaders: true,
        captureBodies: true,
        captureStreamChunks: false,
        targetSessionId: '',
        targetClientKind: '',
        targetModel: '',
        retentionHours: 12,
        maxBodyBytes: 131072,
      },
    };

    expect(reserveSurfaceProxyDebugAttemptBase(session, 3)).toBe(0);
    expect(reserveSurfaceProxyDebugAttemptBase(session, 2)).toBe(3);
    expect(reserveSurfaceProxyDebugAttemptBase(session, 4)).toBe(5);
  });

  it('reserves at least one slot for empty or invalid spans', () => {
    const session = {
      traceId: 802,
      options: {
        enabled: true,
        captureHeaders: true,
        captureBodies: true,
        captureStreamChunks: false,
        targetSessionId: '',
        targetClientKind: '',
        targetModel: '',
        retentionHours: 12,
        maxBodyBytes: 131072,
      },
    };

    expect(reserveSurfaceProxyDebugAttemptBase(session, 0)).toBe(0);
    expect(reserveSurfaceProxyDebugAttemptBase(session, Number.NaN)).toBe(1);
  });
});
