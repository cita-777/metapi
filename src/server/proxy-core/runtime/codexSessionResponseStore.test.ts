import { describe, expect, it } from 'vitest';
import {
  buildCodexSessionResponseStoreKey,
  clearCodexSessionResponseId,
  getCodexSessionResponseId,
  resetCodexSessionResponseStore,
  setCodexSessionResponseId,
} from './codexSessionResponseStore.js';

describe('codexSessionResponseStore', () => {
  it('evicts the oldest session id when the store exceeds the cap', () => {
    resetCodexSessionResponseStore();

    for (let index = 0; index <= 10_000; index += 1) {
      setCodexSessionResponseId(`session-${index}`, `resp-${index}`);
    }

    expect(getCodexSessionResponseId('session-0')).toBeNull();
    expect(getCodexSessionResponseId('session-1')).toBe('resp-1');
    expect(getCodexSessionResponseId('session-10000')).toBe('resp-10000');

    resetCodexSessionResponseStore();
  });

  it('namespaces identical downstream session ids by channel scope', () => {
    resetCodexSessionResponseStore();

    const keyA = buildCodexSessionResponseStoreKey({
      sessionId: 'session-1',
      siteId: 10,
      accountId: 20,
      channelId: 30,
    });
    const keyB = buildCodexSessionResponseStoreKey({
      sessionId: 'session-1',
      siteId: 10,
      accountId: 21,
      channelId: 31,
    });

    setCodexSessionResponseId(keyA, 'resp-a');
    setCodexSessionResponseId(keyB, 'resp-b');

    expect(getCodexSessionResponseId(keyA)).toBe('resp-a');
    expect(getCodexSessionResponseId(keyB)).toBe('resp-b');

    resetCodexSessionResponseStore();
  });

  it('falls back to the bare downstream session id across channel scope drift', () => {
    resetCodexSessionResponseStore();

    const originalScopedKey = buildCodexSessionResponseStoreKey({
      sessionId: 'session-drift',
      siteId: 10,
      accountId: 20,
      channelId: 30,
    });
    const driftedScopedKey = buildCodexSessionResponseStoreKey({
      sessionId: 'session-drift',
      siteId: 10,
      accountId: 21,
      channelId: 31,
    });

    setCodexSessionResponseId(originalScopedKey, 'resp-drift');

    expect(getCodexSessionResponseId(originalScopedKey)).toBe('resp-drift');
    expect(getCodexSessionResponseId(driftedScopedKey)).toBe('resp-drift');

    resetCodexSessionResponseStore();
  });

  it('does not collapse distinct downstream sessions when scoped session ids contain delimiters', () => {
    resetCodexSessionResponseStore();

    const delimitedScopedKey = buildCodexSessionResponseStoreKey({
      sessionId: 'session-delimited|tail',
      siteId: 10,
      accountId: 20,
      channelId: 30,
    });
    const delimitedDriftedScopedKey = buildCodexSessionResponseStoreKey({
      sessionId: 'session-delimited|tail',
      siteId: 10,
      accountId: 21,
      channelId: 31,
    });
    const plainScopedKey = buildCodexSessionResponseStoreKey({
      sessionId: 'session-delimited',
      siteId: 10,
      accountId: 22,
      channelId: 32,
    });

    setCodexSessionResponseId(delimitedScopedKey, 'resp-delimited');
    setCodexSessionResponseId(plainScopedKey, 'resp-plain');

    expect(getCodexSessionResponseId(delimitedDriftedScopedKey)).toBe('resp-delimited');
    expect(getCodexSessionResponseId(plainScopedKey)).toBe('resp-plain');

    resetCodexSessionResponseStore();
  });

  it('clears the bare downstream session fallback when removing a scoped continuation id', () => {
    resetCodexSessionResponseStore();

    const originalScopedKey = buildCodexSessionResponseStoreKey({
      sessionId: 'session-clear',
      siteId: 10,
      accountId: 20,
      channelId: 30,
    });
    const driftedScopedKey = buildCodexSessionResponseStoreKey({
      sessionId: 'session-clear',
      siteId: 10,
      accountId: 21,
      channelId: 31,
    });

    setCodexSessionResponseId(originalScopedKey, 'resp-clear');
    clearCodexSessionResponseId(originalScopedKey);

    expect(getCodexSessionResponseId(originalScopedKey)).toBeNull();
    expect(getCodexSessionResponseId(driftedScopedKey)).toBeNull();

    resetCodexSessionResponseStore();
  });

  it('keeps the latest continuation id when the same downstream session drifts back to an earlier scope', () => {
    resetCodexSessionResponseStore();

    const originalScopedKey = buildCodexSessionResponseStoreKey({
      sessionId: 'session-roundtrip',
      siteId: 10,
      accountId: 20,
      channelId: 30,
    });
    const driftedScopedKey = buildCodexSessionResponseStoreKey({
      sessionId: 'session-roundtrip',
      siteId: 10,
      accountId: 21,
      channelId: 31,
    });

    setCodexSessionResponseId(originalScopedKey, 'resp-roundtrip-1');

    expect(getCodexSessionResponseId(driftedScopedKey)).toBe('resp-roundtrip-1');

    setCodexSessionResponseId(driftedScopedKey, 'resp-roundtrip-2');

    expect(getCodexSessionResponseId(driftedScopedKey)).toBe('resp-roundtrip-2');
    expect(getCodexSessionResponseId(originalScopedKey)).toBe('resp-roundtrip-2');

    resetCodexSessionResponseStore();
  });
});
