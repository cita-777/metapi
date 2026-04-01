import { describe, expect, it } from 'vitest';
import {
  buildCodexSessionResponseStoreKey,
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
});
