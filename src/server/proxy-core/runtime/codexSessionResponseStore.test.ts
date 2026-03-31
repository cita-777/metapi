import { describe, expect, it } from 'vitest';
import {
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
});
