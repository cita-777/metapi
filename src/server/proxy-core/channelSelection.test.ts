import { describe, expect, it } from 'vitest';
import {
  getTesterForcedChannelId,
  normalizeForcedChannelId,
  TESTER_FORCED_CHANNEL_HEADER,
  TESTER_REQUEST_HEADER,
} from './channelSelection.js';

describe('normalizeForcedChannelId', () => {
  it('accepts positive integer ids and rejects fractional or unsafe values', () => {
    expect(normalizeForcedChannelId(77)).toBe(77);
    expect(normalizeForcedChannelId('78')).toBe(78);
    expect(normalizeForcedChannelId(77.9)).toBeNull();
    expect(normalizeForcedChannelId('78.5')).toBeNull();
    expect(normalizeForcedChannelId('9007199254740993')).toBeNull();
    expect(normalizeForcedChannelId(0)).toBeNull();
    expect(normalizeForcedChannelId(-1)).toBeNull();
  });
});

describe('getTesterForcedChannelId', () => {
  it('ignores forged forced-channel headers without the trusted tester bridge marker', () => {
    expect(getTesterForcedChannelId({
      headers: {
        [TESTER_FORCED_CHANNEL_HEADER]: '77',
      },
      clientIp: '127.0.0.1',
    })).toBeNull();

    expect(getTesterForcedChannelId({
      headers: {
        [TESTER_REQUEST_HEADER]: '1',
        [TESTER_FORCED_CHANNEL_HEADER]: '77',
      },
      clientIp: '203.0.113.10',
    })).toBeNull();
  });

  it('accepts the forced channel id only for loopback tester bridge traffic', () => {
    expect(getTesterForcedChannelId({
      headers: {
        [TESTER_REQUEST_HEADER]: '1',
        [TESTER_FORCED_CHANNEL_HEADER]: '77',
      },
      clientIp: '::1',
    })).toBe(77);

    expect(getTesterForcedChannelId({
      headers: {
        [TESTER_REQUEST_HEADER]: '1',
        [TESTER_FORCED_CHANNEL_HEADER]: '78',
      },
      clientIp: '::ffff:127.0.0.1',
    })).toBe(78);
  });
});
