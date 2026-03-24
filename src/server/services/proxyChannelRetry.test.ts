import { afterEach, describe, expect, it } from 'vitest';
import { buildConfig, config } from '../config.js';
import {
  canRetryProxyChannel,
  getProxyMaxChannelAttempts,
  getProxyMaxChannelRetries,
} from './proxyChannelRetry.js';

const originalProxyMaxChannelAttempts = config.proxyMaxChannelAttempts;

afterEach(() => {
  config.proxyMaxChannelAttempts = originalProxyMaxChannelAttempts;
});

describe('proxyChannelRetry', () => {
  it('parses proxy max channel attempts from config with a safer default', () => {
    expect(buildConfig({} as NodeJS.ProcessEnv).proxyMaxChannelAttempts).toBe(3);
    expect(buildConfig({ PROXY_MAX_CHANNEL_ATTEMPTS: '3' } as NodeJS.ProcessEnv).proxyMaxChannelAttempts).toBe(3);
  });

  it('derives retry budget from total channel attempts', () => {
    config.proxyMaxChannelAttempts = 5;

    expect(getProxyMaxChannelAttempts()).toBe(5);
    expect(getProxyMaxChannelRetries()).toBe(4);
    expect(canRetryProxyChannel(3)).toBe(true);
    expect(canRetryProxyChannel(4)).toBe(false);
  });

  it('clamps invalid runtime config to at least one channel attempt', () => {
    config.proxyMaxChannelAttempts = 0;

    expect(getProxyMaxChannelAttempts()).toBe(1);
    expect(getProxyMaxChannelRetries()).toBe(0);
    expect(canRetryProxyChannel(0)).toBe(false);
  });
});
