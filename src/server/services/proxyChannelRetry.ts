import { config } from '../config.js';

export function getProxyMaxChannelAttempts(): number {
  const attempts = Math.trunc(config.proxyMaxChannelAttempts || 0);
  return attempts > 0 ? attempts : 1;
}

export function getProxyMaxChannelRetries(): number {
  return Math.max(0, getProxyMaxChannelAttempts() - 1);
}

export function canRetryProxyChannel(retryCount: number): boolean {
  return retryCount < getProxyMaxChannelRetries();
}
