import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { config } from '../config.js';
import {
  proxyChannelCoordinator,
  resetProxyChannelCoordinatorState,
} from './proxyChannelCoordinator.js';

describe('proxyChannelCoordinator', () => {
  const originalStickyEnabled = config.proxyStickySessionEnabled;
  const originalStickyTtlMs = config.proxyStickySessionTtlMs;
  const originalConcurrencyLimit = config.proxySessionChannelConcurrencyLimit;
  const originalQueueWaitMs = config.proxySessionChannelQueueWaitMs;
  const originalLeaseTtlMs = config.proxySessionChannelLeaseTtlMs;
  const originalLeaseKeepaliveMs = config.proxySessionChannelLeaseKeepaliveMs;

  beforeEach(() => {
    vi.useFakeTimers();
    config.proxyStickySessionEnabled = true;
    config.proxyStickySessionTtlMs = 31_000;
    config.proxySessionChannelConcurrencyLimit = 1;
    config.proxySessionChannelQueueWaitMs = 200;
    config.proxySessionChannelLeaseTtlMs = 100;
    config.proxySessionChannelLeaseKeepaliveMs = 30;
    resetProxyChannelCoordinatorState();
  });

  afterEach(() => {
    config.proxyStickySessionEnabled = originalStickyEnabled;
    config.proxyStickySessionTtlMs = originalStickyTtlMs;
    config.proxySessionChannelConcurrencyLimit = originalConcurrencyLimit;
    config.proxySessionChannelQueueWaitMs = originalQueueWaitMs;
    config.proxySessionChannelLeaseTtlMs = originalLeaseTtlMs;
    config.proxySessionChannelLeaseKeepaliveMs = originalLeaseKeepaliveMs;
    resetProxyChannelCoordinatorState();
    vi.useRealTimers();
  });

  it('stores sticky bindings for session-scoped channels and expires them by ttl', async () => {
    const key = proxyChannelCoordinator.buildStickySessionKey({
      clientKind: 'codex',
      sessionId: 'turn-123',
      requestedModel: 'gpt-5.2',
      downstreamPath: '/v1/responses',
      downstreamApiKeyId: 9,
    });

    proxyChannelCoordinator.bindStickyChannel(key, 42, JSON.stringify({ credentialMode: 'session' }));
    expect(proxyChannelCoordinator.getStickyChannelId(key)).toBe(42);

    await vi.advanceTimersByTimeAsync(31_100);
    expect(proxyChannelCoordinator.getStickyChannelId(key)).toBeNull();
  });

  it('does not store sticky bindings for apikey-only channels', () => {
    const key = proxyChannelCoordinator.buildStickySessionKey({
      clientKind: 'codex',
      sessionId: 'turn-456',
      requestedModel: 'gpt-5.2',
      downstreamPath: '/v1/responses',
      downstreamApiKeyId: 9,
    });

    proxyChannelCoordinator.bindStickyChannel(key, 42, JSON.stringify({ credentialMode: 'apikey' }));
    expect(proxyChannelCoordinator.getStickyChannelId(key)).toBeNull();
  });

  it('queues requests behind the active lease and grants the next waiter after release', async () => {
    const first = await proxyChannelCoordinator.acquireChannelLease({
      channelId: 11,
      accountExtraConfig: JSON.stringify({ credentialMode: 'session' }),
    });
    expect(first.status).toBe('acquired');
    if (first.status !== 'acquired') return;

    let secondSettled = false;
    const secondPromise = proxyChannelCoordinator.acquireChannelLease({
      channelId: 11,
      accountExtraConfig: JSON.stringify({ credentialMode: 'session' }),
    }).then((result) => {
      secondSettled = true;
      return result;
    });

    await vi.advanceTimersByTimeAsync(50);
    expect(secondSettled).toBe(false);

    first.lease.release();
    await vi.advanceTimersByTimeAsync(0);

    const second = await secondPromise;
    expect(second.status).toBe('acquired');
    if (second.status === 'acquired') {
      second.lease.release();
    }
  });

  it('times out queued requests when no slot becomes available', async () => {
    const first = await proxyChannelCoordinator.acquireChannelLease({
      channelId: 11,
      accountExtraConfig: JSON.stringify({ credentialMode: 'session' }),
    });
    expect(first.status).toBe('acquired');
    if (first.status !== 'acquired') return;

    const secondPromise = proxyChannelCoordinator.acquireChannelLease({
      channelId: 11,
      accountExtraConfig: JSON.stringify({ credentialMode: 'session' }),
    });

    await vi.advanceTimersByTimeAsync(250);
    await expect(secondPromise).resolves.toEqual({
      status: 'timeout',
      waitMs: 200,
    });

    first.lease.release();
  });

  it('keeps active leases alive until they are explicitly released', async () => {
    const first = await proxyChannelCoordinator.acquireChannelLease({
      channelId: 11,
      accountExtraConfig: JSON.stringify({ credentialMode: 'session' }),
    });
    expect(first.status).toBe('acquired');
    if (first.status !== 'acquired') return;

    let secondSettled = false;
    const secondPromise = proxyChannelCoordinator.acquireChannelLease({
      channelId: 11,
      accountExtraConfig: JSON.stringify({ credentialMode: 'session' }),
    }).then((result) => {
      secondSettled = true;
      return result;
    });

    await vi.advanceTimersByTimeAsync(180);
    expect(first.lease.isActive()).toBe(true);
    expect(secondSettled).toBe(false);

    first.lease.release();
    await vi.advanceTimersByTimeAsync(0);

    const second = await secondPromise;
    expect(second.status).toBe('acquired');
    if (second.status === 'acquired') {
      second.lease.release();
    }
  });
});
