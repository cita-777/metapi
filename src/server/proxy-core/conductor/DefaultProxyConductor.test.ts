import { describe, expect, it, vi } from 'vitest';

import { DefaultProxyConductor } from './DefaultProxyConductor.js';
import { terminalStreamFailure } from './streamTermination.js';

const baseSelectedChannel = {
  channel: { id: 11, routeId: 22 },
  site: { id: 44, name: 'demo-site', url: 'https://upstream.example.com', platform: 'openai' },
  account: { id: 33, username: 'demo-user' },
  tokenName: 'default',
  tokenValue: 'sk-demo',
  actualModel: 'upstream-gpt',
};

describe('DefaultProxyConductor', () => {
  it('returns the first selected channel when the first attempt succeeds', async () => {
    const selectChannel = vi.fn().mockResolvedValue(baseSelectedChannel);
    const selectNextChannel = vi.fn();
    const recordSuccess = vi.fn().mockResolvedValue(undefined);
    const recordFailure = vi.fn().mockResolvedValue(undefined);
    const conductor = new DefaultProxyConductor({
      selectChannel,
      selectNextChannel,
      recordSuccess,
      recordFailure,
    });
    const attempt = vi.fn().mockResolvedValue({
      ok: true,
      response: new Response('ok', { status: 200 }),
      latencyMs: 12,
      cost: 0.25,
    });

    const result = await conductor.execute({
      requestedModel: 'gpt-5.4',
      attempt,
    });

    expect(result).toMatchObject({
      ok: true,
      selected: baseSelectedChannel,
      attempts: 1,
    });
    expect(selectChannel).toHaveBeenCalledWith('gpt-5.4', undefined);
    expect(selectNextChannel).not.toHaveBeenCalled();
    expect(recordFailure).not.toHaveBeenCalled();
    expect(recordSuccess).toHaveBeenCalledWith(11, {
      latencyMs: 12,
      cost: 0.25,
    });
  });

  it('retries on the same channel when the attempt asks for a same-channel retry', async () => {
    const selectChannel = vi.fn().mockResolvedValue(baseSelectedChannel);
    const selectNextChannel = vi.fn();
    const recordSuccess = vi.fn().mockResolvedValue(undefined);
    const recordFailure = vi.fn().mockResolvedValue(undefined);
    const conductor = new DefaultProxyConductor({
      selectChannel,
      selectNextChannel,
      recordSuccess,
      recordFailure,
    });
    const attempt = vi.fn()
      .mockResolvedValueOnce({
        ok: false,
        action: 'retry_same_channel',
        status: 429,
        rawErrorText: 'rate limited',
      })
      .mockResolvedValueOnce({
        ok: true,
        response: new Response('ok', { status: 200 }),
      });

    const result = await conductor.execute({
      requestedModel: 'gpt-5.4',
      attempt,
    });

    expect(result).toMatchObject({
      ok: true,
      attempts: 2,
    });
    expect(selectNextChannel).not.toHaveBeenCalled();
    expect(attempt).toHaveBeenCalledTimes(2);
    expect(recordFailure).toHaveBeenCalledWith(11, {
      status: 429,
      rawErrorText: 'rate limited',
    });
  });

  it('fails over to the next channel when the attempt asks for failover', async () => {
    const nextSelectedChannel = {
      ...baseSelectedChannel,
      channel: { id: 12, routeId: 22 },
      tokenValue: 'sk-next',
    };
    const selectChannel = vi.fn().mockResolvedValue(baseSelectedChannel);
    const selectNextChannel = vi.fn().mockResolvedValue(nextSelectedChannel);
    const recordSuccess = vi.fn().mockResolvedValue(undefined);
    const recordFailure = vi.fn().mockResolvedValue(undefined);
    const conductor = new DefaultProxyConductor({
      selectChannel,
      selectNextChannel,
      recordSuccess,
      recordFailure,
    });
    const attempt = vi.fn()
      .mockResolvedValueOnce({
        ok: false,
        action: 'failover',
        status: 503,
        rawErrorText: 'upstream unavailable',
      })
      .mockResolvedValueOnce({
        ok: true,
        response: new Response('ok', { status: 200 }),
      });

    const result = await conductor.execute({
      requestedModel: 'gpt-5.4',
      attempt,
    });

    expect(result).toMatchObject({
      ok: true,
      selected: nextSelectedChannel,
      attempts: 2,
    });
    expect(selectNextChannel).toHaveBeenCalledWith('gpt-5.4', [11], undefined);
    expect(recordFailure).toHaveBeenCalledWith(11, {
      status: 503,
      rawErrorText: 'upstream unavailable',
    });
    expect(recordSuccess).toHaveBeenCalledWith(12, {
      latencyMs: null,
      cost: null,
    });
  });

  it('refreshes auth on 401 and retries the same channel with the refreshed selection', async () => {
    const refreshedChannel = {
      ...baseSelectedChannel,
      tokenValue: 'sk-refreshed',
    };
    const refreshAuth = vi.fn().mockResolvedValue(refreshedChannel);
    const conductor = new DefaultProxyConductor({
      selectChannel: vi.fn().mockResolvedValue(baseSelectedChannel),
      selectNextChannel: vi.fn(),
      recordSuccess: vi.fn().mockResolvedValue(undefined),
      recordFailure: vi.fn().mockResolvedValue(undefined),
      refreshAuth,
    });
    const attempt = vi.fn()
      .mockResolvedValueOnce({
        ok: false,
        action: 'refresh_auth',
        status: 401,
        rawErrorText: 'expired token',
      })
      .mockResolvedValueOnce({
        ok: true,
        response: new Response('ok', { status: 200 }),
      });

    const result = await conductor.execute({
      requestedModel: 'gpt-5.4',
      attempt,
    });

    expect(result).toMatchObject({
      ok: true,
      selected: refreshedChannel,
      attempts: 2,
    });
    expect(refreshAuth).toHaveBeenCalledWith(baseSelectedChannel, {
      status: 401,
      rawErrorText: 'expired token',
    });
  });

  it('returns a no_channel result when no channel is available', async () => {
    const conductor = new DefaultProxyConductor({
      selectChannel: vi.fn().mockResolvedValue(null),
      selectNextChannel: vi.fn(),
      recordSuccess: vi.fn(),
      recordFailure: vi.fn(),
      previewSelectedChannel: vi.fn().mockResolvedValue(null),
    });

    expect(await conductor.previewSelectedChannel('gpt-5.4')).toBe(null);

    const result = await conductor.execute({
      requestedModel: 'gpt-5.4',
      attempt: vi.fn(),
    });

    expect(result).toEqual({
      ok: false,
      reason: 'no_channel',
      attempts: 0,
    });
  });

  it('propagates terminal stream failures and calls the terminal failure hook', async () => {
    const onTerminalFailure = vi.fn().mockResolvedValue(undefined);
    const conductor = new DefaultProxyConductor({
      selectChannel: vi.fn().mockResolvedValue(baseSelectedChannel),
      selectNextChannel: vi.fn(),
      recordSuccess: vi.fn(),
      recordFailure: vi.fn().mockResolvedValue(undefined),
    });
    const attempt = vi.fn().mockResolvedValue({
      ok: false,
      ...terminalStreamFailure({
        status: 502,
        rawErrorText: 'stream disconnected before completion',
      }),
    });

    const result = await conductor.execute({
      requestedModel: 'gpt-5.4',
      attempt,
      onTerminalFailure,
    });

    expect(result).toEqual({
      ok: false,
      reason: 'terminal',
      selected: baseSelectedChannel,
      status: 502,
      rawErrorText: 'stream disconnected before completion',
      attempts: 1,
    });
    expect(onTerminalFailure).toHaveBeenCalledWith(baseSelectedChannel, {
      status: 502,
      rawErrorText: 'stream disconnected before completion',
    });
  });
});
