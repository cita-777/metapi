import { beforeEach, describe, expect, it, vi } from 'vitest';

const refreshSub2ApiManagedSessionMock = vi.fn();

vi.mock('./sub2apiManagedAuth.js', () => ({
  refreshSub2ApiManagedSession: (...args: unknown[]) => refreshSub2ApiManagedSessionMock(...args),
}));

describe('sub2apiRefreshSingleflight', () => {
  beforeEach(async () => {
    refreshSub2ApiManagedSessionMock.mockReset();
    const { __resetSub2ApiManagedRefreshSingleflightForTests } = await import('./sub2apiRefreshSingleflight.js');
    __resetSub2ApiManagedRefreshSingleflightForTests();
  });

  it('coalesces concurrent refreshes for the same account id', async () => {
    let resolveRefresh: ((value: { accessToken: string; extraConfig: string }) => void) | null = null;
    refreshSub2ApiManagedSessionMock.mockImplementation(
      () => new Promise((resolve) => {
        resolveRefresh = resolve;
      }),
    );

    const { refreshSub2ApiManagedSessionSingleflight } = await import('./sub2apiRefreshSingleflight.js');

    const params = {
      account: { id: 42 } as { id: number },
      site: { id: 7, platform: 'sub2api', url: 'https://sub2.example.com' } as {
        id: number;
        platform: string;
        url: string;
      },
      currentAccessToken: 'stale-access-token',
      currentExtraConfig: '{"sub2apiAuth":{"refreshToken":"refresh-token"}}',
    };

    const first = refreshSub2ApiManagedSessionSingleflight(params as never);
    const second = refreshSub2ApiManagedSessionSingleflight(params as never);

    expect(refreshSub2ApiManagedSessionMock).toHaveBeenCalledTimes(1);

    resolveRefresh?.({
      accessToken: 'fresh-access-token',
      extraConfig: '{"sub2apiAuth":{"refreshToken":"next-refresh-token"}}',
    });

    await expect(first).resolves.toEqual({
      accessToken: 'fresh-access-token',
      extraConfig: '{"sub2apiAuth":{"refreshToken":"next-refresh-token"}}',
    });
    await expect(second).resolves.toEqual({
      accessToken: 'fresh-access-token',
      extraConfig: '{"sub2apiAuth":{"refreshToken":"next-refresh-token"}}',
    });
  });

  it('cleans up in-flight state after a rejected refresh so the next attempt can retry', async () => {
    let rejectRefresh: ((error: Error) => void) | null = null;
    refreshSub2ApiManagedSessionMock.mockImplementation(
      () => new Promise((_resolve, reject) => {
        rejectRefresh = reject;
      }),
    );

    const { refreshSub2ApiManagedSessionSingleflight } = await import('./sub2apiRefreshSingleflight.js');

    const params = {
      account: { id: 42 } as { id: number },
      site: { id: 7, platform: 'sub2api', url: 'https://sub2.example.com' } as {
        id: number;
        platform: string;
        url: string;
      },
      currentAccessToken: 'stale-access-token',
      currentExtraConfig: '{"sub2apiAuth":{"refreshToken":"refresh-token"}}',
    };

    const first = refreshSub2ApiManagedSessionSingleflight(params as never);
    const second = refreshSub2ApiManagedSessionSingleflight(params as never);

    expect(refreshSub2ApiManagedSessionMock).toHaveBeenCalledTimes(1);

    rejectRefresh?.(new Error('refresh rejected'));

    await expect(first).rejects.toThrow('refresh rejected');
    await expect(second).rejects.toThrow('refresh rejected');

    refreshSub2ApiManagedSessionMock.mockResolvedValueOnce({
      accessToken: 'fresh-access-token',
      extraConfig: '{"sub2apiAuth":{"refreshToken":"next-refresh-token"}}',
    });

    await expect(refreshSub2ApiManagedSessionSingleflight(params as never)).resolves.toEqual({
      accessToken: 'fresh-access-token',
      extraConfig: '{"sub2apiAuth":{"refreshToken":"next-refresh-token"}}',
    });
    expect(refreshSub2ApiManagedSessionMock).toHaveBeenCalledTimes(2);
  });
});
