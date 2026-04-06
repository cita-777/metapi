import { beforeEach, describe, expect, it, vi } from 'vitest';

const adapterMock = {
  getBalance: vi.fn(),
  login: vi.fn(),
};

const selectAllMock = vi.fn();
const updateSetMock = vi.fn();
const insertValuesMock = vi.fn();
const reportTokenExpiredMock = vi.fn();
const sendNotificationMock = vi.fn();
const decryptPasswordMock = vi.fn();
const setAccountRuntimeHealthMock = vi.fn();
const extractRuntimeHealthMock = vi.fn();
const undiciFetchMock = vi.fn();

vi.mock('../db/index.js', () => {
  const selectChain = {
    all: () => selectAllMock(),
    where: () => selectChain,
    innerJoin: () => selectChain,
    from: () => selectChain,
  };

  const updateWhereChain = {
    run: () => ({}),
  };

  const updateSetChain = {
    where: () => updateWhereChain,
  };

  const insertChain = {
    run: () => ({}),
    values: (...args: unknown[]) => {
      insertValuesMock(...args);
      return insertChain;
    },
  };

  return {
    db: {
      select: () => selectChain,
      update: () => ({
        set: (updates: Record<string, unknown>) => {
          updateSetMock(updates);
          return updateSetChain;
        },
      }),
      insert: () => insertChain,
    },
    schema: {
      accounts: { id: 'id', siteId: 'siteId', status: 'status' },
      sites: { id: 'id' },
      events: {},
    },
  };
});

vi.mock('./platforms/index.js', () => ({
  getAdapter: () => adapterMock,
}));

vi.mock('./alertService.js', () => ({
  reportTokenExpired: (...args: unknown[]) => reportTokenExpiredMock(...args),
}));

vi.mock('./notifyService.js', () => ({
  sendNotification: (...args: unknown[]) => sendNotificationMock(...args),
}));

vi.mock('./accountCredentialService.js', () => ({
  decryptAccountPassword: (...args: unknown[]) => decryptPasswordMock(...args),
}));

vi.mock('./accountHealthService.js', () => ({
  setAccountRuntimeHealth: (...args: unknown[]) => setAccountRuntimeHealthMock(...args),
  extractRuntimeHealth: (...args: unknown[]) => extractRuntimeHealthMock(...args),
}));

vi.mock('undici', () => ({
  fetch: (...args: unknown[]) => undiciFetchMock(...args),
}));

describe('balanceService auto relogin', () => {
  beforeEach(() => {
    adapterMock.getBalance.mockReset();
    adapterMock.login.mockReset();
    selectAllMock.mockReset();
    updateSetMock.mockReset();
    insertValuesMock.mockReset();
    reportTokenExpiredMock.mockReset();
    sendNotificationMock.mockReset();
    decryptPasswordMock.mockReset();
    setAccountRuntimeHealthMock.mockReset();
    extractRuntimeHealthMock.mockReset();
    undiciFetchMock.mockReset();

    extractRuntimeHealthMock.mockReturnValue(null);
    undiciFetchMock.mockResolvedValue({
      ok: false,
      json: async () => ({}),
    });
  });

  it('retries balance fetch once after successful auto relogin', async () => {
    selectAllMock.mockReturnValue([
      {
        accounts: {
          id: 1,
          username: 'linuxdo_11494',
          accessToken: 'stale-token',
          status: 'active',
          extraConfig: JSON.stringify({
            platformUserId: 11494,
            autoRelogin: { username: 'linuxdo_11494', passwordCipher: 'cipher' },
          }),
        },
        sites: {
          id: 3,
          name: 'wong',
          url: 'https://wzw.pp.ua',
          platform: 'new-api',
        },
      },
    ]);

    adapterMock.getBalance
      .mockRejectedValueOnce(new Error('HTTP 401: access token required'))
      .mockResolvedValueOnce({ balance: 12, used: 1, quota: 13 });
    decryptPasswordMock.mockReturnValue('plain-password');
    adapterMock.login.mockResolvedValue({ success: true, accessToken: 'fresh-token' });

    const { refreshBalance } = await import('./balanceService.js');
    const result = await refreshBalance(1);

    expect(result).toEqual({ balance: 12, used: 1, quota: 13 });
    expect(adapterMock.login).toHaveBeenCalledTimes(1);
    expect(adapterMock.getBalance).toHaveBeenCalledTimes(2);
    expect(adapterMock.getBalance.mock.calls[0][1]).toBe('stale-token');
    expect(adapterMock.getBalance.mock.calls[1][1]).toBe('fresh-token');
    expect(updateSetMock.mock.calls.some((call) => call[0]?.accessToken === 'fresh-token')).toBe(true);
    expect(reportTokenExpiredMock).not.toHaveBeenCalled();
  });

  it('reports token expired when relogin is unavailable', async () => {
    selectAllMock.mockReturnValue([
      {
        accounts: {
          id: 2,
          username: 'linuxdo_7659',
          accessToken: 'stale-token',
          status: 'active',
          extraConfig: null,
        },
        sites: {
          id: 4,
          name: 'kfc',
          url: 'https://kfc-api.sxxe.net',
          platform: 'new-api',
        },
      },
    ]);

    adapterMock.getBalance.mockRejectedValueOnce(new Error('HTTP 401: access token required'));

    const { refreshBalance } = await import('./balanceService.js');
    await expect(refreshBalance(2)).rejects.toThrow('access token');

    expect(adapterMock.login).not.toHaveBeenCalled();
    expect(reportTokenExpiredMock).toHaveBeenCalledTimes(1);
  });

  it('does not report token expired for generic forbidden balance errors', async () => {
    selectAllMock.mockReturnValue([
      {
        accounts: {
          id: 12,
          username: 'linuxdo_forbidden',
          accessToken: 'stale-token',
          status: 'active',
          extraConfig: null,
        },
        sites: {
          id: 12,
          name: 'kfc',
          url: 'https://kfc-api.sxxe.net',
          platform: 'new-api',
        },
      },
    ]);

    adapterMock.getBalance.mockRejectedValueOnce(new Error('HTTP 403: forbidden'));

    const { refreshBalance } = await import('./balanceService.js');
    await expect(refreshBalance(12)).rejects.toThrow('forbidden');

    expect(reportTokenExpiredMock).not.toHaveBeenCalled();
  });

  it('does not report token expired for missing new-api-user errors', async () => {
    selectAllMock.mockReturnValue([
      {
        accounts: {
          id: 13,
          username: 'linuxdo_missing_user',
          accessToken: 'stale-token',
          status: 'active',
          extraConfig: null,
        },
        sites: {
          id: 13,
          name: 'kfc',
          url: 'https://kfc-api.sxxe.net',
          platform: 'new-api',
        },
      },
    ]);

    adapterMock.getBalance.mockRejectedValueOnce(new Error('HTTP 400: new-api-user required'));

    const { refreshBalance } = await import('./balanceService.js');
    await expect(refreshBalance(13)).rejects.toThrow('new-api-user');

    expect(reportTokenExpiredMock).not.toHaveBeenCalled();
  });

  it('proactively refreshes sub2api token when managed refresh token is near expiry', async () => {
    selectAllMock.mockReturnValue([
      {
        accounts: {
          id: 5,
          username: 'sub2-user',
          accessToken: 'old-access-token',
          status: 'active',
          extraConfig: JSON.stringify({
            sub2apiAuth: {
              refreshToken: 'refresh-token-1',
              tokenExpiresAt: Date.now() + 60_000,
            },
          }),
        },
        sites: {
          id: 7,
          name: 'sub2',
          url: 'https://sub2.example.com',
          platform: 'sub2api',
        },
      },
    ]);

    undiciFetchMock.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        code: 0,
        message: 'success',
        data: {
          access_token: 'new-access-token',
          refresh_token: 'refresh-token-2',
          expires_in: 3600,
        },
      }),
    });
    adapterMock.getBalance.mockResolvedValueOnce({ balance: 20, used: 1, quota: 21 });

    const { refreshBalance } = await import('./balanceService.js');
    const result = await refreshBalance(5);

    expect(result).toEqual({ balance: 20, used: 1, quota: 21 });
    expect(adapterMock.getBalance).toHaveBeenCalledTimes(1);
    expect(adapterMock.getBalance.mock.calls[0]?.[1]).toBe('new-access-token');
    expect(updateSetMock.mock.calls.some((call) => call[0]?.accessToken === 'new-access-token')).toBe(true);
    const updateWithSub2ApiAuth = updateSetMock.mock.calls
      .map((call) => call[0] as Record<string, unknown>)
      .find((payload) => typeof payload.extraConfig === 'string' && String(payload.extraConfig).includes('refresh-token-2'));
    expect(updateWithSub2ApiAuth).toBeDefined();
    const parsedExtra = JSON.parse(String(updateWithSub2ApiAuth?.extraConfig)) as {
      sub2apiAuth?: { refreshToken?: string; tokenExpiresAt?: number };
    };
    expect(parsedExtra.sub2apiAuth?.refreshToken).toBe('refresh-token-2');
    expect(typeof parsedExtra.sub2apiAuth?.tokenExpiresAt).toBe('number');
  });

  it('retries once via sub2api managed refresh token when balance returns 401', async () => {
    selectAllMock.mockReturnValue([
      {
        accounts: {
          id: 6,
          username: 'sub2-user',
          accessToken: 'expired-access-token',
          status: 'active',
          extraConfig: JSON.stringify({
            sub2apiAuth: {
              refreshToken: 'refresh-token-3',
            },
          }),
        },
        sites: {
          id: 8,
          name: 'sub2',
          url: 'https://sub2.example.com',
          platform: 'sub2api',
        },
      },
    ]);

    adapterMock.getBalance
      .mockRejectedValueOnce(new Error('HTTP 401: unauthorized'))
      .mockResolvedValueOnce({ balance: 8, used: 1, quota: 9 });
    adapterMock.login.mockResolvedValue({ success: false });
    undiciFetchMock.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        code: 0,
        message: 'success',
        data: {
          access_token: 'retried-access-token',
          refresh_token: 'refresh-token-4',
          expires_in: 3600,
        },
      }),
    });

    const { refreshBalance } = await import('./balanceService.js');
    const result = await refreshBalance(6);

    expect(result).toEqual({ balance: 8, used: 1, quota: 9 });
    expect(adapterMock.getBalance).toHaveBeenCalledTimes(2);
    expect(adapterMock.getBalance.mock.calls[0]?.[1]).toBe('expired-access-token');
    expect(adapterMock.getBalance.mock.calls[1]?.[1]).toBe('retried-access-token');
    expect(adapterMock.login).not.toHaveBeenCalled();
    expect(reportTokenExpiredMock).not.toHaveBeenCalled();
  });

  it('surfaces upstream sub2api refresh failure detail when managed refresh is rejected', async () => {
    selectAllMock.mockReturnValue([
      {
        accounts: {
          id: 8,
          username: 'sub2-user',
          accessToken: 'expired-access-token',
          status: 'active',
          extraConfig: JSON.stringify({
            sub2apiAuth: {
              refreshToken: 'refresh-token-invalid',
            },
          }),
        },
        sites: {
          id: 9,
          name: 'sub2',
          url: 'https://sub2.example.com',
          platform: 'sub2api',
        },
      },
    ]);

    adapterMock.getBalance.mockRejectedValueOnce(new Error('HTTP 401: unauthorized'));
    undiciFetchMock.mockResolvedValueOnce({
      ok: false,
      status: 401,
      text: async () => JSON.stringify({
        code: 401,
        message: 'invalid refresh token',
        reason: 'REFRESH_TOKEN_INVALID',
      }),
      json: async () => ({
        code: 401,
        message: 'invalid refresh token',
        reason: 'REFRESH_TOKEN_INVALID',
      }),
    });

    const { refreshBalance } = await import('./balanceService.js');
    await expect(refreshBalance(8)).rejects.toThrow(
      'sub2api token refresh failed: HTTP 401: invalid refresh token (REFRESH_TOKEN_INVALID)',
    );

    expect(adapterMock.login).not.toHaveBeenCalled();
  });

  it('skips balance refresh for api-key-only accounts without expiring them', async () => {
    selectAllMock.mockReturnValue([
      {
        accounts: {
          id: 10,
          username: 'wong-key',
          accessToken: '',
          apiToken: 'sk-only-token',
          balance: 5,
          balanceUsed: 1,
          quota: 6,
          status: 'active',
          extraConfig: JSON.stringify({
            credentialMode: 'apikey',
          }),
        },
        sites: {
          id: 10,
          name: 'wong',
          url: 'https://wzw.pp.ua',
          platform: 'new-api',
        },
      },
    ]);

    const { refreshBalance } = await import('./balanceService.js');
    const result = await refreshBalance(10);

    expect(result).toEqual({
      balance: 5,
      used: 1,
      quota: 6,
      skipped: true,
      reason: 'proxy_only',
    });
    expect(adapterMock.getBalance).not.toHaveBeenCalled();
    expect(adapterMock.login).not.toHaveBeenCalled();
    expect(reportTokenExpiredMock).not.toHaveBeenCalled();
    expect(setAccountRuntimeHealthMock).not.toHaveBeenCalled();
  });

  it('keeps degraded health when checkin is unsupported but balance refresh succeeds', async () => {
    selectAllMock.mockReturnValue([
      {
        accounts: {
          id: 3,
          username: 'ld6jl3djexjf',
          accessToken: 'active-token',
          status: 'active',
          extraConfig: JSON.stringify({
            runtimeHealth: {
              state: 'degraded',
              reason: 'checkin endpoint not found',
              source: 'checkin',
            },
          }),
        },
        sites: {
          id: 5,
          name: 'Wind Hub',
          url: 'https://windhub.cc',
          platform: 'done-hub',
        },
      },
    ]);

    adapterMock.getBalance.mockResolvedValueOnce({ balance: 100, used: 2, quota: 102 });
    extractRuntimeHealthMock.mockReturnValue({
      state: 'degraded',
      reason: 'checkin endpoint not found',
      source: 'checkin',
      checkedAt: '2026-02-25T12:00:00.000Z',
    });

    const { refreshBalance } = await import('./balanceService.js');
    const result = await refreshBalance(3);

    expect(result).toEqual({ balance: 100, used: 2, quota: 102 });
    expect(setAccountRuntimeHealthMock).toHaveBeenCalledWith(
      3,
      expect.objectContaining({
        state: 'degraded',
        reason: 'checkin endpoint not found',
      }),
    );
  });

  it('fills today income snapshot from log endpoint when balance api lacks today_income', async () => {
    selectAllMock.mockReturnValue([
      {
        accounts: {
          id: 4,
          username: 'linuxdo_7659',
          accessToken: 'active-token',
          status: 'active',
          extraConfig: null,
        },
        sites: {
          id: 6,
          name: 'kfc',
          url: 'https://kfc-api.sxxe.net',
          platform: 'new-api',
        },
      },
    ]);

    adapterMock.getBalance.mockResolvedValueOnce({ balance: 12, used: 1, quota: 13 });
    undiciFetchMock
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ data: { items: [], total: 0 } }),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          data: {
            items: [{ quota: 0, content: '签到奖励 2.083650 额度' }],
            total: 1,
          },
        }),
      });

    const { refreshBalance } = await import('./balanceService.js');
    const result = await refreshBalance(4);

    expect(result).toEqual({ balance: 12, used: 1, quota: 13, todayIncome: 2.08365 });
    const updateWithSnapshot = updateSetMock.mock.calls
      .map((call) => call[0] as Record<string, unknown>)
      .find((payload) => typeof payload.extraConfig === 'string');
    expect(updateWithSnapshot).toBeDefined();
    const parsedExtra = JSON.parse(String(updateWithSnapshot?.extraConfig));
    expect(parsedExtra.todayIncomeSnapshot?.latest).toBeCloseTo(2.08365, 6);
  });

  it('does not send low balance reminder notification when balance is below threshold', async () => {
    selectAllMock.mockReturnValue([
      {
        accounts: {
          id: 7,
          username: 'linuxdo_low_balance',
          accessToken: 'active-token',
          status: 'active',
          extraConfig: null,
        },
        sites: {
          id: 9,
          name: 'wong',
          url: 'https://wzw.pp.ua',
          platform: 'new-api',
        },
      },
    ]);

    adapterMock.getBalance.mockResolvedValueOnce({ balance: 0.5, used: 1, quota: 1.5 });

    const { refreshBalance } = await import('./balanceService.js');
    const result = await refreshBalance(7);

    expect(result).toEqual({ balance: 0.5, used: 1, quota: 1.5 });
    expect(sendNotificationMock).not.toHaveBeenCalled();
    expect(insertValuesMock).not.toHaveBeenCalled();
  });
});
