import { beforeEach, describe, expect, it, vi } from 'vitest';

const adapterMock = {
  checkin: vi.fn(),
  login: vi.fn(),
};

const notifyMock = vi.fn();
const reportTokenExpiredMock = vi.fn();
const refreshBalanceMock = vi.fn();
const decryptPasswordMock = vi.fn();

const selectAllMock = vi.fn();
const insertValuesMock = vi.fn();
const updateSetMock = vi.fn();

vi.mock('../db/index.js', () => {
  const selectChain = {
    all: () => selectAllMock(),
    where: () => selectChain,
    innerJoin: () => selectChain,
    from: () => selectChain,
  };

  const insertChain = {
    run: () => ({}),
    values: (...args: unknown[]) => {
      insertValuesMock(...args);
      return insertChain;
    },
  };

  const updateWhereChain = {
    run: () => ({}),
  };

  const updateSetChain = {
    where: () => updateWhereChain,
  };

  return {
    db: {
      select: () => selectChain,
      insert: () => insertChain,
      update: () => ({
        set: (updates: Record<string, unknown>) => {
          updateSetMock(updates);
          return updateSetChain;
        },
      }),
    },
    schema: {
      accounts: { id: 'id', siteId: 'siteId', checkinEnabled: 'checkinEnabled', status: 'status' },
      sites: { id: 'id' },
      checkinLogs: {},
      events: {},
    },
  };
});

vi.mock('./platforms/index.js', () => ({
  getAdapter: () => adapterMock,
}));

vi.mock('./notifyService.js', () => ({
  sendNotification: (...args: unknown[]) => notifyMock(...args),
}));

vi.mock('./alertService.js', () => ({
  reportTokenExpired: (...args: unknown[]) => reportTokenExpiredMock(...args),
}));

vi.mock('./balanceService.js', () => ({
  refreshBalance: (...args: unknown[]) => refreshBalanceMock(...args),
}));

vi.mock('./accountCredentialService.js', () => ({
  decryptAccountPassword: (...args: unknown[]) => decryptPasswordMock(...args),
}));

describe('checkinService auto relogin', () => {
  beforeEach(() => {
    adapterMock.checkin.mockReset();
    adapterMock.login.mockReset();
    notifyMock.mockReset();
    reportTokenExpiredMock.mockReset();
    refreshBalanceMock.mockReset();
    decryptPasswordMock.mockReset();
    selectAllMock.mockReset();
    insertValuesMock.mockReset();
    updateSetMock.mockReset();
  });

  it('retries checkin once after auto relogin when access token is missing', async () => {
    selectAllMock.mockReturnValue([
      {
        accounts: {
          id: 1,
          username: 'linuxdo_7659',
          accessToken: 'expired-token',
          status: 'active',
          extraConfig: JSON.stringify({
            autoRelogin: { username: 'linuxdo_7659', passwordCipher: 'cipher' },
          }),
        },
        sites: {
          id: 3,
          name: 'kfc',
          url: 'https://kfc-api.sxxe.net',
          platform: 'new-api',
        },
      },
    ]);

    adapterMock.checkin
      .mockResolvedValueOnce({ success: false, message: '无权进行此操作，未登录且未提供 access token' })
      .mockResolvedValueOnce({ success: true, message: 'checked in' });
    decryptPasswordMock.mockReturnValue('plain-password');
    adapterMock.login.mockResolvedValue({ success: true, accessToken: 'fresh-token' });

    const { checkinAccount } = await import('./checkinService.js');
    const result = await checkinAccount(1);

    expect(result.success).toBe(true);
    expect(adapterMock.login).toHaveBeenCalledTimes(1);
    expect(adapterMock.checkin).toHaveBeenCalledTimes(2);
    expect(adapterMock.checkin.mock.calls[0][1]).toBe('expired-token');
    expect(adapterMock.checkin.mock.calls[1][1]).toBe('fresh-token');
    expect(adapterMock.checkin.mock.calls[0][2]).toBe(7659);
    expect(updateSetMock).toHaveBeenCalledWith(expect.objectContaining({ accessToken: 'fresh-token' }));
  });

  it('prefers the id reported by relogin over the guess, and never writes the guess back', async () => {
    // `alice_1999` ends in digits that are not the account id — precisely the case
    // guessPlatformUserIdFromUsername() gets wrong, since its /(\d{3,8})$/ only
    // knows how to read a trailing number.
    selectAllMock.mockReturnValue([
      {
        accounts: {
          id: 1,
          username: 'alice_1999',
          accessToken: 'expired-token',
          status: 'active',
          extraConfig: JSON.stringify({
            autoRelogin: { username: 'alice_1999', passwordCipher: 'cipher' },
          }),
        },
        sites: {
          id: 3,
          name: 'kfc',
          url: 'https://kfc-api.sxxe.net',
          platform: 'new-api',
        },
      },
    ]);

    adapterMock.checkin
      .mockResolvedValueOnce({ success: false, message: '无权进行此操作，未登录且未提供 access token' })
      .mockResolvedValueOnce({ success: true, message: 'checked in' });
    decryptPasswordMock.mockReturnValue('plain-password');
    adapterMock.login.mockResolvedValue({
      success: true,
      accessToken: 'fresh-token',
      platformUserId: 500123,
    });

    const { checkinAccount } = await import('./checkinService.js');
    await checkinAccount(1);

    // The first attempt has nothing better than the guess...
    expect(adapterMock.checkin.mock.calls[0][2]).toBe(1999);
    // ...but the retry must use the id the site itself reported.
    expect(adapterMock.checkin.mock.calls[1][2]).toBe(500123);

    // And no later write may put the guess back over it. Parse the whole config,
    // not just the id: a write that *replaced* extraConfig with only
    // `{ platformUserId }` would satisfy an id-only assertion while dropping the
    // autoRelogin credentials, leaving nothing to re-login with next time.
    const writtenConfigs = updateSetMock.mock.calls
      .map((call) => (call[0] as Record<string, unknown> | undefined)?.extraConfig)
      .filter((cfg): cfg is string => typeof cfg === 'string')
      .map((cfg) => JSON.parse(cfg) as {
        platformUserId?: number;
        autoRelogin?: { username?: string; passwordCipher?: string };
      });
    expect(writtenConfigs.length).toBeGreaterThan(0);
    // Credentials must survive *every* write. `toContainEqual` would only prove one
    // write got it right, while a later one could still drop them — and a single
    // drop leaves nothing to re-login with next round.
    for (const cfg of writtenConfigs) {
      expect(cfg.autoRelogin).toEqual({ username: 'alice_1999', passwordCipher: 'cipher' });
    }
    const writtenIds = writtenConfigs.map((cfg) => cfg.platformUserId);
    expect(writtenIds).toContain(500123);
    expect(writtenIds).not.toContain(1999);
  });

  it('passes guessed platform user id when config does not include it', async () => {
    selectAllMock.mockReturnValue([
      {
        accounts: {
          id: 2,
          username: 'linuxdo_11494',
          accessToken: 'token',
          status: 'active',
          extraConfig: null,
        },
        sites: {
          id: 4,
          name: 'wong',
          url: 'https://wzw.pp.ua',
          platform: 'new-api',
        },
      },
    ]);

    adapterMock.checkin.mockResolvedValue({ success: true, message: 'checked in' });

    const { checkinAccount } = await import('./checkinService.js');
    await checkinAccount(2);

    expect(adapterMock.checkin).toHaveBeenCalledTimes(1);
    expect(adapterMock.checkin.mock.calls[0][2]).toBe(11494);
  });

  it('keeps successful checkin as success when message is 签到成功', async () => {
    selectAllMock.mockReturnValue([
      {
        accounts: {
          id: 12,
          username: 'linuxdo_5566',
          accessToken: 'token',
          status: 'active',
          extraConfig: null,
        },
        sites: {
          id: 12,
          name: 'demo',
          url: 'https://example.com',
          platform: 'new-api',
        },
      },
    ]);

    adapterMock.checkin.mockResolvedValue({ success: true, message: '签到成功' });

    const { checkinAccount } = await import('./checkinService.js');
    const result = await checkinAccount(12);

    expect(result.success).toBe(true);
    const firstInsertPayload = insertValuesMock.mock.calls[0]?.[0] as Record<string, unknown>;
    expect(firstInsertPayload?.status).toBe('success');
  });

  it('infers reward from balance delta when checkin reward text is empty', async () => {
    selectAllMock.mockReturnValue([
      {
        accounts: {
          id: 13,
          username: 'linuxdo_7788',
          accessToken: 'token',
          status: 'active',
          balance: 10,
          extraConfig: null,
        },
        sites: {
          id: 13,
          name: 'demo',
          url: 'https://example.com',
          platform: 'new-api',
        },
      },
    ]);

    adapterMock.checkin.mockResolvedValue({ success: true, message: 'checkin success' });
    refreshBalanceMock.mockResolvedValue({ balance: 12.5, used: 0, quota: 12.5 });

    const { checkinAccount } = await import('./checkinService.js');
    await checkinAccount(13);

    const firstInsertPayload = insertValuesMock.mock.calls[0]?.[0] as Record<string, unknown>;
    expect(Number(firstInsertPayload?.reward)).toBeCloseTo(2.5, 6);
  });

  it('treats already checked in responses as successful checkins', async () => {
    selectAllMock.mockReturnValue([
      {
        accounts: {
          id: 9,
          username: 'linuxdo_9999',
          accessToken: 'token',
          status: 'active',
          extraConfig: null,
        },
        sites: {
          id: 9,
          name: 'demo',
          url: 'https://example.com',
          platform: 'new-api',
        },
      },
    ]);

    adapterMock.checkin.mockResolvedValue({ success: false, message: '今天已经签到过啦' });

    const { checkinAccount } = await import('./checkinService.js');
    const result = await checkinAccount(9);

    expect(result.success).toBe(true);
    expect(result.status).toBe('success');
    const firstInsertPayload = insertValuesMock.mock.calls[0]?.[0] as Record<string, unknown>;
    expect(firstInsertPayload?.status).toBe('success');
    expect(notifyMock).not.toHaveBeenCalled();
  });

  it('does not advance lastCheckinAt for already checked in responses in interval mode', async () => {
    selectAllMock.mockReturnValue([
      {
        accounts: {
          id: 16,
          username: 'interval-user',
          accessToken: 'token',
          status: 'active',
          extraConfig: null,
        },
        sites: {
          id: 16,
          name: 'demo',
          url: 'https://example.com',
          platform: 'new-api',
        },
      },
    ]);

    adapterMock.checkin.mockResolvedValue({ success: false, message: '今天已经签到过啦' });

    const { checkinAccount } = await import('./checkinService.js');
    const result = await checkinAccount(16, { scheduleMode: 'interval' });

    expect(result.success).toBe(true);
    expect(result.status).toBe('success');
    expect(updateSetMock).not.toHaveBeenCalledWith(expect.objectContaining({ lastCheckinAt: expect.any(String) }));
  });

  it('advances lastCheckinAt when interval mode gets a direct success', async () => {
    selectAllMock.mockReturnValue([
      {
        accounts: {
          id: 17,
          username: 'interval-success',
          accessToken: 'token',
          status: 'active',
          extraConfig: null,
        },
        sites: {
          id: 17,
          name: 'demo',
          url: 'https://example.com',
          platform: 'new-api',
        },
      },
    ]);

    adapterMock.checkin.mockResolvedValue({ success: true, message: '签到成功' });

    const { checkinAccount } = await import('./checkinService.js');
    const result = await checkinAccount(17, { scheduleMode: 'interval' });

    expect(result.success).toBe(true);
    expect(updateSetMock).toHaveBeenCalledWith(expect.objectContaining({ lastCheckinAt: expect.any(String) }));
  });

  it('treats unsupported checkin endpoint responses as skipped', async () => {
    selectAllMock.mockReturnValue([
      {
        accounts: {
          id: 10,
          username: 'linuxdo_131936',
          accessToken: 'token',
          status: 'active',
          extraConfig: null,
        },
        sites: {
          id: 10,
          name: 'anyrouter',
          url: 'https://anyrouter.top',
          platform: 'anyrouter',
        },
      },
    ]);

    adapterMock.checkin.mockResolvedValue({
      success: false,
      message: 'HTTP 404: {"error":{"message":"Invalid URL (POST /api/user/checkin)"}}',
    });

    const { checkinAccount } = await import('./checkinService.js');
    const result = await checkinAccount(10);

    expect(result.success).toBe(true);
    expect(result.status).toBe('skipped');
    const firstInsertPayload = insertValuesMock.mock.calls[0]?.[0] as Record<string, unknown>;
    expect(firstInsertPayload?.status).toBe('skipped');
    expect(refreshBalanceMock).not.toHaveBeenCalled();
    expect(notifyMock).not.toHaveBeenCalled();
  });

  it('skips account updates when unsupported checkin responses do not change account state', async () => {
    selectAllMock.mockReturnValue([
      {
        accounts: {
          id: 18,
          username: 'plain-user',
          accessToken: 'token',
          status: 'active',
          extraConfig: null,
        },
        sites: {
          id: 18,
          name: 'done-hub',
          url: 'https://done.example.com',
          platform: 'donehub',
        },
      },
    ]);

    adapterMock.checkin.mockResolvedValue({
      success: false,
      message: 'checkin endpoint not found',
    });

    const { checkinAccount } = await import('./checkinService.js');
    const result = await checkinAccount(18);

    expect(result.success).toBe(true);
    expect(result.status).toBe('skipped');
    expect(updateSetMock).not.toHaveBeenCalled();
    const firstInsertPayload = insertValuesMock.mock.calls[0]?.[0] as Record<string, unknown>;
    expect(firstInsertPayload?.status).toBe('skipped');
  });

  it('treats sub2api checkin unsupported message as skipped', async () => {
    selectAllMock.mockReturnValue([
      {
        accounts: {
          id: 15,
          username: 'sub2_user',
          accessToken: 'token',
          status: 'active',
          extraConfig: null,
        },
        sites: {
          id: 15,
          name: 'sub2',
          url: 'https://sub2.example.com',
          platform: 'sub2api',
        },
      },
    ]);

    adapterMock.checkin.mockResolvedValue({
      success: false,
      message: 'Check-in is not supported by Sub2API',
    });

    const { checkinAccount } = await import('./checkinService.js');
    const result = await checkinAccount(15);

    expect(result.success).toBe(true);
    expect(result.status).toBe('skipped');
    const firstInsertPayload = insertValuesMock.mock.calls[0]?.[0] as Record<string, unknown>;
    expect(firstInsertPayload?.status).toBe('skipped');
    expect(refreshBalanceMock).not.toHaveBeenCalled();
    expect(notifyMock).not.toHaveBeenCalled();
  });

  it('treats turnstile-required responses as skipped', async () => {
    selectAllMock.mockReturnValue([
      {
        accounts: {
          id: 14,
          username: 'linuxdo_10277',
          accessToken: 'token',
          status: 'active',
          extraConfig: null,
        },
        sites: {
          id: 14,
          name: 'run-anytime',
          url: 'https://runanytime.hxi.me',
          platform: 'new-api',
        },
      },
    ]);

    adapterMock.checkin.mockResolvedValue({
      success: false,
      message: 'Turnstile token 为空',
    });

    const { checkinAccount } = await import('./checkinService.js');
    const result = await checkinAccount(14);

    expect(result.success).toBe(true);
    expect(result.status).toBe('skipped');
    const firstInsertPayload = insertValuesMock.mock.calls[0]?.[0] as Record<string, unknown>;
    expect(firstInsertPayload?.status).toBe('skipped');
    expect(firstInsertPayload?.message).toBe('站点开启了 Turnstile 校验，需要人工签到');
    expect(refreshBalanceMock).not.toHaveBeenCalled();
    expect(notifyMock).not.toHaveBeenCalled();
  });
});
