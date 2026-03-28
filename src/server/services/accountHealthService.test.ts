import { describe, expect, it } from 'vitest';
import { buildRuntimeHealthForAccount } from './accountHealthService.js';

describe('accountHealthService', () => {
  it('marks disabled when site or account is disabled', () => {
    expect(
      buildRuntimeHealthForAccount({ accountStatus: 'active', siteStatus: 'disabled', extraConfig: null }).state,
    ).toBe('disabled');
    expect(
      buildRuntimeHealthForAccount({ accountStatus: 'disabled', siteStatus: 'active', extraConfig: null }).state,
    ).toBe('disabled');
  });

  it('marks unhealthy when account is expired', () => {
    const health = buildRuntimeHealthForAccount({
      accountStatus: 'expired',
      siteStatus: 'active',
      extraConfig: null,
    });
    expect(health.state).toBe('unhealthy');
  });

  it('does not reuse expired session-token health for proxy-only accounts', () => {
    const health = buildRuntimeHealthForAccount({
      accountStatus: 'expired',
      siteStatus: 'active',
      extraConfig: null,
      sessionCapable: false,
    });

    expect(health).toMatchObject({
      state: 'unknown',
      source: 'none',
    });
    expect(health.reason).not.toContain('访问令牌已过期');
  });

  it('ignores stored auth failures for proxy-only accounts', () => {
    const health = buildRuntimeHealthForAccount({
      accountStatus: 'active',
      siteStatus: 'active',
      sessionCapable: false,
      extraConfig: JSON.stringify({
        runtimeHealth: {
          state: 'unhealthy',
          reason: '访问令牌失效：无权进行此操作，access token 无效',
          source: 'auth',
          checkedAt: '2026-03-07T09:00:01.432Z',
        },
      }),
    });

    expect(health).toMatchObject({
      state: 'unknown',
      source: 'none',
    });
    expect(health.reason).not.toContain('访问令牌');
  });

  it('returns stored runtime health from extra config when available', () => {
    const health = buildRuntimeHealthForAccount({
      accountStatus: 'active',
      siteStatus: 'active',
      extraConfig: JSON.stringify({
        runtimeHealth: {
          state: 'healthy',
          reason: '余额刷新成功',
          source: 'balance',
          checkedAt: '2026-02-25T12:00:00.000Z',
        },
      }),
    });

    expect(health).toMatchObject({
      state: 'healthy',
      reason: '余额刷新成功',
      source: 'balance',
      checkedAt: '2026-02-25T12:00:00.000Z',
    });
  });

  it('returns stored runtime health when extra config is already a parsed object', () => {
    const health = buildRuntimeHealthForAccount({
      accountStatus: 'active',
      siteStatus: 'active',
      extraConfig: {
        runtimeHealth: {
          state: 'healthy',
          reason: '余额刷新成功',
          source: 'balance',
          checkedAt: '2026-02-25T12:00:00.000Z',
        },
      },
    });

    expect(health).toMatchObject({
      state: 'healthy',
      reason: '余额刷新成功',
      source: 'balance',
      checkedAt: '2026-02-25T12:00:00.000Z',
    });
  });

  it('falls back to unknown when no runtime health info exists', () => {
    const health = buildRuntimeHealthForAccount({
      accountStatus: 'active',
      siteStatus: 'active',
      extraConfig: null,
    });
    expect(health).toMatchObject({
      state: 'unknown',
      source: 'none',
    });
  });
});
