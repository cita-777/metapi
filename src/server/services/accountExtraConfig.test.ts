import { describe, expect, it } from 'vitest';
import {
  buildStoredSub2ApiSubscriptionSummary,
  getCredentialModeFromExtraConfig,
  hasOauthProvider,
  getPlatformUserIdFromExtraConfig,
  getProxyUrlFromExtraConfig,
  getUseSystemProxyFromExtraConfig,
  resolveProxyUrlFromExtraConfig,
  getSub2ApiAuthFromExtraConfig,
  getSub2ApiSubscriptionFromExtraConfig,
  guessPlatformUserIdFromUsername,
  mergeAccountExtraConfig,
  normalizeCredentialMode,
  resolvePlatformUserId,
  requiresManagedAccountTokens,
  supportsDirectAccountRoutingConnection,
} from './accountExtraConfig.js';
import { config } from '../config.js';

describe('accountExtraConfig', () => {
  it('reads platformUserId from extra config when present', () => {
    expect(getPlatformUserIdFromExtraConfig(JSON.stringify({ platformUserId: 11494 }))).toBe(11494);
    expect(getPlatformUserIdFromExtraConfig(JSON.stringify({ platformUserId: '7659' }))).toBe(7659);
    expect(getPlatformUserIdFromExtraConfig({ platformUserId: 2233 })).toBe(2233);
  });

  it('guesses platformUserId from username suffix digits', () => {
    expect(guessPlatformUserIdFromUsername('linuxdo_7659')).toBe(7659);
    expect(guessPlatformUserIdFromUsername('user11494')).toBe(11494);
    expect(guessPlatformUserIdFromUsername('abc')).toBeUndefined();
    expect(guessPlatformUserIdFromUsername('id_12')).toBeUndefined();
  });

  it('prefers configured user id over guessed user id', () => {
    expect(resolvePlatformUserId(JSON.stringify({ platformUserId: 5001 }), 'linuxdo_7659')).toBe(5001);
  });

  it('merges platformUserId into existing config without dropping keys', () => {
    const merged = mergeAccountExtraConfig(
      JSON.stringify({
        foo: 'bar',
        autoRelogin: { username: 'demo', passwordCipher: 'cipher' },
      }),
      { platformUserId: 7659 },
    );

    expect(merged).toBeTruthy();
    const parsed = JSON.parse(merged!);
    expect(parsed.foo).toBe('bar');
    expect(parsed.autoRelogin?.username).toBe('demo');
    expect(parsed.platformUserId).toBe(7659);
  });

  it('merges object extra config without dropping existing keys', () => {
    const merged = mergeAccountExtraConfig(
      {
        foo: 'bar',
        credentialMode: 'session',
        autoRelogin: { username: 'demo', passwordCipher: 'cipher' },
      },
      { platformUserId: 9001 },
    );

    expect(JSON.parse(merged)).toEqual(expect.objectContaining({
      foo: 'bar',
      credentialMode: 'session',
      platformUserId: 9001,
      autoRelogin: expect.objectContaining({
        username: 'demo',
        passwordCipher: 'cipher',
      }),
    }));
  });

  it('parses credential mode from extra config', () => {
    expect(getCredentialModeFromExtraConfig(JSON.stringify({ credentialMode: 'apikey' }))).toBe('apikey');
    expect(getCredentialModeFromExtraConfig(JSON.stringify({ credentialMode: 'session' }))).toBe('session');
    expect(getCredentialModeFromExtraConfig(JSON.stringify({ credentialMode: 'AUTO' }))).toBe('auto');
    expect(getCredentialModeFromExtraConfig(JSON.stringify({ credentialMode: 'unknown' }))).toBeUndefined();
  });

  it('normalizes credential mode input', () => {
    expect(normalizeCredentialMode(' apikey ')).toBe('apikey');
    expect(normalizeCredentialMode('session')).toBe('session');
    expect(normalizeCredentialMode('AUTO')).toBe('auto');
    expect(normalizeCredentialMode('abc')).toBeUndefined();
  });

  it('parses managed sub2api refresh token config from extra config', () => {
    expect(getSub2ApiAuthFromExtraConfig(JSON.stringify({
      sub2apiAuth: { refreshToken: 'refresh-1', tokenExpiresAt: 1760000000000 },
    }))).toEqual({
      refreshToken: 'refresh-1',
      tokenExpiresAt: 1760000000000,
    });
    expect(getSub2ApiAuthFromExtraConfig(JSON.stringify({
      sub2apiAuth: { refreshToken: '  ' },
    }))).toBeNull();
  });

  it('reads proxyUrl from extra config', () => {
    expect(getProxyUrlFromExtraConfig(JSON.stringify({ proxyUrl: 'http://127.0.0.1:7890' }))).toBe('http://127.0.0.1:7890');
    expect(getProxyUrlFromExtraConfig(JSON.stringify({ proxyUrl: '  socks5://proxy.local:1080  ' }))).toBe('socks5://proxy.local:1080');
  });

  it('returns null for missing or empty proxyUrl', () => {
    expect(getProxyUrlFromExtraConfig(JSON.stringify({}))).toBeNull();
    expect(getProxyUrlFromExtraConfig(JSON.stringify({ proxyUrl: '' }))).toBeNull();
    expect(getProxyUrlFromExtraConfig(JSON.stringify({ proxyUrl: '   ' }))).toBeNull();
    expect(getProxyUrlFromExtraConfig(null)).toBeNull();
    expect(getProxyUrlFromExtraConfig(undefined)).toBeNull();
    expect(getProxyUrlFromExtraConfig('invalid-json')).toBeNull();
  });

  it('reads useSystemProxy from extra config', () => {
    expect(getUseSystemProxyFromExtraConfig(JSON.stringify({ useSystemProxy: true }))).toBe(true);
    expect(getUseSystemProxyFromExtraConfig(JSON.stringify({ useSystemProxy: false }))).toBe(false);
    expect(getUseSystemProxyFromExtraConfig(JSON.stringify({}))).toBe(false);
  });

  it('resolves account proxy url from custom override before system proxy', () => {
    const previousSystemProxyUrl = config.systemProxyUrl;
    try {
      config.systemProxyUrl = 'http://127.0.0.1:7890';
      expect(resolveProxyUrlFromExtraConfig(JSON.stringify({
        proxyUrl: 'http://account-proxy:8080',
        useSystemProxy: true,
      }))).toBe('http://account-proxy:8080');
      expect(resolveProxyUrlFromExtraConfig(JSON.stringify({
        useSystemProxy: true,
      }))).toBe('http://127.0.0.1:7890');
      expect(resolveProxyUrlFromExtraConfig(JSON.stringify({
        useSystemProxy: false,
      }))).toBeNull();
    } finally {
      config.systemProxyUrl = previousSystemProxyUrl;
    }
  });

  it('treats auto-mode api token connections as direct-account routable', () => {
    expect(supportsDirectAccountRoutingConnection({
      accessToken: '',
      apiToken: 'sk-demo',
      extraConfig: null,
    })).toBe(true);
    expect(requiresManagedAccountTokens({
      accessToken: '',
      apiToken: 'sk-demo',
      extraConfig: null,
    })).toBe(false);
  });

  it('treats oauth and session connections as non-managed-token direct routes only when intended', () => {
    expect(supportsDirectAccountRoutingConnection({
      accessToken: 'oauth-access-token',
      apiToken: null,
      extraConfig: JSON.stringify({ credentialMode: 'session', oauth: { provider: 'codex' } }),
    })).toBe(true);
    expect(requiresManagedAccountTokens({
      accessToken: 'oauth-access-token',
      apiToken: null,
      extraConfig: JSON.stringify({ credentialMode: 'session', oauth: { provider: 'codex' } }),
    })).toBe(false);
    expect(supportsDirectAccountRoutingConnection({
      accessToken: 'session-token',
      apiToken: 'sk-default',
      extraConfig: JSON.stringify({ credentialMode: 'session' }),
    })).toBe(false);
    expect(requiresManagedAccountTokens({
      accessToken: 'session-token',
      apiToken: 'sk-default',
      extraConfig: JSON.stringify({ credentialMode: 'session' }),
    })).toBe(true);
  });

  it('recognizes structured oauth provider columns even when extraConfig omits oauth.provider', () => {
    const structuredOauthAccount = {
      oauthProvider: 'codex',
      accessToken: 'oauth-access-token',
      apiToken: null,
      extraConfig: JSON.stringify({
        credentialMode: 'session',
        oauth: {
          email: 'oauth-user@example.com',
        },
      }),
    };

    expect(hasOauthProvider(structuredOauthAccount)).toBe(true);
    expect(supportsDirectAccountRoutingConnection(structuredOauthAccount)).toBe(true);
    expect(requiresManagedAccountTokens(structuredOauthAccount)).toBe(false);
  });

  it('parses stored sub2api subscription summary from extra config', () => {
    const extraConfig = mergeAccountExtraConfig(null, {
      sub2apiSubscription: buildStoredSub2ApiSubscriptionSummary({
        activeCount: 1,
        totalUsedUsd: 3.5,
        subscriptions: [
          {
            id: 7,
            groupName: 'Pro',
            expiresAt: '2026-04-01T00:00:00.000Z',
            monthlyUsedUsd: 3.5,
            monthlyLimitUsd: 20,
          },
        ],
      }, 1760000000000),
    });

    expect(getSub2ApiSubscriptionFromExtraConfig(extraConfig)).toEqual({
      activeCount: 1,
      totalUsedUsd: 3.5,
      subscriptions: [
        {
          id: 7,
          groupName: 'Pro',
          expiresAt: '2026-04-01T00:00:00.000Z',
          monthlyUsedUsd: 3.5,
          monthlyLimitUsd: 20,
        },
      ],
      updatedAt: 1760000000000,
    });
  });
});
