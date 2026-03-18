import { describe, expect, it } from 'vitest';
import {
  getCredentialModeFromExtraConfig,
  getPlatformUserIdFromExtraConfig,
  getSub2ApiAuthFromExtraConfig,
  guessPlatformUserIdFromUsername,
  mergeAccountExtraConfig,
  normalizeCredentialMode,
  resolvePlatformUserId,
  requiresManagedAccountTokens,
  supportsDirectAccountRoutingConnection,
} from './accountExtraConfig.js';

describe('accountExtraConfig', () => {
  it('reads platformUserId from extra config when present', () => {
    expect(getPlatformUserIdFromExtraConfig(JSON.stringify({ platformUserId: 11494 }))).toBe(11494);
    expect(getPlatformUserIdFromExtraConfig(JSON.stringify({ platformUserId: '7659' }))).toBe(7659);
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
});
