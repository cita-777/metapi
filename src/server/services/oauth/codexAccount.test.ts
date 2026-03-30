import { describe, expect, it } from 'vitest';
import {
  buildCodexOauthInfo,
  getCodexOauthInfoFromExtraConfig,
  isCodexPlatform,
} from './codexAccount.js';

describe('codexAccount', () => {
  it('reads codex oauth info from parsed extra config objects', () => {
    const extraConfig = {
      oauth: {
        provider: 'codex',
        accountKey: 'chatgpt-account-123',
        refreshToken: 'refresh-token',
      },
    };

    expect(getCodexOauthInfoFromExtraConfig(extraConfig)).toEqual(expect.objectContaining({
      provider: 'codex',
      accountId: 'chatgpt-account-123',
      accountKey: 'chatgpt-account-123',
      refreshToken: 'refresh-token',
    }));
  });

  it('recognizes parsed codex extra config objects as codex platform accounts', () => {
    expect(isCodexPlatform({
      oauth: {
        provider: 'codex',
        accountKey: 'chatgpt-account-123',
      },
    })).toBe(true);
  });

  it('builds codex oauth info from parsed extra config objects', () => {
    const oauth = buildCodexOauthInfo({
      oauth: {
        provider: 'codex',
        accountKey: 'chatgpt-account-123',
        refreshToken: 'refresh-token',
      },
    });

    expect(oauth).toEqual(expect.objectContaining({
      provider: 'codex',
      accountId: 'chatgpt-account-123',
      accountKey: 'chatgpt-account-123',
      refreshToken: 'refresh-token',
    }));
  });
});
