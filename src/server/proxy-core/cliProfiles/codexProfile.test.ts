import { describe, expect, it } from 'vitest';
import { detectCodexOfficialClientApp } from './codexProfile.js';

describe('detectCodexOfficialClientApp', () => {
  it('returns null for missing or empty headers', () => {
    expect(detectCodexOfficialClientApp()).toBeNull();
    expect(detectCodexOfficialClientApp({})).toBeNull();
  });

  it('detects official Codex clients from originator prefixes', () => {
    expect(detectCodexOfficialClientApp({
      originator: 'codex_exec',
    })).toEqual({
      clientAppId: 'codex_exec',
      clientAppName: 'Codex Exec',
    });
  });

  it('detects official Codex clients from user-agent prefixes', () => {
    expect(detectCodexOfficialClientApp({
      'user-agent': 'Mozilla/5.0 codex_chatgpt_desktop/1.2.3',
    })).toEqual({
      clientAppId: 'codex_chatgpt_desktop',
      clientAppName: 'Codex Desktop',
    });
  });

  it('matches headers case-insensitively and from header arrays', () => {
    expect(detectCodexOfficialClientApp({
      originator: 'CODEX_EXEC',
    })).toEqual({
      clientAppId: 'codex_exec',
      clientAppName: 'Codex Exec',
    });
    expect(detectCodexOfficialClientApp({
      'user-agent': 'Mozilla/5.0 CODEX_chatgpt_desktop/1.2',
    })).toEqual({
      clientAppId: 'codex_chatgpt_desktop',
      clientAppName: 'Codex Desktop',
    });
    expect(detectCodexOfficialClientApp({
      'user-agent': ['Mozilla/5.0', 'codex_chatgpt_desktop/1.2'],
    })).toEqual({
      clientAppId: 'codex_chatgpt_desktop',
      clientAppName: 'Codex Desktop',
    });
    expect(detectCodexOfficialClientApp({
      originator: ['ignored', 'other-client'],
    })).toBeNull();
  });

  it('returns null for non-official Codex clients', () => {
    expect(detectCodexOfficialClientApp({
      'user-agent': 'OpenClaw/1.0',
    })).toBe(null);
  });
});
