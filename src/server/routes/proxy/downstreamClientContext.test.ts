import { describe, expect, it } from 'vitest';
import { extractClaudeCodeSessionId } from '../../proxy-core/cliProfiles/claudeCodeProfile.js';
import { isCodexResponsesSurface } from '../../proxy-core/cliProfiles/codexProfile.js';
import { detectDownstreamClientContext } from '../../proxy-core/downstreamClientContext.js';

describe('extractClaudeCodeSessionId', () => {
  it('extracts session uuid from axonhub-compatible Claude Code user ids', () => {
    expect(extractClaudeCodeSessionId(
      'user_20836b5653ed68aa981604f502c0a491397f6053826a93c953423632578d38ad_account__session_f25958b8-e75c-455d-8b40-f006d87cc2a4',
    )).toBe('f25958b8-e75c-455d-8b40-f006d87cc2a4');
  });

  it('returns null for non-Claude-Code user ids', () => {
    expect(extractClaudeCodeSessionId('user_123')).toBe(null);
    expect(extractClaudeCodeSessionId('session_f25958b8-e75c-455d-8b40-f006d87cc2a4')).toBe(null);
  });
});

describe('isCodexResponsesSurface', () => {
  it('detects Codex responses surface from originator, stainless, and turn-state headers', () => {
    expect(isCodexResponsesSurface({
      originator: 'codex_cli_rs',
    })).toBe(true);

    expect(isCodexResponsesSurface({
      'x-stainless-lang': 'typescript',
    })).toBe(true);

    expect(isCodexResponsesSurface({
      'x-codex-turn-state': 'turn-state-123',
    })).toBe(true);
  });

  it('detects broader Codex official-client family headers from user-agent and originator prefixes', () => {
    expect(isCodexResponsesSurface({
      'user-agent': 'Mozilla/5.0 codex_chatgpt_desktop/1.2.3',
    })).toBe(true);

    expect(isCodexResponsesSurface({
      originator: 'codex_vscode',
    })).toBe(true);
  });

  it('returns false for generic responses clients', () => {
    expect(isCodexResponsesSurface({
      'content-type': 'application/json',
    })).toBe(false);
  });
});

describe('detectDownstreamClientContext', () => {
  it('recognizes Codex requests and attaches Session_id as session and trace hint', () => {
    expect(detectDownstreamClientContext({
      downstreamPath: '/v1/responses',
      headers: {
        originator: 'codex_cli_rs',
        Session_id: 'codex-session-123',
      },
    })).toEqual({
      clientKind: 'codex',
      clientAppId: 'codex_cli_rs',
      clientAppName: 'Codex CLI',
      clientConfidence: 'exact',
      sessionId: 'codex-session-123',
      traceHint: 'codex-session-123',
    });
  });

  it('keeps Codex requests without Session_id as client-only context', () => {
    expect(detectDownstreamClientContext({
      downstreamPath: '/v1/responses/compact',
      headers: {
        'x-stainless-lang': 'typescript',
      },
    })).toEqual({
      clientKind: 'codex',
      clientAppId: 'codex',
      clientAppName: 'Codex',
      clientConfidence: 'heuristic',
    });
  });

  it('recognizes broader Codex official-client user-agent families without requiring stainless headers', () => {
    expect(detectDownstreamClientContext({
      downstreamPath: '/v1/responses',
      headers: {
        'user-agent': 'Mozilla/5.0 codex_chatgpt_desktop/1.2.3',
      },
    })).toEqual({
      clientKind: 'codex',
      clientAppId: 'codex_chatgpt_desktop',
      clientAppName: 'Codex Desktop',
      clientConfidence: 'exact',
    });
  });

  it('recognizes broader Codex official-client originator prefixes', () => {
    expect(detectDownstreamClientContext({
      downstreamPath: '/v1/responses',
      headers: {
        originator: 'codex_exec',
      },
    })).toEqual({
      clientKind: 'codex',
      clientAppId: 'codex_exec',
      clientAppName: 'Codex Exec',
      clientConfidence: 'exact',
    });
  });

  it('prefers explicit self-reported client names before protocol-family fallbacks', () => {
    expect(detectDownstreamClientContext({
      downstreamPath: '/v1/responses',
      headers: {
        'openai-beta': 'responses-2025-03-11',
        'x-openai-client-user-agent': '{"client":"openclaw"}',
      },
    })).toEqual({
      clientKind: 'codex',
      clientAppId: 'openclaw',
      clientAppName: 'openclaw',
      clientConfidence: 'exact',
    });
  });

  it('treats explicit OpenClaw user-agent headers as self-reported app names', () => {
    expect(detectDownstreamClientContext({
      downstreamPath: '/v1/responses',
      headers: {
        'openai-beta': 'responses-2025-03-11',
        'user-agent': 'OpenClaw/1.0',
      },
    })).toEqual({
      clientKind: 'codex',
      clientAppId: 'openclaw',
      clientAppName: 'OpenClaw',
      clientConfidence: 'exact',
    });
  });

  it('recognizes Claude Code requests from metadata.user_id without mutating the body', () => {
    const body = {
      model: 'claude-opus-4-6',
      metadata: {
        user_id: 'user_20836b5653ed68aa981604f502c0a491397f6053826a93c953423632578d38ad_account__session_f25958b8-e75c-455d-8b40-f006d87cc2a4',
      },
    };

    expect(detectDownstreamClientContext({
      downstreamPath: '/v1/messages',
      body,
    })).toEqual({
      clientKind: 'claude_code',
      clientAppId: 'claude_code',
      clientAppName: 'Claude Code',
      clientConfidence: 'exact',
      sessionId: 'f25958b8-e75c-455d-8b40-f006d87cc2a4',
      traceHint: 'f25958b8-e75c-455d-8b40-f006d87cc2a4',
    });
    expect(body).toEqual({
      model: 'claude-opus-4-6',
      metadata: {
        user_id: 'user_20836b5653ed68aa981604f502c0a491397f6053826a93c953423632578d38ad_account__session_f25958b8-e75c-455d-8b40-f006d87cc2a4',
      },
    });
  });

  it('recognizes Claude Code from claude-cli request headers before Codex heuristics on /v1/messages', () => {
    expect(detectDownstreamClientContext({
      downstreamPath: '/v1/messages',
      headers: {
        'user-agent': 'claude-cli/2.1.63 (external, cli)',
        'anthropic-beta': 'claude-code-20250219,oauth-2025-04-20',
        'anthropic-version': '2023-06-01',
        'x-app': 'cli',
        'x-stainless-lang': 'js',
      },
      body: {
        model: 'claude-sonnet-4-5',
      },
    })).toEqual({
      clientKind: 'claude_code',
      clientAppId: 'claude_code',
      clientAppName: 'Claude Code',
      clientConfidence: 'exact',
    });
  });

  it('falls back to generic when Claude metadata.user_id is missing or invalid', () => {
    expect(detectDownstreamClientContext({
      downstreamPath: '/v1/messages',
      body: {
        metadata: {
          user_id: 'user_123',
        },
      },
    })).toEqual({
      clientKind: 'generic',
    });

    expect(detectDownstreamClientContext({
      downstreamPath: '/v1/messages',
      body: {
        metadata: {
          session_id: 'abc123',
        },
      },
    })).toEqual({
      clientKind: 'generic',
    });
  });

  it('recognizes Gemini CLI internal routes as a first-class downstream client kind', () => {
    expect(detectDownstreamClientContext({
      downstreamPath: '/v1internal:generateContent',
      body: {
        model: 'gpt-4.1',
        contents: [
          {
            role: 'user',
            parts: [{ text: 'hello' }],
          },
        ],
      },
    })).toEqual({
      clientKind: 'gemini_cli',
      clientAppId: 'gemini_cli',
      clientAppName: 'Gemini CLI',
      clientConfidence: 'exact',
    });
  });

  it('recognizes app fingerprints alongside a generic protocol family', () => {
    expect(detectDownstreamClientContext({
      downstreamPath: '/v1/chat/completions',
      headers: {
        'x-title': 'Cherry Studio',
        'http-referer': 'https://cherry-ai.com',
      },
    })).toEqual({
      clientKind: 'generic',
      clientAppId: 'cherry_studio',
      clientAppName: 'Cherry Studio',
      clientConfidence: 'exact',
    });
  });

  it('keeps protocol family detection when an app fingerprint also matches', () => {
    expect(detectDownstreamClientContext({
      downstreamPath: '/v1/responses',
      headers: {
        originator: 'codex_cli_rs',
        'x-title': 'Cherry Studio',
        'http-referer': 'https://cherry-ai.com',
      },
    })).toEqual({
      clientKind: 'codex',
      clientAppId: 'cherry_studio',
      clientAppName: 'Cherry Studio',
      clientConfidence: 'exact',
    });
  });

  it('marks weak app-only matches as heuristic instead of upgrading protocol behavior', () => {
    expect(detectDownstreamClientContext({
      downstreamPath: '/v1/chat/completions',
      headers: {
        'user-agent': 'CherryStudio/1.2.3',
      },
    })).toEqual({
      clientKind: 'generic',
      clientAppId: 'cherry_studio',
      clientAppName: 'Cherry Studio',
      clientConfidence: 'heuristic',
    });
  });

  it('marks OpenCode anthropic prompts as an app-level heuristic without changing protocol family', () => {
    expect(detectDownstreamClientContext({
      downstreamPath: '/v1/messages',
      body: {
        model: 'claude-sonnet-4-5',
        system: [
          {
            type: 'text',
            text: 'You are OpenCode, an interactive CLI tool that helps users with software engineering tasks. If the current working directory contains a file called OpenCode.md, it will be automatically added to your context.',
          },
        ],
      },
    })).toEqual({
      clientKind: 'generic',
      clientAppId: 'opencode',
      clientAppName: 'OpenCode',
      clientConfidence: 'heuristic',
    });
  });

  it('recognizes OpenCode anthropic prompts when system is provided as a plain string', () => {
    expect(detectDownstreamClientContext({
      downstreamPath: '/v1/messages',
      body: {
        model: 'claude-sonnet-4-5',
        system: 'You are OpenCode, an interactive CLI tool that helps users with software engineering tasks. If the current working directory contains a file called OpenCode.md, it will be automatically added to your context.',
      },
    })).toEqual({
      clientKind: 'generic',
      clientAppId: 'opencode',
      clientAppName: 'OpenCode',
      clientConfidence: 'heuristic',
    });
  });
});
