import { describe, expect, it } from 'vitest';

import { detectCliProfile } from './registry.js';

describe('detectCliProfile', () => {
  it('detects Codex responses requests and exposes Codex capability flags', () => {
    expect(detectCliProfile({
      downstreamPath: '/v1/responses',
      headers: {
        originator: 'codex_cli_rs',
        Session_id: 'codex-session-123',
      },
    })).toEqual({
      id: 'codex',
      sessionId: 'codex-session-123',
      traceHint: 'codex-session-123',
      clientAppId: 'codex_cli_rs',
      clientAppName: 'Codex CLI',
      clientConfidence: 'exact',
      capabilities: {
        supportsResponsesCompact: true,
        supportsResponsesWebsocketIncremental: true,
        preservesContinuation: true,
        supportsCountTokens: false,
        echoesTurnState: true,
      },
    });
  });

  it('treats x-codex-turn-state as a Codex marker even when session_id is absent', () => {
    expect(detectCliProfile({
      downstreamPath: '/v1/responses',
      headers: {
        'x-codex-turn-state': 'turn-state-123',
      },
    })).toMatchObject({
      id: 'codex',
      capabilities: {
        supportsResponsesWebsocketIncremental: true,
        echoesTurnState: true,
      },
    });
  });

  it('detects broader Codex official-client headers from user-agent and originator prefixes', () => {
    expect(detectCliProfile({
      downstreamPath: '/v1/responses',
      headers: {
        'user-agent': 'Mozilla/5.0 codex_chatgpt_desktop/1.2.3',
      },
    })).toMatchObject({
      id: 'codex',
      capabilities: {
        supportsResponsesWebsocketIncremental: true,
        echoesTurnState: true,
      },
    });

    expect(detectCliProfile({
      downstreamPath: '/v1/responses',
      headers: {
        originator: 'codex_exec',
      },
    })).toMatchObject({
      id: 'codex',
      capabilities: {
        supportsResponsesWebsocketIncremental: true,
        echoesTurnState: true,
      },
    });
  });

  it('detects Claude Code requests on the count_tokens surface and exposes token counting support', () => {
    expect(detectCliProfile({
      downstreamPath: '/v1/messages/count_tokens',
      body: {
        metadata: {
          user_id: 'user_20836b5653ed68aa981604f502c0a491397f6053826a93c953423632578d38ad_account__session_f25958b8-e75c-455d-8b40-f006d87cc2a4',
        },
      },
    })).toEqual({
      id: 'claude_code',
      sessionId: 'f25958b8-e75c-455d-8b40-f006d87cc2a4',
      traceHint: 'f25958b8-e75c-455d-8b40-f006d87cc2a4',
      clientAppId: 'claude_code',
      clientAppName: 'Claude Code',
      clientConfidence: 'exact',
      capabilities: {
        supportsResponsesCompact: false,
        supportsResponsesWebsocketIncremental: false,
        preservesContinuation: true,
        supportsCountTokens: true,
        echoesTurnState: false,
      },
    });
  });

  it('detects Gemini CLI internal routes and exposes Gemini CLI capability flags', () => {
    expect(detectCliProfile({
      downstreamPath: '/v1internal:countTokens',
      body: {
        model: 'gpt-4.1',
        contents: [{ role: 'user', parts: [{ text: 'hello' }] }],
      },
    })).toEqual({
      id: 'gemini_cli',
      clientAppId: 'gemini_cli',
      clientAppName: 'Gemini CLI',
      clientConfidence: 'exact',
      capabilities: {
        supportsResponsesCompact: false,
        supportsResponsesWebsocketIncremental: false,
        preservesContinuation: false,
        supportsCountTokens: true,
        echoesTurnState: false,
      },
    });
  });

  it('falls back to generic for native Gemini routes', () => {
    expect(detectCliProfile({
      downstreamPath: '/v1beta/models/gemini-2.5-flash:generateContent',
      body: {
        contents: [{ role: 'user', parts: [{ text: 'hello' }] }],
      },
    })).toEqual({
      id: 'generic',
      capabilities: {
        supportsResponsesCompact: false,
        supportsResponsesWebsocketIncremental: false,
        preservesContinuation: false,
        supportsCountTokens: false,
        echoesTurnState: false,
      },
    });
  });
});
