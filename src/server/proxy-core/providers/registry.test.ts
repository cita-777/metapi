import { describe, expect, it } from 'vitest';

import { resolveProviderProfile } from './registry.js';

describe('resolveProviderProfile', () => {
  it('builds codex provider requests with codex-specific path, headers, and runtime metadata', () => {
    const profile = resolveProviderProfile('codex');
    expect(profile?.id).toBe('codex');

    const result = profile!.prepareRequest({
      endpoint: 'responses',
      modelName: 'gpt-5.2-codex',
      stream: true,
      tokenValue: 'oauth-access-token',
      sitePlatform: 'codex',
      baseHeaders: {
        Authorization: 'Bearer oauth-access-token',
      },
      providerHeaders: {
        Originator: 'codex_cli_rs',
        'Chatgpt-Account-Id': 'chatgpt-account-123',
      },
      codexSessionCacheKey: 'gpt-5.2-codex:user-123',
      body: {
        model: 'gpt-5.2-codex',
        stream: true,
        store: false,
      },
    });

    expect(result.path).toBe('/responses');
    expect(result.headers.Authorization).toBe('Bearer oauth-access-token');
    expect(result.headers.Originator).toBe('codex_cli_rs');
    expect(result.headers['Chatgpt-Account-Id']).toBe('chatgpt-account-123');
    expect(result.headers.Session_id).toMatch(/^[0-9a-f-]{36}$/i);
    expect(result.headers.Conversation_id).toBe(result.headers.Session_id);
    expect(result.runtime).toMatchObject({
      executor: 'codex',
      modelName: 'gpt-5.2-codex',
      stream: true,
    });
    expect(result.body).toEqual({
      model: 'gpt-5.2-codex',
      stream: true,
      store: false,
    });
  });

  it('builds claude provider requests without rebuilding protocol bodies', () => {
    const profile = resolveProviderProfile('claude');
    expect(profile?.id).toBe('claude');

    const protocolBody = {
      model: 'claude-opus-4-6',
      max_tokens: 256,
      messages: [{ role: 'user', content: 'hello' }],
    };

    const result = profile!.prepareRequest({
      endpoint: 'messages',
      modelName: 'claude-opus-4-6',
      stream: false,
      tokenValue: 'oauth-access-token',
      oauthProvider: 'claude',
      sitePlatform: 'claude',
      baseHeaders: {
        'Content-Type': 'application/json',
      },
      claudeHeaders: {},
      body: protocolBody,
    });

    expect(result.path).toBe('/v1/messages');
    expect(result.headers.Authorization).toBe('Bearer oauth-access-token');
    expect(result.headers['x-api-key']).toBeUndefined();
    expect(result.headers['anthropic-version']).toBe('2023-06-01');
    expect(result.headers['Accept-Encoding']).toBe('gzip, deflate, br, zstd');
    expect(result.runtime).toMatchObject({
      executor: 'claude',
      modelName: 'claude-opus-4-6',
      stream: false,
    });
    expect(result.body).toBe(protocolBody);
  });

  it('builds gemini-cli provider requests with wrapped runtime envelope and project validation', () => {
    const profile = resolveProviderProfile('gemini-cli');
    expect(profile?.id).toBe('gemini-cli');

    const protocolBody = {
      contents: [{ role: 'user', parts: [{ text: 'hello gemini cli' }] }],
    };

    const result = profile!.prepareRequest({
      endpoint: 'chat',
      modelName: 'gemini-2.5-pro',
      stream: false,
      tokenValue: 'oauth-access-token',
      oauthProvider: 'gemini-cli',
      oauthProjectId: 'project-demo',
      sitePlatform: 'gemini-cli',
      baseHeaders: {
        Authorization: 'Bearer oauth-access-token',
      },
      providerHeaders: {
        'User-Agent': 'GeminiCLI/0.31.0/unknown (win32; x64)',
        'X-Goog-Api-Client': 'google-genai-sdk/1.41.0 gl-node/v22.19.0',
      },
      body: protocolBody,
    });

    expect(result.path).toBe('/v1internal:generateContent');
    expect(result.headers.Authorization).toBe('Bearer oauth-access-token');
    expect(result.headers['User-Agent']).toBe('GeminiCLI/0.31.0/gemini-2.5-pro (win32; x64)');
    expect(result.headers['X-Goog-Api-Client']).toContain('google-genai-sdk/');
    expect(result.runtime).toMatchObject({
      executor: 'gemini-cli',
      modelName: 'gemini-2.5-pro',
      oauthProjectId: 'project-demo',
      action: 'generateContent',
    });
    expect(result.body).toEqual({
      project: 'project-demo',
      model: 'gemini-2.5-pro',
      request: protocolBody,
    });
    expect((result.body as Record<string, unknown>).request).toBe(protocolBody);

    expect(() => profile!.prepareRequest({
      endpoint: 'chat',
      modelName: 'gemini-2.5-pro',
      stream: false,
      tokenValue: 'oauth-access-token',
      oauthProvider: 'gemini-cli',
      sitePlatform: 'gemini-cli',
      baseHeaders: {
        Authorization: 'Bearer oauth-access-token',
      },
      body: protocolBody,
    })).toThrow(/project id missing/i);
  });

  it('builds antigravity provider requests without leaking gemini-cli client headers', () => {
    const profile = resolveProviderProfile('antigravity');
    expect(profile?.id).toBe('antigravity');

    const protocolBody = {
      contents: [{ role: 'user', parts: [{ text: 'hello antigravity' }] }],
    };

    const result = profile!.prepareRequest({
      endpoint: 'chat',
      modelName: 'gemini-3-pro-preview',
      stream: true,
      tokenValue: 'oauth-access-token',
      oauthProjectId: 'project-demo',
      sitePlatform: 'antigravity',
      baseHeaders: {
        Authorization: 'Bearer oauth-access-token',
      },
      providerHeaders: {
        'User-Agent': 'GeminiCLI/0.31.0/unknown (win32; x64)',
        'X-Goog-Api-Client': 'google-genai-sdk/1.41.0 gl-node/v22.19.0',
      },
      body: protocolBody,
    });

    expect(result.path).toBe('/v1internal:streamGenerateContent?alt=sse');
    expect(result.headers.Authorization).toBe('Bearer oauth-access-token');
    expect(result.headers['User-Agent']).toBe('antigravity/1.19.6 darwin/arm64');
    expect(result.headers['X-Goog-Api-Client']).toBeUndefined();
    expect(result.headers.Accept).toBe('text/event-stream');
    expect(result.runtime).toMatchObject({
      executor: 'antigravity',
      modelName: 'gemini-3-pro-preview',
      oauthProjectId: 'project-demo',
      action: 'streamGenerateContent',
    });
    expect(result.body).toEqual({
      project: 'project-demo',
      model: 'gemini-3-pro-preview',
      request: protocolBody,
    });
    expect((result.body as Record<string, unknown>).request).toBe(protocolBody);
  });
});
