import { describe, expect, it } from 'vitest';

describe('provider header utils', () => {
  it('coerces header values and performs case-insensitive lookups', async () => {
    const { headerValueToString, getInputHeader } = await import('./headerUtils.js');

    expect(headerValueToString('  value  ')).toBe('value');
    expect(headerValueToString(['', '  first  ', 'second'])).toBe('first');
    expect(getInputHeader({ Authorization: 'Bearer test' }, 'authorization')).toBe('Bearer test');
  });

  it('derives stable uuids from seeds', async () => {
    const { uuidFromSeed } = await import('./headerUtils.js');

    expect(uuidFromSeed('seed-1')).toBe(uuidFromSeed('seed-1'));
    expect(uuidFromSeed('seed-1')).not.toBe(uuidFromSeed('seed-2'));
    expect(uuidFromSeed('seed-1')).toMatch(/^[0-9a-f-]{36}$/);
  });

  it('merges claude beta headers without duplicating entries', async () => {
    const { mergeClaudeBetaHeader } = await import('./headerUtils.js');

    expect(
      mergeClaudeBetaHeader(null, 'beta-a,beta-b', ['beta-b', 'beta-c']),
    ).toBe('beta-a,beta-b,beta-c');
    expect(
      mergeClaudeBetaHeader('custom-a,custom-b', 'beta-a,beta-b', ['beta-c']),
    ).toBe('beta-a,beta-b,custom-a,custom-b,beta-c');
  });

  it('preserves gemini cli runtime metadata when rebuilding user agents', async () => {
    const {
      buildGeminiCliUserAgent,
      parseGeminiCliUserAgentRuntime,
    } = await import('./headerUtils.js');

    expect(
      parseGeminiCliUserAgentRuntime('GeminiCLI/0.55.0/gemini-2.5-pro (darwin; arm64)'),
    ).toEqual({
      version: '0.55.0',
      platform: 'darwin',
      arch: 'arm64',
    });
    expect(
      buildGeminiCliUserAgent(
        'gemini-2.5-flash',
        'GeminiCLI/0.55.0/gemini-2.5-pro (darwin; arm64)',
      ),
    ).toBe('GeminiCLI/0.55.0/gemini-2.5-flash (darwin; arm64)');
  });

  it('builds codex runtime headers with continuity-derived session identifiers', async () => {
    const { buildCodexRuntimeHeaders } = await import('./headerUtils.js');

    const headers = buildCodexRuntimeHeaders({
      baseHeaders: {
        authorization: 'Bearer test',
        version: '0.101.0',
      },
      providerHeaders: {
        originator: 'codex_cli_rs',
        'chatgpt-account-id': 'acct-1',
      },
      stream: false,
      continuityKey: 'cache-key-1',
      explicitSessionId: null,
    });

    expect(headers.Authorization).toBe('Bearer test');
    expect(headers.Originator).toBe('codex_cli_rs');
    expect(headers['Chatgpt-Account-Id']).toBe('acct-1');
    expect(headers.Session_id).toMatch(/^[0-9a-f-]{36}$/);
    expect(headers.Conversation_id).toBe(headers.Session_id);
    expect(headers.Accept).toBe('application/json');
  });

  it('builds claude runtime headers with merged betas and oauth bearer auth', async () => {
    const { buildClaudeRuntimeHeaders } = await import('./headerUtils.js');

    const headers = buildClaudeRuntimeHeaders({
      baseHeaders: {
        'Content-Type': 'application/json',
        authorization: 'Bearer stale-token',
      },
      claudeHeaders: {
        'anthropic-beta': 'custom-beta',
        'x-api-key': 'stale-api-key',
        'user-agent': 'custom-agent',
      },
      anthropicVersion: '2023-06-01',
      stream: true,
      isClaudeOauthUpstream: true,
      tokenValue: 'oauth-token',
    });

    expect(headers['anthropic-version']).toBe('2023-06-01');
    expect(headers['anthropic-beta']).toContain('claude-code-20250219');
    expect(headers['anthropic-beta']).toContain('custom-beta');
    expect(headers.Authorization).toBe('Bearer oauth-token');
    expect(headers.authorization).toBeUndefined();
    expect(headers['x-api-key']).toBeUndefined();
    expect(headers['user-agent']).toBeUndefined();
    expect(headers['User-Agent']).toBe('custom-agent');
    expect(headers.Accept).toBe('text/event-stream');
  });

  it('builds gemini cli runtime headers with preserved api client metadata', async () => {
    const { buildGeminiCliRuntimeHeaders } = await import('./headerUtils.js');

    const headers = buildGeminiCliRuntimeHeaders({
      baseHeaders: {
        authorization: 'Bearer test',
      },
      providerHeaders: {
        'x-goog-api-client': 'gl-node/22 gccl/0.31.0',
        'user-agent': 'GeminiCLI/0.55.0/gemini-2.5-pro (darwin; arm64)',
      },
      modelName: 'gemini-2.5-flash',
      stream: true,
    });

    expect(headers.Authorization).toBe('Bearer test');
    expect(headers['X-Goog-Api-Client']).toBe('gl-node/22 gccl/0.31.0');
    expect(headers['User-Agent']).toBe('GeminiCLI/0.55.0/gemini-2.5-flash (darwin; arm64)');
    expect(headers.Accept).toBe('text/event-stream');
  });
});
