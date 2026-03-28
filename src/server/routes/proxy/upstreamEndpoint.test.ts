import { beforeEach, describe, expect, it, vi } from 'vitest';
import { config } from '../../config.js';

const fetchModelPricingCatalogMock = vi.fn(async (_arg?: unknown): Promise<any> => null);

vi.mock('../../services/modelPricingService.js', () => ({
  fetchModelPricingCatalog: (arg: unknown) => fetchModelPricingCatalogMock(arg),
}));

import {
  buildMinimalJsonHeadersForCompatibility,
  buildUpstreamEndpointRequest,
  isUnsupportedMediaTypeError,
  isEndpointDowngradeError,
  recordUpstreamEndpointFailure,
  recordUpstreamEndpointSuccess,
  resetUpstreamEndpointRuntimeState,
  resolveUpstreamEndpointCandidates,
  boundEndpointRuntimeModelKey,
  MAX_ENDPOINT_RUNTIME_MODEL_KEY_LENGTH,
  MODEL_KEY_HASH_SUFFIX_LENGTH,
} from './upstreamEndpoint.js';

const baseContext = {
  site: {
    id: 1,
    url: 'https://upstream.example.com',
    platform: '',
    apiKey: null,
  },
  account: {
    id: 2,
    accessToken: 'token-demo',
    apiToken: null,
  },
};

describe('resolveUpstreamEndpointCandidates', () => {
  beforeEach(() => {
    fetchModelPricingCatalogMock.mockReset();
    fetchModelPricingCatalogMock.mockResolvedValue(null);
    resetUpstreamEndpointRuntimeState();
    (config as any).codexHeaderDefaults = {
      userAgent: '',
      betaFeatures: '',
    };
    (config as any).payloadRules = {
      default: [],
      defaultRaw: [],
      override: [],
      overrideRaw: [],
      filter: [],
    };
  });

  it('uses downstream-aligned endpoint priority for unknown platforms', async () => {
    const openaiOrder = await resolveUpstreamEndpointCandidates(
      {
        ...baseContext,
        site: { ...baseContext.site, platform: 'new-api' },
      },
      'gpt-5.3',
      'openai',
    );
    expect(openaiOrder).toEqual(['chat', 'messages', 'responses']);

    const claudeOrder = await resolveUpstreamEndpointCandidates(
      {
        ...baseContext,
        site: { ...baseContext.site, platform: 'new-api' },
      },
      'gpt-5.3',
      'claude',
    );
    expect(claudeOrder).toEqual(['messages', 'chat', 'responses']);

    const responsesOrder = await resolveUpstreamEndpointCandidates(
      {
        ...baseContext,
        site: { ...baseContext.site, platform: 'new-api' },
      },
      'gpt-5.3',
      'responses',
    );
    expect(responsesOrder).toEqual(['responses', 'chat', 'messages']);

    const claudeResponsesOrder = await resolveUpstreamEndpointCandidates(
      {
        ...baseContext,
        site: { ...baseContext.site, platform: 'new-api' },
      },
      'claude-haiku-4-5-20251001',
      'responses',
    );
    expect(claudeResponsesOrder).toEqual(['messages', 'chat', 'responses']);
  });

  it('prioritizes messages-first for claude-family models on openai downstream', async () => {
    fetchModelPricingCatalogMock.mockResolvedValue({
      models: [
        {
          modelName: 'claude-opus-4-6',
          supportedEndpointTypes: ['anthropic', 'openai'],
        },
      ],
      groupRatio: {},
    });

    const order = await resolveUpstreamEndpointCandidates(
      {
        ...baseContext,
        site: { ...baseContext.site, platform: 'new-api' },
      },
      'claude-opus-4-6',
      'openai',
    );

    expect(order).toEqual(['messages', 'chat', 'responses']);

    const aliasedOrder = await resolveUpstreamEndpointCandidates(
      {
        ...baseContext,
        site: { ...baseContext.site, platform: 'new-api' },
      },
      'upstream-gpt',
      'openai',
      'claude-haiku-4-5-20251001',
    );

    expect(aliasedOrder).toEqual(['messages', 'chat', 'responses']);
  });

  it('keeps explicit platform priority rules', async () => {
    const openaiOrder = await resolveUpstreamEndpointCandidates(
      {
        ...baseContext,
        site: { ...baseContext.site, platform: 'openai' },
      },
      'gpt-5.3',
      'openai',
    );
    expect(openaiOrder).toEqual(['chat', 'responses', 'messages']);

    const openaiResponsesOrder = await resolveUpstreamEndpointCandidates(
      {
        ...baseContext,
        site: { ...baseContext.site, platform: 'openai' },
      },
      'gpt-5.3',
      'responses',
    );
    expect(openaiResponsesOrder).toEqual(['responses', 'chat', 'messages']);

    const openaiClaudeOrder = await resolveUpstreamEndpointCandidates(
      {
        ...baseContext,
        site: { ...baseContext.site, platform: 'openai' },
      },
      'claude-opus-4-6',
      'openai',
    );
    expect(openaiClaudeOrder).toEqual(['messages', 'chat', 'responses']);

    const claudeOrder = await resolveUpstreamEndpointCandidates(
      {
        ...baseContext,
        site: { ...baseContext.site, platform: 'claude' },
      },
      'claude-opus-4-6',
      'claude',
    );
    expect(claudeOrder).toEqual(['messages']);

    const codexOrder = await resolveUpstreamEndpointCandidates(
      {
        ...baseContext,
        site: { ...baseContext.site, platform: 'codex', url: 'https://chatgpt.com/backend-api/codex' },
      },
      'gpt-5.2-codex',
      'openai',
    );
    expect(codexOrder).toEqual(['responses']);
  });

  it('prefers document-capable endpoints when downstream content contains non-image files', async () => {
    const order = await resolveUpstreamEndpointCandidates(
      {
        ...baseContext,
        site: { ...baseContext.site, platform: 'new-api' },
      },
      'gpt-5.3',
      'openai',
      undefined,
      {
        hasNonImageFileInput: true,
      },
    );

    expect(order).toEqual(['responses', 'messages', 'chat']);
  });

  it('does not apply runtime endpoint memory to image attachments', async () => {
    recordUpstreamEndpointSuccess({
      siteId: baseContext.site.id,
      endpoint: 'responses',
      downstreamFormat: 'openai',
      modelName: 'gpt-5.3',
      requestCapabilities: {
        conversationFileSummary: {
          hasImage: true,
          hasAudio: false,
          hasDocument: false,
          hasRemoteDocumentUrl: false,
        },
      },
    });

    const order = await resolveUpstreamEndpointCandidates(
      {
        ...baseContext,
        site: { ...baseContext.site, platform: 'new-api' },
      },
      'gpt-5.3',
      'openai',
      undefined,
      {
        conversationFileSummary: {
          hasImage: true,
          hasAudio: false,
          hasDocument: false,
          hasRemoteDocumentUrl: false,
        },
      },
    );

    expect(order).toEqual(['chat', 'messages', 'responses']);
  });

  it('does not apply runtime endpoint memory to document attachments', async () => {
    recordUpstreamEndpointSuccess({
      siteId: baseContext.site.id,
      endpoint: 'messages',
      downstreamFormat: 'openai',
      modelName: 'gpt-5.3',
      requestCapabilities: {
        hasNonImageFileInput: true,
        conversationFileSummary: {
          hasImage: false,
          hasAudio: false,
          hasDocument: true,
          hasRemoteDocumentUrl: false,
        },
      },
    });

    const order = await resolveUpstreamEndpointCandidates(
      {
        ...baseContext,
        site: { ...baseContext.site, platform: 'new-api' },
      },
      'gpt-5.3',
      'openai',
      undefined,
      {
        hasNonImageFileInput: true,
        conversationFileSummary: {
          hasImage: false,
          hasAudio: false,
          hasDocument: true,
          hasRemoteDocumentUrl: false,
        },
      },
    );

    expect(order).toEqual(['responses', 'messages', 'chat']);
  });

  it('remembers the last successful endpoint per site capability profile', async () => {
    recordUpstreamEndpointSuccess({
      siteId: baseContext.site.id,
      endpoint: 'responses',
      downstreamFormat: 'openai',
      modelName: 'gpt-5.3',
    });

    const order = await resolveUpstreamEndpointCandidates(
      {
        ...baseContext,
        site: { ...baseContext.site, platform: 'new-api' },
      },
      'gpt-5.3',
      'openai',
    );

    expect(order).toEqual(['responses', 'chat', 'messages']);
  });

  it('keeps learned endpoint state scoped to the model key', async () => {
    recordUpstreamEndpointSuccess({
      siteId: baseContext.site.id,
      endpoint: 'responses',
      downstreamFormat: 'openai',
      modelName: 'gpt-5.3',
    });

    const learnedOrder = await resolveUpstreamEndpointCandidates(
      {
        ...baseContext,
        site: { ...baseContext.site, platform: 'new-api' },
      },
      'gpt-5.3',
      'openai',
    );

    const unrelatedModelOrder = await resolveUpstreamEndpointCandidates(
      {
        ...baseContext,
        site: { ...baseContext.site, platform: 'new-api' },
      },
      'gpt-4.1',
      'openai',
    );

    expect(learnedOrder).toEqual(['responses', 'chat', 'messages']);
    expect(unrelatedModelOrder).toEqual(['chat', 'messages', 'responses']);
  });

  it('bounds runtime model keys before storing them', () => {
    const longModelName = 'gpt-' + 'a'.repeat(MAX_ENDPOINT_RUNTIME_MODEL_KEY_LENGTH + 32);
    const boundedKey = boundEndpointRuntimeModelKey(longModelName);

    expect(boundedKey.length).toBeLessThanOrEqual(
      MAX_ENDPOINT_RUNTIME_MODEL_KEY_LENGTH + 1 + MODEL_KEY_HASH_SUFFIX_LENGTH,
    );
    expect(boundedKey.startsWith(longModelName.slice(0, MAX_ENDPOINT_RUNTIME_MODEL_KEY_LENGTH))).toBe(true);
    expect(boundedKey).toMatch(
      new RegExp(`-[0-9a-f]{${MODEL_KEY_HASH_SUFFIX_LENGTH}}$`),
    );
    expect(boundEndpointRuntimeModelKey(longModelName)).toEqual(boundedKey);
  });

  it('keeps remote-document-url requests on a separate runtime preference bucket from inline document requests', async () => {
    recordUpstreamEndpointSuccess({
      siteId: baseContext.site.id,
      endpoint: 'chat',
      downstreamFormat: 'openai',
      modelName: 'gpt-5.3',
      requestCapabilities: {
        hasNonImageFileInput: true,
        conversationFileSummary: {
          hasImage: false,
          hasAudio: false,
          hasDocument: true,
          hasRemoteDocumentUrl: false,
        },
      },
    });

    const order = await resolveUpstreamEndpointCandidates(
      {
        ...baseContext,
        site: { ...baseContext.site, platform: 'new-api' },
      },
      'gpt-5.3',
      'openai',
      undefined,
      {
        hasNonImageFileInput: true,
        conversationFileSummary: {
          hasImage: false,
          hasAudio: false,
          hasDocument: true,
          hasRemoteDocumentUrl: true,
        },
      },
    );

    expect(order).toEqual(['responses']);
  });

  it('does not remember messages fallback success for generic /v1/responses requests', async () => {
    recordUpstreamEndpointSuccess({
      siteId: baseContext.site.id,
      endpoint: 'messages',
      downstreamFormat: 'responses',
      modelName: 'gpt-5.3',
    });

    const order = await resolveUpstreamEndpointCandidates(
      {
        ...baseContext,
        site: { ...baseContext.site, platform: 'new-api' },
      },
      'gpt-5.3',
      'responses',
    );

    expect(order).toEqual(['responses', 'chat', 'messages']);
  });

  it('does not block generic /v1/responses endpoints on transient upstream errors', async () => {
    recordUpstreamEndpointFailure({
      siteId: baseContext.site.id,
      endpoint: 'responses',
      downstreamFormat: 'responses',
      modelName: 'gpt-5.3',
      status: 504,
      errorText: '{"error":{"message":"Gateway time-out","type":"upstream_error"}}',
    });

    const order = await resolveUpstreamEndpointCandidates(
      {
        ...baseContext,
        site: { ...baseContext.site, platform: 'new-api' },
      },
      'gpt-5.3',
      'responses',
    );

    expect(order).toEqual(['responses', 'chat', 'messages']);
  });

  it('learns a better endpoint from explicit upstream protocol errors', async () => {
    recordUpstreamEndpointFailure({
      siteId: baseContext.site.id,
      endpoint: 'chat',
      downstreamFormat: 'openai',
      modelName: 'gpt-5.3',
      status: 400,
      errorText: 'Unsupported legacy protocol: /v1/chat/completions is not supported. Please use /v1/responses.',
    });

    const order = await resolveUpstreamEndpointCandidates(
      {
        ...baseContext,
        site: { ...baseContext.site, platform: 'new-api' },
      },
      'gpt-5.3',
      'openai',
    );

    expect(order).toEqual(['responses', 'messages']);
  });

  it('keeps claude models messages-first even when openai platform catalog prefers chat', async () => {
    fetchModelPricingCatalogMock.mockResolvedValue({
      models: [
        {
          modelName: 'claude-opus-4-6',
          supportedEndpointTypes: ['/v1/chat/completions', 'openai'],
        },
      ],
      groupRatio: {},
    });

    const order = await resolveUpstreamEndpointCandidates(
      {
        ...baseContext,
        site: { ...baseContext.site, platform: 'openai' },
      },
      'claude-opus-4-6',
      'openai',
    );

    expect(order).toEqual(['messages', 'chat', 'responses']);
  });

  it('keeps anyrouter messages-first special case', async () => {
    const openaiOrder = await resolveUpstreamEndpointCandidates(
      {
        ...baseContext,
        site: { ...baseContext.site, platform: 'anyrouter' },
      },
      'claude-opus-4-6',
      'openai',
    );
    expect(openaiOrder).toEqual(['messages', 'chat', 'responses']);

    const claudeOrder = await resolveUpstreamEndpointCandidates(
      {
        ...baseContext,
        site: { ...baseContext.site, platform: 'anyrouter' },
      },
      'claude-opus-4-6',
      'claude',
    );
    expect(claudeOrder).toEqual(['messages', 'chat', 'responses']);

    const responsesOrder = await resolveUpstreamEndpointCandidates(
      {
        ...baseContext,
        site: { ...baseContext.site, platform: 'anyrouter' },
      },
      'claude-opus-4-6',
      'responses',
    );
    expect(responsesOrder).toEqual(['responses', 'messages', 'chat']);
  });

  it('prefers native responses endpoints for claude-family models when encrypted reasoning is explicitly requested', async () => {
    const order = await resolveUpstreamEndpointCandidates(
      {
        ...baseContext,
        site: { ...baseContext.site, platform: 'new-api' },
      },
      'claude-opus-4-6',
      'responses',
      undefined,
      {
        wantsNativeResponsesReasoning: true,
      } as any,
    );

    expect(order).toEqual(['responses', 'messages', 'chat']);
  });

  it('treats endpoint-not-found responses as downgrade candidates', () => {
    expect(isEndpointDowngradeError(404, '{"error":{"message":"Not Found","type":"not_found_error"}}')).toBe(true);
    expect(isEndpointDowngradeError(405, '{"error":{"message":"Method Not Allowed"}}')).toBe(true);
    expect(isEndpointDowngradeError(400, '{"error":{"message":"unsupported endpoint","type":"invalid_request_error"}}')).toBe(true);
    expect(isEndpointDowngradeError(400, '{"error":{"message":"","type":"upstream_error"}}')).toBe(true);
    expect(isEndpointDowngradeError(400, '{"error":{"message":"openai_error","type":"bad_response_status_code"}}')).toBe(true);
    expect(isEndpointDowngradeError(415, '{"error":{"message":"Unsupported Media Type: Only \\"application/json\\" is allowed"}}')).toBe(true);
  });

  it('treats Claude Code CLI-only restriction on responses as downgrade candidate', () => {
    const upstreamError = JSON.stringify({
      error: {
        code: 'invalid_request',
        type: 'new_api_error',
        message: '请勿在 Claude Code CLI 之外使用接口 (request id: abc123)',
      },
    });

    expect(isEndpointDowngradeError(400, upstreamError)).toBe(true);
  });

  it('detects unsupported media type errors as compatibility retry candidates', () => {
    expect(isUnsupportedMediaTypeError(415, '{"error":{"message":"Unsupported Media Type"}}')).toBe(true);
    expect(isUnsupportedMediaTypeError(400, '{"error":{"message":"Only \\"application/json\\" is allowed"}}')).toBe(true);
    expect(isUnsupportedMediaTypeError(400, '{"error":{"message":"messages is required"}}')).toBe(false);
  });
});

describe('buildUpstreamEndpointRequest', () => {
  it('builds minimal JSON compatibility headers for messages endpoint', () => {
    const headers = buildMinimalJsonHeadersForCompatibility({
      endpoint: 'messages',
      stream: false,
      headers: {
        Authorization: 'Bearer sk-demo',
        'X-Api-Key': 'sk-claude',
        'anthropic-version': '2023-06-01',
        'anthropic-beta': 'prompt-caching-2024-07-31',
        'OpenAI-Beta': 'responses-2025-03-11',
      },
    });

    expect(headers).toEqual({
      authorization: 'Bearer sk-demo',
      'x-api-key': 'sk-claude',
      'anthropic-version': '2023-06-01',
      'anthropic-beta': 'prompt-caching-2024-07-31',
      'content-type': 'application/json',
      accept: 'application/json',
    });
  });

  it('normalizes single-message OpenAI requests to structured responses input', () => {
    const request = buildUpstreamEndpointRequest({
      endpoint: 'responses',
      modelName: 'upstream-gpt',
      stream: false,
      tokenValue: 'sk-test',
      sitePlatform: 'sub2api',
      siteUrl: 'https://example.com',
      openaiBody: {
        model: 'gpt-5.2',
        messages: [{ role: 'user', content: 'hello' }],
      },
      downstreamFormat: 'openai',
    });

    expect(request.path).toBe('/v1/responses');
    expect(request.body.input).toEqual([
      {
        type: 'message',
        role: 'user',
        content: [{ type: 'input_text', text: 'hello' }],
      },
    ]);
  });

  it('builds codex responses requests against backend-api path and preserves oauth provider headers', () => {
    const request = buildUpstreamEndpointRequest({
      endpoint: 'responses',
      modelName: 'gpt-5.2-codex',
      stream: false,
      tokenValue: 'oauth-access-token',
      sitePlatform: 'codex',
      siteUrl: 'https://chatgpt.com/backend-api/codex',
      openaiBody: {
        model: 'gpt-5.2-codex',
        messages: [{ role: 'user', content: 'hello codex' }],
        temperature: 0.2,
        top_p: 0.9,
        user: 'drop-me',
        service_tier: 'auto',
      },
      downstreamFormat: 'openai',
      providerHeaders: {
        Originator: 'codex_cli_rs',
        'Chatgpt-Account-Id': 'chatgpt-account-123',
      },
      codexSessionCacheKey: 'gpt-5.2-codex:proxy:test-key',
    } as any);

    expect(request.path).toBe('/responses');
    expect(request.headers.Authorization).toBe('Bearer oauth-access-token');
    expect(request.headers.Originator).toBe('codex_cli_rs');
    expect(request.headers['Chatgpt-Account-Id']).toBe('chatgpt-account-123');
    expect(request.headers.Version).toBe('0.101.0');
    expect(request.headers.Session_id).toMatch(/^[0-9a-f-]{36}$/i);
    expect(request.headers.Conversation_id).toBe(request.headers.Session_id);
    expect(request.headers['User-Agent']).toBe('codex_cli_rs/0.101.0 (Mac OS 26.0.1; arm64) Apple_Terminal/464');
    expect(request.headers.Accept).toBe('text/event-stream');
    expect(request.headers.Connection).toBe('Keep-Alive');
    expect(request.body.instructions).toBe('');
    expect(request.body.prompt_cache_key).toBeUndefined();
    expect(request.body.stream).toBe(false);
    expect(request.body.store).toBe(false);
    expect(request.body.parallel_tool_calls).toBeUndefined();
    expect(request.body.include).toBeUndefined();
    expect(request.body.max_output_tokens).toBe(4096);
    expect(request.body.temperature).toBe(0.2);
    expect(request.body.top_p).toBe(0.9);
    expect(request.body.user).toBe('drop-me');
    expect(request.body.service_tier).toBe('auto');
  });

  it('reuses a stable codex session id when the same downstream continuity key is provided', () => {
    const firstRequest = buildUpstreamEndpointRequest({
      endpoint: 'responses',
      modelName: 'gpt-5.4',
      stream: false,
      tokenValue: 'oauth-access-token',
      sitePlatform: 'codex',
      siteUrl: 'https://chatgpt.com/backend-api/codex',
      openaiBody: {
        model: 'gpt-5.4',
        messages: [{ role: 'user', content: 'hello codex' }],
      },
      downstreamFormat: 'openai',
      providerHeaders: {
        Originator: 'codex_cli_rs',
      },
      codexSessionCacheKey: 'gpt-5.4:user-123',
    } as any);

    const secondRequest = buildUpstreamEndpointRequest({
      endpoint: 'responses',
      modelName: 'gpt-5.4',
      stream: false,
      tokenValue: 'oauth-access-token',
      sitePlatform: 'codex',
      siteUrl: 'https://chatgpt.com/backend-api/codex',
      openaiBody: {
        model: 'gpt-5.4',
        messages: [{ role: 'user', content: 'hello again codex' }],
      },
      downstreamFormat: 'openai',
      providerHeaders: {
        Originator: 'codex_cli_rs',
      },
      codexSessionCacheKey: 'gpt-5.4:user-123',
    } as any);

    expect(firstRequest.headers.Session_id).toBe(secondRequest.headers.Session_id);
    expect(firstRequest.headers.Conversation_id).toBe(secondRequest.headers.Conversation_id);
    expect(firstRequest.body.prompt_cache_key).toBe(secondRequest.body.prompt_cache_key);
  });

  it('does not synthesize prompt_cache_key or conversation_id for native codex responses requests without one', () => {
    const request = buildUpstreamEndpointRequest({
      endpoint: 'responses',
      modelName: 'gpt-5.4',
      stream: false,
      tokenValue: 'oauth-access-token',
      sitePlatform: 'codex',
      siteUrl: 'https://chatgpt.com/backend-api/codex',
      openaiBody: {},
      downstreamFormat: 'responses',
      responsesOriginalBody: {
        model: 'gpt-5.4',
        input: 'hello codex',
      },
      providerHeaders: {
        Originator: 'codex_cli_rs',
      },
    } as any);

    expect(request.headers.Session_id).toMatch(/^[0-9a-f-]{36}$/i);
    expect(request.headers.Conversation_id).toBeUndefined();
    expect(request.body.prompt_cache_key).toBeUndefined();
  });

  it('preserves explicit prompt_cache_key for native codex responses requests without mapping it into codex session headers', () => {
    const request = buildUpstreamEndpointRequest({
      endpoint: 'responses',
      modelName: 'gpt-5.4',
      stream: false,
      tokenValue: 'oauth-access-token',
      sitePlatform: 'codex',
      siteUrl: 'https://chatgpt.com/backend-api/codex',
      openaiBody: {},
      downstreamFormat: 'responses',
      responsesOriginalBody: {
        model: 'gpt-5.4',
        prompt_cache_key: 'codex-cache-123',
        input: 'hello codex',
      },
      providerHeaders: {
        Originator: 'codex_cli_rs',
      },
    } as any);

    expect(request.headers.Session_id).toMatch(/^[0-9a-f-]{36}$/i);
    expect(request.headers.Conversation_id).toBeUndefined();
    expect(request.body.prompt_cache_key).toBe('codex-cache-123');
  });

  it('preserves native codex responses continuity and request fields without compatibility rewrites', () => {
    const request = buildUpstreamEndpointRequest({
      endpoint: 'responses',
      modelName: 'gpt-5.4',
      stream: false,
      tokenValue: 'oauth-access-token',
      sitePlatform: 'codex',
      siteUrl: 'https://chatgpt.com/backend-api/codex',
      openaiBody: {},
      downstreamFormat: 'responses',
      responsesOriginalBody: {
        model: 'gpt-5.4',
        input: 'hello codex',
        stream: false,
        store: true,
        parallel_tool_calls: false,
        include: ['reasoning.encrypted_content', 'mcp_approval_request.details'],
        previous_response_id: 'resp_prev_123',
        temperature: 0.3,
        top_p: 0.8,
        max_output_tokens: 512,
      },
      providerHeaders: {
        Originator: 'codex_cli_rs',
      },
      codexSessionCacheKey: 'gpt-5.4:user-456',
    } as any);

    expect(request.headers.Session_id).toMatch(/^[0-9a-f-]{36}$/i);
    expect(request.headers.Conversation_id).toBe(request.headers.Session_id);
    expect(request.body.prompt_cache_key).toBeUndefined();
    expect(request.body.instructions).toBe('');
    expect(request.body.stream).toBe(false);
    expect(request.body.store).toBe(false);
    expect(request.body.parallel_tool_calls).toBe(false);
    expect(request.body.include).toEqual(['reasoning.encrypted_content', 'mcp_approval_request.details']);
    expect(request.body.previous_response_id).toBe('resp_prev_123');
    expect(request.body.temperature).toBe(0.3);
    expect(request.body.top_p).toBe(0.8);
    expect(request.body.max_output_tokens).toBe(512);
  });

  it('applies configured codex header defaults with CLIProxyAPI-compatible precedence', () => {
    (config as any).codexHeaderDefaults = {
      userAgent: 'codex-config-ua/1.0',
      betaFeatures: 'multi_agent',
    };

    const websocketRequest = buildUpstreamEndpointRequest({
      endpoint: 'responses',
      modelName: 'gpt-5.4',
      stream: true,
      tokenValue: 'oauth-access-token',
      oauthProvider: 'codex',
      sitePlatform: 'codex',
      siteUrl: 'https://chatgpt.com/backend-api/codex',
      openaiBody: {
        model: 'gpt-5.4',
        messages: [{ role: 'user', content: 'hello codex' }],
      },
      downstreamFormat: 'openai',
      downstreamHeaders: {
        'x-metapi-responses-websocket-transport': '1',
      },
      providerHeaders: {
        Originator: 'codex_cli_rs',
      },
    } as any);

    expect(websocketRequest.headers['User-Agent']).toBe('codex-config-ua/1.0');
    expect(websocketRequest.headers['x-codex-beta-features']).toBe('multi_agent');

    const clientHeaderRequest = buildUpstreamEndpointRequest({
      endpoint: 'responses',
      modelName: 'gpt-5.4',
      stream: true,
      tokenValue: 'oauth-access-token',
      oauthProvider: 'codex',
      sitePlatform: 'codex',
      siteUrl: 'https://chatgpt.com/backend-api/codex',
      openaiBody: {
        model: 'gpt-5.4',
        messages: [{ role: 'user', content: 'hello again codex' }],
      },
      downstreamFormat: 'openai',
      downstreamHeaders: {
        'x-metapi-responses-websocket-transport': '1',
        'user-agent': 'client-ua/2.0',
        'x-codex-beta-features': 'client-beta',
      },
      providerHeaders: {
        Originator: 'codex_cli_rs',
      },
    } as any);

    expect(clientHeaderRequest.headers['User-Agent']).toBe('codex-config-ua/1.0');
    expect(clientHeaderRequest.headers['x-codex-beta-features']).toBe('client-beta');

    const httpRequest = buildUpstreamEndpointRequest({
      endpoint: 'responses',
      modelName: 'gpt-5.4',
      stream: false,
      tokenValue: 'oauth-access-token',
      oauthProvider: 'codex',
      sitePlatform: 'codex',
      siteUrl: 'https://chatgpt.com/backend-api/codex',
      openaiBody: {
        model: 'gpt-5.4',
        messages: [{ role: 'user', content: 'plain http codex' }],
      },
      downstreamFormat: 'openai',
      providerHeaders: {
        Originator: 'codex_cli_rs',
      },
    } as any);

    expect(httpRequest.headers['x-codex-beta-features']).toBeUndefined();
  });

  it('applies configured payload rules before preparing codex responses requests while forcing store false', () => {
    (config as any).payloadRules = {
      default: [
        {
          models: [{ name: 'gpt-*', protocol: 'codex' }],
          params: {
            'reasoning.effort': 'high',
          },
        },
      ],
      defaultRaw: [],
      override: [
        {
          models: [{ name: 'gpt-5.4', protocol: 'codex' }],
          params: {
            'text.verbosity': 'low',
            store: true,
          },
        },
      ],
      overrideRaw: [],
      filter: [
        {
          models: [{ name: 'gpt-5.4', protocol: 'codex' }],
          params: ['safety_identifier'],
        },
      ],
    };

    const request = buildUpstreamEndpointRequest({
      endpoint: 'responses',
      modelName: 'gpt-5.4',
      stream: false,
      tokenValue: 'oauth-access-token',
      oauthProvider: 'codex',
      sitePlatform: 'codex',
      siteUrl: 'https://chatgpt.com/backend-api/codex',
      openaiBody: {
        model: 'gpt-5.4',
        messages: [{ role: 'user', content: 'hello codex' }],
        verbosity: 'high',
        safety_identifier: 'drop-me',
      },
      downstreamFormat: 'openai',
      providerHeaders: {
        Originator: 'codex_cli_rs',
      },
    } as any);

    expect(request.body.reasoning).toEqual({ effort: 'high' });
    expect(request.body.text).toEqual({ verbosity: 'low' });
    expect(request.body.safety_identifier).toBeUndefined();
    expect(request.body.store).toBe(false);
  });

  it('builds gemini-cli native requests with project envelope and bearer headers', () => {
    const request = buildUpstreamEndpointRequest({
      endpoint: 'responses',
      modelName: 'gemini-2.5-pro',
      stream: true,
      tokenValue: 'oauth-access-token',
      oauthProvider: 'gemini-cli',
      oauthProjectId: 'project-demo',
      sitePlatform: 'gemini-cli',
      siteUrl: 'https://cloudcode-pa.googleapis.com',
      openaiBody: {
        model: 'gemini-2.5-pro',
        messages: [
          { role: 'system', content: 'be concise' },
          { role: 'user', content: 'hello gemini cli' },
        ],
        temperature: 0.4,
      },
      downstreamFormat: 'openai',
      providerHeaders: {
        'User-Agent': 'GeminiCLI/0.31.0/unknown (win32; x64)',
        'X-Goog-Api-Client': 'google-genai-sdk/1.41.0 gl-node/v22.19.0',
      },
    });

    expect(request.path).toBe('/v1internal:streamGenerateContent?alt=sse');
    expect(request.headers.Authorization).toBe('Bearer oauth-access-token');
    expect(request.headers['User-Agent']).toBe('GeminiCLI/0.31.0/gemini-2.5-pro (win32; x64)');
    expect(request.headers['X-Goog-Api-Client']).toContain('google-genai-sdk/');
    expect(request.body.project).toBe('project-demo');
    expect(request.body.model).toBe('gemini-2.5-pro');
    expect(request.body.request).toMatchObject({
      generationConfig: {
        temperature: 0.4,
      },
      systemInstruction: {
        role: 'user',
      },
      contents: [
        {
          role: 'user',
          parts: [{ text: 'hello gemini cli' }],
        },
      ],
    });
  });

  it('builds antigravity native requests with the same internal Gemini envelope', () => {
    const request = buildUpstreamEndpointRequest({
      endpoint: 'chat',
      modelName: 'gemini-3-pro-preview',
      stream: false,
      tokenValue: 'oauth-access-token',
      oauthProvider: 'antigravity',
      oauthProjectId: 'project-demo',
      sitePlatform: 'antigravity',
      siteUrl: 'https://cloudcode-pa.googleapis.com',
      openaiBody: {
        model: 'gemini-3-pro-preview',
        messages: [
          { role: 'system', content: 'be concise' },
          { role: 'user', content: 'hello antigravity' },
        ],
      },
      downstreamFormat: 'openai',
      providerHeaders: {
        'User-Agent': 'google-api-nodejs-client/9.15.1',
        'X-Goog-Api-Client': 'google-cloud-sdk vscode_cloudshelleditor/0.1',
      },
    });

    expect(request.path).toBe('/v1internal:generateContent');
    expect(request.headers.Authorization).toBe('Bearer oauth-access-token');
    expect(request.headers['User-Agent']).toBe('antigravity/1.19.6 darwin/arm64');
    expect(request.headers['X-Goog-Api-Client']).toBeUndefined();
    expect(request.headers['Client-Metadata']).toBeUndefined();
    expect(request.body).toEqual({
      project: 'project-demo',
      model: 'gemini-3-pro-preview',
      request: {
        systemInstruction: {
          role: 'user',
          parts: [{ text: 'be concise' }],
        },
        contents: [
          {
            role: 'user',
            parts: [{ text: 'hello antigravity' }],
          },
        ],
      },
    });
  });

  it('uses claude-code runtime headers for claude oauth upstream requests', () => {
    const request = buildUpstreamEndpointRequest({
      endpoint: 'messages',
      modelName: 'claude-opus-4-6',
      stream: true,
      tokenValue: 'oauth-access-token',
      oauthProvider: 'claude',
      sitePlatform: 'claude',
      siteUrl: 'https://api.anthropic.com',
      openaiBody: {
        model: 'claude-opus-4-6',
        messages: [{ role: 'user', content: 'hello claude oauth' }],
      },
      downstreamFormat: 'openai',
    });

    expect(request.path).toBe('/v1/messages');
    expect(request.headers.Authorization).toBe('Bearer oauth-access-token');
    expect(request.headers['x-api-key']).toBeUndefined();
    expect(request.headers['anthropic-version']).toBe('2023-06-01');
    expect(request.headers['Anthropic-Dangerous-Direct-Browser-Access']).toBe('true');
    expect(request.headers['X-App']).toBe('cli');
    expect(request.headers['X-Stainless-Retry-Count']).toBe('0');
    expect(request.headers['X-Stainless-Runtime-Version']).toBe('v24.3.0');
    expect(request.headers['X-Stainless-Package-Version']).toBe('0.74.0');
    expect(request.headers['X-Stainless-Runtime']).toBe('node');
    expect(request.headers['X-Stainless-Lang']).toBe('js');
    expect(request.headers['X-Stainless-Arch']).toBe('x64');
    expect(request.headers['X-Stainless-Os']).toBe('Windows');
    expect(request.headers['X-Stainless-Timeout']).toBe('600');
    expect(request.headers['User-Agent']).toBe('claude-cli/2.1.63 (external, cli)');
    expect(request.headers.Connection).toBe('keep-alive');
    expect(request.headers.Accept).toBe('text/event-stream');
    expect(request.headers['Accept-Encoding']).toBe('gzip, deflate, br, zstd');
  });

  it('uses claude-code beta headers and uncompressed non-stream responses for claude upstream requests', () => {
    const request = buildUpstreamEndpointRequest({
      endpoint: 'messages',
      modelName: 'claude-opus-4-6',
      stream: false,
      tokenValue: 'oauth-access-token',
      oauthProvider: 'claude',
      sitePlatform: 'claude',
      siteUrl: 'https://api.anthropic.com',
      openaiBody: {
        model: 'claude-opus-4-6',
        messages: [{ role: 'user', content: 'hello claude oauth' }],
      },
      downstreamFormat: 'openai',
    });

    expect(request.headers['anthropic-beta']).toContain('claude-code-20250219');
    expect(request.headers['anthropic-beta']).toContain('oauth-2025-04-20');
    expect(request.headers['anthropic-beta']).toContain('context-management-2025-06-27');
    expect(request.headers.Accept).toBe('application/json');
    expect(request.headers['Accept-Encoding']).toBe('gzip, deflate, br, zstd');
  });

  it('converts system roles to developer in native codex responses bodies', () => {
    const request = buildUpstreamEndpointRequest({
      endpoint: 'responses',
      modelName: 'gpt-5.4',
      stream: false,
      tokenValue: 'oauth-access-token',
      sitePlatform: 'codex',
      siteUrl: 'https://chatgpt.com/backend-api/codex',
      openaiBody: {},
      downstreamFormat: 'responses',
      responsesOriginalBody: {
        model: 'gpt-5.4',
        input: [
          {
            type: 'message',
            role: 'system',
            content: [{ type: 'input_text', text: 'be careful' }],
          },
          {
            type: 'message',
            role: 'user',
            content: [{ type: 'input_text', text: 'hello' }],
          },
        ],
      },
    });

    expect(request.body.input).toEqual([
      {
        type: 'message',
        role: 'developer',
        content: [{ type: 'input_text', text: 'be careful' }],
      },
      {
        type: 'message',
        role: 'user',
        content: [{ type: 'input_text', text: 'hello' }],
      },
    ]);
  });

  it('normalizes downstream responses input string before forwarding upstream', () => {
    const request = buildUpstreamEndpointRequest({
      endpoint: 'responses',
      modelName: 'upstream-gpt',
      stream: false,
      tokenValue: 'sk-test',
      sitePlatform: 'sub2api',
      siteUrl: 'https://example.com',
      openaiBody: {},
      downstreamFormat: 'responses',
      responsesOriginalBody: {
        model: 'gpt-5.2',
        input: 'hello',
        metadata: { trace: 'abc123' },
      },
    });

    expect(request.path).toBe('/v1/responses');
    expect(request.body.metadata).toEqual({ trace: 'abc123' });
    expect(request.body.input).toEqual([
      {
        type: 'message',
        role: 'user',
        content: [{ type: 'input_text', text: 'hello' }],
      },
    ]);
  });

  it('preserves multimodal user content when converting chat to messages', () => {
    const request = buildUpstreamEndpointRequest({
      endpoint: 'messages',
      modelName: 'claude-3-7-sonnet',
      stream: false,
      tokenValue: 'sk-test',
      sitePlatform: 'anthropic',
      siteUrl: 'https://example.com',
      openaiBody: {
        model: 'gpt-4o-mini',
        messages: [
          {
            role: 'user',
            content: [
              { type: 'text', text: 'describe this' },
              { type: 'image_url', image_url: { url: 'https://example.com/cat.png' } },
            ],
          },
        ],
      },
      downstreamFormat: 'openai',
    });

    expect(request.path).toBe('/v1/messages');
    expect(request.body.messages).toEqual([
      {
        role: 'user',
        content: [
          { type: 'text', text: 'describe this' },
          {
            type: 'image',
            cache_control: { type: 'ephemeral' },
            source: {
              type: 'url',
              url: 'https://example.com/cat.png',
            },
          },
        ],
      },
    ]);
  });

  it('preserves multimodal user content when converting chat to responses', () => {
    const request = buildUpstreamEndpointRequest({
      endpoint: 'responses',
      modelName: 'gpt-4.1',
      stream: false,
      tokenValue: 'sk-test',
      sitePlatform: 'openai',
      siteUrl: 'https://example.com',
      openaiBody: {
        model: 'gpt-4o-mini',
        messages: [
          {
            role: 'user',
            content: [
              { type: 'text', text: 'describe this' },
              { type: 'image_url', image_url: { url: 'https://example.com/cat.png' } },
            ],
          },
        ],
      },
      downstreamFormat: 'openai',
    });

    expect(request.path).toBe('/v1/responses');
    expect(request.body.input).toEqual([
      {
        type: 'message',
        role: 'user',
        content: [
          { type: 'input_text', text: 'describe this' },
          { type: 'input_image', image_url: { url: 'https://example.com/cat.png' } },
        ],
      },
    ]);
  });

  it('preserves input_file blocks when converting chat to responses', () => {
    const request = buildUpstreamEndpointRequest({
      endpoint: 'responses',
      modelName: 'gpt-4.1',
      stream: false,
      tokenValue: 'sk-test',
      sitePlatform: 'openai',
      siteUrl: 'https://example.com',
      openaiBody: {
        model: 'gpt-4o-mini',
        messages: [
          {
            role: 'user',
            content: [
              { type: 'text', text: 'summarize this file' },
              { type: 'input_file', filename: 'brief.pdf', file_data: 'JVBERi0xLjc=' },
            ],
          },
        ],
      },
      downstreamFormat: 'openai',
    });

    expect(request.path).toBe('/v1/responses');
    expect(request.body.input).toEqual([
      {
        type: 'message',
        role: 'user',
        content: [
          { type: 'input_text', text: 'summarize this file' },
          { type: 'input_file', filename: 'brief.pdf', file_data: 'data:application/pdf;base64,JVBERi0xLjc=' },
        ],
      },
    ]);
  });

  it('serializes file uploads into Responses input_file blocks without conflicting file ids', () => {
    const request = buildUpstreamEndpointRequest({
      endpoint: 'responses',
      modelName: 'gpt-5.2',
      stream: false,
      tokenValue: 'sk-test',
      sitePlatform: 'openai',
      siteUrl: 'https://example.com',
      openaiBody: {
        model: 'gpt-5.2',
        messages: [
          {
            role: 'user',
            content: [
              { type: 'text', text: 'read this' },
              {
                type: 'file',
                file_id: 'file_local_123',
                filename: 'paper.pdf',
                mime_type: 'application/pdf',
                file_data: 'JVBERi0xLjQK',
              },
            ],
          },
        ],
      },
      downstreamFormat: 'openai',
    });

    expect(request.path).toBe('/v1/responses');
    expect(request.body.input).toEqual([
      {
        type: 'message',
        role: 'user',
        content: [
          { type: 'input_text', text: 'read this' },
          {
            type: 'input_file',
            filename: 'paper.pdf',
            file_data: 'data:application/pdf;base64,JVBERi0xLjQK',
          },
        ],
      },
    ]);
  });

  it('preserves unknown native responses fields while still normalizing known compatibility fields', () => {
    const request = buildUpstreamEndpointRequest({
      endpoint: 'responses',
      modelName: 'upstream-gpt',
      stream: false,
      tokenValue: 'sk-test',
      sitePlatform: 'openai',
      siteUrl: 'https://example.com',
      openaiBody: {},
      downstreamFormat: 'responses',
      responsesOriginalBody: {
        model: 'gpt-5.2',
        input: 'hello',
        metadata: { trace: 'abc123' },
        max_completion_tokens: 512,
        custom_vendor_flag: 'keep-me',
      },
    });

    expect(request.path).toBe('/v1/responses');
    expect(request.body.metadata).toEqual({ trace: 'abc123' });
    expect(request.body.custom_vendor_flag).toBe('keep-me');
    expect(request.body.max_completion_tokens).toBeUndefined();
    expect(request.body.max_output_tokens).toBe(512);
    expect(request.body.input).toEqual([
      {
        type: 'message',
        role: 'user',
        content: [{ type: 'input_text', text: 'hello' }],
      },
    ]);
  });

  it('backfills responses input from legacy messages payload', () => {
    const request = buildUpstreamEndpointRequest({
      endpoint: 'responses',
      modelName: 'upstream-gpt',
      stream: false,
      tokenValue: 'sk-test',
      sitePlatform: 'openai',
      siteUrl: 'https://example.com',
      openaiBody: {},
      downstreamFormat: 'responses',
      responsesOriginalBody: {
        model: 'gpt-5.2',
        messages: [{ role: 'user', content: 'hello from messages' }],
      },
    });

    expect(request.path).toBe('/v1/responses');
    expect(request.body.input).toEqual([
      {
        type: 'message',
        role: 'user',
        content: [{ type: 'input_text', text: 'hello from messages' }],
      },
    ]);
  });

  it('backfills responses input from prompt field when input/messages are missing', () => {
    const request = buildUpstreamEndpointRequest({
      endpoint: 'responses',
      modelName: 'upstream-gpt',
      stream: false,
      tokenValue: 'sk-test',
      sitePlatform: 'openai',
      siteUrl: 'https://example.com',
      openaiBody: {},
      downstreamFormat: 'responses',
      responsesOriginalBody: {
        model: 'gpt-5.2',
        prompt: 'hello from prompt',
      },
    });

    expect(request.path).toBe('/v1/responses');
    expect(request.body.input).toEqual([
      {
        type: 'message',
        role: 'user',
        content: [{ type: 'input_text', text: 'hello from prompt' }],
      },
    ]);
  });

  it('blocks downstream content-type passthrough and forces json content-type upstream', () => {
    const request = buildUpstreamEndpointRequest({
      endpoint: 'responses',
      modelName: 'upstream-gpt',
      stream: false,
      tokenValue: 'sk-test',
      sitePlatform: 'new-api',
      siteUrl: 'https://example.com',
      openaiBody: {
        model: 'gpt-5.2',
        messages: [{ role: 'user', content: 'hello' }],
      },
      downstreamFormat: 'openai',
      downstreamHeaders: {
        'content-type': 'text/plain',
      },
    });

    expect(request.headers['content-type']).toBeUndefined();
    expect(request.headers['Content-Type']).toBe('application/json');
  });

  it('strips unsupported openai parameters like frequency_penalty for Gemini models on chat endpoints', () => {
    const request = buildUpstreamEndpointRequest({
      endpoint: 'chat',
      modelName: 'gemini-1.5-pro',
      stream: false,
      tokenValue: 'sk-test',
      sitePlatform: 'gemini',
      openaiBody: {
        model: 'gemini-1.5-pro',
        messages: [{ role: 'user', content: 'hello' }],
        frequency_penalty: 0.5,
        presence_penalty: 0.2,
        logit_bias: { '100': 1 },
        logprobs: true,
        top_logprobs: 2,
        store: true,
        temperature: 0.8,
        top_p: 1.0,
      },
      downstreamFormat: 'openai',
    });

    expect(request.path).toBe('/v1beta/openai/chat/completions');
    expect(request.body.frequency_penalty).toBeUndefined();
    expect(request.body.presence_penalty).toBeUndefined();
    expect(request.body.logit_bias).toBeUndefined();
    expect(request.body.logprobs).toBeUndefined();
    expect(request.body.top_logprobs).toBeUndefined();
    expect(request.body.store).toBeUndefined();
    expect(request.body.temperature).toBe(0.8);
    expect(request.body.top_p).toBe(1.0);
  });

  it('strips unsupported openai parameters like frequency_penalty for Gemini models on responses endpoints', () => {
    const request = buildUpstreamEndpointRequest({
      endpoint: 'responses',
      modelName: 'gemini-1.5-pro',
      stream: false,
      tokenValue: 'sk-test',
      sitePlatform: 'gemini',
      openaiBody: {
        model: 'gemini-1.5-pro',
        messages: [{ role: 'user', content: 'hello' }],
        frequency_penalty: 0.5,
        presence_penalty: 0.2,
        logit_bias: { '100': 1 },
        logprobs: true,
        top_logprobs: 2,
        store: true,
        temperature: 0.8,
        top_p: 1.0,
      },
      downstreamFormat: 'openai',
    });

    expect(request.path).toBe('/v1beta/openai/responses');
    expect(request.body.frequency_penalty).toBeUndefined();
    expect(request.body.presence_penalty).toBeUndefined();
    expect(request.body.logit_bias).toBeUndefined();
    expect(request.body.logprobs).toBeUndefined();
    expect(request.body.top_logprobs).toBeUndefined();
    expect(request.body.store).toBeUndefined();
    expect(request.body.temperature).toBe(0.8);
  });

  it('strips unsupported openai parameters like frequency_penalty for Gemini models from downstream responses bodies', () => {
    const request = buildUpstreamEndpointRequest({
      endpoint: 'responses',
      modelName: 'gemini-1.5-pro',
      stream: false,
      tokenValue: 'sk-test',
      sitePlatform: 'gemini',
      openaiBody: {},
      downstreamFormat: 'responses',
      responsesOriginalBody: {
        model: 'gemini-1.5-pro',
        input: 'hello',
        frequency_penalty: 0.5,
        presence_penalty: 0.2,
        logit_bias: { '100': 1 },
        logprobs: true,
        top_logprobs: 2,
        store: true,
        temperature: 0.8,
        top_p: 1.0,
      },
    });

    expect(request.path).toBe('/v1beta/openai/responses');
    expect(request.body.frequency_penalty).toBeUndefined();
    expect(request.body.presence_penalty).toBeUndefined();
    expect(request.body.logit_bias).toBeUndefined();
    expect(request.body.logprobs).toBeUndefined();
    expect(request.body.top_logprobs).toBeUndefined();
    expect(request.body.store).toBeUndefined();
    expect(request.body.temperature).toBe(0.8);
    expect(request.body.top_p).toBe(1.0);
  });

  it('preserves structured responses content blocks instead of flattening them', () => {
    const request = buildUpstreamEndpointRequest({
      endpoint: 'responses',
      modelName: 'upstream-gpt',
      stream: false,
      tokenValue: 'sk-test',
      sitePlatform: 'openai',
      siteUrl: 'https://example.com',
      openaiBody: {},
      downstreamFormat: 'responses',
      responsesOriginalBody: {
        model: 'gpt-5.2',
        input: [
          {
            type: 'message',
            role: 'user',
            content: [
              { type: 'input_text', text: 'describe this image' },
              { type: 'input_image', image_url: 'https://example.com/cat.png' },
              {
                type: 'input_audio',
                input_audio: {
                  data: 'UklGRg==',
                  format: 'wav',
                },
              },
            ],
          },
        ],
      },
    });

    expect(request.path).toBe('/v1/responses');
    expect(request.body.input).toEqual([
      {
        type: 'message',
        role: 'user',
        content: [
          { type: 'input_text', text: 'describe this image' },
          { type: 'input_image', image_url: 'https://example.com/cat.png' },
          {
            type: 'input_audio',
            input_audio: {
              data: 'UklGRg==',
              format: 'wav',
            },
          },
        ],
      },
    ]);
  });

  it('preserves structured input_file blocks on downstream responses bodies', () => {
    const request = buildUpstreamEndpointRequest({
      endpoint: 'responses',
      modelName: 'upstream-gpt',
      stream: false,
      tokenValue: 'sk-test',
      sitePlatform: 'openai',
      siteUrl: 'https://example.com',
      openaiBody: {},
      downstreamFormat: 'responses',
      responsesOriginalBody: {
        model: 'gpt-5.2',
        input: [
          {
            type: 'message',
            role: 'user',
            content: [
              { type: 'input_text', text: 'summarize this file' },
              {
                type: 'input_file',
                filename: 'notes.txt',
                file_data: 'data:text/plain;base64,aGVsbG8=',
              },
            ],
          },
        ],
      },
    });

    expect(request.body.input).toEqual([
      {
        type: 'message',
        role: 'user',
        content: [
          { type: 'input_text', text: 'summarize this file' },
          {
            type: 'input_file',
            filename: 'notes.txt',
            file_data: 'data:text/plain;base64,aGVsbG8=',
          },
        ],
      },
    ]);
  });

  it('preserves structured input_file file_url blocks on downstream responses bodies', () => {
    const request = buildUpstreamEndpointRequest({
      endpoint: 'responses',
      modelName: 'upstream-gpt',
      stream: false,
      tokenValue: 'sk-test',
      sitePlatform: 'openai',
      siteUrl: 'https://example.com',
      openaiBody: {},
      downstreamFormat: 'responses',
      responsesOriginalBody: {
        model: 'gpt-5.2',
        input: [
          {
            type: 'message',
            role: 'user',
            content: [
              { type: 'input_text', text: 'read this remote file' },
              {
                type: 'input_file',
                filename: 'remote.pdf',
                file_url: 'https://example.com/remote.pdf',
              },
            ],
          },
        ],
      },
    });

    expect(request.body.input).toEqual([
      {
        type: 'message',
        role: 'user',
        content: [
          { type: 'input_text', text: 'read this remote file' },
          {
            type: 'input_file',
            filename: 'remote.pdf',
            file_url: 'https://example.com/remote.pdf',
          },
        ],
      },
    ]);
  });

  it('maps OpenAI file blocks to Anthropic document blocks', () => {
    const request = buildUpstreamEndpointRequest({
      endpoint: 'messages',
      modelName: 'claude-sonnet-4-5',
      stream: false,
      tokenValue: 'sk-test',
      sitePlatform: 'claude',
      siteUrl: 'https://example.com',
      downstreamFormat: 'openai',
      openaiBody: {
        model: 'gpt-5.2',
        messages: [
          {
            role: 'user',
            content: [
              { type: 'text', text: 'summarize this pdf' },
              {
                type: 'input_file',
                filename: 'brief.pdf',
                file_data: 'data:application/pdf;base64,JVBERi0xLjQK',
              },
            ],
          },
        ],
      },
    });

    expect(request.path).toBe('/v1/messages');
    expect(request.body.messages).toEqual([
      {
        role: 'user',
        content: [
          { type: 'text', text: 'summarize this pdf' },
          {
            type: 'document',
            cache_control: { type: 'ephemeral' },
            source: {
              type: 'base64',
              media_type: 'application/pdf',
              data: 'JVBERi0xLjQK',
            },
            title: 'brief.pdf',
          },
        ],
      },
    ]);
  });

  it('preserves multimodal OpenAI user content when converting to Anthropic messages', () => {
    const request = buildUpstreamEndpointRequest({
      endpoint: 'messages',
      modelName: 'claude-sonnet-4-5',
      stream: false,
      tokenValue: 'sk-test',
      sitePlatform: 'claude',
      siteUrl: 'https://example.com',
      downstreamFormat: 'openai',
      openaiBody: {
        model: 'claude-sonnet-4-5',
        messages: [
          {
            role: 'system',
            content: 'be careful',
          },
          {
            role: 'user',
            content: [
              { type: 'text', text: 'describe this image' },
              { type: 'image_url', image_url: { url: 'https://example.com/cat.png' } },
            ],
          },
        ],
      },
    });

    expect(request.path).toBe('/v1/messages');
    expect(request.body.system).toEqual([
      {
        type: 'text',
        text: 'be careful',
        cache_control: { type: 'ephemeral' },
      },
    ]);
    expect(request.body.messages).toEqual([
      {
        role: 'user',
        content: [
          { type: 'text', text: 'describe this image' },
          {
            type: 'image',
            cache_control: { type: 'ephemeral' },
            source: {
              type: 'url',
              url: 'https://example.com/cat.png',
            },
          },
        ],
      },
    ]);
  });

  it('maps input_file blocks to anthropic document content', () => {
    const request = buildUpstreamEndpointRequest({
      endpoint: 'messages',
      modelName: 'claude-sonnet-4-5',
      stream: false,
      tokenValue: 'sk-test',
      sitePlatform: 'claude',
      siteUrl: 'https://example.com',
      openaiBody: {
        model: 'claude-sonnet-4-5',
        messages: [
          {
            role: 'user',
            content: [
              { type: 'text', text: 'read this document' },
              { type: 'input_file', filename: 'brief.pdf', mime_type: 'application/pdf', file_data: 'JVBERi0xLjc=' },
            ],
          },
        ],
      },
      downstreamFormat: 'openai',
    });

    expect(request.path).toBe('/v1/messages');
    expect(request.body.messages).toEqual([
      {
        role: 'user',
        content: [
          { type: 'text', text: 'read this document' },
          {
            type: 'document',
            cache_control: { type: 'ephemeral' },
            title: 'brief.pdf',
            source: {
              type: 'base64',
              media_type: 'application/pdf',
              data: 'JVBERi0xLjc=',
            },
          },
        ],
      },
    ]);
  });

  it('maps file uploads into Anthropic document blocks for messages endpoints', () => {
    const request = buildUpstreamEndpointRequest({
      endpoint: 'messages',
      modelName: 'claude-opus-4-6',
      stream: false,
      tokenValue: 'sk-test',
      sitePlatform: 'claude',
      siteUrl: 'https://example.com',
      downstreamFormat: 'openai',
      openaiBody: {
        model: 'claude-opus-4-6',
        messages: [
          {
            role: 'user',
            content: [
              { type: 'text', text: 'summarize the PDF' },
              {
                type: 'file',
                file_id: 'file_local_789',
                filename: 'report.pdf',
                mime_type: 'application/pdf',
                file_data: 'JVBERi0xLjQK',
              },
            ],
          },
        ],
      },
    });

    expect(request.path).toBe('/v1/messages');
    expect(request.body.messages).toEqual([
      {
        role: 'user',
        content: [
          { type: 'text', text: 'summarize the PDF' },
          {
            type: 'document',
            cache_control: { type: 'ephemeral' },
            source: {
              type: 'base64',
              media_type: 'application/pdf',
              data: 'JVBERi0xLjQK',
            },
            title: 'report.pdf',
          },
        ],
      },
    ]);
  });

  it('preserves assistant reasoning blocks for Anthropic and strips cache_control from thinking blocks', () => {
    const request = buildUpstreamEndpointRequest({
      endpoint: 'messages',
      modelName: 'claude-sonnet-4-5',
      stream: false,
      tokenValue: 'sk-test',
      sitePlatform: 'claude',
      siteUrl: 'https://example.com',
      downstreamFormat: 'openai',
      openaiBody: {
        model: 'claude-sonnet-4-5',
        messages: [
          {
            role: 'assistant',
            content: [
              {
                type: 'reasoning',
                text: 'internal thinking',
                cache_control: { type: 'ephemeral' },
              },
              {
                type: 'text',
                text: 'final answer',
                cache_control: { type: 'ephemeral' },
              },
            ],
          },
        ],
      },
    });

    expect(request.path).toBe('/v1/messages');
    expect(request.body.messages).toEqual([
      {
        role: 'assistant',
        content: [
          {
            type: 'thinking',
            thinking: 'internal thinking',
          },
          {
            type: 'text',
            text: 'final answer',
            cache_control: { type: 'ephemeral' },
          },
        ],
      },
    ]);
  });

  it('preserves native Claude request bodies instead of re-optimizing cache anchors', () => {
    const claudeOriginalBody = {
      model: 'claude-opus-4-6',
      max_tokens: 512,
      tools: [
        {
          name: 'lookup',
          input_schema: { type: 'object' },
          cache_control: { type: 'ephemeral' },
        },
      ],
      messages: [
        {
          role: 'assistant',
          content: [
            {
              type: 'tool_use',
              id: 'tool_1',
              name: 'lookup',
              input: { city: 'paris' },
              cache_control: { type: 'ephemeral' },
            },
            {
              type: 'text',
              text: 'done',
            },
          ],
        },
      ],
      tool_choice: { type: 'tool', name: 'lookup' },
    };

    const request = buildUpstreamEndpointRequest({
      endpoint: 'messages',
      modelName: 'claude-opus-4-6',
      stream: false,
      tokenValue: 'sk-test',
      sitePlatform: 'claude',
      siteUrl: 'https://example.com',
      downstreamFormat: 'claude',
      openaiBody: {
        model: 'ignored',
        messages: [{ role: 'user', content: 'ignored' }],
      },
      claudeOriginalBody,
    });

    expect(request.path).toBe('/v1/messages');
    expect(request.body).toEqual({
      ...claudeOriginalBody,
      model: 'claude-opus-4-6',
      stream: false,
    });
  });

  it('preserves multimodal OpenAI user content when converting to Responses input', () => {
    const request = buildUpstreamEndpointRequest({
      endpoint: 'responses',
      modelName: 'gpt-5.2',
      stream: false,
      tokenValue: 'sk-test',
      sitePlatform: 'openai',
      siteUrl: 'https://example.com',
      downstreamFormat: 'openai',
      openaiBody: {
        model: 'gpt-5.2',
        messages: [
          {
            role: 'user',
            content: [
              { type: 'text', text: 'describe the upload' },
              { type: 'image_url', image_url: { url: 'https://example.com/cat.png' } },
            ],
          },
        ],
      },
    });

    expect(request.path).toBe('/v1/responses');
    expect(request.body.input).toEqual([
      {
        type: 'message',
        role: 'user',
        content: [
          { type: 'input_text', text: 'describe the upload' },
          { type: 'input_image', image_url: { url: 'https://example.com/cat.png' } },
        ],
      },
    ]);
  });

  it('drops Responses-only tools when /v1/responses falls back to /v1/chat/completions', () => {
    const request = buildUpstreamEndpointRequest({
      endpoint: 'chat',
      modelName: 'gpt-5.4',
      stream: false,
      tokenValue: 'sk-test',
      sitePlatform: 'openai',
      siteUrl: 'https://example.com',
      downstreamFormat: 'responses',
      openaiBody: {
        model: 'gpt-5.4',
        messages: [
          {
            role: 'user',
            content: 'summarize the workspace state',
          },
        ],
        tools: [
          {
            type: 'function',
            function: {
              name: 'Glob',
              description: 'Search files',
              parameters: {
                type: 'object',
                properties: {
                  pattern: { type: 'string' },
                },
                required: ['pattern'],
              },
            },
          },
          {
            type: 'custom',
            name: 'browser',
            format: { type: 'text' },
          },
          {
            type: 'image_generation',
            size: '1024x1024',
          },
        ],
        tool_choice: {
          type: 'custom',
          name: 'browser',
        },
      },
    });

    expect(request.path).toBe('/v1/chat/completions');
    expect(request.body).toMatchObject({
      model: 'gpt-5.4',
      stream: false,
      tools: [
        {
          type: 'function',
          function: {
            name: 'Glob',
            description: 'Search files',
            parameters: {
              type: 'object',
              properties: {
                pattern: { type: 'string' },
              },
              required: ['pattern'],
            },
          },
        },
      ],
    });
    expect(request.body.tool_choice).toBeUndefined();
  });

  it('preserves Anthropic image and tool_result blocks instead of flattening to plain text', () => {
    const request = buildUpstreamEndpointRequest({
      endpoint: 'messages',
      modelName: 'claude-opus-4-6',
      stream: false,
      tokenValue: 'sk-test',
      sitePlatform: 'claude',
      siteUrl: 'https://example.com',
      openaiBody: {
        model: 'gpt-5.2',
        messages: [
          {
            role: 'system',
            content: 'system prompt',
          },
          {
            role: 'user',
            content: [
              { type: 'text', text: 'look at this' },
              { type: 'image_url', image_url: 'https://example.com/cat.png' },
            ],
          },
          {
            role: 'assistant',
            tool_calls: [
              {
                id: 'call_1',
                type: 'function',
                function: {
                  name: 'lookup',
                  arguments: '{"topic":"cat"}',
                },
              },
            ],
          },
          {
            role: 'tool',
            tool_call_id: 'call_1',
            content: '{"ok":true}',
          },
          {
            role: 'user',
            content: 'thanks',
          },
        ],
      },
      downstreamFormat: 'openai',
    });

    expect(request.path).toBe('/v1/messages');
    expect(request.body.system).toEqual([
      {
        type: 'text',
        text: 'system prompt',
        cache_control: { type: 'ephemeral' },
      },
    ]);
    expect(request.body.messages).toEqual([
      {
        role: 'user',
        content: [
          { type: 'text', text: 'look at this' },
          {
            type: 'image',
            source: {
              type: 'url',
              url: 'https://example.com/cat.png',
            },
          },
        ],
      },
      {
        role: 'assistant',
        content: [
          {
            type: 'tool_use',
            id: 'call_1',
            name: 'lookup',
            input: { topic: 'cat' },
          },
        ],
      },
      {
        role: 'user',
        content: [
          {
            type: 'tool_result',
            tool_use_id: 'call_1',
            content: '{"ok":true}',
          },
          {
            type: 'text',
            text: 'thanks',
            cache_control: { type: 'ephemeral' },
          },
        ],
      },
    ]);
  });
});
