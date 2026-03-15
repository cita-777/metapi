import { beforeEach, describe, expect, it, vi } from 'vitest';

const fetchModelPricingCatalogMock = vi.fn(async (_arg?: unknown): Promise<any> => null);

vi.mock('../../services/modelPricingService.js', () => ({
  fetchModelPricingCatalog: (arg: unknown) => fetchModelPricingCatalogMock(arg),
}));

import {
  buildMinimalJsonHeadersForCompatibility,
  buildUpstreamEndpointRequest,
  isUnsupportedMediaTypeError,
  isEndpointDowngradeError,
  resolveUpstreamEndpointCandidates,
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

  it('applies global responses standardization and drops non-standard fields', () => {
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
        custom_vendor_flag: 'drop-me',
      },
    });

    expect(request.path).toBe('/v1/responses');
    expect(request.body.metadata).toEqual({ trace: 'abc123' });
    expect(request.body.custom_vendor_flag).toBeUndefined();
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
