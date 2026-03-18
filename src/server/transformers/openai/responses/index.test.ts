import { describe, expect, it } from 'vitest';

import { openAiResponsesTransformer } from './index.js';

describe('openAiResponsesTransformer.inbound', () => {
  it('parses responses requests into canonical envelopes', () => {
    const result = openAiResponsesTransformer.parseRequest({
      model: 'gpt-5',
      input: 'hello',
      previous_response_id: 'resp_prev_1',
      prompt_cache_key: 'cache-key',
      reasoning: {
        effort: 'high',
      },
    });

    expect(result.error).toBeUndefined();
    expect(result.value).toMatchObject({
      operation: 'generate',
      surface: 'openai-responses',
      cliProfile: 'generic',
      requestedModel: 'gpt-5',
      stream: false,
      continuation: {
        previousResponseId: 'resp_prev_1',
        promptCacheKey: 'cache-key',
      },
      messages: [
        {
          role: 'user',
          parts: [{ type: 'text', text: 'hello' }],
        },
      ],
      reasoning: {
        effort: 'high',
      },
    });
  });

  it('builds responses requests from canonical envelopes', () => {
    const body = openAiResponsesTransformer.buildProtocolRequest({
      operation: 'generate',
      surface: 'openai-responses',
      cliProfile: 'codex',
      requestedModel: 'gpt-5',
      stream: true,
      messages: [{ role: 'user', parts: [{ type: 'text', text: 'hello' }] }],
      continuation: {
        previousResponseId: 'resp_prev_1',
        promptCacheKey: 'cache-key',
      },
      reasoning: {
        effort: 'high',
      },
    });

    expect(body).toMatchObject({
      model: 'gpt-5',
      stream: true,
      previous_response_id: 'resp_prev_1',
      prompt_cache_key: 'cache-key',
      input: [
        {
          type: 'message',
          role: 'user',
          content: [{ type: 'input_text', text: 'hello' }],
        },
      ],
      reasoning: {
        effort: 'high',
      },
    });
  });

  it('returns a protocol request envelope with a normalized responses body', () => {
    const result = openAiResponsesTransformer.transformRequest({
      model: 'gpt-5',
      input: 'hello',
      reasoning: {
        effort: 'high',
      },
    });

    expect(result.error).toBeUndefined();
    expect(result.value).toMatchObject({
      protocol: 'openai/responses',
      model: 'gpt-5',
      stream: false,
      rawBody: {
        model: 'gpt-5',
        input: 'hello',
      },
      parsed: {
        normalizedBody: {
          model: 'gpt-5',
          input: [
            {
              type: 'message',
              role: 'user',
              content: [
                {
                  type: 'input_text',
                  text: 'hello',
                },
              ],
            },
          ],
          stream: false,
        },
      },
    });
  });

  it('rejects requests without a model at the transformer boundary', () => {
    const result = openAiResponsesTransformer.transformRequest({
      input: 'hello',
    });

    expect(result.error).toEqual({
      statusCode: 400,
      payload: {
        error: {
          message: 'model is required',
          type: 'invalid_request_error',
        },
      },
    });
  });
});
