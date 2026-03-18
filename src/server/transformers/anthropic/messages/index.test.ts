import { describe, expect, it } from 'vitest';

import { anthropicMessagesTransformer } from './index.js';

describe('anthropicMessagesTransformer protocol contract', () => {
  it('parses native messages requests into canonical envelopes', () => {
    const result = anthropicMessagesTransformer.parseRequest({
      model: 'claude-sonnet-4-5',
      max_tokens: 256,
      messages: [
        {
          role: 'user',
          content: [{ type: 'text', text: 'hello' }],
        },
      ],
      metadata: {
        user_id: 'user_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef_account__session_11111111-2222-3333-4444-555555555555',
      },
    });

    expect(result.error).toBeUndefined();
    expect(result.value).toMatchObject({
      operation: 'generate',
      surface: 'anthropic-messages',
      cliProfile: 'generic',
      requestedModel: 'claude-sonnet-4-5',
      stream: false,
      messages: [
        {
          role: 'user',
          parts: [{ type: 'text', text: 'hello' }],
        },
      ],
    });
  });

  it('builds native messages requests from canonical envelopes', () => {
    const body = anthropicMessagesTransformer.buildProtocolRequest({
      operation: 'count_tokens',
      surface: 'anthropic-messages',
      cliProfile: 'claude_code',
      requestedModel: 'claude-sonnet-4-5',
      stream: false,
      messages: [
        {
          role: 'user',
          parts: [{ type: 'text', text: 'count these tokens' }],
        },
      ],
      tools: [{ name: 'lookup', inputSchema: { type: 'object' } }],
    });

    expect(body).toMatchObject({
      model: 'claude-sonnet-4-5',
      max_tokens: 4096,
      messages: [
        {
          role: 'user',
          content: 'count these tokens',
        },
      ],
      tools: [
        {
          name: 'lookup',
          input_schema: { type: 'object' },
        },
      ],
    });
  });
});
