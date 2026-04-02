import { describe, expect, it } from 'vitest';

import { anthropicMessagesInbound } from './inbound.js';

describe('anthropicMessagesInbound', () => {
  it('rejects requests without a positive max_tokens value', () => {
    const result = anthropicMessagesInbound.parse({
      model: 'claude-opus-4-6',
      max_tokens: 0,
      messages: [{ role: 'user', content: 'hello' }],
    });

    expect(result.error).toEqual({
      statusCode: 400,
      payload: {
        error: {
          message: 'max_tokens is required and must be positive',
          type: 'invalid_request_error',
        },
      },
    });
  });

  it('rejects system prompt blocks that are not text entries', () => {
    const result = anthropicMessagesInbound.parse({
      model: 'claude-opus-4-6',
      max_tokens: 256,
      system: [
        { type: 'text', text: 'allowed' },
        { type: 'image', source: { type: 'url', url: 'https://example.com/system.png' } },
      ],
      messages: [{ role: 'user', content: 'hello' }],
    });

    expect(result.error).toEqual({
      statusCode: 400,
      payload: {
        error: {
          message: 'system prompt must be text',
          type: 'invalid_request_error',
        },
      },
    });
  });

  it('drops null-content turns instead of rejecting the whole Claude request', () => {
    const result = anthropicMessagesInbound.parse({
      model: 'claude-opus-4-6',
      max_tokens: 256,
      messages: [
        { role: 'user', content: 'hello' },
        { role: 'assistant', content: null },
      ],
    });

    expect(result.error).toBeUndefined();
    expect(result.value?.parsed.upstreamBody.messages).toEqual([
      { role: 'user', content: 'hello' },
    ]);
    expect(result.value?.parsed.claudeOriginalBody).toMatchObject({
      messages: [
        { role: 'user', content: 'hello' },
      ],
    });
  });

  it('preserves continuation hints for tool_result-only follow-up turns', () => {
    const result = anthropicMessagesInbound.parse({
      model: 'claude-opus-4-6',
      max_tokens: 256,
      previous_response_id: 'resp_prev_1',
      prompt_cache_key: 'cache-key-1',
      messages: [
        {
          role: 'user',
          content: [
            {
              type: 'tool_result',
              tool_use_id: 'toolu_missing',
              content: [{ type: 'text', text: '{"matches":1}' }],
            },
            { type: 'text', text: 'continue' },
          ],
        },
      ],
    });

    expect(result.error).toBeUndefined();
    expect(result.value?.parsed.upstreamBody).toMatchObject({
      previous_response_id: 'resp_prev_1',
      prompt_cache_key: 'cache-key-1',
      messages: [
        {
          role: 'tool',
          tool_call_id: 'toolu_missing',
          content: '{"matches":1}',
        },
        {
          role: 'user',
          content: 'continue',
        },
      ],
    });
  });

  it('normalizes adaptive effort and tool choice at the inbound boundary', () => {
    const result = anthropicMessagesInbound.parse({
      model: 'claude-opus-4-6',
      max_tokens: 512,
      thinking: { type: 'adaptive' },
      output_config: { effort: 'high', preserve: true },
      tool_choice: { type: 'tool', tool: { name: 'lookup' } },
      messages: [{ role: 'user', content: 'hello' }],
    });

    expect(result.error).toBeUndefined();
    expect(result.value).toMatchObject({
      protocol: 'anthropic/messages',
      model: 'claude-opus-4-6',
      stream: false,
    });
    expect(result.value?.parsed.claudeOriginalBody).toMatchObject({
      thinking: { type: 'adaptive' },
      output_config: { effort: 'high', preserve: true },
      tool_choice: { type: 'tool', name: 'lookup' },
    });
  });

  it('preserves already-native anthropic block shapes and cache markers', () => {
    const result = anthropicMessagesInbound.parse({
      model: 'claude-opus-4-6',
      max_tokens: 512,
      system: [
        { type: 'text', text: 'system prompt', cache_control: { type: 'ephemeral' } },
      ],
      tools: [
        {
          name: 'lookup',
          input_schema: { type: 'object' },
          cache_control: { type: 'ephemeral' },
        },
      ],
      messages: [
        {
          role: 'user',
          content: [
            { type: 'text', text: 'hello', cache_control: { type: 'ephemeral' } },
          ],
        },
      ],
      thinking: { type: 'adaptive' },
      output_config: { effort: 'high' },
      tool_choice: { type: 'tool', name: 'lookup' },
    });

    expect(result.error).toBeUndefined();
    expect(result.value?.parsed.claudeOriginalBody).toEqual({
      model: 'claude-opus-4-6',
      max_tokens: 512,
      system: [
        { type: 'text', text: 'system prompt', cache_control: { type: 'ephemeral' } },
      ],
      tools: [
        {
          name: 'lookup',
          input_schema: { type: 'object' },
          cache_control: { type: 'ephemeral' },
        },
      ],
      messages: [
        {
          role: 'user',
          content: [
            { type: 'text', text: 'hello', cache_control: { type: 'ephemeral' } },
          ],
        },
      ],
      thinking: { type: 'adaptive' },
      output_config: { effort: 'high' },
      tool_choice: { type: 'tool', name: 'lookup' },
    });
  });

  it('keeps native cache_control placement for already-native anthropic bodies', () => {
    const nativeBody = {
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

    const result = anthropicMessagesInbound.parse(nativeBody);

    expect(result.error).toBeUndefined();
    expect(result.value?.parsed.claudeOriginalBody).toEqual(nativeBody);
  });
});
