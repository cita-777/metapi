import { describe, expect, it } from 'vitest';

import type { NormalizedFinalResponse } from '../../shared/normalized.js';
import { anthropicMessagesOutbound } from './outbound.js';
import { anthropicMessagesUsage } from './usage.js';

const normalized: NormalizedFinalResponse = {
  id: 'chatcmpl-1',
  model: 'claude-test',
  created: 456,
  content: 'done',
  reasoningContent: '',
  finishReason: 'stop',
  toolCalls: [],
};

describe('anthropicMessagesOutbound.serializeFinal', () => {
  it('round-trips native anthropic thinking/tool/text block order and signature', () => {
    const payload = {
      id: 'msg_native-1',
      type: 'message',
      role: 'assistant',
      model: 'claude-test',
      content: [
        {
          type: 'thinking',
          thinking: 'plan first',
          signature: 'sig-native',
        },
        {
          type: 'tool_use',
          id: 'toolu_lookup',
          name: 'lookup_weather',
          input: { city: 'Paris' },
        },
        {
          type: 'text',
          text: 'done',
        },
      ],
      stop_reason: 'tool_use',
      stop_sequence: null,
      usage: {
        input_tokens: 100,
        output_tokens: 30,
        cache_read_input_tokens: 12,
        cache_creation_input_tokens: 8,
        cache_creation: {
          ephemeral_5m_input_tokens: 5,
          ephemeral_1h_input_tokens: 3,
        },
      },
    };

    const normalized = anthropicMessagesOutbound.normalizeFinal(payload, 'claude-test');

    expect(anthropicMessagesOutbound.serializeFinal(
      normalized,
      anthropicMessagesUsage.fromPayload(payload),
    )).toEqual({
      id: 'msg_native-1',
      type: 'message',
      role: 'assistant',
      model: 'claude-test',
      content: [
        {
          type: 'thinking',
          thinking: 'plan first',
          signature: 'sig-native',
        },
        {
          type: 'tool_use',
          id: 'toolu_lookup',
          name: 'lookup_weather',
          input: { city: 'Paris' },
        },
        {
          type: 'text',
          text: 'done',
        },
      ],
      stop_reason: 'tool_use',
      stop_sequence: null,
      usage: {
        input_tokens: 100,
        output_tokens: 30,
        cache_read_input_tokens: 12,
        cache_creation_input_tokens: 8,
        cache_creation: {
          ephemeral_5m_input_tokens: 5,
          ephemeral_1h_input_tokens: 3,
        },
      },
    });
  });

  it('preserves anthropic cache read and cache creation semantics from parsed usage', () => {
    expect(anthropicMessagesOutbound.serializeFinal(normalized, {
      promptTokens: 100,
      completionTokens: 30,
      totalTokens: 150,
      cacheReadTokens: 12,
      cacheCreationTokens: 8,
      promptTokensIncludeCache: false,
    })).toEqual({
      id: 'msg_chatcmpl-1',
      type: 'message',
      role: 'assistant',
      model: 'claude-test',
      content: [{ type: 'text', text: 'done' }],
      stop_reason: 'end_turn',
      stop_sequence: null,
      usage: {
        input_tokens: 100,
        output_tokens: 30,
        cache_read_input_tokens: 12,
        cache_creation_input_tokens: 8,
      },
    });
  });

  it('emits cache_creation breakdown when detailed anthropic usage fields are available', () => {
    expect(anthropicMessagesOutbound.serializeFinal(normalized, {
      promptTokens: 100,
      completionTokens: 30,
      totalTokens: 150,
      cacheReadInputTokens: 12,
      cacheCreationInputTokens: 8,
      ephemeral5mInputTokens: 5,
      ephemeral1hInputTokens: 3,
      promptTokensIncludingCache: 120,
    })).toEqual({
      id: 'msg_chatcmpl-1',
      type: 'message',
      role: 'assistant',
      model: 'claude-test',
      content: [{ type: 'text', text: 'done' }],
      stop_reason: 'end_turn',
      stop_sequence: null,
      usage: {
        input_tokens: 100,
        output_tokens: 30,
        cache_read_input_tokens: 12,
        cache_creation_input_tokens: 8,
        cache_creation: {
          ephemeral_5m_input_tokens: 5,
          ephemeral_1h_input_tokens: 3,
        },
      },
    });
  });

  it('cleans tagged signatures and preserves redacted_thinking for generic normalized finals', () => {
    const payload = anthropicMessagesOutbound.serializeFinal({
      id: 'chatcmpl-redacted-1',
      model: 'claude-test',
      created: 456,
      content: 'visible text',
      reasoningContent: 'plan quietly',
      reasoningSignature: 'metapi:anthropic-signature:sig-clean',
      redactedReasoningContent: 'ciphertext',
      finishReason: 'stop',
      toolCalls: [],
    } as any, {
      promptTokens: 9,
      completionTokens: 3,
      totalTokens: 12,
    });

    expect(payload.content).toEqual([
      {
        type: 'thinking',
        thinking: 'plan quietly',
        signature: 'sig-clean',
      },
      {
        type: 'redacted_thinking',
        data: 'ciphertext',
      },
      {
        type: 'text',
        text: 'visible text',
      },
    ]);
  });

  it('cleans tagged native thinking signatures while preserving native anthropic block order', () => {
    const sourcePayload = {
      id: 'msg_native-tagged-1',
      type: 'message',
      role: 'assistant',
      model: 'claude-test',
      content: [
        {
          type: 'thinking',
          thinking: 'plan first',
          signature: 'metapi:anthropic-signature:sig-native',
        },
        {
          type: 'tool_use',
          id: 'toolu_lookup',
          name: 'lookup_weather',
          input: { city: 'Paris' },
        },
        {
          type: 'text',
          text: 'done',
        },
      ],
      stop_reason: 'tool_use',
      stop_sequence: null,
      usage: {
        input_tokens: 100,
        output_tokens: 30,
      },
    };

    const normalized = anthropicMessagesOutbound.normalizeFinal(sourcePayload, 'claude-test');
    const payload = anthropicMessagesOutbound.serializeFinal(
      normalized,
      anthropicMessagesUsage.fromPayload(sourcePayload),
    );

    expect(payload.content).toEqual([
      {
        type: 'thinking',
        thinking: 'plan first',
        signature: 'sig-native',
      },
      {
        type: 'tool_use',
        id: 'toolu_lookup',
        name: 'lookup_weather',
        input: { city: 'Paris' },
      },
      {
        type: 'text',
        text: 'done',
      },
    ]);
  });
});
