import { describe, expect, it } from 'vitest';

import { anthropicMessagesTransformer, serializeAnthropicFinalAsStream } from './index.js';

type SerializedAnthropicEvent = {
  event: string;
  payload: Record<string, any>;
};

function collectSerializedEvents(events: Array<Record<string, unknown>>): SerializedAnthropicEvent[] {
  const streamContext = anthropicMessagesTransformer.createStreamContext('claude-opus-4-6');
  const downstreamContext = anthropicMessagesTransformer.createDownstreamContext();
  const serialized = events
    .flatMap((event) => anthropicMessagesTransformer.serializeStreamEvent(event as any, streamContext, downstreamContext))
    .join('');

  return anthropicMessagesTransformer.pullSseEvents(serialized).events.map((item) => ({
    event: item.event,
    payload: JSON.parse(item.data),
  }));
}

describe('anthropicMessagesStream.serializeEvent', () => {
  it('buffers signature deltas until the active thinking block closes', () => {
    const events = collectSerializedEvents([
      {
        anthropic: {
          startBlock: {
            kind: 'thinking',
            index: 0,
          },
        },
      },
      {
        reasoningDelta: 'step-1',
      },
      {
        anthropic: {
          signatureDelta: 'sig-buffered-until-stop',
        },
      },
      {
        reasoningDelta: 'step-2',
      },
      {
        anthropic: {
          stopBlockIndex: 0,
        },
      },
    ]);

    expect(events.map((item) => ({
      type: item.payload.type,
      deltaType: item.payload.delta?.type,
      thinking: item.payload.delta?.thinking,
      signature: item.payload.delta?.signature,
    }))).toEqual([
      {
        type: 'message_start',
        deltaType: undefined,
        thinking: undefined,
        signature: undefined,
      },
      {
        type: 'content_block_start',
        deltaType: undefined,
        thinking: undefined,
        signature: undefined,
      },
      {
        type: 'content_block_delta',
        deltaType: 'thinking_delta',
        thinking: 'step-1',
        signature: undefined,
      },
      {
        type: 'content_block_delta',
        deltaType: 'thinking_delta',
        thinking: 'step-2',
        signature: undefined,
      },
      {
        type: 'content_block_delta',
        deltaType: 'signature_delta',
        thinking: undefined,
        signature: 'sig-buffered-until-stop',
      },
      {
        type: 'content_block_stop',
        deltaType: undefined,
        thinking: undefined,
        signature: undefined,
      },
    ]);
  });

  it('flushes a buffered signature when an explicit thinking block closes before redacted thinking', () => {
    const events = collectSerializedEvents([
      {
        anthropic: {
          startBlock: {
            kind: 'thinking',
            index: 0,
          },
        },
      },
      {
        anthropic: {
          signatureDelta: 'sig-buffered',
        },
      },
      {
        anthropic: {
          startBlock: {
            kind: 'redacted_thinking',
            index: 1,
          },
          redactedThinkingData: 'ciphertext',
        },
      },
    ]);

    expect(events.map((item) => item.payload.type)).toEqual([
      'message_start',
      'content_block_start',
      'content_block_delta',
      'content_block_stop',
      'content_block_start',
    ]);
    expect(events[1]?.payload.content_block).toEqual({
      type: 'thinking',
      thinking: '',
    });
    expect(events[2]?.payload.delta).toEqual({
      type: 'signature_delta',
      signature: 'sig-buffered',
    });
    expect(events[3]?.payload.index).toBe(0);
    expect(events[4]?.payload.content_block).toEqual({
      type: 'redacted_thinking',
      data: 'ciphertext',
    });
  });

  it('closes the previous tool_use block before starting the next one and keeps JSON increments on the same block', () => {
    const events = collectSerializedEvents([
      {
        toolCallDeltas: [{
          index: 0,
          id: 'call_1',
          name: 'lookup_city',
          argumentsDelta: '{"city":"par',
        }],
      },
      {
        toolCallDeltas: [{
          index: 0,
          argumentsDelta: 'is"}',
        }],
      },
      {
        toolCallDeltas: [{
          index: 1,
          id: 'call_2',
          name: 'lookup_weather',
          argumentsDelta: '{"days":2}',
        }],
      },
    ]);

    expect(events.map((item) => ({
      type: item.payload.type,
      index: item.payload.index,
      blockType: item.payload.content_block?.type,
      deltaType: item.payload.delta?.type,
      partialJson: item.payload.delta?.partial_json,
    }))).toEqual([
      {
        type: 'message_start',
        index: undefined,
        blockType: undefined,
        deltaType: undefined,
        partialJson: undefined,
      },
      {
        type: 'content_block_start',
        index: 0,
        blockType: 'tool_use',
        deltaType: undefined,
        partialJson: undefined,
      },
      {
        type: 'content_block_delta',
        index: 0,
        blockType: undefined,
        deltaType: 'input_json_delta',
        partialJson: '{"city":"par',
      },
      {
        type: 'content_block_delta',
        index: 0,
        blockType: undefined,
        deltaType: 'input_json_delta',
        partialJson: 'is"}',
      },
      {
        type: 'content_block_stop',
        index: 0,
        blockType: undefined,
        deltaType: undefined,
        partialJson: undefined,
      },
      {
        type: 'content_block_start',
        index: 1,
        blockType: 'tool_use',
        deltaType: undefined,
        partialJson: undefined,
      },
      {
        type: 'content_block_delta',
        index: 1,
        blockType: undefined,
        deltaType: 'input_json_delta',
        partialJson: '{"days":2}',
      },
    ]);
  });

  it('flushes a buffered signature on finish even when no thinking delta ever arrived', () => {
    const events = collectSerializedEvents([
      {
        anthropic: {
          signatureDelta: 'sig-finish-only',
        },
      },
      {
        finishReason: 'stop',
        done: true,
      },
    ]);

    expect(events.map((item) => item.payload.type)).toEqual([
      'message_start',
      'content_block_start',
      'content_block_delta',
      'content_block_stop',
      'message_delta',
      'message_stop',
    ]);
    expect(events[1]?.payload.content_block).toEqual({
      type: 'thinking',
      thinking: '',
    });
    expect(events[2]?.payload.delta).toEqual({
      type: 'signature_delta',
      signature: 'sig-finish-only',
    });
    expect(events[4]?.payload.delta).toEqual({
      stop_reason: 'end_turn',
      stop_sequence: null,
    });
  });

  it('keeps redacted_thinking open until an explicit stop arrives', () => {
    const streamContext = anthropicMessagesTransformer.createStreamContext('claude-opus-4-6');
    const downstreamContext = anthropicMessagesTransformer.createDownstreamContext();

    const startSerialized = anthropicMessagesTransformer.serializeStreamEvent({
      anthropic: {
        startBlock: {
          kind: 'redacted_thinking',
          index: 1,
        },
        redactedThinkingData: 'ciphertext',
      },
    } as any, streamContext, downstreamContext).join('');
    const stopSerialized = anthropicMessagesTransformer.serializeStreamEvent({
      anthropic: {
        stopBlockIndex: 1,
      },
    } as any, streamContext, downstreamContext).join('');

    const startEvents = anthropicMessagesTransformer.pullSseEvents(startSerialized).events.map((item) => ({
      event: item.event,
      payload: JSON.parse(item.data),
    }));
    const stopEvents = anthropicMessagesTransformer.pullSseEvents(stopSerialized).events.map((item) => ({
      event: item.event,
      payload: JSON.parse(item.data),
    }));

    expect(startEvents.map((item) => item.payload.type)).toEqual([
      'message_start',
      'content_block_start',
    ]);
    expect(startEvents[1]?.payload.content_block).toEqual({
      type: 'redacted_thinking',
      data: 'ciphertext',
    });
    expect(stopEvents.map((item) => item.payload.type)).toEqual([
      'content_block_stop',
    ]);
    expect(stopEvents[0]?.payload.index).toBe(1);
  });
});

describe('serializeAnthropicFinalAsStream', () => {
  it('emits thinking signature and tool_use blocks for normalized final payloads', () => {
    const streamContext = anthropicMessagesTransformer.createStreamContext('claude-opus-4-6');
    const downstreamContext = anthropicMessagesTransformer.createDownstreamContext();

    const serialized = serializeAnthropicFinalAsStream({
      id: 'resp_final_stream',
      model: 'claude-opus-4-6',
      created: 1700000000,
      content: '',
      reasoningContent: 'plan quietly',
      reasoningSignature: 'sig-final',
      finishReason: 'tool_calls',
      toolCalls: [{
        id: 'call_1',
        name: 'lookup_city',
        arguments: '{"city":"Paris"}',
      }],
    }, streamContext, downstreamContext).join('');

    const events = anthropicMessagesTransformer.pullSseEvents(serialized).events.map((item) => ({
      event: item.event,
      payload: JSON.parse(item.data),
    }));

    expect(events.some((item) =>
      item.payload.type === 'content_block_delta'
      && item.payload.delta?.type === 'signature_delta'
      && item.payload.delta?.signature === 'sig-final',
    )).toBe(true);
    expect(events.some((item) =>
      item.payload.type === 'content_block_start'
      && item.payload.content_block?.type === 'tool_use'
      && item.payload.content_block?.id === 'call_1'
      && item.payload.content_block?.name === 'lookup_city',
    )).toBe(true);
    expect(events.some((item) =>
      item.payload.type === 'content_block_delta'
      && item.payload.delta?.type === 'input_json_delta'
      && item.payload.delta?.partial_json === '{"city":"Paris"}',
    )).toBe(true);
  });

  it('preserves native anthropic block order and cleans tagged signatures when serializing fallback streams', () => {
    const streamContext = anthropicMessagesTransformer.createStreamContext('claude-opus-4-6');
    const downstreamContext = anthropicMessagesTransformer.createDownstreamContext();

    const serialized = serializeAnthropicFinalAsStream({
      id: 'resp_native_order_1',
      model: 'claude-opus-4-6',
      created: 1700000000,
      content: '',
      reasoningContent: '',
      finishReason: 'tool_calls',
      toolCalls: [],
      nativeContent: [
        {
          type: 'thinking',
          thinking: 'plan first',
          signature: 'metapi:anthropic-signature:sig-native',
        },
        {
          type: 'tool_use',
          id: 'toolu_lookup',
          name: 'lookup_city',
          input: { city: 'Paris' },
        },
        {
          type: 'text',
          text: 'done',
        },
      ],
    } as any, streamContext, downstreamContext).join('');

    const events = anthropicMessagesTransformer.pullSseEvents(serialized).events.map((item) => ({
      event: item.event,
      payload: JSON.parse(item.data),
    }));

    expect(events
      .filter((item) => item.payload.type === 'content_block_start')
      .map((item) => item.payload.content_block?.type)).toEqual([
      'thinking',
      'tool_use',
      'text',
    ]);
    expect(events.some((item) =>
      item.payload.type === 'content_block_delta'
      && item.payload.delta?.type === 'signature_delta'
      && item.payload.delta?.signature === 'sig-native',
    )).toBe(true);
    expect(events.some((item) =>
      item.payload.type === 'content_block_delta'
      && item.payload.delta?.type === 'input_json_delta'
      && item.payload.delta?.partial_json === '{"city":"Paris"}',
    )).toBe(true);
  });

  it('preserves redacted_thinking in generic normalized final fallback streams', () => {
    const streamContext = anthropicMessagesTransformer.createStreamContext('claude-opus-4-6');
    const downstreamContext = anthropicMessagesTransformer.createDownstreamContext();

    const serialized = serializeAnthropicFinalAsStream({
      id: 'resp_redacted_1',
      model: 'claude-opus-4-6',
      created: 1700000000,
      content: 'visible text',
      reasoningContent: 'plan quietly',
      reasoningSignature: 'metapi:anthropic-signature:sig-redacted',
      redactedReasoningContent: 'ciphertext',
      finishReason: 'stop',
      toolCalls: [],
    } as any, streamContext, downstreamContext).join('');

    const events = anthropicMessagesTransformer.pullSseEvents(serialized).events.map((item) => ({
      event: item.event,
      payload: JSON.parse(item.data),
    }));

    expect(events
      .filter((item) => item.payload.type === 'content_block_start')
      .map((item) => item.payload.content_block?.type)).toEqual([
      'thinking',
      'redacted_thinking',
      'text',
    ]);
    expect(events.some((item) =>
      item.payload.type === 'content_block_start'
      && item.payload.content_block?.type === 'redacted_thinking'
      && item.payload.content_block?.data === 'ciphertext',
    )).toBe(true);
    expect(events.some((item) =>
      item.payload.type === 'content_block_delta'
      && item.payload.delta?.type === 'signature_delta'
      && item.payload.delta?.signature === 'sig-redacted',
    )).toBe(true);
  });
});
