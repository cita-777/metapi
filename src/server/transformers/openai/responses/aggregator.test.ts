import { describe, expect, it } from 'vitest';

import { createStreamTransformContext } from '../../shared/normalized.js';
import {
  completeResponsesStream,
  createOpenAiResponsesAggregateState,
  failResponsesStream,
  serializeConvertedResponsesEvents,
} from './aggregator.js';

function parseSsePayloads(lines: string[]): Array<Record<string, unknown>> {
  return lines
    .flatMap((line) => line.split('\n\n').filter((block) => block.trim().length > 0))
    .map((block) => {
      const dataLine = block
        .split('\n')
        .find((line) => line.startsWith('data: '));
      if (!dataLine) return null;
      try {
        return JSON.parse(dataLine.slice('data: '.length)) as Record<string, unknown>;
      } catch {
        return null;
      }
    })
    .filter((item): item is Record<string, unknown> => !!item);
}

function parseSseEvents(lines: string[]): Array<{ event: string | null; payload: Record<string, unknown> | '[DONE]' }> {
  return lines
    .flatMap((line) => line.split('\n\n').filter((block) => block.trim().length > 0))
    .map((block) => {
      const eventLine = block
        .split('\n')
        .find((line) => line.startsWith('event: '));
      const dataLine = block
        .split('\n')
        .find((line) => line.startsWith('data: '));
      if (!dataLine) return null;
      if (dataLine === 'data: [DONE]') {
        return {
          event: eventLine ? eventLine.slice('event: '.length) : null,
          payload: '[DONE]' as const,
        };
      }
      try {
        return {
          event: eventLine ? eventLine.slice('event: '.length) : null,
          payload: JSON.parse(dataLine.slice('data: '.length)) as Record<string, unknown>,
        };
      } catch {
        return null;
      }
    })
    .filter((item): item is { event: string | null; payload: Record<string, unknown> | '[DONE]' } => !!item);
}

describe('serializeConvertedResponsesEvents', () => {
  it('aggregates reasoning summary events into the completed response payload', () => {
    const state = createOpenAiResponsesAggregateState('gpt-5');
    const streamContext = createStreamTransformContext('gpt-5');
    const usage = {
      promptTokens: 1,
      completionTokens: 2,
      totalTokens: 3,
    };

    serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        responsesEventType: 'response.reasoning_summary_part.added',
        responsesPayload: {
          type: 'response.reasoning_summary_part.added',
          item_id: 'rs_1',
          output_index: 0,
          summary_index: 0,
          part: {
            type: 'summary_text',
            text: '',
          },
        },
      },
    });

    serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        responsesEventType: 'response.reasoning_summary_text.delta',
        responsesPayload: {
          type: 'response.reasoning_summary_text.delta',
          item_id: 'rs_1',
          output_index: 0,
          summary_index: 0,
          delta: 'Think ',
        },
      },
    });

    const completedLines = serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        responsesEventType: 'response.completed',
        responsesPayload: {
          type: 'response.completed',
          response: {
            id: 'resp_1',
            model: 'gpt-5',
            usage: {
              input_tokens: 1,
              output_tokens: 2,
              total_tokens: 3,
            },
          },
        },
      },
    });

    const payloads = parseSsePayloads(completedLines);
    const completed = payloads.find((item) => item.type === 'response.completed');
    expect(completed).toBeTruthy();
    expect(completed?.response).toMatchObject({
      id: 'resp_1',
      output: [
        {
          id: 'rs_1',
          type: 'reasoning',
          summary: [
            {
              type: 'summary_text',
              text: 'Think ',
            },
          ],
        },
      ],
    });
  });

  it('keeps encrypted-only reasoning output items during stream aggregation', () => {
    const state = createOpenAiResponsesAggregateState('gpt-5');
    const streamContext = createStreamTransformContext('gpt-5');
    const usage = {
      promptTokens: 1,
      completionTokens: 2,
      totalTokens: 3,
    };

    serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        responsesEventType: 'response.output_item.added',
        responsesPayload: {
          type: 'response.output_item.added',
          output_index: 0,
          item: {
            type: 'reasoning',
            encrypted_content: 'enc-only',
          },
        },
      },
    });

    const completedLines = serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        responsesEventType: 'response.completed',
        responsesPayload: {
          type: 'response.completed',
          response: {
            id: 'resp_enc_only',
            model: 'gpt-5',
            usage: {
              input_tokens: 1,
              output_tokens: 2,
              total_tokens: 3,
            },
          },
        },
      },
    });

    const payloads = parseSsePayloads(completedLines);
    const completed = payloads.find((item) => item.type === 'response.completed');
    expect(completed).toBeTruthy();
    expect(completed?.response?.output?.[0]).toMatchObject({
      type: 'reasoning',
      encrypted_content: 'enc-only',
    });
    expect((completed?.response?.output?.[0] as any)?.id).toMatch(/^rs_/);
  });

  it('starts a synthetic reasoning item when fallback streams only carry encrypted reasoning signatures', () => {
    const state = createOpenAiResponsesAggregateState('gpt-5');
    const streamContext = createStreamTransformContext('gpt-5');
    const usage = {
      promptTokens: 1,
      completionTokens: 2,
      totalTokens: 3,
    };

    const signatureLines = serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        reasoningSignature: 'enc-stream-only',
      } as any,
    });

    const signaturePayloads = parseSsePayloads(signatureLines);
    expect(signaturePayloads).toEqual([
      {
        type: 'response.output_item.added',
        output_index: 0,
        item: {
          id: 'rs_0',
          type: 'reasoning',
          status: 'in_progress',
          summary: [],
          encrypted_content: 'enc-stream-only',
        },
      },
    ]);

    const completedLines = serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        responsesEventType: 'response.completed',
        responsesPayload: {
          type: 'response.completed',
          response: {
            id: 'resp_enc_stream_only',
            model: 'gpt-5',
            usage: {
              input_tokens: 1,
              output_tokens: 2,
              total_tokens: 3,
            },
          },
        },
      },
    });

    const payloads = parseSsePayloads(completedLines);
    const completed = payloads.find((item) => item.type === 'response.completed');
    expect(completed?.response?.output).toEqual([
      {
        id: 'rs_0',
        type: 'reasoning',
        status: 'completed',
        summary: [],
        encrypted_content: 'enc-stream-only',
      },
    ]);
  });

  it('emits response.output_item.added before synthetic reasoning summary events for delta-only reasoning streams', () => {
    const state = createOpenAiResponsesAggregateState('gpt-5');
    const streamContext = createStreamTransformContext('gpt-5');
    const usage = {
      promptTokens: 1,
      completionTokens: 2,
      totalTokens: 3,
    };

    const lines = serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        reasoningDelta: 'Think ',
      } as any,
    });

    const events = parseSseEvents(lines);

    expect(events.map((entry) => entry.event)).toEqual([
      'response.output_item.added',
      'response.reasoning_summary_part.added',
      'response.reasoning_summary_text.delta',
    ]);
    expect(events[0]?.payload).toMatchObject({
      type: 'response.output_item.added',
      output_index: 0,
      item: {
        id: 'rs_0',
        type: 'reasoning',
        status: 'in_progress',
        summary: [],
      },
    });
    expect(events[1]?.payload).toMatchObject({
      type: 'response.reasoning_summary_part.added',
      item_id: 'rs_0',
      output_index: 0,
      summary_index: 0,
      part: {
        type: 'summary_text',
        text: '',
      },
    });
    expect(events[2]?.payload).toMatchObject({
      type: 'response.reasoning_summary_text.delta',
      item_id: 'rs_0',
      output_index: 0,
      summary_index: 0,
      delta: 'Think ',
    });
  });

  it('keeps synthetic reasoning and message output items separate when reasoning arrives before content', () => {
    const state = createOpenAiResponsesAggregateState('gpt-5');
    const streamContext = createStreamTransformContext('gpt-5');
    const usage = {
      promptTokens: 1,
      completionTokens: 2,
      totalTokens: 3,
    };

    serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        reasoningDelta: 'plan first',
      } as any,
    });

    const contentLines = serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        contentDelta: 'final answer',
      } as any,
    });

    const contentEvents = parseSseEvents(contentLines);
    expect(contentEvents.map((entry) => entry.event)).toEqual([
      'response.output_item.added',
      'response.content_part.added',
      'response.output_text.delta',
    ]);
    expect(contentEvents[0]?.payload).toMatchObject({
      type: 'response.output_item.added',
      output_index: 1,
      item: {
        id: 'msg_1',
        type: 'message',
        content: [],
      },
    });

    const completedLines = completeResponsesStream(state, streamContext, usage);
    const payloads = parseSsePayloads(completedLines);
    const completed = payloads.find((item) => item.type === 'response.completed');
    expect(completed?.response?.output).toEqual([
      {
        id: 'rs_0',
        type: 'reasoning',
        status: 'completed',
        summary: [
          {
            type: 'summary_text',
            text: 'plan first',
          },
        ],
      },
      {
        id: 'msg_1',
        type: 'message',
        role: 'assistant',
        status: 'completed',
        content: [
          {
            type: 'output_text',
            text: 'final answer',
          },
        ],
      },
    ]);
    expect(completed?.response?.output_text).toBe('final answer');
  });

  it('keeps synthetic message and function call items separate when one event contains both', () => {
    const state = createOpenAiResponsesAggregateState('gpt-5');
    const streamContext = createStreamTransformContext('gpt-5');
    const usage = {
      promptTokens: 1,
      completionTokens: 2,
      totalTokens: 3,
    };

    const lines = serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        contentDelta: 'hello',
        toolCallDeltas: [{
          index: 0,
          id: 'call_1',
          name: 'Glob',
          argumentsDelta: '{}',
        }],
      } as any,
    });

    const events = parseSseEvents(lines);
    expect(events.map((entry) => entry.event)).toEqual([
      'response.output_item.added',
      'response.content_part.added',
      'response.output_text.delta',
      'response.output_item.added',
      'response.function_call_arguments.delta',
    ]);
    expect(events[3]?.payload).toMatchObject({
      type: 'response.output_item.added',
      output_index: 1,
      item: {
        id: 'call_1',
        type: 'function_call',
        call_id: 'call_1',
        name: 'Glob',
        arguments: '',
      },
    });

    const completedLines = completeResponsesStream(state, streamContext, usage);
    const payloads = parseSsePayloads(completedLines);
    const completed = payloads.find((item) => item.type === 'response.completed');
    expect(completed?.response?.output).toEqual([
      {
        id: 'msg_0',
        type: 'message',
        role: 'assistant',
        status: 'completed',
        content: [
          {
            type: 'output_text',
            text: 'hello',
          },
        ],
      },
      {
        id: 'call_1',
        type: 'function_call',
        status: 'completed',
        call_id: 'call_1',
        name: 'Glob',
        arguments: '{}',
      },
    ]);
  });

  it('backfills missing parent events before sparse native function call argument deltas', () => {
    const state = createOpenAiResponsesAggregateState('gpt-5');
    const streamContext = createStreamTransformContext('gpt-5');
    const usage = {
      promptTokens: 1,
      completionTokens: 2,
      totalTokens: 3,
    };

    const lines = serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        responsesEventType: 'response.function_call_arguments.delta',
        responsesPayload: {
          type: 'response.function_call_arguments.delta',
          output_index: 0,
          call_id: 'call_sparse',
          name: 'lookup',
          delta: '{"q":"x"}',
        },
      },
    });

    const events = parseSseEvents(lines);
    expect(events.map((entry) => entry.event)).toEqual([
      'response.output_item.added',
      'response.function_call_arguments.delta',
    ]);
    expect(events[0]?.payload).toMatchObject({
      type: 'response.output_item.added',
      output_index: 0,
      item: {
        type: 'function_call',
        call_id: 'call_sparse',
        name: 'lookup',
      },
    });
  });

  it('preserves richer image_generation_call fields while aggregating progress events', () => {
    const state = createOpenAiResponsesAggregateState('gpt-5');
    const streamContext = createStreamTransformContext('gpt-5');
    const usage = {
      promptTokens: 1,
      completionTokens: 2,
      totalTokens: 3,
    };

    serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        responsesEventType: 'response.image_generation_call.partial_image',
        responsesPayload: {
          type: 'response.image_generation_call.partial_image',
          item_id: 'img_1',
          output_index: 0,
          partial_image_index: 0,
          partial_image_b64: 'partial',
          background: 'transparent',
          output_format: 'png',
          quality: 'high',
          size: '1024x1024',
        },
      },
    });

    const completedLines = serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        responsesEventType: 'response.image_generation_call.completed',
        responsesPayload: {
          type: 'response.image_generation_call.completed',
          item_id: 'img_1',
          output_index: 0,
          result: 'final-image',
          background: 'transparent',
          output_format: 'png',
          quality: 'high',
          size: '1024x1024',
        },
      },
    });

    const payloads = parseSsePayloads(completedLines);
    const imageEvent = payloads.find((item) => item.type === 'response.image_generation_call.completed');
    expect(imageEvent).toBeTruthy();
    expect(state.outputItems[0]).toMatchObject({
      id: 'img_1',
      type: 'image_generation_call',
      status: 'completed',
      result: 'final-image',
      background: 'transparent',
      output_format: 'png',
      quality: 'high',
      size: '1024x1024',
      partial_images: [
        {
          partial_image_index: 0,
          partial_image_b64: 'partial',
        },
      ],
    });
  });

  it('emits response.output_item.done after native image generation completion', () => {
    const state = createOpenAiResponsesAggregateState('gpt-5');
    const streamContext = createStreamTransformContext('gpt-5');
    const usage = {
      promptTokens: 1,
      completionTokens: 2,
      totalTokens: 3,
    };

    serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        responsesEventType: 'response.image_generation_call.completed',
        responsesPayload: {
          type: 'response.image_generation_call.completed',
          item_id: 'img_done_1',
          output_index: 0,
          result: 'image-final',
        },
      },
    });

    const lines = serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        responsesEventType: 'response.completed',
        responsesPayload: {
          type: 'response.completed',
          response: {
            id: 'resp_image_done',
            model: 'gpt-5',
            usage: {
              input_tokens: 1,
              output_tokens: 2,
              total_tokens: 3,
            },
          },
        },
      },
    });

    const events = parseSseEvents(lines);
    expect(events.map((entry) => entry.event)).toEqual([
      'response.output_item.done',
      'response.completed',
    ]);
  });

  it('backfills native parent lifecycle events before forwarding sparse function call argument deltas', () => {
    const state = createOpenAiResponsesAggregateState('gpt-5');
    const streamContext = createStreamTransformContext('gpt-5');
    const usage = {
      promptTokens: 1,
      completionTokens: 2,
      totalTokens: 3,
    };

    const lines = serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        responsesEventType: 'response.function_call_arguments.delta',
        responsesPayload: {
          type: 'response.function_call_arguments.delta',
          output_index: 0,
          call_id: 'call_sparse_1',
          name: 'Glob',
          delta: '{}',
        },
      },
    });

    const events = parseSseEvents(lines);
    expect(events.map((entry) => entry.event)).toEqual([
      'response.output_item.added',
      'response.function_call_arguments.delta',
    ]);
    expect(events[0]?.payload).toMatchObject({
      type: 'response.output_item.added',
      output_index: 0,
      item: {
        id: 'call_sparse_1',
        type: 'function_call',
        call_id: 'call_sparse_1',
        name: 'Glob',
        arguments: '',
      },
    });
  });

  it('backfills native content part openers before forwarding sparse output_text.done events', () => {
    const state = createOpenAiResponsesAggregateState('gpt-5');
    const streamContext = createStreamTransformContext('gpt-5');
    const usage = {
      promptTokens: 1,
      completionTokens: 2,
      totalTokens: 3,
    };

    const lines = serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        responsesEventType: 'response.output_text.done',
        responsesPayload: {
          type: 'response.output_text.done',
          output_index: 0,
          item_id: 'msg_sparse_1',
          text: 'hello world',
        },
      },
    });

    const events = parseSseEvents(lines);
    expect(events.map((entry) => entry.event)).toEqual([
      'response.output_item.added',
      'response.content_part.added',
      'response.output_text.done',
    ]);
    expect(events[0]?.payload).toMatchObject({
      type: 'response.output_item.added',
      output_index: 0,
      item: {
        id: 'msg_sparse_1',
        type: 'message',
      },
    });
    expect(events[1]?.payload).toMatchObject({
      type: 'response.content_part.added',
      output_index: 0,
      item_id: 'msg_sparse_1',
      content_index: 0,
      part: {
        type: 'output_text',
        text: '',
      },
    });
    expect(events[2]?.payload).toMatchObject({
      type: 'response.output_text.done',
      output_index: 0,
      item_id: 'msg_sparse_1',
      text: 'hello world',
    });
  });

  it('preserves native message item ids when sparse content parts open the parent item', () => {
    const state = createOpenAiResponsesAggregateState('gpt-5');
    const streamContext = createStreamTransformContext('gpt-5');
    const usage = {
      promptTokens: 1,
      completionTokens: 2,
      totalTokens: 3,
    };

    const lines = serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        responsesEventType: 'response.content_part.added',
        responsesPayload: {
          type: 'response.content_part.added',
          output_index: 0,
          item_id: 'msg_sparse_content_1',
          content_index: 0,
          part: {
            type: 'output_text',
            text: '',
          },
        },
      },
    });

    const events = parseSseEvents(lines);
    expect(events.map((entry) => entry.event)).toEqual([
      'response.output_item.added',
      'response.content_part.added',
    ]);
    expect(events[0]?.payload).toMatchObject({
      type: 'response.output_item.added',
      output_index: 0,
      item: {
        id: 'msg_sparse_content_1',
        type: 'message',
      },
    });
    expect(events[1]?.payload).toMatchObject({
      type: 'response.content_part.added',
      output_index: 0,
      item_id: 'msg_sparse_content_1',
      content_index: 0,
      part: {
        type: 'output_text',
        text: '',
      },
    });
  });

  it('emits canonical message done events before response.completed when recovering a sparse text stream', () => {
    const state = createOpenAiResponsesAggregateState('gpt-5');
    const streamContext = createStreamTransformContext('gpt-5');
    const usage = {
      promptTokens: 2,
      completionTokens: 4,
      totalTokens: 6,
    };

    serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        contentDelta: 'hello world',
      } as any,
    });

    const completionLines = completeResponsesStream(state, streamContext, usage);
    const events = parseSseEvents(completionLines);

    expect(events.map((entry) => entry.event ?? (entry.payload === '[DONE]' ? '[DONE]' : 'data'))).toEqual([
      'response.output_text.done',
      'response.content_part.done',
      'response.output_item.done',
      'response.completed',
      '[DONE]',
    ]);

    expect(events[0]?.payload).toMatchObject({
      type: 'response.output_text.done',
      output_index: 0,
      item_id: 'msg_0',
      text: 'hello world',
    });
    expect(events[1]?.payload).toMatchObject({
      type: 'response.content_part.done',
      output_index: 0,
      item_id: 'msg_0',
      content_index: 0,
      part: {
        type: 'output_text',
        text: 'hello world',
      },
    });
    expect(events[2]?.payload).toMatchObject({
      type: 'response.output_item.done',
      output_index: 0,
      item: {
        id: 'msg_0',
        type: 'message',
        status: 'completed',
      },
    });
  });

  it('emits terminal done events before relaying an upstream response.completed event', () => {
    const state = createOpenAiResponsesAggregateState('gpt-5');
    const streamContext = createStreamTransformContext('gpt-5');
    const usage = {
      promptTokens: 2,
      completionTokens: 4,
      totalTokens: 6,
    };

    serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        contentDelta: 'hello world',
      } as any,
    });

    const completionLines = serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        responsesEventType: 'response.completed',
        responsesPayload: {
          type: 'response.completed',
          response: {
            id: 'resp_done_1',
            model: 'gpt-5',
            usage: {
              input_tokens: 2,
              output_tokens: 4,
              total_tokens: 6,
            },
          },
        },
      },
    });

    const events = parseSseEvents(completionLines);
    expect(events.map((entry) => entry.event ?? 'data')).toEqual([
      'response.output_text.done',
      'response.content_part.done',
      'response.output_item.done',
      'response.completed',
    ]);
  });

  it('emits canonical reasoning done events before response.completed when recovering sparse reasoning output', () => {
    const state = createOpenAiResponsesAggregateState('gpt-5');
    const streamContext = createStreamTransformContext('gpt-5');
    const usage = {
      promptTokens: 2,
      completionTokens: 4,
      totalTokens: 6,
    };

    serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        reasoningSignature: 'enc-signature',
        reasoningDelta: 'plan first',
      } as any,
    });

    const completionLines = completeResponsesStream(state, streamContext, usage);
    const events = parseSseEvents(completionLines);

    expect(events.map((entry) => entry.event ?? (entry.payload === '[DONE]' ? '[DONE]' : 'data'))).toEqual([
      'response.reasoning_summary_text.done',
      'response.reasoning_summary_part.done',
      'response.output_item.done',
      'response.completed',
      '[DONE]',
    ]);

    expect(events[0]?.payload).toMatchObject({
      type: 'response.reasoning_summary_text.done',
      item_id: 'rs_0',
      output_index: 0,
      summary_index: 0,
      text: 'plan first',
    });
    expect(events[1]?.payload).toMatchObject({
      type: 'response.reasoning_summary_part.done',
      item_id: 'rs_0',
      output_index: 0,
      summary_index: 0,
      part: {
        type: 'summary_text',
        text: 'plan first',
      },
    });
    expect(events[2]?.payload).toMatchObject({
      type: 'response.output_item.done',
      output_index: 0,
      item: {
        id: 'rs_0',
        type: 'reasoning',
        status: 'completed',
        encrypted_content: 'enc-signature',
      },
    });
  });

  it('emits canonical message done events before response.failed when failing a sparse text stream', () => {
    const state = createOpenAiResponsesAggregateState('gpt-5');
    const streamContext = createStreamTransformContext('gpt-5');
    const usage = {
      promptTokens: 2,
      completionTokens: 4,
      totalTokens: 6,
    };

    serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        contentDelta: 'partial answer',
      } as any,
    });

    const failedLines = failResponsesStream(state, streamContext, usage, {
      error: {
        message: 'upstream stream failed',
      },
    });
    const events = parseSseEvents(failedLines);

    expect(events.map((entry) => entry.event ?? (entry.payload === '[DONE]' ? '[DONE]' : 'data'))).toEqual([
      'response.output_text.done',
      'response.content_part.done',
      'response.output_item.done',
      'response.failed',
      '[DONE]',
    ]);

    expect(events[2]?.payload).toMatchObject({
      type: 'response.output_item.done',
      output_index: 0,
      item: {
        id: 'msg_0',
        type: 'message',
        status: 'failed',
      },
    });
    expect(events[3]?.payload).toMatchObject({
      type: 'response.failed',
      response: {
        status: 'failed',
        output_text: 'partial answer',
      },
      error: {
        message: 'upstream stream failed',
        type: 'upstream_error',
      },
    });
  });

  it('does not synthesize duplicate message done events after original text completion already arrived', () => {
    const state = createOpenAiResponsesAggregateState('gpt-5');
    const streamContext = createStreamTransformContext('gpt-5');
    const usage = {
      promptTokens: 2,
      completionTokens: 4,
      totalTokens: 6,
    };

    serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        responsesEventType: 'response.output_item.added',
        responsesPayload: {
          type: 'response.output_item.added',
          output_index: 0,
          item: {
            id: 'msg_1',
            type: 'message',
            role: 'assistant',
            status: 'in_progress',
            content: [],
          },
        },
      },
    });

    serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        responsesEventType: 'response.content_part.added',
        responsesPayload: {
          type: 'response.content_part.added',
          output_index: 0,
          item_id: 'msg_1',
          content_index: 0,
          part: {
            type: 'output_text',
            text: '',
          },
        },
      },
    });

    serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        responsesEventType: 'response.output_text.delta',
        responsesPayload: {
          type: 'response.output_text.delta',
          output_index: 0,
          item_id: 'msg_1',
          delta: 'hello ',
        },
      },
    });

    serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        responsesEventType: 'response.output_text.done',
        responsesPayload: {
          type: 'response.output_text.done',
          output_index: 0,
          item_id: 'msg_1',
          text: 'hello world',
        },
      },
    });

    serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        responsesEventType: 'response.content_part.done',
        responsesPayload: {
          type: 'response.content_part.done',
          output_index: 0,
          item_id: 'msg_1',
          content_index: 0,
          part: {
            type: 'output_text',
            text: 'hello world',
          },
        },
      },
    });

    const completionLines = completeResponsesStream(state, streamContext, usage);
    const events = parseSseEvents(completionLines);

    expect(events.map((entry) => entry.event ?? (entry.payload === '[DONE]' ? '[DONE]' : 'data'))).toEqual([
      'response.output_item.done',
      'response.completed',
      '[DONE]',
    ]);

    expect(events[0]?.payload).toMatchObject({
      type: 'response.output_item.done',
      output_index: 0,
      item: {
        id: 'msg_1',
        type: 'message',
        status: 'completed',
      },
    });
    expect(events[1]?.payload).toMatchObject({
      type: 'response.completed',
      response: {
        status: 'completed',
        output_text: 'hello world',
      },
    });
  });

  it('backfills missing native content_part.done even after output_item.done already marks the message completed', () => {
    const state = createOpenAiResponsesAggregateState('gpt-5');
    const streamContext = createStreamTransformContext('gpt-5');
    const usage = {
      promptTokens: 2,
      completionTokens: 4,
      totalTokens: 6,
    };

    serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        responsesEventType: 'response.content_part.added',
        responsesPayload: {
          type: 'response.content_part.added',
          output_index: 0,
          item_id: 'msg_native_done_1',
          content_index: 0,
          part: {
            type: 'output_text',
            text: '',
          },
        },
      },
    });

    serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        responsesEventType: 'response.output_text.done',
        responsesPayload: {
          type: 'response.output_text.done',
          output_index: 0,
          item_id: 'msg_native_done_1',
          text: 'hello world',
        },
      },
    });

    serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        responsesEventType: 'response.output_item.done',
        responsesPayload: {
          type: 'response.output_item.done',
          output_index: 0,
          item: {
            id: 'msg_native_done_1',
            type: 'message',
            status: 'completed',
          },
        },
      },
    });

    const lines = serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        responsesEventType: 'response.completed',
        responsesPayload: {
          type: 'response.completed',
          response: {
            id: 'resp_native_done_1',
            model: 'gpt-5',
            usage: {
              input_tokens: 2,
              output_tokens: 4,
              total_tokens: 6,
            },
          },
        },
      },
    });

    const events = parseSseEvents(lines);
    expect(events.map((entry) => entry.event)).toEqual([
      'response.completed',
    ]);
  });

  it('does not synthesize duplicate reasoning done events after original reasoning completion already arrived', () => {
    const state = createOpenAiResponsesAggregateState('gpt-5');
    const streamContext = createStreamTransformContext('gpt-5');
    const usage = {
      promptTokens: 2,
      completionTokens: 4,
      totalTokens: 6,
    };

    serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        responsesEventType: 'response.output_item.added',
        responsesPayload: {
          type: 'response.output_item.added',
          output_index: 0,
          item: {
            id: 'rs_1',
            type: 'reasoning',
            status: 'in_progress',
            summary: [],
          },
        },
      },
    });

    serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        responsesEventType: 'response.reasoning_summary_part.added',
        responsesPayload: {
          type: 'response.reasoning_summary_part.added',
          item_id: 'rs_1',
          output_index: 0,
          summary_index: 0,
          part: {
            type: 'summary_text',
            text: '',
          },
        },
      },
    });

    serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        responsesEventType: 'response.reasoning_summary_text.delta',
        responsesPayload: {
          type: 'response.reasoning_summary_text.delta',
          item_id: 'rs_1',
          output_index: 0,
          summary_index: 0,
          delta: 'plan ',
        },
      },
    });

    serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        responsesEventType: 'response.reasoning_summary_text.done',
        responsesPayload: {
          type: 'response.reasoning_summary_text.done',
          item_id: 'rs_1',
          output_index: 0,
          summary_index: 0,
          text: 'plan first',
        },
      },
    });

    serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        responsesEventType: 'response.reasoning_summary_part.done',
        responsesPayload: {
          type: 'response.reasoning_summary_part.done',
          item_id: 'rs_1',
          output_index: 0,
          summary_index: 0,
          part: {
            type: 'summary_text',
            text: 'plan first',
          },
        },
      },
    });

    const completionLines = completeResponsesStream(state, streamContext, usage);
    const events = parseSseEvents(completionLines);

    expect(events.map((entry) => entry.event ?? (entry.payload === '[DONE]' ? '[DONE]' : 'data'))).toEqual([
      'response.output_item.done',
      'response.completed',
      '[DONE]',
    ]);

    expect(events[0]?.payload).toMatchObject({
      type: 'response.output_item.done',
      output_index: 0,
      item: {
        id: 'rs_1',
        type: 'reasoning',
        status: 'completed',
      },
    });
    expect(events[1]?.payload).toMatchObject({
      type: 'response.completed',
      response: {
        status: 'completed',
        output: [
          {
            id: 'rs_1',
            type: 'reasoning',
            status: 'completed',
            summary: [
              {
                type: 'summary_text',
                text: 'plan first',
              },
            ],
          },
        ],
      },
    });
  });

  it('emits terminal done events before forwarding an upstream response.completed event', () => {
    const state = createOpenAiResponsesAggregateState('gpt-5');
    const streamContext = createStreamTransformContext('gpt-5');
    const usage = {
      promptTokens: 2,
      completionTokens: 4,
      totalTokens: 6,
    };

    serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        contentDelta: 'hello world',
      } as any,
    });

    const lines = serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        responsesEventType: 'response.completed',
        responsesPayload: {
          type: 'response.completed',
          response: {
            id: 'resp_1',
            model: 'gpt-5',
            usage: {
              input_tokens: 2,
              output_tokens: 4,
              total_tokens: 6,
            },
          },
        },
      },
    });

    const events = parseSseEvents(lines);
    expect(events.map((entry) => entry.event)).toEqual([
      'response.output_text.done',
      'response.content_part.done',
      'response.output_item.done',
      'response.completed',
    ]);
  });

  it('closes reasoning summary parts before forwarding an upstream response.completed event', () => {
    const state = createOpenAiResponsesAggregateState('gpt-5');
    const streamContext = createStreamTransformContext('gpt-5');
    const usage = {
      promptTokens: 1,
      completionTokens: 2,
      totalTokens: 3,
    };

    serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        reasoningDelta: 'Think ',
      } as any,
    });

    const lines = serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        responsesEventType: 'response.completed',
        responsesPayload: {
          type: 'response.completed',
          response: {
            id: 'resp_reasoning_done',
            model: 'gpt-5',
            usage: {
              input_tokens: 1,
              output_tokens: 2,
              total_tokens: 3,
            },
          },
        },
      },
    });

    const events = parseSseEvents(lines);
    expect(events.map((entry) => entry.event)).toEqual([
      'response.reasoning_summary_text.done',
      'response.reasoning_summary_part.done',
      'response.output_item.done',
      'response.completed',
    ]);
  });

  it('preserves terminal response output from sparse response.incomplete payloads', () => {
    const state = createOpenAiResponsesAggregateState('gpt-5');
    const streamContext = createStreamTransformContext('gpt-5');
    const usage = {
      promptTokens: 1,
      completionTokens: 2,
      totalTokens: 3,
    };

    const lines = serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        responsesEventType: 'response.incomplete',
        responsesPayload: {
          type: 'response.incomplete',
          response: {
            id: 'resp_sparse_incomplete',
            model: 'gpt-5',
            status: 'incomplete',
            output: [
              {
                id: 'msg_sparse_incomplete',
                type: 'message',
                role: 'assistant',
                status: 'incomplete',
                content: [
                  {
                    type: 'output_text',
                    text: 'partial answer',
                  },
                ],
              },
            ],
            usage: {
              input_tokens: 1,
              output_tokens: 2,
              total_tokens: 3,
            },
          },
        },
      },
    });

    const events = parseSseEvents(lines);
    expect(events.at(-1)?.payload).toMatchObject({
      type: 'response.incomplete',
      response: {
        id: 'resp_sparse_incomplete',
        status: 'incomplete',
        output_text: 'partial answer',
        output: [
          {
            id: 'msg_sparse_incomplete',
            type: 'message',
            role: 'assistant',
            status: 'incomplete',
            content: [
              {
                type: 'output_text',
                text: 'partial answer',
              },
            ],
          },
        ],
      },
    });
  });

  it('preserves response.incomplete as a first-class terminal event', () => {
    const state = createOpenAiResponsesAggregateState('gpt-5');
    const streamContext = createStreamTransformContext('gpt-5');
    const usage = {
      promptTokens: 2,
      completionTokens: 4,
      totalTokens: 6,
    };

    serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        contentDelta: 'partial answer',
      } as any,
    });

    const lines = serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        responsesEventType: 'response.incomplete',
        responsesPayload: {
          type: 'response.incomplete',
          response: {
            id: 'resp_incomplete_1',
            model: 'gpt-5',
            status: 'incomplete',
            incomplete_details: {
              reason: 'max_output_tokens',
            },
            usage: {
              input_tokens: 2,
              output_tokens: 4,
              total_tokens: 6,
            },
          },
        },
      },
    });

    const events = parseSseEvents(lines);
    expect(events.map((entry) => entry.event)).toEqual([
      'response.output_text.done',
      'response.content_part.done',
      'response.output_item.done',
      'response.incomplete',
    ]);
    expect(events[3]?.payload).toMatchObject({
      type: 'response.incomplete',
      response: {
        id: 'resp_incomplete_1',
        status: 'incomplete',
        incomplete_details: {
          reason: 'max_output_tokens',
        },
        output_text: 'partial answer',
      },
    });
  });

  it('closes every unterminated message part and only emits output_text.done for text parts', () => {
    const state = createOpenAiResponsesAggregateState('gpt-5');
    const streamContext = createStreamTransformContext('gpt-5');
    const usage = {
      promptTokens: 1,
      completionTokens: 2,
      totalTokens: 3,
    };

    serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        responsesEventType: 'response.output_item.added',
        responsesPayload: {
          type: 'response.output_item.added',
          output_index: 0,
          item: {
            id: 'msg_multi_1',
            type: 'message',
            role: 'assistant',
            status: 'in_progress',
            content: [],
          },
        },
      },
    });

    serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        responsesEventType: 'response.content_part.added',
        responsesPayload: {
          type: 'response.content_part.added',
          output_index: 0,
          item_id: 'msg_multi_1',
          content_index: 0,
          part: {
            type: 'refusal',
            text: 'no',
          },
        },
      },
    });

    serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        responsesEventType: 'response.content_part.added',
        responsesPayload: {
          type: 'response.content_part.added',
          output_index: 0,
          item_id: 'msg_multi_1',
          content_index: 1,
          part: {
            type: 'output_text',
            text: 'yes',
          },
        },
      },
    });

    const lines = completeResponsesStream(state, streamContext, usage);
    const events = parseSseEvents(lines);

    expect(events.map((entry) => entry.event ?? (entry.payload === '[DONE]' ? '[DONE]' : 'data'))).toEqual([
      'response.content_part.done',
      'response.output_text.done',
      'response.content_part.done',
      'response.output_item.done',
      'response.completed',
      '[DONE]',
    ]);
    expect(events[0]?.payload).toMatchObject({
      type: 'response.content_part.done',
      content_index: 0,
      part: {
        type: 'refusal',
        text: 'no',
      },
    });
    expect(events[1]?.payload).toMatchObject({
      type: 'response.output_text.done',
      item_id: 'msg_multi_1',
      text: 'yes',
    });
    expect(events[2]?.payload).toMatchObject({
      type: 'response.content_part.done',
      content_index: 1,
      part: {
        type: 'output_text',
        text: 'yes',
      },
    });
  });

  it('closes every unterminated reasoning summary part before completion', () => {
    const state = createOpenAiResponsesAggregateState('gpt-5');
    const streamContext = createStreamTransformContext('gpt-5');
    const usage = {
      promptTokens: 1,
      completionTokens: 2,
      totalTokens: 3,
    };

    serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        responsesEventType: 'response.output_item.added',
        responsesPayload: {
          type: 'response.output_item.added',
          output_index: 0,
          item: {
            id: 'rs_multi_1',
            type: 'reasoning',
            status: 'in_progress',
            summary: [],
          },
        },
      },
    });

    for (const [summaryIndex, text] of [[0, 'first'], [1, 'second']] as const) {
      serializeConvertedResponsesEvents({
        state,
        streamContext,
        usage,
        event: {
          responsesEventType: 'response.reasoning_summary_part.added',
          responsesPayload: {
            type: 'response.reasoning_summary_part.added',
            item_id: 'rs_multi_1',
            output_index: 0,
            summary_index: summaryIndex,
            part: {
              type: 'summary_text',
              text,
            },
          },
        },
      });
    }

    const lines = completeResponsesStream(state, streamContext, usage);
    const events = parseSseEvents(lines);

    expect(events.map((entry) => entry.event ?? (entry.payload === '[DONE]' ? '[DONE]' : 'data'))).toEqual([
      'response.reasoning_summary_text.done',
      'response.reasoning_summary_part.done',
      'response.reasoning_summary_text.done',
      'response.reasoning_summary_part.done',
      'response.output_item.done',
      'response.completed',
      '[DONE]',
    ]);
    expect(events[0]?.payload).toMatchObject({
      type: 'response.reasoning_summary_text.done',
      summary_index: 0,
      text: 'first',
    });
    expect(events[2]?.payload).toMatchObject({
      type: 'response.reasoning_summary_text.done',
      summary_index: 1,
      text: 'second',
    });
  });

  it('emits a generic output_item.done for native image generation items that completed earlier', () => {
    const state = createOpenAiResponsesAggregateState('gpt-5');
    const streamContext = createStreamTransformContext('gpt-5');
    const usage = {
      promptTokens: 1,
      completionTokens: 2,
      totalTokens: 3,
    };

    serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        responsesEventType: 'response.image_generation_call.completed',
        responsesPayload: {
          type: 'response.image_generation_call.completed',
          item_id: 'img_terminal_1',
          output_index: 0,
          result: 'final-image',
        },
      },
    });

    const lines = serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        responsesEventType: 'response.completed',
        responsesPayload: {
          type: 'response.completed',
          response: {
            id: 'resp_image_done_1',
            model: 'gpt-5',
            usage: {
              input_tokens: 1,
              output_tokens: 2,
              total_tokens: 3,
            },
          },
        },
      },
    });

    const events = parseSseEvents(lines);
    expect(events.map((entry) => entry.event)).toEqual([
      'response.output_item.done',
      'response.completed',
    ]);
    expect(events[0]?.payload).toMatchObject({
      type: 'response.output_item.done',
      output_index: 0,
      item: {
        id: 'img_terminal_1',
        type: 'image_generation_call',
        status: 'completed',
        result: 'final-image',
      },
    });
  });

  it('does not synthesize duplicate tool input done events after original tool completion already arrived', () => {
    const state = createOpenAiResponsesAggregateState('gpt-5');
    const streamContext = createStreamTransformContext('gpt-5');
    const usage = {
      promptTokens: 1,
      completionTokens: 2,
      totalTokens: 3,
    };

    serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        responsesEventType: 'response.output_item.added',
        responsesPayload: {
          type: 'response.output_item.added',
          output_index: 0,
          item: {
            id: 'fc_done_1',
            type: 'function_call',
            status: 'in_progress',
            call_id: 'fc_done_1',
            name: 'browser',
            arguments: '',
          },
        },
      },
    });

    serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        responsesEventType: 'response.function_call_arguments.done',
        responsesPayload: {
          type: 'response.function_call_arguments.done',
          item_id: 'fc_done_1',
          call_id: 'fc_done_1',
          output_index: 0,
          name: 'browser',
          arguments: '{"url":"https://example.com"}',
        },
      },
    });

    serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        responsesEventType: 'response.output_item.added',
        responsesPayload: {
          type: 'response.output_item.added',
          output_index: 1,
          item: {
            id: 'ct_done_1',
            type: 'custom_tool_call',
            status: 'in_progress',
            call_id: 'ct_done_1',
            name: 'browser',
            input: '',
          },
        },
      },
    });

    serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        responsesEventType: 'response.custom_tool_call_input.done',
        responsesPayload: {
          type: 'response.custom_tool_call_input.done',
          item_id: 'ct_done_1',
          call_id: 'ct_done_1',
          output_index: 1,
          name: 'browser',
          input: 'open example.com',
        },
      },
    });

    const lines = completeResponsesStream(state, streamContext, usage);
    const events = parseSseEvents(lines);

    expect(events.map((entry) => entry.event ?? (entry.payload === '[DONE]' ? '[DONE]' : 'data'))).toEqual([
      'response.output_item.done',
      'response.output_item.done',
      'response.completed',
      '[DONE]',
    ]);
  });

  it('keeps synthetic reasoning and message items separate when reasoning arrives before visible text', () => {
    const state = createOpenAiResponsesAggregateState('gpt-5');
    const streamContext = createStreamTransformContext('gpt-5');
    const usage = {
      promptTokens: 1,
      completionTokens: 2,
      totalTokens: 3,
    };

    serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        reasoningDelta: 'think first',
      } as any,
    });

    const messageLines = serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        contentDelta: 'visible answer',
      } as any,
    });

    const messageEvents = parseSseEvents(messageLines);
    expect(messageEvents[0]?.payload).toMatchObject({
      type: 'response.output_item.added',
      item: {
        type: 'message',
      },
    });

    const completionLines = completeResponsesStream(state, streamContext, usage);
    const completionPayloads = parseSsePayloads(completionLines);
    const completed = completionPayloads.find((item) => item.type === 'response.completed');
    expect(completed?.response?.output).toHaveLength(2);
    expect(completed?.response?.output?.find((item: any) => item.type === 'reasoning')).toMatchObject({
      type: 'reasoning',
      summary: [{ type: 'summary_text', text: 'think first' }],
    });
    expect(completed?.response?.output?.find((item: any) => item.type === 'message')).toMatchObject({
      type: 'message',
      content: [{ type: 'output_text', text: 'visible answer' }],
    });
    expect(completed?.response?.output_text).toBe('visible answer');
  });

  it('keeps synthetic message and tool call items separate when content and tool deltas arrive together', () => {
    const state = createOpenAiResponsesAggregateState('gpt-5');
    const streamContext = createStreamTransformContext('gpt-5');
    const usage = {
      promptTokens: 1,
      completionTokens: 2,
      totalTokens: 3,
    };

    serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        contentDelta: 'hi',
        toolCallDeltas: [{
          index: 0,
          id: 'call_1',
          name: 'Glob',
          argumentsDelta: '{"pattern":"README*"}',
        }],
      } as any,
    });

    const completionLines = completeResponsesStream(state, streamContext, usage);
    const completionPayloads = parseSsePayloads(completionLines);
    const completed = completionPayloads.find((item) => item.type === 'response.completed');
    expect(completed?.response?.output).toHaveLength(2);
    expect(completed?.response?.output?.find((item: any) => item.type === 'message')).toMatchObject({
      type: 'message',
      content: [{ type: 'output_text', text: 'hi' }],
    });
    expect(completed?.response?.output?.find((item: any) => item.type === 'function_call')).toMatchObject({
      type: 'function_call',
      call_id: 'call_1',
      name: 'Glob',
      arguments: '{"pattern":"README*"}',
    });
  });

  it('backfills missing output_item.added before sparse native function_call argument events', () => {
    const state = createOpenAiResponsesAggregateState('gpt-5');
    const streamContext = createStreamTransformContext('gpt-5');
    const usage = {
      promptTokens: 1,
      completionTokens: 2,
      totalTokens: 3,
    };

    const lines = serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        responsesEventType: 'response.function_call_arguments.delta',
        responsesPayload: {
          type: 'response.function_call_arguments.delta',
          output_index: 0,
          call_id: 'call_sparse_1',
          name: 'Glob',
          delta: '{"pattern":"README*"}',
        },
      },
    });

    const events = parseSseEvents(lines);
    expect(events.map((entry) => entry.event)).toEqual([
      'response.output_item.added',
      'response.function_call_arguments.delta',
    ]);
    expect(events[0]?.payload).toMatchObject({
      type: 'response.output_item.added',
      output_index: 0,
      item: {
        type: 'function_call',
        call_id: 'call_sparse_1',
        name: 'Glob',
      },
    });
  });

  it('emits a generic output_item.done for native image_generation completion before response.completed', () => {
    const state = createOpenAiResponsesAggregateState('gpt-5');
    const streamContext = createStreamTransformContext('gpt-5');
    const usage = {
      promptTokens: 1,
      completionTokens: 2,
      totalTokens: 3,
    };

    serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        responsesEventType: 'response.image_generation_call.completed',
        responsesPayload: {
          type: 'response.image_generation_call.completed',
          output_index: 0,
          item_id: 'img_1',
          result: 'image-result',
        },
      },
    });

    const lines = serializeConvertedResponsesEvents({
      state,
      streamContext,
      usage,
      event: {
        responsesEventType: 'response.completed',
        responsesPayload: {
          type: 'response.completed',
          response: {
            id: 'resp_image_1',
            model: 'gpt-5',
            usage: {
              input_tokens: 1,
              output_tokens: 2,
              total_tokens: 3,
            },
          },
        },
      },
    });

    const events = parseSseEvents(lines);
    expect(events.map((entry) => entry.event)).toEqual([
      'response.output_item.done',
      'response.completed',
    ]);
    expect(events[0]?.payload).toMatchObject({
      type: 'response.output_item.done',
      output_index: 0,
      item: {
        id: 'img_1',
        type: 'image_generation_call',
        status: 'completed',
        result: 'image-result',
      },
    });
  });
});
