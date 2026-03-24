import { describe, expect, it } from 'vitest';

import {
  convertClaudeRequestToOpenAiBody,
  createClaudeDownstreamContext,
  createStreamTransformContext,
  normalizeUpstreamStreamEvent,
  serializeNormalizedStreamEvent,
} from './chatFormatsCore.js';

describe('chatFormatsCore inline think parsing', () => {
  it('tracks split think tags across stream chunks', () => {
    const context = createStreamTransformContext('gpt-test');

    expect(normalizeUpstreamStreamEvent({
      id: 'chatcmpl-split-think',
      model: 'gpt-test',
      choices: [{
        index: 0,
        delta: { role: 'assistant' },
        finish_reason: null,
      }],
    }, context, 'gpt-test')).toMatchObject({
      role: 'assistant',
    });

    const openingFragment = normalizeUpstreamStreamEvent({
      id: 'chatcmpl-split-think',
      model: 'gpt-test',
      choices: [{
        index: 0,
        delta: { content: '<thin' },
        finish_reason: null,
      }],
    }, context, 'gpt-test');
    expect(openingFragment.contentDelta).toBeUndefined();
    expect(openingFragment.reasoningDelta).toBeUndefined();

    expect(normalizeUpstreamStreamEvent({
      id: 'chatcmpl-split-think',
      model: 'gpt-test',
      choices: [{
        index: 0,
        delta: { content: 'k>plan ' },
        finish_reason: null,
      }],
    }, context, 'gpt-test')).toMatchObject({
      reasoningDelta: 'plan ',
    });

    expect(normalizeUpstreamStreamEvent({
      id: 'chatcmpl-split-think',
      model: 'gpt-test',
      choices: [{
        index: 0,
        delta: { content: 'quietly</th' },
        finish_reason: null,
      }],
    }, context, 'gpt-test')).toMatchObject({
      reasoningDelta: 'quietly',
    });

    expect(normalizeUpstreamStreamEvent({
      id: 'chatcmpl-split-think',
      model: 'gpt-test',
      choices: [{
        index: 0,
        delta: { content: 'ink>visible answer' },
        finish_reason: null,
      }],
    }, context, 'gpt-test')).toMatchObject({
      contentDelta: 'visible answer',
    });
  });

  it('treats response.reasoning_summary_text.done as reasoning-only stream output', () => {
    const context = createStreamTransformContext('gpt-test');

    expect(normalizeUpstreamStreamEvent({
      type: 'response.reasoning_summary_text.done',
      item_id: 'rs_1',
      output_index: 0,
      summary_index: 0,
      text: 'plan first',
    }, context, 'gpt-test')).toEqual({
      reasoningDelta: 'plan first',
    });
  });

  it('accumulates reasoning summary deltas before reconciling response.reasoning_summary_text.done', () => {
    const context = createStreamTransformContext('gpt-test');

    expect(normalizeUpstreamStreamEvent({
      type: 'response.reasoning_summary_text.delta',
      item_id: 'rs_multi',
      output_index: 0,
      summary_index: 0,
      delta: 'plan ',
    }, context, 'gpt-test')).toEqual({
      reasoningDelta: 'plan ',
    });

    expect(normalizeUpstreamStreamEvent({
      type: 'response.reasoning_summary_text.delta',
      item_id: 'rs_multi',
      output_index: 0,
      summary_index: 0,
      delta: 'first',
    }, context, 'gpt-test')).toEqual({
      reasoningDelta: 'first',
    });

    expect(normalizeUpstreamStreamEvent({
      type: 'response.reasoning_summary_text.done',
      item_id: 'rs_multi',
      output_index: 0,
      summary_index: 0,
      text: 'plan first',
    }, context, 'gpt-test')).toEqual({});
  });

  it('preserves terminal-only native responses output item payloads in stream normalization', () => {
    const context = createStreamTransformContext('gpt-test');

    expect(normalizeUpstreamStreamEvent({
      type: 'response.output_item.done',
      output_index: 0,
      item: {
        id: 'msg_1',
        type: 'message',
        role: 'assistant',
        status: 'completed',
        content: [{ type: 'output_text', text: 'hello' }],
      },
    }, context, 'gpt-test')).toEqual({
      role: 'assistant',
      contentDelta: 'hello',
    });

    expect(normalizeUpstreamStreamEvent({
      type: 'response.output_item.done',
      output_index: 1,
      item: {
        id: 'fc_1',
        type: 'function_call',
        call_id: 'call_1',
        name: 'lookup',
        arguments: '{"q":"x"}',
        status: 'completed',
      },
    }, context, 'gpt-test')).toEqual({
      toolCallDeltas: [{
        index: 0,
        id: 'call_1',
        name: 'lookup',
        argumentsDelta: '{"q":"x"}',
      }],
    });
  });

  it('keeps responses tool-call indices stable when response.completed replays mixed output arrays', () => {
    const context = createStreamTransformContext('gpt-test');
    const claudeContext = createClaudeDownstreamContext();

    const streamingDelta = normalizeUpstreamStreamEvent({
      type: 'response.function_call_arguments.delta',
      output_index: 1,
      call_id: 'call_1',
      name: 'lookup',
      delta: '{"q":"x"}',
    }, context, 'gpt-test');

    expect(streamingDelta).toEqual({
      toolCallDeltas: [{
        index: 0,
        id: 'call_1',
        name: 'lookup',
        argumentsDelta: '{"q":"x"}',
      }],
    });
    expect(serializeNormalizedStreamEvent('openai', streamingDelta, context, claudeContext)).toHaveLength(1);

    expect(normalizeUpstreamStreamEvent({
      type: 'response.completed',
      response: {
        id: 'resp_3',
        model: 'gpt-test',
        status: 'completed',
        output: [
          {
            id: 'msg_1',
            type: 'message',
            role: 'assistant',
            status: 'completed',
            content: [{ type: 'output_text', text: 'working on it' }],
          },
          {
            id: 'fc_1',
            type: 'function_call',
            call_id: 'call_1',
            name: 'lookup',
            arguments: '{"q":"x"}',
            status: 'completed',
          },
        ],
      },
    }, context, 'gpt-test')).toEqual({
      role: 'assistant',
      contentDelta: 'working on it',
      finishReason: 'stop',
      done: true,
    });
  });

  it('preserves terminal response.completed payload output when it carries the only final content', () => {
    const context = createStreamTransformContext('gpt-test');

    expect(normalizeUpstreamStreamEvent({
      type: 'response.completed',
      response: {
        id: 'resp_1',
        status: 'completed',
        output: [
          {
            id: 'msg_1',
            type: 'message',
            role: 'assistant',
            status: 'completed',
            content: [{ type: 'output_text', text: 'hello' }],
          },
        ],
      },
    }, context, 'gpt-test')).toEqual({
      role: 'assistant',
      contentDelta: 'hello',
      finishReason: 'stop',
      done: true,
    });
  });

  it('preserves streamed trailing whitespace when reconciling response.completed content', () => {
    const context = createStreamTransformContext('gpt-test');

    expect(normalizeUpstreamStreamEvent({
      type: 'response.output_text.delta',
      output_index: 0,
      item_id: 'msg_ws_space',
      delta: 'hello ',
    }, context, 'gpt-test')).toEqual({
      contentDelta: 'hello ',
    });

    expect(normalizeUpstreamStreamEvent({
      type: 'response.completed',
      response: {
        id: 'resp_space_1',
        status: 'completed',
        output: [
          {
            id: 'msg_ws_space',
            type: 'message',
            role: 'assistant',
            status: 'completed',
            content: [{ type: 'output_text', text: 'hello world' }],
          },
        ],
      },
    }, context, 'gpt-test')).toEqual({
      role: 'assistant',
      contentDelta: 'world',
      finishReason: 'stop',
      done: true,
    });
  });

  it('preserves terminal response.completed custom tool metadata in stream normalization', () => {
    const context = createStreamTransformContext('gpt-test');

    expect(normalizeUpstreamStreamEvent({
      type: 'response.completed',
      response: {
        id: 'resp_2',
        model: 'gpt-test',
        status: 'completed',
        output: [
          {
            id: 'ct_1',
            type: 'custom_tool_call',
            call_id: 'call_custom_1',
            name: 'Shell',
            input: '{"command":"pwd"}',
          },
        ],
      },
    }, context, 'gpt-test')).toEqual({
      toolCallDeltas: [{
        index: 0,
        id: 'call_custom_1',
        name: 'Shell',
        argumentsDelta: '{"command":"pwd"}',
      }],
      finishReason: 'tool_calls',
      done: true,
    });
  });

  it('normalizes custom tool calls through the existing tool-call stream shape', () => {
    const context = createStreamTransformContext('gpt-test');

    expect(normalizeUpstreamStreamEvent({
      type: 'response.output_item.added',
      output_index: 0,
      item: {
        id: 'ct_1',
        type: 'custom_tool_call',
        call_id: 'call_custom',
        name: 'MyTool',
        input: '',
      },
    }, context, 'gpt-test')).toEqual({
      toolCallDeltas: [{
        index: 0,
        id: 'call_custom',
        name: 'MyTool',
      }],
    });

    expect(normalizeUpstreamStreamEvent({
      type: 'response.custom_tool_call_input.done',
      output_index: 0,
      item_id: 'ct_1',
      call_id: 'call_custom',
      name: 'MyTool',
      input: '{"path":"README.md"}',
    }, context, 'gpt-test')).toEqual({
      toolCallDeltas: [{
        index: 0,
        id: 'call_custom',
        name: 'MyTool',
        argumentsDelta: '{"path":"README.md"}',
      }],
    });
  });
});

describe('convertClaudeRequestToOpenAiBody', () => {
  it('keeps Claude tool_result content structured when a tool produces image blocks', () => {
    const payload = {
      model: 'gpt-test',
      messages: [
        {
          role: 'assistant',
          content: [
            {
              type: 'tool_use',
              id: 'call-image',
              name: 'ImageTool',
              input: { query: 'cat' },
            },
          ],
        },
        {
          role: 'user',
          content: [
            {
              type: 'tool_result',
              tool_use_id: 'call-image',
              content: [
                { type: 'text', text: 'found 1' },
                {
                  type: 'image',
                  source: {
                    type: 'url',
                    url: 'https://example.com/cat.png',
                    media_type: 'image/png',
                  },
                },
              ],
            },
          ],
        },
      ],
    };

    const { messages } = convertClaudeRequestToOpenAiBody(payload);
    const toolMessage = messages.find((message) => message.role === 'tool');
    expect(toolMessage).toBeTruthy();
    expect(Array.isArray(toolMessage?.content)).toBe(true);
    expect(toolMessage?.content.some((part: any) => part?.type === 'image_url')).toBe(true);
  });
});
