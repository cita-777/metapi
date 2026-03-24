import { describe, expect, it } from 'vitest';

import { createStreamTransformContext, normalizeUpstreamStreamEvent, convertClaudeRequestToOpenAiBody } from './chatFormatsCore.js';

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
