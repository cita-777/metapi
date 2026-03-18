import { describe, expect, it } from 'vitest';

import {
  convertOpenAiBodyToAnthropicMessagesBody,
  convertOpenAiToolChoiceToAnthropic,
  sanitizeAnthropicMessagesBody,
} from './conversion.js';
import { anthropicMessagesInbound } from './inbound.js';
import { anthropicMessagesTransformer } from './index.js';
import { extractAnthropicUsage, extractAnthropicUsageMetadata } from './usage.js';
import { applyAnthropicMessagesAggregateEvent, createAnthropicMessagesAggregateState } from './aggregator.js';

describe('sanitizeAnthropicMessagesBody', () => {
  it('drops top_p when temperature is present and normalizes adaptive thinking', () => {
    const result = sanitizeAnthropicMessagesBody({
      model: 'claude-opus',
      temperature: 0.6,
      top_p: 0.9,
      thinking: {
        type: 'adaptive',
        budget_tokens: 512,
      },
    });

    expect(result.top_p).toBeUndefined();
    expect(result.thinking).toEqual({
      type: 'enabled',
      budget_tokens: 512,
    });
  });

  it('normalizes string system and message content before rebuilding cache anchors', () => {
    const result = sanitizeAnthropicMessagesBody({
      model: 'claude-opus-4-6',
      system: 'system prompt',
      messages: [
        {
          role: 'user',
          content: 'hello from user',
        },
      ],
    });

    expect(result.system).toEqual([
      {
        type: 'text',
        text: 'system prompt',
        cache_control: { type: 'ephemeral' },
      },
    ]);
    expect(result.messages).toEqual([
      {
        role: 'user',
        content: [
          {
            type: 'text',
            text: 'hello from user',
            cache_control: { type: 'ephemeral' },
          },
        ],
      },
    ]);
  });

  it('drops output_config.effort unless thinking stays adaptive', () => {
    const enabled = sanitizeAnthropicMessagesBody({
      model: 'claude-opus-4-6',
      thinking: {
        type: 'enabled',
        budget_tokens: 256,
      },
      output_config: {
        effort: 'high',
        format: 'json',
      },
    });
    const adaptive = sanitizeAnthropicMessagesBody({
      model: 'claude-opus-4-6',
      thinking: {
        type: 'adaptive',
      },
      output_config: {
        effort: 'high',
        format: 'json',
      },
    });

    expect(enabled.output_config).toEqual({
      format: 'json',
    });
    expect(adaptive.output_config).toEqual({
      effort: 'high',
      format: 'json',
    });
  });

  it('drops non-ephemeral cache_control markers while preserving valid tool block markers', () => {
    const result = sanitizeAnthropicMessagesBody({
      model: 'claude-opus-4-6',
      messages: [
        {
          role: 'assistant',
          content: [
            {
              type: 'thinking',
              thinking: 'internal',
              cache_control: { type: 'persistent' },
            },
            {
              type: 'tool_use',
              id: 'tool_1',
              name: 'lookup',
              input: { city: 'paris' },
              cache_control: { type: 'ephemeral' },
            },
            {
              type: 'tool_result',
              tool_use_id: 'tool_1',
              content: 'done',
              cache_control: { type: 'persistent' },
            },
          ],
        },
      ],
    });

    expect(result.messages).toEqual([
      {
        role: 'assistant',
        content: [
          {
            type: 'thinking',
            thinking: 'internal',
          },
          {
            type: 'tool_use',
            id: 'tool_1',
            name: 'lookup',
            input: { city: 'paris' },
          },
          {
            type: 'tool_result',
            tool_use_id: 'tool_1',
            content: 'done',
            cache_control: { type: 'ephemeral' },
          },
        ],
      },
    ]);
  });
});

describe('convertOpenAiBodyToAnthropicMessagesBody', () => {
  it('maps OpenAI file blocks into Anthropic document blocks', () => {
    const base64Pdf = Buffer.from('%PDF-hello').toString('base64');
    const body = convertOpenAiBodyToAnthropicMessagesBody(
      {
        model: 'gpt-5',
        messages: [
          {
            role: 'user',
            content: [
              { type: 'text', text: 'summarize this file' },
              {
                type: 'file',
                file: {
                  filename: 'paper.pdf',
                  file_data: base64Pdf,
                },
              },
            ],
          },
        ],
      },
      'claude-opus-4-6',
      false,
    );

    expect(body.messages).toEqual([
      {
        role: 'user',
        content: [
          { type: 'text', text: 'summarize this file' },
          {
            type: 'document',
            source: {
              type: 'base64',
              media_type: 'application/pdf',
              data: base64Pdf,
            },
            title: 'paper.pdf',
          },
        ],
      },
    ]);
  });

  it('preserves image blocks, tool_use blocks, and tool_result chains', () => {
    const body = convertOpenAiBodyToAnthropicMessagesBody(
      {
        model: 'gpt-5',
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
      'claude-opus-4-6',
      false,
    );

    expect(body.system).toBe('system prompt');
    expect(body.messages).toEqual([
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
          },
        ],
      },
    ]);
  });

  it('drops thinking blocks whose signatures belong to another provider', () => {
    const body = convertOpenAiBodyToAnthropicMessagesBody(
      {
        model: 'gpt-5',
        messages: [
          {
            role: 'assistant',
            content: [
              {
                type: 'thinking',
                thinking: 'internal only',
                signature: 'metapi:openai-encrypted-reasoning:enc-foreign',
              },
              {
                type: 'text',
                text: 'final answer',
              },
            ],
          },
        ],
      },
      'claude-opus-4-6',
      false,
    );

    expect(body.messages).toEqual([
      {
        role: 'assistant',
        content: 'final answer',
      },
    ]);
  });

  it('decodes anthropic-tagged thinking signatures before sending upstream', () => {
    const body = convertOpenAiBodyToAnthropicMessagesBody(
      {
        model: 'gpt-5',
        messages: [
          {
            role: 'assistant',
            content: [
              {
                type: 'thinking',
                thinking: 'internal only',
                signature: 'metapi:anthropic-signature:sig-anthropic-1',
              },
              {
                type: 'text',
                text: 'final answer',
              },
            ],
          },
        ],
      },
      'claude-opus-4-6',
      false,
    );

    expect(body.messages).toEqual([
      {
        role: 'assistant',
        content: [
          {
            type: 'thinking',
            thinking: 'internal only',
            signature: 'sig-anthropic-1',
          },
          {
            type: 'text',
            text: 'final answer',
          },
        ],
      },
    ]);
  });

  it('preserves top-level reasoning_signature when rebuilding assistant thinking blocks for messages fallback', () => {
    const body = convertOpenAiBodyToAnthropicMessagesBody(
      {
        model: 'gpt-5',
        messages: [
          {
            role: 'assistant',
            content: 'final answer',
            reasoning_content: 'internal only',
            reasoning_signature: 'metapi:anthropic-signature:sig-top-level-1',
          },
        ],
      },
      'claude-opus-4-6',
      false,
    );

    expect(body.messages).toEqual([
      {
        role: 'assistant',
        content: [
          {
            type: 'thinking',
            thinking: 'internal only',
            signature: 'sig-top-level-1',
          },
          {
            type: 'text',
            text: 'final answer',
          },
        ],
      },
    ]);
  });

  it('strips cache_control from thinking blocks and empty text blocks', () => {
    const body = convertOpenAiBodyToAnthropicMessagesBody(
      {
        model: 'gpt-5',
        messages: [
          {
            role: 'assistant',
            content: [
              {
                type: 'thinking',
                thinking: 'internal',
                cache_control: { type: 'ephemeral' },
              },
              {
                type: 'text',
                text: '   ',
                cache_control: { type: 'ephemeral' },
              },
            ],
          },
        ],
      },
      'claude-opus-4-6',
      false,
    );

    expect(body.messages).toEqual([
      {
        role: 'assistant',
        content: [
          {
            type: 'thinking',
            thinking: 'internal',
          },
        ],
      },
    ]);
  });

  it('preserves cache_control on tool blocks while stripping unsupported thinking/text markers', () => {
    const result = sanitizeAnthropicMessagesBody({
      model: 'claude-opus-4-6',
      messages: [
        {
          role: 'assistant',
          content: [
            {
              type: 'thinking',
              thinking: 'internal',
              cache_control: { type: 'ephemeral' },
            },
            {
              type: 'tool_use',
              id: 'tool_1',
              name: 'lookup',
              input: { city: 'paris' },
              cache_control: { type: 'ephemeral' },
            },
            {
              type: 'text',
              text: '',
              cache_control: { type: 'ephemeral' },
            },
          ],
        },
      ],
    });

    expect(result.messages).toEqual([
      {
        role: 'assistant',
        content: [
          {
            type: 'thinking',
            thinking: 'internal',
          },
          {
            type: 'tool_use',
            id: 'tool_1',
            name: 'lookup',
            input: { city: 'paris' },
            cache_control: { type: 'ephemeral' },
          },
        ],
      },
    ]);
  });

  it('rebuilds cache_control anchors on structural blocks and the last cacheable message block', () => {
    const result = sanitizeAnthropicMessagesBody({
      model: 'claude-opus-4-6',
      tools: [
        { name: 'lookup', input_schema: { type: 'object' }, cache_control: { type: 'ephemeral' } },
        { name: 'search', input_schema: { type: 'object' } },
      ],
      system: [
        { type: 'text', text: 'system 1' },
        { type: 'text', text: 'system 2', cache_control: { type: 'ephemeral' } },
      ],
      messages: [
        {
          role: 'user',
          content: [
            { type: 'text', text: 'prefix' },
            { type: 'thinking', thinking: 'internal', cache_control: { type: 'ephemeral' } },
            { type: 'tool_use', id: 'tool_1', name: 'lookup', input: { city: 'paris' } },
          ],
        },
      ],
    });

    expect(result.tools).toEqual([
      { name: 'lookup', input_schema: { type: 'object' } },
      { name: 'search', input_schema: { type: 'object' }, cache_control: { type: 'ephemeral' } },
    ]);
    expect(result.system).toEqual([
      { type: 'text', text: 'system 1' },
      { type: 'text', text: 'system 2', cache_control: { type: 'ephemeral' } },
    ]);
    expect(result.messages).toEqual([
      {
        role: 'user',
        content: [
          { type: 'text', text: 'prefix' },
          { type: 'thinking', thinking: 'internal' },
          { type: 'tool_use', id: 'tool_1', name: 'lookup', input: { city: 'paris' }, cache_control: { type: 'ephemeral' } },
        ],
      },
    ]);
  });

  it('preserves tool_reference blocks inside tool_result content arrays', () => {
    const result = sanitizeAnthropicMessagesBody({
      model: 'claude-opus-4-6',
      messages: [
        {
          role: 'user',
          content: [
            {
              type: 'tool_result',
              tool_use_id: 'tool_1',
              content: [
                { type: 'tool_reference', tool_name: 'lookup' },
                { type: 'text', text: 'follow-up' },
              ],
            },
          ],
        },
      ],
    });

    expect(result.messages).toEqual([
      {
        role: 'user',
        content: [
          {
            type: 'tool_result',
            tool_use_id: 'tool_1',
            content: [
              { type: 'tool_reference', tool_name: 'lookup' },
              { type: 'text', text: 'follow-up' },
            ],
            cache_control: { type: 'ephemeral' },
          },
        ],
      },
    ]);
  });

  it('adds a second message cache anchor around the 20-block window for long prompts', () => {
    const longContent = Array.from({ length: 25 }, (_, index) => ({
      type: 'text',
      text: `block-${index + 1}`,
    }));

    const result = sanitizeAnthropicMessagesBody({
      model: 'claude-opus-4-6',
      messages: [
        {
          role: 'user',
          content: longContent,
        },
      ],
    });

    const content = (result.messages as Array<any>)[0].content as Array<any>;
    const anchoredIndexes = content
      .map((item, index) => item?.cache_control ? index : -1)
      .filter((index) => index >= 0);

    expect(anchoredIndexes).toEqual([4, 24]);
  });

  it('maps reasoning effort to anthropic output_config.effort with adaptive thinking', () => {
    const body = convertOpenAiBodyToAnthropicMessagesBody(
      {
        model: 'gpt-5',
        reasoning_effort: 'high',
        messages: [
          { role: 'user', content: 'hello' },
        ],
      },
      'claude-opus-4-6',
      true,
    );

    expect(body.thinking).toEqual({ type: 'adaptive' });
    expect(body.output_config).toEqual({ effort: 'high' });
  });

  it('keeps inbound claude bodies thin instead of rebuilding cache anchors', () => {
    const result = anthropicMessagesInbound.parse(
      {
        model: 'gpt-5',
        max_tokens: 512,
        tools: [
          {
            name: 'lookup',
            input_schema: { type: 'object' },
          },
          {
            name: 'search',
            input_schema: { type: 'object' },
          },
        ],
        system: 'system prompt',
        messages: [{ role: 'user', content: 'hello' }],
      },
    );

    expect(result.error).toBeUndefined();
    expect(result.value?.parsed.claudeOriginalBody).toEqual({
      model: 'gpt-5',
      max_tokens: 512,
      tools: [
        {
          name: 'lookup',
          input_schema: { type: 'object' },
        },
        {
          name: 'search',
          input_schema: { type: 'object' },
        },
      ],
      system: 'system prompt',
      messages: [{ role: 'user', content: 'hello' }],
    });
  });
});

describe('convertOpenAiToolChoiceToAnthropic', () => {
  it('maps required to any and function choice to tool', () => {
    expect(convertOpenAiToolChoiceToAnthropic('required')).toEqual({ type: 'any' });
    expect(convertOpenAiToolChoiceToAnthropic({
      type: 'function',
      function: { name: 'lookup' },
    })).toEqual({
      type: 'tool',
      name: 'lookup',
    });
  });

  it('normalizes tool-style objects and strips unsupported name on non-tool variants', () => {
    expect(anthropicMessagesInbound.parse({
      model: 'claude-opus-4-6',
      max_tokens: 512,
      messages: [{ role: 'user', content: 'hello' }],
      tool_choice: { type: 'tool', tool: { name: 'lookup' } },
    }).value?.parsed.claudeOriginalBody?.tool_choice).toEqual({
      type: 'tool',
      name: 'lookup',
    });

    expect(anthropicMessagesInbound.parse({
      model: 'claude-opus-4-6',
      max_tokens: 512,
      messages: [{ role: 'user', content: 'hello' }],
      tool_choice: { type: 'none', name: 'should-disappear' },
    }).value?.parsed.claudeOriginalBody?.tool_choice).toEqual({
      type: 'none',
    });
  });
});

describe('anthropicMessagesInbound', () => {
  it('rejects invalid tool_choice.type and invalid output_config.effort', () => {
    const invalidToolChoice = anthropicMessagesInbound.parse({
      model: 'claude-opus-4-6',
      max_tokens: 512,
      messages: [{ role: 'user', content: 'hello' }],
      tool_choice: { type: 'invalid' },
    });
    expect(invalidToolChoice.error?.statusCode).toBe(400);

    const invalidEffort = anthropicMessagesInbound.parse({
      model: 'claude-opus-4-6',
      max_tokens: 512,
      messages: [{ role: 'user', content: 'hello' }],
      thinking: { type: 'adaptive' },
      output_config: { effort: 'turbo' },
    });
    expect(invalidEffort.error?.statusCode).toBe(400);
  });

  it('rejects tool choice without a tool name', () => {
    const result = anthropicMessagesInbound.parse({
      model: 'claude-opus-4-6',
      max_tokens: 512,
      messages: [{ role: 'user', content: 'hello' }],
      tool_choice: { type: 'tool' },
    });

    expect(result.error?.statusCode).toBe(400);
  });

  it('rejects string tool_choice tool without a tool name', () => {
    const result = anthropicMessagesInbound.parse({
      model: 'claude-opus-4-6',
      max_tokens: 512,
      messages: [{ role: 'user', content: 'hello' }],
      tool_choice: 'tool',
    });

    expect(result.error?.statusCode).toBe(400);
  });
});

describe('anthropicMessagesTransformer.stream', () => {
  it('serializes reasoning separately from text for Claude downstream', () => {
    const streamContext = anthropicMessagesTransformer.createStreamContext('claude-opus-4-6');
    const downstreamContext = anthropicMessagesTransformer.createDownstreamContext();

    const chunks = [
      ...anthropicMessagesTransformer.serializeStreamEvent({ role: 'assistant' }, streamContext, downstreamContext),
      ...anthropicMessagesTransformer.serializeStreamEvent({ reasoningDelta: 'internal thought' }, streamContext, downstreamContext),
      ...anthropicMessagesTransformer.serializeStreamEvent({ contentDelta: 'final answer' }, streamContext, downstreamContext),
      ...anthropicMessagesTransformer.serializeStreamEvent({ finishReason: 'stop', done: true }, streamContext, downstreamContext),
    ].join('');

    expect(chunks).toContain('"type":"thinking_delta"');
    expect(chunks).toContain('"type":"text_delta"');
    expect(chunks).not.toContain('internal thought\\n\\nfinal answer');
  });

  it('buffers signature_delta until a thinking block is closed', () => {
    const streamContext = anthropicMessagesTransformer.createStreamContext('claude-opus-4-6');
    const downstreamContext = anthropicMessagesTransformer.createDownstreamContext();

    const signatureEvent = anthropicMessagesTransformer.transformStreamEvent({
      type: 'content_block_delta',
      index: 0,
      delta: { type: 'signature_delta', signature: 'sig-1' },
    }, streamContext, 'claude-opus-4-6');
    const thinkingStart = anthropicMessagesTransformer.transformStreamEvent({
      type: 'content_block_start',
      index: 0,
      content_block: { type: 'thinking', thinking: '' },
    }, streamContext, 'claude-opus-4-6');
    const thinkingDelta = anthropicMessagesTransformer.transformStreamEvent({
      type: 'content_block_delta',
      index: 0,
      delta: { type: 'thinking_delta', thinking: 'internal' },
    }, streamContext, 'claude-opus-4-6');
    const textDelta = anthropicMessagesTransformer.transformStreamEvent({
      type: 'content_block_delta',
      index: 1,
      delta: { type: 'text_delta', text: 'final' },
    }, streamContext, 'claude-opus-4-6');

    const serialized = [
      ...anthropicMessagesTransformer.serializeStreamEvent(signatureEvent, streamContext, downstreamContext),
      ...anthropicMessagesTransformer.serializeStreamEvent(thinkingStart, streamContext, downstreamContext),
      ...anthropicMessagesTransformer.serializeStreamEvent(thinkingDelta, streamContext, downstreamContext),
      ...anthropicMessagesTransformer.serializeStreamEvent(textDelta, streamContext, downstreamContext),
    ].join('');

    expect(serialized).toContain('"type":"signature_delta"');
    expect(serialized.indexOf('"type":"signature_delta"')).toBeGreaterThan(serialized.indexOf('"type":"thinking_delta"'));
    expect(serialized.indexOf('"type":"signature_delta"')).toBeLessThan(serialized.indexOf('"type":"text_delta"'));
  });

  it('emits redacted_thinking as its own lifecycle block', () => {
    const streamContext = anthropicMessagesTransformer.createStreamContext('claude-opus-4-6');
    const downstreamContext = anthropicMessagesTransformer.createDownstreamContext();

    const redactedStart = anthropicMessagesTransformer.transformStreamEvent({
      type: 'content_block_start',
      index: 0,
      content_block: { type: 'redacted_thinking', data: 'ciphertext' },
    }, streamContext, 'claude-opus-4-6');
    const redactedStop = anthropicMessagesTransformer.transformStreamEvent({
      type: 'content_block_stop',
      index: 0,
    }, streamContext, 'claude-opus-4-6');

    const serialized = [
      ...anthropicMessagesTransformer.serializeStreamEvent(redactedStart, streamContext, downstreamContext),
      ...anthropicMessagesTransformer.serializeStreamEvent(redactedStop, streamContext, downstreamContext),
    ].join('');
    expect(serialized).toContain('"type":"redacted_thinking"');
    expect(serialized).toContain('content_block_start');
    expect(serialized).toContain('content_block_stop');
  });
});

describe('extractAnthropicUsage', () => {
  it('maps cache read and cache creation tokens into normalized usage', () => {
    expect(extractAnthropicUsage({
      usage: {
        input_tokens: 100,
        output_tokens: 30,
        cache_read_input_tokens: 12,
        cache_creation_input_tokens: 8,
      },
    })).toMatchObject({
      promptTokens: 120,
      completionTokens: 30,
      totalTokens: 150,
      cachedTokens: 12,
      cacheReadInputTokens: 12,
      cacheCreationInputTokens: 8,
      promptTokensIncludingCache: 120,
      reasoningTokens: 0,
      audioInputTokens: 0,
      audioOutputTokens: 0,
      acceptedPredictionTokens: 0,
      rejectedPredictionTokens: 0,
    });
  });

  it('exposes cache read/cache creation details for metadata consumers', () => {
    expect(extractAnthropicUsageMetadata({
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
    })).toMatchObject({
      cacheReadInputTokens: 12,
      cacheCreationInputTokens: 8,
      ephemeral5mInputTokens: 5,
      ephemeral1hInputTokens: 3,
      promptTokensIncludingCache: 120,
    });
  });

  it('derives cache creation input tokens from nested cache_creation when the top-level field is missing', () => {
    expect(extractAnthropicUsageMetadata({
      usage: {
        input_tokens: 100,
        output_tokens: 30,
        cache_read_input_tokens: 12,
        cache_creation: {
          ephemeral_5m_input_tokens: 5,
          ephemeral_1h_input_tokens: 3,
        },
      },
    })).toMatchObject({
      cacheReadInputTokens: 12,
      cacheCreationInputTokens: 8,
      ephemeral5mInputTokens: 5,
      ephemeral1hInputTokens: 3,
      promptTokensIncludingCache: 120,
    });
  });
});

describe('applyAnthropicMessagesAggregateEvent', () => {
  it('tracks text, reasoning, redacted thinking, and tool call arguments', () => {
    const state = createAnthropicMessagesAggregateState();

    applyAnthropicMessagesAggregateEvent(state, { reasoningDelta: 'think-1' });
    applyAnthropicMessagesAggregateEvent(state, { contentDelta: 'answer-1' });
    applyAnthropicMessagesAggregateEvent(state, {
      toolCallDeltas: [{ index: 0, id: 'call_1', name: 'lookup', argumentsDelta: '{"city":"par' }],
    });
    applyAnthropicMessagesAggregateEvent(state, {
      toolCallDeltas: [{ index: 0, argumentsDelta: 'is"}' }],
    });
    applyAnthropicMessagesAggregateEvent(state, {
      anthropic: {
        redactedThinkingData: 'cipher',
      },
    } as any);

    expect(state.reasoning).toEqual(['think-1']);
    expect(state.text).toEqual(['answer-1']);
    expect(state.redactedReasoning).toEqual(['cipher']);
    expect(state.toolCalls[0]).toEqual({
      id: 'call_1',
      name: 'lookup',
      arguments: '{"city":"paris"}',
    });
  });

  it('buffers signature until the thinking block closes and records lifecycle markers', () => {
    const state = createAnthropicMessagesAggregateState();

    applyAnthropicMessagesAggregateEvent(state, {
      anthropic: {
        signatureDelta: 'sig-buffered',
      },
    } as any);
    applyAnthropicMessagesAggregateEvent(state, {
      anthropic: {
        startBlock: {
          kind: 'thinking',
          index: 2,
        },
      },
    } as any);
    applyAnthropicMessagesAggregateEvent(state, { reasoningDelta: 'deliberating' });
    applyAnthropicMessagesAggregateEvent(state, {
      anthropic: {
        stopBlockIndex: 2,
      },
    } as any);
    applyAnthropicMessagesAggregateEvent(state, {
      anthropic: {
        startBlock: {
          kind: 'redacted_thinking',
          index: 3,
        },
        redactedThinkingData: 'cipher-2',
      },
    } as any);
    applyAnthropicMessagesAggregateEvent(state, {
      anthropic: {
        stopBlockIndex: 3,
      },
    } as any);

    expect(state.pendingSignature).toBeNull();
    expect(state.signatures).toEqual(['sig-buffered']);
    expect(state.blockLifecycle).toEqual([
      { kind: 'thinking', phase: 'start', index: 2 },
      { kind: 'thinking', phase: 'stop', index: 2 },
      { kind: 'redacted_thinking', phase: 'start', index: 3 },
      { kind: 'redacted_thinking', phase: 'stop', index: 3 },
    ]);
    expect(state.redactedReasoning).toEqual(['cipher-2']);
  });

  it('flushes pending signatures and closes open thinking/redacted blocks on finish', () => {
    const state = createAnthropicMessagesAggregateState();

    applyAnthropicMessagesAggregateEvent(state, {
      anthropic: {
        signatureDelta: 'sig-finish',
      },
    } as any);
    applyAnthropicMessagesAggregateEvent(state, {
      anthropic: {
        startBlock: {
          kind: 'thinking',
          index: 4,
        },
      },
    } as any);
    applyAnthropicMessagesAggregateEvent(state, {
      anthropic: {
        startBlock: {
          kind: 'redacted_thinking',
          index: 5,
        },
        redactedThinkingData: 'cipher-finish',
      },
    } as any);
    applyAnthropicMessagesAggregateEvent(state, {
      finishReason: 'stop',
      done: true,
    });

    expect(state.pendingSignature).toBeNull();
    expect(state.signatures).toEqual(['sig-finish']);
    expect(state.blockLifecycle).toEqual([
      { kind: 'thinking', phase: 'start', index: 4 },
      { kind: 'thinking', phase: 'stop', index: 4 },
      { kind: 'redacted_thinking', phase: 'start', index: 5 },
      { kind: 'redacted_thinking', phase: 'stop', index: 5 },
    ]);
    expect(state.finishReason).toBe('stop');
  });

  it('creates a synthetic thinking lifecycle when a buffered signature is flushed on finish', () => {
    const state = createAnthropicMessagesAggregateState();

    applyAnthropicMessagesAggregateEvent(state, {
      anthropic: {
        signatureDelta: 'sig-only',
      },
    } as any);
    applyAnthropicMessagesAggregateEvent(state, {
      finishReason: 'stop',
      done: true,
    });

    expect(state.pendingSignature).toBeNull();
    expect(state.signatures).toEqual(['sig-only']);
    expect(state.contentBlocks).toEqual([
      {
        type: 'thinking',
        thinking: '',
        signature: 'sig-only',
      },
    ]);
    expect(state.blockLifecycle).toEqual([
      { kind: 'thinking', phase: 'start' },
      { kind: 'thinking', phase: 'stop' },
    ]);
  });
});
