import { describe, expect, it } from 'vitest';

import { createClaudeDownstreamContext } from '../../shared/normalized.js';
import { toTransformerMetadataRecord } from '../../shared/normalized.js';
import { openAiChatTransformer } from './index.js';

function parseSsePayloads(lines: string[]): Array<Record<string, unknown>> {
  return lines
    .filter((line) => line.startsWith('data: ') && line.trim() !== 'data: [DONE]')
    .map((line) => JSON.parse(line.slice(6)) as Record<string, unknown>);
}

describe('openAiChatTransformer.inbound', () => {
  it('parses chat requests into canonical envelopes', () => {
    const result = openAiChatTransformer.parseRequest({
      model: 'gpt-5',
      stream: true,
      messages: [{ role: 'user', content: 'hello' }],
      prompt_cache_key: 'cache-key',
      reasoning_effort: 'high',
      reasoning_budget: 1024,
    });

    expect(result.error).toBeUndefined();
    expect(result.value).toMatchObject({
      operation: 'generate',
      surface: 'openai-chat',
      cliProfile: 'generic',
      requestedModel: 'gpt-5',
      stream: true,
      messages: [
        {
          role: 'user',
          parts: [{ type: 'text', text: 'hello' }],
        },
      ],
      continuation: {
        promptCacheKey: 'cache-key',
      },
      reasoning: {
        effort: 'high',
        budgetTokens: 1024,
      },
    });
  });

  it('builds chat requests from canonical envelopes', () => {
    const body = openAiChatTransformer.buildProtocolRequest({
      operation: 'generate',
      surface: 'openai-chat',
      cliProfile: 'codex',
      requestedModel: 'gpt-5',
      stream: true,
      messages: [{ role: 'user', parts: [{ type: 'text', text: 'hello' }] }],
      reasoning: {
        effort: 'medium',
        budgetTokens: 512,
      },
      continuation: {
        promptCacheKey: 'cache-key',
      },
    });

    expect(body).toMatchObject({
      model: 'gpt-5',
      stream: true,
      messages: [{ role: 'user', content: 'hello' }],
      prompt_cache_key: 'cache-key',
      reasoning_effort: 'medium',
      reasoning_budget: 512,
    });
  });

  it('captures chat request metadata fields without changing upstream body', () => {
    const result = openAiChatTransformer.transformRequest({
      model: 'gpt-5',
      messages: [{ role: 'user', content: 'hello' }],
      modalities: ['text', 'audio'],
      audio: { voice: 'alloy', format: 'mp3' },
      reasoning_effort: 'high',
      reasoning_budget: 1024,
      reasoning_summary: 'detailed',
      service_tier: 'priority',
      top_logprobs: 3,
      logit_bias: { '42': 5 },
      prompt_cache_key: 'cache-key',
      safety_identifier: 'safety-id',
      verbosity: 'low',
      response_format: { type: 'json_object' },
      stream_options: { include_usage: true },
    });

    expect(result.error).toBeUndefined();
    expect(result.value).toMatchObject({
      protocol: 'openai/chat',
      model: 'gpt-5',
      stream: false,
      rawBody: {
        model: 'gpt-5',
        messages: [{ role: 'user', content: 'hello' }],
      },
    });
    expect(result.value?.parsed.upstreamBody).toMatchObject({
      modalities: ['text', 'audio'],
      audio: { voice: 'alloy', format: 'mp3' },
      reasoning_effort: 'high',
      reasoning_budget: 1024,
      reasoning_summary: 'detailed',
      service_tier: 'priority',
      top_logprobs: 3,
      logit_bias: { '42': 5 },
      prompt_cache_key: 'cache-key',
      safety_identifier: 'safety-id',
      verbosity: 'low',
      response_format: { type: 'json_object' },
      stream_options: { include_usage: true },
    });
    expect((result.value as any)?.metadata).toEqual({
      modalities: ['text', 'audio'],
      audio: { voice: 'alloy', format: 'mp3' },
      reasoningEffort: 'high',
      reasoningBudget: 1024,
      reasoningSummary: 'detailed',
      serviceTier: 'priority',
      topLogprobs: 3,
      logitBias: { '42': 5 },
      promptCacheKey: 'cache-key',
      safetyIdentifier: 'safety-id',
      verbosity: 'low',
      responseFormat: { type: 'json_object' },
      streamOptionsIncludeUsage: true,
    });
  });

  it('normalizes typed inbound metadata without mutating upstream body', () => {
    const result = openAiChatTransformer.transformRequest({
      model: 'gpt-5',
      messages: [{ role: 'user', content: 'hello' }],
      modalities: ['text', 42, 'audio', '', null],
      audio: { voice: 'alloy', format: 'wav' },
      reasoning_effort: 'medium',
      reasoning_budget: '2048',
      reasoning_summary: 'concise',
      service_tier: 'priority',
      top_logprobs: '5',
      logit_bias: { '42': '7', invalid: 'oops' },
      prompt_cache_key: 'cache-key',
      safety_identifier: 'safety-id',
      verbosity: 'high',
      stream_options: { include_usage: 1 },
    });

    expect(result.error).toBeUndefined();
    expect(result.value).toMatchObject({
      protocol: 'openai/chat',
      model: 'gpt-5',
      stream: false,
    });
    expect(result.value?.parsed.upstreamBody).toMatchObject({
      modalities: ['text', 42, 'audio', '', null],
      reasoning_budget: '2048',
      top_logprobs: '5',
      logit_bias: { '42': '7', invalid: 'oops' },
      stream_options: { include_usage: 1 },
    });
    expect((result.value as any)?.metadata).toEqual({
      modalities: ['text', 'audio'],
      audio: { voice: 'alloy', format: 'wav' },
      reasoningEffort: 'medium',
      reasoningBudget: 2048,
      reasoningSummary: 'concise',
      serviceTier: 'priority',
      topLogprobs: 5,
      logitBias: { '42': 7 },
      promptCacheKey: 'cache-key',
      safetyIdentifier: 'safety-id',
      verbosity: 'high',
      streamOptionsIncludeUsage: true,
    });
  });
});

describe('openAiChatTransformer.outbound', () => {
  it('normalizes inline think tags in final chat responses', () => {
    const normalized = openAiChatTransformer.transformFinalResponse({
      id: 'chatcmpl-inline-think',
      model: 'gpt-5',
      created: 123,
      choices: [{
        index: 0,
        finish_reason: 'stop',
        message: {
          role: 'assistant',
          content: '<think>plan quietly</think>visible answer',
        },
      }],
    }, 'gpt-5');

    expect(normalized).toMatchObject({
      content: 'visible answer',
      reasoningContent: 'plan quietly',
      finishReason: 'stop',
    });
  });

  it('carries annotations, citations, and detailed usage through final serialization', () => {
    const normalized = openAiChatTransformer.transformFinalResponse({
      id: 'chatcmpl-1',
      model: 'gpt-5',
      created: 123,
      choices: [{
        index: 0,
        finish_reason: 'stop',
        message: {
          role: 'assistant',
          content: 'hello',
          reasoning_content: 'think',
          annotations: [
            { type: 'url_citation', url_citation: { url: 'https://a.example' } },
            { type: 'url_citation', url_citation: { url: 'https://a.example' } },
          ],
        },
      }],
      citations: ['https://c.example', 'https://c.example'],
      usage: {
        prompt_tokens: 11,
        completion_tokens: 7,
        total_tokens: 18,
        prompt_tokens_details: { cached_tokens: 3 },
        completion_tokens_details: { reasoning_tokens: 2 },
      },
    }, 'gpt-5');

    const payload = openAiChatTransformer.serializeFinalResponse(normalized, {
      promptTokens: 11,
      completionTokens: 7,
      totalTokens: 18,
    });

    const choice = (payload as any).choices[0];
    expect(choice.message.annotations).toEqual([
      { type: 'url_citation', url_citation: { url: 'https://a.example' } },
    ]);
    expect((payload as any).citations).toEqual(['https://c.example', 'https://a.example']);
    expect((payload as any).usage).toMatchObject({
      prompt_tokens: 11,
      completion_tokens: 7,
      total_tokens: 18,
      prompt_tokens_details: { cached_tokens: 3 },
      completion_tokens_details: { reasoning_tokens: 2 },
    });
  });

  it('consumes shared transformer metadata citations on openai-compatible final responses', () => {
    const normalized = openAiChatTransformer.transformFinalResponse({
      id: 'chatcmpl-shared-metadata',
      model: 'gpt-5',
      created: 123,
      transformer_metadata: toTransformerMetadataRecord({
        citations: [{ uri: 'https://shared.example/citation' }],
        thoughtSignature: 'sig-final',
        thoughtSignatures: ['sig-tool', 'sig-final'],
        passthrough: {
          cachedContent: 'cached/item-1',
        },
      }),
      choices: [{
        index: 0,
        finish_reason: 'stop',
        message: {
          role: 'assistant',
          content: 'hello',
        },
      }],
    }, 'gpt-5');

    expect((normalized as any).citations).toEqual(['https://shared.example/citation']);
  });

  it('serializes multi-choice chat responses with per-choice annotations, reasoning, tool calls, and shared citations', () => {
    const normalized = openAiChatTransformer.transformFinalResponse({
      id: 'chatcmpl-multi',
      model: 'gpt-5',
      created: 123,
      citations: ['https://shared.example', 'https://shared.example'],
      usage: {
        prompt_tokens: 21,
        completion_tokens: 9,
        total_tokens: 30,
        prompt_tokens_details: { cached_tokens: 4, audio_tokens: 1 },
        completion_tokens_details: { reasoning_tokens: 3, audio_tokens: 2 },
      },
      choices: [
        {
          index: 0,
          finish_reason: 'stop',
          message: {
            role: 'assistant',
            content: 'choice-0',
            reasoning_content: 'reason-0',
            annotations: [
              { type: 'url_citation', url_citation: { url: 'https://a.example' } },
            ],
          },
        },
        {
          index: 1,
          finish_reason: 'tool_calls',
          message: {
            role: 'assistant',
            content: '',
            reasoning_content: 'reason-1',
            tool_calls: [{
              id: 'call_1',
              type: 'function',
              function: { name: 'search', arguments: '{"q":"cat"}' },
            }],
            annotations: [
              { type: 'url_citation', url_citation: { url: 'https://b.example' } },
            ],
          },
        },
      ],
    }, 'gpt-5');

    const payload = openAiChatTransformer.serializeFinalResponse(normalized, {
      promptTokens: 21,
      completionTokens: 9,
      totalTokens: 30,
    }) as any;

    expect(payload.choices).toHaveLength(2);
    expect(payload.choices[0]).toMatchObject({
      index: 0,
      finish_reason: 'stop',
      message: {
        role: 'assistant',
        content: 'choice-0',
        reasoning_content: 'reason-0',
        annotations: [
          { type: 'url_citation', url_citation: { url: 'https://a.example' } },
        ],
      },
    });
    expect(payload.choices[1]).toMatchObject({
      index: 1,
      finish_reason: 'tool_calls',
      message: {
        role: 'assistant',
        content: '',
        reasoning_content: 'reason-1',
        tool_calls: [{
          id: 'call_1',
          type: 'function',
          function: { name: 'search', arguments: '{"q":"cat"}' },
        }],
        annotations: [
          { type: 'url_citation', url_citation: { url: 'https://b.example' } },
        ],
      },
    });
    expect(payload.citations).toEqual([
      'https://shared.example',
      'https://a.example',
      'https://b.example',
    ]);
    expect(payload.usage).toMatchObject({
      prompt_tokens_details: { cached_tokens: 4, audio_tokens: 1 },
      completion_tokens_details: { reasoning_tokens: 3, audio_tokens: 2 },
    });
  });
});

describe('openAiChatTransformer.stream', () => {
  it('preserves annotations, citations, and usage payload on serialized stream chunks', () => {
    const context = openAiChatTransformer.createStreamContext('gpt-5');
    const event = openAiChatTransformer.transformStreamEvent({
      id: 'chatcmpl-1',
      model: 'gpt-5',
      choices: [{
        index: 0,
        finish_reason: null,
        delta: {
          role: 'assistant',
          content: 'hello',
          reasoning_content: 'why',
          annotations: [
            { type: 'url_citation', url_citation: { url: 'https://a.example' } },
          ],
        },
      }],
      citations: ['https://c.example', 'https://a.example'],
      usage: {
        prompt_tokens: 11,
        completion_tokens: 7,
        total_tokens: 18,
        prompt_tokens_details: { cached_tokens: 3 },
      },
    }, context, 'gpt-5');

    const payloads = parseSsePayloads(
      openAiChatTransformer.serializeStreamEvent(event, context, createClaudeDownstreamContext()),
    );

    expect(payloads[0]).toMatchObject({
      citations: ['https://c.example', 'https://a.example'],
      usage: {
        prompt_tokens: 11,
        completion_tokens: 7,
        total_tokens: 18,
        prompt_tokens_details: { cached_tokens: 3 },
      },
    });
    expect(((payloads[0] as any).choices[0] as any).delta.annotations).toEqual([
      { type: 'url_citation', url_citation: { url: 'https://a.example' } },
    ]);
  });

  it('serializes multi-choice stream chunks without collapsing choice-specific deltas', () => {
    const context = openAiChatTransformer.createStreamContext('gpt-5');
    const event = openAiChatTransformer.transformStreamEvent({
      id: 'chatcmpl-stream-multi',
      model: 'gpt-5',
      choices: [
        {
          index: 0,
          finish_reason: null,
          delta: {
            role: 'assistant',
            content: 'choice-0',
            reasoning_content: 'reason-0',
            annotations: [
              { type: 'url_citation', url_citation: { url: 'https://a.example' } },
            ],
          },
        },
        {
          index: 1,
          finish_reason: null,
          delta: {
            role: 'assistant',
            content: 'choice-1',
            tool_calls: [{
              index: 0,
              id: 'call_1',
              type: 'function',
              function: { name: 'search', arguments: '{"q":"dog"}' },
            }],
            annotations: [
              { type: 'url_citation', url_citation: { url: 'https://b.example' } },
            ],
          },
        },
      ],
      citations: ['https://shared.example'],
      usage: {
        prompt_tokens: 11,
        completion_tokens: 7,
        total_tokens: 18,
        prompt_tokens_details: { cached_tokens: 3 },
      },
    }, context, 'gpt-5');

    const payloads = parseSsePayloads(
      openAiChatTransformer.serializeStreamEvent(event, context, createClaudeDownstreamContext()),
    );

    expect(payloads[0].choices).toHaveLength(2);
    expect((payloads[0] as any).choices[0]).toMatchObject({
      index: 0,
      delta: {
        role: 'assistant',
        content: 'choice-0',
        reasoning_content: 'reason-0',
        annotations: [
          { type: 'url_citation', url_citation: { url: 'https://a.example' } },
        ],
      },
    });
    expect((payloads[0] as any).choices[1]).toMatchObject({
      index: 1,
      delta: {
        role: 'assistant',
        content: 'choice-1',
        tool_calls: [{
          index: 0,
          id: 'call_1',
          function: { name: 'search', arguments: '{"q":"dog"}' },
        }],
        annotations: [
          { type: 'url_citation', url_citation: { url: 'https://b.example' } },
        ],
      },
    });
    expect((payloads[0] as any).citations).toEqual([
      'https://shared.example',
      'https://a.example',
      'https://b.example',
    ]);
  });

  it('normalizes inline think tags inside multi-choice stream chunks', () => {
    const context = openAiChatTransformer.createStreamContext('gpt-5');
    const event = openAiChatTransformer.transformStreamEvent({
      id: 'chatcmpl-stream-multi-think',
      model: 'gpt-5',
      choices: [
        {
          index: 0,
          finish_reason: null,
          delta: {
            role: 'assistant',
            content: '<think>plan-0</think>choice-0',
          },
        },
        {
          index: 1,
          finish_reason: null,
          delta: {
            role: 'assistant',
            content: '<think>plan-1</think>choice-1',
          },
        },
      ],
    }, context, 'gpt-5');

    const payloads = parseSsePayloads(
      openAiChatTransformer.serializeStreamEvent(event, context, createClaudeDownstreamContext()),
    );

    expect((payloads[0] as any).choices[0]).toMatchObject({
      index: 0,
      delta: {
        role: 'assistant',
        content: 'choice-0',
        reasoning_content: 'plan-0',
      },
    });
    expect((payloads[0] as any).choices[1]).toMatchObject({
      index: 1,
      delta: {
        role: 'assistant',
        content: 'choice-1',
        reasoning_content: 'plan-1',
      },
    });
  });
});

describe('openAiChatTransformer.aggregator', () => {
  it('deduplicates annotations/citations while aggregating reasoning, tool calls, and usage details', () => {
    const state = openAiChatTransformer.aggregator.createState();

    openAiChatTransformer.aggregator.applyEvent(state, {
      contentDelta: 'hel',
      reasoningDelta: 'why',
      toolCallDeltas: [{
        index: 0,
        id: 'call_1',
        name: 'search',
        argumentsDelta: '{"q":"cat"',
      }],
      annotations: [
        { type: 'url_citation', url_citation: { url: 'https://a.example' } },
      ],
      citations: ['https://c.example'],
      usageDetails: {
        prompt_tokens_details: { cached_tokens: 2 },
      },
    } as any);

    openAiChatTransformer.aggregator.applyEvent(state, {
      contentDelta: 'lo',
      reasoningDelta: ' now',
      toolCallDeltas: [{
        index: 0,
        id: 'call_1',
        name: 'search',
        argumentsDelta: ',"k":1}',
      }],
      annotations: [
        { type: 'url_citation', url_citation: { url: 'https://a.example' } },
        { type: 'url_citation', url_citation: { url: 'https://b.example' } },
      ],
      citations: ['https://c.example', 'https://d.example'],
      usageDetails: {
        completion_tokens_details: { reasoning_tokens: 4 },
      },
      finishReason: 'tool_calls',
    } as any);

    const normalized = openAiChatTransformer.aggregator.finalize(state, {
      id: 'chatcmpl-1',
      model: 'gpt-5',
      created: 123,
      content: '',
      reasoningContent: '',
      finishReason: 'stop',
      toolCalls: [],
    });

    expect(normalized).toMatchObject({
      content: 'hello',
      reasoningContent: 'why now',
      finishReason: 'tool_calls',
      toolCalls: [{
        id: 'call_1',
        name: 'search',
        arguments: '{"q":"cat","k":1}',
      }],
      citations: ['https://c.example', 'https://d.example'],
      usageDetails: {
        prompt_tokens_details: { cached_tokens: 2 },
        completion_tokens_details: { reasoning_tokens: 4 },
      },
    });
    expect((normalized as any).annotations).toEqual([
      { type: 'url_citation', url_citation: { url: 'https://a.example' } },
      { type: 'url_citation', url_citation: { url: 'https://b.example' } },
    ]);
  });

  it('aggregates stream events by choice index and preserves per-choice annotations, citations, tools, reasoning, and usage details', () => {
    const state = openAiChatTransformer.aggregator.createState();

    openAiChatTransformer.aggregator.applyEvent(state, {
      choiceIndex: 0,
      role: 'assistant',
      contentDelta: 'hello',
      reasoningDelta: 'why-0',
      annotations: [
        { type: 'url_citation', url_citation: { url: 'https://a.example' } },
      ],
      citations: ['https://shared.example'],
      usageDetails: {
        prompt_tokens_details: { cached_tokens: 2 },
      },
    } as any);

    openAiChatTransformer.aggregator.applyEvent(state, {
      choiceIndex: 1,
      role: 'assistant',
      contentDelta: 'tool-choice',
      reasoningDelta: 'why-1',
      toolCallDeltas: [{
        index: 0,
        id: 'call_1',
        name: 'search',
        argumentsDelta: '{"q":"bird"}',
      }],
      annotations: [
        { type: 'url_citation', url_citation: { url: 'https://b.example' } },
      ],
      citations: ['https://other.example'],
      usageDetails: {
        completion_tokens_details: { reasoning_tokens: 4 },
      },
      finishReason: 'tool_calls',
    } as any);

    const normalized = openAiChatTransformer.aggregator.finalize(state, {
      id: 'chatcmpl-multi',
      model: 'gpt-5',
      created: 123,
      content: '',
      reasoningContent: '',
      finishReason: 'stop',
      toolCalls: [],
    }) as any;

    expect(normalized.choices).toHaveLength(2);
    expect(normalized.choices[0]).toMatchObject({
      index: 0,
      content: 'hello',
      reasoningContent: 'why-0',
      finishReason: 'stop',
      citations: ['https://shared.example'],
      annotations: [
        { type: 'url_citation', url_citation: { url: 'https://a.example' } },
      ],
    });
    expect(normalized.choices[1]).toMatchObject({
      index: 1,
      content: 'tool-choice',
      reasoningContent: 'why-1',
      finishReason: 'tool_calls',
      toolCalls: [{
        id: 'call_1',
        name: 'search',
        arguments: '{"q":"bird"}',
      }],
      citations: ['https://other.example'],
      annotations: [
        { type: 'url_citation', url_citation: { url: 'https://b.example' } },
      ],
    });
    expect(normalized.citations).toEqual(['https://other.example', 'https://shared.example']);
    expect(normalized.usageDetails).toEqual({
      prompt_tokens_details: { cached_tokens: 2 },
      completion_tokens_details: { reasoning_tokens: 4 },
    });
  });
});
