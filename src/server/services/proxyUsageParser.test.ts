import { describe, expect, it } from 'vitest';
import {
  hasProxyUsagePayload,
  mergeProxyUsage,
  parseProxyUsage,
  pullSseDataEvents,
} from './proxyUsageParser.js';

describe('proxyUsageParser', () => {
  it('parses standard OpenAI usage fields', () => {
    const usage = parseProxyUsage({
      usage: {
        prompt_tokens: 123,
        completion_tokens: 45,
        total_tokens: 168,
      },
    });

    expect(usage).toEqual({
      promptTokens: 123,
      completionTokens: 45,
      totalTokens: 168,
      cacheReadTokens: 0,
      cacheCreationTokens: 0,
      promptTokensIncludeCache: null,
    });
  });

  it('parses input/output token style usage fields', () => {
    const usage = parseProxyUsage({
      usage: {
        input_tokens: 80,
        output_tokens: 20,
      },
    });

    expect(usage).toEqual({
      promptTokens: 80,
      completionTokens: 20,
      totalTokens: 100,
      cacheReadTokens: 0,
      cacheCreationTokens: 0,
      promptTokensIncludeCache: null,
    });
  });

  it('parses Gemini usageMetadata shape', () => {
    const usage = parseProxyUsage({
      usageMetadata: {
        promptTokenCount: 12,
        candidatesTokenCount: 34,
        totalTokenCount: 46,
      },
    });

    expect(usage).toEqual({
      promptTokens: 12,
      completionTokens: 34,
      totalTokens: 46,
      cacheReadTokens: 0,
      cacheCreationTokens: 0,
      promptTokensIncludeCache: null,
    });
  });

  it('parses deeply nested usage payloads', () => {
    const usage = parseProxyUsage({
      data: {
        result: {
          response: {
            usage: {
              prompt_tokens: 210,
              completion_tokens: 40,
              total_tokens: 250,
            },
          },
        },
      },
    });

    expect(usage).toEqual({
      promptTokens: 210,
      completionTokens: 40,
      totalTokens: 250,
      cacheReadTokens: 0,
      cacheCreationTokens: 0,
      promptTokensIncludeCache: null,
    });
  });

  it('falls back to usage detail objects when aggregate fields are absent', () => {
    const usage = parseProxyUsage({
      usage: {
        prompt_tokens_details: {
          text_tokens: 7,
          cached_tokens: 3,
        },
        completion_tokens_details: {
          reasoning_tokens: 20,
        },
      },
    });

    expect(usage).toEqual({
      promptTokens: 10,
      completionTokens: 20,
      totalTokens: 30,
      cacheReadTokens: 3,
      cacheCreationTokens: 0,
      promptTokensIncludeCache: true,
    });
  });

  it('parses anthropic cache usage fields without treating input tokens as cache-inclusive', () => {
    const usage = parseProxyUsage({
      usage: {
        input_tokens: 120,
        output_tokens: 30,
        cache_read_input_tokens: 1000,
        cache_creation_input_tokens: 40,
      },
    });

    expect(usage).toEqual({
      promptTokens: 120,
      completionTokens: 30,
      totalTokens: 150,
      cacheReadTokens: 1000,
      cacheCreationTokens: 40,
      promptTokensIncludeCache: false,
    });
  });

  it('merges usage snapshots by keeping richer values', () => {
    const merged = mergeProxyUsage(
      {
        promptTokens: 0,
        completionTokens: 0,
        totalTokens: 0,
        cacheReadTokens: 0,
        cacheCreationTokens: 0,
        promptTokensIncludeCache: null,
      },
      {
        promptTokens: 90,
        completionTokens: 30,
        totalTokens: 120,
        cacheReadTokens: 0,
        cacheCreationTokens: 0,
        promptTokensIncludeCache: null,
      },
    );

    expect(merged).toEqual({
      promptTokens: 90,
      completionTokens: 30,
      totalTokens: 120,
      cacheReadTokens: 0,
      cacheCreationTokens: 0,
      promptTokensIncludeCache: null,
    });
  });

  it('does not treat null placeholders as explicit upstream usage', () => {
    expect(hasProxyUsagePayload({
      usage: {
        total_tokens: null,
        cache_creation: {},
      },
    })).toBe(false);
  });

  it('treats explicit zero usage values as upstream usage', () => {
    expect(hasProxyUsagePayload({
      usage: {
        total_tokens: 0,
      },
    })).toBe(true);
    expect(hasProxyUsagePayload({
      usage: {
        prompt_tokens_details: {
          cached_tokens: 0,
        },
      },
    })).toBe(true);
  });

  it('pulls SSE data events across chunk boundaries', () => {
    const first = pullSseDataEvents('data: {"a":1}\n\ndata: {"b":');
    expect(first.events).toEqual(['{"a":1}']);
    expect(first.rest).toBe('data: {"b":');

    const second = pullSseDataEvents(`${first.rest}2}\n\ndata: [DONE]\n\n`);
    expect(second.events).toEqual(['{"b":2}']);
    expect(second.rest).toBe('');
  });
});
