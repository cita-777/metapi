import { describe, expect, it } from 'vitest';

import { createGeminiGenerateContentAggregateState } from './aggregator.js';
import { extractResponseMetadata, serializeGeminiAggregateResponse } from './outbound.js';
import {
  applyJsonPayloadToAggregate,
  applySsePayloadsToAggregate,
  consumeUpstreamSseBuffer,
  geminiGenerateContentStream,
  parseGeminiStreamPayload,
  serializeUpstreamJsonPayload,
  serializeAggregateSsePayload,
} from './stream.js';
import { extractGeminiUsage } from './usage.js';

describe('geminiGenerateContentStream', () => {
  it('treats stringified json payloads as json when content type is not sse', () => {
    const payload = JSON.stringify([
      {
        responseId: 'resp-json-string',
        candidates: [
          {
            index: 0,
            finishReason: 'STOP',
            content: {
              parts: [{ text: 'json-string-body' }],
            },
          },
        ],
      },
    ]);

    expect(parseGeminiStreamPayload(payload, 'application/json')).toEqual({
      format: 'json',
      events: [
        {
          responseId: 'resp-json-string',
          candidates: [
            {
              index: 0,
              finishReason: 'STOP',
              content: {
                parts: [{ text: 'json-string-body' }],
              },
            },
          ],
        },
      ],
      rest: '',
    });
  });

  it('aggregates SSE and JSON-array payloads into the same final semantics', () => {
    const requestPayload = {
      systemInstruction: { role: 'system', parts: [{ text: 'system prompt' }] },
      cachedContent: 'cached/abc',
      generationConfig: {
        responseModalities: ['TEXT'],
        responseSchema: { type: 'object' },
        responseMimeType: 'application/json',
      },
      tools: [
        { googleSearch: {} },
        { codeExecution: {} },
      ],
    };

    const chunks = [
      {
        responseId: 'resp-1',
        modelVersion: 'gemini-2.5-pro',
        candidates: [
          {
            index: 0,
            content: {
              parts: [{ text: 'thinking', thought: true, thoughtSignature: 'sig-1' }],
            },
            groundingMetadata: { webSearchQueries: ['cat'] },
            citationMetadata: { citations: [{ uri: 'https://a.example.com' }] },
          },
          {
            index: 1,
            content: {
              parts: [{ text: 'alt-answer' }],
            },
            groundingMetadata: { webSearchQueries: ['dog'] },
            citationMetadata: { citations: [{ uri: 'https://b.example.com' }] },
          },
        ],
      },
      {
        responseId: 'resp-1',
        modelVersion: 'gemini-2.5-pro',
        candidates: [
          {
            index: 0,
            finishReason: 'STOP',
            content: {
              parts: [{ text: 'answer' }],
            },
          },
          {
            index: 1,
            finishReason: 'MAX_TOKENS',
            content: {
              parts: [{ functionCall: { id: 'tool-1', name: 'lookup', args: { q: 'cat' } }, thoughtSignature: 'sig-tool-1' }],
            },
          },
        ],
        usageMetadata: {
          promptTokenCount: 10,
          candidatesTokenCount: 4,
          totalTokenCount: 16,
          cachedContentTokenCount: 3,
          thoughtsTokenCount: 2,
        },
      },
    ];

    const ssePayload = `${chunks
      .map((chunk) => `data: ${JSON.stringify(chunk)}\n\n`)
      .join('')}data: [DONE]\n\n`;

    const sseState = createGeminiGenerateContentAggregateState();
    const sseResult = applySsePayloadsToAggregate(sseState, ssePayload);

    const jsonState = createGeminiGenerateContentAggregateState();
    applyJsonPayloadToAggregate(jsonState, chunks);

    expect(sseResult.rest).toBe('');
    expect(serializeGeminiAggregateResponse(sseResult.state)).toEqual(
      serializeGeminiAggregateResponse(jsonState),
    );
    expect(extractResponseMetadata(sseResult.state, requestPayload)).toEqual(
      extractResponseMetadata(jsonState, requestPayload),
    );
    expect(extractGeminiUsage(sseResult.state)).toEqual(
      extractGeminiUsage(jsonState),
    );
    expect(serializeAggregateSsePayload(sseResult.state)).toBe(
      `data: ${JSON.stringify(serializeGeminiAggregateResponse(jsonState))}\n\n`,
    );
  });

  it('keeps trailing rest for partial SSE blocks and ignores done markers', () => {
    const state = createGeminiGenerateContentAggregateState();
    const payload = [
      'data: {"responseId":"resp-1","candidates":[{"content":{"parts":[{"text":"hello"}]}}]}',
      '',
      'data: [DONE]',
      '',
      'data: {"responseId":"resp-1"',
    ].join('\n');

    const result = applySsePayloadsToAggregate(state, payload);

    expect(result.rest).toBe('data: {"responseId":"resp-1"');
    expect(serializeGeminiAggregateResponse(result.state)).toEqual({
      responseId: 'resp-1',
      modelVersion: '',
      candidates: [
        {
          index: 0,
          finishReason: 'STOP',
          content: {
            role: 'model',
            parts: [{ text: 'hello' }],
          },
        },
      ],
    });
  });

  it('returns raw upstream sse blocks while aggregating tool-calling state', () => {
    const state = createGeminiGenerateContentAggregateState();
    const firstBlock = 'data: {"promptFeedback":{"blockReason":"BLOCK_REASON_UNSPECIFIED"},"candidates":[{"content":{"parts":[{"functionCall":{"id":"tool-1","name":"lookup","args":{"q":"cat"}},"thoughtSignature":"sig-tool-1"}]}}]}\r\n\r\n';
    const secondBlock = 'data: {"candidates":[{"content":{"parts":[{"text":"answer"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":4,"totalTokenCount":14}}\r\n\r\n';
    const doneBlock = 'data: [DONE]\r\n\r\n';
    const result = consumeUpstreamSseBuffer(
      state,
      `${firstBlock}${secondBlock}${doneBlock}data: {"responseId":"partial"`,
    );

    expect(result.lines).toEqual([firstBlock, secondBlock, doneBlock]);
    expect(result.events).toEqual([
      {
        promptFeedback: { blockReason: 'BLOCK_REASON_UNSPECIFIED' },
        candidates: [
          {
            content: {
              parts: [{ functionCall: { id: 'tool-1', name: 'lookup', args: { q: 'cat' } }, thoughtSignature: 'sig-tool-1' }],
            },
          },
        ],
      },
      {
        candidates: [
          {
            content: {
              parts: [{ text: 'answer' }],
            },
            finishReason: 'STOP',
          },
        ],
        usageMetadata: {
          promptTokenCount: 10,
          candidatesTokenCount: 4,
          totalTokenCount: 14,
        },
      },
    ]);
    expect(result.rest).toBe('data: {"responseId":"partial"');
    expect(extractGeminiUsage(result.state)).toEqual({
      promptTokens: 10,
      completionTokens: 4,
      totalTokens: 14,
      cachedTokens: 0,
      cacheReadTokens: 0,
      cacheCreationTokens: 0,
      reasoningTokens: 0,
    });
  });

  it('normalizes object payloads through the JSON-array path', () => {
    const state = createGeminiGenerateContentAggregateState();

    applyJsonPayloadToAggregate(state, {
      responseId: 'resp-2',
      candidates: [
        {
          index: 0,
          finishReason: 'STOP',
          content: {
            parts: [{ text: 'single-object' }],
          },
        },
      ],
    });

    expect(geminiGenerateContentStream.parseJsonArrayPayload({
      responseId: 'resp-2',
    })).toEqual([{ responseId: 'resp-2' }]);
    expect(serializeGeminiAggregateResponse(state)).toEqual({
      responseId: 'resp-2',
      modelVersion: '',
      candidates: [
        {
          index: 0,
          finishReason: 'STOP',
          content: {
            role: 'model',
            parts: [{ text: 'single-object' }],
          },
        },
      ],
    });
  });

  it('keeps json stream chunks raw while still aggregating usage', () => {
    const state = createGeminiGenerateContentAggregateState();
    const payload = [
      {
        promptFeedback: { blockReason: 'BLOCK_REASON_UNSPECIFIED' },
        candidates: [
          {
            content: {
              parts: [{ functionCall: { id: 'tool-1', name: 'lookup', args: { q: 'cat' } } }],
            },
          },
        ],
      },
      {
        serverContent: { modelTurn: { parts: [{ text: 'tool result received' }] } },
        candidates: [
          {
            content: {
              parts: [{ text: 'final answer' }],
            },
            finishReason: 'STOP',
          },
        ],
        usageMetadata: {
          promptTokenCount: 8,
          candidatesTokenCount: 5,
          totalTokenCount: 13,
        },
      },
    ];

    expect(serializeUpstreamJsonPayload(state, payload, true)).toEqual(payload);
    expect(extractGeminiUsage(state)).toEqual({
      promptTokens: 8,
      completionTokens: 5,
      totalTokens: 13,
      cachedTokens: 0,
      cacheReadTokens: 0,
      cacheCreationTokens: 0,
      reasoningTokens: 0,
    });
  });
});
