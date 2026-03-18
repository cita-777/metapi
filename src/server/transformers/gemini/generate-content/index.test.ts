import { describe, expect, it } from 'vitest';

import {
  geminiGenerateContentTransformer,
  reasoningEffortToGeminiThinkingConfig,
  geminiThinkingConfigToReasoning,
} from './index.js';
import { extractGeminiUsage } from './usage.js';
import { serializeGeminiAggregateResponse, extractResponseMetadata } from './outbound.js';
import { resolveGeminiThinkingConfigFromRequest } from './convert.js';
import {
  parseGeminiStreamPayload,
  serializeAggregateJsonPayload,
  serializeAggregatePayload,
} from './stream.js';

describe('geminiGenerateContentTransformer.inbound', () => {
  it('parses native Gemini requests into canonical envelopes', () => {
    const result = geminiGenerateContentTransformer.parseRequest({
      model: 'gemini-2.5-pro',
      contents: [
        {
          role: 'user',
          parts: [{ text: 'hello' }],
        },
      ],
      generationConfig: {
        thinkingConfig: {
          thinkingBudget: 512,
        },
      },
    });

    expect(result.error).toBeUndefined();
    expect(result.value).toMatchObject({
      operation: 'generate',
      surface: 'gemini-generate-content',
      cliProfile: 'generic',
      requestedModel: 'gemini-2.5-pro',
      stream: false,
      messages: [
        {
          role: 'user',
          parts: [{ type: 'text', text: 'hello' }],
        },
      ],
      reasoning: {
        budgetTokens: 512,
      },
    });
  });

  it('builds native Gemini requests from canonical envelopes', () => {
    const body = geminiGenerateContentTransformer.buildProtocolRequest({
      operation: 'generate',
      surface: 'gemini-generate-content',
      cliProfile: 'gemini_cli',
      requestedModel: 'gemini-2.5-pro',
      stream: false,
      messages: [{ role: 'user', parts: [{ type: 'text', text: 'hello' }] }],
      reasoning: {
        budgetTokens: 512,
      },
      tools: [{ name: 'lookup', inputSchema: { type: 'object' } }],
      toolChoice: 'required',
    });

    expect(body).toMatchObject({
      contents: [
        {
          role: 'user',
          parts: [{ text: 'hello' }],
        },
      ],
      tools: [
        {
          functionDeclarations: [
            {
              name: 'lookup',
              parameters: { type: 'object' },
            },
          ],
        },
      ],
      toolConfig: {
        functionCallingConfig: {
          mode: 'ANY',
        },
      },
      generationConfig: {
        thinkingConfig: {
          thinkingBudget: 512,
        },
      },
    });
  });

  it('preserves native Gemini request fields through normalization', () => {
    const body = geminiGenerateContentTransformer.inbound.normalizeRequest({
      contents: [
        {
          role: 'user',
          parts: [{ text: 'hello' }],
        },
      ],
      systemInstruction: {
        role: 'system',
        parts: [{ text: 'system prompt' }],
      },
      cachedContent: 'cached/abc',
      generationConfig: {
        responseModalities: ['TEXT'],
        responseMimeType: 'application/json',
        responseSchema: {
          type: 'object',
          properties: {
            answer: { type: 'string' },
          },
        },
        thinkingConfig: {
          thinkingBudget: 512,
        },
        imageConfig: {
          aspectRatio: '1:1',
        },
      },
      tools: [
        {
          functionDeclarations: [
            {
              name: 'lookup',
              description: 'find facts',
            },
          ],
        },
        { googleSearch: {} },
        { urlContext: {} },
        { codeExecution: {} },
      ],
    });

    expect(body).toEqual({
      contents: [
        {
          role: 'user',
          parts: [{ text: 'hello' }],
        },
      ],
      systemInstruction: {
        role: 'system',
        parts: [{ text: 'system prompt' }],
      },
      cachedContent: 'cached/abc',
      generationConfig: {
        responseModalities: ['TEXT'],
        responseMimeType: 'application/json',
        responseSchema: {
          type: 'object',
          properties: {
            answer: { type: 'string' },
          },
        },
        thinkingConfig: {
          thinkingBudget: 512,
        },
        imageConfig: {
          aspectRatio: '1:1',
        },
      },
      tools: [
        {
          functionDeclarations: [
            {
              name: 'lookup',
              description: 'find facts',
            },
          ],
        },
        { googleSearch: {} },
        { urlContext: {} },
        { codeExecution: {} },
      ],
    });
  });

  it('uses thinkingLevel for Gemini 3 reasoning budgets within standard ranges and preserves very high budgets', () => {
    const standardBudget = geminiGenerateContentTransformer.inbound.normalizeRequest(
      {
        generationConfig: {},
        reasoning_budget: 1024,
      },
      'gemini-3-pro',
    );

    expect(standardBudget.generationConfig).toEqual({
      thinkingConfig: {
        thinkingLevel: 'low',
        includeThoughts: true,
      },
    });

    const higherBudget = geminiGenerateContentTransformer.inbound.normalizeRequest(
      {
        generationConfig: {},
        reasoning: {
          budget_tokens: 12000,
        },
      },
      'gemini-3-pro',
    );

    expect(higherBudget.generationConfig).toEqual({
      thinkingConfig: {
        thinkingBudget: 12000,
        includeThoughts: true,
      },
    });
  });

  it('prefers thinkingLevel for Gemini 3.1 standard reasoning budgets and preserves non-standard budgets', () => {
    const standardBudgetBody = geminiGenerateContentTransformer.inbound.normalizeRequest(
      {
        generationConfig: {},
        reasoning: {
          budget_tokens: 1024,
        },
      },
      'gemini-3.1-pro-preview',
    );

    expect(standardBudgetBody.generationConfig).toEqual({
      thinkingConfig: {
        thinkingLevel: 'low',
        includeThoughts: true,
      },
    });

    const nonStandardBudgetBody = geminiGenerateContentTransformer.inbound.normalizeRequest(
      {
        generationConfig: {},
        reasoning: {
          budget_tokens: 50000,
        },
      },
      'gemini-3-flash',
    );

    expect(nonStandardBudgetBody.generationConfig).toEqual({
      thinkingConfig: {
        thinkingBudget: 50000,
        includeThoughts: true,
      },
    });
  });

  it('normalizes native thinking config and keeps request metadata stable when injecting derived thinking config', () => {
    const body = geminiGenerateContentTransformer.inbound.normalizeRequest(
      {
        model: 'gemini-3-pro',
        contents: [
          {
            role: 'user',
            parts: [{ text: 'hello' }],
          },
        ],
        systemInstruction: {
          role: 'system',
          parts: [{ text: 'system prompt' }],
        },
        cachedContent: 'cached/abc',
        generationConfig: {
          responseModalities: ['TEXT', 'AUDIO'],
          responseMimeType: 'application/json',
          thinkingConfig: {
            thinkingLevel: 'minimal',
          },
        },
        tools: [
          { googleSearch: {} },
          { urlContext: {} },
          { codeExecution: {} },
        ],
        reasoning_effort: 'high',
        reasoning_budget: 4096,
      },
      'gemini-3-pro',
    );

    expect(body.systemInstruction).toEqual({
      role: 'system',
      parts: [{ text: 'system prompt' }],
    });
    expect(body.cachedContent).toBe('cached/abc');
    expect(body.tools).toEqual([
      { googleSearch: {} },
      { urlContext: {} },
      { codeExecution: {} },
    ]);
    expect(body.generationConfig).toEqual({
      responseModalities: ['TEXT', 'AUDIO'],
      responseMimeType: 'application/json',
      thinkingConfig: {
        thinkingLevel: 'low',
      },
    });
    expect(body.reasoning_effort).toBeUndefined();
    expect(body.reasoning_budget).toBeUndefined();
  });
});

describe('geminiGenerateContentTransformer.aggregator', () => {
  it('collects grounding metadata, citations, thought signatures, and usage from streamed chunks', () => {
    const state = geminiGenerateContentTransformer.aggregator.createState();

    geminiGenerateContentTransformer.aggregator.apply(state, [
      {
        candidates: [
          {
            groundingMetadata: { webSearchQueries: ['cat'] },
            citationMetadata: { citations: [{ uri: 'https://example.com' }] },
            content: {
              parts: [
                { text: 'hello', thoughtSignature: 'sig-1' },
              ],
            },
          },
        ],
        usageMetadata: {
          promptTokenCount: 10,
          candidatesTokenCount: 4,
          totalTokenCount: 14,
          cachedContentTokenCount: 3,
          thoughtsTokenCount: 2,
        },
      },
    ]);

    expect(state.groundingMetadata).toEqual([{ webSearchQueries: ['cat'] }]);
    expect(state.citations).toEqual([{ citations: [{ uri: 'https://example.com' }] }]);
    expect(state.thoughtSignatures).toEqual(['sig-1']);
    expect(state.usage).toEqual({
      promptTokenCount: 10,
      candidatesTokenCount: 4,
      totalTokenCount: 14,
      cachedContentTokenCount: 3,
      thoughtsTokenCount: 2,
    });
  });

  it('serializes aggregate state back into Gemini response semantics', () => {
    const state = geminiGenerateContentTransformer.aggregator.createState();
    geminiGenerateContentTransformer.aggregator.apply(state, {
      responseId: 'resp-1',
      modelVersion: 'gemini-2.5-pro',
      candidates: [
        {
          groundingMetadata: { webSearchQueries: ['cat'] },
          citationMetadata: { citations: [{ uri: 'https://example.com' }] },
          content: {
            parts: [
              { text: 'thinking', thought: true, thoughtSignature: 'sig-1' },
              { text: 'answer' },
            ],
          },
          finishReason: 'STOP',
        },
      ],
      usageMetadata: {
        promptTokenCount: 10,
        candidatesTokenCount: 4,
        totalTokenCount: 14,
        cachedContentTokenCount: 3,
        thoughtsTokenCount: 2,
      },
    });

    const response = serializeGeminiAggregateResponse(state);
    expect(response).toEqual({
      responseId: 'resp-1',
      modelVersion: 'gemini-2.5-pro',
      candidates: [
        {
          index: 0,
          finishReason: 'STOP',
          content: {
            role: 'model',
            parts: [
              { text: 'thinking', thought: true, thoughtSignature: 'sig-1' },
              { text: 'answer' },
            ],
          },
          groundingMetadata: { webSearchQueries: ['cat'] },
          citationMetadata: { citations: [{ uri: 'https://example.com' }] },
        },
      ],
      usageMetadata: {
        promptTokenCount: 10,
        candidatesTokenCount: 4,
        totalTokenCount: 14,
        cachedContentTokenCount: 3,
        thoughtsTokenCount: 2,
      },
    });

    expect(extractResponseMetadata(state)).toEqual({
      citations: [{ citations: [{ uri: 'https://example.com' }] }],
      groundingMetadata: [{ webSearchQueries: ['cat'] }],
      thoughtSignature: 'sig-1',
      thoughtSignatures: ['sig-1'],
      usageMetadata: {
        promptTokenCount: 10,
        candidatesTokenCount: 4,
        totalTokenCount: 14,
        cachedContentTokenCount: 3,
        thoughtsTokenCount: 2,
      },
    });
  });

  it('preserves multiple candidate streams instead of collapsing them into one candidate', () => {
    const state = geminiGenerateContentTransformer.aggregator.createState();
    geminiGenerateContentTransformer.aggregator.apply(state, {
      responseId: 'resp-multi',
      modelVersion: 'gemini-2.5-pro',
      candidates: [
        {
          index: 0,
          content: {
            parts: [{ text: 'candidate-a' }],
          },
          finishReason: 'STOP',
          groundingMetadata: { webSearchQueries: ['a'] },
          citationMetadata: { citations: [{ uri: 'https://a.example.com' }] },
        },
        {
          index: 1,
          content: {
            parts: [{ text: 'candidate-b' }],
          },
          finishReason: 'MAX_TOKENS',
          groundingMetadata: { webSearchQueries: ['b'] },
          citationMetadata: { citations: [{ uri: 'https://b.example.com' }] },
        },
      ],
    });

    expect(serializeGeminiAggregateResponse(state)).toEqual({
      responseId: 'resp-multi',
      modelVersion: 'gemini-2.5-pro',
      candidates: [
        {
          index: 0,
          finishReason: 'STOP',
          content: {
            role: 'model',
            parts: [{ text: 'candidate-a' }],
          },
          groundingMetadata: { webSearchQueries: ['a'] },
          citationMetadata: { citations: [{ uri: 'https://a.example.com' }] },
        },
        {
          index: 1,
          finishReason: 'MAX_TOKENS',
          content: {
            role: 'model',
            parts: [{ text: 'candidate-b' }],
          },
          groundingMetadata: { webSearchQueries: ['b'] },
          citationMetadata: { citations: [{ uri: 'https://b.example.com' }] },
        },
      ],
    });
  });

  it('merges preserved request semantics into extracted metadata when provided', () => {
    const metadata = extractResponseMetadata(
      {
        candidates: [
          {
            groundingMetadata: { webSearchQueries: ['cat'] },
            citationMetadata: { citations: [{ uri: 'https://example.com' }] },
            content: {
              parts: [{ text: 'answer', thoughtSignature: 'sig-1' }],
            },
          },
        ],
      },
      {
        systemInstruction: { role: 'system', parts: [{ text: 'system prompt' }] },
        cachedContent: 'cached/abc',
        generationConfig: {
          responseModalities: ['TEXT'],
          responseSchema: { type: 'object' },
          responseMimeType: 'application/json',
        },
        tools: [
          { googleSearch: {} },
          { urlContext: {} },
          { codeExecution: {} },
        ],
      },
    );

    expect(metadata.systemInstruction).toEqual({ role: 'system', parts: [{ text: 'system prompt' }] });
    expect(metadata.cachedContent).toBe('cached/abc');
    expect(metadata.responseModalities).toEqual(['TEXT']);
    expect(metadata.responseSchema).toEqual({ type: 'object' });
    expect(metadata.responseMimeType).toBe('application/json');
    expect(metadata.tools).toEqual([
      { googleSearch: {} },
      { urlContext: {} },
      { codeExecution: {} },
    ]);
  });

  it('preserves tool thought signatures and request-side Gemini metadata in outbound helpers', () => {
    const state = geminiGenerateContentTransformer.aggregator.createState();
    geminiGenerateContentTransformer.aggregator.apply(state, {
      responseId: 'resp-tools',
      modelVersion: 'gemini-3-pro',
      candidates: [
        {
          index: 0,
          finishReason: 'STOP',
          content: {
            parts: [
              {
                functionCall: {
                  id: 'call-1',
                  name: 'lookup',
                  args: { query: 'cat' },
                },
                thoughtSignature: 'tool-sig-1',
              },
            ],
          },
          groundingMetadata: { webSearchQueries: ['cat'] },
          citationMetadata: { citations: [{ uri: 'https://example.com/cat' }] },
        },
      ],
      usageMetadata: {
        promptTokenCount: 12,
        candidatesTokenCount: 4,
        totalTokenCount: 18,
        cachedContentTokenCount: 6,
        thoughtsTokenCount: 2,
      },
    });

    expect(serializeGeminiAggregateResponse(state)).toEqual({
      responseId: 'resp-tools',
      modelVersion: 'gemini-3-pro',
      candidates: [
        {
          index: 0,
          finishReason: 'STOP',
          content: {
            role: 'model',
            parts: [
              {
                functionCall: {
                  id: 'call-1',
                  name: 'lookup',
                  args: { query: 'cat' },
                },
                thoughtSignature: 'tool-sig-1',
              },
            ],
          },
          groundingMetadata: { webSearchQueries: ['cat'] },
          citationMetadata: { citations: [{ uri: 'https://example.com/cat' }] },
        },
      ],
      usageMetadata: {
        promptTokenCount: 12,
        candidatesTokenCount: 4,
        totalTokenCount: 18,
        cachedContentTokenCount: 6,
        thoughtsTokenCount: 2,
      },
    });

    expect(extractResponseMetadata(state, {
      systemInstruction: { role: 'system', parts: [{ text: 'system prompt' }] },
      cachedContent: 'cached/tooling',
      safetySettings: [{ category: 'HARM_CATEGORY_DANGEROUS_CONTENT', threshold: 'BLOCK_ONLY_HIGH' }],
      toolConfig: {
        functionCallingConfig: {
          mode: 'ANY',
          allowedFunctionNames: ['lookup'],
        },
      },
      generationConfig: {
        responseModalities: ['TEXT'],
        responseSchema: { type: 'object' },
        responseMimeType: 'application/json',
        thinkingConfig: { thinkingLevel: 'high' },
        imageConfig: { aspectRatio: '1:1' },
      },
      tools: [
        { functionDeclarations: [{ name: 'lookup', description: 'find facts' }] },
        { googleSearch: {} },
      ],
    })).toEqual({
      systemInstruction: { role: 'system', parts: [{ text: 'system prompt' }] },
      cachedContent: 'cached/tooling',
      safetySettings: [{ category: 'HARM_CATEGORY_DANGEROUS_CONTENT', threshold: 'BLOCK_ONLY_HIGH' }],
      toolConfig: {
        functionCallingConfig: {
          mode: 'ANY',
          allowedFunctionNames: ['lookup'],
        },
      },
      responseModalities: ['TEXT'],
      responseSchema: { type: 'object' },
      responseMimeType: 'application/json',
      thinkingConfig: { thinkingLevel: 'high' },
      imageConfig: { aspectRatio: '1:1' },
      tools: [
        { functionDeclarations: [{ name: 'lookup', description: 'find facts' }] },
        { googleSearch: {} },
      ],
      citations: [{ citations: [{ uri: 'https://example.com/cat' }] }],
      groundingMetadata: [{ webSearchQueries: ['cat'] }],
      thoughtSignature: 'tool-sig-1',
      thoughtSignatures: ['tool-sig-1'],
      usageMetadata: {
        promptTokenCount: 12,
        candidatesTokenCount: 4,
        totalTokenCount: 18,
        cachedContentTokenCount: 6,
        thoughtsTokenCount: 2,
      },
    });
  });
});

describe('extractGeminiUsage', () => {
  it('maps cached and thought token counts into normalized usage', () => {
    expect(extractGeminiUsage({
      usageMetadata: {
        promptTokenCount: 11,
        candidatesTokenCount: 7,
        totalTokenCount: 18,
        cachedContentTokenCount: 5,
        thoughtsTokenCount: 3,
      },
    })).toEqual({
      promptTokens: 11,
      completionTokens: 10,
      totalTokens: 18,
      cachedTokens: 5,
      cacheReadTokens: 5,
      cacheCreationTokens: 0,
      reasoningTokens: 3,
    });
  });
});

describe('Gemini reasoning mapping', () => {
  it('supports explicit none reasoning effort and maps it back from thinking config', () => {
    expect(reasoningEffortToGeminiThinkingConfig('gemini-3-5m', 'none')).toEqual({
      thinkingLevel: 'none',
    });

    expect(geminiThinkingConfigToReasoning({
      thinkingLevel: 'none',
    })).toEqual({
      reasoningEffort: 'none',
      reasoningBudget: 0,
    });
  });

  it('uses thinkingLevel for Gemini 3 models when reasoning effort is provided', () => {
    expect(reasoningEffortToGeminiThinkingConfig('gemini-3-5m', 'high')).toEqual({
      thinkingLevel: 'high',
    });
  });

  it('uses thinkingBudget for non-Gemini 3 models when reasoning effort is provided', () => {
    expect(reasoningEffortToGeminiThinkingConfig('gemini-2.5-flash', 'medium')).toEqual({
      thinkingBudget: 8192,
    });
  });

  it('uses thinkingLevel for Gemini 3 budget values up to the high tier and preserves very high budgets', () => {
    expect(resolveGeminiThinkingConfigFromRequest('gemini-3-pro', {
      reasoning_budget: 8192,
    })).toEqual({
      thinkingLevel: 'medium',
      includeThoughts: true,
    });

    expect(resolveGeminiThinkingConfigFromRequest('gemini-3-pro', {
      reasoning_budget: 12000,
    })).toEqual({
      thinkingBudget: 12000,
      includeThoughts: true,
    });
  });

  it('injects derived thinking config into normalized requests when runtime model name is provided', () => {
    const body = geminiGenerateContentTransformer.inbound.normalizeRequest(
      {
        contents: [{ role: 'user', parts: [{ text: 'hello' }] }],
        generationConfig: {
          responseModalities: ['TEXT'],
          thinkingConfig: {},
        },
        reasoning_effort: 'high',
      },
      'gemini-3-pro',
    );

    expect(body.generationConfig).toEqual({
      responseModalities: ['TEXT'],
      thinkingConfig: {
        thinkingLevel: 'high',
        includeThoughts: true,
      },
    });
  });

  it('maps Gemini thinking config back to normalized reasoning hints', () => {
    expect(geminiThinkingConfigToReasoning({
      thinkingLevel: 'medium',
    })).toEqual({
      reasoningEffort: 'medium',
      reasoningBudget: 8192,
    });

    expect(geminiThinkingConfigToReasoning({
      thinkingBudget: 512,
    })).toEqual({
      reasoningEffort: 'low',
      reasoningBudget: 512,
    });
  });

  it('uses thinkingLevel for Gemini 3 models when reasoning_budget is a standard tier', () => {
    const normalized = geminiGenerateContentTransformer.inbound.normalizeRequest(
      {
        contents: [{ role: 'user', parts: [{ text: 'hello' }] }],
        reasoning_budget: 8192,
      },
      'gemini-3-flash',
    );

    expect(normalized.generationConfig).toEqual({
      thinkingConfig: {
        thinkingLevel: 'medium',
        includeThoughts: true,
      },
    });
  });

  it('preserves non-standard Gemini 3 reasoning_budget values instead of coercing them to a tier', () => {
    const normalized = geminiGenerateContentTransformer.inbound.normalizeRequest(
      {
        contents: [{ role: 'user', parts: [{ text: 'hello' }] }],
        reasoning_budget: 5000,
      },
      'gemini-3-flash',
    );

    expect(normalized.generationConfig).toEqual({
      thinkingConfig: {
        thinkingBudget: 5000,
        includeThoughts: true,
      },
    });
  });

  it('fills missing native thinkingConfig from reasoning_effort while preserving request metadata', () => {
    const normalized = geminiGenerateContentTransformer.inbound.normalizeRequest(
      {
        cachedContent: 'cached/abc',
        generationConfig: {
          responseModalities: ['TEXT'],
          thinkingConfig: {
            includeThoughts: true,
          },
        },
        reasoning_effort: 'high',
      },
      'gemini-3-flash',
    );

    expect(normalized.cachedContent).toBe('cached/abc');
    expect(normalized.generationConfig).toEqual({
      responseModalities: ['TEXT'],
      thinkingConfig: {
        includeThoughts: true,
        thinkingLevel: 'high',
      },
    });
  });

  it('preserves non-standard explicit Gemini 3 budgets instead of coercing them to a standard effort level', () => {
    expect(
      geminiGenerateContentTransformer.inbound.normalizeRequest(
        {
          reasoning_budget: 50000,
        },
        'gemini-3-pro',
      ),
    ).toEqual({
      generationConfig: {
        thinkingConfig: {
          thinkingBudget: 50000,
          includeThoughts: true,
        },
      },
    });
  });
});

describe('Gemini convert/inbound runtime strategy', () => {
  it('uses thinkingLevel only for standard Gemini 3 budget tiers and preserves non-standard budgets', () => {
    expect(resolveGeminiThinkingConfigFromRequest('gemini-3-pro', {
      reasoning_budget: 1024,
    })).toEqual({
      thinkingLevel: 'low',
      includeThoughts: true,
    });

    expect(resolveGeminiThinkingConfigFromRequest('gemini-3-pro', {
      reasoning_budget: 512,
    })).toEqual({
      thinkingBudget: 512,
      includeThoughts: true,
    });
  });

  it('prefers the runtime model name when injecting thinkingConfig and keeps request metadata stable', () => {
    const normalized = geminiGenerateContentTransformer.inbound.normalizeRequest(
      {
        model: 'gemini-2.5-flash',
        cachedContent: 'cached/runtime',
        systemInstruction: {
          role: 'system',
          parts: [{ text: 'system prompt' }],
        },
        generationConfig: {
          responseModalities: ['TEXT'],
        },
        reasoning_budget: 512,
      },
      'gemini-3-pro',
    );

    expect(normalized.cachedContent).toBe('cached/runtime');
    expect(normalized.systemInstruction).toEqual({
      role: 'system',
      parts: [{ text: 'system prompt' }],
    });
    expect(normalized.generationConfig).toEqual({
      responseModalities: ['TEXT'],
      thinkingConfig: {
        thinkingBudget: 512,
        includeThoughts: true,
      },
    });
  });
});

describe('geminiGenerateContentTransformer.stream', () => {
  it('aggregates SSE payloads and JSON-array payloads to the same final semantics', () => {
    const chunks = [
      {
        responseId: 'resp-1',
        modelVersion: 'gemini-2.5-pro',
        candidates: [
          {
            groundingMetadata: { webSearchQueries: ['cat'] },
            citationMetadata: { citations: [{ uri: 'https://example.com' }] },
            content: {
              parts: [
                { text: 'thinking', thought: true, thoughtSignature: 'sig-1' },
              ],
            },
            finishReason: '',
          },
        ],
      },
      {
        responseId: 'resp-1',
        modelVersion: 'gemini-2.5-pro',
        candidates: [
          {
            groundingMetadata: { webSearchQueries: ['cat'] },
            citationMetadata: { citations: [{ uri: 'https://example.com' }] },
            content: {
              parts: [
                { text: 'answer' },
              ],
            },
            finishReason: 'STOP',
          },
        ],
        usageMetadata: {
          promptTokenCount: 10,
          candidatesTokenCount: 4,
          totalTokenCount: 14,
          cachedContentTokenCount: 3,
          thoughtsTokenCount: 2,
        },
      },
    ];

    const ssePayload = chunks
      .map((chunk) => `data: ${JSON.stringify(chunk)}\n\n`)
      .join('');

    const sseParsed = geminiGenerateContentTransformer.stream.parseSsePayloads(ssePayload);
    const sseState = geminiGenerateContentTransformer.aggregator.createState();
    for (const payload of sseParsed.events) {
      geminiGenerateContentTransformer.aggregator.apply(sseState, payload);
    }

    const jsonState = geminiGenerateContentTransformer.aggregator.createState();
    for (const payload of geminiGenerateContentTransformer.stream.parseJsonArrayPayload(chunks)) {
      geminiGenerateContentTransformer.aggregator.apply(jsonState, payload);
    }

    expect(serializeGeminiAggregateResponse(sseState)).toEqual(
      serializeGeminiAggregateResponse(jsonState),
    );
    expect(extractResponseMetadata(sseState)).toEqual(
      extractResponseMetadata(jsonState),
    );
    expect(extractGeminiUsage(sseState)).toEqual(
      extractGeminiUsage(jsonState),
    );
  });

  it('normalizes SSE and JSON-array payloads through the same parse/apply boundary', () => {
    const chunks = [
      {
        responseId: 'resp-boundary',
        modelVersion: 'gemini-2.5-pro',
        candidates: [
          {
            index: 0,
            content: {
              parts: [{ text: 'hello', thought: true, thoughtSignature: 'sig-a' }],
            },
            groundingMetadata: { webSearchQueries: ['cat'] },
            citationMetadata: { citations: [{ uri: 'https://example.com/a' }] },
          },
        ],
      },
      {
        responseId: 'resp-boundary',
        modelVersion: 'gemini-2.5-pro',
        candidates: [
          {
            index: 0,
            finishReason: 'STOP',
            content: {
              parts: [{ text: 'world' }],
            },
          },
        ],
        usageMetadata: {
          promptTokenCount: 10,
          candidatesTokenCount: 4,
          totalTokenCount: 14,
          cachedContentTokenCount: 3,
          thoughtsTokenCount: 2,
        },
      },
    ];

    const sseInput = chunks.map((chunk) => `data: ${JSON.stringify(chunk)}\n\n`).join('');
    const parsedSse = parseGeminiStreamPayload(sseInput, 'text/event-stream');
    const parsedJson = parseGeminiStreamPayload(chunks, 'application/json');

    expect(parsedSse.events).toEqual(parsedJson.events);
    expect(parsedSse.rest).toBe('');
    expect(parsedJson.rest).toBe('');

    const sseState = geminiGenerateContentTransformer.stream.createAggregateState();
    const jsonState = geminiGenerateContentTransformer.stream.createAggregateState();
    geminiGenerateContentTransformer.stream.applyParsedPayloadToAggregate(sseState, parsedSse);
    geminiGenerateContentTransformer.stream.applyParsedPayloadToAggregate(jsonState, parsedJson);

    expect(serializeGeminiAggregateResponse(sseState)).toEqual(
      serializeGeminiAggregateResponse(jsonState),
    );
  });

  it('serializes aggregate payloads with identical final semantics for SSE and JSON modes', () => {
    const state = geminiGenerateContentTransformer.aggregator.createState();
    geminiGenerateContentTransformer.aggregator.apply(state, {
      responseId: 'resp-serialize',
      modelVersion: 'gemini-2.5-pro',
      candidates: [
        {
          index: 0,
          finishReason: 'STOP',
          content: {
            parts: [{ text: 'answer', thoughtSignature: 'sig-final' }],
          },
        },
      ],
      usageMetadata: {
        promptTokenCount: 9,
        candidatesTokenCount: 5,
        totalTokenCount: 14,
        cachedContentTokenCount: 4,
        thoughtsTokenCount: 1,
      },
    });

    const jsonPayload = serializeAggregateJsonPayload(state);
    const ssePayload = serializeAggregatePayload(state, 'sse');
    const reparsedSse = parseGeminiStreamPayload(ssePayload, 'text/event-stream');

    expect(jsonPayload).toEqual(serializeGeminiAggregateResponse(state));
    expect(reparsedSse.events).toEqual([jsonPayload]);
  });
});
