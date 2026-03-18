import { describe, it, expect } from 'vitest';
import { buildGeminiGenerateContentRequestFromOpenAi } from './geminiCliCompat.js';

describe('thoughtSignature injection in OpenAI→Gemini conversion', () => {
  it('injects thoughtSignature from provider_specific_fields into functionCall parts', () => {
    const result = buildGeminiGenerateContentRequestFromOpenAi({
      body: {
        model: 'gemini-3-flash-preview',
        messages: [
          { role: 'user', content: 'What is the weather?' },
          {
            role: 'assistant',
            content: 'Let me check.',
            tool_calls: [
              {
                id: 'call_123',
                type: 'function',
                function: { name: 'get_weather', arguments: '{"city":"Tokyo"}' },
                provider_specific_fields: { thought_signature: 'real_sig_abc' },
              },
            ],
          },
          { role: 'tool', tool_call_id: 'call_123', content: '{"temp":"22C"}' },
        ],
      },
      modelName: 'gemini-3-flash-preview',
    }) as Record<string, unknown>;

    const contents = result.contents as Array<Record<string, unknown>>;
    // Find the model message with functionCall
    const modelMsgs = contents.filter((c) => c.role === 'model');
    const fcParts = modelMsgs
      .flatMap((m) => (m.parts as Array<Record<string, unknown>>))
      .filter((p) => 'functionCall' in p);

    expect(fcParts.length).toBe(1);
    expect(fcParts[0].thoughtSignature).toBe('real_sig_abc');
  });

  it('splits text and signed functionCall parts into separate model messages', () => {
    const result = buildGeminiGenerateContentRequestFromOpenAi({
      body: {
        model: 'gemini-3-flash-preview',
        messages: [
          { role: 'user', content: 'Read the file.' },
          {
            role: 'assistant',
            content: 'I will read it.',
            tool_calls: [
              {
                id: 'call_456',
                type: 'function',
                function: { name: 'Read', arguments: '{"path":"/tmp/x"}' },
                provider_specific_fields: { thought_signature: 'sig_split_test' },
              },
            ],
          },
          { role: 'tool', tool_call_id: 'call_456', content: 'file content here' },
        ],
      },
      modelName: 'gemini-3-flash-preview',
    }) as Record<string, unknown>;

    const contents = result.contents as Array<Record<string, unknown>>;
    const modelMsgs = contents.filter((c) => c.role === 'model');

    // Should be 2 model messages: text (unsigned) + functionCall (signed)
    expect(modelMsgs.length).toBe(2);

    const firstParts = modelMsgs[0].parts as Array<Record<string, unknown>>;
    const secondParts = modelMsgs[1].parts as Array<Record<string, unknown>>;

    // First: text only, no thoughtSignature
    expect(firstParts.every((p) => 'text' in p)).toBe(true);
    expect(firstParts.every((p) => !('thoughtSignature' in p))).toBe(true);

    // Second: functionCall with thoughtSignature
    expect(secondParts.every((p) => 'functionCall' in p)).toBe(true);
    expect(secondParts[0].thoughtSignature).toBe('sig_split_test');
  });

  it('injects dummy sentinel when thinking enabled but no signature available', () => {
    const result = buildGeminiGenerateContentRequestFromOpenAi({
      body: {
        model: 'gemini-3-flash-preview',
        reasoning_effort: 'high',
        messages: [
          { role: 'user', content: 'Do something.' },
          {
            role: 'assistant',
            tool_calls: [
              {
                id: 'call_no_sig',
                type: 'function',
                function: { name: 'Bash', arguments: '{"command":"ls"}' },
                // No provider_specific_fields — signature missing
              },
            ],
          },
          { role: 'tool', tool_call_id: 'call_no_sig', content: 'file1\nfile2' },
        ],
      },
      modelName: 'gemini-3-flash-preview',
    }) as Record<string, unknown>;

    const contents = result.contents as Array<Record<string, unknown>>;
    const modelMsgs = contents.filter((c) => c.role === 'model');
    const fcParts = modelMsgs
      .flatMap((m) => (m.parts as Array<Record<string, unknown>>))
      .filter((p) => 'functionCall' in p);

    expect(fcParts.length).toBe(1);
    // Should have a dummy sentinel, not be missing
    expect(typeof fcParts[0].thoughtSignature).toBe('string');
    expect((fcParts[0].thoughtSignature as string).length).toBeGreaterThan(0);
  });

  it('does not inject thoughtSignature when thinking is not enabled', () => {
    const result = buildGeminiGenerateContentRequestFromOpenAi({
      body: {
        model: 'gemini-2.5-flash',
        messages: [
          { role: 'user', content: 'Hello' },
          {
            role: 'assistant',
            tool_calls: [
              {
                id: 'call_no_think',
                type: 'function',
                function: { name: 'Read', arguments: '{"path":"/x"}' },
              },
            ],
          },
          { role: 'tool', tool_call_id: 'call_no_think', content: 'data' },
        ],
      },
      modelName: 'gemini-2.5-flash',
    }) as Record<string, unknown>;

    const contents = result.contents as Array<Record<string, unknown>>;
    const modelMsgs = contents.filter((c) => c.role === 'model');
    const fcParts = modelMsgs
      .flatMap((m) => (m.parts as Array<Record<string, unknown>>))
      .filter((p) => 'functionCall' in p);

    expect(fcParts.length).toBe(1);
    // No thinking → no signature injected
    expect(fcParts[0].thoughtSignature).toBeUndefined();
  });

  it('preserves functionResponse count matching functionCall count', () => {
    const result = buildGeminiGenerateContentRequestFromOpenAi({
      body: {
        model: 'gemini-3-flash-preview',
        messages: [
          { role: 'user', content: 'Read two files.' },
          {
            role: 'assistant',
            tool_calls: [
              {
                id: 'call_a',
                type: 'function',
                function: { name: 'Read', arguments: '{"path":"/a"}' },
                provider_specific_fields: { thought_signature: 'sig_a' },
              },
              {
                id: 'call_b',
                type: 'function',
                function: { name: 'Read', arguments: '{"path":"/b"}' },
                provider_specific_fields: { thought_signature: 'sig_b' },
              },
            ],
          },
          { role: 'tool', tool_call_id: 'call_a', content: 'content a' },
          { role: 'tool', tool_call_id: 'call_b', content: 'content b' },
        ],
      },
      modelName: 'gemini-3-flash-preview',
    }) as Record<string, unknown>;

    const contents = result.contents as Array<Record<string, unknown>>;

    // Count functionCall and functionResponse parts
    let fcCount = 0;
    let frCount = 0;
    for (const content of contents) {
      for (const part of (content.parts as Array<Record<string, unknown>>)) {
        if ('functionCall' in part) fcCount++;
        if ('functionResponse' in part) frCount++;
      }
    }

    expect(fcCount).toBe(2);
    expect(frCount).toBe(2);
  });
});
