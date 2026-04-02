import { describe, expect, it } from 'vitest';
import { normalizeCodexResponsesBodyForProxy } from './codexCompatibility.js';

describe('normalizeCodexResponsesBodyForProxy', () => {
  it('normalizes codex responses bodies before proxying upstream', () => {
    const body = normalizeCodexResponsesBodyForProxy({
      input: [
        {
          type: 'message',
          role: 'system',
          content: [{ type: 'input_text', text: 'be precise' }],
        },
      ],
      max_output_tokens: 512,
      max_completion_tokens: 256,
      max_tokens: 128,
      temperature: 0.3,
      store: true,
    }, 'codex');

    expect(body).toEqual({
      input: [
        {
          type: 'message',
          role: 'developer',
          content: [{ type: 'input_text', text: 'be precise' }],
        },
      ],
      instructions: '',
      store: false,
      temperature: 0.3,
    });
  });

  it('leaves non-codex bodies untouched', () => {
    const source = {
      input: 'hello',
      max_output_tokens: 512,
    };

    const body = normalizeCodexResponsesBodyForProxy(source, 'openai');

    expect(body).toBe(source);
  });
});
