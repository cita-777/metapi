import { describe, expect, it } from 'vitest';

import {
  normalizeResponsesInputForCompatibility,
  normalizeResponsesMessageContent,
} from './normalization.js';

describe('responses input image normalization (issue #598)', () => {
  it('strips file_id when an input_image block also carries image_url', () => {
    const result = normalizeResponsesInputForCompatibility([
      {
        type: 'message',
        role: 'user',
        content: [
          {
            type: 'input_image',
            file_id: 'file_remote_abc',
            image_url: 'https://example.com/cat.png',
          },
        ],
      },
    ]) as Array<Record<string, unknown>>;

    const content = result[0].content as Array<Record<string, unknown>>;
    expect(content).toHaveLength(1);
    expect(content[0]).toEqual({
      type: 'input_image',
      image_url: 'https://example.com/cat.png',
    });
    expect(content[0]).not.toHaveProperty('file_id');
  });

  it('strips file_id when an image_url-typed block also carries image_url', () => {
    const result = normalizeResponsesInputForCompatibility([
      {
        type: 'message',
        role: 'user',
        content: [
          {
            type: 'image_url',
            file_id: 'file_remote_abc',
            image_url: 'https://example.com/cat.png',
          },
        ],
      },
    ]) as Array<Record<string, unknown>>;

    const content = result[0].content as Array<Record<string, unknown>>;
    expect(content).toHaveLength(1);
    expect(content[0]).toEqual({
      type: 'input_image',
      image_url: 'https://example.com/cat.png',
    });
    expect(content[0]).not.toHaveProperty('file_id');
  });

  it('drops the conflicting file_id while preserving other siblings', () => {
    const result = normalizeResponsesInputForCompatibility([
      {
        type: 'message',
        role: 'user',
        content: [
          {
            type: 'input_image',
            file_id: 'file_remote_abc',
            image_url: 'https://example.com/cat.png',
            detail: 'high',
          },
        ],
      },
    ]) as Array<Record<string, unknown>>;

    const content = result[0].content as Array<Record<string, unknown>>;
    expect(content[0]).toEqual({
      type: 'input_image',
      image_url: 'https://example.com/cat.png',
      detail: 'high',
    });
    expect(content[0]).not.toHaveProperty('file_id');
  });
});
