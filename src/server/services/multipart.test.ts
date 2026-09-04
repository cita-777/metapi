import type { FastifyInstance, FastifyRequest } from 'fastify';
import { describe, expect, it, vi } from 'vitest';
import {
  cloneFormDataWithOverrides,
  ensureMultipartBufferParser,
  isMultipartRequest,
  parseMultipartFormData,
} from './multipart.js';

function requestFixture(
  headers: Record<string, unknown>,
  body?: unknown,
): FastifyRequest {
  return { headers, body } as unknown as FastifyRequest;
}

describe('multipart service helpers', () => {
  it('registers the Fastify parser once per app instance', () => {
    const addContentTypeParser = vi.fn();
    const app = { addContentTypeParser } as unknown as FastifyInstance;

    ensureMultipartBufferParser(app);
    ensureMultipartBufferParser(app);

    expect(addContentTypeParser).toHaveBeenCalledTimes(1);
  });

  it.each([
    ['multipart/form-data; boundary=abc', true],
    ['MULTIPART/FORM-DATA; boundary=abc', true],
    ['application/json', false],
    ['', false],
  ])('recognizes multipart content type %s as %s', (contentType, expected) => {
    expect(isMultipartRequest(requestFixture({ 'content-type': contentType }))).toBe(expected);
  });

  it('parses a buffered multipart request and preserves fields', async () => {
    const boundary = '----metapi-test-boundary';
    const body = Buffer.from([
      `--${boundary}`,
      'Content-Disposition: form-data; name="model"',
      '',
      'gpt-4o',
      `--${boundary}`,
      'Content-Disposition: form-data; name="prompt"',
      '',
      'hello',
      `--${boundary}--`,
      '',
    ].join('\r\n'));
    const form = await parseMultipartFormData(requestFixture({
      'content-type': `multipart/form-data; boundary=${boundary}`,
    }, body));

    expect(form?.get('model')).toBe('gpt-4o');
    expect(form?.get('prompt')).toBe('hello');
  });

  it('overrides existing fields and appends new fields without dropping files', () => {
    const original = new FormData();
    original.append('model', 'old-model');
    original.append('file', new File(['payload'], 'input.txt', { type: 'text/plain' }));

    const cloned = cloneFormDataWithOverrides(original, {
      model: 'new-model',
      response_format: 'json',
    });

    expect(cloned.get('model')).toBe('new-model');
    expect(cloned.get('response_format')).toBe('json');
    const file = cloned.get('file');
    expect(file).toBeInstanceOf(File);
    expect((file as File).name).toBe('input.txt');
  });
});
