import Fastify, { type FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { config } from '../../config.js';

const fetchMock = vi.fn();

vi.mock('undici', async () => {
  const actual = await vi.importActual<typeof import('undici')>('undici');
  return {
    ...actual,
    fetch: (...args: unknown[]) => fetchMock(...args),
  };
});

describe('/api/test proxy tester routes', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    const { testRoutes } = await import('./test.js');
    app = Fastify();
    await app.register(testRoutes);
  });

  beforeEach(() => {
    fetchMock.mockReset();
  });

  afterAll(async () => {
    await app.close();
  });

  it('rejects proxy paths outside the allowlist', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/test/proxy',
      payload: {
        method: 'POST',
        path: '/admin/secret',
        requestKind: 'json',
        jsonBody: {},
      },
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({
      error: {
        message: 'path is not allowed: /admin/secret',
        type: 'validation_error',
      },
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('forwards raw json bodies without dropping extra proxy fields', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      object: 'response',
      output_text: 'ok',
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const rawPayload = {
      model: 'gpt-5.2',
      include: ['reasoning.encrypted_content'],
      reasoning: { effort: 'medium' },
      metadata: { source: 'tester' },
    };

    const response = await app.inject({
      method: 'POST',
      url: '/api/test/proxy',
      payload: {
        method: 'POST',
        path: '/v1/responses',
        requestKind: 'json',
        rawMode: true,
        rawJsonText: JSON.stringify(rawPayload),
      },
    });

    expect(response.statusCode).toBe(200);
    const [targetUrl, requestInit] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(targetUrl).toBe(`http://127.0.0.1:${config.port}/v1/responses`);
    expect(JSON.parse(String(requestInit.body))).toEqual({
      ...rawPayload,
      stream: false,
    });
  });

  it('rejects empty multipart envelopes', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/test/proxy',
      payload: {
        method: 'POST',
        path: '/v1/images/edits',
        requestKind: 'multipart',
      },
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({
      error: {
        message: 'multipart requests require multipartFields or multipartFiles',
        type: 'validation_error',
      },
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('allows multipart /v1/files uploads through the proxy tester', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      id: 'file_demo_123',
      object: 'file',
      filename: 'notes.txt',
      bytes: 11,
      purpose: 'user_data',
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/api/test/proxy',
      payload: {
        method: 'POST',
        path: '/v1/files',
        requestKind: 'multipart',
        multipartFields: {
          purpose: 'user_data',
        },
        multipartFiles: [
          {
            field: 'file',
            name: 'notes.txt',
            mimeType: 'text/plain',
            dataUrl: 'data:text/plain;base64,aGVsbG8gZmlsZXM=',
          },
        ],
      },
    });

    expect(response.statusCode).toBe(200);
    const [targetUrl, requestInit] = fetchMock.mock.calls[0] as [string, RequestInit & { body?: { constructor?: { name?: string } } }];
    expect(targetUrl).toBe(`http://127.0.0.1:${config.port}/v1/files`);
    expect(requestInit.method).toBe('POST');
    expect(requestInit.body?.constructor?.name).toBe('FormData');
  });

  it('keeps legacy /api/test/chat wrapper working for responses payloads', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      object: 'response',
      output_text: 'hello',
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/api/test/chat',
      payload: {
        model: 'gpt-5.2',
        targetFormat: 'responses',
        messages: [
          { role: 'system', content: 'be concise' },
          { role: 'user', content: 'hello' },
        ],
      },
    });

    expect(response.statusCode).toBe(200);
    const [targetUrl, requestInit] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(targetUrl).toBe(`http://127.0.0.1:${config.port}/v1/responses`);
    expect(JSON.parse(String(requestInit.body))).toEqual({
      model: 'gpt-5.2',
      stream: false,
      input: [{ role: 'user', content: 'hello' }],
      instructions: 'be concise',
      max_output_tokens: 4096,
    });
  });

  it('rejects gemini on legacy /api/test/chat wrapper until a native mapping exists', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/test/chat',
      payload: {
        model: 'gemini-2.5-flash',
        targetFormat: 'gemini',
        messages: [
          { role: 'user', content: 'hello' },
        ],
      },
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toEqual({
      error: 'targetFormat=gemini is not supported on legacy /api/test/chat routes; use the proxy tester Gemini path instead',
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
