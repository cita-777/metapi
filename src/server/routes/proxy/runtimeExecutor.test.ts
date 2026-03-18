import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fetch } from 'undici';
import type { BuiltEndpointRequest } from './endpointFlow.js';

vi.mock('undici', () => ({
  fetch: vi.fn(),
}));

const fetchMock = vi.mocked(fetch);

describe('dispatchRuntimeRequest', () => {
  beforeEach(() => {
    fetchMock.mockReset();
  });

  it('routes antigravity runtime requests through daily then sandbox base urls and rewrites the payload fingerprint', async () => {
    const { dispatchRuntimeRequest } = await import('./runtimeExecutor.js');
    const request: BuiltEndpointRequest = {
      endpoint: 'chat',
      path: '/v1internal:generateContent',
      headers: {
        Authorization: 'Bearer antigravity-token',
        'Content-Type': 'application/json',
        'User-Agent': 'google-api-nodejs-client/9.15.1',
      },
      body: {
        project: 'project-demo',
        model: 'gemini-3-pro-preview',
        request: {
          contents: [
            {
              role: 'user',
              parts: [{ text: 'hello runtime executor' }],
            },
          ],
        },
      },
      runtime: {
        executor: 'antigravity',
        modelName: 'gemini-3-pro-preview',
        stream: false,
      },
    };

    fetchMock
      .mockResolvedValueOnce(new Response(JSON.stringify({
        error: { message: 'try fallback base url' },
      }), {
        status: 429,
        headers: { 'content-type': 'application/json' },
      }) as unknown as Awaited<ReturnType<typeof fetch>>)
      .mockResolvedValueOnce(new Response(JSON.stringify({
        response: { responseId: 'ok' },
      }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }) as unknown as Awaited<ReturnType<typeof fetch>>);

    const response = await dispatchRuntimeRequest({
      siteUrl: 'https://cloudcode-pa.googleapis.com',
      request,
      buildInit: (_url, nextRequest) => ({
        method: 'POST',
        headers: nextRequest.headers,
        body: JSON.stringify(nextRequest.body),
      }),
    });

    expect(response.ok).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock.mock.calls[0]?.[0]).toBe('https://daily-cloudcode-pa.googleapis.com/v1internal:generateContent');
    expect(fetchMock.mock.calls[1]?.[0]).toBe('https://daily-cloudcode-pa.sandbox.googleapis.com/v1internal:generateContent');

    const firstInit = fetchMock.mock.calls[0]?.[1] as RequestInit;
    expect(firstInit.headers).toMatchObject({
      Authorization: 'Bearer antigravity-token',
      'Content-Type': 'application/json',
      Accept: 'application/json',
      'User-Agent': 'antigravity/1.19.6 darwin/arm64',
    });

    const upstreamBody = JSON.parse(String(firstInit.body));
    expect(upstreamBody).toMatchObject({
      project: 'project-demo',
      model: 'gemini-3-pro-preview',
      userAgent: 'antigravity',
      requestType: 'agent',
      request: {
        sessionId: expect.any(String),
        contents: [
          {
            role: 'user',
            parts: [{ text: 'hello runtime executor' }],
          },
        ],
      },
    });
    expect(upstreamBody.requestId).toMatch(/^agent-[0-9a-f-]{36}$/i);
  });

  it('keeps gemini-cli countTokens payload lean while forcing a model-aware user agent', async () => {
    const { dispatchRuntimeRequest } = await import('./runtimeExecutor.js');
    const request: BuiltEndpointRequest = {
      endpoint: 'chat',
      path: '/v1internal:countTokens',
      headers: {
        Authorization: 'Bearer gemini-cli-token',
        'Content-Type': 'application/json',
        'User-Agent': 'GeminiCLI/0.31.0/unknown (win32; x64)',
        'X-Goog-Api-Client': 'google-genai-sdk/1.41.0 gl-node/v22.19.0',
      },
      body: {
        project: 'project-demo',
        model: 'gemini-2.5-pro',
        request: {
          contents: [
            {
              role: 'user',
              parts: [{ text: 'count these tokens' }],
            },
          ],
        },
      },
      runtime: {
        executor: 'gemini-cli',
        modelName: 'gemini-2.5-pro',
        stream: false,
        action: 'countTokens',
      },
    };

    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({
      totalTokens: 12,
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }) as unknown as Awaited<ReturnType<typeof fetch>>);

    const response = await dispatchRuntimeRequest({
      siteUrl: 'https://cloudcode-pa.googleapis.com',
      request,
      buildInit: (_url, nextRequest) => ({
        method: 'POST',
        headers: nextRequest.headers,
        body: JSON.stringify(nextRequest.body),
      }),
    });

    expect(response.ok).toBe(true);
    const requestInit = fetchMock.mock.calls[0]?.[1] as RequestInit;
    expect(requestInit.headers).toMatchObject({
      Authorization: 'Bearer gemini-cli-token',
      'Content-Type': 'application/json',
      'User-Agent': 'GeminiCLI/0.31.0/gemini-2.5-pro (win32; x64)',
      'X-Goog-Api-Client': 'google-genai-sdk/1.41.0 gl-node/v22.19.0',
    });
    expect(JSON.parse(String(requestInit.body))).toEqual({
      request: {
        contents: [
          {
            role: 'user',
            parts: [{ text: 'count these tokens' }],
          },
        ],
      },
    });
  });

  it('retries antigravity runtime requests on transport errors before falling back to the next base url', async () => {
    const { dispatchRuntimeRequest } = await import('./runtimeExecutor.js');
    const request: BuiltEndpointRequest = {
      endpoint: 'chat',
      path: '/v1internal:generateContent',
      headers: {
        Authorization: 'Bearer antigravity-token',
        'Content-Type': 'application/json',
      },
      body: {
        project: 'project-demo',
        model: 'gemini-3-pro-preview',
        request: {
          contents: [
            {
              role: 'user',
              parts: [{ text: 'hello runtime executor' }],
            },
          ],
        },
      },
      runtime: {
        executor: 'antigravity',
        modelName: 'gemini-3-pro-preview',
        stream: false,
      },
    };

    fetchMock
      .mockRejectedValueOnce(new Error('socket hang up'))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        response: { responseId: 'ok' },
      }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }) as unknown as Awaited<ReturnType<typeof fetch>>);

    const response = await dispatchRuntimeRequest({
      siteUrl: 'https://cloudcode-pa.googleapis.com',
      request,
      buildInit: (_url, nextRequest) => ({
        method: 'POST',
        headers: nextRequest.headers,
        body: JSON.stringify(nextRequest.body),
      }),
    });

    expect(response.ok).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock.mock.calls[0]?.[0]).toBe('https://daily-cloudcode-pa.googleapis.com/v1internal:generateContent');
    expect(fetchMock.mock.calls[1]?.[0]).toBe('https://daily-cloudcode-pa.sandbox.googleapis.com/v1internal:generateContent');
  });
});
