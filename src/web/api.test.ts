import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { api, type ProxyTestRequestEnvelope } from './api.js';
import { persistAuthSession } from './authSession.js';

function createMemoryStorage() {
  const store = new Map<string, string>();
  return {
    getItem(key: string) {
      return store.has(key) ? store.get(key)! : null;
    },
    setItem(key: string, value: string) {
      store.set(key, value);
    },
    removeItem(key: string) {
      store.delete(key);
    },
  };
}

function installPendingFetch() {
  const fetchMock = vi.fn((_input: RequestInfo | URL, init?: RequestInit) => new Promise<Response>((_resolve, reject) => {
    const signal = init?.signal;
    if (!signal) return;
    if (signal.aborted) {
      reject(new DOMException('Aborted', 'AbortError'));
      return;
    }
    signal.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')), { once: true });
  }));

  vi.stubGlobal('fetch', fetchMock);
  return fetchMock;
}

function createAbortAwarePendingResponse(
  signal?: AbortSignal | null,
  init: ResponseInit = {},
) {
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      if (signal?.aborted) {
        controller.error(new DOMException('Aborted', 'AbortError'));
        return;
      }
      signal?.addEventListener(
        'abort',
        () => controller.error(new DOMException('Aborted', 'AbortError')),
        { once: true },
      );
    },
  });
  return new Response(stream, {
    status: 200,
    headers: { 'content-type': 'application/json' },
    ...init,
  });
}

describe('api proxy test timeout handling', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.stubGlobal('localStorage', createMemoryStorage());
    persistAuthSession(globalThis.localStorage as Storage, 'token-1');
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('keeps image generation proxy tests alive past the default 30 second timeout', async () => {
    installPendingFetch();

    const payload: ProxyTestRequestEnvelope = {
      method: 'POST',
      path: '/v1/images/generations',
      requestKind: 'json',
      jsonBody: {
        model: 'gemini-imagen',
        prompt: 'banana cat',
      },
    };

    let settled = false;
    const promise = api.proxyTest(payload);
    const handled = promise
      .then(() => ({ ok: true as const }))
      .catch((error: Error) => ({ ok: false as const, error }))
      .finally(() => {
        settled = true;
      });

    await vi.advanceTimersByTimeAsync(30_000);
    expect(settled).toBe(false);

    await vi.advanceTimersByTimeAsync(120_000);
    const result = await handled;
    expect(result.ok).toBe(false);
    if (result.ok) {
      throw new Error('Expected image generation proxy test to time out');
    }
    expect(result.error.message).toBe('请求超时（150s）');
  });

  it('still uses the default 30 second timeout for generic proxy tests', async () => {
    installPendingFetch();

    const payload: ProxyTestRequestEnvelope = {
      method: 'POST',
      path: '/v1/embeddings',
      requestKind: 'json',
      jsonBody: {
        model: 'text-embedding-3-small',
        input: 'hello',
      },
    };

    const promise = api.proxyTest(payload).catch((error: Error) => error);

    await vi.advanceTimersByTimeAsync(30_000);
    await expect(promise).resolves.toMatchObject({ message: '请求超时（30s）' });
  });

  it('keeps all-model site probes alive past the default 30 second timeout', async () => {
    installPendingFetch();

    let settled = false;
    const promise = api.probeSiteNow(1, { scope: 'all' });
    const handled = promise
      .then(() => ({ ok: true as const }))
      .catch((error: Error) => ({ ok: false as const, error }))
      .finally(() => {
        settled = true;
      });

    await vi.advanceTimersByTimeAsync(30_000);
    expect(settled).toBe(false);

    await vi.advanceTimersByTimeAsync(90_000);
    const result = await handled;
    expect(result.ok).toBe(false);
    if (result.ok) {
      throw new Error('Expected all-model site probe to time out');
    }
    expect(result.error.message).toBe('请求超时（120s）');
  });

  it('times out replay hydration file-content fetches after 30 seconds', async () => {
    installPendingFetch();

    const getProxyFileContentDataUrl = (api as Record<string, any>).getProxyFileContentDataUrl;
    let settled = false;
    const handled = getProxyFileContentDataUrl?.('file-metapi-123')
      .then(() => ({ ok: true as const }))
      .catch((error: Error) => ({ ok: false as const, error }))
      .finally(() => {
        settled = true;
      });

    await vi.advanceTimersByTimeAsync(30_000);
    expect(settled).toBe(true);

    const result = await handled;
    expect(result.ok).toBe(false);
    if (result.ok) {
      throw new Error('Expected replay hydration file-content fetch to time out');
    }
    expect(result.error.message).toBe('请求超时（30s）');
  });

  it('loads proxy file content as a data URL for replay hydration', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(
      new Blob([Buffer.from('PDF')], { type: 'application/pdf' }),
      {
        status: 200,
        headers: {
          'content-type': 'application/pdf',
          'content-disposition': 'inline; filename="brief.pdf"',
        },
      },
    ));
    vi.stubGlobal('fetch', fetchMock);

    const getProxyFileContentDataUrl = (api as Record<string, any>).getProxyFileContentDataUrl;
    const result = await getProxyFileContentDataUrl?.('file-metapi-123');

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0]?.[0]).toBe('/v1/files/file-metapi-123/content');
    const init = fetchMock.mock.calls[0]?.[1] as RequestInit | undefined;
    expect(init?.method).toBe('GET');
    expect(init?.headers).toBeInstanceOf(Headers);
    expect((init?.headers as Headers).get('Authorization')).toBe('Bearer token-1');
    expect(result).toEqual({
      filename: 'brief.pdf',
      mimeType: 'application/pdf',
      data: 'data:application/pdf;base64,UERG',
    });
  });

  it('keeps the request timeout active while a JSON body is pending', async () => {
    const fetchMock = vi.fn((_input: RequestInfo | URL, init?: RequestInit) =>
      Promise.resolve(createAbortAwarePendingResponse(init?.signal)),
    );
    vi.stubGlobal('fetch', fetchMock);

    const promise = api.proxyTest({
      method: 'POST',
      path: '/v1/embeddings',
      requestKind: 'json',
      jsonBody: { model: 'text-embedding-3-small', input: 'hello' },
    });

    await vi.advanceTimersByTimeAsync(29_999);
    let settled = false;
    void promise.then(
      () => {
        settled = true;
      },
      () => {
        settled = true;
      },
    );
    expect(settled).toBe(false);

    await vi.advanceTimersByTimeAsync(1);
    await expect(promise).rejects.toMatchObject({
      message: '请求超时（30s）',
    });
    expect(fetchMock.mock.calls[0]?.[1]).toMatchObject({
      signal: expect.objectContaining({ aborted: true }),
    });
  });

  it('settles a timeout even when a custom body stream ignores abort', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(new ReadableStream<Uint8Array>(), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
    );
    vi.stubGlobal('fetch', fetchMock);

    const result = api.proxyTest({
      method: 'POST',
      path: '/v1/embeddings',
      requestKind: 'json',
      jsonBody: { model: 'demo', input: 'hello' },
    }).then(
      () => ({ ok: true as const }),
      (error) => ({ ok: false as const, error }),
    );

    await vi.advanceTimersByTimeAsync(30_000);
    await expect(result).resolves.toMatchObject({
      ok: false,
      error: { message: '请求超时（30s）' },
    });
  });

  it('settles a timeout when a fetch adapter ignores abort before headers', async () => {
    let resolveFetch!: (response: Response) => void;
    const fetchMock = vi.fn(
      () => new Promise<Response>((resolve) => {
        resolveFetch = resolve;
      }),
    );
    vi.stubGlobal('fetch', fetchMock);

    const result = api.search('non-cooperative-fetch').then(
      () => ({ ok: true as const }),
      (error) => ({ ok: false as const, error }),
    );

    await vi.advanceTimersByTimeAsync(30_000);
    await expect(result).resolves.toMatchObject({
      ok: false,
      error: { message: '请求超时（30s）' },
    });

    // Let the late adapter response settle so the test does not retain a
    // pending promise; the API should cancel its body and ignore the value.
    resolveFetch(new Response(null, { status: 200 }));
    await Promise.resolve();
  });

  it('cleans the timeout after a response body is fully consumed', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ success: true }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
    );
    vi.stubGlobal('fetch', fetchMock);

    await expect(
      api.proxyTest({
        method: 'POST',
        path: '/v1/embeddings',
        requestKind: 'json',
        jsonBody: { model: 'demo', input: 'hello' },
      }),
    ).resolves.toEqual({ success: true });
    expect(vi.getTimerCount()).toBe(0);
  });

  it('propagates caller cancellation while a JSON body is pending', async () => {
    const controller = new AbortController();
    const fetchMock = vi.fn((_input: RequestInfo | URL, init?: RequestInit) =>
      Promise.resolve(createAbortAwarePendingResponse(init?.signal)),
    );
    vi.stubGlobal('fetch', fetchMock);

    const promise = api.search('pending', { signal: controller.signal });
    await Promise.resolve();
    await Promise.resolve();
    controller.abort();

    await expect(promise).rejects.toMatchObject({ name: 'AbortError' });
    expect(fetchMock.mock.calls[0]?.[1]).toMatchObject({
      signal: expect.objectContaining({ aborted: true }),
    });
    expect(vi.getTimerCount()).toBe(0);
  });

  it('races deferred response doubles against the caller signal', async () => {
    const controller = new AbortController();
    let resolveBody!: (value: unknown) => void;
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: () => new Promise((resolve) => {
        resolveBody = resolve;
      }),
    });
    vi.stubGlobal('fetch', fetchMock);

    const promise = api.search('double', { signal: controller.signal });
    await Promise.resolve();
    await Promise.resolve();
    controller.abort();

    await expect(promise).rejects.toMatchObject({ name: 'AbortError' });
    // Resolve the abandoned operation when the lazy body reader won the
    // scheduling race. An abort may legitimately arrive before `json()` is
    // invoked, in which case there is no deferred promise to drain.
    resolveBody?.({});
  });

  it('does not return a null-body response after a pre-aborted signal', async () => {
    const controller = new AbortController();
    controller.abort();
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(null, { status: 204 }),
    );
    vi.stubGlobal('fetch', fetchMock);

    const promise = api.proxyTestStream(
      {
        method: 'POST',
        path: '/v1/embeddings',
        requestKind: 'json',
        jsonBody: { model: 'demo', input: 'hello' },
      },
      controller.signal,
    );

    await expect(promise).rejects.toMatchObject({ name: 'AbortError' });
  });

  it('keeps file arrayBuffer reads under the request timeout', async () => {
    const fetchMock = vi.fn((_input: RequestInfo | URL, init?: RequestInit) =>
      Promise.resolve(
        createAbortAwarePendingResponse(init?.signal, {
          headers: { 'content-type': 'application/pdf' },
        }),
      ),
    );
    vi.stubGlobal('fetch', fetchMock);

    const getProxyFileContentDataUrl =
      (api as Record<string, any>).getProxyFileContentDataUrl;
    const promise = getProxyFileContentDataUrl('file-pending').catch(
      (error: Error) => error,
    );

    await vi.advanceTimersByTimeAsync(30_000);
    await expect(promise).resolves.toMatchObject({
      message: '请求超时（30s）',
    });
  });

  it('propagates caller cancellation while an SSE reader is pending', async () => {
    const controller = new AbortController();
    const fetchMock = vi.fn((_input: RequestInfo | URL, init?: RequestInit) =>
      Promise.resolve(
        createAbortAwarePendingResponse(init?.signal, {
          headers: { 'content-type': 'text/event-stream' },
        }),
      ),
    );
    vi.stubGlobal('fetch', fetchMock);

    const promise = api.streamUpdateCenterTaskLogs('task-pending', {
      signal: controller.signal,
    });
    await Promise.resolve();
    await Promise.resolve();
    controller.abort();

    await expect(promise).rejects.toMatchObject({ name: 'AbortError' });
  });

  it('preserves SSE events while the managed body reaches EOF', async () => {
    const payload = [
      'event: log\ndata: {"message":"hello"}\n\n',
      'event: done\ndata: {"status":"succeeded"}\n\n',
    ].join('');
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(new TextEncoder().encode(payload), {
        status: 200,
        headers: { 'content-type': 'text/event-stream' },
      }),
    );
    vi.stubGlobal('fetch', fetchMock);

    const logs: unknown[] = [];
    const done: unknown[] = [];
    await api.streamUpdateCenterTaskLogs('task-success', {
      onLog: (entry) => logs.push(entry),
      onDone: (entry) => done.push(entry),
    });

    expect(logs).toEqual([{ message: 'hello' }]);
    expect(done).toEqual([{ status: 'succeeded' }]);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('reports the stream timeout when an SSE reader exceeds its deadline', async () => {
    const fetchMock = vi.fn((_input: RequestInfo | URL, init?: RequestInit) =>
      Promise.resolve(
        createAbortAwarePendingResponse(init?.signal, {
          headers: { 'content-type': 'text/event-stream' },
        }),
      ),
    );
    vi.stubGlobal('fetch', fetchMock);

    const result = api.streamUpdateCenterTaskLogs('task-timeout', {}).then(
      () => ({ ok: true as const }),
      (error) => ({ ok: false as const, error }),
    );
    await vi.advanceTimersByTimeAsync(120_000);

    await expect(result).resolves.toMatchObject({
      ok: false,
      error: { message: '请求超时（120s）' },
    });
  });

  it('does not hide body-stage cancellation for non-OK responses', async () => {
    const controller = new AbortController();
    const fetchMock = vi.fn((_input: RequestInfo | URL, init?: RequestInit) =>
      Promise.resolve(
        createAbortAwarePendingResponse(init?.signal, {
          status: 502,
          statusText: 'Bad Gateway',
        }),
      ),
    );
    vi.stubGlobal('fetch', fetchMock);

    const promise = api.search('error', { signal: controller.signal });
    await Promise.resolve();
    await Promise.resolve();
    controller.abort();

    await expect(promise).rejects.toMatchObject({ name: 'AbortError' });
  });

  it('keeps a returned streaming Response cancellable after headers arrive', async () => {
    const controller = new AbortController();
    const fetchMock = vi.fn((_input: RequestInfo | URL, init?: RequestInit) =>
      Promise.resolve(createAbortAwarePendingResponse(init?.signal)),
    );
    vi.stubGlobal('fetch', fetchMock);

    const response = await api.proxyTestStream(
      {
        method: 'POST',
        path: '/v1/chat/completions',
        requestKind: 'json',
        stream: true,
        jsonBody: { model: 'demo', messages: [] },
      },
      controller.signal,
    );
    const bodyPromise = response.json();
    controller.abort();

    await expect(bodyPromise).rejects.toMatchObject({ name: 'AbortError' });
  });

  it('does not expose a prefetched chunk after caller cancellation', async () => {
    const controller = new AbortController();
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(new TextEncoder().encode('prefetched'), { status: 200 }),
    );
    vi.stubGlobal('fetch', fetchMock);

    const response = await api.proxyTestStream(
      {
        method: 'POST',
        path: '/v1/embeddings',
        requestKind: 'json',
        jsonBody: { model: 'demo', input: 'hello' },
      },
      controller.signal,
    );
    controller.abort();
    const reader = response.body!.getReader();
    const result = reader.read().then(
      (value) => ({ ok: true as const, value }),
      (error) => ({ ok: false as const, error }),
    );

    await expect(result).resolves.toMatchObject({
      ok: false,
      error: { name: 'AbortError' },
    });
  });

  it('normalizes a timeout from a returned streaming Response body', async () => {
    const fetchMock = vi.fn((_input: RequestInfo | URL, init?: RequestInit) =>
      Promise.resolve(createAbortAwarePendingResponse(init?.signal)),
    );
    vi.stubGlobal('fetch', fetchMock);

    const response = await api.proxyTestStream({
      method: 'POST',
      path: '/v1/embeddings',
      requestKind: 'json',
      jsonBody: { model: 'demo', input: 'hello' },
    });
    const bodyResult = response.json().then(
      (value) => ({ ok: true as const, value }),
      (error) => ({ ok: false as const, error }),
    );

    await vi.advanceTimersByTimeAsync(30_000);
    await expect(bodyResult).resolves.toMatchObject({
      ok: false,
      error: { message: '请求超时（30s）' },
    });
  });

  it('cancels a returned body promptly even when its source ignores abort', async () => {
    const controller = new AbortController();
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(new ReadableStream<Uint8Array>(), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
    );
    vi.stubGlobal('fetch', fetchMock);

    const response = await api.proxyTestStream(
      {
        method: 'POST',
        path: '/v1/embeddings',
        requestKind: 'json',
        jsonBody: { model: 'demo', input: 'hello' },
      },
      controller.signal,
    );
    const result = response.json().then(
      () => ({ ok: true as const }),
      (error) => ({ ok: false as const, error }),
    );
    controller.abort();

    await expect(result).resolves.toMatchObject({
      ok: false,
      error: { name: 'AbortError' },
    });
  });

  it('releases lifecycle resources when a returned reader is canceled', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(new TextEncoder().encode('chunk'));
        },
      }), { status: 200 }),
    );
    vi.stubGlobal('fetch', fetchMock);

    const response = await api.proxyTestStream({
      method: 'POST',
      path: '/v1/embeddings',
      requestKind: 'json',
      jsonBody: { model: 'demo', input: 'hello' },
    });
    const reader = response.body?.getReader();
    expect(reader).toBeDefined();
    await reader?.read();
    await reader?.cancel();

    expect(vi.getTimerCount()).toBe(0);
  });

  it('settles a pending returned reader when cancellation is requested', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        new ReadableStream<Uint8Array>({
          pull: () => new Promise<void>(() => {}),
          cancel: () => new Promise<void>(() => {}),
        }),
        { status: 200 },
      ),
    );
    vi.stubGlobal('fetch', fetchMock);

    const response = await api.proxyTestStream({
      method: 'POST',
      path: '/v1/embeddings',
      requestKind: 'json',
      jsonBody: { model: 'demo', input: 'hello' },
    });
    const reader = response.body!.getReader();
    const readResult = reader.read();
    await reader.cancel();

    await expect(readResult).resolves.toMatchObject({ done: true });
  });

  it('reuses the same proxy test implementations for legacy aliases', () => {
    expect(api.proxyTest).toBe(api.testProxy);
    expect(api.proxyTestStream).toBe(api.testProxyStream);
  });
});
