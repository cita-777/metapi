import { Headers, Response } from 'undici';

type ObservedResponseMeta = {
  firstByteLatencyMs: number | null;
  timedOutBeforeFirstByte: boolean;
};

const observedResponseMeta = new WeakMap<Response, ObservedResponseMeta>();

function setObservedResponseMeta<T extends Response>(response: T, meta: ObservedResponseMeta): T {
  observedResponseMeta.set(response, meta);
  return response;
}

function clearTimer(timer: ReturnType<typeof setTimeout> | null) {
  if (!timer) return;
  clearTimeout(timer);
}

function buildFirstByteTimeoutMessage(timeoutMs: number): string {
  const seconds = Math.max(1, Math.round(timeoutMs / 1000));
  return `first byte timeout (${seconds}s)`;
}

function buildObservedTimeoutResponse(timeoutMs: number): Response {
  return setObservedResponseMeta(new Response(buildFirstByteTimeoutMessage(timeoutMs), {
    status: 408,
    headers: { 'content-type': 'text/plain; charset=utf-8' },
  }), {
    firstByteLatencyMs: null,
    timedOutBeforeFirstByte: true,
  });
}

async function cancelReaderQuietly(reader: ReadableStreamDefaultReader<Uint8Array> | null) {
  if (!reader) return;
  try {
    await reader.cancel();
  } catch {
    // Ignore cancellation errors from already-closed streams.
  }
  try {
    reader.releaseLock();
  } catch {
    // Ignore release errors from already-released readers.
  }
}

function buildReplayResponse<T extends Response>(
  response: T,
  reader: ReadableStreamDefaultReader<Uint8Array>,
  firstChunk: ReadableStreamReadResult<Uint8Array>,
): T {
  let firstChunkDelivered = false;
  let readerReleased = false;
  const releaseReader = () => {
    if (readerReleased) return;
    readerReleased = true;
    try {
      reader.releaseLock();
    } catch {
      // Ignore release failures from cancelled/closed readers.
    }
  };

  const stream = new ReadableStream<Uint8Array>({
    async pull(controller) {
      if (!firstChunkDelivered) {
        firstChunkDelivered = true;
        if (firstChunk.done) {
          controller.close();
          releaseReader();
          return;
        }
        controller.enqueue(firstChunk.value);
        return;
      }

      try {
        const next = await reader.read();
        if (next.done) {
          controller.close();
          releaseReader();
          return;
        }
        controller.enqueue(next.value);
      } catch (error) {
        controller.error(error);
        releaseReader();
      }
    },
    async cancel(reason) {
      try {
        await reader.cancel(reason);
      } catch {
        // Ignore cancellation failures from already-closed streams.
      }
      releaseReader();
    },
  });

  return new Response(stream, {
    status: response.status,
    statusText: response.statusText,
    headers: new Headers(response.headers),
  }) as T;
}

export async function fetchWithObservedFirstByte<T extends Response>(
  dispatch: (signal?: AbortSignal) => Promise<T>,
  options: {
    firstByteTimeoutMs?: number;
    startedAtMs?: number;
  } = {},
): Promise<T> {
  const timeoutMs = Math.max(0, Math.trunc(options.firstByteTimeoutMs ?? 0));
  const startedAtMs = options.startedAtMs ?? Date.now();
  const controller = timeoutMs > 0 ? new AbortController() : null;
  let timer: ReturnType<typeof setTimeout> | null = null;
  let timedOutBeforeFirstByte = false;
  const timeoutSentinel = Symbol('first-byte-timeout');
  const timeoutPromise = timeoutMs > 0
    ? new Promise<typeof timeoutSentinel>((resolve) => {
      timer = setTimeout(() => {
        timedOutBeforeFirstByte = true;
        controller?.abort(new Error(buildFirstByteTimeoutMessage(timeoutMs)));
        resolve(timeoutSentinel);
      }, timeoutMs);
    })
    : null;

  try {
    const dispatched = timeoutPromise
      ? await Promise.race([dispatch(controller?.signal), timeoutPromise])
      : await dispatch(controller?.signal);
    if (dispatched === timeoutSentinel) {
      return buildObservedTimeoutResponse(timeoutMs) as T;
    }
    const response = dispatched as T;
    if (!response.body) {
      clearTimer(timer);
      return setObservedResponseMeta(response, {
        firstByteLatencyMs: Math.max(0, Date.now() - startedAtMs),
        timedOutBeforeFirstByte: false,
      });
    }

    const reader = response.body.getReader() as ReadableStreamDefaultReader<Uint8Array>;
    const firstChunk = timeoutPromise
      ? await Promise.race([reader.read(), timeoutPromise])
      : await reader.read();
    if (firstChunk === timeoutSentinel) {
      await cancelReaderQuietly(reader);
      return buildObservedTimeoutResponse(timeoutMs) as T;
    }
    clearTimer(timer);
    return setObservedResponseMeta(buildReplayResponse(response, reader, firstChunk), {
      firstByteLatencyMs: Math.max(0, Date.now() - startedAtMs),
      timedOutBeforeFirstByte: false,
    });
  } catch (error) {
    clearTimer(timer);
    if (timedOutBeforeFirstByte && timeoutMs > 0) {
      return buildObservedTimeoutResponse(timeoutMs) as T;
    }
    throw error;
  } finally {
    clearTimer(timer);
  }
}

export function getObservedResponseMeta(response: Response | null | undefined): ObservedResponseMeta | null {
  if (!response) return null;
  return observedResponseMeta.get(response) ?? null;
}

export function isObservedFirstByteTimeoutResponse(response: Response | null | undefined): boolean {
  return getObservedResponseMeta(response)?.timedOutBeforeFirstByte === true;
}
