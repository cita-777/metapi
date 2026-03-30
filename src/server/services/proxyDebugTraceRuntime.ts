import { readRuntimeResponseText } from '../proxy-core/executors/types.js';
import type {
  EndpointAttemptSuccessContext,
} from '../routes/proxy/endpointFlow.js';
import {
  finalizeProxyDebugTrace,
  insertProxyDebugAttempt,
  normalizeProxyDebugResponseHeaders,
  startProxyDebugTraceSession,
  updateProxyDebugAttempt,
  updateProxyDebugTraceCandidates,
  updateProxyDebugTraceSelection,
  type ProxyDebugTraceSession,
} from './proxyDebugTraceStore.js';

type MutableProxyDebugTraceSession = ProxyDebugTraceSession & {
  nextAttemptIndex?: number;
};

function parseDebugTextPayload(rawText: string): unknown {
  if (!rawText) return null;
  try {
    return JSON.parse(rawText);
  } catch {
    return rawText;
  }
}

export async function startSurfaceProxyDebugTrace(input: {
  downstreamPath: string;
  clientKind?: string | null;
  sessionId?: string | null;
  traceHint?: string | null;
  requestedModel?: string | null;
  downstreamApiKeyId?: number | null;
  requestHeaders?: Record<string, unknown>;
  requestBody?: unknown;
}): Promise<ProxyDebugTraceSession | null> {
  try {
    return await startProxyDebugTraceSession(input);
  } catch (error) {
    console.warn('[proxy-debug] failed to create trace session', error);
    return null;
  }
}

export async function safeUpdateSurfaceProxyDebugSelection(
  session: ProxyDebugTraceSession | null,
  input: Parameters<typeof updateProxyDebugTraceSelection>[1],
): Promise<void> {
  if (!session) return;
  try {
    await updateProxyDebugTraceSelection(session.traceId, input);
  } catch (error) {
    console.warn('[proxy-debug] failed to update selection', error);
  }
}

export async function safeUpdateSurfaceProxyDebugCandidates(
  session: ProxyDebugTraceSession | null,
  input: Parameters<typeof updateProxyDebugTraceCandidates>[1],
): Promise<void> {
  if (!session) return;
  try {
    await updateProxyDebugTraceCandidates(session.traceId, input);
  } catch (error) {
    console.warn('[proxy-debug] failed to update endpoint candidates', error);
  }
}

export async function safeInsertSurfaceProxyDebugAttempt(
  session: ProxyDebugTraceSession | null,
  input: Omit<Parameters<typeof insertProxyDebugAttempt>[0], 'traceId'>,
): Promise<void> {
  if (!session) return;
  try {
    await insertProxyDebugAttempt({
      ...input,
      traceId: session.traceId,
      requestHeaders: session.options.captureHeaders ? input.requestHeaders : null,
      requestBody: session.options.captureBodies ? input.requestBody : null,
      responseHeaders: session.options.captureHeaders ? input.responseHeaders : null,
      responseBody: session.options.captureBodies ? input.responseBody : null,
      maxBodyBytes: session.options.maxBodyBytes,
    });
  } catch (error) {
    console.warn('[proxy-debug] failed to insert attempt', error);
  }
}

export function reserveSurfaceProxyDebugAttemptBase(
  session: ProxyDebugTraceSession | null,
  span: number,
): number {
  if (!session) return 0;

  const mutableSession = session as MutableProxyDebugTraceSession;
  const base = mutableSession.nextAttemptIndex ?? 0;
  const normalizedSpan = Number.isFinite(span)
    ? Math.max(1, Math.trunc(span))
    : 1;
  mutableSession.nextAttemptIndex = base + normalizedSpan;
  return base;
}

export async function safeFinalizeSurfaceProxyDebugTrace(
  session: ProxyDebugTraceSession | null,
  input: Parameters<typeof finalizeProxyDebugTrace>[1],
): Promise<void> {
  if (!session) return;
  try {
    await finalizeProxyDebugTrace(session.traceId, {
      ...input,
      finalResponseHeaders: session.options.captureHeaders ? input.finalResponseHeaders : null,
      finalResponseBody: session.options.captureBodies ? input.finalResponseBody : null,
      maxBodyBytes: session.options.maxBodyBytes,
    });
  } catch (error) {
    console.warn('[proxy-debug] failed to finalize trace', error);
  }
}

export async function safeUpdateSurfaceProxyDebugAttempt(
  session: ProxyDebugTraceSession | null,
  attemptIndex: number,
  input: Parameters<typeof updateProxyDebugAttempt>[2],
): Promise<void> {
  if (!session) return;
  try {
    await updateProxyDebugAttempt(session.traceId, attemptIndex, input);
  } catch (error) {
    console.warn('[proxy-debug] failed to update attempt', error);
  }
}

export async function captureSurfaceProxyDebugSuccessResponseBody(
  session: ProxyDebugTraceSession | null,
  ctx: EndpointAttemptSuccessContext,
): Promise<unknown> {
  if (!session?.options.captureBodies) return null;

  const contentType = (ctx.response.headers.get('content-type') || '').toLowerCase();
  const requestBody = ctx.request.body as Record<string, unknown> | undefined;
  const isStream = ctx.request.runtime?.stream === true
    || requestBody?.stream === true
    || contentType.includes('text/event-stream');
  if (isStream) return null;

  try {
    const rawText = await readRuntimeResponseText(ctx.response.clone());
    return parseDebugTextPayload(rawText);
  } catch {
    return null;
  }
}

export function buildSurfaceProxyDebugResponseHeaders(
  response:
    | Headers
    | Record<string, unknown>
    | { headers?: Headers | Record<string, unknown> | null | undefined }
    | null
    | undefined,
): Record<string, unknown> | null {
  if (!response) return null;
  if (typeof response === 'object' && 'headers' in response) {
    const responseHeaders = (response as {
      headers?: Headers | Record<string, unknown> | null | undefined;
    }).headers;
    return normalizeProxyDebugResponseHeaders(responseHeaders ?? null);
  }
  return normalizeProxyDebugResponseHeaders(response);
}

export function parseSurfaceProxyDebugTextPayload(rawText: string): unknown {
  return parseDebugTextPayload(rawText);
}
