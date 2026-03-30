import type { IncomingMessage } from 'node:http';
import WebSocket from 'ws';
import {
  buildCodexWebsocketHandshakeHeaders,
  buildCodexWebsocketRequestBody,
  toCodexWebsocketUrl,
} from './codexWebsocketHeaders.js';
import { createCodexWebsocketSessionStore } from './codexWebsocketSessionStore.js';
import type {
  CodexWebsocketRuntimeResult,
  CodexWebsocketRuntimeSendInput,
  CodexWebsocketSession,
  CodexWebsocketSessionStore,
} from './types.js';

function asTrimmedString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function isTerminalEvent(payload: Record<string, unknown>): boolean {
  const type = asTrimmedString(payload.type);
  return type === 'response.completed'
    || type === 'response.failed'
    || type === 'response.incomplete'
    || type === 'error';
}

function isRuntimeErrorEvent(payload: Record<string, unknown>): boolean {
  const type = asTrimmedString(payload.type);
  return type === 'error';
}

function asFiniteNumber(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}

function extractFailureTerminalStatus(payload: Record<string, unknown>): number {
  const response = isRecord(payload.response) ? payload.response : null;
  const responseError = response && isRecord(response.error) ? response.error : null;
  const topLevelError = isRecord(payload.error) ? payload.error : null;
  const candidates = [
    payload.status,
    payload.statusCode,
    payload.code,
    topLevelError?.status,
    topLevelError?.statusCode,
    topLevelError?.code,
    responseError?.status,
    responseError?.statusCode,
    responseError?.code,
  ];
  for (const candidate of candidates) {
    const status = asFiniteNumber(candidate);
    if (status !== undefined) return status;
  }
  return 502;
}

function extractTerminalErrorMessage(payload: Record<string, unknown>): string {
  const type = asTrimmedString(payload.type);
  if (type === 'error' && isRecord(payload.error)) {
    return asTrimmedString(payload.error.message) || 'upstream websocket error';
  }
  if ((type === 'response.failed' || type === 'response.incomplete') && isRecord(payload.response)) {
    if (isRecord(payload.response.error)) {
      return asTrimmedString(payload.response.error.message) || `upstream ${type}`;
    }
    if (isRecord(payload.response.incomplete_details)) {
      return asTrimmedString(payload.response.incomplete_details.reason) || `upstream ${type}`;
    }
  }
  return `upstream ${type || 'websocket error'}`;
}

export class CodexWebsocketRuntimeError extends Error {
  events: Array<Record<string, unknown>>;
  status?: number;
  payload?: unknown;

  constructor(
    message: string,
    options?: {
      events?: Array<Record<string, unknown>>;
      status?: number;
      payload?: unknown;
    },
  ) {
    super(message);
    this.name = 'CodexWebsocketRuntimeError';
    this.events = options?.events ?? [];
    this.status = options?.status;
    this.payload = options?.payload;
  }
}

function tryParseJson(raw: string): unknown {
  const trimmed = raw.trim();
  if (!trimmed) return undefined;
  try {
    return JSON.parse(trimmed);
  } catch {
    return undefined;
  }
}

async function readUnexpectedResponseBody(response: IncomingMessage): Promise<string> {
  return await new Promise<string>((resolve) => {
    const chunks: Buffer[] = [];
    response.on('data', (chunk) => {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    });
    response.once('end', () => {
      resolve(Buffer.concat(chunks).toString('utf8'));
    });
    response.once('error', () => {
      resolve('');
    });
  });
}

async function waitForSocketOpen(socket: WebSocket): Promise<void> {
  if (socket.readyState === WebSocket.OPEN) return;
  if (socket.readyState !== WebSocket.CONNECTING) {
    throw new Error('upstream websocket is not open');
  }
  await new Promise<void>((resolve, reject) => {
    const cleanup = () => {
      socket.off('open', onOpen);
      socket.off('error', onError);
      socket.off('close', onClose);
      socket.off('unexpected-response', onUnexpectedResponse);
    };
    const onOpen = () => {
      cleanup();
      resolve();
    };
    const onError = (error: Error) => {
      cleanup();
      reject(error);
    };
    const onClose = () => {
      cleanup();
      reject(new Error('upstream websocket closed before opening'));
    };
    const onUnexpectedResponse = (_request: unknown, response: IncomingMessage) => {
      void readUnexpectedResponseBody(response).then((body) => {
        cleanup();
        reject(new CodexWebsocketRuntimeError(
          body.trim() || response.statusMessage || `upstream websocket upgrade failed with status ${response.statusCode || 502}`,
          {
            status: response.statusCode || 502,
            payload: tryParseJson(body),
          },
        ));
      });
    };
    socket.once('open', onOpen);
    socket.once('error', onError);
    socket.once('close', onClose);
    socket.once('unexpected-response', onUnexpectedResponse);
  });
}

async function closeSocket(socket: WebSocket | null): Promise<void> {
  if (!socket) return;
  if (socket.readyState === WebSocket.CLOSED) return;
  await new Promise<void>((resolve) => {
    const onClose = () => resolve();
    socket.once('close', onClose);
    try {
      socket.close();
    } catch {
      socket.off('close', onClose);
      resolve();
    }
    setTimeout(() => {
      socket.off('close', onClose);
      resolve();
    }, 200);
  });
}

function clearSessionSocket(session: CodexWebsocketSession, socket: WebSocket): void {
  if (session.socket !== socket) return;
  session.socket = null;
  session.socketUrl = null;
}

async function ensureSessionSocket(
  session: CodexWebsocketSession,
  input: CodexWebsocketRuntimeSendInput,
): Promise<{ socket: WebSocket; reusedSession: boolean }> {
  const requestUrl = toCodexWebsocketUrl(input.requestUrl);
  const existing = session.socket;
  if (
    existing
    && session.socketUrl === requestUrl
    && existing.readyState === WebSocket.OPEN
  ) {
    return {
      socket: existing,
      reusedSession: true,
    };
  }

  if (existing) {
    await closeSocket(existing);
    clearSessionSocket(session, existing);
  }

  const nextSocket = new WebSocket(requestUrl, {
    headers: buildCodexWebsocketHandshakeHeaders(input.headers),
  });
  await waitForSocketOpen(nextSocket);
  session.socket = nextSocket;
  session.socketUrl = requestUrl;

  nextSocket.on('close', () => {
    clearSessionSocket(session, nextSocket);
  });
  nextSocket.on('error', () => {
    clearSessionSocket(session, nextSocket);
  });

  return {
    socket: nextSocket,
    reusedSession: false,
  };
}

async function sendSessionRequest(
  session: CodexWebsocketSession,
  input: CodexWebsocketRuntimeSendInput,
): Promise<CodexWebsocketRuntimeResult> {
  const { socket, reusedSession } = await ensureSessionSocket(session, input);
  const events: Array<Record<string, unknown>> = [];

  return new Promise<CodexWebsocketRuntimeResult>((resolve, reject) => {
    let settled = false;

    const cleanup = () => {
      socket.off('message', onMessage);
      socket.off('error', onError);
      socket.off('close', onClose);
    };

    const rejectWith = (message: string) => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(new CodexWebsocketRuntimeError(message, { events: [...events] }));
    };

    const onMessage = (payload: WebSocket.RawData) => {
      try {
        const parsed = JSON.parse(String(payload));
        if (!isRecord(parsed)) return;
        events.push(parsed);
        if (!isTerminalEvent(parsed)) return;
        if (settled) return;
        if (isRuntimeErrorEvent(parsed)) {
          settled = true;
          cleanup();
          clearSessionSocket(session, socket);
          void closeSocket(socket);
          reject(new CodexWebsocketRuntimeError(extractTerminalErrorMessage(parsed), {
            events: [...events],
            status: extractFailureTerminalStatus(parsed),
            payload: parsed,
          }));
          return;
        }
        settled = true;
        cleanup();
        resolve({
          events: [...events],
          reusedSession,
        });
      } catch {
        // Ignore malformed frames and wait for a terminal event.
      }
    };

    const onError = (error: Error) => {
      clearSessionSocket(session, socket);
      rejectWith(error.message || 'upstream websocket error');
    };

    const onClose = () => {
      clearSessionSocket(session, socket);
      rejectWith('stream closed before response.completed');
    };

    socket.on('message', onMessage);
    socket.once('error', onError);
    socket.once('close', onClose);

    socket.send(JSON.stringify(buildCodexWebsocketRequestBody(input.body)), (error) => {
      if (!error) return;
      clearSessionSocket(session, socket);
      rejectWith(error.message || 'failed to send upstream websocket request');
    });
  });
}

export function createCodexWebsocketRuntime(input?: {
  sessionStore?: CodexWebsocketSessionStore;
}) {
  const sessionStore = input?.sessionStore || createCodexWebsocketSessionStore();

  return {
    async sendRequest(payload: CodexWebsocketRuntimeSendInput): Promise<CodexWebsocketRuntimeResult> {
      const sessionId = payload.sessionId.trim();
      if (!sessionId) {
        throw new CodexWebsocketRuntimeError('missing websocket session id');
      }

      const session = sessionStore.getOrCreate(sessionId);
      const run = session.queue
        .catch(() => undefined)
        .then(() => sendSessionRequest(session, payload));
      session.queue = run.then(() => undefined, () => undefined);
      return run;
    },

    async closeSession(sessionId: string): Promise<void> {
      const session = sessionStore.take(sessionId);
      if (!session) return;
      await session.queue.catch(() => undefined);
      await closeSocket(session.socket);
      session.socket = null;
      session.socketUrl = null;
    },

    async closeAllSessions(): Promise<void> {
      const sessions = sessionStore.list();
      for (const session of sessions) {
        await this.closeSession(session.sessionId);
      }
    },
  };
}
