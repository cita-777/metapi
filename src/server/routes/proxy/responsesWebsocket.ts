import { randomUUID } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import type { IncomingMessage } from 'node:http';
import { WebSocketServer, type RawData, type WebSocket } from 'ws';
import { openAiResponsesTransformer } from '../../transformers/openai/responses/index.js';

const installedApps = new WeakSet<FastifyInstance>();

type NormalizedResponsesWebsocketRequest =
  | {
    ok: true;
    request: Record<string, unknown>;
    nextRequestSnapshot: Record<string, unknown>;
  }
  | {
    ok: false;
    status: number;
    message: string;
  };

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function asTrimmedString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function parseJsonObject(raw: RawData): Record<string, unknown> | null {
  try {
    const parsed = JSON.parse(String(raw));
    return isRecord(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function cloneJsonObject<T>(value: T): T {
  return structuredClone(value);
}

function toResponseInputArray(value: unknown): unknown[] {
  return Array.isArray(value) ? cloneJsonObject(value) : [];
}

function normalizeResponsesWebsocketRequest(
  raw: RawData,
  lastRequest: Record<string, unknown> | null,
  lastResponseOutput: unknown[],
): NormalizedResponsesWebsocketRequest {
  const parsed = parseJsonObject(raw);
  if (!parsed) {
    return {
      ok: false,
      status: 400,
      message: 'Invalid websocket JSON payload',
    };
  }

  const requestType = asTrimmedString(parsed.type);
  if (requestType !== 'response.create' && requestType !== 'response.append') {
    return {
      ok: false,
      status: 400,
      message: `unsupported websocket request type: ${requestType || 'unknown'}`,
    };
  }

  if (requestType === 'response.create' && parsed.generate === false) {
    const next = cloneJsonObject(parsed);
    delete next.type;
    delete next.generate;
    next.stream = true;
    if (!Array.isArray(next.input)) next.input = [];
    const modelName = asTrimmedString(next.model);
    if (!modelName) {
      return {
        ok: false,
        status: 400,
        message: 'missing model in response.create request',
      };
    }
    return {
      ok: true,
      request: next,
      nextRequestSnapshot: cloneJsonObject(next),
    };
  }

  if (!lastRequest) {
    if (requestType !== 'response.create') {
      return {
        ok: false,
        status: 400,
        message: 'websocket request received before response.create',
      };
    }
    const next = cloneJsonObject(parsed);
    delete next.type;
    next.stream = true;
    if (!Array.isArray(next.input)) next.input = [];
    const modelName = asTrimmedString(next.model);
    if (!modelName) {
      return {
        ok: false,
        status: 400,
        message: 'missing model in response.create request',
      };
    }
    return {
      ok: true,
      request: next,
      nextRequestSnapshot: cloneJsonObject(next),
    };
  }

  if (!Array.isArray(parsed.input)) {
    return {
      ok: false,
      status: 400,
      message: 'websocket request requires array field: input',
    };
  }

  const mergedInput = [
    ...toResponseInputArray(lastRequest.input),
    ...cloneJsonObject(lastResponseOutput),
    ...cloneJsonObject(parsed.input),
  ];
  const next = cloneJsonObject(parsed);
  delete next.type;
  delete next.previous_response_id;
  next.input = mergedInput;
  next.stream = true;
  if (!('model' in next) && typeof lastRequest.model === 'string') {
    next.model = lastRequest.model;
  }
  if (!('instructions' in next) && lastRequest.instructions !== undefined) {
    next.instructions = cloneJsonObject(lastRequest.instructions);
  }

  return {
    ok: true,
    request: next,
    nextRequestSnapshot: cloneJsonObject(next),
  };
}

function writeResponsesWebsocketError(
  socket: WebSocket,
  status: number,
  message: string,
  errorPayload?: unknown,
) {
  socket.send(JSON.stringify({
    type: 'error',
    status,
    error: isRecord(errorPayload) && isRecord(errorPayload.error)
      ? errorPayload.error
      : {
        type: status >= 500 ? 'server_error' : 'invalid_request_error',
        message,
      },
  }));
}

function synthesizePrewarmResponsePayloads(request: Record<string, unknown>) {
  const responseId = `resp_prewarm_${randomUUID()}`;
  const modelName = asTrimmedString(request.model) || 'unknown';
  const createdAt = Math.floor(Date.now() / 1000);
  return [
    {
      type: 'response.created',
      response: {
        id: responseId,
        object: 'response',
        created_at: createdAt,
        status: 'in_progress',
        model: modelName,
        output: [],
      },
    },
    {
      type: 'response.completed',
      response: {
        id: responseId,
        object: 'response',
        created_at: createdAt,
        status: 'completed',
        model: modelName,
        output: [],
        usage: {
          input_tokens: 0,
          output_tokens: 0,
          total_tokens: 0,
        },
      },
    },
  ];
}

function collectResponsesOutput(payloads: unknown[]): unknown[] {
  const outputByIndex = new Map<number, unknown>();
  let completedOutput: unknown[] | null = null;

  for (const payload of payloads) {
    if (!isRecord(payload)) continue;
    const type = asTrimmedString(payload.type);
    if ((type === 'response.output_item.added' || type === 'response.output_item.done')
      && Number.isInteger(payload.output_index)
      && payload.item !== undefined) {
      outputByIndex.set(Number(payload.output_index), cloneJsonObject(payload.item));
      continue;
    }
    if (type === 'response.completed' && isRecord(payload.response) && Array.isArray(payload.response.output)) {
      completedOutput = cloneJsonObject(payload.response.output);
    }
  }

  if (completedOutput) return completedOutput;
  return [...outputByIndex.entries()]
    .sort((left, right) => left[0] - right[0])
    .map(([, value]) => value);
}

function buildInjectHeaders(request: IncomingMessage): Record<string, string | string[]> {
  const headers: Record<string, string | string[]> = {};
  for (const [rawKey, rawValue] of Object.entries(request.headers)) {
    const key = rawKey.toLowerCase();
    if (!rawValue) continue;
    if (
      key === 'host'
      || key === 'connection'
      || key === 'upgrade'
      || key === 'sec-websocket-key'
      || key === 'sec-websocket-version'
      || key === 'sec-websocket-extensions'
      || key === 'sec-websocket-protocol'
    ) {
      continue;
    }
    headers[rawKey] = rawValue as string | string[];
  }
  return headers;
}

async function handleResponsesWebsocketConnection(
  app: FastifyInstance,
  socket: WebSocket,
  request: IncomingMessage,
) {
  let lastRequest: Record<string, unknown> | null = null;
  let lastResponseOutput: unknown[] = [];

  socket.on('message', async (raw) => {
    const parsed = parseJsonObject(raw);
    if (!parsed) {
      writeResponsesWebsocketError(socket, 400, 'Invalid websocket JSON payload');
      return;
    }

    const normalized = normalizeResponsesWebsocketRequest(raw, lastRequest, lastResponseOutput);
    if (!normalized.ok) {
      writeResponsesWebsocketError(socket, normalized.status, normalized.message);
      return;
    }

    lastRequest = normalized.nextRequestSnapshot;
    if (parsed.generate === false && asTrimmedString(parsed.type) === 'response.create') {
      lastResponseOutput = [];
      for (const payload of synthesizePrewarmResponsePayloads(normalized.request)) {
        socket.send(JSON.stringify(payload));
      }
      return;
    }

    const response = await app.inject({
      method: 'POST',
      url: '/v1/responses',
      headers: buildInjectHeaders(request),
      payload: normalized.request,
    });

    if (response.statusCode < 200 || response.statusCode >= 300) {
      let payload: unknown = null;
      try {
        payload = JSON.parse(response.body);
      } catch {
        payload = null;
      }
      writeResponsesWebsocketError(
        socket,
        response.statusCode,
        response.statusMessage || 'Upstream error',
        payload,
      );
      return;
    }

    const contentType = String(response.headers['content-type'] || '').toLowerCase();
    if (!contentType.includes('text/event-stream')) {
      try {
        const payload = JSON.parse(response.body);
        socket.send(JSON.stringify(payload));
        lastResponseOutput = isRecord(payload?.response) && Array.isArray(payload.response.output)
          ? cloneJsonObject(payload.response.output)
          : [];
      } catch {
        writeResponsesWebsocketError(socket, 502, 'Unexpected non-JSON websocket proxy response');
      }
      return;
    }

    const pulled = openAiResponsesTransformer.pullSseEvents(response.body);
    const forwardedPayloads: unknown[] = [];
    for (const event of pulled.events) {
      if (event.data === '[DONE]') continue;
      try {
        const payload = JSON.parse(event.data);
        forwardedPayloads.push(payload);
        socket.send(JSON.stringify(payload));
      } catch {
        // Ignore malformed SSE frames; the HTTP route already normalizes them.
      }
    }
    lastResponseOutput = collectResponsesOutput(forwardedPayloads);
  });
}

export function ensureResponsesWebsocketTransport(app: FastifyInstance) {
  if (installedApps.has(app)) return;
  installedApps.add(app);

  const websocketServer = new WebSocketServer({ noServer: true });

  app.server.on('upgrade', (request, socket, head) => {
    const url = new URL(request.url || '/', 'http://localhost');
    if (url.pathname !== '/v1/responses') return;
    websocketServer.handleUpgrade(request, socket, head, (client) => {
      void handleResponsesWebsocketConnection(app, client, request);
    });
  });

  app.addHook('onClose', async () => {
    await new Promise<void>((resolve) => {
      websocketServer.close(() => resolve());
    });
  });
}
