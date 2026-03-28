import { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { randomUUID } from 'node:crypto';
import { fetch, File as UndiciFile, FormData as UndiciFormData } from 'undici';
import { config } from '../../config.js';
import { readRuntimeResponseText } from '../../proxy-core/executors/types.js';

type UndiciRequestInit = Parameters<typeof fetch>[1];

type TestChatMessage = { role: string; content: string };
type TestTargetFormat = 'openai' | 'claude' | 'responses' | 'gemini';

type TestChatRequestBody = {
  model?: string;
  messages?: TestChatMessage[];
  targetFormat?: TestTargetFormat;
  stream?: boolean;
  temperature?: number;
  top_p?: number;
  max_tokens?: number;
  frequency_penalty?: number;
  presence_penalty?: number;
  seed?: number;
};

type ValidatedTestChatPayload = {
  model: string;
  messages: TestChatMessage[];
  targetFormat: TestTargetFormat;
  stream?: boolean;
  temperature?: number;
  top_p?: number;
  max_tokens?: number;
  frequency_penalty?: number;
  presence_penalty?: number;
  seed?: number;
};

type ProxyTestMethod = 'POST' | 'GET' | 'DELETE';
type ProxyTestRequestKind = 'json' | 'multipart' | 'empty';

type ProxyTestMultipartFile = {
  field: string;
  name: string;
  mimeType: string;
  dataUrl: string;
};

type ProxyTestEnvelope = {
  method?: ProxyTestMethod;
  path?: string;
  requestKind?: ProxyTestRequestKind;
  stream?: boolean;
  jobMode?: boolean;
  rawMode?: boolean;
  jsonBody?: unknown;
  rawJsonText?: string;
  multipartFields?: Record<string, string>;
  multipartFiles?: ProxyTestMultipartFile[];
};

type ValidatedProxyTestEnvelope = {
  method: ProxyTestMethod;
  path: string;
  requestKind: ProxyTestRequestKind;
  stream: boolean;
  jobMode: boolean;
  rawMode: boolean;
  jsonBody?: unknown;
  rawJsonText?: string;
  multipartFields?: Record<string, string>;
  multipartFiles?: ProxyTestMultipartFile[];
};

type TestJobStatus = 'pending' | 'succeeded' | 'failed' | 'cancelled';

type TestProxyJob = {
  id: string;
  status: TestJobStatus;
  envelope: ValidatedProxyTestEnvelope;
  result?: unknown;
  error?: unknown;
  controller?: AbortController | null;
  createdAt: number;
  updatedAt: number;
  expiresAt: number;
};

const JOB_TTL_MS = 10 * 60 * 1000;
const JOB_CLEANUP_INTERVAL_MS = 60 * 1000;
const jobs = new Map<string, TestProxyJob>();

const ALLOWED_PROXY_PATH_PATTERNS: RegExp[] = [
  /^\/v1\/chat\/completions(?:\?.*)?$/i,
  /^\/v1\/files(?:\/[^/?#]+(?:\/content)?)?(?:\?.*)?$/i,
  /^\/v1\/responses(?:\/compact)?(?:\?.*)?$/i,
  /^\/v1\/messages(?:\?.*)?$/i,
  /^\/v1\/embeddings(?:\?.*)?$/i,
  /^\/v1\/search(?:\?.*)?$/i,
  /^\/v1\/images\/(?:generations|edits)(?:\?.*)?$/i,
  /^\/v1\/videos(?:\?.*)?$/i,
  /^\/v1\/videos\/[^/?#]+(?:\?.*)?$/i,
  /^\/gemini\/[^/]+\/models(?:\?.*)?$/i,
  /^\/gemini\/[^/]+\/models\/.+(?:\?.*)?$/i,
  /^\/v1beta\/models(?:\?.*)?$/i,
  /^\/v1beta\/models\/.+(?:\?.*)?$/i,
];

class UpstreamProxyError extends Error {
  statusCode: number;
  responsePayload: unknown;

  constructor(statusCode: number, responsePayload: unknown) {
    super(`Upstream request failed with status ${statusCode}`);
    this.name = 'UpstreamProxyError';
    this.statusCode = statusCode;
    this.responsePayload = responsePayload;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function normalizeErrorPayload(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return { error: { message: text, type: 'upstream_error' } };
  }
}

function normalizeProxyPath(value: unknown): string {
  if (typeof value !== 'string') return '';
  const trimmed = value.trim();
  if (!trimmed) return '';
  try {
    if (/^https?:\/\//i.test(trimmed)) {
      const url = new URL(trimmed);
      return `${url.pathname}${url.search}`;
    }
  } catch {
    // ignore invalid absolute URL
  }
  return trimmed.startsWith('/') ? trimmed : `/${trimmed}`;
}

function isAllowedProxyPath(path: string): boolean {
  return ALLOWED_PROXY_PATH_PATTERNS.some((pattern) => pattern.test(path));
}

function validateLegacyPayload(
  body: TestChatRequestBody,
  reply: FastifyReply,
): ValidatedTestChatPayload | null {
  if (!body.model || body.model.trim().length === 0) {
    reply.code(400).send({ error: 'model is required' });
    return null;
  }

  if (!Array.isArray(body.messages) || body.messages.length === 0) {
    reply.code(400).send({ error: 'messages is required' });
    return null;
  }

  const targetFormat: TestTargetFormat = body.targetFormat === 'claude'
    ? 'claude'
    : body.targetFormat === 'responses'
      ? 'responses'
      : body.targetFormat === 'gemini'
        ? 'gemini'
        : 'openai';

  return {
    model: body.model,
    messages: body.messages,
    targetFormat,
    stream: body.stream,
    temperature: body.temperature,
    top_p: body.top_p,
    max_tokens: body.max_tokens,
    frequency_penalty: body.frequency_penalty,
    presence_penalty: body.presence_penalty,
    seed: body.seed,
  };
}

function convertOpenAiPayloadToClaudeBody(
  payload: ValidatedTestChatPayload,
  forceStream: boolean,
): Record<string, unknown> {
  const systemContents: string[] = [];
  const messages: Array<{ role: 'user' | 'assistant'; content: string }> = [];

  for (const message of payload.messages) {
    const role = typeof message.role === 'string' ? message.role : 'user';
    const content = typeof message.content === 'string' ? message.content : '';
    if (!content.trim()) continue;

    if (role === 'system') {
      systemContents.push(content);
      continue;
    }

    messages.push({
      role: role === 'assistant' ? 'assistant' : 'user',
      content,
    });
  }

  const body: Record<string, unknown> = {
    model: payload.model,
    stream: forceStream,
    max_tokens: typeof payload.max_tokens === 'number' && Number.isFinite(payload.max_tokens)
      ? payload.max_tokens
      : 4096,
    messages,
  };

  if (systemContents.length > 0) body.system = systemContents.join('\n\n');
  if (typeof payload.temperature === 'number' && Number.isFinite(payload.temperature)) {
    body.temperature = payload.temperature;
  }
  if (typeof payload.top_p === 'number' && Number.isFinite(payload.top_p)) {
    body.top_p = payload.top_p;
  }

  return body;
}

function convertOpenAiPayloadToResponsesBody(
  payload: ValidatedTestChatPayload,
  forceStream: boolean,
): Record<string, unknown> {
  const systemContents: string[] = [];
  const messages: Array<{ role: 'user' | 'assistant'; content: string }> = [];

  for (const message of payload.messages) {
    const role = typeof message.role === 'string' ? message.role : 'user';
    const content = typeof message.content === 'string' ? message.content : '';
    if (!content.trim()) continue;

    if (role === 'system') {
      systemContents.push(content);
      continue;
    }

    messages.push({
      role: role === 'assistant' ? 'assistant' : 'user',
      content,
    });
  }

  const body: Record<string, unknown> = {
    model: payload.model,
    stream: forceStream,
  };

  if (messages.length === 1 && messages[0].role === 'user' && systemContents.length === 0) {
    body.input = messages[0].content;
  } else {
    body.input = messages;
    if (systemContents.length > 0) {
      body.instructions = systemContents.join('\n\n');
    }
  }

  if (typeof payload.temperature === 'number' && Number.isFinite(payload.temperature)) {
    body.temperature = payload.temperature;
  }
  if (typeof payload.top_p === 'number' && Number.isFinite(payload.top_p)) {
    body.top_p = payload.top_p;
  }
  body.max_output_tokens = typeof payload.max_tokens === 'number' && Number.isFinite(payload.max_tokens)
    ? payload.max_tokens
    : 4096;

  return body;
}

function convertLegacyPayloadToEnvelope(
  payload: ValidatedTestChatPayload,
  forceStream: boolean,
): ValidatedProxyTestEnvelope {
  if (payload.targetFormat === 'claude') {
    return {
      method: 'POST',
      path: '/v1/messages',
      requestKind: 'json',
      stream: forceStream,
      jobMode: false,
      rawMode: false,
      jsonBody: convertOpenAiPayloadToClaudeBody(payload, forceStream),
    };
  }

  if (payload.targetFormat === 'responses') {
    return {
      method: 'POST',
      path: '/v1/responses',
      requestKind: 'json',
      stream: forceStream,
      jobMode: false,
      rawMode: false,
      jsonBody: convertOpenAiPayloadToResponsesBody(payload, forceStream),
    };
  }

  return {
    method: 'POST',
    path: '/v1/chat/completions',
    requestKind: 'json',
    stream: forceStream,
    jobMode: false,
    rawMode: false,
    jsonBody: {
      ...payload,
      stream: forceStream,
    },
  };
}

function validateProxyEnvelope(
  body: ProxyTestEnvelope,
  reply: FastifyReply,
): ValidatedProxyTestEnvelope | null {
  const method = body.method === 'GET' || body.method === 'DELETE' ? body.method : 'POST';
  const path = normalizeProxyPath(body.path);

  if (!path) {
    reply.code(400).send({ error: { message: 'path is required', type: 'validation_error' } });
    return null;
  }

  if (!isAllowedProxyPath(path)) {
    reply.code(400).send({ error: { message: `path is not allowed: ${path}`, type: 'validation_error' } });
    return null;
  }

  const requestKind: ProxyTestRequestKind = body.requestKind === 'multipart'
    ? 'multipart'
    : body.requestKind === 'empty'
      ? 'empty'
      : 'json';

  if (method !== 'POST' && requestKind !== 'empty') {
    reply.code(400).send({
      error: { message: `${method} only supports requestKind=empty in tester`, type: 'validation_error' },
    });
    return null;
  }

  const envelope: ValidatedProxyTestEnvelope = {
    method,
    path,
    requestKind,
    stream: body.stream === true,
    jobMode: body.jobMode === true,
    rawMode: body.rawMode === true,
  };

  if (requestKind === 'json') {
    if (typeof body.rawJsonText === 'string' && body.rawJsonText.trim().length > 0) {
      envelope.rawJsonText = body.rawJsonText;
    }
    if (body.jsonBody !== undefined) {
      envelope.jsonBody = body.jsonBody;
    }
    if (envelope.rawMode && typeof envelope.rawJsonText !== 'string') {
      reply.code(400).send({
        error: { message: 'rawJsonText is required when rawMode is enabled', type: 'validation_error' },
      });
      return null;
    }
  }

  if (requestKind === 'multipart') {
    envelope.multipartFields = isRecord(body.multipartFields)
      ? Object.fromEntries(
        Object.entries(body.multipartFields)
          .filter((entry): entry is [string, string] => typeof entry[0] === 'string' && typeof entry[1] === 'string'),
      )
      : {};
    envelope.multipartFiles = Array.isArray(body.multipartFiles)
      ? body.multipartFiles
        .filter((item): item is ProxyTestMultipartFile => (
          !!item
          && typeof item.field === 'string'
          && item.field.trim().length > 0
          && typeof item.name === 'string'
          && item.name.trim().length > 0
          && typeof item.mimeType === 'string'
          && item.mimeType.trim().length > 0
          && typeof item.dataUrl === 'string'
          && item.dataUrl.trim().length > 0
        ))
      : [];
    if ((envelope.multipartFiles?.length || 0) === 0 && Object.keys(envelope.multipartFields || {}).length === 0) {
      reply.code(400).send({
        error: { message: 'multipart requests require multipartFields or multipartFiles', type: 'validation_error' },
      });
      return null;
    }
  }

  if (requestKind === 'empty' && (method === 'POST' || path === '/v1/search')) {
    // keep explicit empty body path legal, no additional validation
  }

  return envelope;
}

function decodeDataUrl(dataUrl: string): { mimeType: string; buffer: Buffer } {
  const match = /^data:([^;,]+)?;base64,(.+)$/i.exec(dataUrl.trim());
  if (!match) {
    throw new Error('multipartFiles[].dataUrl must be a base64 data URL');
  }
  return {
    mimeType: match[1] || 'application/octet-stream',
    buffer: Buffer.from(match[2], 'base64'),
  };
}

function createDefaultHeadersForPath(path: string): Record<string, string> {
  if (/^\/v1\/messages$/i.test(path)) {
    return {
      'x-api-key': config.proxyToken,
      'anthropic-version': '2023-06-01',
    };
  }

  if (/^\/(?:gemini\/[^/]+\/models\/.+|v1beta\/models\/.+)$/i.test(path)) {
    return {
      'x-goog-api-key': config.proxyToken,
    };
  }

  return {
    Authorization: `Bearer ${config.proxyToken}`,
  };
}

function applyStreamOverride(value: unknown, forceStream: boolean): unknown {
  if (!isRecord(value)) return value;
  return {
    ...value,
    stream: forceStream,
  };
}

function serializeJsonEnvelopeBody(
  envelope: ValidatedProxyTestEnvelope,
  forceStream: boolean,
): string | undefined {
  if (typeof envelope.rawJsonText === 'string' && envelope.rawJsonText.trim().length > 0) {
    try {
      const parsed = JSON.parse(envelope.rawJsonText);
      return JSON.stringify(applyStreamOverride(parsed, forceStream));
    } catch {
      return envelope.rawJsonText;
    }
  }

  if (envelope.jsonBody !== undefined) {
    return JSON.stringify(applyStreamOverride(envelope.jsonBody, forceStream));
  }

  return JSON.stringify({ stream: forceStream });
}

async function buildUpstreamRequestInit(
  envelope: ValidatedProxyTestEnvelope,
  forceStream: boolean,
): Promise<UndiciRequestInit> {
  const headers: Record<string, string> = createDefaultHeadersForPath(envelope.path);

  if (envelope.requestKind === 'json') {
    headers['Content-Type'] = 'application/json';
    return {
      method: envelope.method,
      headers,
      body: serializeJsonEnvelopeBody(envelope, forceStream),
    };
  }

  if (envelope.requestKind === 'multipart') {
    const FormDataCtor = globalThis.FormData ?? UndiciFormData;
    const FileCtor = globalThis.File ?? UndiciFile;
    const formData = new FormDataCtor();
    for (const [field, value] of Object.entries(envelope.multipartFields || {})) {
      formData.append(field, value);
    }
    for (const file of envelope.multipartFiles || []) {
      const decoded = decodeDataUrl(file.dataUrl);
      const bytes = Uint8Array.from(decoded.buffer);
      formData.append(
        file.field,
        new FileCtor([bytes], file.name, { type: file.mimeType || decoded.mimeType }),
      );
    }

    return {
      method: envelope.method,
      headers,
      body: formData as any,
    };
  }

  return {
    method: envelope.method,
    headers,
  };
}

async function fetchProxyBuffered(
  envelope: ValidatedProxyTestEnvelope,
  signal?: AbortSignal,
  forceStream = false,
): Promise<unknown> {
  const upstream = await fetch(`http://127.0.0.1:${config.port}${envelope.path}`, {
    ...(await buildUpstreamRequestInit(envelope, forceStream)),
    signal,
  });

  const contentType = upstream.headers.get('content-type') || '';
  const text = await readRuntimeResponseText(upstream);

  if (!upstream.ok) {
    throw new UpstreamProxyError(upstream.status, normalizeErrorPayload(text));
  }

  if (contentType.includes('application/json')) {
    try {
      return JSON.parse(text);
    } catch {
      return { raw: text };
    }
  }

  try {
    return JSON.parse(text);
  } catch {
    return { raw: text };
  }
}

function cleanupExpiredJobs() {
  const now = Date.now();
  for (const [jobId, job] of jobs.entries()) {
    if (job.expiresAt <= now) {
      jobs.delete(jobId);
    }
  }
}

async function runJob(jobId: string) {
  const job = jobs.get(jobId);
  if (!job || job.status !== 'pending') return;

  const controller = new AbortController();
  job.controller = controller;

  try {
    const result = await fetchProxyBuffered(job.envelope, controller.signal, job.envelope.stream);
    const current = jobs.get(jobId);
    if (!current) return;
    current.controller = null;
    current.status = 'succeeded';
    current.result = result;
    current.updatedAt = Date.now();
    current.expiresAt = current.updatedAt + JOB_TTL_MS;
  } catch (error) {
    const current = jobs.get(jobId);
    if (!current) return;
    current.controller = null;

    if ((error as any)?.name === 'AbortError') {
      current.status = 'cancelled';
      current.error = { error: { message: 'job cancelled', type: 'cancelled' } };
      current.updatedAt = Date.now();
      current.expiresAt = current.updatedAt + 30_000;
      return;
    }

    current.status = 'failed';
    current.error = error instanceof UpstreamProxyError
      ? error.responsePayload
      : { error: { message: (error as any)?.message || 'proxy request failed', type: 'server_error' } };
    current.updatedAt = Date.now();
    current.expiresAt = current.updatedAt + JOB_TTL_MS;
  }
}

async function sendBufferedEnvelope(
  envelope: ValidatedProxyTestEnvelope,
  reply: FastifyReply,
  forceStream = false,
) {
  try {
    const data = await fetchProxyBuffered(envelope, undefined, forceStream);
    return reply.send(data);
  } catch (error) {
    if (error instanceof UpstreamProxyError) {
      return reply.code(error.statusCode).send(error.responsePayload);
    }
    return reply.code(502).send({
      error: {
        message: (error as any)?.message || 'proxy request failed',
        type: 'server_error',
      },
    });
  }
}

async function sendStreamingEnvelope(
  envelope: ValidatedProxyTestEnvelope,
  request: FastifyRequest,
  reply: FastifyReply,
  forceStream = true,
) {
  const controller = new AbortController();
  const abortUpstream = () => {
    try {
      if (!controller.signal.aborted) {
        controller.abort();
      }
    } catch {
      // no-op
    }
  };

  const onClientAborted = () => abortUpstream();
  const onClientClosed = () => {
    if (!reply.raw.writableEnded) abortUpstream();
  };
  const cleanupClientListeners = () => {
    request.raw.off?.('aborted', onClientAborted);
    reply.raw.off?.('close', onClientClosed);
  };

  request.raw.on('aborted', onClientAborted);
  reply.raw.on('close', onClientClosed);

  let upstream;
  try {
    upstream = await fetch(`http://127.0.0.1:${config.port}${envelope.path}`, {
      ...(await buildUpstreamRequestInit(envelope, forceStream)),
      signal: controller.signal,
    });
  } catch (error) {
    cleanupClientListeners();
    return reply.code(502).send({
      error: {
        message: (error as any)?.message || 'proxy request failed',
        type: 'server_error',
      },
    });
  }

  if (!upstream.ok) {
    const text = await readRuntimeResponseText(upstream);
    cleanupClientListeners();
    return reply.code(upstream.status).send(normalizeErrorPayload(text));
  }

  const contentType = upstream.headers.get('content-type') || '';
  const reader = contentType.includes('text/event-stream') ? upstream.body?.getReader() : null;
  if (contentType.includes('text/event-stream') && !reader) {
    cleanupClientListeners();
    return reply.code(502).send({
      error: {
        message: 'upstream stream body missing',
        type: 'server_error',
      },
    });
  }

  reply.hijack();
  reply.raw.statusCode = 200;
  reply.raw.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
  reply.raw.setHeader('Cache-Control', 'no-cache, no-transform');
  reply.raw.setHeader('Connection', 'keep-alive');
  reply.raw.setHeader('X-Accel-Buffering', 'no');

  try {
    if (contentType.includes('text/event-stream')) {
      const streamReader = reader!;
      try {
        while (true) {
          const { done, value } = await streamReader.read();
          if (done) break;
          if (value) {
            reply.raw.write(Buffer.from(value));
          }
        }
      } finally {
        try {
          await streamReader.cancel();
        } catch {
          // no-op
        } finally {
          streamReader.releaseLock();
        }
      }
    } else {
      const text = await readRuntimeResponseText(upstream);
      for (const line of text.split(/\r?\n/)) {
        reply.raw.write(`data: ${line}\n`);
      }
      reply.raw.write('\n');
      reply.raw.write('data: [DONE]\n\n');
    }
  } catch (error) {
    if (!reply.raw.writableEnded) {
      const message = JSON.stringify({
        error: { message: (error as any)?.message || 'stream interrupted', type: 'stream_error' },
      });
      reply.raw.write(`event: error\ndata: ${message}\n\n`);
    }
  } finally {
    cleanupClientListeners();
    if (!reply.raw.writableEnded) {
      reply.raw.end();
    }
  }
}

export async function testRoutes(app: FastifyInstance) {
  const cleanupTimer = setInterval(cleanupExpiredJobs, JOB_CLEANUP_INTERVAL_MS);
  cleanupTimer.unref?.();

  app.addHook('onClose', async () => {
    clearInterval(cleanupTimer);
  });

  app.post<{ Body: ProxyTestEnvelope }>(
    '/api/test/proxy',
    async (request, reply) => {
      const envelope = validateProxyEnvelope(request.body || {}, reply);
      if (!envelope) return;
      return sendBufferedEnvelope(envelope, reply, false);
    },
  );

  app.post<{ Body: ProxyTestEnvelope }>(
    '/api/test/proxy/stream',
    async (request, reply) => {
      const envelope = validateProxyEnvelope(request.body || {}, reply);
      if (!envelope) return;
      return sendStreamingEnvelope(envelope, request, reply, true);
    },
  );

  app.post<{ Body: ProxyTestEnvelope }>(
    '/api/test/proxy/jobs',
    async (request, reply) => {
      const envelope = validateProxyEnvelope(request.body || {}, reply);
      if (!envelope) return;

      const now = Date.now();
      const jobId = randomUUID();
      const job: TestProxyJob = {
        id: jobId,
        status: 'pending',
        envelope,
        controller: null,
        createdAt: now,
        updatedAt: now,
        expiresAt: now + JOB_TTL_MS,
      };

      jobs.set(jobId, job);
      void runJob(jobId);

      return reply.code(202).send({
        jobId,
        status: job.status,
        createdAt: new Date(job.createdAt).toISOString(),
        expiresAt: new Date(job.expiresAt).toISOString(),
      });
    },
  );

  app.get<{ Params: { jobId: string } }>(
    '/api/test/proxy/jobs/:jobId',
    async (request, reply) => {
      const job = jobs.get(request.params.jobId);
      if (!job) {
        return reply.code(404).send({ error: { message: 'job not found', type: 'not_found' } });
      }

      return reply.send({
        jobId: job.id,
        status: job.status,
        result: job.result,
        error: job.error,
        createdAt: new Date(job.createdAt).toISOString(),
        updatedAt: new Date(job.updatedAt).toISOString(),
        expiresAt: new Date(job.expiresAt).toISOString(),
      });
    },
  );

  app.delete<{ Params: { jobId: string } }>(
    '/api/test/proxy/jobs/:jobId',
    async (request, reply) => {
      const job = jobs.get(request.params.jobId);
      if (!job) {
        return reply.code(404).send({ error: { message: 'job not found', type: 'not_found' } });
      }

      if (job.status === 'pending' && job.controller) {
        try {
          job.controller.abort();
        } catch {
          // no-op
        }
      }

      jobs.delete(request.params.jobId);
      return reply.send({ success: true });
    },
  );

  app.post<{ Body: TestChatRequestBody }>(
    '/api/test/chat',
    async (request, reply) => {
      const payload = validateLegacyPayload(request.body || {}, reply);
      if (!payload) return;
      return sendBufferedEnvelope(convertLegacyPayloadToEnvelope(payload, false), reply, false);
    },
  );

  app.post<{ Body: TestChatRequestBody }>(
    '/api/test/chat/stream',
    async (request, reply) => {
      const payload = validateLegacyPayload(request.body || {}, reply);
      if (!payload) return;
      return sendStreamingEnvelope(convertLegacyPayloadToEnvelope(payload, true), request, reply, true);
    },
  );

  app.post<{ Body: TestChatRequestBody }>(
    '/api/test/chat/jobs',
    async (request, reply) => {
      const payload = validateLegacyPayload(request.body || {}, reply);
      if (!payload) return;

      const envelope = convertLegacyPayloadToEnvelope(payload, false);
      const now = Date.now();
      const jobId = randomUUID();
      const job: TestProxyJob = {
        id: jobId,
        status: 'pending',
        envelope,
        controller: null,
        createdAt: now,
        updatedAt: now,
        expiresAt: now + JOB_TTL_MS,
      };

      jobs.set(jobId, job);
      void runJob(jobId);

      return reply.code(202).send({
        jobId,
        status: job.status,
        createdAt: new Date(job.createdAt).toISOString(),
        expiresAt: new Date(job.expiresAt).toISOString(),
      });
    },
  );

  app.get<{ Params: { jobId: string } }>(
    '/api/test/chat/jobs/:jobId',
    async (request, reply) => {
      const job = jobs.get(request.params.jobId);
      if (!job) {
        return reply.code(404).send({ error: { message: 'job not found', type: 'not_found' } });
      }

      return reply.send({
        jobId: job.id,
        status: job.status,
        result: job.result,
        error: job.error,
        createdAt: new Date(job.createdAt).toISOString(),
        updatedAt: new Date(job.updatedAt).toISOString(),
        expiresAt: new Date(job.expiresAt).toISOString(),
      });
    },
  );

  app.delete<{ Params: { jobId: string } }>(
    '/api/test/chat/jobs/:jobId',
    async (request, reply) => {
      const job = jobs.get(request.params.jobId);
      if (!job) {
        return reply.code(404).send({ error: { message: 'job not found', type: 'not_found' } });
      }

      if (job.status === 'pending' && job.controller) {
        try {
          job.controller.abort();
        } catch {
          // no-op
        }
      }

      jobs.delete(request.params.jobId);
      return reply.send({ success: true });
    },
  );
}
