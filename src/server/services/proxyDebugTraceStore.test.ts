import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Response } from 'undici';

type DbModule = typeof import('../db/index.js');
type StoreModule = typeof import('./proxyDebugTraceStore.js');

describe('proxyDebugTraceStore', () => {
  let db: DbModule['db'];
  let schema: DbModule['schema'];
  let store: StoreModule;
  let dataDir = '';

  beforeAll(async () => {
    dataDir = mkdtempSync(join(tmpdir(), 'metapi-proxy-debug-traces-'));
    process.env.DATA_DIR = dataDir;

    await import('../db/migrate.js');
    const dbModule = await import('../db/index.js');
    const storeModule = await import('./proxyDebugTraceStore.js');
    db = dbModule.db;
    schema = dbModule.schema;
    store = storeModule;
  });

  beforeEach(async () => {
    await db.delete(schema.proxyDebugAttempts).run();
    await db.delete(schema.proxyDebugTraces).run();
  });

  afterAll(async () => {
    const dbModule = await import('../db/index.js');
    await dbModule.closeDbConnections();
    delete process.env.DATA_DIR;
  });

  it('creates, updates, and reads unredacted debug traces and attempts', async () => {
    const trace = await store.createProxyDebugTrace({
      downstreamPath: '/v1/responses',
      clientKind: 'codex',
      sessionId: 'sess-1',
      traceHint: 'trace-abc',
      requestedModel: 'gpt-4o',
      downstreamApiKeyId: 7,
      requestHeaders: {
        authorization: 'Bearer developer-token',
        'x-client': 'Codex Desktop',
      },
      requestBody: {
        model: 'gpt-4o',
        input: [{ role: 'user', content: 'hello' }],
      },
    });

    await store.updateProxyDebugTraceSelection(trace.id, {
      stickySessionKey: 'key:7|codex|/v1/responses|gpt-4o|sess-1',
      stickyHitChannelId: 12,
      selectedChannelId: 12,
      selectedRouteId: 99,
      selectedAccountId: 33,
      selectedSiteId: 8,
      selectedSitePlatform: 'codex',
    });

    await store.updateProxyDebugTraceCandidates(trace.id, {
      endpointCandidates: ['responses', 'chat'],
      endpointRuntimeState: {
        preferredEndpoint: 'responses',
        blockedEndpoints: [],
      },
      decisionSummary: {
        reason: 'platform default + sticky session',
      },
    });

    const attempt = await store.insertProxyDebugAttempt({
      traceId: trace.id,
      attemptIndex: 0,
      endpoint: 'responses',
      requestPath: '/responses',
      targetUrl: 'https://chatgpt.com/backend-api/codex/responses',
      runtimeExecutor: 'codex',
      requestHeaders: {
        authorization: 'Bearer developer-token',
      },
      requestBody: {
        model: 'gpt-4o',
        store: false,
      },
      responseStatus: 403,
      responseHeaders: {
        'content-type': 'application/json',
      },
      responseBody: {
        error: {
          message: 'forbidden',
        },
      },
      rawErrorText: '{"error":{"message":"forbidden"}}',
      recoverApplied: false,
      downgradeDecision: true,
      downgradeReason: '[upstream:/responses] forbidden',
      memoryWrite: {
        action: 'failure',
        blockedEndpoint: 'responses',
      },
    });

    expect(attempt.id).toBeGreaterThan(0);

    await store.finalizeProxyDebugTrace(trace.id, {
      finalStatus: 'failed',
      finalHttpStatus: 503,
      finalUpstreamPath: '/responses',
      finalResponseHeaders: {
        'content-type': 'application/json',
      },
      finalResponseBody: {
        error: {
          message: 'Channel busy',
        },
      },
    });

    const list = await store.listProxyDebugTraces({ limit: 20 });
    expect(list).toHaveLength(1);
    expect(list[0]).toMatchObject({
      requestedModel: 'gpt-4o',
      downstreamPath: '/v1/responses',
      clientKind: 'codex',
      sessionId: 'sess-1',
      selectedChannelId: 12,
      finalStatus: 'failed',
      finalHttpStatus: 503,
      finalUpstreamPath: '/responses',
    });

    const detail = await store.getProxyDebugTraceDetail(trace.id);
    expect(detail?.trace.requestHeadersJson || '').toContain('Bearer developer-token');
    expect(detail?.trace.requestBodyJson || '').toContain('"hello"');
    expect(detail?.trace.finalResponseBodyJson || '').toContain('Channel busy');
    expect(detail?.attempts).toHaveLength(1);
    expect(detail?.attempts[0]?.requestHeadersJson || '').toContain('developer-token');
    expect(detail?.attempts[0]?.responseBodyJson || '').toContain('forbidden');
    expect(detail?.attempts[0]).toMatchObject({
      endpoint: 'responses',
      runtimeExecutor: 'codex',
      responseStatus: 403,
      downgradeDecision: true,
    });
  });

  it('stores truncated debug payload previews as valid JSON text for json-capable databases', async () => {
    const trace = await store.createProxyDebugTrace({
      downstreamPath: '/v1/responses',
      clientKind: 'codex',
      requestedModel: 'gpt-5.4',
      requestHeaders: {
        authorization: `Bearer ${'x'.repeat(5000)}`,
        'x-client': 'Codex Desktop',
      },
      requestBody: {
        model: 'gpt-5.4',
        input: [{ role: 'user', content: 'hello '.repeat(2000) }],
      },
      maxBodyBytes: 1024,
    });

    const detail = await store.getProxyDebugTraceDetail(trace.id);
    const headersPayload = JSON.parse(detail?.trace.requestHeadersJson || 'null');
    const bodyPayload = JSON.parse(detail?.trace.requestBodyJson || 'null');

    expect(headersPayload).toMatchObject({
      __metapiTruncated: true,
    });
    expect(typeof headersPayload.preview).toBe('string');
    expect(headersPayload.preview).toContain('authorization');

    expect(bodyPayload).toMatchObject({
      __metapiTruncated: true,
    });
    expect(typeof bodyPayload.preview).toBe('string');
    expect(bodyPayload.preview).toContain('"model": "gpt-5.4"');
  });

  it('normalizes undici response headers for proxy debug capture', () => {
    const response = new Response('ok', {
      headers: {
        'content-type': 'application/json',
        'x-trace-id': 'trace-123',
      },
    });

    expect(store.normalizeProxyDebugResponseHeaders(response.headers)).toEqual({
      'content-type': 'application/json',
      'x-trace-id': 'trace-123',
    });
  });
});
