import Fastify, { type FastifyInstance } from 'fastify';
import { createServer, type Server } from 'node:http';
import { AddressInfo } from 'node:net';
import WebSocket, { WebSocketServer } from 'ws';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { config } from '../../config.js';

const fetchMock = vi.fn();
const selectChannelMock = vi.fn();
const selectNextChannelMock = vi.fn();
const previewSelectedChannelMock = vi.fn();
const recordSuccessMock = vi.fn();
const recordFailureMock = vi.fn();
const authorizeDownstreamTokenMock = vi.fn();
const consumeManagedKeyRequestMock = vi.fn();
const refreshModelsAndRebuildRoutesMock = vi.fn();
const reportProxyAllFailedMock = vi.fn();
const reportTokenExpiredMock = vi.fn();
const resolveProxyUsageWithSelfLogFallbackMock = vi.fn(async ({ usage }: any) => ({
  ...usage,
  estimatedCostFromQuota: 0,
  recoveredFromSelfLog: false,
}));
const dbInsertMock = vi.fn((_arg?: any) => ({
  values: () => ({
    run: () => undefined,
  }),
}));

vi.mock('undici', () => ({
  fetch: (...args: unknown[]) => fetchMock(...args),
}));

vi.mock('../../services/tokenRouter.js', () => ({
  tokenRouter: {
    selectChannel: (...args: unknown[]) => selectChannelMock(...args),
    selectNextChannel: (...args: unknown[]) => selectNextChannelMock(...args),
    previewSelectedChannel: (...args: unknown[]) => previewSelectedChannelMock(...args),
    recordSuccess: (...args: unknown[]) => recordSuccessMock(...args),
    recordFailure: (...args: unknown[]) => recordFailureMock(...args),
  },
}));

vi.mock('../../services/modelService.js', () => ({
  refreshModelsAndRebuildRoutes: (...args: unknown[]) => refreshModelsAndRebuildRoutesMock(...args),
}));

vi.mock('../../services/alertService.js', () => ({
  reportProxyAllFailed: (...args: unknown[]) => reportProxyAllFailedMock(...args),
  reportTokenExpired: (...args: unknown[]) => reportTokenExpiredMock(...args),
}));

vi.mock('../../services/downstreamApiKeyService.js', () => ({
  authorizeDownstreamToken: (...args: unknown[]) => authorizeDownstreamTokenMock(...args),
  consumeManagedKeyRequest: (...args: unknown[]) => consumeManagedKeyRequestMock(...args),
  isModelAllowedByPolicyOrAllowedRoutes: async (
    model: string,
    policy: { supportedModels?: string[]; allowedRouteIds?: number[]; denyAllWhenEmpty?: boolean },
  ) => {
    const supportedModels = Array.isArray(policy?.supportedModels) ? policy.supportedModels : [];
    const allowedRouteIds = Array.isArray(policy?.allowedRouteIds) ? policy.allowedRouteIds : [];
    if (supportedModels.length === 0 && allowedRouteIds.length === 0) {
      return policy?.denyAllWhenEmpty === true ? false : true;
    }
    return supportedModels.includes(model);
  },
}));

vi.mock('../../services/alertRules.js', () => ({
  isTokenExpiredError: () => false,
}));

vi.mock('../../services/modelPricingService.js', () => ({
  estimateProxyCost: async () => 0,
  buildProxyBillingDetails: async () => null,
  fetchModelPricingCatalog: async () => null,
}));

vi.mock('../../services/proxyRetryPolicy.js', () => ({
  shouldRetryProxyRequest: () => false,
}));

vi.mock('../../services/proxyUsageFallbackService.js', () => ({
  resolveProxyUsageWithSelfLogFallback: (arg: any) => resolveProxyUsageWithSelfLogFallbackMock(arg),
}));

vi.mock('../../services/oauth/quota.js', () => ({
  recordOauthQuotaResetHint: async () => undefined,
}));

vi.mock('../../db/index.js', () => ({
  db: {
    insert: (arg: any) => dbInsertMock(arg),
  },
  hasProxyLogBillingDetailsColumn: async () => false,
  hasProxyLogClientColumns: async () => false,
  hasProxyLogDownstreamApiKeyIdColumn: async () => false,
  schema: {
    proxyLogs: {},
  },
}));

function createSseResponse(chunks: string[], status = 200) {
  const encoder = new TextEncoder();
  return new Response(new ReadableStream<Uint8Array>({
    start(controller) {
      for (const chunk of chunks) {
        controller.enqueue(encoder.encode(chunk));
      }
      controller.close();
    },
  }), {
    status,
    headers: { 'content-type': 'text/event-stream; charset=utf-8' },
  });
}

function createSelectedChannel(options?: {
  siteName?: string;
  siteUrl?: string;
  sitePlatform?: string;
  username?: string;
  extraConfig?: string;
  tokenValue?: string;
  actualModel?: string;
}) {
  const sitePlatform = options?.sitePlatform ?? 'codex';
  const isCodex = sitePlatform === 'codex';
  return {
    channel: { id: 11, routeId: 22 },
    site: {
      name: options?.siteName ?? (isCodex ? 'codex-site' : 'openai-site'),
      url: options?.siteUrl ?? (isCodex ? 'https://chatgpt.com/backend-api/codex' : 'https://api.openai.com'),
      platform: sitePlatform,
    },
    account: {
      id: 33,
      username: options?.username ?? (isCodex ? 'codex-user@example.com' : 'openai-user@example.com'),
      extraConfig: options?.extraConfig ?? (isCodex
        ? JSON.stringify({
          credentialMode: 'session',
          oauth: {
            provider: 'codex',
            accountId: 'chatgpt-account-123',
            email: 'codex-user@example.com',
          },
        })
        : '{}'),
    },
    tokenName: 'default',
    tokenValue: options?.tokenValue ?? (isCodex ? 'oauth-access-token' : 'sk-openai-token'),
    actualModel: options?.actualModel ?? (isCodex ? 'gpt-5.4' : 'gpt-4.1'),
  };
}

function waitForSocketOpen(socket: WebSocket) {
  return new Promise<void>((resolve, reject) => {
    socket.once('open', () => resolve());
    socket.once('error', reject);
  });
}

function waitForSocketUpgrade(socket: WebSocket) {
  return new Promise<{ headers: Record<string, string | string[] | undefined> }>((resolve, reject) => {
    socket.once('upgrade', (response) => resolve({ headers: response.headers as Record<string, string | string[] | undefined> }));
    socket.once('error', reject);
  });
}

function waitForSocketMessages(socket: WebSocket, count: number, timeoutMs = 1000) {
  return new Promise<any[]>((resolve, reject) => {
    const messages: any[] = [];
    const timeout = setTimeout(() => {
      socket.off('message', onMessage);
      socket.off('error', onError);
      reject(new Error(`Timed out waiting for ${count} websocket messages`));
    }, timeoutMs);
    const onMessage = (payload: WebSocket.RawData) => {
      messages.push(JSON.parse(String(payload)));
      if (messages.length >= count) {
        clearTimeout(timeout);
        socket.off('message', onMessage);
        socket.off('error', onError);
        resolve(messages);
      }
    };
    const onError = (error: Error) => {
      clearTimeout(timeout);
      socket.off('message', onMessage);
      reject(error);
    };
    socket.on('message', onMessage);
    socket.once('error', onError);
  });
}

function waitForSocketMessageMatching(
  socket: WebSocket,
  predicate: (message: any) => boolean,
  timeoutMs = 1000,
) {
  return new Promise<any>((resolve, reject) => {
    const timeout = setTimeout(() => {
      socket.off('message', onMessage);
      socket.off('error', onError);
      reject(new Error('Timed out waiting for matching websocket message'));
    }, timeoutMs);
    const onMessage = (payload: WebSocket.RawData) => {
      const message = JSON.parse(String(payload));
      if (!predicate(message)) return;
      clearTimeout(timeout);
      socket.off('message', onMessage);
      socket.off('error', onError);
      resolve(message);
    };
    const onError = (error: Error) => {
      clearTimeout(timeout);
      socket.off('message', onMessage);
      reject(error);
    };
    socket.on('message', onMessage);
    socket.once('error', onError);
  });
}

function createDeferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

function createClientSocket(baseUrl: string, headers: Record<string, string> = {}) {
  return new WebSocket(`${baseUrl}/v1/responses`, {
    headers: {
      Authorization: 'Bearer sk-global-proxy-token',
      ...headers,
    },
  });
}

function createClientSocketForPath(path: string, headers: Record<string, string> = {}) {
  return new WebSocket(path, { headers });
}

describe('responses websocket transport', () => {
  const originalCodexResponsesWebsocketBeta = config.codexResponsesWebsocketBeta;
  let app: FastifyInstance;
  let baseUrl: string;
  let upstreamServer: WebSocketServer;
  let upstreamSiteUrl: string;
  let upstreamConnectionCount: number;
  let upstreamUpgradeHeaders: Record<string, string>;
  let upstreamRequests: Record<string, unknown>[];
  let upstreamMessageHandler: (socket: WebSocket, parsed: Record<string, unknown>, requestIndex: number) => void;
  let rejectedUpgradeServer: Server;
  let rejectedUpgradeSiteUrl: string;
  let rejectedUpgradeStatus: number;
  let rejectedUpgradeStatusText: string;
  let rejectedUpgradeBody: string;

  beforeAll(async () => {
    const { responsesProxyRoute } = await import('./responses.js');
    app = Fastify();
    await app.register(responsesProxyRoute);
    await app.listen({ port: 0, host: '127.0.0.1' });
    const address = app.server.address() as AddressInfo;
    baseUrl = `ws://127.0.0.1:${address.port}`;

    upstreamServer = new WebSocketServer({ port: 0 });
    upstreamServer.on('connection', (socket, request) => {
      upstreamConnectionCount += 1;
      upstreamUpgradeHeaders = Object.fromEntries(
        Object.entries(request.headers)
          .map(([key, value]) => [key, Array.isArray(value) ? value[0] || '' : value || '']),
      );
      socket.on('message', (payload) => {
        const parsed = JSON.parse(String(payload)) as Record<string, unknown>;
        upstreamRequests.push(parsed);
        upstreamMessageHandler(socket, parsed, upstreamRequests.length);
      });
    });
    await new Promise<void>((resolve) => upstreamServer.once('listening', () => resolve()));
    const upstreamAddress = upstreamServer.address() as AddressInfo;
    upstreamSiteUrl = `http://127.0.0.1:${upstreamAddress.port}/backend-api/codex`;

    rejectedUpgradeServer = createServer();
    rejectedUpgradeServer.on('upgrade', (_request, socket) => {
      const body = rejectedUpgradeBody;
      socket.write(
        `HTTP/1.1 ${rejectedUpgradeStatus} ${rejectedUpgradeStatusText}\r\n`
        + 'Content-Type: text/plain\r\n'
        + `Content-Length: ${Buffer.byteLength(body)}\r\n`
        + 'Connection: close\r\n'
        + '\r\n'
        + body,
      );
      socket.destroy();
    });
    await new Promise<void>((resolve) => rejectedUpgradeServer.listen(0, '127.0.0.1', () => resolve()));
    const rejectedAddress = rejectedUpgradeServer.address() as AddressInfo;
    rejectedUpgradeSiteUrl = `http://127.0.0.1:${rejectedAddress.port}/backend-api/codex`;
  });

  beforeEach(() => {
    fetchMock.mockReset();
    selectChannelMock.mockReset();
    selectNextChannelMock.mockReset();
    previewSelectedChannelMock.mockReset();
    recordSuccessMock.mockReset();
    recordFailureMock.mockReset();
    authorizeDownstreamTokenMock.mockReset();
    consumeManagedKeyRequestMock.mockReset();
    refreshModelsAndRebuildRoutesMock.mockReset();
    reportProxyAllFailedMock.mockReset();
    reportTokenExpiredMock.mockReset();
    resolveProxyUsageWithSelfLogFallbackMock.mockClear();
    dbInsertMock.mockClear();

    const selectedChannel = createSelectedChannel();
    selectChannelMock.mockReturnValue(selectedChannel);
    selectNextChannelMock.mockReturnValue(null);
    previewSelectedChannelMock.mockResolvedValue(selectedChannel);
    upstreamConnectionCount = 0;
    upstreamUpgradeHeaders = {};
    upstreamRequests = [];
    (config as any).codexResponsesWebsocketBeta = originalCodexResponsesWebsocketBeta;
    rejectedUpgradeStatus = 426;
    rejectedUpgradeStatusText = 'Upgrade Required';
    rejectedUpgradeBody = 'Upgrade Required';
    authorizeDownstreamTokenMock.mockResolvedValue({
      ok: true,
      source: 'global',
      token: 'sk-global-proxy-token',
      key: null,
      policy: {
        supportedModels: [],
        allowedRouteIds: [],
        siteWeightMultipliers: {},
      },
    });
    upstreamMessageHandler = (socket, parsed, requestIndex) => {
      const responseId = `resp_upstream_${requestIndex}`;
      socket.send(JSON.stringify({
        type: 'response.completed',
        response: {
          id: responseId,
          object: 'response',
          model: parsed.model || 'gpt-5.4',
          status: 'completed',
          output: [],
          usage: {
            input_tokens: 1,
            output_tokens: 1,
            total_tokens: 2,
          },
        },
      }));
    };
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => rejectedUpgradeServer.close(() => resolve()));
    await new Promise<void>((resolve) => upstreamServer.close(() => resolve()));
    await app.close();
  });

  it('accepts response.create over GET /v1/responses websocket and forwards streamed responses events', async () => {
    const selectedChannel = createSelectedChannel({
      siteUrl: upstreamSiteUrl,
    });
    selectChannelMock.mockReturnValue(selectedChannel);
    previewSelectedChannelMock.mockResolvedValue(selectedChannel);
    upstreamMessageHandler = (socket) => {
      socket.send(JSON.stringify({
        type: 'response.created',
        response: {
          id: 'resp_ws',
          model: 'gpt-5.4',
          created_at: 1706000000,
          status: 'in_progress',
          output: [],
        },
      }));
      socket.send(JSON.stringify({
        type: 'response.output_item.added',
        output_index: 0,
        item: {
          id: 'msg_ws',
          type: 'message',
          role: 'assistant',
          status: 'in_progress',
          content: [],
        },
      }));
      socket.send(JSON.stringify({
        type: 'response.output_text.delta',
        output_index: 0,
        item_id: 'msg_ws',
        delta: 'pong',
      }));
      socket.send(JSON.stringify({
        type: 'response.completed',
        response: {
          id: 'resp_ws',
          model: 'gpt-5.4',
          status: 'completed',
          output: [{
            id: 'msg_ws',
            type: 'message',
            role: 'assistant',
            status: 'completed',
            content: [{ type: 'output_text', text: 'pong' }],
          }],
          usage: {
            input_tokens: 3,
            output_tokens: 1,
            total_tokens: 4,
          },
        },
      }));
    };

    const socket = createClientSocket(baseUrl);
    await waitForSocketOpen(socket);
    const messagesPromise = waitForSocketMessages(socket, 4);

    socket.send(JSON.stringify({
      type: 'response.create',
      model: 'gpt-5.4',
      input: [
        {
          type: 'message',
          role: 'user',
          content: [{ type: 'input_text', text: 'hello websocket' }],
        },
      ],
    }));

    const messages = await messagesPromise;
    socket.close();

    expect(messages.map((message) => message.type)).toEqual([
      'response.created',
      'response.output_item.added',
      'response.output_text.delta',
      'response.completed',
    ]);
    expect(messages[3]?.response?.output?.[0]?.content?.[0]?.text).toBe('pong');
    expect(fetchMock).toHaveBeenCalledTimes(0);
    expect(upstreamConnectionCount).toBe(1);
  });

  it('echoes x-codex-turn-state on websocket upgrade responses', async () => {
    const socket = createClientSocket(baseUrl, {
      'x-codex-turn-state': 'turn-state-123',
    });

    const [upgrade] = await Promise.all([
      waitForSocketUpgrade(socket),
      waitForSocketOpen(socket),
    ]);
    socket.close();

    expect(upgrade.headers['x-codex-turn-state']).toBe('turn-state-123');
  });

  it('reuses one upstream codex websocket session across sequential websocket turns', async () => {
    (config as any).codexResponsesWebsocketBeta = 'responses_websockets=2099-01-01';
    const selectedChannel = createSelectedChannel({
      siteUrl: upstreamSiteUrl,
    });
    selectChannelMock.mockReturnValue(selectedChannel);
    previewSelectedChannelMock.mockResolvedValue(selectedChannel);

    const socket = createClientSocket(baseUrl, {
      'x-codex-turn-state': 'turn-state-123',
      'x-codex-beta-features': 'feature-a,feature-b',
    });
    await waitForSocketOpen(socket);
    const firstMessagesPromise = waitForSocketMessages(socket, 1);

    socket.send(JSON.stringify({
      type: 'response.create',
      model: 'gpt-5.4',
      input: [],
    }));

    const firstMessages = await firstMessagesPromise;

    const secondMessagesPromise = waitForSocketMessages(socket, 1);
    socket.send(JSON.stringify({
      type: 'response.create',
      model: 'gpt-5.4',
      previous_response_id: firstMessages[0]?.response?.id,
      input: [],
    }));

    const secondMessages = await secondMessagesPromise;
    socket.close();

    expect(fetchMock).toHaveBeenCalledTimes(0);
    expect(firstMessages[0]?.type).toBe('response.completed');
    expect(secondMessages[0]?.type).toBe('response.completed');
    expect(upstreamConnectionCount).toBe(1);
    expect(upstreamRequests).toHaveLength(2);
    expect(upstreamRequests[0]).toMatchObject({
      type: 'response.create',
      model: 'gpt-5.4',
    });
    expect(upstreamRequests[1]).toMatchObject({
      type: 'response.create',
      previous_response_id: firstMessages[0]?.response?.id,
    });
    expect(upstreamUpgradeHeaders['x-codex-turn-state']).toBe('turn-state-123');
    expect(upstreamUpgradeHeaders['x-codex-beta-features']).toBe('feature-a,feature-b');
    expect(upstreamUpgradeHeaders['openai-beta']).toContain('responses_websockets=2099-01-01');
  });

  it('falls back to the HTTP responses executor when the upstream codex websocket upgrade returns 426', async () => {
    const selectedChannel = createSelectedChannel({
      siteUrl: rejectedUpgradeSiteUrl,
    });
    selectChannelMock.mockReturnValue(selectedChannel);
    previewSelectedChannelMock.mockResolvedValue(selectedChannel);
    fetchMock.mockResolvedValueOnce(createSseResponse([
      'event: response.completed\n',
      'data: {"type":"response.completed","response":{"id":"resp_http_fallback","model":"gpt-5.4","status":"completed","output":[],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}\n\n',
      'data: [DONE]\n\n',
    ]));

    const socket = createClientSocket(baseUrl);
    await waitForSocketOpen(socket);
    const messagesPromise = waitForSocketMessages(socket, 1);

    socket.send(JSON.stringify({
      type: 'response.create',
      model: 'gpt-5.4',
      input: [],
    }));

    const messages = await messagesPromise;
    socket.close();

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(messages.map((message) => message.type)).toEqual(['response.completed']);
    expect(messages[0]?.response?.id).toBe('resp_http_fallback');
  });

  it('falls back to the HTTP responses executor when the upstream codex websocket upgrade returns 401', async () => {
    rejectedUpgradeStatus = 401;
    rejectedUpgradeStatusText = 'Unauthorized';
    rejectedUpgradeBody = JSON.stringify({
      error: {
        message: 'expired token',
        type: 'invalid_request_error',
      },
    });
    const selectedChannel = createSelectedChannel({
      siteUrl: rejectedUpgradeSiteUrl,
    });
    selectChannelMock.mockReturnValue(selectedChannel);
    previewSelectedChannelMock.mockResolvedValue(selectedChannel);
    fetchMock.mockResolvedValueOnce(createSseResponse([
      'event: response.completed\n',
      'data: {"type":"response.completed","response":{"id":"resp_http_fallback_401","model":"gpt-5.4","status":"completed","output":[],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}\n\n',
      'data: [DONE]\n\n',
    ]));

    const socket = createClientSocket(baseUrl);
    await waitForSocketOpen(socket);
    const messagesPromise = waitForSocketMessages(socket, 1);

    socket.send(JSON.stringify({
      type: 'response.create',
      model: 'gpt-5.4',
      input: [],
    }));

    const messages = await messagesPromise;
    socket.close();

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(messages.map((message) => message.type)).toEqual(['response.completed']);
    expect(messages[0]?.response?.id).toBe('resp_http_fallback_401');
  });

  it('preserves previous_response_id when websocket upgrade fallback uses HTTP on incremental-capable upstreams', async () => {
    rejectedUpgradeStatus = 426;
    rejectedUpgradeStatusText = 'Upgrade Required';
    rejectedUpgradeBody = JSON.stringify({
      error: {
        message: 'upgrade required',
        type: 'invalid_request_error',
      },
    });

    const selectedChannel = createSelectedChannel({
      siteUrl: rejectedUpgradeSiteUrl,
    });
    selectChannelMock.mockReturnValue(selectedChannel);
    previewSelectedChannelMock.mockResolvedValue(selectedChannel);
    fetchMock
      .mockResolvedValueOnce(createSseResponse([
        'event: response.completed\n',
        'data: {"type":"response.completed","response":{"id":"resp_http_fallback_1","model":"gpt-5.4","status":"completed","output":[{"id":"msg_1","type":"message","role":"assistant","status":"completed","content":[{"type":"output_text","text":"first"}]}],"usage":{"input_tokens":3,"output_tokens":1,"total_tokens":4}}}\n\n',
        'data: [DONE]\n\n',
      ]))
      .mockResolvedValueOnce(createSseResponse([
        'event: response.completed\n',
        'data: {"type":"response.completed","response":{"id":"resp_http_fallback_2","model":"gpt-5.4","status":"completed","output":[{"id":"msg_2","type":"message","role":"assistant","status":"completed","content":[{"type":"output_text","text":"second"}]}],"usage":{"input_tokens":5,"output_tokens":1,"total_tokens":6}}}\n\n',
        'data: [DONE]\n\n',
      ]));

    const socket = createClientSocket(baseUrl);
    await waitForSocketOpen(socket);
    const firstResponsePromise = waitForSocketMessages(socket, 1);

    socket.send(JSON.stringify({
      type: 'response.create',
      model: 'gpt-5.4',
      instructions: 'be helpful',
      input: [],
    }));

    const firstMessages = await firstResponsePromise;
    const secondResponsePromise = waitForSocketMessages(socket, 1);
    socket.send(JSON.stringify({
      type: 'response.create',
      model: 'gpt-5.4',
      previous_response_id: 'resp_http_fallback_1',
      input: [
        {
          id: 'tool_out_1',
          type: 'function_call_output',
          call_id: 'call_1',
          output: 'tool result',
        },
      ],
    }));

    await secondResponsePromise;
    socket.close();

    expect(firstMessages[0]?.type).toBe('response.completed');
    expect(fetchMock).toHaveBeenCalledTimes(2);
    const [, secondOptions] = fetchMock.mock.calls[1] as [string, RequestInit];
    const secondBody = JSON.parse(String(secondOptions.body));
    expect(secondBody.previous_response_id).toBe('resp_http_fallback_1');
    expect(secondBody.input).toEqual([
      {
        id: 'tool_out_1',
        type: 'function_call_output',
        call_id: 'call_1',
        output: 'tool result',
      },
    ]);
  });

  it('preserves query parameter auth when websocket transport falls back to the HTTP responses route', async () => {
    rejectedUpgradeStatus = 401;
    rejectedUpgradeStatusText = 'Unauthorized';
    rejectedUpgradeBody = JSON.stringify({
      error: {
        message: 'expired token',
        type: 'invalid_request_error',
      },
    });
    const selectedChannel = createSelectedChannel({
      siteUrl: rejectedUpgradeSiteUrl,
    });
    selectChannelMock.mockReturnValue(selectedChannel);
    previewSelectedChannelMock.mockResolvedValue(selectedChannel);
    authorizeDownstreamTokenMock.mockResolvedValueOnce({
      ok: true,
      source: 'global',
      token: 'sk-query-auth',
      key: null,
      policy: {
        supportedModels: [],
        allowedRouteIds: [],
        siteWeightMultipliers: {},
      },
    });
    fetchMock.mockResolvedValueOnce(createSseResponse([
      'event: response.completed\n',
      'data: {"type":"response.completed","response":{"id":"resp_http_fallback_query","model":"gpt-5.4","status":"completed","output":[],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}\n\n',
      'data: [DONE]\n\n',
    ]));

    const socket = createClientSocketForPath(`${baseUrl}/v1/responses?key=sk-query-auth`);
    await waitForSocketOpen(socket);
    const messagesPromise = waitForSocketMessages(socket, 1);

    socket.send(JSON.stringify({
      type: 'response.create',
      model: 'gpt-5.4',
      input: [],
    }));

    const messages = await messagesPromise;
    socket.close();

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(messages[0]?.response?.id).toBe('resp_http_fallback_query');
  });

  it('rejects websocket turns whose model is blocked by the downstream key policy before channel selection', async () => {
    authorizeDownstreamTokenMock.mockResolvedValueOnce({
      ok: true,
      source: 'managed',
      token: 'sk-managed-denied',
      key: {
        id: 99,
        name: 'limited-key',
      },
      policy: {
        supportedModels: ['gpt-4.1'],
        allowedRouteIds: [],
        siteWeightMultipliers: {},
      },
    });

    const socket = createClientSocket(baseUrl);
    await waitForSocketOpen(socket);
    const messagesPromise = waitForSocketMessages(socket, 1);

    socket.send(JSON.stringify({
      type: 'response.create',
      model: 'gpt-5.4',
      input: [],
    }));

    const messages = await messagesPromise;
    socket.close();

    expect(messages[0]).toMatchObject({
      type: 'error',
      status: 403,
    });
    expect(selectChannelMock).not.toHaveBeenCalled();
  });

  it('merges follow-up response.create payloads when the selected upstream does not support incremental mode', async () => {
    const selectedChannel = createSelectedChannel({
      sitePlatform: 'openai',
      actualModel: 'gpt-4.1',
    });
    selectChannelMock.mockReturnValue(selectedChannel);
    previewSelectedChannelMock.mockResolvedValue(selectedChannel);
    fetchMock
      .mockResolvedValueOnce(createSseResponse([
        'event: response.output_item.done\n',
        'data: {"type":"response.output_item.done","output_index":0,"item":{"id":"fc_1","type":"function_call","call_id":"call_1"}}\n\n',
        'event: response.output_item.done\n',
        'data: {"type":"response.output_item.done","output_index":1,"item":{"id":"msg_1","type":"message","role":"assistant","status":"completed","content":[{"type":"output_text","text":"call tool"}]}}\n\n',
        'event: response.completed\n',
        'data: {"type":"response.completed","response":{"id":"resp_ws_1","model":"gpt-4.1","status":"completed","output":[{"id":"fc_1","type":"function_call","call_id":"call_1"},{"id":"msg_1","type":"message","role":"assistant","status":"completed","content":[{"type":"output_text","text":"call tool"}]}],"usage":{"input_tokens":3,"output_tokens":1,"total_tokens":4}}}\n\n',
        'data: [DONE]\n\n',
      ]))
      .mockResolvedValueOnce(createSseResponse([
        'event: response.completed\n',
        'data: {"type":"response.completed","response":{"id":"resp_ws_2","model":"gpt-4.1","status":"completed","output":[{"id":"msg_2","type":"message","role":"assistant","status":"completed","content":[{"type":"output_text","text":"done"}]}],"usage":{"input_tokens":5,"output_tokens":1,"total_tokens":6}}}\n\n',
        'data: [DONE]\n\n',
      ]));

    const socket = createClientSocket(baseUrl);
    await waitForSocketOpen(socket);

    const firstResponsePromise = waitForSocketMessages(socket, 1);
    socket.send(JSON.stringify({
      type: 'response.create',
      model: 'gpt-4.1',
      instructions: 'be helpful',
      input: [
        {
          id: 'msg_user_1',
          type: 'message',
          role: 'user',
          content: [{ type: 'input_text', text: 'call the tool' }],
        },
      ],
    }));
    await firstResponsePromise;

    const secondResponsePromise = waitForSocketMessages(socket, 1);
    socket.send(JSON.stringify({
      type: 'response.create',
      previous_response_id: 'resp_ws_1',
      input: [
        {
          id: 'tool_out_1',
          type: 'function_call_output',
          call_id: 'call_1',
          output: 'tool result',
        },
      ],
    }));
    await secondResponsePromise;
    socket.close();

    expect(fetchMock).toHaveBeenCalledTimes(2);
    const [, firstOptions] = fetchMock.mock.calls[0] as [string, RequestInit];
    const [, secondOptions] = fetchMock.mock.calls[1] as [string, RequestInit];
    const firstBody = JSON.parse(String(firstOptions.body));
    const secondBody = JSON.parse(String(secondOptions.body));

    expect(firstBody.input).toHaveLength(1);
    expect(secondBody.previous_response_id).toBeUndefined();
    expect(secondBody.model).toBe('gpt-4.1');
    expect(secondBody.instructions).toBe('be helpful');
    expect(secondBody.input).toEqual([
      {
        id: 'msg_user_1',
        type: 'message',
        role: 'user',
        content: [{ type: 'input_text', text: 'call the tool' }],
      },
      {
        id: 'fc_1',
        type: 'function_call',
        call_id: 'call_1',
        status: 'completed',
      },
      {
        id: 'msg_1',
        type: 'message',
        role: 'assistant',
        status: 'completed',
        content: [{ type: 'output_text', text: 'call tool' }],
      },
      {
        id: 'tool_out_1',
        type: 'function_call_output',
        call_id: 'call_1',
        output: 'tool result',
      },
    ]);
  });

  it('serializes websocket messages per connection so follow-up turns wait for the previous HTTP fallback to finish', async () => {
    const selectedChannel = createSelectedChannel({
      sitePlatform: 'openai',
      actualModel: 'gpt-4.1',
    });
    selectChannelMock.mockReturnValue(selectedChannel);
    previewSelectedChannelMock.mockResolvedValue(selectedChannel);
    const firstResponseGate = createDeferred<Response>();
    fetchMock
      .mockImplementationOnce(() => firstResponseGate.promise)
      .mockResolvedValueOnce(createSseResponse([
        'event: response.completed\n',
        'data: {"type":"response.completed","response":{"id":"resp_ws_2","model":"gpt-4.1","status":"completed","output":[{"id":"msg_2","type":"message","role":"assistant","status":"completed","content":[{"type":"output_text","text":"done"}]}],"usage":{"input_tokens":5,"output_tokens":1,"total_tokens":6}}}\n\n',
        'data: [DONE]\n\n',
      ]));

    const socket = createClientSocket(baseUrl);
    await waitForSocketOpen(socket);

    socket.send(JSON.stringify({
      type: 'response.create',
      model: 'gpt-4.1',
      instructions: 'be helpful',
      input: [
        {
          id: 'msg_user_1',
          type: 'message',
          role: 'user',
          content: [{ type: 'input_text', text: 'call the tool' }],
        },
      ],
    }));

    while (fetchMock.mock.calls.length < 1) {
      await new Promise((resolve) => setTimeout(resolve, 0));
    }

    socket.send(JSON.stringify({
      type: 'response.create',
      previous_response_id: 'resp_ws_1',
      input: [
        {
          id: 'tool_out_1',
          type: 'function_call_output',
          call_id: 'call_1',
          output: 'tool result',
        },
      ],
    }));

    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(fetchMock).toHaveBeenCalledTimes(1);

    const secondTurnPromise = waitForSocketMessageMatching(
      socket,
      (message) => message?.type === 'response.completed' && message?.response?.id === 'resp_ws_2',
    );
    firstResponseGate.resolve(createSseResponse([
      'event: response.output_item.done\n',
      'data: {"type":"response.output_item.done","output_index":0,"item":{"id":"fc_1","type":"function_call","call_id":"call_1"}}\n\n',
      'event: response.output_item.done\n',
      'data: {"type":"response.output_item.done","output_index":1,"item":{"id":"msg_1","type":"message","role":"assistant","status":"completed","content":[{"type":"output_text","text":"call tool"}]}}\n\n',
      'event: response.completed\n',
      'data: {"type":"response.completed","response":{"id":"resp_ws_1","model":"gpt-4.1","status":"completed","output":[{"id":"fc_1","type":"function_call","call_id":"call_1"},{"id":"msg_1","type":"message","role":"assistant","status":"completed","content":[{"type":"output_text","text":"call tool"}]}],"usage":{"input_tokens":3,"output_tokens":1,"total_tokens":4}}}\n\n',
      'data: [DONE]\n\n',
    ]));

    while (fetchMock.mock.calls.length < 2) {
      await new Promise((resolve) => setTimeout(resolve, 0));
    }

    const secondTurnMessage = await secondTurnPromise;
    socket.close();

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(secondTurnMessage).toMatchObject({
      type: 'response.completed',
      response: {
        id: 'resp_ws_2',
      },
    });
    const [, secondOptions] = fetchMock.mock.calls[1] as [string, RequestInit];
    const secondBody = JSON.parse(String(secondOptions.body));
    expect(secondBody.input).toEqual([
      {
        id: 'msg_user_1',
        type: 'message',
        role: 'user',
        content: [{ type: 'input_text', text: 'call the tool' }],
      },
      {
        id: 'fc_1',
        type: 'function_call',
        call_id: 'call_1',
        status: 'completed',
      },
      {
        id: 'msg_1',
        type: 'message',
        role: 'assistant',
        status: 'completed',
        content: [{ type: 'output_text', text: 'call tool' }],
      },
      {
        id: 'tool_out_1',
        type: 'function_call_output',
        call_id: 'call_1',
        output: 'tool result',
      },
    ]);
  });

  it('preserves incremental response.create payloads with previous_response_id for websocket-capable upstreams', async () => {
    const selectedChannel = createSelectedChannel({
      siteUrl: upstreamSiteUrl,
    });
    selectChannelMock.mockReturnValue(selectedChannel);
    previewSelectedChannelMock.mockResolvedValue(selectedChannel);
    upstreamMessageHandler = (socket, _parsed, requestIndex) => {
      if (requestIndex === 1) {
        socket.send(JSON.stringify({
          type: 'response.completed',
          response: {
            id: 'resp_ws_1',
            model: 'gpt-5.4',
            status: 'completed',
            output: [{
              id: 'msg_1',
              type: 'message',
              role: 'assistant',
              status: 'completed',
              content: [{ type: 'output_text', text: 'call tool' }],
            }],
            usage: {
              input_tokens: 3,
              output_tokens: 1,
              total_tokens: 4,
            },
          },
        }));
        return;
      }
      socket.send(JSON.stringify({
        type: 'response.completed',
        response: {
          id: 'resp_ws_2',
          model: 'gpt-5.4',
          status: 'completed',
          output: [{
            id: 'msg_2',
            type: 'message',
            role: 'assistant',
            status: 'completed',
            content: [{ type: 'output_text', text: 'done' }],
          }],
          usage: {
            input_tokens: 5,
            output_tokens: 1,
            total_tokens: 6,
          },
        },
      }));
    };

    const socket = createClientSocket(baseUrl);
    await waitForSocketOpen(socket);

    const firstResponsePromise = waitForSocketMessages(socket, 1);
    socket.send(JSON.stringify({
      type: 'response.create',
      model: 'gpt-5.4',
      instructions: 'be helpful',
      input: [
        {
          id: 'msg_user_1',
          type: 'message',
          role: 'user',
          content: [{ type: 'input_text', text: 'call the tool' }],
        },
      ],
    }));
    await firstResponsePromise;

    const secondResponsePromise = waitForSocketMessageMatching(
      socket,
      (message) => message?.type === 'response.completed' && message?.response?.id === 'resp_ws_2',
    );
    socket.send(JSON.stringify({
      type: 'response.create',
      previous_response_id: 'resp_ws_1',
      input: [
        {
          id: 'tool_out_1',
          type: 'function_call_output',
          call_id: 'call_1',
          output: 'tool result',
        },
      ],
    }));
    const secondResponse = await secondResponsePromise;
    socket.close();

    expect(secondResponse).toMatchObject({
      type: 'response.completed',
      response: {
        id: 'resp_ws_2',
      },
    });
    expect(upstreamConnectionCount).toBe(1);
    expect(upstreamRequests).toHaveLength(2);
    expect(upstreamRequests[0]).toMatchObject({
      type: 'response.create',
      model: 'gpt-5.4',
      instructions: 'be helpful',
    });
    expect(upstreamRequests[1]).toMatchObject({
      type: 'response.create',
      previous_response_id: 'resp_ws_1',
      model: 'gpt-5.4',
      instructions: 'be helpful',
      input: [
        {
          id: 'tool_out_1',
          type: 'function_call_output',
          call_id: 'call_1',
          output: 'tool result',
        },
      ],
    });
  });

  it('disables codex websocket incremental transport when the selected account marks websockets as disabled', async () => {
    const selectedChannel = createSelectedChannel({
      extraConfig: JSON.stringify({
        credentialMode: 'session',
        websockets: false,
        oauth: {
          provider: 'codex',
          accountId: 'chatgpt-account-123',
          email: 'codex-user@example.com',
        },
      }),
    });
    selectChannelMock.mockReturnValue(selectedChannel);
    previewSelectedChannelMock.mockResolvedValue(selectedChannel);
    fetchMock
      .mockResolvedValueOnce(createSseResponse([
        'event: response.completed\n',
        'data: {"type":"response.completed","response":{"id":"resp_http_1","model":"gpt-5.4","status":"completed","output":[{"id":"msg_1","type":"message","role":"assistant","status":"completed","content":[{"type":"output_text","text":"first"}]}],"usage":{"input_tokens":3,"output_tokens":1,"total_tokens":4}}}\n\n',
        'data: [DONE]\n\n',
      ]))
      .mockResolvedValueOnce(createSseResponse([
        'event: response.completed\n',
        'data: {"type":"response.completed","response":{"id":"resp_http_2","model":"gpt-5.4","status":"completed","output":[{"id":"msg_2","type":"message","role":"assistant","status":"completed","content":[{"type":"output_text","text":"second"}]}],"usage":{"input_tokens":5,"output_tokens":1,"total_tokens":6}}}\n\n',
        'data: [DONE]\n\n',
      ]));

    const socket = createClientSocket(baseUrl);
    await waitForSocketOpen(socket);
    const firstResponsePromise = waitForSocketMessages(socket, 1);

    socket.send(JSON.stringify({
      type: 'response.create',
      model: 'gpt-5.4',
      instructions: 'be helpful',
      input: [],
    }));

    const firstMessages = await firstResponsePromise;
    const secondResponsePromise = waitForSocketMessages(socket, 1);
    socket.send(JSON.stringify({
      type: 'response.create',
      model: 'gpt-5.4',
      previous_response_id: 'resp_http_1',
      input: [
        {
          id: 'tool_out_1',
          type: 'function_call_output',
          call_id: 'call_1',
          output: 'tool result',
        },
      ],
    }));

    await secondResponsePromise;
    socket.close();

    expect(firstMessages[0]?.type).toBe('response.completed');
    expect(upstreamConnectionCount).toBe(0);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    const [, secondOptions] = fetchMock.mock.calls[1] as [string, RequestInit];
    const secondBody = JSON.parse(String(secondOptions.body));
    expect(secondBody.previous_response_id).toBeUndefined();
    expect(secondBody.input).toEqual([
      {
        id: 'tool_out_1',
        type: 'function_call_output',
        call_id: 'call_1',
        output: 'tool result',
      },
    ]);
  });

  it('handles generate=false locally only for non-websocket-capable upstreams', async () => {
    const selectedChannel = createSelectedChannel({
      sitePlatform: 'openai',
      actualModel: 'gpt-4.1',
    });
    selectChannelMock.mockReturnValue(selectedChannel);
    previewSelectedChannelMock.mockResolvedValue(selectedChannel);
    fetchMock.mockResolvedValueOnce(createSseResponse([
      'event: response.completed\n',
      'data: {"type":"response.completed","response":{"id":"resp_ws_after_prewarm","model":"gpt-4.1","status":"completed","output":[{"id":"msg_2","type":"message","role":"assistant","status":"completed","content":[{"type":"output_text","text":"done"}]}],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}\n\n',
      'data: [DONE]\n\n',
    ]));

    const socket = createClientSocket(baseUrl);
    await waitForSocketOpen(socket);

    const prewarmMessagesPromise = waitForSocketMessages(socket, 2);
    socket.send(JSON.stringify({
      type: 'response.create',
      model: 'gpt-4.1',
      generate: false,
    }));
    const prewarmMessages = await prewarmMessagesPromise;
    expect(prewarmMessages.map((message) => message.type)).toEqual(['response.created', 'response.completed']);
    expect(fetchMock).toHaveBeenCalledTimes(0);

    const secondResponsePromise = waitForSocketMessages(socket, 1);
    socket.send(JSON.stringify({
      type: 'response.create',
      previous_response_id: prewarmMessages[0]?.response?.id,
      input: [
        {
          id: 'msg_followup_1',
          type: 'message',
          role: 'user',
          content: [{ type: 'input_text', text: 'continue' }],
        },
      ],
    }));
    await secondResponsePromise;
    socket.close();

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    const forwardedBody = JSON.parse(String(options.body));
    expect(forwardedBody.generate).toBeUndefined();
    expect(forwardedBody.previous_response_id).toBeUndefined();
    expect(forwardedBody.model).toBe('gpt-4.1');
    expect(forwardedBody.input).toEqual([
      {
        id: 'msg_followup_1',
        type: 'message',
        role: 'user',
        content: [{ type: 'input_text', text: 'continue' }],
      },
    ]);
  });

  it('forwards generate=false upstream for websocket-capable upstreams instead of synthesizing prewarm events', async () => {
    const selectedChannel = createSelectedChannel({
      siteUrl: upstreamSiteUrl,
    });
    selectChannelMock.mockReturnValue(selectedChannel);
    previewSelectedChannelMock.mockResolvedValue(selectedChannel);

    const socket = createClientSocket(baseUrl);
    await waitForSocketOpen(socket);
    const messagesPromise = waitForSocketMessages(socket, 1);

    socket.send(JSON.stringify({
      type: 'response.create',
      model: 'gpt-5.4',
      generate: false,
    }));

    const messages = await messagesPromise;
    socket.close();

    expect(messages.map((message) => message.type)).toEqual(['response.completed']);
    expect(fetchMock).toHaveBeenCalledTimes(0);
    expect(upstreamRequests[0]).toMatchObject({
      type: 'response.create',
      generate: false,
    });
  });

  it('emits websocket error when the upstream stream closes before a terminal responses event', async () => {
    const selectedChannel = createSelectedChannel({
      siteUrl: upstreamSiteUrl,
    });
    selectChannelMock.mockReturnValue(selectedChannel);
    previewSelectedChannelMock.mockResolvedValue(selectedChannel);
    upstreamMessageHandler = (socket) => {
      socket.send(JSON.stringify({
        type: 'response.created',
        response: {
          id: 'resp_incomplete',
          model: 'gpt-5.4',
          created_at: 1706000000,
          status: 'in_progress',
          output: [],
        },
      }));
      socket.send(JSON.stringify({
        type: 'response.output_text.delta',
        output_index: 0,
        item_id: 'msg_ws',
        delta: 'partial',
      }));
      socket.close();
    };

    const socket = createClientSocket(baseUrl);
    await waitForSocketOpen(socket);
    const messagesPromise = waitForSocketMessages(socket, 3, 400);

    socket.send(JSON.stringify({
      type: 'response.create',
      model: 'gpt-5.4',
      input: [
        {
          type: 'message',
          role: 'user',
          content: [{ type: 'input_text', text: 'hello websocket' }],
        },
      ],
    }));

    const messages = await messagesPromise;
    socket.close();

    expect(messages.map((message) => message.type)).toEqual([
      'response.created',
      'response.output_text.delta',
      'error',
    ]);
    expect(messages[2]?.error?.message).toContain('stream closed before response.completed');
  });
});
