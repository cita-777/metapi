import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { type AddressInfo } from 'node:net';
import {
  CODEX_LOOPBACK_CALLBACK_PATH,
  CODEX_LOOPBACK_CALLBACK_PORT,
  CODEX_OAUTH_PROVIDER,
} from './codexProvider.js';
import { handleOauthCallback } from './service.js';

type CallbackHandler = typeof handleOauthCallback;

type StartCodexLoopbackCallbackServerOptions = {
  port?: number;
  host?: string;
  callbackHandler?: CallbackHandler;
};

export type CodexLoopbackCallbackServerState = {
  attempted: boolean;
  ready: boolean;
  host?: string;
  port: number;
  origin: string;
  error?: string;
};

const DEFAULT_STATE: CodexLoopbackCallbackServerState = {
  attempted: false,
  ready: false,
  port: CODEX_LOOPBACK_CALLBACK_PORT,
  origin: `http://localhost:${CODEX_LOOPBACK_CALLBACK_PORT}`,
};

let callbackServer: Server | null = null;
let callbackServerState: CodexLoopbackCallbackServerState = { ...DEFAULT_STATE };
let startPromise: Promise<CodexLoopbackCallbackServerState> | null = null;

function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function renderCompletionPage(message: string): string {
  const safeMessage = escapeHtml(message);
  return `<!doctype html>
<html lang="zh-CN">
  <head>
    <meta charset="utf-8" />
    <title>Codex OAuth Callback</title>
  </head>
  <body>
    <script>window.close();</script>
    ${safeMessage}
  </body>
</html>`;
}

function respondHtml(response: ServerResponse, statusCode: number, message: string) {
  response.writeHead(statusCode, {
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-store',
  });
  response.end(renderCompletionPage(message));
}

async function handleCallbackRequest(
  request: IncomingMessage,
  response: ServerResponse,
  callbackHandler: CallbackHandler,
) {
  if (request.method !== 'GET') {
    response.writeHead(405, { Allow: 'GET' });
    response.end('Method not allowed');
    return;
  }

  const requestUrl = new URL(request.url || '/', 'http://localhost');
  if (requestUrl.pathname !== CODEX_LOOPBACK_CALLBACK_PATH) {
    response.writeHead(404);
    response.end('Not found');
    return;
  }

  try {
    await callbackHandler({
      provider: CODEX_OAUTH_PROVIDER,
      state: requestUrl.searchParams.get('state') || '',
      code: requestUrl.searchParams.get('code') || undefined,
      error: requestUrl.searchParams.get('error') || undefined,
    });
    respondHtml(response, 200, 'OAuth authorization succeeded. You can close this window.');
  } catch (error: any) {
    respondHtml(response, 500, `OAuth authorization failed: ${error?.message || 'unknown error'}`);
  }
}

function normalizeOrigin(host: string | undefined, port: number): string {
  if (!host || host === '::' || host === '0.0.0.0') {
    return `http://localhost:${port}`;
  }
  if (host.includes(':') && !host.startsWith('[')) {
    return `http://[${host}]:${port}`;
  }
  return `http://${host}:${port}`;
}

export function getCodexLoopbackCallbackServerState(): CodexLoopbackCallbackServerState {
  return { ...callbackServerState };
}

export async function startCodexLoopbackCallbackServer(
  options: StartCodexLoopbackCallbackServerOptions = {},
): Promise<CodexLoopbackCallbackServerState> {
  if (callbackServer) {
    return getCodexLoopbackCallbackServerState();
  }
  if (startPromise) {
    return startPromise;
  }

  const callbackHandler = options.callbackHandler || handleOauthCallback;
  const requestedPort = options.port ?? CODEX_LOOPBACK_CALLBACK_PORT;
  const requestedHost = options.host;

  startPromise = new Promise<CodexLoopbackCallbackServerState>((resolve, reject) => {
    const server = createServer((request, response) => {
      void handleCallbackRequest(request, response, callbackHandler);
    });

    const finalizeFailure = (error: Error) => {
      callbackServerState = {
        attempted: true,
        ready: false,
        host: requestedHost,
        port: requestedPort,
        origin: normalizeOrigin(requestedHost, requestedPort),
        error: error.message || 'failed to start codex oauth callback server',
      };
      callbackServer = null;
      reject(error);
    };

    server.once('error', (error) => {
      finalizeFailure(error as Error);
    });

    server.listen(requestedPort, requestedHost, () => {
      server.removeAllListeners('error');
      callbackServer = server;
      const address = server.address() as AddressInfo | null;
      const port = address?.port || requestedPort;
      const host = address?.address || requestedHost;
      callbackServerState = {
        attempted: true,
        ready: true,
        host,
        port,
        origin: normalizeOrigin(host, port),
      };
      resolve(getCodexLoopbackCallbackServerState());
    });
  }).finally(() => {
    startPromise = null;
  });

  return startPromise;
}

export async function stopCodexLoopbackCallbackServer(): Promise<void> {
  const server = callbackServer;
  callbackServer = null;
  callbackServerState = { ...DEFAULT_STATE };

  if (!server) return;

  await new Promise<void>((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
}
