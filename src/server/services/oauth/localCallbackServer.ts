import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { type AddressInfo } from 'node:net';
import { getOAuthProviderDefinition, listOAuthProviderDefinitions } from './providers.js';
import { handleOauthCallback } from './service.js';

type CallbackHandler = typeof handleOauthCallback;

type StartOAuthLoopbackCallbackServerOptions = {
  host?: string;
  port?: number;
  callbackHandler?: CallbackHandler;
};

export type OAuthLoopbackCallbackServerState = {
  provider: string;
  attempted: boolean;
  ready: boolean;
  host?: string;
  port: number;
  path: string;
  origin: string;
  redirectUri: string;
  error?: string;
};

const servers = new Map<string, Server>();
const states = new Map<string, OAuthLoopbackCallbackServerState>();
const startPromises = new Map<string, Promise<OAuthLoopbackCallbackServerState>>();

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
    <title>OAuth Callback</title>
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

function normalizeOrigin(host: string | undefined, port: number): string {
  if (!host || host === '::' || host === '0.0.0.0') {
    return `http://localhost:${port}`;
  }
  if (host.includes(':') && !host.startsWith('[')) {
    return `http://[${host}]:${port}`;
  }
  return `http://${host}:${port}`;
}

function createDefaultState(provider: string): OAuthLoopbackCallbackServerState {
  const definition = getOAuthProviderDefinition(provider);
  if (!definition) {
    throw new Error(`unsupported oauth provider: ${provider}`);
  }
  return {
    provider,
    attempted: false,
    ready: false,
    host: definition.loopback.host,
    port: definition.loopback.port,
    path: definition.loopback.path,
    origin: normalizeOrigin(definition.loopback.host, definition.loopback.port),
    redirectUri: definition.loopback.redirectUri,
  };
}

async function handleCallbackRequest(
  provider: string,
  request: IncomingMessage,
  response: ServerResponse,
  callbackHandler: CallbackHandler,
) {
  const definition = getOAuthProviderDefinition(provider);
  if (!definition) {
    response.writeHead(404);
    response.end('Not found');
    return;
  }

  if (request.method !== 'GET') {
    response.writeHead(405, { Allow: 'GET' });
    response.end('Method not allowed');
    return;
  }

  const requestUrl = new URL(request.url || '/', 'http://localhost');
  if (requestUrl.pathname !== definition.loopback.path) {
    response.writeHead(404);
    response.end('Not found');
    return;
  }

  try {
    await callbackHandler({
      provider,
      state: requestUrl.searchParams.get('state') || '',
      code: requestUrl.searchParams.get('code') || undefined,
      error: requestUrl.searchParams.get('error') || undefined,
    });
    respondHtml(response, 200, 'OAuth authorization succeeded. You can close this window.');
  } catch {
    respondHtml(response, 500, 'OAuth authorization failed. Return to metapi and review the server logs.');
  }
}

export function getOAuthLoopbackCallbackServerState(provider: string): OAuthLoopbackCallbackServerState {
  return { ...(states.get(provider) || createDefaultState(provider)) };
}

export function getOAuthLoopbackCallbackServerStates(): OAuthLoopbackCallbackServerState[] {
  return listOAuthProviderDefinitions().map((provider) => getOAuthLoopbackCallbackServerState(provider.metadata.provider));
}

export async function startOAuthLoopbackCallbackServer(
  provider: string,
  options: StartOAuthLoopbackCallbackServerOptions = {},
): Promise<OAuthLoopbackCallbackServerState> {
  const definition = getOAuthProviderDefinition(provider);
  if (!definition) {
    throw new Error(`unsupported oauth provider: ${provider}`);
  }
  if (servers.has(provider)) {
    return getOAuthLoopbackCallbackServerState(provider);
  }
  const existingStart = startPromises.get(provider);
  if (existingStart) {
    return existingStart;
  }

  const callbackHandler = options.callbackHandler || handleOauthCallback;
  const host = options.host || definition.loopback.host;
  const port = options.port ?? definition.loopback.port;
  const { path, redirectUri } = definition.loopback;
  const startPromise = new Promise<OAuthLoopbackCallbackServerState>((resolve, reject) => {
    const server = createServer((request, response) => {
      void handleCallbackRequest(provider, request, response, callbackHandler);
    });

    const finalizeFailure = (error: Error) => {
      const failedState: OAuthLoopbackCallbackServerState = {
        provider,
        attempted: true,
        ready: false,
        host,
        port,
        path,
        origin: normalizeOrigin(host, port),
        redirectUri,
        error: error.message || `failed to start ${provider} oauth callback server`,
      };
      states.set(provider, failedState);
      servers.delete(provider);
      reject(error);
    };

    const onStartupError = (error: Error) => {
      finalizeFailure(error);
    };

    server.once('error', onStartupError);
    server.listen(port, host, () => {
      server.off('error', onStartupError);
      servers.set(provider, server);
      const address = server.address() as AddressInfo | null;
      const listeningPort = address?.port || port;
      const listeningHost = address?.address || host;
      const nextState: OAuthLoopbackCallbackServerState = {
        provider,
        attempted: true,
        ready: true,
        host: listeningHost,
        port: listeningPort,
        path,
        origin: normalizeOrigin(listeningHost, listeningPort),
        redirectUri,
      };
      states.set(provider, nextState);
      resolve(getOAuthLoopbackCallbackServerState(provider));
    });
  }).finally(() => {
    startPromises.delete(provider);
  });

  startPromises.set(provider, startPromise);
  return startPromise;
}

export async function startOAuthLoopbackCallbackServers(
  options: StartOAuthLoopbackCallbackServerOptions = {},
): Promise<OAuthLoopbackCallbackServerState[]> {
  const results = await Promise.allSettled(
    listOAuthProviderDefinitions().map((provider) =>
      startOAuthLoopbackCallbackServer(provider.metadata.provider, options)),
  );
  return results.map((result, index) => {
    if (result.status === 'fulfilled') return result.value;
    return getOAuthLoopbackCallbackServerState(listOAuthProviderDefinitions()[index]!.metadata.provider);
  });
}

export async function stopOAuthLoopbackCallbackServers(): Promise<void> {
  const activeServers = Array.from(servers.entries());
  servers.clear();
  states.clear();
  startPromises.clear();

  await Promise.all(activeServers.map(async ([provider, server]) => {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    }).catch(() => undefined);
    states.set(provider, createDefaultState(provider));
  }));
}

export async function startCodexLoopbackCallbackServer(
  options: StartOAuthLoopbackCallbackServerOptions = {},
): Promise<OAuthLoopbackCallbackServerState> {
  return startOAuthLoopbackCallbackServer('codex', options);
}

export async function stopCodexLoopbackCallbackServer(): Promise<void> {
  await stopOAuthLoopbackCallbackServers();
}
