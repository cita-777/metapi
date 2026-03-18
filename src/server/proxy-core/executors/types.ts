import { fetch, type RequestInit as UndiciRequestInit } from 'undici';

export type ProxyRuntimeRequest = {
  endpoint: 'chat' | 'messages' | 'responses';
  path: string;
  headers: Record<string, string>;
  body: Record<string, unknown>;
  runtime?: {
    executor: 'default' | 'codex' | 'gemini-cli' | 'antigravity' | 'claude';
    modelName?: string;
    stream?: boolean;
    oauthProjectId?: string | null;
    action?: 'generateContent' | 'streamGenerateContent' | 'countTokens';
  };
};

export type RuntimeDispatchInput = {
  siteUrl: string;
  request: ProxyRuntimeRequest;
  targetUrl?: string;
  buildInit: (requestUrl: string, request: ProxyRuntimeRequest) => Promise<UndiciRequestInit> | UndiciRequestInit;
};

export type RuntimeExecutor = {
  dispatch(input: RuntimeDispatchInput): Promise<Awaited<ReturnType<typeof fetch>>>;
};

export function asTrimmedString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

export function withRequestBody(
  request: ProxyRuntimeRequest,
  body: Record<string, unknown>,
  headers?: Record<string, string>,
): ProxyRuntimeRequest {
  return {
    ...request,
    headers: headers ? { ...headers } : { ...request.headers },
    body,
  };
}

function buildUpstreamUrl(siteUrl: string, path: string): string {
  const normalizedBase = siteUrl.replace(/\/+$/, '');
  const normalizedPath = path.startsWith('/') ? path : `/${path}`;
  return `${normalizedBase}${normalizedPath}`;
}

export async function performFetch(
  input: RuntimeDispatchInput,
  request: ProxyRuntimeRequest,
  requestUrl = input.targetUrl || buildUpstreamUrl(input.siteUrl, request.path),
): Promise<Awaited<ReturnType<typeof fetch>>> {
  const init = await input.buildInit(requestUrl, request);
  return fetch(requestUrl, init);
}

export async function materializeErrorResponse(
  response: Awaited<ReturnType<typeof fetch>>,
): Promise<Awaited<ReturnType<typeof fetch>>> {
  if (response.ok) return response;
  const text = await response.text().catch(() => '');
  return new Response(text, {
    status: response.status,
    headers: response.headers,
  }) as unknown as Awaited<ReturnType<typeof fetch>>;
}
