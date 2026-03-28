import {
  brotliDecompressSync,
  gunzipSync,
  inflateSync,
  zstdDecompressSync,
} from 'node:zlib';
import {
  Response,
  fetch,
  type RequestInit as UndiciRequestInit,
  type Response as UndiciResponse,
} from 'undici';

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

export type RuntimeResponse = UndiciResponse;

export type RuntimeExecutor = {
  dispatch(input: RuntimeDispatchInput): Promise<RuntimeResponse>;
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
): Promise<RuntimeResponse> {
  const init = await input.buildInit(requestUrl, request);
  return fetch(requestUrl, init);
}

function hasZstdContentEncoding(contentEncoding: string | null): boolean {
  if (!contentEncoding) return false;
  return contentEncoding
    .split(',')
    .some((encoding) => encoding.trim().toLowerCase() === 'zstd');
}

function looksLikeZstdFrame(buffer: Buffer): boolean {
  return buffer.length >= 4
    && buffer[0] === 0x28
    && buffer[1] === 0xb5
    && buffer[2] === 0x2f
    && buffer[3] === 0xfd;
}

function decodeRuntimeResponseBuffer(buffer: Buffer, contentEncoding: string | null): Buffer {
  if (!contentEncoding) return buffer;

  let decoded = buffer;
  const encodings = contentEncoding
    .split(',')
    .map((encoding) => encoding.trim().toLowerCase())
    .filter(Boolean)
    .reverse();

  for (const encoding of encodings) {
    if (encoding === 'zstd') {
      decoded = zstdDecompressSync(decoded);
      continue;
    }
    if (encoding === 'br') {
      decoded = brotliDecompressSync(decoded);
      continue;
    }
    if (encoding === 'gzip' || encoding === 'x-gzip') {
      decoded = gunzipSync(decoded);
      continue;
    }
    if (encoding === 'deflate') {
      decoded = inflateSync(decoded);
      continue;
    }
  }

  return decoded;
}

export async function readRuntimeResponseText(
  response: RuntimeResponse,
): Promise<string> {
  const contentEncoding = typeof response.headers?.get === 'function'
    ? response.headers.get('content-encoding')
    : null;
  if (!hasZstdContentEncoding(contentEncoding)) {
    return typeof response.text === 'function'
      ? response.text().catch(() => '')
      : '';
  }

  const rawBuffer = Buffer.from(await response.arrayBuffer());
  try {
    return decodeRuntimeResponseBuffer(rawBuffer, contentEncoding).toString('utf8');
  } catch {
    return looksLikeZstdFrame(rawBuffer) ? '' : rawBuffer.toString('utf8');
  }
}

export async function materializeErrorResponse(
  response: RuntimeResponse,
): Promise<RuntimeResponse> {
  if (response.ok) return response;
  const text = await readRuntimeResponseText(response);
  const headers = new Headers(response.headers);
  headers.delete('content-encoding');
  headers.delete('content-length');
  return new Response(text, {
    status: response.status,
    headers,
  });
}
