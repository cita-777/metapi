export type UpstreamEndpoint = 'chat' | 'messages' | 'responses';

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object';
}

function collapseWhitespace(text: string): string {
  return text.replace(/\s+/g, ' ').trim();
}

function extractJsonErrorMessage(rawText: string): string {
  try {
    const parsed = JSON.parse(rawText) as unknown;
    const root = isRecord(parsed) ? parsed : null;
    const error = (root && isRecord(root.error)) ? root.error : root;
    if (!error) return '';

    const message = typeof error.message === 'string' ? collapseWhitespace(error.message) : '';
    if (message) return message;

    const code = typeof error.code === 'string' ? collapseWhitespace(error.code) : '';
    const type = typeof error.type === 'string' ? collapseWhitespace(error.type) : '';
    return [type, code].filter((part) => part.length > 0).join('/');
  } catch {
    return '';
  }
}

function extractHtmlTitle(rawText: string): string {
  const match = rawText.match(/<title[^>]*>([^<>]*)<\/title>/i);
  if (!match?.[1]) return '';
  return collapseWhitespace(match[1]);
}

function extractCloudflareHtmlSummary(rawText: string, status: number): string {
  if (!/cloudflare/i.test(rawText)) return '';
  const title = extractHtmlTitle(rawText);
  const codeMatch = (
    title.match(/\b(\d{3,4})\s*:\s*([^\|<]+)/i)
    || rawText.match(/Error code\s*(\d{3,4})/i)
  );
  const code = codeMatch?.[1] || (status > 0 ? String(status) : '');
  const reason = collapseWhitespace(
    (typeof codeMatch?.[2] === 'string' ? codeMatch[2] : '')
    || (status >= 500 ? 'origin host error' : 'request blocked')
  );
  if (code) return `Cloudflare ${code}: ${reason}`;
  return `Cloudflare: ${reason}`;
}

function extractHtmlSummary(rawText: string, status: number): string {
  if (!/(<!doctype|<html)/i.test(rawText)) return '';

  const cloudflareSummary = extractCloudflareHtmlSummary(rawText, status);
  if (cloudflareSummary) return cloudflareSummary;

  const title = extractHtmlTitle(rawText);
  if (title) return title;

  const heading = rawText.match(/<h1[^>]*>([^<>]*)<\/h1>/i)?.[1] || '';
  return collapseWhitespace(heading);
}

function formatUrlOrigin(url: URL): string {
  const username = url.username ? encodeURIComponent(url.username) : '';
  const password = url.password ? encodeURIComponent(url.password) : '';
  const auth = username
    ? `${username}${password ? `:${password}` : ''}@`
    : '';

  return `${url.protocol}//${auth}${url.host}`;
}

function joinPath(basePath: string, requestPath: string): string {
  const base = basePath.replace(/\/+$/, '');
  const path = requestPath.startsWith('/') ? requestPath : `/${requestPath}`;

  if (!base || base === '/') return path || '/';
  if (!path || path === '/') return base;
  return `${base}${path}`;
}

export function summarizeUpstreamError(status: number, rawErrorText: string): string {
  const statusPrefix = status > 0
    ? `Upstream returned HTTP ${status}`
    : 'Upstream request failed';

  const raw = typeof rawErrorText === 'string' ? rawErrorText.trim() : '';
  if (!raw) return statusPrefix;

  const jsonMessage = extractJsonErrorMessage(raw);
  if (jsonMessage) return `${statusPrefix}: ${jsonMessage}`;

  const htmlMessage = extractHtmlSummary(raw, status);
  if (htmlMessage) return `${statusPrefix}: ${htmlMessage}`;

  const compact = collapseWhitespace(raw);
  if (!compact) return statusPrefix;
  if (compact.length <= 400) return `${statusPrefix}: ${compact}`;
  return `${statusPrefix}: ${compact.slice(0, 400)}...(truncated)`;
}

export function buildUpstreamUrl(siteUrl: string, requestPath: string): string {
  const baseRaw = typeof siteUrl === 'string' ? siteUrl.trim() : '';
  const pathRaw = typeof requestPath === 'string' ? requestPath.trim() : '';
  const fallbackBase = baseRaw.replace(/\/+$/, '');
  const requestHashIndex = pathRaw.indexOf('#');
  const requestHash = requestHashIndex >= 0 ? pathRaw.slice(requestHashIndex) : '';
  const pathWithQuery = requestHashIndex >= 0 ? pathRaw.slice(0, requestHashIndex) : pathRaw;
  const requestQueryIndex = pathWithQuery.indexOf('?');
  const requestQuery = requestQueryIndex >= 0 ? pathWithQuery.slice(requestQueryIndex + 1) : '';
  let path = (requestQueryIndex >= 0 ? pathWithQuery.slice(0, requestQueryIndex) : pathWithQuery);
  path = path.startsWith('/') ? path : `/${path}`;

  const stripVersionPrefix = (baseVersion?: string) => {
    const requestVersionMatch = path.match(/^\/(v\d+(?:beta)?)(?=\/|$)/i);
    if (!requestVersionMatch) return;
    const requestVersion = requestVersionMatch[1];
    const normalizedRequestVersion = requestVersion.toLowerCase();
    const normalizedBaseVersion = baseVersion?.toLowerCase();
    // Compatibility endpoints conventionally receive a /v1 request prefix,
    // while native Gemini paths use /v1beta and must remain intact when the
    // configured base is a different API version.
    if (normalizedRequestVersion !== 'v1' && normalizedRequestVersion !== normalizedBaseVersion) return;
    path = path.slice(requestVersion.length + 1) || '/';
  };

  if (!fallbackBase) return path || '/';
  if (!path || path === '/') return fallbackBase;

  try {
    const parsed = new URL(baseRaw);
    let basePath = parsed.pathname.replace(/\/+$/, '');
    // Native Gemini fallbacks use /v1beta/models even when the configured
    // compatibility base is /v1beta/openai. Remove only that known suffix so
    // the request is not sent to /v1beta/openai/v1beta/models.
    const nativeGeminiPath = /^\/(v\d+(?:beta)?)\/models(?:\/|$)/i.test(path);
    if (nativeGeminiPath) {
      const compatibilitySuffix = basePath.match(/\/(?:api\/)?v\d+(?:beta)?\/openai$/i);
      if (compatibilitySuffix?.index !== undefined) {
        basePath = basePath.slice(0, compatibilitySuffix.index).replace(/\/+$/, '');
      } else if (/\/openai$/i.test(basePath)) {
        basePath = basePath.slice(0, -'/openai'.length).replace(/\/+$/, '');
      }
    }
    const baseVersionMatch = basePath.match(/\/(?:api\/)?(v\d+(?:beta)?)$/i);
    const baseHasVersionSuffix = !!baseVersionMatch;
    if (baseHasVersionSuffix) {
      const baseVersion = baseVersionMatch?.[1] || 'v1';
      stripVersionPrefix(baseVersion);
    }

    const joinedPath = joinPath(basePath, path);
    const mergedQuery = new URLSearchParams(parsed.search);
    for (const [key, value] of new URLSearchParams(requestQuery)) {
      mergedQuery.set(key, value);
    }
    const query = mergedQuery.toString();
    return `${formatUrlOrigin(parsed)}${joinedPath}${query ? `?${query}` : ''}${requestHash || parsed.hash}`;
  } catch {
    const baseVersionMatch = fallbackBase.match(/\/(?:api\/)?(v\d+(?:beta)?)$/i);
    const baseHasVersionSuffix = !!baseVersionMatch;
    if (baseHasVersionSuffix) {
      const baseVersion = baseVersionMatch?.[1] || 'v1';
      stripVersionPrefix(baseVersion);
    }

    const query = requestQuery ? `?${requestQuery}` : '';
    return `${fallbackBase}${path}${query}${requestHash}`;
  }
}
