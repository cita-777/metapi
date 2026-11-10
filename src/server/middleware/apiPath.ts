/**
 * Path helpers for deciding which requests belong to the admin API.
 *
 * Auth decisions must not depend on the raw request-target string: the router
 * decodes and normalizes the path before matching, so the guard derives the
 * path the same way (and errs towards treating a request as an API request).
 */

const MAX_DECODE_PASSES = 3;

function decodePathOnce(path: string): string | null {
  try {
    return decodeURIComponent(path);
  } catch {
    return null;
  }
}

/** Only origin-form targets ("/path?query") and the asterisk form are accepted. */
export function isOriginFormTarget(rawUrl: string | undefined): boolean {
  if (!rawUrl) return false;
  if (rawUrl === '*') return true;
  return rawUrl.charCodeAt(0) === 47 /* '/' */;
}

/**
 * Normalize a request target into a canonical lowercase pathname: strip the
 * query/fragment, percent-decode (repeatedly, fail-safe), unify separators,
 * collapse duplicate slashes and resolve dot segments.
 */
export function normalizeRequestPath(rawUrl: string | undefined): string {
  let path = String(rawUrl || '/');
  const queryIndex = path.search(/[?#]/);
  if (queryIndex >= 0) path = path.slice(0, queryIndex);

  for (let i = 0; i < MAX_DECODE_PASSES; i += 1) {
    const decoded = decodePathOnce(path);
    if (decoded === null || decoded === path) break;
    path = decoded;
  }

  path = path.replace(/\\/g, '/').replace(/[\u0000-\u001f\u007f]/g, '');
  const segments: string[] = [];
  for (const segment of path.split('/')) {
    if (segment === '' || segment === '.') continue;
    if (segment === '..') {
      segments.pop();
      continue;
    }
    segments.push(segment);
  }
  const trailingSlash = path.endsWith('/') && segments.length > 0 ? '/' : '';
  return `/${segments.join('/')}${trailingSlash}`.toLowerCase();
}

function hasPrefix(path: string, prefix: string): boolean {
  return path === prefix || path.startsWith(`${prefix}/`);
}

export function isApiPath(path: string): boolean {
  return hasPrefix(path, '/api');
}

export function isProxyApiPath(path: string): boolean {
  return hasPrefix(path, '/v1');
}

/**
 * Decide whether a request must pass admin auth. Uses both the route the
 * router actually matched (authoritative) and the normalized request path
 * (covers unmatched requests), so either signal is enough to require auth.
 */
export function requiresAdminAuth(
  matchedRouteUrl: string | undefined,
  rawUrl: string | undefined,
  isPublicRoute: (path: string) => boolean,
): boolean {
  const normalizedPath = normalizeRequestPath(rawUrl);
  const matched = matchedRouteUrl ? matchedRouteUrl.toLowerCase() : '';
  const matchedIsApi = matched ? isApiPath(matched) : false;
  if (!matchedIsApi && !isApiPath(normalizedPath)) return false;

  // Public exemptions are decided on the matched route when there is one, so a
  // path that only *looks* public cannot reach a protected handler.
  if (matched) return !(matchedIsApi && isPublicRoute(matched));
  return !isPublicRoute(normalizedPath);
}

type GuardRequest = { url: string; routeOptions?: { url?: string } };
type GuardReply = { code(statusCode: number): { send(payload: unknown): unknown } };

/** Build the global onRequest hook that gates the admin API behind `authenticate`. */
export function createAdminAuthHook<Req extends GuardRequest, Rep extends GuardReply>(
  authenticate: (request: Req, reply: Rep) => Promise<unknown>,
  isPublicRoute: (path: string) => boolean,
) {
  return async function adminAuthHook(request: Req, reply: Rep) {
    if (!isOriginFormTarget(request.url)) {
      return reply.code(400).send({ error: 'Bad request target' });
    }
    if (requiresAdminAuth(request.routeOptions?.url, request.url, isPublicRoute)) {
      await authenticate(request, reply);
    }
    return undefined;
  };
}
