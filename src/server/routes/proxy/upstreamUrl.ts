function formatUrlOrigin(url: URL): string {
  // URL.origin drops credentials; preserve them if present.
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

export function buildUpstreamUrl(siteUrl: string, requestPath: string): string {
  const baseRaw = typeof siteUrl === 'string' ? siteUrl.trim() : '';
  const pathRaw = typeof requestPath === 'string' ? requestPath.trim() : '';
  const fallbackBase = baseRaw.replace(/\/+$/, '');
  let path = pathRaw.startsWith('/') ? pathRaw : `/${pathRaw}`;

  if (!fallbackBase) return path || '/';
  if (!path || path === '/') return fallbackBase;

  try {
    const parsed = new URL(baseRaw);
    const basePath = parsed.pathname.replace(/\/+$/, '');
    const baseHasVersionSuffix = /\/(?:api\/)?v1$/i.test(basePath);
    if (baseHasVersionSuffix) {
      if (path === '/v1') {
        path = '/';
      } else if (path.startsWith('/v1/')) {
        path = path.slice('/v1'.length) || '/';
      }
    }

    const joinedPath = joinPath(basePath, path);
    return `${formatUrlOrigin(parsed)}${joinedPath}${parsed.search}${parsed.hash}`;
  } catch {
    // Ignore URL parsing errors and fall back to naive join.
    const baseHasVersionSuffix = /\/(?:api\/)?v1$/i.test(fallbackBase);
    if (baseHasVersionSuffix) {
      if (path === '/v1') {
        path = '/';
      } else if (path.startsWith('/v1/')) {
        path = path.slice('/v1'.length) || '/';
      }
    }

    return `${fallbackBase}${path}`;
  }
}

