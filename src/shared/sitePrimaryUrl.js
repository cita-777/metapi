function normalizePathname(pathname) {
  let normalized = typeof pathname === 'string' ? pathname.trim() : '';
  if (!normalized || normalized === '/') return '/';
  if (!normalized.startsWith('/')) normalized = `/${normalized}`;
  while (normalized.length > 1 && normalized.endsWith('/')) {
    normalized = normalized.slice(0, -1);
  }
  return normalized;
}

function parseUrlCandidate(url) {
  const trimmed = typeof url === 'string' ? url.trim() : '';
  if (!trimmed) return null;

  const candidates = trimmed.includes('://')
    ? [trimmed]
    : [`https://${trimmed}`];

  for (const candidate of candidates) {
    try {
      return new URL(candidate);
    } catch {}
  }
  return null;
}

const AUTO_STRIP_PRIMARY_SITE_PATHS = new Set([
  '/v1',
  '/v1beta',
  '/v1/models',
  '/v1/chat/completions',
  '/v1/responses',
  '/v1/messages',
  '/v1beta/models',
]);

const SEMANTIC_PRIMARY_SITE_PATHS = new Set([
  '/backend-api/codex',
  '/anthropic',
  '/apps/anthropic',
  '/api/anthropic',
  '/api/coding/paas/v4',
  '/v1beta/openai',
]);

export function analyzePrimarySiteUrl(url) {
  const parsed = parseUrlCandidate(url);
  if (!parsed) {
    const trimmed = typeof url === 'string' ? url.trim().replace(/\/+$/, '') : '';
    return {
      canonicalUrl: trimmed,
      persistedUrl: trimmed,
      matchedPath: '',
      action: 'unchanged',
    };
  }

  parsed.search = '';
  parsed.hash = '';
  const matchedPath = normalizePathname(parsed.pathname);
  const canonicalUrl = matchedPath === '/'
    ? parsed.origin
    : `${parsed.origin}${matchedPath}`;

  if (matchedPath === '/') {
    return {
      canonicalUrl,
      persistedUrl: canonicalUrl,
      matchedPath,
      action: 'unchanged',
    };
  }

  if (SEMANTIC_PRIMARY_SITE_PATHS.has(matchedPath)) {
    return {
      canonicalUrl,
      persistedUrl: canonicalUrl,
      matchedPath,
      action: 'preserve_semantic_path',
    };
  }

  if (AUTO_STRIP_PRIMARY_SITE_PATHS.has(matchedPath)) {
    return {
      canonicalUrl,
      persistedUrl: parsed.origin,
      matchedPath,
      action: 'auto_strip_known_api_suffix',
    };
  }

  if (matchedPath.startsWith('/api')) {
    return {
      canonicalUrl,
      persistedUrl: canonicalUrl,
      matchedPath,
      action: 'preserve_api_path',
    };
  }

  return {
    canonicalUrl,
    persistedUrl: canonicalUrl,
    matchedPath,
    action: 'preserve_unknown_path',
  };
}
