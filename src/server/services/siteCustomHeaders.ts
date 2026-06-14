import { Headers, type HeadersInit } from 'undici';

export type SiteCustomHeadersRecord = Record<string, string>;
export type SiteCustomHeadersMergePriority = 'request' | 'site';

export type SiteCustomHeadersMergeOptions = {
  priority?: SiteCustomHeadersMergePriority;
};

export type ParsedSiteCustomHeadersInput = {
  present: boolean;
  valid: boolean;
  customHeaders: string | null;
  headers: SiteCustomHeadersRecord | null;
  error?: string;
};

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return Object.prototype.toString.call(value) === '[object Object]';
}

function normalizeSiteCustomHeadersRecord(input: Record<string, unknown>): SiteCustomHeadersRecord | null {
  const normalized = new Headers();

  for (const [rawKey, rawValue] of Object.entries(input)) {
    const key = rawKey.trim();
    if (!key) {
      throw new Error('Header name cannot be empty.');
    }
    if (typeof rawValue !== 'string') {
      throw new Error(`Header "${key}" must use a string value.`);
    }
    normalized.set(key, rawValue);
  }

  const entries = Array.from(normalized.entries()).sort(([left], [right]) => left.localeCompare(right));
  if (entries.length === 0) {
    return null;
  }

  return Object.fromEntries(entries);
}

export function parseSiteCustomHeadersInput(input: unknown): ParsedSiteCustomHeadersInput {
  if (input === undefined) {
    return { present: false, valid: true, customHeaders: null, headers: null };
  }
  if (input === null) {
    return { present: true, valid: true, customHeaders: null, headers: null };
  }

  let parsedInput: unknown = input;
  if (typeof input === 'string') {
    const trimmed = input.trim();
    if (!trimmed) {
      return { present: true, valid: true, customHeaders: null, headers: null };
    }
    try {
      parsedInput = JSON.parse(trimmed);
    } catch {
      return {
        present: true,
        valid: false,
        customHeaders: null,
        headers: null,
        error: 'Invalid customHeaders. Expected a JSON object like {"x-header":"value"}.',
      };
    }
  }

  if (!isPlainObject(parsedInput)) {
    return {
      present: true,
      valid: false,
      customHeaders: null,
      headers: null,
      error: 'Invalid customHeaders. Expected a JSON object like {"x-header":"value"}.',
    };
  }

  try {
    const headers = normalizeSiteCustomHeadersRecord(parsedInput);
    return {
      present: true,
      valid: true,
      customHeaders: headers ? JSON.stringify(headers) : null,
      headers,
    };
  } catch (error) {
    return {
      present: true,
      valid: false,
      customHeaders: null,
      headers: null,
      error: error instanceof Error
        ? `Invalid customHeaders. ${error.message}`
        : 'Invalid customHeaders. Expected a JSON object like {"x-header":"value"}.',
    };
  }
}

export function readSiteCustomHeaders(input: unknown): SiteCustomHeadersRecord | null {
  const parsed = parseSiteCustomHeadersInput(input);
  if (!parsed.valid) {
    return null;
  }
  return parsed.headers;
}

export function mergeHeadersWithSiteCustomHeaders(
  siteCustomHeaders: unknown,
  requestHeaders?: HeadersInit,
  options: SiteCustomHeadersMergeOptions = {},
): HeadersInit | undefined {
  const normalizedSiteHeaders = readSiteCustomHeaders(siteCustomHeaders);
  if (!normalizedSiteHeaders) {
    return requestHeaders;
  }

  const priority = options.priority ?? 'request';
  const merged = new Headers(priority === 'site' ? requestHeaders : normalizedSiteHeaders);
  const headersToApplyLast = new Headers(priority === 'site' ? normalizedSiteHeaders : requestHeaders);
  headersToApplyLast.forEach((value, key) => {
    merged.set(key, value);
  });
  return merged;
}
