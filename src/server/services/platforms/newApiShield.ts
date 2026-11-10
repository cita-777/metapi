import type { RequestInit as UndiciRequestInit } from 'undici';
import { withSiteProxyRequestInit } from '../siteProxy.js';

const SHIELD_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36';

export function buildNewApiCookieCandidates(token: string): string[] {
  const trimmed = (token || '').trim();
  if (!trimmed) return [];

  const raw = trimmed.startsWith('Bearer ') ? trimmed.slice(7).trim() : trimmed;
  const candidates: string[] = [];

  if (raw.includes('=')) {
    candidates.push(raw);
  }

  candidates.push(`session=${raw}`);
  candidates.push(`token=${raw}`);

  return Array.from(new Set(candidates));
}

export function hasUsableSessionCookie(cookieHeader: string): boolean {
  if (!cookieHeader) return false;
  const ignored = new Set(['acw_tc', 'acw_sc__v2', 'cdn_sec_tc']);
  const pairs = cookieHeader.split(';').map((part) => part.trim()).filter(Boolean);
  for (const pair of pairs) {
    const eq = pair.indexOf('=');
    if (eq <= 0) continue;
    const name = pair.slice(0, eq).trim().toLowerCase();
    if (!name || ignored.has(name)) continue;
    if (
      name === 'session'
      || name === 'token'
      || name === 'auth_token'
      || name === 'access_token'
      || name === 'jwt'
      || name === 'jwt_token'
      || name.includes('session')
      || name.includes('token')
      || name.includes('auth')
    ) {
      return true;
    }
  }
  return false;
}

function parseChallengeArg1(html: string): string | null {
  const match = html.match(/var\s+arg1\s*=\s*['"]([0-9a-fA-F]+)['"]/);
  return match?.[1]?.toUpperCase() || null;
}

function parseChallengeMapping(html: string): number[] | null {
  const match = html.match(/for\(var m=\[([^\]]+)\],p=L\(0x115\)/);
  if (!match?.[1]) return null;

  const values = match[1].split(',').map((raw) => {
    const value = raw.trim().toLowerCase();
    if (!value) return Number.NaN;
    if (value.startsWith('0x')) return Number.parseInt(value.slice(2), 16);
    return Number.parseInt(value, 10);
  });

  if (values.some((value) => Number.isNaN(value))) return null;
  return values;
}

const CHALLENGE_STRING_TABLE_PATTERN = /function\s+[\w$]+\(\)\s*\{\s*var\s+[\w$]+\s*=\s*\[([^\]]*)\]/;
const CHALLENGE_STRING_LITERAL_PATTERN = /'([A-Za-z0-9+/=]*)'/g;

// The challenge page ships a string table encoded with a case-swapped base64
// alphabet. Decode it as data only: upstream script is never executed.
function decodeChallengeTableEntry(encoded: string): string | null {
  const standard = encoded.replace(/[a-zA-Z]/g, (ch) => (
    ch === ch.toLowerCase() ? ch.toUpperCase() : ch.toLowerCase()
  ));
  try {
    return Buffer.from(standard, 'base64').toString('utf8');
  } catch {
    return null;
  }
}

function parseChallengeXorSeed(html: string, expectedLength: number): string | null {
  const table = html.match(CHALLENGE_STRING_TABLE_PATTERN)?.[1];
  if (!table || expectedLength <= 0) return null;

  const candidates = new Set<string>();
  for (const match of table.matchAll(CHALLENGE_STRING_LITERAL_PATTERN)) {
    const decoded = decodeChallengeTableEntry(match[1]);
    if (decoded && decoded.length === expectedLength && /^[0-9a-f]+$/i.test(decoded)) {
      candidates.add(decoded.toLowerCase());
    }
  }

  // Fail closed unless exactly one plausible seed is present.
  return candidates.size === 1 ? [...candidates][0] : null;
}

export function solveNewApiAcwScV2(html: string): string | null {
  const arg1 = parseChallengeArg1(html);
  const mapping = parseChallengeMapping(html);
  if (!arg1 || !mapping) return null;
  const xorSeed = parseChallengeXorSeed(html, arg1.length);
  if (!xorSeed) return null;

  const reordered: string[] = [];
  for (let i = 0; i < arg1.length; i += 1) {
    const ch = arg1[i];
    for (let j = 0; j < mapping.length; j += 1) {
      if (mapping[j] === i + 1) {
        reordered[j] = ch;
      }
    }
  }

  const source = reordered.join('');
  let out = '';
  for (let i = 0; i < source.length && i < xorSeed.length; i += 2) {
    const left = Number.parseInt(source.slice(i, i + 2), 16);
    const right = Number.parseInt(xorSeed.slice(i, i + 2), 16);
    if (Number.isNaN(left) || Number.isNaN(right)) return null;
    out += (left ^ right).toString(16).padStart(2, '0');
  }

  return out || null;
}

function isShieldChallenge(contentType: string, text: string): boolean {
  const normalizedType = (contentType || '').toLowerCase();
  if (normalizedType.includes('text/html') && /var\s+arg1\s*=|acw_sc__v2|cdn_sec_tc|<script/i.test(text)) {
    return true;
  }
  return /var\s+arg1\s*=/.test(text);
}

function normalizeHeaders(headers?: UndiciRequestInit['headers']): Record<string, string> {
  const output: Record<string, string> = {};
  if (!headers) return output;

  if (Array.isArray(headers)) {
    for (const [key, value] of headers) {
      output[String(key)] = String(value);
    }
    return output;
  }

  const maybeIterable = headers as { forEach?: (fn: (value: string, key: string) => void) => void };
  if (typeof maybeIterable.forEach === 'function') {
    maybeIterable.forEach((value, key) => {
      output[key] = value;
    });
    return output;
  }

  for (const [key, value] of Object.entries(headers as Record<string, unknown>)) {
    if (value === undefined || value === null) continue;
    output[key] = String(value);
  }
  return output;
}

function upsertCookie(cookieHeader: string, name: string, value: string): string {
  const parts = cookieHeader.split(';').map((part) => part.trim()).filter(Boolean);
  let replaced = false;
  const next = parts.map((part) => {
    const eq = part.indexOf('=');
    if (eq < 0) return part;
    const key = part.slice(0, eq).trim();
    if (key !== name) return part;
    replaced = true;
    return `${name}=${value}`;
  });
  if (!replaced) next.push(`${name}=${value}`);
  return next.join('; ');
}

function mergeSetCookiePairs(cookieHeader: string, setCookieHeaders: string[]): string {
  let merged = cookieHeader;
  for (const raw of setCookieHeaders) {
    if (!raw) continue;
    const firstPair = raw.split(';')[0]?.trim();
    if (!firstPair) continue;
    const eq = firstPair.indexOf('=');
    if (eq <= 0) continue;
    const name = firstPair.slice(0, eq).trim();
    const value = firstPair.slice(eq + 1);
    merged = upsertCookie(merged, name, value);
  }
  return merged;
}

function parseJsonSafe<T>(text: string): T | null {
  try {
    return JSON.parse(text) as T;
  } catch {
    return null;
  }
}

function collectSetCookieHeaders(headers: Headers): string[] {
  const getSetCookie = (headers as unknown as { getSetCookie?: () => string[] }).getSetCookie;
  if (typeof getSetCookie === 'function') {
    return getSetCookie.call(headers) || [];
  }

  const single = headers.get('set-cookie');
  return single ? [single] : [];
}

export async function fetchJsonWithShieldCookieRetry<T>(
  url: string,
  options?: UndiciRequestInit,
): Promise<{ data: T | null; cookieHeader: string }> {
  const { fetch } = await import('undici');
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'User-Agent': SHIELD_USER_AGENT,
    ...normalizeHeaders(options?.headers),
  };

  let cookieHeader = headers.Cookie || headers.cookie || '';
  if (cookieHeader) {
    headers.Cookie = cookieHeader;
    delete headers.cookie;
  }

  for (let attempt = 0; attempt < 3; attempt += 1) {
    const requestOptions: UndiciRequestInit = {
      ...options,
      body: options?.body ?? undefined,
      headers,
    };
    const proxiedRequestOptions = await withSiteProxyRequestInit(url, requestOptions);
    const response = await fetch(url, proxiedRequestOptions);
    const text = await response.text();

    cookieHeader = mergeSetCookiePairs(cookieHeader, collectSetCookieHeaders(response.headers));
    const parsed = parseJsonSafe<T>(text);
    if (parsed) return { data: parsed, cookieHeader };

    if (!isShieldChallenge(response.headers.get('content-type') || '', text)) {
      return { data: null, cookieHeader };
    }
    if (!cookieHeader) {
      return { data: null, cookieHeader };
    }

    const acwScV2 = solveNewApiAcwScV2(text);
    if (!acwScV2) {
      return { data: null, cookieHeader };
    }

    cookieHeader = upsertCookie(cookieHeader, 'acw_sc__v2', acwScV2);
    headers.Cookie = cookieHeader;
  }

  return { data: null, cookieHeader };
}
