import type { RequestInit as UndiciRequestInit } from 'undici';
import { createContext, runInContext } from 'node:vm';
import { withSiteProxyRequestInit } from '../siteProxy.js';

const SHIELD_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36';

/**
 * New API 站点可能返回的防护挑战类型。
 * `aliyun-esa-browser` 依赖真实浏览器环境，不能在 node:vm 中伪造完成。
 */
export type NewApiShieldChallengeKind = 'legacy-acw-sc-v2' | 'aliyun-esa-browser';

/** 新版 ESA 挑战的稳定提示，供登录、签到和余额刷新共用。 */
export const NEW_API_ESA_BROWSER_CHALLENGE_MESSAGE =
  '站点返回了阿里云 ESA 浏览器验证页面，需要真实浏览器执行 JavaScript，当前 HTTP 客户端无法完成验证';

/**
 * 让上层可以按错误类型处理挑战，而不是依赖 undici 的 HTML JSON 解析文案。
 */
export class NewApiShieldChallengeError extends Error {
  readonly code = 'new_api_shield_challenge';
  readonly challenge: NewApiShieldChallengeKind;

  constructor(challenge: NewApiShieldChallengeKind) {
    super(
      challenge === 'aliyun-esa-browser'
        ? NEW_API_ESA_BROWSER_CHALLENGE_MESSAGE
        : '站点返回了防护验证页面，当前请求无法完成验证',
    );
    this.name = 'NewApiShieldChallengeError';
    this.challenge = challenge;
  }
}

/** 识别阿里云 ESA 新版 meta 挑战页；该挑战需要 DOM、时序和浏览器指纹。 */
export function isAliyunEsaBrowserChallenge(text: string): boolean {
  return /<meta\b[^>]*\bname\s*=\s*["']aliyun_waf_(?:aa|bb)["'][^>]*>/i.test(text || '');
}

/** 统一识别旧版 acw_sc__v2 与新版 ESA 挑战。 */
export function detectNewApiShieldChallenge(
  contentType: string,
  text: string,
): NewApiShieldChallengeKind | null {
  if (isAliyunEsaBrowserChallenge(text)) return 'aliyun-esa-browser';

  const normalizedType = (contentType || '').toLowerCase();
  if (
    (normalizedType.includes('text/html')
      && /var\s+arg1\s*=|acw_sc__v2|cdn_sec_tc|<script/i.test(text))
    || /var\s+arg1\s*=/.test(text)
  ) {
    return 'legacy-acw-sc-v2';
  }

  return null;
}

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

function parseChallengeXorSeed(html: string): string | null {
  const fnStart = html.indexOf('function a0i()');
  const bStart = html.indexOf('function b(');
  const rotateStart = html.indexOf('(function(a,c){');
  const rotateEnd = html.indexOf('),!(function', rotateStart);
  if (fnStart < 0 || bStart < 0 || bStart <= fnStart || rotateStart < 0 || rotateEnd < 0) {
    return null;
  }

  const helperCode = html.slice(fnStart, bStart);
  const rotateCode = `${html.slice(rotateStart, rotateEnd + 1)})`;

  try {
    const sandbox: Record<string, unknown> = { decodeURIComponent };
    createContext(sandbox);
    runInContext(helperCode, sandbox, { timeout: 100 });
    runInContext(rotateCode, sandbox, { timeout: 100 });
    const decoder = sandbox.a0j;
    if (typeof decoder !== 'function') return null;
    const seed = (decoder as (index: number) => unknown)(0x115);
    if (typeof seed !== 'string' || !/^[0-9a-f]+$/i.test(seed)) return null;
    return seed;
  } catch {
    return null;
  }
}

export function solveNewApiAcwScV2(html: string): string | null {
  const arg1 = parseChallengeArg1(html);
  const mapping = parseChallengeMapping(html);
  const xorSeed = parseChallengeXorSeed(html);
  if (!arg1 || !mapping || !xorSeed) return null;

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

export interface ShieldCookieFetchResult<T> {
  data: T | null;
  cookieHeader: string;
  /** 本次响应如果是挑战页，返回其类型而不是丢失上下文。 */
  challenge?: NewApiShieldChallengeKind;
  /** 面向日志/UI 的稳定错误提示。 */
  error?: string;
}

export async function fetchJsonWithShieldCookieRetry<T>(
  url: string,
  options?: UndiciRequestInit,
): Promise<ShieldCookieFetchResult<T>> {
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

    const challenge = detectNewApiShieldChallenge(response.headers.get('content-type') || '', text);
    if (!challenge) {
      if (!response.ok) {
        return {
          data: null,
          cookieHeader,
          error: `HTTP ${response.status}: ${text}`,
        };
      }
      return { data: null, cookieHeader };
    }

    // 新版 ESA 不是旧版 acw_sc__v2 的换算题，返回稳定上下文供调用方停止重试。
    if (challenge === 'aliyun-esa-browser') {
      return {
        data: null,
        cookieHeader,
        challenge,
        error: NEW_API_ESA_BROWSER_CHALLENGE_MESSAGE,
      };
    }

    if (!cookieHeader) {
      return {
        data: null,
        cookieHeader,
        challenge,
        error: '站点返回了防护验证页面，当前请求无法完成验证',
      };
    }

    const acwScV2 = solveNewApiAcwScV2(text);
    if (!acwScV2) {
      return {
        data: null,
        cookieHeader,
        challenge,
        error: '站点返回了防护验证页面，当前请求无法完成验证',
      };
    }

    cookieHeader = upsertCookie(cookieHeader, 'acw_sc__v2', acwScV2);
    headers.Cookie = cookieHeader;
  }

  return { data: null, cookieHeader };
}
