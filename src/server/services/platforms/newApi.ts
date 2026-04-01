import { ApiTokenInfo, BasePlatformAdapter, CheckinResult, BalanceInfo, UserInfo, TokenVerifyResult, CreateApiTokenOptions, type SiteAnnouncement } from './base.js';
import type { RequestInit as UndiciRequestInit } from 'undici';
import { createContext, runInContext } from 'node:vm';
import { withSiteProxyRequestInit } from '../siteProxy.js';
import { fetchJsonWithShieldCookieRetry } from './newApiShield.js';

export class NewApiAdapter extends BasePlatformAdapter {
  readonly platformName: string = 'new-api';

  async detect(url: string): Promise<boolean> {
    try {
      const res = await this.fetchJson<any>(`${url}/api/status`);
      return res?.success === true && typeof res?.data?.system_name === 'string';
    } catch {
      return false;
    }
  }

  override async getSiteAnnouncements(baseUrl: string, _accessToken: string): Promise<SiteAnnouncement[]> {
    try {
      const payload = await this.fetchJson<any>(`${baseUrl}/api/notice`);
      const content = typeof payload?.data === 'string'
        ? payload.data.trim()
        : (typeof payload === 'string' ? payload.trim() : '');
      if (!content) return [];
      return [{
        sourceKey: this.buildNoticeSourceKey(content),
        title: 'Site notice',
        content,
        level: 'info',
        sourceUrl: '/api/notice',
        rawPayload: payload,
      }];
    } catch {
      return [];
    }
  }

  private tryDecodeUserId(token: string): number | null {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) return null;
      const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
      if (typeof payload?.id === 'number') return payload.id;
      if (typeof payload?.sub === 'string' || typeof payload?.sub === 'number') {
        const n = Number.parseInt(String(payload.sub), 10);
        if (!Number.isNaN(n)) return n;
      }
    } catch {}
    return null;
  }

  private authHeaders(accessToken: string, userId?: number): Record<string, string> {
    const headers: Record<string, string> = { Authorization: `Bearer ${accessToken}` };
    if (userId) {
      const value = String(userId);
      headers['New-API-User'] = value;
      headers['Veloera-User'] = value;
      headers['voapi-user'] = value;
      headers['User-id'] = value;
      headers['Rix-Api-User'] = value;
      headers['neo-api-user'] = value;
    }
    return headers;
  }

  private buildCookieCandidates(token: string): string[] {
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

  private decodeBase64Loose(value: string): string | null {
    if (!value) return null;
    try {
      return Buffer.from(value, 'base64').toString('utf8');
    } catch {}
    try {
      const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
      return Buffer.from(normalized, 'base64').toString('utf8');
    } catch {}
    return null;
  }

  private decodeBase64BufferLoose(value: string): Buffer | null {
    if (!value) return null;
    try {
      return Buffer.from(value, 'base64');
    } catch {}
    try {
      const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
      return Buffer.from(normalized, 'base64');
    } catch {}
    return null;
  }

  private decodeGobSignedInt(encoded: Buffer): number | null {
    if (!encoded.length) return null;

    let unsigned = 0n;
    if (encoded[0] < 0x80) {
      unsigned = BigInt(encoded[0]);
    } else {
      const width = 0x100 - encoded[0];
      if (width <= 0 || encoded.length !== width + 1) return null;
      for (let i = 1; i < encoded.length; i += 1) {
        unsigned = (unsigned << 8n) | BigInt(encoded[i]);
      }
    }

    const signed = (unsigned & 1n) === 0n
      ? unsigned >> 1n
      : -((unsigned >> 1n) + 1n);
    if (signed <= 0n || signed > BigInt(Number.MAX_SAFE_INTEGER)) return null;
    return Number(signed);
  }

  private extractGobFieldInts(payload: Buffer, fieldName: string): number[] {
    const ids: number[] = [];
    const push = (value: number | null) => {
      if (typeof value !== 'number' || Number.isNaN(value)) return;
      if (value <= 0 || value > 10_000_000) return;
      if (!ids.includes(value)) ids.push(value);
    };

    const marker = Buffer.concat([
      Buffer.from(fieldName, 'utf8'),
      Buffer.from([0x03]),
      Buffer.from('int', 'utf8'),
      Buffer.from([0x04]),
    ]);

    let start = 0;
    while (start < payload.length) {
      const position = payload.indexOf(marker, start);
      if (position < 0) break;

      const encodedLength = payload[position + marker.length];
      const delimiter = payload[position + marker.length + 1];
      if (typeof encodedLength === 'number' && delimiter === 0x00) {
        const byteLength = encodedLength - 1;
        const valueStart = position + marker.length + 2;
        const valueEnd = valueStart + byteLength;
        if (byteLength > 0 && valueEnd <= payload.length) {
          push(this.decodeGobSignedInt(payload.subarray(valueStart, valueEnd)));
        }
      }

      start = position + marker.length;
    }

    return ids;
  }

  private extractLikelyUserIds(token: string): number[] {
    const ids: number[] = [];
    const push = (value: unknown) => {
      const n = Number.parseInt(String(value), 10);
      if (Number.isNaN(n)) return;
      if (n <= 0 || n > 10_000_000) return;
      if (!ids.includes(n)) ids.push(n);
    };

    const raw = (token || '').trim();
    if (!raw) return ids;

    const cookieCandidates = this.buildCookieCandidates(raw);
    const sessionValues = new Set<string>();
    for (const candidate of cookieCandidates) {
      const match = candidate.match(/(?:^|;\s*)session=([^;]+)/i);
      if (match?.[1]) sessionValues.add(match[1].trim());
    }

    if (raw && !raw.includes('=')) {
      sessionValues.add(raw.startsWith('Bearer ') ? raw.slice(7).trim() : raw);
    }

    for (const sessionValue of sessionValues) {
      const decodedBuffer = this.decodeBase64BufferLoose(sessionValue);
      if (!decodedBuffer) continue;

      const decoded = decodedBuffer.toString('utf8');

      const payloadCandidates: string[] = [decoded];
      const payloadBuffers: Buffer[] = [decodedBuffer];
      const parts = decoded.split('|');
      if (parts.length >= 2) {
        const middlePayloadBuffer = this.decodeBase64BufferLoose(parts[1]);
        if (middlePayloadBuffer) {
          payloadCandidates.push(middlePayloadBuffer.toString('utf8'));
          payloadBuffers.push(middlePayloadBuffer);
        }
      }

      for (const payload of payloadCandidates) {
        for (const m of payload.matchAll(/_(\d{4,8})(?!\d)/g)) {
          push(m[1]);
        }
        for (const m of payload.matchAll(/(?:user(?:name)?|uid|id)[^\d]{0,16}(\d{4,8})(?!\d)/gi)) {
          push(m[1]);
        }
      }

      for (const payload of payloadBuffers) {
        for (const value of this.extractGobFieldInts(payload, 'id')) {
          push(value);
        }
      }
    }

    return ids;
  }

  private buildUserIdProbeCandidates(token: string): number[] {
    const candidates: number[] = [];
    const push = (value: number | null) => {
      if (typeof value !== 'number' || Number.isNaN(value) || value <= 0) return;
      if (!candidates.includes(value)) candidates.push(value);
    };

    push(this.tryDecodeUserId(token));
    for (const guessed of this.extractLikelyUserIds(token)) {
      push(guessed);
    }
    for (const id of [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 15, 20, 50, 100, 8899, 11494]) {
      push(id);
    }

    return candidates;
  }

  private parseTokenItems(payload: any): any[] {
    if (Array.isArray(payload?.data)) return payload.data;
    if (Array.isArray(payload?.data?.items)) return payload.data.items;
    if (Array.isArray(payload?.data?.data)) return payload.data.data;
    if (Array.isArray(payload?.items)) return payload.items;
    if (Array.isArray(payload?.list)) return payload.list;
    if (Array.isArray(payload?.data?.list)) return payload.data.list;
    return [];
  }

  private isTokenListResponse(payload: any): boolean {
    if (!payload || typeof payload !== 'object') return false;
    if (payload?.success === true) return true;
    return (
      Array.isArray(payload?.data)
      || Array.isArray(payload?.data?.items)
      || Array.isArray(payload?.data?.data)
      || Array.isArray(payload?.items)
      || Array.isArray(payload?.list)
      || Array.isArray(payload?.data?.list)
    );
  }

  private normalizeTokenKeyForCompare(value?: string | null): string {
    const trimmed = (value || '').trim();
    return trimmed.startsWith('Bearer ') ? trimmed.slice(7).trim() : trimmed;
  }

  private parseGroupKeys(payload: any): string[] {
    if (payload && typeof payload === 'object' && payload?.success === false) {
      return [];
    }

    const source = payload?.data ?? payload;
    if (Array.isArray(source)) {
      return source
        .map((item) => String(item || '').trim())
        .filter(Boolean);
    }

    if (source && typeof source === 'object') {
      return Object.keys(source)
        .map((key) => key.trim())
        .filter((key) => !['success', 'message', 'code', 'data', 'error'].includes(key.toLowerCase()))
        .filter(Boolean);
    }

    return [];
  }

  private resolveGroupFetchErrorMessage(payload: any): string {
    const message = typeof payload?.message === 'string' ? payload.message.trim() : '';
    const normalized = message.toLowerCase();
    const indicatesExpired = normalized.includes('expired')
      || normalized.includes('invalid token')
      || normalized.includes('access token')
      || normalized.includes('unauthorized')
      || normalized.includes('forbidden')
      || normalized.includes('未登录')
      || normalized.includes('登录')
      || normalized.includes('过期');
    if (indicatesExpired) return '账号会话可能已过期，请重新登录后再拉取分组';
    return message || '拉取分组失败';
  }

  private normalizeTokenItems(items: any[]): ApiTokenInfo[] {
    const normalized: ApiTokenInfo[] = [];
    for (let index = 0; index < items.length; index += 1) {
      const item = items[index];
      const key = typeof item?.key === 'string' ? item.key.trim() : '';
      if (!key) continue;
      const rawName = typeof item?.name === 'string' ? item.name.trim() : '';
      const rawGroup = typeof item?.group === 'string'
        ? item.group.trim()
        : (typeof item?.group_name === 'string'
          ? item.group_name.trim()
          : (typeof item?.token_group === 'string' ? item.token_group.trim() : ''));
      const status = typeof item?.status === 'number' ? item.status : undefined;
      const tokenInfo: ApiTokenInfo = {
        name: rawName || (index === 0 ? 'default' : `token-${index + 1}`),
        key,
        enabled: status === undefined ? true : status === 1,
      };
      if (rawGroup) tokenInfo.tokenGroup = rawGroup;
      normalized.push(tokenInfo);
    }
    return normalized;
  }

  private parseUserInfo(data: any): UserInfo {
    return {
      username: data?.username || data?.display_name || '',
      displayName: data?.display_name,
      email: data?.email,
      role: data?.role,
    };
  }

  private parseBalance(data: any): BalanceInfo {
    const quota = (data?.quota || 0) / 500000;
    const used = (data?.used_quota || 0) / 500000;
    const total = quota + used;
    const todayIncome = Number.isFinite(data?.today_income) ? (data.today_income / 500000) : undefined;
    const todayQuotaConsumption = Number.isFinite(data?.today_quota_consumption) ? (data.today_quota_consumption / 500000) : undefined;
    return { balance: quota, used, quota: total, todayIncome, todayQuotaConsumption };
  }

  private extractLoginAccessToken(payload: any): string | null {
    const candidates: unknown[] = [
      payload?.data,
      payload?.token,
      payload?.accessToken,
      payload?.access_token,
      payload?.data?.token,
      payload?.data?.accessToken,
      payload?.data?.access_token,
    ];
    for (const candidate of candidates) {
      if (typeof candidate !== 'string') continue;
      const token = candidate.trim();
      if (token) return token;
    }
    return null;
  }

  private buildDefaultTokenPayload(options?: CreateApiTokenOptions): Record<string, unknown> {
    const normalizedName = (options?.name || '').trim() || 'metapi';
    const unlimitedQuota = options?.unlimitedQuota ?? true;
    const remainQuota = Number.isFinite(options?.remainQuota)
      ? Math.max(0, Math.trunc(options?.remainQuota as number))
      : 0;
    const expiredTime = Number.isFinite(options?.expiredTime)
      ? Math.trunc(options?.expiredTime as number)
      : -1;
    return {
      name: normalizedName,
      unlimited_quota: unlimitedQuota,
      expired_time: expiredTime,
      remain_quota: remainQuota,
      allow_ips: (options?.allowIps || '').trim(),
      model_limits_enabled: options?.modelLimitsEnabled ?? false,
      model_limits: (options?.modelLimits || '').trim(),
      group: (options?.group || '').trim(),
    };
  }

  private parseChallengeArg1(html: string): string | null {
    const match = html.match(/var\s+arg1\s*=\s*['"]([0-9a-fA-F]+)['"]/);
    return match?.[1]?.toUpperCase() || null;
  }

  private parseChallengeMapping(html: string): number[] | null {
    const match = html.match(/for\(var m=\[([^\]]+)\],p=L\(0x115\)/);
    if (!match?.[1]) return null;

    const values = match[1].split(',').map((raw) => {
      const v = raw.trim().toLowerCase();
      if (!v) return Number.NaN;
      if (v.startsWith('0x')) return Number.parseInt(v.slice(2), 16);
      return Number.parseInt(v, 10);
    });
    if (values.some((v) => Number.isNaN(v))) return null;
    return values;
  }

  private parseChallengeXorSeed(html: string): string | null {
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
      const decoder = sandbox['a0j'];
      if (typeof decoder !== 'function') return null;
      const seed = (decoder as (idx: number) => unknown)(0x115);
      if (typeof seed !== 'string' || !/^[0-9a-f]+$/i.test(seed)) return null;
      return seed;
    } catch {
      return null;
    }
  }

  private solveAcwScV2(html: string): string | null {
    const arg1 = this.parseChallengeArg1(html);
    const mapping = this.parseChallengeMapping(html);
    const xorSeed = this.parseChallengeXorSeed(html);
    if (!arg1 || !mapping || !xorSeed) return null;

    const q: string[] = [];
    for (let i = 0; i < arg1.length; i += 1) {
      const ch = arg1[i];
      for (let j = 0; j < mapping.length; j += 1) {
        if (mapping[j] === i + 1) {
          q[j] = ch;
        }
      }
    }

    const reordered = q.join('');
    let out = '';
    for (let i = 0; i < reordered.length && i < xorSeed.length; i += 2) {
      const left = Number.parseInt(reordered.slice(i, i + 2), 16);
      const right = Number.parseInt(xorSeed.slice(i, i + 2), 16);
      if (Number.isNaN(left) || Number.isNaN(right)) return null;
      out += (left ^ right).toString(16).padStart(2, '0');
    }

    return out || null;
  }

  private upsertCookie(cookieHeader: string, name: string, value: string): string {
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

  private mergeSetCookiePairs(cookieHeader: string, setCookieHeaders: string[]): string {
    let merged = cookieHeader;
    for (const raw of setCookieHeaders) {
      if (!raw) continue;
      const firstPair = raw.split(';')[0]?.trim();
      if (!firstPair) continue;
      const eq = firstPair.indexOf('=');
      if (eq <= 0) continue;
      const name = firstPair.slice(0, eq).trim();
      const value = firstPair.slice(eq + 1);
      merged = this.upsertCookie(merged, name, value);
    }
    return merged;
  }

  private parseJsonSafe<T>(text: string): T | null {
    try {
      return JSON.parse(text) as T;
    } catch {
      return null;
    }
  }

  private extractHtmlErrorSummary(payloadRaw: string): string | null {
    const text = (payloadRaw || '').trim();
    if (!text || !/<html|<!doctype/i.test(text)) return null;

    const titleMatch = text.match(/<title>\s*([^<]+?)\s*<\/title>/i);
    let title = titleMatch?.[1]?.trim() || '';
    if (title.includes('|')) {
      title = title.split('|')[0]?.trim() || title;
    }
    if (!title && /cloudflare tunnel error/i.test(text)) {
      title = 'Cloudflare Tunnel error';
    }
    if (!title) return null;

    const codeMatch = text.match(/<span[^>]*>\s*Error\s*<\/span>\s*<span[^>]*>\s*(\d{3,4})\s*<\/span>/i)
      || text.match(/\bError\s*(\d{3,4})\b/i);
    const code = codeMatch?.[1];
    return code ? `${title} (Error ${code})` : title;
  }

  private formatRequestErrorMessage(err: unknown): string | null {
    const raw = typeof (err as { message?: unknown })?.message === 'string'
      ? (err as { message: string }).message.trim()
      : '';
    if (!raw) return null;

    const httpMatch = raw.match(/^(HTTP\s+\d+):\s*([\s\S]+)$/);
    if (!httpMatch) return raw;

    const [, prefix, payloadRaw] = httpMatch;
    const payload = this.parseJsonSafe<any>(payloadRaw);
    const bodyMessage = this.extractResponseMessage(payload);
    if (bodyMessage) return `${prefix}: ${bodyMessage}`;
    const htmlSummary = this.extractHtmlErrorSummary(payloadRaw);
    if (htmlSummary) return `${prefix}: ${htmlSummary}`;
    return raw;
  }

  private extractResponseMessage(payload: any): string {
    if (typeof payload?.message === 'string' && payload.message.trim()) {
      return payload.message.trim();
    }
    if (typeof payload?.error?.message === 'string' && payload.error.message.trim()) {
      return payload.error.message.trim();
    }
    if (typeof payload?.msg === 'string' && payload.msg.trim()) {
      return payload.msg.trim();
    }
    return '';
  }

  private isShieldChallenge(contentType: string, text: string): boolean {
    const ct = (contentType || '').toLowerCase();
    if (ct.includes('text/html') && /var\s+arg1\s*=|acw_sc__v2|cdn_sec_tc|<script/i.test(text)) {
      return true;
    }
    return /var\s+arg1\s*=/.test(text);
  }

  private normalizeHeaders(headers?: UndiciRequestInit['headers']): Record<string, string> {
    const output: Record<string, string> = {};
    if (!headers) return output;

    if (Array.isArray(headers)) {
      for (const [k, v] of headers) {
        output[String(k)] = String(v);
      }
      return output;
    }

    const maybeIterable = headers as { forEach?: (fn: (v: string, k: string) => void) => void };
    if (typeof maybeIterable.forEach === 'function') {
      maybeIterable.forEach((v, k) => {
        output[String(k)] = String(v);
      });
      return output;
    }

    for (const [k, v] of Object.entries(headers as Record<string, unknown>)) {
      if (v === undefined || v === null) continue;
      output[k] = String(v);
    }
    return output;
  }

  private hasUsableSessionCookie(cookieHeader: string): boolean {
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

  private shouldFallbackToCookieCheckin(message?: string | null): boolean {
    if (!message) return true;
    const text = message.toLowerCase();
    return (
      text.includes('unexpected token') ||
      text.includes('not valid json') ||
      text.includes('<html') ||
      text.includes('new-api-user') ||
      text.includes('access token') ||
      text.includes('unauthorized') ||
      text.includes('forbidden') ||
      text.includes('not login') ||
      text.includes('not logged') ||
      text.includes('invalid url (post /api/user/checkin)') ||
      (text.includes('http 404') && text.includes('/api/user/checkin')) ||
      text.includes('未登录') ||
      text.includes('未提供')
    );
  }

  private isMissingCheckinEndpointMessage(message?: string | null): boolean {
    if (!message) return false;
    const text = message.toLowerCase();
    return (
      text.includes('invalid url (post /api/user/checkin)') ||
      (text.includes('http 404') && text.includes('/api/user/checkin')) ||
      text.includes('checkin endpoint not found') ||
      text.includes('check-in is not supported') ||
      text.includes('checkin is not supported') ||
      text.includes('does not support checkin') ||
      text.includes('not support checkin')
    );
  }

  private isCookieSessionFailureMessage(message?: string | null): boolean {
    if (!message) return false;
    const text = message.toLowerCase();
    return (
      text.includes('access token') ||
      text.includes('unauthorized') ||
      text.includes('forbidden') ||
      text.includes('new-api-user') ||
      text.includes('user id') ||
      text.includes('invalid token') ||
      text.includes('expired') ||
      text.includes('无权') ||
      text.includes('未登录') ||
      text.includes('未提供') ||
      text.includes('未授权') ||
      text.includes('not login') ||
      text.includes('not logged')
    );
  }

  private async detectCookieSessionFailureMessage(
    baseUrl: string,
    accessToken: string,
    candidateUserIds: Array<number | null | undefined>,
  ): Promise<string | null> {
    let failureMessage: string | null = null;
    const rememberFailure = (message: string) => {
      if (failureMessage) return;
      const text = message.trim();
      if (!this.isCookieSessionFailureMessage(text)) return;
      failureMessage = text;
    };

    const uniqueCandidateUserIds = Array.from(new Set(
      candidateUserIds.filter((value): value is number => typeof value === 'number' && value > 0),
    ));

    if (uniqueCandidateUserIds.length === 0) {
      await this.fetchUserSelfByCookie(baseUrl, accessToken, undefined, rememberFailure);
      return failureMessage;
    }

    for (const userId of uniqueCandidateUserIds) {
      await this.fetchUserSelfByCookie(baseUrl, accessToken, userId, rememberFailure);
      if (failureMessage) {
        return failureMessage;
      }
    }

    return failureMessage;
  }

  private async fetchJsonRawWithCookie<T>(
    url: string,
    options?: UndiciRequestInit,
  ): Promise<{ data: T | null; cookieHeader: string }> {
    const { fetch } = await import('undici');
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36',
      ...this.normalizeHeaders(options?.headers),
    };

    let cookieHeader = headers['Cookie'] || headers['cookie'] || '';
    if (cookieHeader) {
      headers['Cookie'] = cookieHeader;
      delete headers['cookie'];
    }

    for (let attempt = 0; attempt < 3; attempt += 1) {
      const requestOptions: UndiciRequestInit = {
        ...options,
        body: options?.body ?? undefined,
        headers,
      };
      const proxiedRequestOptions = await withSiteProxyRequestInit(url, requestOptions);
      const res = await fetch(url, proxiedRequestOptions);
      const text = await res.text();
      const getSetCookie = (res.headers as unknown as { getSetCookie?: () => string[] }).getSetCookie;
      if (typeof getSetCookie === 'function') {
        cookieHeader = this.mergeSetCookiePairs(cookieHeader, getSetCookie.call(res.headers) || []);
      }
      const parsed = this.parseJsonSafe<T>(text);
      if (parsed) return { data: parsed, cookieHeader };

      if (!this.isShieldChallenge(res.headers.get('content-type') || '', text)) {
        return { data: null, cookieHeader };
      }
      if (!cookieHeader) {
        return { data: null, cookieHeader };
      }

      const acwScV2 = this.solveAcwScV2(text);
      if (!acwScV2) {
        return { data: null, cookieHeader };
      }
      cookieHeader = this.upsertCookie(cookieHeader, 'acw_sc__v2', acwScV2);
      headers['Cookie'] = cookieHeader;
    }

    return { data: null, cookieHeader };
  }

  private async fetchJsonRaw<T>(url: string, options?: UndiciRequestInit): Promise<T | null> {
    const result = await this.fetchJsonRawWithCookie<T>(url, options);
    return result.data;
  }

  private async fetchUserSelfByCookie(
    baseUrl: string,
    token: string,
    platformUserId?: number,
    onFailureMessage?: (message: string) => void,
  ): Promise<any | null> {
    for (const cookie of this.buildCookieCandidates(token)) {
      try {
        const headers: Record<string, string> = { Cookie: cookie };
        if (platformUserId) headers['New-Api-User'] = String(platformUserId);
        const res = await this.fetchJsonRaw<any>(`${baseUrl}/api/user/self`, { headers });
        if (res?.success && res?.data) return res;
        if (typeof res?.message === 'string' && res.message.trim()) {
          onFailureMessage?.(res.message.trim());
        }
      } catch {}
    }
    return null;
  }

  private async probeUserIdByCookie(baseUrl: string, token: string): Promise<number | null> {
    const candidates = this.buildUserIdProbeCandidates(token);
    for (const cookie of this.buildCookieCandidates(token)) {
      for (const id of candidates) {
        try {
          const res = await this.fetchJsonRaw<any>(`${baseUrl}/api/user/self`, {
            headers: { Cookie: cookie, 'New-Api-User': String(id) },
          });
          if (res?.success && res?.data) return id;
        } catch {}
      }
    }
    return null;
  }

  private async probeAlternateUserIdByCookie(
    baseUrl: string,
    token: string,
    currentUserId?: number | null,
  ): Promise<number | null> {
    const probed = await this.probeUserIdByCookie(baseUrl, token);
    if (!probed) return null;
    if (typeof currentUserId === 'number' && currentUserId > 0 && probed === currentUserId) {
      return null;
    }
    return probed;
  }

  private async getApiTokensByCookie(baseUrl: string, token: string, userId?: number | null): Promise<ApiTokenInfo[]> {
    for (const cookie of this.buildCookieCandidates(token)) {
      try {
        const headers: Record<string, string> = { Cookie: cookie };
        if (userId) headers['New-Api-User'] = String(userId);
        const res = await this.fetchJsonRaw<any>(`${baseUrl}/api/token/?p=0&size=100`, { headers });
        const normalized = this.normalizeTokenItems(this.parseTokenItems(res));
        if (normalized.length > 0) return normalized;
      } catch {}
    }
    return [];
  }

  private async getSessionModelsByCookie(baseUrl: string, token: string, userId?: number | null): Promise<string[]> {
    for (const cookie of this.buildCookieCandidates(token)) {
      try {
        const headers: Record<string, string> = { Cookie: cookie };
        if (userId) headers['New-Api-User'] = String(userId);
        const res = await this.fetchJsonRaw<any>(`${baseUrl}/api/user/models`, { headers });
        if (Array.isArray(res?.data) && res.data.length > 0) return res.data.filter(Boolean);
        if (res?.data && typeof res.data === 'object') {
          const keys = Object.keys(res.data).filter(Boolean);
          if (keys.length > 0) return keys;
        }
      } catch {}
    }
    return [];
  }

  private extractOpenAiModels(payload: any): string[] {
    if (!Array.isArray(payload?.data)) return [];
    return payload.data.map((m: any) => m?.id).filter(Boolean);
  }

  private async getOpenAiModelsViaShieldCookie(baseUrl: string, token: string): Promise<string[]> {
    for (const cookie of this.buildCookieCandidates(token)) {
      try {
        const { data } = await fetchJsonWithShieldCookieRetry<any>(`${baseUrl}/v1/models`, {
          headers: {
            Authorization: `Bearer ${token}`,
            Cookie: cookie,
          },
        });
        const models = this.extractOpenAiModels(data);
        if (models.length > 0) return models;
      } catch {}
    }
    return [];
  }

  private async getOpenAiModels(baseUrl: string, token: string): Promise<string[]> {
    const shouldTryShieldCookie = this.platformName === 'anyrouter' || token.includes('=');
    if (shouldTryShieldCookie) {
      const shieldModels = await this.getOpenAiModelsViaShieldCookie(baseUrl, token);
      if (shieldModels.length > 0) return shieldModels;
    }

    try {
      const res = await this.fetchJson<any>(`${baseUrl}/v1/models`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      return this.extractOpenAiModels(res);
    } catch {
      return [];
    }
  }

  private async discoverUserId(baseUrl: string, accessToken: string): Promise<number | null> {
    const jwtId = this.tryDecodeUserId(accessToken);
    if (jwtId) {
      try {
        const res = await this.fetchJsonRaw<any>(`${baseUrl}/api/user/self`, {
          headers: this.authHeaders(accessToken, jwtId),
        });
        if (res?.success && res?.data) return jwtId;
      } catch {}
    }

    try {
      const res = await this.fetchJsonRaw<any>(`${baseUrl}/api/user/self`, {
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      if (res?.success && res?.data?.id) return res.data.id;
    } catch {}

    try {
      const cookieRes = await this.fetchUserSelfByCookie(baseUrl, accessToken);
      if (cookieRes?.success && cookieRes?.data?.id) return cookieRes.data.id;
    } catch {}

    const cookieId = await this.probeUserIdByCookie(baseUrl, accessToken);
    if (cookieId) return cookieId;

    return null;
  }

  override async getUserInfo(baseUrl: string, accessToken: string, platformUserId?: number): Promise<UserInfo | null> {
    try {
      const directRes = await this.fetchJsonRaw<any>(`${baseUrl}/api/user/self`, {
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      if (directRes?.success && directRes?.data) {
        return this.parseUserInfo(directRes.data);
      }
    } catch {}

    try {
      const cookieRes = await this.fetchUserSelfByCookie(baseUrl, accessToken, platformUserId);
      if (cookieRes?.success && cookieRes?.data) {
        return this.parseUserInfo(cookieRes.data);
      }
    } catch {}

    try {
      const fallbackUserId = await this.probeAlternateUserIdByCookie(baseUrl, accessToken, platformUserId);
      if (fallbackUserId) {
        const cookieRetry = await this.fetchUserSelfByCookie(baseUrl, accessToken, fallbackUserId);
        if (cookieRetry?.success && cookieRetry?.data) {
          return this.parseUserInfo(cookieRetry.data);
        }
      }
    } catch {}

    return null;
  }

  override async login(
    baseUrl: string,
    username: string,
    password: string,
  ): Promise<{ success: boolean; accessToken?: string; username?: string; message?: string }> {
    try {
      const { data: res, cookieHeader } = await this.fetchJsonRawWithCookie<any>(`${baseUrl}/api/user/login`, {
        method: 'POST',
        body: JSON.stringify({ username, password }),
        headers: {
          'X-Requested-With': 'XMLHttpRequest',
        },
      });
      if (!res) {
        return { success: false, message: 'shield challenge blocked login' };
      }

      const accessToken = this.extractLoginAccessToken(res);
      if (res?.success && accessToken) {
        return {
          success: true,
          accessToken,
          username,
        };
      }
      if (res?.success && this.hasUsableSessionCookie(cookieHeader)) {
        return {
          success: true,
          accessToken: cookieHeader,
          username,
        };
      }

      return {
        success: false,
        message: this.extractResponseMessage(res) || '登录失败：未获取到可用会话凭据，请改用 Cookie/Token 导入',
      };
    } catch (err: any) {
      return {
        success: false,
        message: this.formatRequestErrorMessage(err) || err?.message || '登录请求失败',
      };
    }
  }

  override async verifyToken(baseUrl: string, token: string, platformUserId?: number): Promise<TokenVerifyResult> {
    const openAiModels = await this.getOpenAiModels(baseUrl, token);
    if (openAiModels.length > 0) {
      return { tokenType: 'apikey', models: openAiModels };
    }

    try {
      const directRes = await this.fetchJsonRaw<any>(`${baseUrl}/api/user/self`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (directRes?.success && directRes?.data) {
        const userId = directRes.data.id;
        const userInfo = this.parseUserInfo(directRes.data);
        const balance = this.parseBalance(directRes.data);
        let apiToken: string | null = null;
        try { apiToken = await this.getApiTokenWithUser(baseUrl, token, userId); } catch {}
        return { tokenType: 'session', userInfo, balance, apiToken };
      }

      if (directRes?.message?.includes('New-Api-User')) {
        const userId = platformUserId || await this.probeUserId(baseUrl, token);
        if (userId) {
          const res = await this.fetchJsonRaw<any>(`${baseUrl}/api/user/self`, {
            headers: this.authHeaders(token, userId),
          });
          if (res?.success && res?.data) {
            const userInfo = this.parseUserInfo(res.data);
            const balance = this.parseBalance(res.data);
            let apiToken: string | null = null;
            try { apiToken = await this.getApiTokenWithUser(baseUrl, token, userId); } catch {}
            return { tokenType: 'session', userInfo, balance, apiToken };
          }
          if (
            platformUserId &&
            typeof res?.message === 'string' &&
            /娑撳秴灏柊宄緈ismatch/i.test(res.message)
          ) {
            return { tokenType: 'unknown' };
          }
        }
      }
    } catch {}

    const cookieRes = await this.fetchUserSelfByCookie(baseUrl, token, platformUserId);
    if (cookieRes?.success && cookieRes?.data) {
      const userId = cookieRes.data.id;
      const userInfo = this.parseUserInfo(cookieRes.data);
      const balance = this.parseBalance(cookieRes.data);
      let apiToken: string | null = null;
      try { apiToken = await this.getApiTokenWithUser(baseUrl, token, userId); } catch {}
      return { tokenType: 'session', userInfo, balance, apiToken };
    }

    const cookieUserId = await this.probeAlternateUserIdByCookie(baseUrl, token, platformUserId);
    if (cookieUserId) {
      const cookieRetry = await this.fetchUserSelfByCookie(baseUrl, token, cookieUserId);
      if (cookieRetry?.success && cookieRetry?.data) {
        const userInfo = this.parseUserInfo(cookieRetry.data);
        const balance = this.parseBalance(cookieRetry.data);
        let apiToken: string | null = null;
        try { apiToken = await this.getApiTokenWithUser(baseUrl, token, cookieUserId); } catch {}
        return { tokenType: 'session', userInfo, balance, apiToken };
      }
    }

    return { tokenType: 'unknown' };
  }

  private async probeUserId(baseUrl: string, accessToken: string): Promise<number | null> {
    const jwtId = this.tryDecodeUserId(accessToken);
    if (jwtId) {
      const valid = await this.testUserId(baseUrl, accessToken, jwtId);
      if (valid) return jwtId;
    }

    for (const id of this.buildUserIdProbeCandidates(accessToken)) {
      if (id === jwtId) continue;
      if (await this.testUserId(baseUrl, accessToken, id)) return id;
    }

    return null;
  }

  private async testUserId(baseUrl: string, accessToken: string, userId: number): Promise<boolean> {
    try {
      const res = await this.fetchJsonRaw<any>(`${baseUrl}/api/user/self`, {
        headers: this.authHeaders(accessToken, userId),
      });
      return res?.success === true && !!res?.data;
    } catch {
      return false;
    }
  }

  async checkin(baseUrl: string, accessToken: string, platformUserId?: number): Promise<CheckinResult> {
    const resolvedUserId = platformUserId || await this.discoverUserId(baseUrl, accessToken);
    let firstFailureMessage: string | undefined;

    try {
      const headers = this.authHeaders(accessToken, resolvedUserId || undefined);

      const res = await this.fetchJson<any>(`${baseUrl}/api/user/checkin`, {
        method: 'POST',
        headers,
      });
      if (res?.success) {
        return { success: true, message: res.message || 'checkin success', reward: res.data?.reward?.toString() };
      }
      const directMessage = this.extractResponseMessage(res);
      if (directMessage) firstFailureMessage = directMessage;
    } catch (err) {
      const parsed = this.formatRequestErrorMessage(err);
      if (parsed) firstFailureMessage = parsed;
    }

    if (firstFailureMessage && !this.shouldFallbackToCookieCheckin(firstFailureMessage)) {
      return { success: false, message: firstFailureMessage };
    }

    const tryCookieCheckin = async (cookieUserId?: number | null): Promise<CheckinResult | null> => {
      for (const cookie of this.buildCookieCandidates(accessToken)) {
        try {
          const signInRes = await this.fetchJsonRaw<any>(`${baseUrl}/api/user/sign_in`, {
            method: 'POST',
            body: '{}',
            headers: {
              Cookie: cookie,
              'X-Requested-With': 'XMLHttpRequest',
            },
          });
          if (signInRes?.success) {
            return {
              success: true,
              message: signInRes.message || 'checked in',
              reward: signInRes.data?.reward?.toString(),
            };
          }
          const signInMessage = this.extractResponseMessage(signInRes);
          if (!firstFailureMessage && signInMessage) firstFailureMessage = signInMessage;
        } catch (err) {
          const parsed = this.formatRequestErrorMessage(err);
          if (!firstFailureMessage && parsed) firstFailureMessage = parsed;
        }

        try {
          const headers: Record<string, string> = { Cookie: cookie };
          if (cookieUserId) headers['New-Api-User'] = String(cookieUserId);
          const res = await this.fetchJsonRaw<any>(`${baseUrl}/api/user/checkin`, {
            method: 'POST',
            headers,
          });
          if (res?.success) {
            return { success: true, message: res.message || 'checkin success', reward: res.data?.reward?.toString() };
          }
          const cookieMessage = this.extractResponseMessage(res);
          if (cookieMessage) firstFailureMessage = cookieMessage;
        } catch (err) {
          const parsed = this.formatRequestErrorMessage(err);
          if (parsed) firstFailureMessage = parsed;
        }
      }

      return null;
    };

    const initialCookieResult = await tryCookieCheckin(resolvedUserId);
    if (initialCookieResult) return initialCookieResult;

    const alternateCookieUserId = await this.probeAlternateUserIdByCookie(baseUrl, accessToken, resolvedUserId);
    if (alternateCookieUserId) {
      const retriedCookieResult = await tryCookieCheckin(alternateCookieUserId);
      if (retriedCookieResult) return retriedCookieResult;
    }

    if (this.isMissingCheckinEndpointMessage(firstFailureMessage)) {
      const cookieSessionFailureMessage = await this.detectCookieSessionFailureMessage(
        baseUrl,
        accessToken,
        [resolvedUserId, alternateCookieUserId],
      );
      if (cookieSessionFailureMessage) {
        return { success: false, message: cookieSessionFailureMessage };
      }
    }

    return { success: false, message: firstFailureMessage || 'checkin failed' };
  }

  async getBalance(baseUrl: string, accessToken: string, platformUserId?: number): Promise<BalanceInfo> {
    const resolvedUserId = platformUserId || await this.discoverUserId(baseUrl, accessToken);
    let failureMessage: string | null = null;
    const rememberFailure = (message?: string | null) => {
      if (failureMessage) return;
      const text = typeof message === 'string' ? message.trim() : '';
      if (!text) return;
      failureMessage = text;
    };

    try {
      const res = await this.fetchJson<any>(`${baseUrl}/api/user/self`, {
        headers: this.authHeaders(accessToken, resolvedUserId || undefined),
      });
      if (res?.success && res?.data) {
        return this.parseBalance(res.data);
      }
      rememberFailure(typeof res?.message === 'string' ? res.message : null);
    } catch (err) {
      rememberFailure(this.formatRequestErrorMessage(err));
    }

    const cookieRes = await this.fetchUserSelfByCookie(
      baseUrl,
      accessToken,
      resolvedUserId || undefined,
      rememberFailure,
    );
    if (cookieRes?.success && cookieRes?.data) {
      return this.parseBalance(cookieRes.data);
    }

    const cookieUserId = await this.probeAlternateUserIdByCookie(baseUrl, accessToken, resolvedUserId);
    if (cookieUserId) {
      const cookieRetry = await this.fetchUserSelfByCookie(baseUrl, accessToken, cookieUserId, rememberFailure);
      if (cookieRetry?.success && cookieRetry?.data) {
        return this.parseBalance(cookieRetry.data);
      }
    }

    throw new Error(failureMessage || 'failed to fetch balance');
  }

  async getModels(baseUrl: string, token: string, platformUserId?: number): Promise<string[]> {
    const openAiModels = await this.getOpenAiModels(baseUrl, token);
    if (openAiModels.length > 0) return openAiModels;

    const userId = platformUserId || await this.discoverUserId(baseUrl, token);
    if (userId) {
      try {
        const res = await this.fetchJson<any>(`${baseUrl}/api/user/models`, {
          headers: this.authHeaders(token, userId),
        });
        if (Array.isArray(res?.data)) {
          return res.data.filter(Boolean);
        }
        if (res?.data && typeof res.data === 'object') {
          return Object.keys(res.data).filter(Boolean);
        }
      } catch {}
    }

    const cookieModels = await this.getSessionModelsByCookie(baseUrl, token, userId || platformUserId);
    if (cookieModels.length > 0) return cookieModels;

    const alternateCookieUserId = await this.probeAlternateUserIdByCookie(baseUrl, token, userId || platformUserId);
    if (alternateCookieUserId) {
      const fallbackModels = await this.getSessionModelsByCookie(baseUrl, token, alternateCookieUserId);
      if (fallbackModels.length > 0) return fallbackModels;
    }

    return [];
  }

  async getApiToken(baseUrl: string, accessToken: string, platformUserId?: number): Promise<string | null> {
    const userId = platformUserId || await this.discoverUserId(baseUrl, accessToken);
    const tokens = await this.getApiTokensWithUser(baseUrl, accessToken, userId);
    return tokens.find((token) => token.enabled !== false)?.key || tokens[0]?.key || null;
  }

  async getApiTokens(baseUrl: string, accessToken: string, platformUserId?: number): Promise<ApiTokenInfo[]> {
    const userId = platformUserId || await this.discoverUserId(baseUrl, accessToken);
    return this.getApiTokensWithUser(baseUrl, accessToken, userId);
  }

  private async getApiTokenWithUser(baseUrl: string, accessToken: string, userId: number | null): Promise<string | null> {
    const tokens = await this.getApiTokensWithUser(baseUrl, accessToken, userId);
    return tokens.find((token) => token.enabled !== false)?.key || tokens[0]?.key || null;
  }

  async createApiToken(
    baseUrl: string,
    accessToken: string,
    platformUserId?: number,
    options?: CreateApiTokenOptions,
  ): Promise<boolean> {
    const payload = JSON.stringify(this.buildDefaultTokenPayload(options));
    const resolvedUserId = platformUserId || await this.discoverUserId(baseUrl, accessToken);

    try {
      const res = await this.fetchJson<any>(`${baseUrl}/api/token/`, {
        method: 'POST',
        headers: this.authHeaders(accessToken, resolvedUserId || undefined),
        body: payload,
      });
      if (res?.success) return true;
    } catch {}

    const cookieUserId = resolvedUserId || await this.probeUserIdByCookie(baseUrl, accessToken);
    for (const cookie of this.buildCookieCandidates(accessToken)) {
      try {
        const headers: Record<string, string> = { Cookie: cookie };
        if (cookieUserId) headers['New-Api-User'] = String(cookieUserId);
        const res = await this.fetchJsonRaw<any>(`${baseUrl}/api/token/`, {
          method: 'POST',
          headers,
          body: payload,
        });
        if (res?.success) return true;
      } catch {}
    }

    return false;
  }

  async getUserGroups(baseUrl: string, accessToken: string, platformUserId?: number): Promise<string[]> {
    const resolvedUserId = platformUserId || await this.discoverUserId(baseUrl, accessToken);
    const dedupe = (groups: string[]) => Array.from(new Set(groups.map((item) => item.trim()).filter(Boolean)));
    let terminalError: string | null = null;

    try {
      const res = await this.fetchJson<any>(`${baseUrl}/api/user/self/groups`, {
        headers: this.authHeaders(accessToken, resolvedUserId || undefined),
      });
      if (res?.success === false) {
        terminalError = this.resolveGroupFetchErrorMessage(res);
      }
      const parsed = dedupe(this.parseGroupKeys(res));
      if (parsed.length > 0) return parsed;
    } catch {}

    try {
      const res = await this.fetchJson<any>(`${baseUrl}/api/user_group_map`, {
        headers: this.authHeaders(accessToken, resolvedUserId || undefined),
      });
      if (res?.success === false) {
        terminalError = this.resolveGroupFetchErrorMessage(res);
      }
      const parsed = dedupe(this.parseGroupKeys(res));
      if (parsed.length > 0) return parsed;
    } catch {}

    const cookieUserId = resolvedUserId || await this.probeUserIdByCookie(baseUrl, accessToken);
    for (const cookie of this.buildCookieCandidates(accessToken)) {
      const headers: Record<string, string> = { Cookie: cookie };
      if (cookieUserId) headers['New-Api-User'] = String(cookieUserId);

      try {
        const res = await this.fetchJsonRaw<any>(`${baseUrl}/api/user/self/groups`, { headers });
        if (res?.success === false) {
          terminalError = this.resolveGroupFetchErrorMessage(res);
        }
        const parsed = dedupe(this.parseGroupKeys(res));
        if (parsed.length > 0) return parsed;
      } catch {}

      try {
        const res = await this.fetchJsonRaw<any>(`${baseUrl}/api/user_group_map`, { headers });
        if (res?.success === false) {
          terminalError = this.resolveGroupFetchErrorMessage(res);
        }
        const parsed = dedupe(this.parseGroupKeys(res));
        if (parsed.length > 0) return parsed;
      } catch {}
    }

    if (terminalError) {
      throw new Error(terminalError);
    }

    return ['default'];
  }

  async deleteApiToken(
    baseUrl: string,
    accessToken: string,
    tokenKey: string,
    platformUserId?: number,
  ): Promise<boolean> {
    const targetKey = this.normalizeTokenKeyForCompare(tokenKey);
    if (!targetKey) return false;
    const resolvedUserId = platformUserId || await this.discoverUserId(baseUrl, accessToken);

    const pickTokenId = (items: any[]): number | null => {
      for (const item of items) {
        const key = this.normalizeTokenKeyForCompare(item?.key);
        const id = Number.parseInt(String(item?.id), 10);
        if (key && key === targetKey && Number.isFinite(id) && id > 0) {
          return id;
        }
      }
      return null;
    };

    let tokenId: number | null = null;

    try {
      const list = await this.fetchJson<any>(`${baseUrl}/api/token/?p=0&size=100`, {
        headers: this.authHeaders(accessToken, resolvedUserId || undefined),
      });
      tokenId = pickTokenId(this.parseTokenItems(list));
      if (tokenId) {
        const res = await this.fetchJson<any>(`${baseUrl}/api/token/${tokenId}`, {
          method: 'DELETE',
          headers: this.authHeaders(accessToken, resolvedUserId || undefined),
        });
        return !!res?.success;
      }
    } catch {}

    const cookieUserId = resolvedUserId || await this.probeUserIdByCookie(baseUrl, accessToken);
    for (const cookie of this.buildCookieCandidates(accessToken)) {
      const headers: Record<string, string> = { Cookie: cookie };
      if (cookieUserId) headers['New-Api-User'] = String(cookieUserId);

      try {
        if (!tokenId) {
          const list = await this.fetchJsonRaw<any>(`${baseUrl}/api/token/?p=0&size=100`, { headers });
          tokenId = pickTokenId(this.parseTokenItems(list));
        }

        if (!tokenId) continue;

        const res = await this.fetchJsonRaw<any>(`${baseUrl}/api/token/${tokenId}`, {
          method: 'DELETE',
          headers,
        });
        if (res?.success) return true;
      } catch {}
    }

    // Upstream key already absent means local deletion is safe.
    if (!tokenId) return true;
    return false;
  }

  private async getApiTokensWithUser(baseUrl: string, accessToken: string, userId: number | null): Promise<ApiTokenInfo[]> {
    try {
      const res = await this.fetchJson<any>(`${baseUrl}/api/token/?p=0&size=100`, {
        headers: this.authHeaders(accessToken, userId || undefined),
      });
      const normalized = this.normalizeTokenItems(this.parseTokenItems(res));
      if (normalized.length > 0) return normalized;
      if (this.isTokenListResponse(res)) return [];
    } catch {}

    const cookieTokens = await this.getApiTokensByCookie(baseUrl, accessToken, userId);
    if (cookieTokens.length > 0) return cookieTokens;

    const alternateCookieUserId = await this.probeAlternateUserIdByCookie(baseUrl, accessToken, userId);
    if (alternateCookieUserId) {
      const fallbackTokens = await this.getApiTokensByCookie(baseUrl, accessToken, alternateCookieUserId);
      if (fallbackTokens.length > 0) return fallbackTokens;
    }

    return [];
  }
}
