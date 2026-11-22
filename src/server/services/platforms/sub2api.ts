import {
  ApiTokenInfo,
  BasePlatformAdapter,
  CheckinResult,
  BalanceInfo,
  CreateApiTokenOptions,
  LoginResult,
  SubscriptionPlanSummary,
  SubscriptionSummary,
  type SiteAnnouncement,
  UserInfo,
} from './base.js';
import { stripTrailingSlashes } from '../urlNormalization.js';
import {
  buildEndpointModelContextLengthScope,
  extractContextLengthsFromPayload,
  setModelContextLengths,
} from '../modelContextLengthCache.js';

function normalizeBaseUrl(baseUrl: string): string {
  return stripTrailingSlashes(baseUrl || '');
}

type Sub2ApiLoginSession = {
  accessToken: string;
  refreshToken: string;
  tokenExpiresAt?: number;
  platformUserId?: number;
  displayName?: string;
};

type Sub2ApiFailure = {
  status?: number;
  code?: string;
  message: string;
};

/** Split the `HTTP <status>: <body>` error thrown by `fetchJson` into fields. */
function parseSub2ApiVerificationFailure(error: unknown): Sub2ApiFailure {
  const rawMessage = error instanceof Error
    ? error.message
    : typeof error === 'string'
      ? error
      : '';
  const httpMatch = rawMessage.match(/^HTTP\s+(\d+):\s*([\s\S]*)$/i);
  const status = httpMatch ? Number.parseInt(httpMatch[1] || '', 10) : undefined;
  const bodyText = httpMatch?.[2]?.trim() || '';

  let payload: Record<string, unknown> | null = null;
  if (bodyText) {
    try {
      const parsed = JSON.parse(bodyText) as unknown;
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        payload = parsed as Record<string, unknown>;
      }
    } catch {
      // Plain-text body: the raw text is the message.
    }
  }

  const reason = typeof payload?.reason === 'string' && payload.reason.trim()
    ? payload.reason.trim()
    : typeof payload?.code === 'string' && payload.code.trim()
      ? payload.code.trim()
      : undefined;
  const message = typeof payload?.message === 'string'
    ? payload.message.trim()
    : bodyText && !payload
      ? bodyText.slice(0, 240)
      : '';

  return {
    ...(Number.isFinite(status) ? { status } : {}),
    ...(reason ? { code: reason } : {}),
    message: message || rawMessage.trim(),
  };
}

/**
 * Sub2API adapter.
 *
 * Sub2API uses JWT-based auth with endpoints under /api/v1/*.
 * Login is email + password (`POST /api/v1/auth/login`); the guard emails the
 * caller a refresh token so the session can be renewed without a browser.
 * Check-in uses the built-in `/api/v1/user/checkin` endpoint when the
 * deployment ships one.
 * Balance is derived from a USD amount returned by /api/v1/auth/me.
 */
export class Sub2ApiAdapter extends BasePlatformAdapter {
  readonly platformName = 'sub2api';

  private roundCurrency(value: number): number {
    return Math.round(value * 1_000_000) / 1_000_000;
  }

  private parsePositiveInteger(raw: unknown): number | undefined {
    if (typeof raw === 'number' && Number.isFinite(raw) && raw > 0) return Math.trunc(raw);
    if (typeof raw === 'string') {
      const parsed = Number.parseInt(raw.trim(), 10);
      if (!Number.isNaN(parsed) && parsed > 0) return parsed;
    }
    return undefined;
  }

  private parseNonNegativeInteger(raw: unknown): number | undefined {
    if (typeof raw === 'number' && Number.isFinite(raw) && raw >= 0) return Math.trunc(raw);
    if (typeof raw === 'string') {
      const parsed = Number.parseInt(raw.trim(), 10);
      if (!Number.isNaN(parsed) && parsed >= 0) return parsed;
    }
    return undefined;
  }

  private parseNonNegativeNumber(raw: unknown): number | undefined {
    if (typeof raw === 'number' && Number.isFinite(raw) && raw >= 0) {
      return this.roundCurrency(raw);
    }
    if (typeof raw === 'string') {
      const parsed = Number(raw.trim());
      if (Number.isFinite(parsed) && parsed >= 0) {
        return this.roundCurrency(parsed);
      }
    }
    return undefined;
  }

  private parseDateTime(raw: unknown): string | undefined {
    if (typeof raw === 'number' && Number.isFinite(raw) && raw > 0) {
      const ms = raw > 10_000_000_000 ? raw : raw * 1000;
      return new Date(ms).toISOString();
    }
    if (typeof raw !== 'string') return undefined;
    const trimmed = raw.trim();
    if (!trimmed) return undefined;

    const numeric = Number(trimmed);
    if (Number.isFinite(numeric) && numeric > 0) {
      const ms = numeric > 10_000_000_000 ? numeric : numeric * 1000;
      return new Date(ms).toISOString();
    }

    const parsed = Date.parse(trimmed);
    if (Number.isFinite(parsed)) return new Date(parsed).toISOString();
    return undefined;
  }

  private parseSubscriptionItem(raw: unknown): SubscriptionPlanSummary | null {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;

    const item = raw as Record<string, unknown>;
    const group = item.group && typeof item.group === 'object' && !Array.isArray(item.group)
      ? item.group as Record<string, unknown>
      : null;

    const normalized: SubscriptionPlanSummary = {};

    const id = this.parsePositiveInteger(item.id);
    if (id) normalized.id = id;

    const groupId = this.parsePositiveInteger(item.group_id ?? item.groupId ?? group?.id);
    if (groupId) normalized.groupId = groupId;

    const groupNameCandidates = [
      item.group_name,
      item.groupName,
      item.name,
      item.title,
      group?.name,
      group?.title,
    ];
    for (const candidate of groupNameCandidates) {
      if (typeof candidate !== 'string') continue;
      const trimmed = candidate.trim();
      if (!trimmed) continue;
      normalized.groupName = trimmed;
      break;
    }

    if (typeof item.status === 'string' && item.status.trim()) {
      normalized.status = item.status.trim();
    }

    const expiresAt = this.parseDateTime(
      item.expires_at
      ?? item.expiresAt
      ?? item.expired_at
      ?? item.expiredAt
      ?? item.end_at
      ?? item.endAt
      ?? item.end_time
      ?? item.endTime
      ?? item.current_period_end
      ?? item.currentPeriodEnd,
    );
    if (expiresAt) normalized.expiresAt = expiresAt;

    const dailyUsedUsd = this.parseNonNegativeNumber(item.daily_used_usd ?? item.dailyUsedUsd);
    if (dailyUsedUsd !== undefined) normalized.dailyUsedUsd = dailyUsedUsd;

    const dailyLimitUsd = this.parseNonNegativeNumber(item.daily_limit_usd ?? item.dailyLimitUsd);
    if (dailyLimitUsd !== undefined) normalized.dailyLimitUsd = dailyLimitUsd;

    const weeklyUsedUsd = this.parseNonNegativeNumber(item.weekly_used_usd ?? item.weeklyUsedUsd);
    if (weeklyUsedUsd !== undefined) normalized.weeklyUsedUsd = weeklyUsedUsd;

    const weeklyLimitUsd = this.parseNonNegativeNumber(item.weekly_limit_usd ?? item.weeklyLimitUsd);
    if (weeklyLimitUsd !== undefined) normalized.weeklyLimitUsd = weeklyLimitUsd;

    const monthlyUsedUsd = this.parseNonNegativeNumber(
      item.monthly_used_usd
      ?? item.monthlyUsedUsd
      ?? item.used_usd
      ?? item.usedUsd
      ?? item.total_used_usd
      ?? item.totalUsedUsd,
    );
    if (monthlyUsedUsd !== undefined) normalized.monthlyUsedUsd = monthlyUsedUsd;

    const monthlyLimitUsd = this.parseNonNegativeNumber(
      item.monthly_limit_usd
      ?? item.monthlyLimitUsd
      ?? item.limit_usd
      ?? item.limitUsd
      ?? item.total_limit_usd
      ?? item.totalLimitUsd,
    );
    if (monthlyLimitUsd !== undefined) normalized.monthlyLimitUsd = monthlyLimitUsd;

    return Object.keys(normalized).length > 0 ? normalized : null;
  }

  private parseSubscriptionItems(raw: unknown): SubscriptionPlanSummary[] {
    const rawItems = (() => {
      if (Array.isArray(raw)) return raw;
      if (raw && typeof raw === 'object') {
        const body = raw as Record<string, unknown>;
        if (Array.isArray(body.subscriptions)) return body.subscriptions;
        if (Array.isArray(body.items)) return body.items;
        if (Array.isArray(body.list)) return body.list;
        if (Array.isArray(body.data)) return body.data;
      }
      return [];
    })();

    return rawItems
      .map((item) => this.parseSubscriptionItem(item))
      .filter((item): item is SubscriptionPlanSummary => !!item);
  }

  private buildSubscriptionSummary(payload: unknown): SubscriptionSummary {
    const body = payload && typeof payload === 'object' && !Array.isArray(payload)
      ? payload as Record<string, unknown>
      : {};
    const subscriptions = this.parseSubscriptionItems(payload);
    const activeCount = this.parseNonNegativeInteger(body.active_count ?? body.activeCount);
    const totalUsedUsd = this.parseNonNegativeNumber(body.total_used_usd ?? body.totalUsedUsd);
    const inferredUsedUsd = subscriptions.reduce((sum, item) => sum + (item.monthlyUsedUsd || 0), 0);

    return {
      activeCount: activeCount ?? subscriptions.length,
      totalUsedUsd: totalUsedUsd ?? this.roundCurrency(inferredUsedUsd),
      subscriptions,
    };
  }

  private async fetchSubscriptionSummary(baseUrl: string, accessToken: string): Promise<SubscriptionSummary | undefined> {
    const headers = this.buildAuthHeader(accessToken);
    const summaryEndpoint = '/api/v1/subscriptions/summary';

    try {
      const res = await this.fetchJson<any>(`${baseUrl}${summaryEndpoint}`, { headers });
      const data = this.parseSub2ApiEnvelope<any>(res, summaryEndpoint);
      return this.buildSubscriptionSummary(data);
    } catch {}

    const fallbackEndpoints = ['/api/v1/subscriptions/active'];
    for (const endpoint of fallbackEndpoints) {
      try {
        const res = await this.fetchJson<any>(`${baseUrl}${endpoint}`, { headers });
        const data = this.parseSub2ApiEnvelope<any>(res, endpoint);
        return this.buildSubscriptionSummary(data);
      } catch {}
    }

    return undefined;
  }

  private stripBearerPrefix(value?: string | null): string {
    const trimmed = (value || '').trim();
    if (!trimmed) return '';
    return trimmed.replace(/^bearer\s+/i, '').trim();
  }

  private normalizeTokenKeyForCompare(value?: string | null): string {
    return this.stripBearerPrefix(value);
  }

  private buildAuthHeader(accessToken: string): Record<string, string> {
    const normalized = this.stripBearerPrefix(accessToken);
    return { Authorization: `Bearer ${normalized}` };
  }

  private parseTokenEnabled(status: unknown): boolean {
    if (typeof status === 'boolean') return status;
    if (typeof status === 'number') return status === 1;
    if (typeof status !== 'string') return true;
    const normalized = status.trim().toLowerCase();
    if (!normalized) return true;
    if (['inactive', 'disabled', 'false', '0', 'off'].includes(normalized)) return false;
    if (['active', 'enabled', 'true', '1', 'on'].includes(normalized)) return true;
    return true;
  }

  private parseTokenItems(payload: any): Array<{ id: number; key: string; name: string; enabled: boolean; tokenGroup: string | null }> {
    const source = payload?.data ?? payload;
    const rawItems = (() => {
      if (Array.isArray(source)) return source;
      if (Array.isArray(source?.items)) return source.items;
      if (Array.isArray(source?.list)) return source.list;
      if (Array.isArray(source?.data)) return source.data;
      return [];
    })();

    const items: Array<{ id: number; key: string; name: string; enabled: boolean; tokenGroup: string | null }> = [];
    for (const item of rawItems) {
      const key = typeof item?.key === 'string' ? item.key.trim() : '';
      if (!key) continue;
      const id = Number.parseInt(String(item?.id), 10);
      if (!Number.isFinite(id) || id <= 0) continue;
      const name = typeof item?.name === 'string' && item.name.trim()
        ? item.name.trim()
        : `token-${id}`;
      const tokenGroup = (() => {
        const fromNumeric = Number.parseInt(String(item?.group_id ?? item?.groupId ?? ''), 10);
        if (Number.isFinite(fromNumeric) && fromNumeric > 0) return String(fromNumeric);
        const fromText = typeof item?.group_name === 'string'
          ? item.group_name.trim()
          : (typeof item?.group === 'string' ? item.group.trim() : '');
        return fromText || null;
      })();
      items.push({
        id,
        key,
        name,
        enabled: this.parseTokenEnabled(item?.status),
        tokenGroup,
      });
    }
    return items;
  }

  private parseGroupItems(payload: any): string[] {
    const source = payload?.data ?? payload;
    const rawItems = (() => {
      if (Array.isArray(source)) return source;
      if (Array.isArray(source?.items)) return source.items;
      if (Array.isArray(source?.list)) return source.list;
      if (Array.isArray(source?.groups)) return source.groups;
      if (Array.isArray(source?.data)) return source.data;
      return [];
    })();

    const groups: string[] = [];
    for (const item of rawItems) {
      if (item == null) continue;
      if (typeof item === 'number' && Number.isFinite(item) && item > 0) {
        groups.push(String(Math.trunc(item)));
        continue;
      }
      if (typeof item === 'string') {
        const normalized = item.trim();
        if (normalized) groups.push(normalized);
        continue;
      }
      if (typeof item !== 'object') continue;

      const numericCandidates = [
        (item as any).group_id,
        (item as any).groupId,
        (item as any).id,
        (item as any).value,
      ];
      let picked = '';
      for (const candidate of numericCandidates) {
        const parsed = Number.parseInt(String(candidate), 10);
        if (Number.isFinite(parsed) && parsed > 0) {
          picked = String(parsed);
          break;
        }
      }
      if (picked) {
        groups.push(picked);
        continue;
      }

      const textCandidates = [
        (item as any).name,
        (item as any).group_name,
        (item as any).groupName,
        (item as any).title,
        (item as any).label,
        (item as any).code,
      ];
      for (const candidate of textCandidates) {
        if (typeof candidate !== 'string') continue;
        const normalized = candidate.trim();
        if (!normalized) continue;
        groups.push(normalized);
        break;
      }
    }

    return Array.from(new Set(groups));
  }

  private async listGroups(baseUrl: string, accessToken: string): Promise<string[]> {
    const endpoints = [
      '/api/v1/groups/available',
      '/api/v1/groups?page=1&page_size=100',
      '/api/v1/groups',
      '/api/v1/group?page=1&page_size=100',
      '/api/v1/group',
    ];

    const headers = this.buildAuthHeader(accessToken);
    for (const endpoint of endpoints) {
      try {
        const res = await this.fetchJson<any>(`${baseUrl}${endpoint}`, {
          headers,
        });
        const parsed = (() => {
          try {
            return this.parseSub2ApiEnvelope<any>(res, endpoint);
          } catch {
            return res;
          }
        })();
        const groups = this.parseGroupItems(parsed);
        if (groups.length > 0) return groups;
      } catch {}
    }

    return [];
  }

  private parseGroupIdsFromTokenPayload(payload: any): string[] {
    const source = payload?.data ?? payload;
    const rawItems = (() => {
      if (Array.isArray(source)) return source;
      if (Array.isArray(source?.items)) return source.items;
      if (Array.isArray(source?.list)) return source.list;
      if (Array.isArray(source?.data)) return source.data;
      return [];
    })();

    const groups: string[] = [];
    for (const item of rawItems) {
      if (!item || typeof item !== 'object') continue;
      const groupId = Number.parseInt(String((item as any).group_id ?? (item as any).groupId ?? ''), 10);
      if (!Number.isFinite(groupId) || groupId <= 0) continue;
      groups.push(String(groupId));
    }
    return Array.from(new Set(groups));
  }

  private async inferGroupsFromKeys(baseUrl: string, accessToken: string): Promise<string[]> {
    const endpoints = [
      '/api/v1/keys?page=1&page_size=100',
      '/api/v1/api-keys?page=1&page_size=100',
    ];

    const headers = this.buildAuthHeader(accessToken);
    for (const endpoint of endpoints) {
      try {
        const res = await this.fetchJson<any>(`${baseUrl}${endpoint}`, {
          headers,
        });
        const parsed = (() => {
          try {
            return this.parseSub2ApiEnvelope<any>(res, endpoint);
          } catch {
            return res;
          }
        })();
        const groups = this.parseGroupIdsFromTokenPayload(parsed);
        if (groups.length > 0) return groups;
      } catch {}
    }

    return [];
  }

  private extractModelIds(payload: any): string[] {
    const source = payload?.data ?? payload;
    const rawModels = (() => {
      if (Array.isArray(source)) return source;
      if (Array.isArray(source?.items)) return source.items;
      if (Array.isArray(source?.models)) return source.models;
      return [];
    })();

    const models = rawModels
      .map((item: any) => (typeof item === 'string' ? item : item?.id ?? item?.name))
      .map((value: unknown) => String(value || '').trim())
      .map((value: string) => value.replace(/^models\//i, ''))
      .filter(Boolean);
    return Array.from(new Set(models));
  }

  private resolveModelEndpoints(baseUrl: string): string[] {
    const normalizedBase = normalizeBaseUrl(baseUrl);
    if (!normalizedBase) return [];
    if (/\/models$/i.test(normalizedBase)) return [normalizedBase];
    if (/\/(?:antigravity\/)?v\d+(?:\.\d+)?(?:beta)?$/i.test(normalizedBase)) {
      return [`${normalizedBase}/models`];
    }
    if (/\/antigravity$/i.test(normalizedBase)) {
      return [
        `${normalizedBase}/v1/models`,
        `${normalizedBase}/v1beta/models`,
      ];
    }
    return [
      `${normalizedBase}/v1/models`,
      `${normalizedBase}/api/v1/models`,
      `${normalizedBase}/v1beta/models`,
      `${normalizedBase}/antigravity/v1beta/models`,
    ];
  }

  private resolveManagementBaseUrl(baseUrl: string): string {
    let normalizedBase = normalizeBaseUrl(baseUrl);
    if (!normalizedBase) return normalizedBase;

    const suffixes = [
      '/models',
      '/antigravity',
      '/antigravity/v1beta',
      '/antigravity/v1',
      '/api/v1',
      '/v1beta',
      '/v1',
    ];

    let changed = true;
    while (changed) {
      changed = false;
      for (const suffix of suffixes) {
        if (!normalizedBase.toLowerCase().endsWith(suffix)) continue;
        const trimmed = normalizeBaseUrl(normalizedBase.slice(0, -suffix.length));
        if (!trimmed || trimmed === normalizedBase) continue;
        normalizedBase = trimmed;
        changed = true;
        break;
      }
    }

    return normalizedBase;
  }

  private async listApiKeys(baseUrl: string, accessToken: string): Promise<Array<{ id: number; key: string; name: string; enabled: boolean; tokenGroup: string | null }>> {
    const endpoints = [
      '/api/v1/keys?page=1&page_size=100',
      '/api/v1/api-keys?page=1&page_size=100',
    ];

    const headers = this.buildAuthHeader(accessToken);
    for (const endpoint of endpoints) {
      try {
        const res = await this.fetchJson<any>(`${baseUrl}${endpoint}`, {
          headers,
        });
        const data = this.parseSub2ApiEnvelope<any>(res, endpoint);
        const items = this.parseTokenItems(data);
        if (items.length > 0) return items;
      } catch {}
    }

    return [];
  }

  private async fetchModelsByToken(baseUrl: string, token: string, contextSourceScope?: string): Promise<string[]> {
    const authToken = this.normalizeTokenKeyForCompare(token);
    if (!authToken) return [];

    for (const url of this.resolveModelEndpoints(baseUrl)) {
      try {
        const res = await this.fetchJson<any>(url, {
          headers: { Authorization: `Bearer ${authToken}` },
        });
        setModelContextLengths(
          extractContextLengthsFromPayload(res),
          contextSourceScope || buildEndpointModelContextLengthScope(baseUrl),
        );
        const models = this.extractModelIds(res);
        if (models.length > 0) return models;
      } catch {}
    }

    return [];
  }

  private resolveExpiresInDays(expiredTime?: number): number | undefined {
    if (!Number.isFinite(expiredTime)) return undefined;
    const raw = Math.trunc(expiredTime as number);
    if (raw <= 0) return undefined;
    const expiresAtMs = raw > 10_000_000_000 ? raw : raw * 1000;
    const deltaMs = expiresAtMs - Date.now();
    const days = Math.max(1, Math.ceil(deltaMs / (24 * 60 * 60 * 1000)));
    return Number.isFinite(days) ? Math.min(days, 3650) : undefined;
  }

  async detect(url: string): Promise<boolean> {
    const normalized = (url || '').toLowerCase();
    if (normalized.includes('sub2api')) return true;

    const base = normalizeBaseUrl(url);
    const { fetch } = await import('undici');
    const probeEndpoint = async (path: string) => {
      try {
        return await fetch(`${base}${path}`, {
          method: 'GET',
          signal: AbortSignal.timeout(5000),
        });
      } catch {
        return null;
      }
    };

    const matchSub2ApiErrorEnvelope = async (res: {
      headers: { get(name: string): string | null };
      json: () => Promise<unknown>;
    } | null): Promise<boolean> => {
      if (!res) return false;
      const contentType = res.headers.get('content-type') || '';
      if (!contentType.toLowerCase().includes('application/json')) return false;
      const body = await res.json().catch(() => null) as Record<string, unknown> | null;
      if (!body || typeof body !== 'object') return false;
      const rawCode = body.code;
      const code = typeof rawCode === 'string' ? rawCode.trim().toUpperCase() : '';
      const message = typeof body.message === 'string' ? body.message.trim().toLowerCase() : '';

      if (code === 'UNAUTHORIZED' || code === 'API_KEY_REQUIRED') return true;
      if (
        message.includes('authorization header is required')
        || message.includes('api key is required')
      ) {
        return true;
      }

      // Some Sub2API variants return numeric success envelope for authorized calls.
      if (typeof rawCode === 'number' && rawCode === 0) {
        return Object.prototype.hasOwnProperty.call(body, 'data');
      }

      return false;
    };

    const authProbe = await probeEndpoint('/api/v1/auth/me');
    if (await matchSub2ApiErrorEnvelope(authProbe)) return true;

    const modelsProbe = await probeEndpoint('/v1/models');
    if (await matchSub2ApiErrorEnvelope(modelsProbe)) return true;

    // Last fallback: many Sub2API UIs expose an identifying title on root.
    const rootProbe = await probeEndpoint('/');
    if (!rootProbe) return false;
    const rootType = rootProbe.headers.get('content-type') || '';
    if (!rootType.toLowerCase().includes('text/html')) return false;
    const rootText = await rootProbe.text().catch(() => '');
    return /<title>\s*sub2api\b/i.test(rootText);
  }

  /**
   * Parse the Sub2API { code, message, data } envelope.
   * code === 0 means success; anything else is an error.
   */
  private parseSub2ApiEnvelope<T>(body: any, endpoint: string): T {
    if (!body || typeof body !== 'object') {
      throw new Error(`Invalid response from ${endpoint}`);
    }
    if (typeof body.code !== 'number') {
      throw new Error(`Invalid response format from ${endpoint}`);
    }
    if (body.code !== 0) {
      const message = typeof body.message === 'string' && body.message.trim()
        ? body.message.trim()
        : `Error code ${body.code} from ${endpoint}`;
      throw new Error(message);
    }
    if (body.data === undefined) {
      throw new Error(`Missing data in response from ${endpoint}`);
    }
    return body.data as T;
  }

  /**
   * Extract display name: prefer username, fall back to email local part.
   */
  private getDisplayName(username?: string, email?: string): string {
    const name = (username || '').trim();
    if (name) return name;
    const mail = (email || '').trim();
    if (!mail) return '';
    const atIndex = mail.indexOf('@');
    return atIndex > 0 ? mail.slice(0, atIndex) : mail;
  }

  /**
   * Fetch user data from /api/v1/auth/me.
   */
  private async fetchAuthMe(baseUrl: string, accessToken: string): Promise<{
    id: number;
    username: string;
    email: string;
    balance: number;
  }> {
    const endpoint = '/api/v1/auth/me';
    const res = await this.fetchJson<any>(`${baseUrl}${endpoint}`, {
      headers: this.buildAuthHeader(accessToken),
    });
    const data = this.parseSub2ApiEnvelope<any>(res, endpoint);

    const id = typeof data.id === 'number' ? data.id
      : typeof data.id === 'string' ? Number.parseInt(data.id, 10)
      : NaN;
    if (!Number.isFinite(id) || id <= 0) {
      throw new Error(`Invalid user ID in response from ${endpoint}`);
    }

    const balance = typeof data.balance === 'number' ? data.balance
      : typeof data.balance === 'string' ? Number.parseFloat(data.balance)
      : 0;

    return {
      id,
      username: typeof data.username === 'string' ? data.username : '',
      email: typeof data.email === 'string' ? data.email : '',
      balance: Number.isFinite(balance) ? balance : 0,
    };
  }

  /**
   * Convert USD balance to internal quota unit.
   * Uses the same conversion factor as all-api-hub (500000 per USD).
   */
  private usdToQuota(balanceUsd: number): number {
    return Math.round(Math.max(0, balanceUsd) * 500000);
  }

  // --- Login: email + password (JWT session) ---
  //
  // Sub2API exposes `POST /api/v1/auth/login` (JSON: Email + Password) and
  // answers `{ code: 0, data: { access_token, refresh_token, expires_in, user } }`.
  // Login used to be hard-coded as unsupported, which forced users to log in
  // through a browser and copy the session by hand; the refresh token issued
  // here lets the caller renew the session automatically.
  override async login(
    baseUrl: string,
    username: string,
    password: string,
  ): Promise<LoginResult> {
    const identifier = (username || '').trim();
    if (!identifier || !password) {
      return { success: false, message: '请输入 Sub2API 站点的邮箱和密码' };
    }

    const normalizedBase = normalizeBaseUrl(baseUrl);
    const endpoint = '/api/v1/auth/login';

    let session: Sub2ApiLoginSession | null = null;
    let envelopeMessage = '';
    try {
      const payload = await this.fetchJson<unknown>(`${normalizedBase}${endpoint}`, {
        method: 'POST',
        body: JSON.stringify({ email: identifier, password }),
      });
      session = this.parseSub2ApiLoginSession(payload);
      if (!session && this.isSub2ApiTotpChallenge(payload)) {
        return {
          success: false,
          message: '该账号启用了两步验证 (TOTP)，登录需要动态验证码；请先关闭 2FA 或改用 Session 方式绑定',
        };
      }
      if (!session) {
        envelopeMessage = this.readEnvelopeString(payload, ['message', 'error', 'reason']);
      }
    } catch (error) {
      const failure = parseSub2ApiVerificationFailure(error);
      const rawMessage = failure.message || (error instanceof Error ? error.message : '');
      return {
        success: false,
        message: this.describeSub2ApiLoginFailure(rawMessage, failure.code),
      };
    }

    if (!session) {
      return { success: false, message: this.describeSub2ApiLoginFailure(envelopeMessage) };
    }

    // The login payload already carries `user`; only fill the gaps from
    // /api/v1/auth/me, and never fail the login when that probe fails.
    let platformUserId = session.platformUserId;
    let displayName = session.displayName || '';
    if (!platformUserId || !displayName) {
      try {
        const me = await this.fetchAuthMe(normalizedBase, session.accessToken);
        platformUserId = platformUserId ?? me.id;
        displayName = displayName || this.getDisplayName(me.username, me.email);
      } catch {
        // Best-effort enrichment only.
      }
    }

    return {
      success: true,
      accessToken: session.accessToken,
      refreshToken: session.refreshToken,
      ...(session.tokenExpiresAt ? { tokenExpiresAt: session.tokenExpiresAt } : {}),
      username: displayName || identifier,
      ...(platformUserId ? { platformUserId } : {}),
    };
  }

  private readEnvelopeString(payload: unknown, keys: string[]): string {
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return '';
    const envelope = payload as Record<string, unknown>;
    for (const key of keys) {
      const value = envelope[key];
      if (typeof value === 'string' && value.trim()) return value.trim();
    }
    return '';
  }

  private readEnvelopeNumber(payload: Record<string, unknown>, keys: string[]): number {
    for (const key of keys) {
      const value = payload[key];
      if (typeof value === 'number' && Number.isFinite(value)) return value;
      if (typeof value === 'string' && value.trim()) {
        const parsed = Number(value.trim());
        if (Number.isFinite(parsed)) return parsed;
      }
    }
    return Number.NaN;
  }

  /**
   * Parse `{ code: 0, data: { access_token, refresh_token, expires_in } }`.
   *
   * `expires_in` is the documented shape; when a deployment omits it we fall
   * back to the JWT `exp` claim so callers still get a renewal deadline.
   */
  private parseSub2ApiLoginSession(payload: unknown): Sub2ApiLoginSession | null {
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return null;
    const envelope = payload as Record<string, unknown>;
    const code = typeof envelope.code === 'number'
      ? envelope.code
      : typeof envelope.code === 'string'
        ? Number.parseInt(envelope.code.trim(), 10)
        : Number.NaN;
    if (!Number.isFinite(code) || code !== 0) return null;

    const data = envelope.data;
    if (!data || typeof data !== 'object' || Array.isArray(data)) return null;
    const body = data as Record<string, unknown>;

    const accessToken = this.readEnvelopeString(body, ['access_token', 'accessToken', 'token']);
    const refreshToken = this.readEnvelopeString(body, ['refresh_token', 'refreshToken']);
    if (!accessToken || !refreshToken) return null;

    const expiresInSeconds = this.readEnvelopeNumber(body, ['expires_in', 'expiresIn']);
    const tokenExpiresAt = Number.isFinite(expiresInSeconds) && expiresInSeconds > 0
      ? Date.now() + Math.trunc(expiresInSeconds) * 1000
      : this.resolveJwtExpiryMs(accessToken);

    // AuthResponse carries `user`, which saves an /api/v1/auth/me round trip.
    const user = body.user && typeof body.user === 'object' && !Array.isArray(body.user)
      ? body.user as Record<string, unknown>
      : null;
    const platformUserId = user ? this.parsePositiveInteger(user.id) : undefined;
    const displayName = user
      ? this.getDisplayName(
        typeof user.username === 'string' ? user.username : '',
        typeof user.email === 'string' ? user.email : '',
      )
      : '';

    return {
      accessToken,
      refreshToken,
      ...(tokenExpiresAt ? { tokenExpiresAt } : {}),
      ...(platformUserId ? { platformUserId } : {}),
      ...(displayName ? { displayName } : {}),
    };
  }

  private isSub2ApiTotpChallenge(payload: unknown): boolean {
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return false;
    const data = (payload as Record<string, unknown>).data;
    if (!data || typeof data !== 'object' || Array.isArray(data)) return false;
    return (data as Record<string, unknown>).requires_2fa === true;
  }

  private resolveJwtExpiryMs(token: string): number | undefined {
    const parts = token.split('.');
    if (parts.length < 3 || !parts[1]) return undefined;
    try {
      const claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')) as unknown;
      if (!claims || typeof claims !== 'object' || Array.isArray(claims)) return undefined;
      const exp = (claims as Record<string, unknown>).exp;
      const expSeconds = typeof exp === 'number'
        ? exp
        : typeof exp === 'string'
          ? Number.parseInt(exp.trim(), 10)
          : Number.NaN;
      if (!Number.isFinite(expSeconds) || expSeconds <= 0) return undefined;
      return Math.trunc(expSeconds) * 1000;
    } catch {
      return undefined;
    }
  }

  private describeSub2ApiLoginFailure(message: string, reason?: string): string {
    const text = (message || '').trim();
    const reasonText = (reason || '').trim();
    const suffix = reasonText ? ` (${reasonText})` : '';
    const lowered = text.toLowerCase();
    if (/invalid email or password|invalid credentials|incorrect (email|password|username)/.test(lowered)) {
      return `Sub2API 登录失败：邮箱或密码不正确${suffix}`;
    }
    if (/turnstile|captcha|challenge|risk/i.test(lowered)) {
      return `Sub2API 登录被站点验证码/风控拦截，请在站点侧完成验证后重试${suffix}`;
    }
    if (text) return `Sub2API 登录失败：${text}`;
    return 'Sub2API 登录失败：站点未返回可用会话';
  }

  // --- User Info ---
  override async getUserInfo(baseUrl: string, accessToken: string): Promise<UserInfo | null> {
    try {
      const user = await this.fetchAuthMe(baseUrl, accessToken);
      return {
        username: this.getDisplayName(user.username, user.email),
        email: user.email || undefined,
      };
    } catch {
      return null;
    }
  }

  // --- Check-in: built-in daily check-in ---
  //
  // Newer Sub2API deployments ship a built-in check-in: `GET
  // /api/v1/user/checkin` reports the current day, `POST` with `{ day }`
  // claims it. Deployments without it answer 404 (or fall back to the SPA
  // shell), which keeps the historical "not supported" answer so the caller
  // marks the account as skipped instead of failed.
  async checkin(baseUrl: string, accessToken: string): Promise<CheckinResult> {
    const normalizedBase = normalizeBaseUrl(baseUrl);

    const nativeResult = await this.tryNativeCheckin(normalizedBase, accessToken);
    if (nativeResult) return nativeResult;

    return { success: false, message: 'Check-in is not supported by Sub2API' };
  }

  /**
   * Claim the built-in daily check-in.
   *
   * Returns `null` when the deployment has no such endpoint (404/405/501, or
   * an unmatched path served as the SPA's index.html), so the caller can fall
   * back to the historical "unsupported" answer.
   */
  private async tryNativeCheckin(baseUrl: string, accessToken: string): Promise<CheckinResult | null> {
    const endpoint = '/api/v1/user/checkin';

    let status: any;
    try {
      const res = await this.fetchJson<any>(`${baseUrl}${endpoint}`, {
        headers: { ...this.buildAuthHeader(accessToken), Accept: 'application/json' },
      });
      status = this.parseSub2ApiEnvelope<any>(res, endpoint);
    } catch (error) {
      if (this.isMissingNativeCheckinEndpoint(error)) return null;
      return { success: false, message: this.describeCheckinError(error) };
    }

    const day = typeof status?.day === 'string' ? status.day.trim() : '';
    const reason = typeof status?.reason === 'string' ? status.reason.trim() : '';

    // Already claimed: report the amount instead of posting again.
    if (reason === 'claimed' || reason === 'legacy_claimed') {
      const reward = this.formatNativeCheckinReward(status, day);
      return {
        success: true,
        message: `今日已签到${reward ? `，奖励 ${reward}` : ''}`,
        ...(reward ? { reward } : {}),
      };
    }

    if (reason && reason !== 'available') {
      return { success: false, message: this.describeNativeCheckinReason(reason) };
    }

    if (!day) {
      return { success: false, message: '站点未返回可签到的日期' };
    }

    let payload: any;
    try {
      const res = await this.fetchJson<any>(`${baseUrl}${endpoint}`, {
        method: 'POST',
        headers: {
          ...this.buildAuthHeader(accessToken),
          Accept: 'application/json',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ day }),
      });
      payload = this.parseSub2ApiEnvelope<any>(res, endpoint);
    } catch (error) {
      return { success: false, message: this.describeCheckinError(error) };
    }

    // A successful claim usually answers reason=claimed; only a different,
    // explicit reason means the site rejected it.
    const blockedReason = typeof payload?.reason === 'string' ? payload.reason.trim() : '';
    if (blockedReason
      && blockedReason !== 'claimed'
      && blockedReason !== 'legacy_claimed'
      && blockedReason !== 'available') {
      return { success: false, message: this.describeNativeCheckinReason(blockedReason) };
    }

    const fallbackUnit = this.readNativeCheckinUnit(status);
    const reward = this.formatNativeCheckinReward(payload, day, fallbackUnit);
    return {
      success: true,
      message: `签到成功${reward ? `，奖励 ${reward}` : ''}`,
      ...(reward ? { reward } : {}),
    };
  }

  /** The built-in endpoint is missing: an old deployment 404s, some serve the SPA shell. */
  private isMissingNativeCheckinEndpoint(error: unknown): boolean {
    const message = (error instanceof Error ? error.message : String(error ?? '')).toLowerCase();
    if (!message) return false;
    if (message.includes('http 404') || message.includes('http 405') || message.includes('http 501')) {
      return true;
    }
    return message.includes('invalid response format from /api/v1/user/checkin')
      || message.includes('invalid response from /api/v1/user/checkin');
  }

  /** Reward unit reported by the status payload (usually USD). */
  private readNativeCheckinUnit(payload: any, fallback = 'USD'): string {
    const unit = typeof payload?.unit === 'string' ? payload.unit.trim() : '';
    return unit || fallback;
  }

  /** Render `<amount> <unit>`; undefined when the amount cannot be read. */
  private formatNativeCheckinReward(payload: any, day: string, fallbackUnit = 'USD'): string | undefined {
    const amount = this.readNativeCheckinAmount(payload, day);
    if (amount === undefined) return undefined;
    return `${amount} ${this.readNativeCheckinUnit(payload, fallbackUnit)}`;
  }

  /** Prefer `receipt.amount`, then the matching `history` entry for `day`. */
  private readNativeCheckinAmount(payload: any, day: string): number | undefined {
    const receiptDay = typeof payload?.receipt?.day === 'string' ? payload.receipt.day : '';
    const receiptAmount = this.parseNonNegativeNumber(payload?.receipt?.amount);
    if (receiptAmount !== undefined && (!receiptDay || !day || receiptDay === day)) {
      return receiptAmount;
    }

    const history = Array.isArray(payload?.history) ? payload.history : [];
    for (const entry of history) {
      if (!entry || typeof entry.day !== 'string') continue;
      if (day && entry.day !== day) continue;
      const amount = this.parseNonNegativeNumber(entry.amount);
      if (amount !== undefined) return amount;
    }
    return undefined;
  }

  /** Turn the built-in check-in `reason` into a readable message. */
  private describeNativeCheckinReason(reason: string): string {
    switch (reason) {
      case 'account_on_hold':
        return '账号处于冻结状态，站点未开放签到';
      case 'account_ineligible':
        return '账号不满足该站点的签到条件';
      case 'migration_pending':
        return '站点签到数据迁移中，稍后再试';
      default:
        return `站点返回不可签到状态（${reason}）`;
    }
  }

  private extractCheckinMessage(payload: any): string {
    for (const key of ['message', 'error', 'msg']) {
      const value = payload?.[key];
      if (typeof value === 'string' && value.trim()) {
        return value.trim();
      }
    }
    return '';
  }

  /** Restore the readable message out of `HTTP <status>: <body>`. */
  private describeCheckinError(error: unknown): string {
    const raw = error instanceof Error ? error.message : String(error ?? '');
    const match = raw.match(/^HTTP\s+(\d+):\s*([\s\S]*)$/i);
    if (!match) return raw.trim() || 'check-in failed';

    const body = (match[2] || '').trim();
    if (!body) return `HTTP ${match[1]}`;
    try {
      const message = this.extractCheckinMessage(JSON.parse(body));
      if (message) return message;
    } catch {
      // Non-JSON body: fall through to the truncated text.
    }
    return `HTTP ${match[1]}: ${body.slice(0, 240)}`;
  }

  // --- Balance ---
  async getBalance(baseUrl: string, accessToken: string): Promise<BalanceInfo> {
    const normalizedBase = normalizeBaseUrl(baseUrl);
    const [user, subscriptionSummary] = await Promise.all([
      this.fetchAuthMe(normalizedBase, accessToken),
      this.fetchSubscriptionSummary(normalizedBase, accessToken),
    ]);
    const quotaValue = this.usdToQuota(user.balance);
    // Sub2API only provides current balance, no usage breakdown
    return {
      balance: quotaValue / 500000,
      used: 0,
      quota: quotaValue / 500000,
      subscriptionSummary,
    };
  }

  // --- Models: Standard OpenAI-compatible endpoint ---
  async getModels(
    baseUrl: string,
    apiToken: string,
    _platformUserId?: number,
    contextSourceScope?: string,
  ): Promise<string[]> {
    const normalizedBase = normalizeBaseUrl(baseUrl);
    const managementBase = this.resolveManagementBaseUrl(normalizedBase);
    const directModels = await this.fetchModelsByToken(normalizedBase, apiToken, contextSourceScope);
    if (directModels.length > 0) return directModels;

    // Session JWT cannot access /v1/models directly; discover a user key first.
    const discoveredApiToken = await this.getApiToken(managementBase, apiToken);
    if (!discoveredApiToken) return [];
    if (this.normalizeTokenKeyForCompare(discoveredApiToken) === this.normalizeTokenKeyForCompare(apiToken)) {
      return [];
    }
    return this.fetchModelsByToken(normalizedBase, discoveredApiToken, contextSourceScope);
  }

  override async getSiteAnnouncements(baseUrl: string, accessToken: string): Promise<SiteAnnouncement[]> {
    try {
      const endpoint = '/api/v1/announcements?page=1&page_size=100';
      const res = await this.fetchJson<any>(`${normalizeBaseUrl(baseUrl)}${endpoint}`, {
        headers: this.buildAuthHeader(accessToken),
      });
      const data = this.parseSub2ApiEnvelope<any>(res, endpoint);
      const rawItems = Array.isArray(data)
        ? data
        : (Array.isArray(data?.items) ? data.items : []);
      const rows: SiteAnnouncement[] = [];
      for (const item of rawItems) {
        const id = Number.parseInt(String(item?.id), 10);
        if (!Number.isFinite(id) || id <= 0) continue;
        const title = typeof item?.title === 'string' ? item.title.trim() : '';
        const content = typeof item?.content === 'string' ? item.content.trim() : '';
        if (!title && !content) continue;
        rows.push({
          sourceKey: `announcement:${id}`,
          title: title || `Announcement ${id}`,
          content: content || title,
          level: 'info',
          startsAt: typeof item?.starts_at === 'string' ? item.starts_at : undefined,
          endsAt: typeof item?.ends_at === 'string' ? item.ends_at : undefined,
          upstreamCreatedAt: typeof item?.created_at === 'string' ? item.created_at : undefined,
          upstreamUpdatedAt: typeof item?.updated_at === 'string' ? item.updated_at : undefined,
          rawPayload: item,
        });
      }
      return rows;
    } catch {
      return [];
    }
  }

  override async getApiTokens(baseUrl: string, accessToken: string): Promise<ApiTokenInfo[]> {
    try {
      const keys = await this.listApiKeys(normalizeBaseUrl(baseUrl), accessToken);
      return keys.map((item) => {
        const tokenInfo: ApiTokenInfo = {
          name: item.name,
          key: item.key,
          enabled: item.enabled,
        };
        if (item.tokenGroup) tokenInfo.tokenGroup = item.tokenGroup;
        return tokenInfo;
      });
    } catch {
      return [];
    }
  }

  override async getApiToken(baseUrl: string, accessToken: string): Promise<string | null> {
    const tokens = await this.getApiTokens(baseUrl, accessToken);
    return tokens.find((token) => token.enabled !== false)?.key || tokens[0]?.key || null;
  }

  override async getUserGroups(baseUrl: string, accessToken: string): Promise<string[]> {
    const normalizedBase = normalizeBaseUrl(baseUrl);
    const directGroups = await this.listGroups(normalizedBase, accessToken);
    if (directGroups.length > 0) return directGroups;

    const inferredFromKeys = await this.inferGroupsFromKeys(normalizedBase, accessToken);
    if (inferredFromKeys.length > 0) return inferredFromKeys;

    return ['default'];
  }

  override async createApiToken(
    baseUrl: string,
    accessToken: string,
    _platformUserId?: number,
    options?: CreateApiTokenOptions,
  ): Promise<boolean> {
    const normalizedBase = normalizeBaseUrl(baseUrl);
    const payload: Record<string, unknown> = {
      name: (options?.name || '').trim() || 'metapi',
    };

    const groupId = Number.parseInt((options?.group || '').trim(), 10);
    if (Number.isFinite(groupId) && groupId > 0) {
      payload.group_id = groupId;
    }

    const expiresInDays = this.resolveExpiresInDays(options?.expiredTime);
    if (expiresInDays) {
      payload.expires_in_days = expiresInDays;
    }

    if (options?.unlimitedQuota === false && Number.isFinite(options.remainQuota)) {
      payload.quota = Math.max(0, Number(options.remainQuota));
    }

    const endpoints = ['/api/v1/keys', '/api/v1/api-keys'];
    const headers = this.buildAuthHeader(accessToken);
    for (const endpoint of endpoints) {
      try {
        const res = await this.fetchJson<any>(`${normalizedBase}${endpoint}`, {
          method: 'POST',
          headers,
          body: JSON.stringify(payload),
        });
        this.parseSub2ApiEnvelope<any>(res, endpoint);
        return true;
      } catch {}
    }

    return false;
  }

  override async deleteApiToken(
    baseUrl: string,
    accessToken: string,
    tokenKey: string,
  ): Promise<boolean> {
    const targetKey = this.normalizeTokenKeyForCompare(tokenKey);
    if (!targetKey) return false;

    const normalizedBase = normalizeBaseUrl(baseUrl);
    let tokenId: number | null = null;
    try {
      const items = await this.listApiKeys(normalizedBase, accessToken);
      tokenId = items.find((item) => this.normalizeTokenKeyForCompare(item.key) === targetKey)?.id || null;
    } catch {
      return false;
    }

    // Upstream key already absent means local deletion is safe.
    if (!tokenId) return true;

    const endpoints = [
      `/api/v1/keys/${tokenId}`,
      `/api/v1/api-keys/${tokenId}`,
    ];
    const headers = this.buildAuthHeader(accessToken);
    for (const endpoint of endpoints) {
      try {
        const res = await this.fetchJson<any>(`${normalizedBase}${endpoint}`, {
          method: 'DELETE',
          headers,
        });
        this.parseSub2ApiEnvelope<any>(res, endpoint);
        return true;
      } catch {}
    }

    return false;
  }
}
