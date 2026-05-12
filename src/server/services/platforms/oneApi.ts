import { ApiTokenInfo, BasePlatformAdapter, CheckinResult, BalanceInfo, CreateApiTokenOptions } from './base.js';
import {
  buildEndpointModelContextLengthScope,
  extractContextLengthsFromPayload,
  setModelContextLengths,
} from '../modelContextLengthCache.js';

type CreateApiTokenPayload = {
  name: string;
  unlimited_quota: boolean;
  expired_time: number;
  remain_quota: number;
  allow_ips: string;
  model_limits_enabled: boolean;
  model_limits: string;
  group: string;
};

export class OneApiAdapter extends BasePlatformAdapter {
  readonly platformName: string = 'one-api';

  private normalizeTokenKeyForCompare(value?: string | null): string {
    const trimmed = (value || '').trim();
    return trimmed.startsWith('Bearer ') ? trimmed.slice(7).trim() : trimmed;
  }

  private buildDefaultTokenPayload(options?: CreateApiTokenOptions): CreateApiTokenPayload {
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

  async detect(url: string): Promise<boolean> {
    try {
      const res = await this.fetchJson<any>(`${url}/api/status`);
      return res?.success === true && !res?.data?.system_name;
    } catch {
      return false;
    }
  }

  async checkin(baseUrl: string, accessToken: string): Promise<CheckinResult> {
    try {
      const res = await this.fetchJson<any>(`${baseUrl}/api/user/checkin`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      if (res?.success) {
        return { success: true, message: res.message || 'Check-in successful', reward: res.data?.reward?.toString() };
      }
      return { success: false, message: res?.message || 'Check-in failed' };
    } catch (err: any) {
      return { success: false, message: err.message };
    }
  }

  async getBalance(baseUrl: string, accessToken: string): Promise<BalanceInfo> {
    const res = await this.fetchJson<any>(`${baseUrl}/api/user/self`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    const data = res?.data;
    const quota = (data?.quota || 0) / 500000;
    const used = (data?.used_quota || 0) / 500000;
    const todayIncome = Number.isFinite(data?.today_income) ? (data.today_income / 500000) : undefined;
    const todayQuotaConsumption = Number.isFinite(data?.today_quota_consumption) ? (data.today_quota_consumption / 500000) : undefined;
    return { balance: quota - used, used, quota, todayIncome, todayQuotaConsumption };
  }

  async getModels(
    baseUrl: string,
    apiToken: string,
    _platformUserId?: number,
    contextSourceScope?: string,
  ): Promise<string[]> {
    const res = await this.fetchJson<any>(`${baseUrl}/v1/models`, {
      headers: { Authorization: `Bearer ${apiToken}` },
    });
    setModelContextLengths(
      extractContextLengthsFromPayload(res),
      contextSourceScope || buildEndpointModelContextLengthScope(baseUrl),
    );
    return (res?.data || []).map((m: any) => m.id).filter(Boolean);
  }

  async getApiTokens(baseUrl: string, accessToken: string): Promise<ApiTokenInfo[]> {
    try {
      const res = await this.fetchJson<any>(`${baseUrl}/api/token/?p=0&size=100`, {
        headers: { Authorization: `Bearer ${accessToken}` },
      });

      const items = (() => {
        if (Array.isArray(res?.data)) return res.data;
        if (Array.isArray(res?.data?.items)) return res.data.items;
        if (Array.isArray(res?.data?.data)) return res.data.data;
        if (Array.isArray(res?.items)) return res.items;
        if (Array.isArray(res?.list)) return res.list;
        if (Array.isArray(res?.data?.list)) return res.data.list;
        return [];
      })();

      return items
        .map((item: any, index: number) => {
          const key = typeof item?.key === 'string' ? item.key.trim() : '';
          if (!key) return null;
          const rawName = typeof item?.name === 'string' ? item.name.trim() : '';
          const rawGroup = typeof item?.group === 'string'
            ? item.group.trim()
            : (typeof item?.token_group === 'string' ? item.token_group.trim() : '');
          const status = typeof item?.status === 'number' ? item.status : undefined;
          const tokenInfo: ApiTokenInfo = {
            name: rawName || (index === 0 ? 'default' : `token-${index + 1}`),
            key,
            enabled: status === undefined ? true : status === 1,
          };
          if (rawGroup) tokenInfo.tokenGroup = rawGroup;
          return tokenInfo;
        })
        .filter((item: ApiTokenInfo | null): item is ApiTokenInfo => !!item);
    } catch {
      return [];
    }
  }

  async getApiToken(baseUrl: string, accessToken: string): Promise<string | null> {
    const tokens = await this.getApiTokens(baseUrl, accessToken);
    return tokens.find((token) => token.enabled !== false)?.key || tokens[0]?.key || null;
  }

  async getUserGroups(baseUrl: string, accessToken: string): Promise<string[]> {
    const headers = { Authorization: `Bearer ${accessToken}` };
    const resolveGroupFetchErrorMessage = (payload: any): string => {
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
    };
    const extractGroupKeys = (payload: any): string[] => {
      if (payload && typeof payload === 'object' && payload?.success === false) return [];
      const source = payload?.data || payload;
      if (!source || typeof source !== 'object') return [];
      return Object.keys(source)
        .map((key) => key.trim())
        .filter((key) => !['success', 'message', 'code', 'data', 'error'].includes(key.toLowerCase()))
        .filter(Boolean);
    };
    let terminalError: string | null = null;

    try {
      const groupMap = await this.fetchJson<any>(`${baseUrl}/api/user_group_map`, { headers });
      if (groupMap?.success === false) terminalError = resolveGroupFetchErrorMessage(groupMap);
      const keys = extractGroupKeys(groupMap);
      if (keys.length > 0) return Array.from(new Set(keys));
    } catch {}

    try {
      const groups = await this.fetchJson<any>(`${baseUrl}/api/user/self/groups`, { headers });
      if (groups?.success === false) terminalError = resolveGroupFetchErrorMessage(groups);
      const keys = extractGroupKeys(groups);
      if (keys.length > 0) return Array.from(new Set(keys));
    } catch {}

    if (terminalError) {
      throw new Error(terminalError);
    }

    return ['default'];
  }

  async createApiToken(
    baseUrl: string,
    accessToken: string,
    _platformUserId?: number,
    options?: CreateApiTokenOptions,
  ): Promise<boolean> {
    try {
      const res = await this.fetchJson<any>(`${baseUrl}/api/token/`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${accessToken}` },
        body: JSON.stringify(this.buildDefaultTokenPayload(options)),
      });
      return !!res?.success;
    } catch {
      return false;
    }
  }

  async deleteApiToken(
    baseUrl: string,
    accessToken: string,
    tokenKey: string,
  ): Promise<boolean> {
    const targetKey = this.normalizeTokenKeyForCompare(tokenKey);
    if (!targetKey) return false;

    const headers = { Authorization: `Bearer ${accessToken}` };
    let tokenId: number | null = null;
    try {
      const res = await this.fetchJson<any>(`${baseUrl}/api/token/?p=0&size=100`, { headers });
      const items = (() => {
        if (Array.isArray(res?.data)) return res.data;
        if (Array.isArray(res?.data?.items)) return res.data.items;
        if (Array.isArray(res?.items)) return res.items;
        return [];
      })();
      for (const item of items) {
        const key = this.normalizeTokenKeyForCompare(item?.key);
        const id = Number.parseInt(String(item?.id), 10);
        if (key && key === targetKey && Number.isFinite(id)) {
          tokenId = id;
          break;
        }
      }
    } catch {
      return false;
    }

    if (!tokenId) return true;

    try {
      const res = await this.fetchJson<any>(`${baseUrl}/api/token/${tokenId}`, {
        method: 'DELETE',
        headers,
      });
      if (res?.success) return true;
    } catch {}

    try {
      const res = await this.fetchJson<any>(`${baseUrl}/api/token/${tokenId}/`, {
        method: 'DELETE',
        headers,
      });
      return !!res?.success;
    } catch {
      return false;
    }
  }
}
