import { createHash } from 'node:crypto';
import type { RequestInit as UndiciRequestInit } from 'undici';
import { withSiteProxyRequestInit } from '../siteProxy.js';

export interface CheckinResult {
  success: boolean;
  message: string;
  reward?: string;
}

export interface SubscriptionPlanSummary {
  id?: number;
  groupId?: number;
  groupName?: string;
  status?: string;
  expiresAt?: string;
  dailyUsedUsd?: number;
  dailyLimitUsd?: number;
  weeklyUsedUsd?: number;
  weeklyLimitUsd?: number;
  monthlyUsedUsd?: number;
  monthlyLimitUsd?: number;
}

export interface SubscriptionSummary {
  activeCount: number;
  totalUsedUsd: number;
  subscriptions: SubscriptionPlanSummary[];
}

export interface BalanceInfo {
  balance: number;
  used: number;
  quota: number;
  todayIncome?: number;
  todayQuotaConsumption?: number;
  subscriptionSummary?: SubscriptionSummary;
}

interface LoginResult {
  success: boolean;
  accessToken?: string;
  username?: string;
  message?: string;
}

export interface UserInfo {
  username: string;
  displayName?: string;
  email?: string;
  role?: number;
}

export interface TokenVerifyResult {
  tokenType: 'session' | 'apikey' | 'unknown';
  userInfo?: UserInfo | null;
  balance?: BalanceInfo | null;
  apiToken?: string | null;
  models?: string[];
}

export interface ApiTokenInfo {
  name: string;
  key: string;
  enabled?: boolean;
  tokenGroup?: string | null;
}

export interface SiteAnnouncement {
  sourceKey: string;
  title: string;
  content: string;
  level: 'info' | 'warning' | 'error';
  sourceUrl?: string | null;
  startsAt?: string | null;
  endsAt?: string | null;
  upstreamCreatedAt?: string | null;
  upstreamUpdatedAt?: string | null;
  rawPayload?: unknown;
}

export interface CreateApiTokenOptions {
  name?: string;
  group?: string;
  unlimitedQuota?: boolean;
  remainQuota?: number;
  expiredTime?: number;
  allowIps?: string;
  modelLimitsEnabled?: boolean;
  modelLimits?: string;
}

export interface PlatformAdapter {
  readonly platformName: string;
  detect(url: string): Promise<boolean>;
  login(baseUrl: string, username: string, password: string): Promise<LoginResult>;
  getUserInfo(baseUrl: string, accessToken: string, platformUserId?: number): Promise<UserInfo | null>;
  verifyToken(baseUrl: string, token: string, platformUserId?: number): Promise<TokenVerifyResult>;
  checkin(baseUrl: string, accessToken: string, platformUserId?: number): Promise<CheckinResult>;
  getBalance(baseUrl: string, accessToken: string, platformUserId?: number): Promise<BalanceInfo>;
  getModels(baseUrl: string, token: string, platformUserId?: number, contextSourceScope?: string): Promise<string[]>;
  getApiToken(baseUrl: string, accessToken: string, platformUserId?: number): Promise<string | null>;
  getApiTokens(baseUrl: string, accessToken: string, platformUserId?: number): Promise<ApiTokenInfo[]>;
  getSiteAnnouncements(baseUrl: string, accessToken: string, platformUserId?: number): Promise<SiteAnnouncement[]>;
  getUserGroups(baseUrl: string, accessToken: string, platformUserId?: number): Promise<string[]>;
  createApiToken(baseUrl: string, accessToken: string, platformUserId?: number, options?: CreateApiTokenOptions): Promise<boolean>;
  deleteApiToken(baseUrl: string, accessToken: string, tokenKey: string, platformUserId?: number): Promise<boolean>;
}

export abstract class BasePlatformAdapter implements PlatformAdapter {
  abstract readonly platformName: string;

  abstract detect(url: string): Promise<boolean>;
  abstract checkin(baseUrl: string, accessToken: string): Promise<CheckinResult>;
  abstract getBalance(baseUrl: string, accessToken: string): Promise<BalanceInfo>;
  abstract getModels(baseUrl: string, token: string, platformUserId?: number, contextSourceScope?: string): Promise<string[]>;

  async verifyToken(baseUrl: string, token: string, _platformUserId?: number): Promise<TokenVerifyResult> {
    // 1. Try as session/access token first (for management APIs)
    const userInfo = await this.getUserInfo(baseUrl, token);
    if (userInfo) {
      let balance: BalanceInfo | null = null;
      try { balance = await this.getBalance(baseUrl, token); } catch {}
      let apiToken: string | null = null;
      try { apiToken = await this.getApiToken(baseUrl, token); } catch {}
      return { tokenType: 'session', userInfo, balance, apiToken };
    }

    // 2. Try as API key (for /v1/models)
    try {
      const models = await this.getModels(baseUrl, token);
      if (models && models.length > 0) {
        return { tokenType: 'apikey', models };
      }
    } catch {}

    return { tokenType: 'unknown' };
  }

  async getUserInfo(baseUrl: string, accessToken: string): Promise<UserInfo | null> {
    try {
      const res = await this.fetchJson<any>(`${baseUrl}/api/user/self`, {
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      if (res?.success && res?.data) {
        return {
          username: res.data.username || res.data.display_name || '',
          displayName: res.data.display_name,
          email: res.data.email,
          role: res.data.role,
        };
      }
      return null;
    } catch {
      return null;
    }
  }

  async login(baseUrl: string, username: string, password: string): Promise<LoginResult> {
    try {
      const res = await this.fetchJson<any>(`${baseUrl}/api/user/login`, {
        method: 'POST',
        body: JSON.stringify({ username, password }),
      });
      if (res?.success && res?.data) {
        return {
          success: true,
          accessToken: typeof res.data === 'string' ? res.data : res.data.token || res.data.access_token,
          username,
        };
      }
      return { success: false, message: res?.message || '登录失败' };
    } catch (err: any) {
      return { success: false, message: err.message || '登录请求失败' };
    }
  }

  async getApiToken(_baseUrl: string, _accessToken: string, _platformUserId?: number): Promise<string | null> {
    return null;
  }

  async getApiTokens(baseUrl: string, accessToken: string, platformUserId?: number): Promise<ApiTokenInfo[]> {
    const token = await this.getApiToken(baseUrl, accessToken, platformUserId);
    if (!token) return [];
    return [{ name: 'default', key: token, enabled: true, tokenGroup: 'default' }];
  }

  async getSiteAnnouncements(
    _baseUrl: string,
    _accessToken: string,
    _platformUserId?: number,
  ): Promise<SiteAnnouncement[]> {
    return [];
  }

  async createApiToken(
    _baseUrl: string,
    _accessToken: string,
    _platformUserId?: number,
    _options?: CreateApiTokenOptions,
  ): Promise<boolean> {
    return false;
  }

  async getUserGroups(
    _baseUrl: string,
    _accessToken: string,
    _platformUserId?: number,
  ): Promise<string[]> {
    return ['default'];
  }

  async deleteApiToken(
    _baseUrl: string,
    _accessToken: string,
    _tokenKey: string,
    _platformUserId?: number,
  ): Promise<boolean> {
    return false;
  }

  protected async fetchJson<T>(url: string, options?: UndiciRequestInit): Promise<T> {
    const { fetch } = await import('undici');
    const requestOptions: UndiciRequestInit = {
      ...options,
      body: options?.body ?? undefined,
      headers: {
        'Content-Type': 'application/json',
        ...options?.headers,
      },
    };
    const proxiedRequestOptions = await withSiteProxyRequestInit(url, requestOptions);
    const res = await fetch(url, proxiedRequestOptions);
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}: ${await res.text()}`);
    }
    return res.json() as Promise<T>;
  }

  protected buildNoticeSourceKey(content: string): string {
    const normalized = (content || '').trim();
    return `notice:${createHash('sha1').update(normalized).digest('hex')}`;
  }
}
