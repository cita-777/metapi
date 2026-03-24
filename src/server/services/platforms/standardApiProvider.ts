import {
  BasePlatformAdapter,
  type BalanceInfo,
  type CheckinResult,
  type UserInfo,
} from './base.js';

type FetchModelsOptions = {
  baseUrl: string;
  headers?: Record<string, string>;
  resolveUrl?: (normalizedBaseUrl: string) => string;
  mapResponse?: (payload: any) => unknown[];
};

export function normalizePlatformBaseUrl(baseUrl: string): string {
  let normalized = baseUrl || '';
  while (normalized.endsWith('/')) {
    normalized = normalized.slice(0, -1);
  }
  return normalized;
}

export function resolveVersionedModelsUrl(baseUrl: string): string {
  const normalized = normalizePlatformBaseUrl(baseUrl);
  if (/\/v\d+(?:\.\d+)?(?:beta)?$/i.test(normalized)) {
    return `${normalized}/models`;
  }
  return `${normalized}/v1/models`;
}

export abstract class StandardApiProviderAdapterBase extends BasePlatformAdapter {
  protected loginUnsupportedMessage = 'login endpoint not supported';
  protected checkinUnsupportedMessage = 'checkin endpoint not supported';

  override async login(_baseUrl: string, _username: string, _password: string) {
    return {
      success: false as const,
      message: this.loginUnsupportedMessage,
    };
  }

  override async getUserInfo(_baseUrl: string, _accessToken: string): Promise<UserInfo | null> {
    return null;
  }

  override async checkin(_baseUrl: string, _accessToken: string): Promise<CheckinResult> {
    return {
      success: false,
      message: this.checkinUnsupportedMessage,
    };
  }

  override async getBalance(_baseUrl: string, _accessToken: string): Promise<BalanceInfo> {
    return { balance: 0, used: 0, quota: 0 };
  }

  protected async fetchModelsFromStandardEndpoint(options: FetchModelsOptions): Promise<string[]> {
    const normalizedBaseUrl = normalizePlatformBaseUrl(options.baseUrl);
    const url = options.resolveUrl
      ? options.resolveUrl(normalizedBaseUrl)
      : resolveVersionedModelsUrl(normalizedBaseUrl);

    let payload: any;
    try {
      payload = await this.fetchJson<any>(url, {
        headers: options.headers,
      });
    } catch {
      return [];
    }

    const rows = options.mapResponse
      ? options.mapResponse(payload)
      : Array.isArray(payload?.data)
        ? payload.data.map((item: any) => item?.id)
        : null;

    if (!Array.isArray(rows)) {
      throw new Error('invalid standard models payload');
    }

    return rows
      .map((item) => (typeof item === 'string' ? item.trim() : ''))
      .filter((item) => item.length > 0);
  }
}
