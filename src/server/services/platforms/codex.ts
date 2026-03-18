import { BasePlatformAdapter, type BalanceInfo, type CheckinResult, type UserInfo } from './base.js';

function normalizeBaseUrl(baseUrl: string): string {
  let normalized = (baseUrl || '').trim();
  while (normalized.endsWith('/')) {
    normalized = normalized.slice(0, -1);
  }
  return normalized;
}

export class CodexAdapter extends BasePlatformAdapter {
  readonly platformName = 'codex';

  async detect(url: string): Promise<boolean> {
    const normalized = normalizeBaseUrl(url).toLowerCase();
    return normalized.includes('chatgpt.com/backend-api/codex');
  }

  override async login(_baseUrl: string, _username: string, _password: string) {
    return { success: false as const, message: 'codex oauth login is managed via OAuth flow' };
  }

  override async getUserInfo(_baseUrl: string, _accessToken: string): Promise<UserInfo | null> {
    return null;
  }

  async checkin(_baseUrl: string, _accessToken: string): Promise<CheckinResult> {
    return { success: false, message: 'codex oauth connections do not support checkin' };
  }

  async getBalance(_baseUrl: string, _accessToken: string): Promise<BalanceInfo> {
    return { balance: 0, used: 0, quota: 0 };
  }

  async getModels(_baseUrl: string, _token: string): Promise<string[]> {
    return [];
  }
}
