import { BasePlatformAdapter, type BalanceInfo, type CheckinResult, type UserInfo } from './base.js';

function normalizeBaseUrl(baseUrl: string): string {
  return (baseUrl || '').replace(/\/+$/, '');
}

function stripModelPrefix(name: string): string {
  const trimmed = name.trim();
  if (!trimmed) return '';
  return trimmed.replace(/^models\//i, '');
}

function normalizeModelList(models: string[]): string[] {
  const deduped = new Set<string>();
  for (const model of models) {
    const normalized = stripModelPrefix(model);
    if (normalized) deduped.add(normalized);
  }
  return Array.from(deduped);
}

function isOpenAiCompatGeminiBase(baseUrl: string): boolean {
  return /\/openai(?:\/|$)/i.test(baseUrl);
}

function resolveGeminiOpenAiModelsUrl(baseUrl: string): string {
  const normalized = normalizeBaseUrl(baseUrl);
  if (/\/models$/i.test(normalized)) return normalized;
  return `${normalized}/models`;
}

function resolveGeminiNativeModelsUrl(baseUrl: string, apiToken: string): string {
  const normalized = normalizeBaseUrl(baseUrl);
  const withVersion = /\/v\d+(?:beta)?(?:\/|$)/i.test(normalized)
    ? normalized
    : `${normalized}/v1beta`;
  const listBase = /\/models$/i.test(withVersion)
    ? withVersion
    : `${withVersion}/models`;
  const separator = listBase.includes('?') ? '&' : '?';
  return `${listBase}${separator}key=${encodeURIComponent(apiToken)}`;
}

export class GeminiAdapter extends BasePlatformAdapter {
  readonly platformName: string = 'gemini';

  async detect(url: string): Promise<boolean> {
    const normalized = (url || '').toLowerCase();
    return (
      normalized.includes('generativelanguage.googleapis.com')
      || normalized.includes('googleapis.com/v1beta/openai')
      || normalized.includes('gemini.google.com')
    );
  }

  override async login(_baseUrl: string, _username: string, _password: string) {
    return { success: false, message: 'login endpoint not supported' };
  }

  override async getUserInfo(_baseUrl: string, _accessToken: string): Promise<UserInfo | null> {
    return null;
  }

  async checkin(_baseUrl: string, _accessToken: string): Promise<CheckinResult> {
    return { success: false, message: 'checkin endpoint not supported' };
  }

  async getBalance(_baseUrl: string, _accessToken: string): Promise<BalanceInfo> {
    // Gemini API keys generally do not expose account balance via API.
    return { balance: 0, used: 0, quota: 0 };
  }

  async getModels(baseUrl: string, apiToken: string): Promise<string[]> {
    const normalizedBase = normalizeBaseUrl(baseUrl);

    if (isOpenAiCompatGeminiBase(normalizedBase)) {
      try {
        const res = await this.fetchJson<any>(resolveGeminiOpenAiModelsUrl(normalizedBase), {
          headers: { Authorization: `Bearer ${apiToken}` },
        });
        const openAiModels = (res?.data || []).map((m: any) => String(m?.id || '').trim()).filter(Boolean);
        if (openAiModels.length > 0) return normalizeModelList(openAiModels);
      } catch {}
    }

    try {
      const res = await this.fetchJson<any>(resolveGeminiNativeModelsUrl(normalizedBase, apiToken));
      const nativeModels = (res?.models || [])
        .map((m: any) => String(m?.name || '').trim())
        .filter(Boolean);
      if (nativeModels.length > 0) return normalizeModelList(nativeModels);
    } catch {}

    if (!isOpenAiCompatGeminiBase(normalizedBase)) {
      try {
        const res = await this.fetchJson<any>(`${normalizedBase}/v1beta/openai/models`, {
          headers: { Authorization: `Bearer ${apiToken}` },
        });
        const openAiModels = (res?.data || []).map((m: any) => String(m?.id || '').trim()).filter(Boolean);
        if (openAiModels.length > 0) return normalizeModelList(openAiModels);
      } catch {}
    }

    return [];
  }
}
