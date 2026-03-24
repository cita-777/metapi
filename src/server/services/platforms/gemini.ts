import { StandardApiProviderAdapterBase, normalizePlatformBaseUrl } from './standardApiProvider.js';

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
  const normalized = normalizePlatformBaseUrl(baseUrl);
  if (/\/models$/i.test(normalized)) return normalized;
  return `${normalized}/models`;
}

function resolveGeminiNativeModelsUrl(baseUrl: string, apiToken: string): string {
  const normalized = normalizePlatformBaseUrl(baseUrl);
  const withVersion = /\/v\d+(?:beta)?(?:\/|$)/i.test(normalized)
    ? normalized
    : `${normalized}/v1beta`;
  const listBase = /\/models$/i.test(withVersion)
    ? withVersion
    : `${withVersion}/models`;
  const separator = listBase.includes('?') ? '&' : '?';
  return `${listBase}${separator}key=${encodeURIComponent(apiToken)}`;
}

export class GeminiAdapter extends StandardApiProviderAdapterBase {
  readonly platformName: string = 'gemini';

  async detect(url: string): Promise<boolean> {
    const normalized = (url || '').toLowerCase();
    return (
      normalized.includes('generativelanguage.googleapis.com')
      || normalized.includes('googleapis.com/v1beta/openai')
      || normalized.includes('gemini.google.com')
    );
  }

  async getModels(baseUrl: string, apiToken: string): Promise<string[]> {
    const normalizedBase = normalizePlatformBaseUrl(baseUrl);

    if (isOpenAiCompatGeminiBase(normalizedBase)) {
      const openAiModels = await this.fetchModelsFromStandardEndpoint({
        baseUrl: normalizedBase,
        headers: { Authorization: `Bearer ${apiToken}` },
        resolveUrl: resolveGeminiOpenAiModelsUrl,
      });
      if (openAiModels.length > 0) return normalizeModelList(openAiModels);
    }

    try {
      const res = await this.fetchJson<any>(resolveGeminiNativeModelsUrl(normalizedBase, apiToken));
      const nativeModels = (res?.models || [])
        .map((m: any) => String(m?.name || '').trim())
        .filter(Boolean);
      if (nativeModels.length > 0) return normalizeModelList(nativeModels);
    } catch {}

    if (!isOpenAiCompatGeminiBase(normalizedBase)) {
      const openAiModels = await this.fetchModelsFromStandardEndpoint({
        baseUrl: `${normalizedBase}/v1beta/openai`,
        headers: { Authorization: `Bearer ${apiToken}` },
      });
      if (openAiModels.length > 0) return normalizeModelList(openAiModels);
    }

    return [];
  }
}
