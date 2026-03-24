import { StandardApiProviderAdapterBase } from './standardApiProvider.js';

export class OpenAiAdapter extends StandardApiProviderAdapterBase {
  readonly platformName = 'openai';

  async detect(url: string): Promise<boolean> {
    const normalized = (url || '').toLowerCase();
    return normalized.includes('api.openai.com');
  }

  async getModels(baseUrl: string, apiToken: string): Promise<string[]> {
    return this.fetchModelsFromStandardEndpoint({
      baseUrl,
      headers: { Authorization: `Bearer ${apiToken}` },
    });
  }
}
