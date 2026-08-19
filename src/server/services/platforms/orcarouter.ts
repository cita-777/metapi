import { StandardApiProviderAdapterBase } from './standardApiProvider.js';

export class OrcaRouterAdapter extends StandardApiProviderAdapterBase {
  readonly platformName = 'orcarouter';

  async detect(url: string): Promise<boolean> {
    const normalized = (url || '').toLowerCase();
    return normalized.includes('orcarouter');
  }

  async getModels(baseUrl: string, apiToken: string): Promise<string[]> {
    return this.fetchModelsFromStandardEndpoint({
      baseUrl,
      headers: { Authorization: `Bearer ${apiToken}` },
    });
  }
}
