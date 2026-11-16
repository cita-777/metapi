import { StandardApiProviderAdapterBase } from './standardApiProvider.js';
import { detectPlatformByUrlHint } from '../../../shared/platformIdentity.js';

export class CheaperInferenceAdapter extends StandardApiProviderAdapterBase {
  readonly platformName = 'cheaperinference';

  async detect(url: string): Promise<boolean> {
    return detectPlatformByUrlHint(url) === this.platformName;
  }

  async getModels(baseUrl: string, apiToken: string): Promise<string[]> {
    return this.fetchModelsFromStandardEndpoint({
      baseUrl,
      headers: { Authorization: `Bearer ${apiToken}` },
    });
  }
}
