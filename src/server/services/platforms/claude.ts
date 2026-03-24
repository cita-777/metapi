import { StandardApiProviderAdapterBase } from './standardApiProvider.js';
import { CLAUDE_DEFAULT_ANTHROPIC_VERSION } from '../oauth/claudeProvider.js';

export class ClaudeAdapter extends StandardApiProviderAdapterBase {
  readonly platformName = 'claude';

  async detect(url: string): Promise<boolean> {
    const normalized = (url || '').toLowerCase();
    return normalized.includes('api.anthropic.com') || normalized.includes('anthropic.com/v1');
  }

  async getModels(baseUrl: string, apiToken: string): Promise<string[]> {
    return this.fetchModelsFromStandardEndpoint({
      baseUrl,
      headers: {
        'x-api-key': apiToken,
        'anthropic-version': CLAUDE_DEFAULT_ANTHROPIC_VERSION,
      },
    });
  }
}
