import { StandardApiProviderAdapterBase } from './standardApiProvider.js';
import { CLAUDE_DEFAULT_ANTHROPIC_VERSION } from '../oauth/claudeProvider.js';

function resolveOpenAiCompatibleBaseUrl(baseUrl: string): string | null {
  const normalized = (baseUrl || '').trim().replace(/\/+$/, '');
  const match = normalized.match(/^(.*)\/anthropic$/i);
  return match?.[1] || null;
}

export class ClaudeAdapter extends StandardApiProviderAdapterBase {
  readonly platformName = 'claude';

  async detect(url: string): Promise<boolean> {
    const normalized = (url || '').toLowerCase();
    return normalized.includes('api.anthropic.com') || normalized.includes('anthropic.com/v1');
  }

  async getModels(baseUrl: string, apiToken: string, _platformUserId?: number, contextSourceScope?: string): Promise<string[]> {
    const openAiCompatibleBaseUrl = resolveOpenAiCompatibleBaseUrl(baseUrl);
    try {
      const claudeModels = await this.fetchModelsFromStandardEndpoint({
        baseUrl,
        headers: {
          'x-api-key': apiToken,
          'anthropic-version': CLAUDE_DEFAULT_ANTHROPIC_VERSION,
        },
        contextSourceScope,
      });
      if (claudeModels.length > 0) return claudeModels;
    } catch (error) {
      if (!openAiCompatibleBaseUrl) throw error;
    }

    if (!openAiCompatibleBaseUrl) return [];

    return this.fetchModelsFromStandardEndpoint({
      contextSourceScope,
      baseUrl: openAiCompatibleBaseUrl,
      headers: { Authorization: `Bearer ${apiToken}` },
    });
  }
}
