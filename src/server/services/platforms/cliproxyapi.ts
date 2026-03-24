import {
  StandardApiProviderAdapterBase,
  normalizePlatformBaseUrl,
  resolveVersionedModelsUrl,
} from './standardApiProvider.js';

export class CliProxyApiAdapter extends StandardApiProviderAdapterBase {
  readonly platformName = 'cliproxyapi';
  protected override loginUnsupportedMessage = 'CLIProxyAPI does not support login';
  protected override checkinUnsupportedMessage = 'CLIProxyAPI does not support checkin';

  async detect(url: string): Promise<boolean> {
    const normalized = (url || '').toLowerCase();

    if (/:8317(\/|$)/.test(normalized)) {
      return true;
    }

    if (normalized.includes('cliproxy')) {
      return true;
    }

    try {
      const base = normalizePlatformBaseUrl(url);
      const { fetch } = await import('undici');
      const res = await fetch(`${base}/v0/management/openai-compatibility`, {
        method: 'GET',
        signal: AbortSignal.timeout(5000),
      });

      const hasCpaHeaders = Boolean(
        res.headers.get('x-cpa-version')
        || res.headers.get('x-cpa-commit')
        || res.headers.get('x-cpa-build-date'),
      );
      if (hasCpaHeaders) {
        return res.status === 200 || res.status === 401 || res.status === 403;
      }

      if (res.status === 200) {
        const payload = await res.json().catch(() => null);
        if (payload && typeof payload === 'object') {
          return Object.prototype.hasOwnProperty.call(payload, 'openai-compatibility');
        }
      }

      return false;
    } catch {
      return false;
    }
  }

  async getModels(baseUrl: string, apiToken: string): Promise<string[]> {
    return this.fetchModelsFromStandardEndpoint({
      baseUrl,
      headers: { Authorization: `Bearer ${apiToken}` },
      resolveUrl: resolveVersionedModelsUrl,
    });
  }
}
