import { describe, expect, it } from 'vitest';
import {
  StandardApiProviderAdapterBase,
  normalizePlatformBaseUrl,
  resolveVersionedModelsUrl,
} from './standardApiProvider.js';

class TestStandardApiProviderAdapter extends StandardApiProviderAdapterBase {
  readonly platformName = 'test-standard';
  fetchJsonImpl = async () => ({ data: [] as Array<{ id: string }> });

  async detect(_url: string): Promise<boolean> {
    return false;
  }

  async getModels(_baseUrl: string, _token: string): Promise<string[]> {
    return [];
  }

  protected override async fetchJson<T>(url: string, options?: Parameters<StandardApiProviderAdapterBase['fetchJson']>[1]): Promise<T> {
    return this.fetchJsonImpl(url, options) as Promise<T>;
  }

  async fetchModelsForTest(options: Parameters<StandardApiProviderAdapterBase['fetchModelsFromStandardEndpoint']>[0]) {
    return this.fetchModelsFromStandardEndpoint(options);
  }
}

describe('standardApiProvider helpers', () => {
  it('normalizes provider base urls and appends /v1/models when needed', () => {
    expect(normalizePlatformBaseUrl('https://api.example.com///')).toBe('https://api.example.com');
    expect(resolveVersionedModelsUrl('https://api.example.com')).toBe('https://api.example.com/v1/models');
    expect(resolveVersionedModelsUrl('https://api.example.com/v1')).toBe('https://api.example.com/v1/models');
    expect(resolveVersionedModelsUrl('https://api.example.com/v1beta')).toBe('https://api.example.com/v1beta/models');
  });

  it('provides shared unsupported login/checkin and zero-balance defaults', async () => {
    const adapter = new TestStandardApiProviderAdapter();

    await expect(adapter.login('https://api.example.com', 'user', 'pass')).resolves.toEqual({
      success: false,
      message: 'login endpoint not supported',
    });
    await expect(adapter.getUserInfo('https://api.example.com', 'token')).resolves.toBe(null);
    await expect(adapter.checkin('https://api.example.com', 'token')).resolves.toEqual({
      success: false,
      message: 'checkin endpoint not supported',
    });
    await expect(adapter.getBalance('https://api.example.com', 'token')).resolves.toEqual({
      balance: 0,
      used: 0,
      quota: 0,
    });
  });

  it('does not swallow mapper bugs while still returning empty lists for network failures', async () => {
    const adapter = new TestStandardApiProviderAdapter();
    adapter.fetchJsonImpl = async () => ({ data: [{ id: 'gpt-5' }] });

    await expect(adapter.fetchModelsForTest({
      baseUrl: 'https://api.example.com',
      mapResponse: () => {
        throw new Error('mapper exploded');
      },
    })).rejects.toThrow('mapper exploded');

    adapter.fetchJsonImpl = async () => {
      throw new Error('network failed');
    };

    await expect(adapter.fetchModelsForTest({
      baseUrl: 'https://api.example.com',
    })).resolves.toEqual([]);
  });

  it('rejects invalid payload shapes instead of silently treating them as no models', async () => {
    const adapter = new TestStandardApiProviderAdapter();
    adapter.fetchJsonImpl = async () => ({ data: 'not-an-array' });

    await expect(adapter.fetchModelsForTest({
      baseUrl: 'https://api.example.com',
    })).rejects.toThrow('invalid standard models payload');
  });
});
