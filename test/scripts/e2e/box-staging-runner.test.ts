import { describe, expect, it } from 'vitest';
import { executeCases, loadCases, selectCases } from './box-staging-runner.mjs';

const catalog = loadCases(new URL('../../fixtures/e2e/cases.json', import.meta.url));

describe('box staging e2e runner', () => {
  it('keeps a tagged catalog and does not invent the missing Windows 50-case list', () => {
    expect(catalog.note).toContain('not in this repository');
    expect(catalog.cases.length).not.toBe(50);
    expect(catalog.cases.every((item: { id: string; tags: string[] }) => item.id && item.tags.length > 0)).toBe(true);
    expect(JSON.stringify(catalog)).not.toContain('monitor-proxy');
    const proxy = selectCases(catalog.cases, ['proxy']);
    expect(proxy.map((item: { id: string }) => item.id)).toEqual(['proxy-chat', 'proxy-stream', 'proxy-billing-log']);
    expect(selectCases(catalog.cases, ['stream']).map((item: { id: string }) => item.id)).toEqual(['proxy-stream']);
  });

  it('runs a tagged subset and does not print tokens', async () => {
    const token = 'admin-token-should-not-appear';
    const proxyToken = 'proxy-token-should-not-appear';
    const seen: string[] = [];
    const results = await executeCases(selectCases(catalog.cases, ['auth']), {
      base: 'http://127.0.0.1',
      env: { AUTH_TOKEN: token, PROXY_TOKEN: proxyToken },
      fetchImpl: async (_url: string, init: { headers?: Record<string, string> }) => {
        seen.push(init.headers?.authorization || '');
        const authorized = init.headers?.authorization === `Bearer ${token}`;
        return {
          status: authorized ? 200 : 401,
          text: async () => authorized ? 'ok' : token,
        };
      },
    });
    expect(results.map((result: { id: string; ok: boolean }) => [result.id, result.ok])).toEqual([
      ['auth-sites-no-token', true],
      ['auth-sites-ok', true],
    ]);
    expect(JSON.stringify(results)).not.toContain(token);
    expect(seen).toContain(`Bearer ${token}`);
  });
});
