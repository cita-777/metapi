import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { registerStagingUpstream, siteBody } from './register-staging-upstream.mjs';

describe('staging upstream registration helper', () => {
  it('builds a loopback site and does not write a seed', () => {
    expect(siteBody('http://127.0.0.1:9', 'metapi-staging-mock')).toMatchObject({
      url: 'http://127.0.0.1:9',
      platform: 'openai',
    });
    expect(() => siteBody('https://example.com', 'metapi-staging-mock')).toThrow(/loopback/);
    const source = readFileSync(new URL('./register-staging-upstream.mjs', import.meta.url), 'utf8');
    expect(source).not.toContain('defaultSiteSeedService');
    expect(source).not.toContain('hub.db');
  });

  it('registers a site, account, and route refresh without logging the admin token', async () => {
    const token = 'admin-token-should-not-appear';
    const calls: string[] = [];
    const created = await registerStagingUpstream({
      base: 'http://127.0.0.1:4100',
      upstream: 'http://127.0.0.1:9',
      token,
      fetchImpl: async (url: string, init: { headers: Record<string, string>; body: string }) => {
        calls.push(`${url} ${init.body}`);
        expect(init.headers.authorization).toBe(`Bearer ${token}`);
        if (url.endsWith('/api/sites')) return { status: 200, text: async () => JSON.stringify({ id: 7 }) };
        if (url.endsWith('/api/accounts')) return { status: 200, text: async () => JSON.stringify({ id: 8 }) };
        return { status: 200, text: async () => JSON.stringify({ success: true }) };
      },
    });
    expect(created).toMatchObject({ siteId: 7, accountId: 8, upstream: 'http://127.0.0.1:9' });
    expect(calls[0]).toContain('/api/sites');
    expect(calls[1]).toContain('"siteId":7');
    expect(calls[2]).toContain('/api/routes/rebuild');
    expect(JSON.stringify(created)).not.toContain(token);
  });
});
