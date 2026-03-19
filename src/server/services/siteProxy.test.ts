import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { once } from 'node:events';
import { mkdtempSync } from 'node:fs';
import { createServer } from 'node:http';
import { connect as connectSocket } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { sql } from 'drizzle-orm';
import { SocksClient } from 'socks';
import { Headers, fetch } from 'undici';

type DbModule = typeof import('../db/index.js');

describe('siteProxy', () => {
  let db: DbModule['db'];
  let schema: DbModule['schema'];
  let dataDir = '';

  beforeAll(async () => {
    dataDir = mkdtempSync(join(tmpdir(), 'metapi-site-proxy-'));
    process.env.DATA_DIR = dataDir;
    await import('../db/migrate.js');
    const dbModule = await import('../db/index.js');
    db = dbModule.db;
    schema = dbModule.schema;
  });

  beforeEach(async () => {
    const { invalidateSiteProxyCache } = await import('./siteProxy.js');
    await db.delete(schema.accounts).run();
    await db.delete(schema.settings).run();
    await db.delete(schema.sites).run();
    invalidateSiteProxyCache();
  });

  afterAll(() => {
    delete process.env.DATA_DIR;
  });

  it('resolves system proxy only for sites that opt in', async () => {
    await db.insert(schema.settings).values({
      key: 'system_proxy_url',
      value: JSON.stringify('http://127.0.0.1:7890'),
    }).run();

    await db.run(sql`
      INSERT INTO sites (name, url, platform, use_system_proxy)
      VALUES
        ('base-site', 'https://relay.example.com', 'new-api', 0),
        ('openai-site', 'https://relay.example.com/openai', 'new-api', 1)
    `);

    const { resolveSiteProxyUrlByRequestUrl } = await import('./siteProxy.js');
    expect(await resolveSiteProxyUrlByRequestUrl('https://relay.example.com/openai/v1/models'))
      .toBe('http://127.0.0.1:7890');
    expect(await resolveSiteProxyUrlByRequestUrl('https://relay.example.com/v1/models'))
      .toBeNull();
  });

  it('injects dispatcher when a site opts into the configured system proxy', async () => {
    await db.insert(schema.settings).values({
      key: 'system_proxy_url',
      value: JSON.stringify('http://127.0.0.1:7890'),
    }).run();
    await db.run(sql`
      INSERT INTO sites (name, url, platform, use_system_proxy)
      VALUES ('proxy-site', 'https://proxy-site.example.com', 'new-api', 1)
    `);

    const { withSiteProxyRequestInit } = await import('./siteProxy.js');
    const requestInit = await withSiteProxyRequestInit('https://proxy-site.example.com/v1/chat/completions', {
      method: 'POST',
    });

    expect('dispatcher' in requestInit).toBe(true);
  });

  it('injects a working dispatcher for socks5 system proxies', async () => {
    const upstreamServer = createServer((_request, response) => {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ ok: true }));
    });
    upstreamServer.listen(0, '127.0.0.1');
    await once(upstreamServer, 'listening');
    const upstreamAddress = upstreamServer.address();
    if (!upstreamAddress || typeof upstreamAddress === 'string') {
      throw new Error('Failed to determine upstream server address');
    }
    const requestUrl = `http://proxy-site.example.com:${upstreamAddress.port}/v1/chat/completions`;

    await db.insert(schema.settings).values({
      key: 'system_proxy_url',
      value: JSON.stringify('socks5h://127.0.0.1:1080'),
    }).run();
    await db.run(sql`
      INSERT INTO sites (name, url, platform, use_system_proxy)
      VALUES ('proxy-site', ${`http://proxy-site.example.com:${upstreamAddress.port}`}, 'new-api', 1)
    `);

    const createConnectionSpy = vi.spyOn(SocksClient, 'createConnection').mockImplementation(async () => {
      const socket = connectSocket(upstreamAddress.port, '127.0.0.1');
      await once(socket, 'connect');
      return { socket } as Awaited<ReturnType<typeof SocksClient.createConnection>>;
    });

    try {
      const { withSiteProxyRequestInit } = await import('./siteProxy.js');
      const requestInit = await withSiteProxyRequestInit(requestUrl, {
        method: 'GET',
      });

      expect('dispatcher' in requestInit).toBe(true);

      const response = await fetch(requestUrl, requestInit);

      expect(response.status).toBe(200);
      expect(createConnectionSpy).toHaveBeenCalledTimes(1);
      expect(createConnectionSpy).toHaveBeenCalledWith(expect.objectContaining({
        command: 'connect',
        proxy: expect.objectContaining({
          host: '127.0.0.1',
          port: 1080,
          type: 5,
        }),
        destination: expect.objectContaining({
          host: 'proxy-site.example.com',
          port: upstreamAddress.port,
        }),
      }));
    } finally {
      createConnectionSpy.mockRestore();
      await new Promise<void>((resolve, reject) => {
        upstreamServer.close((error) => {
          if (error) {
            reject(error);
            return;
          }
          resolve();
        });
      });
    }
  });

  it('merges site custom headers by matched request url and keeps explicit headers authoritative', async () => {
    await db.insert(schema.sites).values({
      name: 'headers-site',
      url: 'https://headers-site.example.com',
      platform: 'new-api',
      customHeaders: JSON.stringify({
        'cf-access-client-id': 'site-client',
        authorization: 'Bearer site-default',
      }),
    }).run();

    const { withSiteProxyRequestInit } = await import('./siteProxy.js');
    const requestInit = await withSiteProxyRequestInit('https://headers-site.example.com/v1/models', {
      method: 'GET',
      headers: {
        Authorization: 'Bearer request-token',
        'X-Trace-Id': 'trace-1',
      },
    });
    const headers = new Headers(requestInit.headers);

    expect(headers.get('cf-access-client-id')).toBe('site-client');
    expect(headers.get('authorization')).toBe('Bearer request-token');
    expect(headers.get('x-trace-id')).toBe('trace-1');
  });

  it('merges site custom headers from site records even without cache lookup', async () => {
    const { withSiteRecordProxyRequestInit } = await import('./siteProxy.js');
    const requestInit = withSiteRecordProxyRequestInit({
      useSystemProxy: false,
      customHeaders: JSON.stringify({
        'x-site-scope': 'site-level',
      }),
    }, {
      method: 'POST',
      headers: {
        'X-Request-Id': 'req-1',
      },
    });
    const headers = new Headers(requestInit.headers);

    expect(headers.get('x-site-scope')).toBe('site-level');
    expect(headers.get('x-request-id')).toBe('req-1');
  });
});
