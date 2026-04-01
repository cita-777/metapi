import Fastify, { type FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

const fetchMock = vi.fn();

vi.mock('undici', async () => {
  const actual = await vi.importActual<typeof import('undici')>('undici');
  return {
    ...actual,
    fetch: (...args: unknown[]) => fetchMock(...args),
  };
});

type ConfigModule = typeof import('../../config.js');

describe('settings system proxy test route', () => {
  let app: FastifyInstance;
  let config: ConfigModule['config'];
  let dataDir = '';

  beforeAll(async () => {
    dataDir = mkdtempSync(join(tmpdir(), 'metapi-settings-system-proxy-test-'));
    process.env.DATA_DIR = dataDir;

    await import('../../db/migrate.js');
    const configModule = await import('../../config.js');
    const settingsRoutesModule = await import('./settings.js');

    config = configModule.config;

    app = Fastify();
    await app.register(settingsRoutesModule.settingsRoutes);
  });

  beforeEach(() => {
    fetchMock.mockReset();
    config.systemProxyUrl = '';
  });

  afterAll(async () => {
    await app.close();
    delete process.env.DATA_DIR;
  });

  it('tests the provided system proxy url and returns latency', async () => {
    fetchMock.mockResolvedValue(new Response(null, {
      status: 204,
      headers: { 'content-type': 'text/plain' },
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/api/settings/system-proxy/test',
      payload: {
        proxyUrl: 'http://127.0.0.1:7890',
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      success: true,
      proxyUrl: 'http://127.0.0.1:7890',
      probeUrl: 'https://www.gstatic.com/generate_204',
      finalUrl: 'https://www.gstatic.com/generate_204',
      reachable: true,
      ok: true,
      statusCode: 204,
    });
    expect((response.json() as { latencyMs?: number }).latencyMs).toBeGreaterThanOrEqual(1);

    const [url, requestInit] = fetchMock.mock.calls[0] as [string, Record<string, unknown>];
    expect(url).toBe('https://www.gstatic.com/generate_204');
    expect(requestInit.method).toBe('GET');
    expect(requestInit.dispatcher).toBeTruthy();
  });

  it('uses the saved system proxy url when request body is empty', async () => {
    config.systemProxyUrl = 'socks5://127.0.0.1:1080';
    fetchMock.mockResolvedValue(new Response(null, { status: 204 }));

    const response = await app.inject({
      method: 'POST',
      url: '/api/settings/system-proxy/test',
      payload: {},
    });

    expect(response.statusCode).toBe(200);
    expect((response.json() as { proxyUrl?: string }).proxyUrl).toBe('socks5://127.0.0.1:1080');
  });

  it('rejects missing system proxy url', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/settings/system-proxy/test',
      payload: {},
    });

    expect(response.statusCode).toBe(400);
    expect((response.json() as { message?: string }).message).toContain('请先填写系统代理地址');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('rejects array payloads for system proxy test', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/settings/system-proxy/test',
      payload: [],
    });

    expect(response.statusCode).toBe(400);
    expect((response.json() as { message?: string }).message).toContain('settings payload');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('rejects non-string proxyUrl payloads for system proxy test', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/settings/system-proxy/test',
      payload: {
        proxyUrl: 123,
      },
    });

    expect(response.statusCode).toBe(400);
    expect((response.json() as { message?: string }).message).toContain('string');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('returns 502 when the proxy probe request fails', async () => {
    fetchMock.mockRejectedValue(new TypeError('fetch failed', {
      cause: new Error('connect ECONNREFUSED 127.0.0.1:7890'),
    }));

    const response = await app.inject({
      method: 'POST',
      url: '/api/settings/system-proxy/test',
      payload: {
        proxyUrl: 'http://127.0.0.1:7890',
      },
    });

    expect(response.statusCode).toBe(502);
    expect((response.json() as { message?: string }).message).toContain('连接被拒绝');
    expect((response.json() as { message?: string }).message).not.toContain('fetch failed');
  });
});
