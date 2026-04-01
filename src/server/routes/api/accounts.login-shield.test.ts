import Fastify, { type FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { resetRequestRateLimitStore } from '../../middleware/requestRateLimit.js';

const loginMock = vi.fn();

vi.mock('../../services/platforms/index.js', () => ({
  getAdapter: () => ({
    login: (...args: unknown[]) => loginMock(...args),
  }),
}));

type DbModule = typeof import('../../db/index.js');

describe('accounts login shield detection', () => {
  let app: FastifyInstance;
  let db: DbModule['db'];
  let schema: DbModule['schema'];
  let dataDir = '';

  beforeAll(async () => {
    dataDir = mkdtempSync(join(tmpdir(), 'metapi-accounts-login-shield-'));
    process.env.DATA_DIR = dataDir;

    await import('../../db/migrate.js');
    const dbModule = await import('../../db/index.js');
    const routesModule = await import('./accounts.js');
    db = dbModule.db;
    schema = dbModule.schema;

    app = Fastify();
    await app.register(routesModule.accountsRoutes);
  });

  beforeEach(async () => {
    loginMock.mockReset();
    resetRequestRateLimitStore();

    await db.delete(schema.proxyLogs).run();
    await db.delete(schema.checkinLogs).run();
    await db.delete(schema.routeChannels).run();
    await db.delete(schema.tokenRoutes).run();
    await db.delete(schema.tokenModelAvailability).run();
    await db.delete(schema.modelAvailability).run();
    await db.delete(schema.accountTokens).run();
    await db.delete(schema.accounts).run();
    await db.delete(schema.sites).run();
  });

  afterAll(async () => {
    await app.close();
    delete process.env.DATA_DIR;
  });

  it('returns shieldBlocked when login fails with html-json parse syntax error', async () => {
    loginMock.mockResolvedValueOnce({
      success: false,
      message: "Unexpected token '<', \"<html><scr\"... is not valid JSON",
    });

    const site = await db.insert(schema.sites).values({
      name: 'AnyRouter',
      url: 'https://anyrouter.example.com',
      platform: 'new-api',
    }).returning().get();

    const response = await app.inject({
      method: 'POST',
      url: '/api/accounts/login',
      payload: {
        siteId: site.id,
        username: 'demo-user',
        password: 'demo-password',
      },
    });

    expect(response.statusCode).toBe(200);
    const body = response.json() as { success?: boolean; shieldBlocked?: boolean; message?: string };
    expect(body.success).toBe(false);
    expect(body.shieldBlocked).toBe(true);
    expect((body.message || '').toLowerCase()).toContain('shield');
    expect(body.message || '').not.toContain('Unexpected token');
  });

  it('rate limits repeated login attempts from the same client ip', async () => {
    loginMock.mockResolvedValue({
      success: false,
      message: 'invalid credentials',
    });

    const site = await db.insert(schema.sites).values({
      name: 'AnyRouter',
      url: 'https://anyrouter.example.com',
      platform: 'new-api',
    }).returning().get();

    for (let attempt = 0; attempt < 5; attempt += 1) {
      const response = await app.inject({
        method: 'POST',
        url: '/api/accounts/login',
        remoteAddress: '198.51.100.10',
        payload: {
          siteId: site.id,
          username: 'demo-user',
          password: 'demo-password',
        },
      });
      expect(response.statusCode).toBe(200);
    }

    const limited = await app.inject({
      method: 'POST',
      url: '/api/accounts/login',
      remoteAddress: '198.51.100.10',
      payload: {
        siteId: site.id,
        username: 'demo-user',
        password: 'demo-password',
      },
    });

    expect(limited.statusCode).toBe(429);
    expect(limited.json()).toMatchObject({
      success: false,
      message: '请求过于频繁，请稍后再试',
    });
  });

  it('rejects malformed login payloads at the route boundary', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/accounts/login',
      payload: {
        siteId: '1',
        username: 'demo-user',
        password: 'demo-password',
      },
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({
      success: false,
      message: 'Invalid siteId. Expected positive number.',
    });
  });
});
