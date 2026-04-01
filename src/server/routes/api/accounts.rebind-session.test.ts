import Fastify, { type FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { eq } from 'drizzle-orm';

const verifyTokenMock = vi.fn();

vi.mock('../../services/platforms/index.js', () => ({
  getAdapter: () => ({
    verifyToken: (...args: unknown[]) => verifyTokenMock(...args),
  }),
}));

type DbModule = typeof import('../../db/index.js');

describe('accounts rebind-session api', { timeout: 15_000 }, () => {
  let app: FastifyInstance;
  let db: DbModule['db'];
  let schema: DbModule['schema'];
  let dataDir = '';

  beforeAll(async () => {
    dataDir = mkdtempSync(join(tmpdir(), 'metapi-accounts-rebind-session-'));
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
    verifyTokenMock.mockReset();

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

  it('rejects rebinding when token is not verified as session', async () => {
    verifyTokenMock.mockResolvedValueOnce({ tokenType: 'unknown' });

    const site = await db.insert(schema.sites).values({
      name: 'Rebind Site',
      url: 'https://rebind.example.com',
      platform: 'new-api',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'linuxdo_1001',
      accessToken: 'old-access-token',
      status: 'expired',
    }).returning().get();

    const response = await app.inject({
      method: 'POST',
      url: `/api/accounts/${account.id}/rebind-session`,
      payload: {
        accessToken: 'new-access-token',
      },
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({
      success: false,
    });

    const latest = await db.select().from(schema.accounts).where(eq(schema.accounts.id, account.id)).get();
    expect(latest?.accessToken).toBe('old-access-token');
    expect(latest?.status).toBe('expired');
  });

  it('rejects non-string accessToken payload before session rebind verification', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'Rebind Site',
      url: 'https://rebind.example.com',
      platform: 'new-api',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'linuxdo_1001',
      accessToken: 'old-access-token',
      status: 'expired',
    }).returning().get();

    const response = await app.inject({
      method: 'POST',
      url: `/api/accounts/${account.id}/rebind-session`,
      payload: {
        accessToken: { value: 'bad-token' },
      },
    });

    expect(response.statusCode).toBe(400);
    expect((response.json() as { message?: string }).message).toContain('accessToken');
    expect(verifyTokenMock).not.toHaveBeenCalled();
  });

  it('returns rebind hint when verify reports invalid access token', async () => {
    verifyTokenMock.mockRejectedValueOnce(new Error('无权进行此操作，access token 无效'));

    const site = await db.insert(schema.sites).values({
      name: 'Rebind Site',
      url: 'https://rebind.example.com',
      platform: 'new-api',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'linuxdo_1001',
      accessToken: 'old-access-token',
      status: 'expired',
    }).returning().get();

    const response = await app.inject({
      method: 'POST',
      url: `/api/accounts/${account.id}/rebind-session`,
      payload: {
        accessToken: 'new-access-token',
      },
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({
      success: false,
      message: '无权进行此操作，access token 无效，请在中转站重新生成系统访问令牌后重新绑定账号',
    });
  });

  it('reactivates expired account when session token verification succeeds', async () => {
    verifyTokenMock.mockResolvedValueOnce({
      tokenType: 'session',
      userInfo: { username: 'linuxdo_1002' },
      apiToken: 'sk-rebound-token',
    });

    const site = await db.insert(schema.sites).values({
      name: 'Rebind Site',
      url: 'https://rebind.example.com',
      platform: 'new-api',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'linuxdo_1001',
      accessToken: 'old-access-token',
      status: 'expired',
      extraConfig: JSON.stringify({ platformUserId: 1001 }),
    }).returning().get();

    const response = await app.inject({
      method: 'POST',
      url: `/api/accounts/${account.id}/rebind-session`,
      payload: {
        accessToken: 'new-session-token',
      },
    });

    expect(response.statusCode).toBe(200);
    const body = response.json() as { success?: boolean; apiTokenFound?: boolean };
    expect(body.success).toBe(true);
    expect(body.apiTokenFound).toBe(true);

    const latest = await db.select().from(schema.accounts).where(eq(schema.accounts.id, account.id)).get();
    expect(latest?.accessToken).toBe('new-session-token');
    expect(latest?.apiToken).toBe('sk-rebound-token');
    expect(latest?.username).toBe('linuxdo_1002');
    expect(latest?.status).toBe('active');
  });

  it('stores managed sub2api refresh token fields when provided during rebind', async () => {
    verifyTokenMock.mockResolvedValueOnce({
      tokenType: 'session',
      userInfo: { username: 'sub2_user' },
    });

    const site = await db.insert(schema.sites).values({
      name: 'Sub2 Rebind Site',
      url: 'https://sub2.example.com',
      platform: 'sub2api',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'sub2_user',
      accessToken: 'old-access-token',
      status: 'expired',
      extraConfig: JSON.stringify({
        sub2apiAuth: {
          refreshToken: 'old-refresh-token',
          tokenExpiresAt: 1750000000000,
        },
      }),
    }).returning().get();

    const response = await app.inject({
      method: 'POST',
      url: `/api/accounts/${account.id}/rebind-session`,
      payload: {
        accessToken: 'new-session-token',
        refreshToken: 'new-refresh-token',
        tokenExpiresAt: 1760000000000,
      },
    });

    expect(response.statusCode).toBe(200);

    const latest = await db.select().from(schema.accounts).where(eq(schema.accounts.id, account.id)).get();
    const parsedExtra = JSON.parse(String(latest?.extraConfig || '{}')) as {
      sub2apiAuth?: { refreshToken?: string; tokenExpiresAt?: number };
    };
    expect(parsedExtra.sub2apiAuth?.refreshToken).toBe('new-refresh-token');
    expect(parsedExtra.sub2apiAuth?.tokenExpiresAt).toBe(1760000000000);
  });

  it('keeps existing sub2api refresh token when rebind payload refreshToken is empty', async () => {
    verifyTokenMock.mockResolvedValueOnce({
      tokenType: 'session',
      userInfo: { username: 'sub2_user' },
    });

    const site = await db.insert(schema.sites).values({
      name: 'Sub2 Rebind Site',
      url: 'https://sub2.example.com',
      platform: 'sub2api',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'sub2_user',
      accessToken: 'old-access-token',
      status: 'expired',
      extraConfig: JSON.stringify({
        sub2apiAuth: {
          refreshToken: 'kept-refresh-token',
          tokenExpiresAt: 1750000000000,
        },
      }),
    }).returning().get();

    const response = await app.inject({
      method: 'POST',
      url: `/api/accounts/${account.id}/rebind-session`,
      payload: {
        accessToken: 'new-session-token',
        refreshToken: '',
        tokenExpiresAt: 1760000000000,
      },
    });

    expect(response.statusCode).toBe(200);

    const latest = await db.select().from(schema.accounts).where(eq(schema.accounts.id, account.id)).get();
    const parsedExtra = JSON.parse(String(latest?.extraConfig || '{}')) as {
      sub2apiAuth?: { refreshToken?: string; tokenExpiresAt?: number };
    };
    expect(parsedExtra.sub2apiAuth?.refreshToken).toBe('kept-refresh-token');
    expect(parsedExtra.sub2apiAuth?.tokenExpiresAt).toBe(1760000000000);
  });

  it('ignores managed sub2api refresh token fields for non-sub2api rebind', async () => {
    verifyTokenMock.mockResolvedValueOnce({
      tokenType: 'session',
      userInfo: { username: 'linuxdo_1003' },
    });

    const site = await db.insert(schema.sites).values({
      name: 'Rebind Site',
      url: 'https://rebind.example.com',
      platform: 'new-api',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'linuxdo_1001',
      accessToken: 'old-access-token',
      status: 'expired',
      extraConfig: JSON.stringify({ platformUserId: 1001 }),
    }).returning().get();

    const response = await app.inject({
      method: 'POST',
      url: `/api/accounts/${account.id}/rebind-session`,
      payload: {
        accessToken: 'new-session-token',
        refreshToken: 'should-be-ignored',
        tokenExpiresAt: 1760000000000,
      },
    });

    expect(response.statusCode).toBe(200);

    const latest = await db.select().from(schema.accounts).where(eq(schema.accounts.id, account.id)).get();
    const parsedExtra = JSON.parse(String(latest?.extraConfig || '{}')) as {
      sub2apiAuth?: { refreshToken?: string; tokenExpiresAt?: number };
      platformUserId?: number;
    };
    expect(parsedExtra.platformUserId).toBe(1001);
    expect(parsedExtra.sub2apiAuth).toBeUndefined();
  });
});
