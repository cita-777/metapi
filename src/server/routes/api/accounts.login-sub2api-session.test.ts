import Fastify, { type FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const loginMock = vi.fn();

vi.mock('../../services/platforms/index.js', () => ({
  getAdapter: () => ({
    login: (...args: unknown[]) => loginMock(...args),
    getApiToken: async () => null,
    getApiTokens: async () => [],
  }),
}));

vi.mock('../../services/accountMutationWorkflow.js', () => ({
  convergeAccountMutation: vi.fn(async () => undefined),
  rebuildRoutesBestEffort: vi.fn(),
}));

// The login guard caps attempts per minute; these cases need more than the cap.
vi.mock('../../middleware/requestRateLimit.js', () => ({
  createRateLimitGuard: () => async () => undefined,
  resetRequestRateLimitStore: () => undefined,
}));

type DbModule = typeof import('../../db/index.js');
type ExtraConfigModule = typeof import('../../services/accountExtraConfig.js');

describe('accounts login for Sub2API sessions', () => {
  let app: FastifyInstance;
  let db: DbModule['db'];
  let schema: DbModule['schema'];
  let getSub2ApiAuthFromExtraConfig: ExtraConfigModule['getSub2ApiAuthFromExtraConfig'];
  let dataDir = '';

  beforeAll(async () => {
    dataDir = mkdtempSync(join(tmpdir(), 'metapi-accounts-login-sub2api-'));
    process.env.DATA_DIR = dataDir;

    await import('../../db/migrate.js');
    const dbModule = await import('../../db/index.js');
    const routesModule = await import('./accounts.js');
    const extraConfigModule = await import('../../services/accountExtraConfig.js');
    db = dbModule.db;
    schema = dbModule.schema;
    getSub2ApiAuthFromExtraConfig = extraConfigModule.getSub2ApiAuthFromExtraConfig;

    app = Fastify();
    await app.register(routesModule.accountsRoutes);
  });

  beforeEach(async () => {
    loginMock.mockReset();

    await db.delete(schema.accountTokens).run();
    await db.delete(schema.accounts).run();
    await db.delete(schema.sites).run();
  });

  afterAll(async () => {
    await app.close();
    if (dataDir) {
      try {
        rmSync(dataDir, { recursive: true, force: true });
      } catch {
        // Windows keeps the sqlite handle briefly; the temp dir is disposable.
      }
    }
    delete process.env.DATA_DIR;
  });

  async function createSub2ApiSite() {
    return db.insert(schema.sites).values({
      name: 'Nyro',
      url: 'https://sapi.nyro.lol',
      platform: 'sub2api',
    }).returning().get();
  }

  it('stores the refresh token and expiry returned by the password login', async () => {
    const site = await createSub2ApiSite();
    loginMock.mockResolvedValue({
      success: true,
      accessToken: 'jwt-token',
      refreshToken: 'rt-1',
      tokenExpiresAt: 1_700_000_000_000,
      username: 'alice',
      platformUserId: 42,
    });

    const response = await app.inject({
      method: 'POST',
      url: '/api/accounts/login',
      payload: {
        siteId: site.id,
        username: 'alice@example.com',
        password: 'secret',
      },
    });

    expect(response.statusCode).toBe(200);
    const body = response.json();
    expect(body.success).toBe(true);

    const accounts = await db.select().from(schema.accounts).all();
    expect(accounts).toHaveLength(1);
    expect(accounts[0].accessToken).toBe('jwt-token');
    expect(accounts[0].status).toBe('active');
    expect(getSub2ApiAuthFromExtraConfig(accounts[0].extraConfig)).toEqual({
      refreshToken: 'rt-1',
      tokenExpiresAt: 1_700_000_000_000,
    });
  });

  it('rotates the stored refresh token when the same account logs in again', async () => {
    const site = await createSub2ApiSite();
    loginMock.mockResolvedValue({
      success: true,
      accessToken: 'jwt-token-1',
      refreshToken: 'rt-1',
      platformUserId: 42,
    });

    await app.inject({
      method: 'POST',
      url: '/api/accounts/login',
      payload: { siteId: site.id, username: 'alice@example.com', password: 'secret' },
    });

    loginMock.mockResolvedValue({
      success: true,
      accessToken: 'jwt-token-2',
      refreshToken: 'rt-2',
      platformUserId: 42,
    });

    await app.inject({
      method: 'POST',
      url: '/api/accounts/login',
      payload: { siteId: site.id, username: 'alice@example.com', password: 'secret' },
    });

    const accounts = await db.select().from(schema.accounts).all();
    expect(accounts).toHaveLength(1);
    expect(accounts[0].accessToken).toBe('jwt-token-2');
    expect(getSub2ApiAuthFromExtraConfig(accounts[0].extraConfig)?.refreshToken).toBe('rt-2');
  });

  it('reuses the existing row when the site user id already has an account', async () => {
    const site = await createSub2ApiSite();
    loginMock.mockResolvedValue({
      success: true,
      accessToken: 'old-token',
      refreshToken: 'rt-old',
      username: '1129481742',
      platformUserId: 42,
    });

    // An account bound before password login stored the numeric site id.
    await app.inject({
      method: 'POST',
      url: '/api/accounts/login',
      payload: { siteId: site.id, username: '1129481742', password: 'secret' },
    });
    const existing = (await db.select().from(schema.accounts).all())[0];

    loginMock.mockResolvedValue({
      success: true,
      accessToken: 'jwt-token',
      refreshToken: 'rt-1',
      username: '1129481742@qq.com',
      platformUserId: 42,
    });

    const response = await app.inject({
      method: 'POST',
      url: '/api/accounts/login',
      payload: {
        siteId: site.id,
        username: '1129481742@qq.com',
        password: 'secret',
      },
    });

    expect(response.json().reusedAccount).toBe(true);

    const accounts = await db.select().from(schema.accounts).all();
    expect(accounts).toHaveLength(1);
    expect(accounts[0].id).toBe(existing.id);
    expect(accounts[0].username).toBe('1129481742');
    expect(accounts[0].accessToken).toBe('jwt-token');
  });

  it('does not create an account when the site rejects the credentials', async () => {
    const site = await createSub2ApiSite();
    loginMock.mockResolvedValue({
      success: false,
      message: 'Sub2API 登录失败：邮箱或密码不正确 (INVALID_CREDENTIALS)',
    });

    const response = await app.inject({
      method: 'POST',
      url: '/api/accounts/login',
      payload: { siteId: site.id, username: 'alice@example.com', password: 'wrong' },
    });

    expect(response.json().success).toBe(false);
    expect(response.json().message).toContain('邮箱或密码不正确');
    expect(await db.select().from(schema.accounts).all()).toHaveLength(0);
  });
});
