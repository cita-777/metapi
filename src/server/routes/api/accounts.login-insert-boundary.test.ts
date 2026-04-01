import Fastify, { type FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const loginMock = vi.fn();
const getApiTokenMock = vi.fn();
const getApiTokensMock = vi.fn();
const convergeAccountMutationMock = vi.fn();

vi.mock('../../services/platforms/index.js', () => ({
  getAdapter: () => ({
    login: (...args: unknown[]) => loginMock(...args),
    getApiToken: (...args: unknown[]) => getApiTokenMock(...args),
    getApiTokens: (...args: unknown[]) => getApiTokensMock(...args),
  }),
}));

vi.mock('../../services/accountMutationWorkflow.js', () => ({
  convergeAccountMutation: (...args: unknown[]) => convergeAccountMutationMock(...args),
  rebuildRoutesBestEffort: vi.fn(),
}));

vi.mock('../../db/insertHelpers.js', async () => {
  const actual = await vi.importActual<typeof import('../../db/insertHelpers.js')>('../../db/insertHelpers.js');
  return {
    ...actual,
    insertAndGetById: vi.fn(async () => {
      throw new Error('account create failed');
    }),
  };
});

type DbModule = typeof import('../../db/index.js');

describe('accounts login insert boundary', () => {
  let app: FastifyInstance;
  let db: DbModule['db'];
  let schema: DbModule['schema'];
  let dataDir = '';

  beforeAll(async () => {
    dataDir = mkdtempSync(join(tmpdir(), 'metapi-accounts-login-insert-boundary-'));
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
    getApiTokenMock.mockReset();
    getApiTokensMock.mockReset();
    convergeAccountMutationMock.mockReset();

    await db.delete(schema.accountTokens).run();
    await db.delete(schema.accounts).run();
    await db.delete(schema.sites).run();
  });

  afterAll(async () => {
    await app.close();
    if (dataDir) {
      rmSync(dataDir, { recursive: true, force: true });
    }
    delete process.env.DATA_DIR;
  });

  it('fails fast when login account creation cannot complete through the shared insert helper', async () => {
    loginMock.mockResolvedValue({
      success: true,
      accessToken: 'session-token',
    });
    getApiTokenMock.mockResolvedValue(null);
    getApiTokensMock.mockResolvedValue([]);
    convergeAccountMutationMock.mockResolvedValue(undefined);

    const site = await db.insert(schema.sites).values({
      name: 'Login Site',
      url: 'https://login.example.com',
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

    expect(response.statusCode).toBe(500);
    expect(await db.select().from(schema.accounts).all()).toHaveLength(0);
    expect(convergeAccountMutationMock).not.toHaveBeenCalled();
  });
});
