import Fastify, { type FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { eq } from 'drizzle-orm';

const getApiTokensMock = vi.fn();
const getApiTokenMock = vi.fn();
const createApiTokenMock = vi.fn();
const getUserGroupsMock = vi.fn();
const deleteApiTokenMock = vi.fn();
const getModelsMock = vi.fn();

vi.mock('../../services/platforms/index.js', () => ({
  getAdapter: () => ({
    getApiTokens: (...args: unknown[]) => getApiTokensMock(...args),
    getApiToken: (...args: unknown[]) => getApiTokenMock(...args),
    createApiToken: (...args: unknown[]) => createApiTokenMock(...args),
    getUserGroups: (...args: unknown[]) => getUserGroupsMock(...args),
    deleteApiToken: (...args: unknown[]) => deleteApiTokenMock(...args),
    getModels: (...args: unknown[]) => getModelsMock(...args),
  }),
}));

type DbModule = typeof import('../../db/index.js');

describe('account token coverage refresh', { timeout: 15_000 }, () => {
  let app: FastifyInstance;
  let db: DbModule['db'];
  let schema: DbModule['schema'];
  let dataDir = '';
  let seedId = 0;

  const nextSeed = () => {
    seedId += 1;
    return seedId;
  };

  const seedAccount = async (modelName: string) => {
    const id = nextSeed();
    const site = await db.insert(schema.sites).values({
      name: `site-${id}`,
      url: `https://site-${id}.example.com`,
      platform: 'new-api',
      status: 'active',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: `user-${id}`,
      accessToken: `acc-token-${id}`,
      status: 'active',
    }).returning().get();

    await db.insert(schema.modelAvailability).values({
      accountId: account.id,
      modelName,
      available: true,
    }).run();

    return { site, account };
  };

  const readTokenCandidates = async () => {
    const response = await app.inject({
      method: 'GET',
      url: '/api/models/token-candidates',
    });
    expect(response.statusCode).toBe(200);
    return response.json() as {
      models: Record<string, Array<{ tokenId: number; accountId: number }>>;
      modelsWithoutToken: Record<string, Array<{ accountId: number }>>;
    };
  };

  beforeAll(async () => {
    dataDir = mkdtempSync(join(tmpdir(), 'metapi-account-token-coverage-'));
    process.env.DATA_DIR = dataDir;

    await import('../../db/migrate.js');
    const dbModule = await import('../../db/index.js');
    const accountTokenRoutesModule = await import('./accountTokens.js');
    const statsRoutesModule = await import('./stats.js');
    db = dbModule.db;
    schema = dbModule.schema;

    app = Fastify();
    await app.register(accountTokenRoutesModule.accountTokensRoutes);
    await app.register(statsRoutesModule.statsRoutes);
  });

  beforeEach(async () => {
    getApiTokensMock.mockReset();
    getApiTokenMock.mockReset();
    createApiTokenMock.mockReset();
    getUserGroupsMock.mockReset();
    deleteApiTokenMock.mockReset();
    getModelsMock.mockReset();
    seedId = 0;

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

  it('refreshes token coverage after manually adding an account token', async () => {
    const modelName = 'gpt-4o-mini';
    const { account } = await seedAccount(modelName);
    getModelsMock.mockImplementation(async (_url: string, credential: string) => {
      if (credential === account.accessToken || credential === 'sk-manual-token') {
        return [modelName];
      }
      return [];
    });

    const response = await app.inject({
      method: 'POST',
      url: '/api/account-tokens',
      payload: {
        accountId: account.id,
        name: 'manual-token',
        token: 'sk-manual-token',
      },
    });

    expect(response.statusCode).toBe(200);

    const token = await db.select()
      .from(schema.accountTokens)
      .where(eq(schema.accountTokens.accountId, account.id))
      .get();
    expect(token).toBeDefined();

    const tokenAvailability = await db.select()
      .from(schema.tokenModelAvailability)
      .where(eq(schema.tokenModelAvailability.tokenId, token!.id))
      .all();
    expect(tokenAvailability.map((row) => row.modelName)).toContain(modelName);

    const candidates = await readTokenCandidates();
    expect(candidates.modelsWithoutToken[modelName]).toBeUndefined();
    expect(candidates.models[modelName]).toEqual([
      expect.objectContaining({
        accountId: account.id,
        tokenId: token!.id,
      }),
    ]);
  });

  it('refreshes token coverage after syncing account tokens from upstream', async () => {
    const modelName = 'claude-sonnet-4-5-20250929';
    const { account } = await seedAccount(modelName);
    getApiTokensMock.mockResolvedValue([
      { name: 'default', key: 'sk-synced-token', enabled: true },
    ]);
    getModelsMock.mockImplementation(async (_url: string, credential: string) => {
      if (credential === account.accessToken || credential === 'sk-synced-token') {
        return [modelName];
      }
      return [];
    });

    const response = await app.inject({
      method: 'POST',
      url: `/api/account-tokens/sync/${account.id}`,
    });

    expect(response.statusCode).toBe(200);

    const token = await db.select()
      .from(schema.accountTokens)
      .where(eq(schema.accountTokens.accountId, account.id))
      .get();
    expect(token).toBeDefined();

    const tokenAvailability = await db.select()
      .from(schema.tokenModelAvailability)
      .where(eq(schema.tokenModelAvailability.tokenId, token!.id))
      .all();
    expect(tokenAvailability.map((row) => row.modelName)).toContain(modelName);

    const candidates = await readTokenCandidates();
    expect(candidates.modelsWithoutToken[modelName]).toBeUndefined();
    expect(candidates.models[modelName]).toEqual([
      expect.objectContaining({
        accountId: account.id,
        tokenId: token!.id,
      }),
    ]);
  });
});
