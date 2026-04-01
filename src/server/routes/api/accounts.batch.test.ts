import Fastify, { type FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

const { refreshBalanceMock } = vi.hoisted(() => ({
  refreshBalanceMock: vi.fn(),
}));

vi.mock('../../services/balanceService.js', () => ({
  refreshBalance: refreshBalanceMock,
}));

type DbModule = typeof import('../../db/index.js');

describe('accounts batch routes', () => {
  let app: FastifyInstance;
  let db: DbModule['db'];
  let schema: DbModule['schema'];
  let dataDir = '';

  beforeAll(async () => {
    dataDir = mkdtempSync(join(tmpdir(), 'metapi-accounts-batch-'));
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
    refreshBalanceMock.mockReset();
    refreshBalanceMock.mockImplementation(async (id: number) => {
      if (id === 999) return null;
      return { id, balance: 12.5 };
    });
    await db.delete(schema.accountTokens).run();
    await db.delete(schema.accounts).run();
    await db.delete(schema.sites).run();

    await db.insert(schema.sites).values({
      id: 1,
      name: 'site-1',
      url: 'https://site-1.example.com',
      platform: 'new-api',
    }).run();

    await db.insert(schema.accounts).values([
      {
        id: 1,
        siteId: 1,
        username: 'alpha',
        accessToken: 'session-alpha',
        status: 'active',
      },
      {
        id: 2,
        siteId: 1,
        username: 'beta',
        accessToken: 'session-beta',
        status: 'active',
      },
    ]).run();
  });

  afterAll(async () => {
    await app.close();
    delete process.env.DATA_DIR;
  });

  it('refreshes balance for selected accounts and reports failures', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/accounts/batch',
      payload: {
        ids: [1, 2, 999],
        action: 'refreshBalance',
      },
    });

    expect(response.statusCode).toBe(200);
    const body = response.json() as {
      successIds?: number[];
      failedItems?: Array<{ id: number; message: string }>;
    };
    expect(body.successIds).toEqual([1, 2]);
    expect(body.failedItems).toHaveLength(1);
    expect(body.failedItems?.[0]?.id).toBe(999);
    expect(refreshBalanceMock).toHaveBeenCalledTimes(3);
  });

  it('rejects invalid accounts batch action', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/accounts/batch',
      payload: {
        ids: [1],
        action: 'nope',
      },
    });

    expect(response.statusCode).toBe(400);
    expect((response.json() as { message?: string }).message).toContain('action');
  });

  it('rejects batch payloads whose ids include non-number values', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/accounts/batch',
      payload: {
        ids: [1, '2'],
        action: 'enable',
      },
    });

    expect(response.statusCode).toBe(400);
    expect((response.json() as { message?: string }).message).toContain('ids');
  });
});
