import Fastify, { type FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { eq } from 'drizzle-orm';

const { deleteApiTokenMock } = vi.hoisted(() => ({
  deleteApiTokenMock: vi.fn(),
}));

vi.mock('../../services/platforms/index.js', () => ({
  getAdapter: vi.fn(() => ({
    deleteApiToken: deleteApiTokenMock,
  })),
}));

type DbModule = typeof import('../../db/index.js');

describe('account token batch routes', () => {
  let app: FastifyInstance;
  let db: DbModule['db'];
  let schema: DbModule['schema'];
  let dataDir = '';

  beforeAll(async () => {
    dataDir = mkdtempSync(join(tmpdir(), 'metapi-account-tokens-batch-'));
    process.env.DATA_DIR = dataDir;

    await import('../../db/migrate.js');
    const dbModule = await import('../../db/index.js');
    const routesModule = await import('./accountTokens.js');
    db = dbModule.db;
    schema = dbModule.schema;

    app = Fastify();
    await app.register(routesModule.accountTokensRoutes);
  });

  beforeEach(async () => {
    deleteApiTokenMock.mockReset();
    deleteApiTokenMock.mockResolvedValue(true);
    await db.delete(schema.accountTokens).run();
    await db.delete(schema.accounts).run();
    await db.delete(schema.sites).run();

    await db.insert(schema.sites).values({
      id: 1,
      name: 'site-1',
      url: 'https://site-1.example.com',
      platform: 'new-api',
      status: 'active',
    }).run();

    await db.insert(schema.accounts).values({
      id: 1,
      siteId: 1,
      username: 'alpha',
      accessToken: 'session-alpha',
      status: 'active',
    }).run();

    await db.insert(schema.accountTokens).values([
      {
        id: 1,
        accountId: 1,
        name: 'token-1',
        token: 'sk-token-1',
        enabled: false,
      },
      {
        id: 2,
        accountId: 1,
        name: 'token-2',
        token: 'sk-token-2',
        enabled: false,
      },
    ]).run();
  });

  afterAll(async () => {
    await app.close();
    delete process.env.DATA_DIR;
  });

  it('enables selected account tokens and reports failures', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/account-tokens/batch',
      payload: {
        ids: [1, 2, 999],
        action: 'enable',
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

    const rows = await db.select().from(schema.accountTokens).all();
    expect(rows.every((row) => row.enabled === true)).toBe(true);
  });

  it('rejects enabling masked_pending placeholders until they are completed', async () => {
    await db.update(schema.accountTokens)
      .set({
        enabled: false,
        valueStatus: 'masked_pending' as any,
        token: 'sk-mask***tail',
      })
      .where(eq(schema.accountTokens.id, 1))
      .run();

    const response = await app.inject({
      method: 'POST',
      url: '/api/account-tokens/batch',
      payload: {
        ids: [1, 2],
        action: 'enable',
      },
    });

    expect(response.statusCode).toBe(200);
    const body = response.json() as {
      successIds?: number[];
      failedItems?: Array<{ id: number; message: string }>;
    };
    expect(body.successIds).toEqual([2]);
    expect(body.failedItems).toEqual([
      expect.objectContaining({
        id: 1,
        message: expect.stringContaining('待补全令牌'),
      }),
    ]);

    const rows = await db.select().from(schema.accountTokens).all();
    expect(rows.find((row) => row.id === 1)?.enabled).toBe(false);
    expect(rows.find((row) => row.id === 2)?.enabled).toBe(true);
  });

  it('deletes selected account tokens through the upstream adapter', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/account-tokens/batch',
      payload: {
        ids: [1],
        action: 'delete',
      },
    });

    expect(response.statusCode).toBe(200);
    expect(deleteApiTokenMock).toHaveBeenCalledTimes(1);
    const remaining = await db.select().from(schema.accountTokens).all();
    expect(remaining.map((item) => item.id)).toEqual([2]);
  });

  it('accepts the edit-panel payload when updating account token metadata without changing token value', async () => {
    const response = await app.inject({
      method: 'PUT',
      url: '/api/account-tokens/1',
      payload: {
        name: 'token-1-updated',
        group: 'default',
        enabled: true,
        isDefault: false,
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      success: true,
      token: {
        id: 1,
        name: 'token-1-updated',
        tokenGroup: 'default',
        enabled: true,
        isDefault: false,
      },
    });

    const row = await db.select().from(schema.accountTokens).where(eq(schema.accountTokens.id, 1)).get();
    expect(row).toMatchObject({
      name: 'token-1-updated',
      tokenGroup: 'default',
      enabled: true,
      isDefault: false,
    });
  });

  it('rejects invalid account token batch action', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/account-tokens/batch',
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
      url: '/api/account-tokens/batch',
      payload: {
        ids: [1, '2'],
        action: 'enable',
      },
    });

    expect(response.statusCode).toBe(400);
    expect((response.json() as { message?: string }).message).toContain('ids');
  });
});
