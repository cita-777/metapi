import Fastify, { type FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { eq } from 'drizzle-orm';

const getModelsMock = vi.fn();

vi.mock('../../services/platforms/index.js', () => ({
  getAdapter: () => ({
    getModels: (...args: unknown[]) => getModelsMock(...args),
  }),
}));

type DbModule = typeof import('../../db/index.js');

describe('accounts api key recovery', { timeout: 15_000 }, () => {
  let app: FastifyInstance;
  let db: DbModule['db'];
  let schema: DbModule['schema'];
  let dataDir = '';

  beforeAll(async () => {
    dataDir = mkdtempSync(join(tmpdir(), 'metapi-accounts-apikey-recovery-'));
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
    getModelsMock.mockReset();

    await db.delete(schema.proxyLogs).run();
    await db.delete(schema.checkinLogs).run();
    await db.delete(schema.routeChannels).run();
    await db.delete(schema.tokenRoutes).run();
    await db.delete(schema.tokenModelAvailability).run();
    await db.delete(schema.modelAvailability).run();
    await db.delete(schema.accountTokens).run();
    await db.delete(schema.siteApiEndpoints).run();
    await db.delete(schema.accounts).run();
    await db.delete(schema.sites).run();
  });

  afterAll(async () => {
    await app.close();
    delete process.env.DATA_DIR;
  });

  it('reactivates an expired API key connection after editing in a working replacement key', async () => {
    getModelsMock.mockResolvedValueOnce(['gpt-4.1']);

    const site = await db.insert(schema.sites).values({
      name: 'Recovery Site',
      url: 'https://recovery.example.com',
      platform: 'new-api',
      status: 'active',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'expired-apikey-user',
      accessToken: '',
      apiToken: 'sk-old-expired-key',
      status: 'expired',
      checkinEnabled: false,
      extraConfig: JSON.stringify({ credentialMode: 'apikey' }),
    }).returning().get();

    const response = await app.inject({
      method: 'PUT',
      url: `/api/accounts/${account.id}`,
      payload: {
        username: 'expired-apikey-user',
        status: 'expired',
        checkinEnabled: false,
        accessToken: '',
        apiToken: 'sk-new-valid-key',
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      id: account.id,
      status: 'active',
      apiToken: 'sk-new-valid-key',
    });

    const latest = await db.select().from(schema.accounts).where(eq(schema.accounts.id, account.id)).get();
    expect(latest).toMatchObject({
      id: account.id,
      status: 'active',
      apiToken: 'sk-new-valid-key',
    });

    const availabilityRows = await db.select().from(schema.modelAvailability)
      .where(eq(schema.modelAvailability.accountId, account.id))
      .all();
    expect(availabilityRows.map((row) => row.modelName)).toContain('gpt-4.1');

    const routeChannels = await db.select().from(schema.routeChannels).all();
    expect(routeChannels.some((channel) => channel.accountId === account.id)).toBe(true);
  });

  it('keeps an expired API key connection pinned when only status is edited', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'Pinned Site',
      url: 'https://pinned.example.com',
      platform: 'new-api',
      status: 'active',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'status-only-user',
      accessToken: '',
      apiToken: 'sk-still-expired',
      status: 'expired',
      checkinEnabled: false,
      extraConfig: JSON.stringify({ credentialMode: 'apikey' }),
    }).returning().get();

    const response = await app.inject({
      method: 'PUT',
      url: `/api/accounts/${account.id}`,
      payload: {
        username: 'status-only-user-edited',
        status: 'active',
        checkinEnabled: false,
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      id: account.id,
      username: 'status-only-user-edited',
      status: 'expired',
    });
    expect(getModelsMock).not.toHaveBeenCalled();
  });

  it('keeps the new api key but preserves expired status and previous availability when recovery fails', async () => {
    getModelsMock.mockRejectedValueOnce(new Error('upstream unavailable'));

    const site = await db.insert(schema.sites).values({
      name: 'Recovery Failure Site',
      url: 'https://recovery-failure.example.com',
      platform: 'new-api',
      status: 'active',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'expired-apikey-user',
      accessToken: '',
      apiToken: 'sk-old-expired-key',
      status: 'expired',
      checkinEnabled: false,
      extraConfig: JSON.stringify({ credentialMode: 'apikey' }),
    }).returning().get();

    await db.insert(schema.modelAvailability).values({
      accountId: account.id,
      modelName: 'gpt-4.1',
      available: true,
      latencyMs: 100,
      checkedAt: '2026-04-01T10:00:00.000Z',
    }).run();

    const route = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-4.1',
      enabled: true,
    }).returning().get();

    const seededChannel = await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: account.id,
      tokenId: null,
      priority: 0,
      weight: 10,
      enabled: true,
      manualOverride: false,
    }).returning().get();

    const response = await app.inject({
      method: 'PUT',
      url: `/api/accounts/${account.id}`,
      payload: {
        username: 'expired-apikey-user',
        status: 'expired',
        checkinEnabled: false,
        accessToken: '',
        apiToken: 'sk-new-invalid-key',
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      id: account.id,
      status: 'expired',
      apiToken: 'sk-new-invalid-key',
    });

    const latest = await db.select().from(schema.accounts).where(eq(schema.accounts.id, account.id)).get();
    expect(latest).toMatchObject({
      id: account.id,
      status: 'expired',
      apiToken: 'sk-new-invalid-key',
    });

    const availabilityRows = await db.select().from(schema.modelAvailability)
      .where(eq(schema.modelAvailability.accountId, account.id))
      .all();
    expect(availabilityRows).toHaveLength(1);
    expect(availabilityRows[0]).toMatchObject({
      accountId: account.id,
      modelName: 'gpt-4.1',
    });

    const routeChannels = await db.select().from(schema.routeChannels).all();
    expect(routeChannels).toContainEqual(expect.objectContaining({
      id: seededChannel.id,
      routeId: route.id,
      accountId: account.id,
      tokenId: null,
    }));
  });
});
