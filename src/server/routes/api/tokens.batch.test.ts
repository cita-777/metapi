import Fastify, { type FastifyInstance } from 'fastify';
import { describe, expect, it, beforeAll, beforeEach, afterAll } from 'vitest';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { mkdtempSync } from 'node:fs';
import { eq } from 'drizzle-orm';

type DbModule = typeof import('../../db/index.js');

describe('PUT /api/channels/batch', () => {
  let app: FastifyInstance;
  let db: DbModule['db'];
  let schema: DbModule['schema'];
  let dataDir = '';
  let seedId = 0;

  const nextId = () => {
    seedId += 1;
    return seedId;
  };

  const seedChannel = async (options: { priority: number; weight: number; manualOverride?: boolean }) => {
    const id = nextId();
    const site = await db.insert(schema.sites).values({
      name: `site-${id}`,
      url: `https://example.com/${id}`,
      platform: 'new-api',
    }).returning().get();
    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      accessToken: `access-token-${id}`,
      apiToken: `api-token-${id}`,
    }).returning().get();
    const route = await db.insert(schema.tokenRoutes).values({
      modelPattern: `gpt-4o-${id}`,
      enabled: true,
    }).returning().get();

    return await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: account.id,
      priority: options.priority,
      weight: options.weight,
      manualOverride: options.manualOverride ?? false,
    }).returning().get();
  };

  beforeAll(async () => {
    dataDir = mkdtempSync(join(tmpdir(), 'metapi-tokens-batch-'));
    process.env.DATA_DIR = dataDir;

    await import('../../db/migrate.js');
    const dbModule = await import('../../db/index.js');
    const routesModule = await import('./tokens.js');
    db = dbModule.db;
    schema = dbModule.schema;

    app = Fastify();
    await app.register(routesModule.tokensRoutes);
  });

  beforeEach(async () => {
    await db.delete(schema.routeChannels).run();
    await db.delete(schema.accountTokens).run();
    await db.delete(schema.tokenRoutes).run();
    await db.delete(schema.accounts).run();
    await db.delete(schema.sites).run();
  });

  afterAll(async () => {
    await app.close();
  });

  it('returns 400 when updates is missing or empty', async () => {
    const missingRes = await app.inject({
      method: 'PUT',
      url: '/api/channels/batch',
      payload: {},
    });
    expect(missingRes.statusCode).toBe(400);
    expect(missingRes.json()).toMatchObject({ success: false });

    const emptyRes = await app.inject({
      method: 'PUT',
      url: '/api/channels/batch',
      payload: { updates: [] },
    });
    expect(emptyRes.statusCode).toBe(400);
    expect(emptyRes.json()).toMatchObject({ success: false });
  });

  it('returns 400 when an update item is invalid', async () => {
    const invalidIdRes = await app.inject({
      method: 'PUT',
      url: '/api/channels/batch',
      payload: {
        updates: [{ id: '1', priority: 1 }],
      },
    });
    expect(invalidIdRes.statusCode).toBe(400);
    expect(invalidIdRes.json()).toMatchObject({ success: false });

    const invalidPriorityRes = await app.inject({
      method: 'PUT',
      url: '/api/channels/batch',
      payload: {
        updates: [{ id: 1, priority: null }],
      },
    });
    expect(invalidPriorityRes.statusCode).toBe(400);
    expect(invalidPriorityRes.json()).toMatchObject({ success: false });
  });

  it('updates priorities in batch, sets manualOverride, and keeps weight unchanged', async () => {
    const channelA = await seedChannel({ priority: 9, weight: 17, manualOverride: false });
    const channelB = await seedChannel({ priority: 8, weight: 23, manualOverride: false });

    const res = await app.inject({
      method: 'PUT',
      url: '/api/channels/batch',
      payload: {
        updates: [
          { id: channelA.id, priority: 3.8 },
          { id: channelB.id, priority: -7.2 },
        ],
      },
    });

    expect(res.statusCode).toBe(200);
    const body = res.json() as {
      success: boolean;
      channels: Array<{ id: number; priority: number; weight: number; manualOverride: boolean }>;
    };
    expect(body.success).toBe(true);
    expect(body.channels).toHaveLength(2);

    const returnedA = body.channels.find((channel) => channel.id === channelA.id);
    const returnedB = body.channels.find((channel) => channel.id === channelB.id);
    expect(returnedA).toBeDefined();
    expect(returnedB).toBeDefined();
    expect(returnedA?.priority).toBe(3);
    expect(returnedB?.priority).toBe(0);
    expect(returnedA?.weight).toBe(17);
    expect(returnedB?.weight).toBe(23);
    expect(returnedA?.manualOverride).toBe(true);
    expect(returnedB?.manualOverride).toBe(true);

    const dbA = await db.select().from(schema.routeChannels).where(eq(schema.routeChannels.id, channelA.id)).get();
    const dbB = await db.select().from(schema.routeChannels).where(eq(schema.routeChannels.id, channelB.id)).get();
    expect(dbA?.priority).toBe(3);
    expect(dbB?.priority).toBe(0);
    expect(dbA?.weight).toBe(17);
    expect(dbB?.weight).toBe(23);
    expect(dbA?.manualOverride).toBe(true);
    expect(dbB?.manualOverride).toBe(true);
  });

  it('reports the number of routes actually updated in route batch operations', async () => {
    const route = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-4o-mini',
      enabled: true,
    }).returning().get();

    const res = await app.inject({
      method: 'POST',
      url: '/api/routes/batch',
      payload: {
        ids: [route.id, route.id + 999],
        action: 'disable',
      },
    });

    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({
      success: true,
      updatedCount: 1,
    });

    const updatedRoute = await db.select().from(schema.tokenRoutes).where(eq(schema.tokenRoutes.id, route.id)).get();
    expect(updatedRoute?.enabled).toBe(false);
  });

  it('rejects route batch payloads whose ids include non-number values', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/api/routes/batch',
      payload: {
        ids: ['1'],
        action: 'disable',
      },
    });

    expect(res.statusCode).toBe(400);
    expect(res.json()).toMatchObject({
      success: false,
      message: 'Invalid ids. Expected number[].',
    });
  });

  it('rejects non-boolean wait when rebuilding routes', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/api/routes/rebuild',
      payload: {
        wait: 'true',
      },
    });

    expect(res.statusCode).toBe(400);
    expect(res.json()).toMatchObject({
      success: false,
      message: 'Invalid wait. Expected boolean.',
    });
  });
});
