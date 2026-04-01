import Fastify, { type FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { asc, eq } from 'drizzle-orm';

type DbModule = typeof import('../../db/index.js');

describe('sites api endpoints', () => {
  let app: FastifyInstance;
  let db: DbModule['db'];
  let schema: DbModule['schema'];
  let dataDir = '';

  beforeAll(async () => {
    dataDir = mkdtempSync(join(tmpdir(), 'metapi-sites-api-endpoints-'));
    process.env.DATA_DIR = dataDir;

    await import('../../db/migrate.js');
    const dbModule = await import('../../db/index.js');
    const routesModule = await import('./sites.js');
    db = dbModule.db;
    schema = dbModule.schema;

    app = Fastify();
    await app.register(routesModule.sitesRoutes);
  });

  beforeEach(async () => {
    await db.delete(schema.accounts).run();
    await db.delete(schema.siteApiEndpoints).run();
    await db.delete(schema.sites).run();
  });

  afterAll(async () => {
    await app.close();
    delete process.env.DATA_DIR;
  });

  it('accepts apiEndpoints on create and returns them in stable sort order with server-owned metadata', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/sites',
      payload: {
        name: 'split-host-site',
        url: 'https://panel.example.com',
        platform: 'new-api',
        apiEndpoints: [
          {
            url: 'https://api-b.example.com',
            enabled: false,
            sortOrder: 1,
            cooldownUntil: '2099-01-01T00:00:00.000Z',
            lastFailureReason: 'should-be-ignored',
          },
          {
            url: 'https://api-a.example.com/',
            enabled: true,
            sortOrder: 0,
            lastSelectedAt: '2099-01-01T00:00:00.000Z',
          },
        ],
      },
    });

    expect(response.statusCode).toBe(200);
    const payload = response.json() as {
      id: number;
      apiEndpoints?: Array<Record<string, unknown>>;
    };
    expect(payload.apiEndpoints).toEqual([
      expect.objectContaining({
        url: 'https://api-a.example.com',
        enabled: true,
        sortOrder: 0,
        cooldownUntil: null,
        lastSelectedAt: null,
        lastFailedAt: null,
        lastFailureReason: null,
      }),
      expect.objectContaining({
        url: 'https://api-b.example.com',
        enabled: false,
        sortOrder: 1,
        cooldownUntil: null,
        lastSelectedAt: null,
        lastFailedAt: null,
        lastFailureReason: null,
      }),
    ]);

    const stored = await db.select().from(schema.siteApiEndpoints)
      .where(eq(schema.siteApiEndpoints.siteId, payload.id))
      .orderBy(asc(schema.siteApiEndpoints.sortOrder), asc(schema.siteApiEndpoints.id))
      .all();
    expect(stored.map((row) => row.url)).toEqual([
      'https://api-a.example.com',
      'https://api-b.example.com',
    ]);
  });

  it('replaces apiEndpoints on update', async () => {
    const created = await app.inject({
      method: 'POST',
      url: '/api/sites',
      payload: {
        name: 'replace-site',
        url: 'https://panel.example.com',
        platform: 'new-api',
        apiEndpoints: [
          { url: 'https://api-old.example.com', enabled: true, sortOrder: 0 },
        ],
      },
    });
    expect(created.statusCode).toBe(200);
    const site = created.json() as { id: number };

    const updated = await app.inject({
      method: 'PUT',
      url: `/api/sites/${site.id}`,
      payload: {
        apiEndpoints: [
          { url: 'https://api-b.example.com', enabled: true, sortOrder: 1 },
          { url: 'https://api-a.example.com', enabled: false, sortOrder: 0 },
        ],
      },
    });

    expect(updated.statusCode).toBe(200);
    const payload = updated.json() as { apiEndpoints?: Array<Record<string, unknown>> };
    expect(payload.apiEndpoints).toEqual([
      expect.objectContaining({
        url: 'https://api-a.example.com',
        enabled: false,
        sortOrder: 0,
      }),
      expect.objectContaining({
        url: 'https://api-b.example.com',
        enabled: true,
        sortOrder: 1,
      }),
    ]);

    const stored = await db.select().from(schema.siteApiEndpoints)
      .where(eq(schema.siteApiEndpoints.siteId, site.id))
      .orderBy(asc(schema.siteApiEndpoints.sortOrder), asc(schema.siteApiEndpoints.id))
      .all();
    expect(stored.map((row) => row.url)).toEqual([
      'https://api-a.example.com',
      'https://api-b.example.com',
    ]);
  });

  it('rejects duplicate api endpoint urls under the same site after normalization', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/sites',
      payload: {
        name: 'duplicate-endpoints-site',
        url: 'https://panel.example.com',
        platform: 'new-api',
        apiEndpoints: [
          { url: 'https://api.example.com/', enabled: true, sortOrder: 0 },
          { url: 'https://api.example.com', enabled: false, sortOrder: 1 },
        ],
      },
    });

    expect(response.statusCode).toBe(400);
    expect((response.json() as { error?: string }).error).toContain('Duplicate apiEndpoints url');
  });

  it('includes apiEndpoints in GET /api/sites using stable endpoint order', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'listed-site',
      url: 'https://panel.example.com',
      platform: 'new-api',
      status: 'active',
    }).returning().get();

    await db.insert(schema.siteApiEndpoints).values([
      {
        siteId: site.id,
        url: 'https://api-b.example.com',
        enabled: true,
        sortOrder: 1,
        cooldownUntil: '2026-03-31T12:05:00.000Z',
        lastFailedAt: '2026-03-31T12:00:00.000Z',
        lastFailureReason: 'HTTP 502',
      },
      {
        siteId: site.id,
        url: 'https://api-a.example.com',
        enabled: false,
        sortOrder: 0,
      },
    ]).run();

    const response = await app.inject({
      method: 'GET',
      url: '/api/sites',
    });

    expect(response.statusCode).toBe(200);
    const payload = response.json() as Array<{
      id: number;
      apiEndpoints?: Array<Record<string, unknown>>;
    }>;
    const listed = payload.find((row) => row.id === site.id);
    expect(listed?.apiEndpoints).toEqual([
      expect.objectContaining({
        url: 'https://api-a.example.com',
        enabled: false,
        sortOrder: 0,
      }),
      expect.objectContaining({
        url: 'https://api-b.example.com',
        enabled: true,
        sortOrder: 1,
        cooldownUntil: '2026-03-31T12:05:00.000Z',
        lastFailureReason: 'HTTP 502',
      }),
    ]);
  });
});
