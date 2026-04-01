import Fastify, { type FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import Database from 'better-sqlite3';

type DbModule = typeof import('../../db/index.js');

describe('settings database migration api', () => {
  let app: FastifyInstance;
  let db: DbModule['db'];
  let schema: DbModule['schema'];
  let dataDir = '';

  beforeAll(async () => {
    dataDir = mkdtempSync(join(tmpdir(), 'metapi-settings-db-migration-'));
    process.env.DATA_DIR = dataDir;

    await import('../../db/migrate.js');
    const dbModule = await import('../../db/index.js');
    const settingsRoutesModule = await import('./settings.js');

    db = dbModule.db;
    schema = dbModule.schema;

    app = Fastify();
    await app.register(settingsRoutesModule.settingsRoutes);
  });

  beforeEach(async () => {
    await db.delete(schema.routeChannels).run();
    await db.delete(schema.tokenRoutes).run();
    await db.delete(schema.accountTokens).run();
    await db.delete(schema.accounts).run();
    await db.delete(schema.sites).run();
    await db.delete(schema.settings).run();
    await db.delete(schema.events).run();
  });

  afterAll(async () => {
    await app.close();
    delete process.env.DATA_DIR;
  });

  it('tests sqlite target connection from settings api', async () => {
    const targetPath = join(dataDir, 'target-connect.db');
    const response = await app.inject({
      method: 'POST',
      url: '/api/settings/database/test-connection',
      payload: {
        dialect: 'sqlite',
        connectionString: targetPath,
      },
    });

    expect(response.statusCode).toBe(200);
    const body = response.json() as { success?: boolean; dialect?: string };
    expect(body.success).toBe(true);
    expect(body.dialect).toBe('sqlite');
  });

  it('migrates current sqlite data to another sqlite file via settings api', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'Target Site',
      url: 'https://example.com',
      platform: 'new-api',
      status: 'active',
      proxyUrl: null,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'u1',
      accessToken: 'token-1',
      apiToken: null,
      status: 'active',
      checkinEnabled: true,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    }).returning().get();

    await db.insert(schema.accountTokens).values({
      accountId: account.id,
      name: 'default',
      token: 'sk-test',
      source: 'manual',
      enabled: true,
      isDefault: true,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    }).run();

    await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-4o-mini',
      modelMapping: null,
      enabled: true,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    }).run();

    await db.insert(schema.settings).values({
      key: 'routing_fallback_unit_cost',
      value: JSON.stringify(0.25),
    }).run();

    const targetPath = join(dataDir, 'target-migrate.db');
    const response = await app.inject({
      method: 'POST',
      url: '/api/settings/database/migrate',
      payload: {
        dialect: 'sqlite',
        connectionString: targetPath,
        overwrite: true,
      },
    });

    expect(response.statusCode).toBe(200);
    const body = response.json() as { success?: boolean; rows?: Record<string, number> };
    expect(body.success).toBe(true);
    expect(body.rows?.sites).toBe(1);
    expect(body.rows?.accounts).toBe(1);
    expect(body.rows?.accountTokens).toBe(1);
    expect(body.rows?.settings).toBe(1);

    const targetDb = new Database(targetPath);
    try {
      const targetSites = targetDb.prepare('SELECT COUNT(*) AS cnt FROM sites').get() as { cnt: number };
      const targetAccounts = targetDb.prepare('SELECT COUNT(*) AS cnt FROM accounts').get() as { cnt: number };
      const targetSettings = targetDb.prepare('SELECT COUNT(*) AS cnt FROM settings').get() as { cnt: number };

      expect(targetSites.cnt).toBe(1);
      expect(targetAccounts.cnt).toBe(1);
      expect(targetSettings.cnt).toBe(1);
    } finally {
      targetDb.close();
    }
  });

  it('rejects non-boolean overwrite payload when migrating through settings api', async () => {
    const targetPath = join(dataDir, 'target-migrate-invalid.db');
    const response = await app.inject({
      method: 'POST',
      url: '/api/settings/database/migrate',
      payload: {
        dialect: 'sqlite',
        connectionString: targetPath,
        overwrite: 'false',
      },
    });

    expect(response.statusCode).toBe(400);
    expect((response.json() as { message?: string }).message).toContain('overwrite');
  });
});
