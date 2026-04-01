import Fastify, { type FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { eq } from 'drizzle-orm';

type DbModule = typeof import('../../db/index.js');
type ConfigModule = typeof import('../../config.js');

describe('settings database runtime config api', () => {
  let app: FastifyInstance;
  let db: DbModule['db'];
  let schema: DbModule['schema'];
  let config: ConfigModule['config'];
  let dataDir = '';

  beforeAll(async () => {
    dataDir = mkdtempSync(join(tmpdir(), 'metapi-settings-db-runtime-'));
    process.env.DATA_DIR = dataDir;

    await import('../../db/migrate.js');
    const dbModule = await import('../../db/index.js');
    const configModule = await import('../../config.js');
    const settingsRoutesModule = await import('./settings.js');

    db = dbModule.db;
    schema = dbModule.schema;
    config = configModule.config;

    app = Fastify();
    await app.register(settingsRoutesModule.settingsRoutes);
  });

  beforeEach(async () => {
    await db.delete(schema.settings).run();
    await db.delete(schema.events).run();

    config.dbType = 'sqlite';
    config.dbUrl = '';
  });

  afterAll(async () => {
    await app.close();
    delete process.env.DATA_DIR;
  });

  it('gets runtime database config state', async () => {
    const response = await app.inject({
      method: 'GET',
      url: '/api/settings/database/runtime',
    });

    expect(response.statusCode).toBe(200);
    const body = response.json() as {
      success?: boolean;
      active?: { dialect?: string };
      saved?: unknown;
      restartRequired?: boolean;
    };
    expect(body.success).toBe(true);
    expect(body.active?.dialect).toBe('sqlite');
    expect(body.saved).toBeNull();
    expect(body.restartRequired).toBe(false);
  });

  it('saves runtime database config and marks restart required', async () => {
    const response = await app.inject({
      method: 'PUT',
      url: '/api/settings/database/runtime',
      payload: {
        dialect: 'postgres',
        connectionString: 'postgres://metapi:secret@127.0.0.1:5432/postgres',
      },
    });

    expect(response.statusCode).toBe(200);
    const body = response.json() as {
      success?: boolean;
      saved?: { dialect?: string; connection?: string };
      restartRequired?: boolean;
    };
    expect(body.success).toBe(true);
    expect(body.saved?.dialect).toBe('postgres');
    expect(body.saved?.connection).toContain('***');
    expect(body.restartRequired).toBe(true);

    const dbType = await db.select().from(schema.settings).where(eq(schema.settings.key, 'db_type')).get();
    const dbUrl = await db.select().from(schema.settings).where(eq(schema.settings.key, 'db_url')).get();
    expect(dbType?.value).toBe(JSON.stringify('postgres'));
    expect(dbUrl?.value).toBe(JSON.stringify('postgres://metapi:secret@127.0.0.1:5432/postgres'));
  });

  it('rejects invalid runtime database config payload', async () => {
    const response = await app.inject({
      method: 'PUT',
      url: '/api/settings/database/runtime',
      payload: {
        dialect: 'postgres',
        connectionString: 'mysql://root:pass@127.0.0.1:3306/mysql',
      },
    });

    expect(response.statusCode).toBe(400);
    const body = response.json() as { success?: boolean; message?: string };
    expect(body.success).toBe(false);
    expect(body.message || '').toContain('postgres');
  });

  it('rejects sqlite dialect with network url connection string', async () => {
    const response = await app.inject({
      method: 'PUT',
      url: '/api/settings/database/runtime',
      payload: {
        dialect: 'sqlite',
        connectionString: 'postgres://metapi:secret@127.0.0.1:5432/postgres',
      },
    });

    expect(response.statusCode).toBe(400);
    const body = response.json() as { success?: boolean; message?: string };
    expect(body.success).toBe(false);
    expect(body.message || '').toContain('SQLite');
  });

  it('saves and loads ssl setting correctly', async () => {
    const putResponse = await app.inject({
      method: 'PUT',
      url: '/api/settings/database/runtime',
      payload: {
        dialect: 'mysql',
        connectionString: 'mysql://root:pass@tidb.example.com:4000/db',
        ssl: true,
      },
    });

    expect(putResponse.statusCode).toBe(200);
    const putBody = putResponse.json() as {
      success?: boolean;
      saved?: { dialect?: string; ssl?: boolean };
    };
    expect(putBody.success).toBe(true);
    expect(putBody.saved?.ssl).toBe(true);

    const dbSsl = await db.select().from(schema.settings).where(eq(schema.settings.key, 'db_ssl')).get();
    expect(dbSsl?.value).toBe(JSON.stringify(true));

    const getResponse = await app.inject({
      method: 'GET',
      url: '/api/settings/database/runtime',
    });
    const getBody = getResponse.json() as {
      success?: boolean;
      saved?: { ssl?: boolean };
    };
    expect(getBody.success).toBe(true);
    expect(getBody.saved?.ssl).toBe(true);
  });

  it('defaults ssl to false when not provided', async () => {
    const putResponse = await app.inject({
      method: 'PUT',
      url: '/api/settings/database/runtime',
      payload: {
        dialect: 'postgres',
        connectionString: 'postgres://user:pass@db.example.com:5432/mydb',
      },
    });

    expect(putResponse.statusCode).toBe(200);
    const putBody = putResponse.json() as {
      success?: boolean;
      saved?: { ssl?: boolean };
    };
    expect(putBody.success).toBe(true);
    expect(putBody.saved?.ssl).toBe(false);
  });

  it('rejects non-boolean ssl payload when saving runtime database config', async () => {
    const response = await app.inject({
      method: 'PUT',
      url: '/api/settings/database/runtime',
      payload: {
        dialect: 'postgres',
        connectionString: 'postgres://user:pass@db.example.com:5432/mydb',
        ssl: 'false',
      },
    });

    expect(response.statusCode).toBe(400);
    expect((response.json() as { message?: string }).message).toContain('ssl');
  });

  it('includes ssl in active runtime state', async () => {
    const response = await app.inject({
      method: 'GET',
      url: '/api/settings/database/runtime',
    });

    const body = response.json() as {
      active?: { ssl?: boolean };
    };
    expect(typeof body.active?.ssl).toBe('boolean');
  });
});
