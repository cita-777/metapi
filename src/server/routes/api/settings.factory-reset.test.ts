import Fastify, { type FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { eq } from 'drizzle-orm';

type DbModule = typeof import('../../db/index.js');
type ConfigModule = typeof import('../../config.js');
type ServiceModule = typeof import('../../services/factoryResetService.js');

describe('settings factory reset api', () => {
  let app: FastifyInstance;
  let db: DbModule['db'];
  let schema: DbModule['schema'];
  let config: ConfigModule['config'];
  let FACTORY_RESET_ADMIN_TOKEN: ServiceModule['FACTORY_RESET_ADMIN_TOKEN'];
  let dataDir = '';

  beforeAll(async () => {
    dataDir = mkdtempSync(join(tmpdir(), 'metapi-settings-factory-reset-'));
    process.env.DATA_DIR = dataDir;

    await import('../../db/migrate.js');
    const dbModule = await import('../../db/index.js');
    const configModule = await import('../../config.js');
    const serviceModule = await import('../../services/factoryResetService.js');
    const settingsRoutesModule = await import('./settings.js');

    db = dbModule.db;
    schema = dbModule.schema;
    config = configModule.config;
    FACTORY_RESET_ADMIN_TOKEN = serviceModule.FACTORY_RESET_ADMIN_TOKEN;

    app = Fastify();
    await app.register(settingsRoutesModule.settingsRoutes);
  });

  beforeEach(async () => {
    await db.delete(schema.routeChannels).run();
    await db.delete(schema.tokenModelAvailability).run();
    await db.delete(schema.modelAvailability).run();
    await db.delete(schema.proxyLogs).run();
    await db.delete(schema.proxyVideoTasks).run();
    await db.delete(schema.checkinLogs).run();
    await db.delete(schema.accountTokens).run();
    await db.delete(schema.accounts).run();
    await db.delete(schema.tokenRoutes).run();
    await db.delete(schema.sites).run();
    await db.delete(schema.downstreamApiKeys).run();
    await db.delete(schema.events).run();
    await db.delete(schema.settings).run();

    config.authToken = 'before-reset-token';
    config.dbType = 'sqlite';
    config.dbUrl = '';
    config.dbSsl = true;
    config.systemProxyUrl = 'http://127.0.0.1:7890';
  });

  afterAll(async () => {
    await app.close();
    delete process.env.DATA_DIR;
  });

  it('clears business data while preserving infrastructure settings', async () => {
    const siteInsert = await db.insert(schema.sites).values({
      name: 'Reset Me',
      url: 'https://reset.example.com',
      platform: 'new-api',
      status: 'disabled',
    }).run();
    const siteId = Number(siteInsert.lastInsertRowid);

    const accountInsert = await db.insert(schema.accounts).values({
      siteId,
      accessToken: 'session-token',
      status: 'expired',
    }).run();
    const accountId = Number(accountInsert.lastInsertRowid);

    const tokenInsert = await db.insert(schema.accountTokens).values({
      accountId,
      name: 'Reset token',
      token: 'token-value',
    }).run();
    const tokenId = Number(tokenInsert.lastInsertRowid);

    const routeInsert = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-*',
      enabled: true,
    }).run();
    const routeId = Number(routeInsert.lastInsertRowid);

    await db.insert(schema.routeChannels).values({
      routeId,
      accountId,
      tokenId,
      enabled: true,
    }).run();
    await db.insert(schema.modelAvailability).values({
      accountId,
      modelName: 'gpt-4.1',
      available: true,
    }).run();
    await db.insert(schema.tokenModelAvailability).values({
      tokenId,
      modelName: 'gpt-4.1',
      available: true,
    }).run();
    await db.insert(schema.checkinLogs).values({
      accountId,
      status: 'success',
      message: 'ok',
    }).run();
    await db.insert(schema.proxyLogs).values({
      accountId,
      status: 'success',
      modelRequested: 'gpt-4.1',
    }).run();
    await db.insert(schema.proxyVideoTasks).values({
      publicId: 'public-video-1',
      upstreamVideoId: 'upstream-video-1',
      siteUrl: 'https://reset.example.com',
      tokenValue: 'session-token',
    }).run();
    await db.insert(schema.downstreamApiKeys).values({
      name: 'Downstream',
      key: 'downstream-key',
    }).run();
    await db.insert(schema.events).values({
      type: 'status',
      title: 'Before reset',
      message: 'should be gone',
      level: 'warning',
    }).run();
    await db.insert(schema.settings).values([
      { key: 'auth_token', value: JSON.stringify('before-reset-token') },
      { key: 'db_type', value: JSON.stringify('postgres') },
      { key: 'db_url', value: JSON.stringify('postgres://user:pass@127.0.0.1:5432/metapi') },
      { key: 'db_ssl', value: JSON.stringify(true) },
      { key: 'system_proxy_url', value: JSON.stringify('http://127.0.0.1:7890') },
    ]).run();

    const response = await app.inject({
      method: 'POST',
      url: '/api/settings/maintenance/factory-reset',
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ success: true });
    expect(config.authToken).toBe('before-reset-token');
    expect(config.dbType).toBe('sqlite');
    expect(config.dbUrl).toBe('');
    expect(config.dbSsl).toBe(false);
    expect(config.systemProxyUrl).toBe('http://127.0.0.1:7890');

    const sites = await db.select().from(schema.sites).all();
    expect(sites.map((site) => site.name)).toEqual([
      'OpenAI 官方',
      'Claude 官方',
      'Gemini 官方',
      'CLIProxyAPI',
    ]);

    const authTokenSetting = await db.select().from(schema.settings).where(eq(schema.settings.key, 'auth_token')).get();
    const dbTypeSetting = await db.select().from(schema.settings).where(eq(schema.settings.key, 'db_type')).get();
    const dbUrlSetting = await db.select().from(schema.settings).where(eq(schema.settings.key, 'db_url')).get();
    const dbSslSetting = await db.select().from(schema.settings).where(eq(schema.settings.key, 'db_ssl')).get();
    const systemProxySetting = await db.select().from(schema.settings).where(eq(schema.settings.key, 'system_proxy_url')).get();
    expect(authTokenSetting?.value).toBe(JSON.stringify('before-reset-token'));
    expect(dbTypeSetting?.value).toBe(JSON.stringify('sqlite'));
    expect(dbUrlSetting?.value).toBe(JSON.stringify(''));
    expect(dbSslSetting?.value).toBe(JSON.stringify(false));
    expect(systemProxySetting?.value).toBe(JSON.stringify('http://127.0.0.1:7890'));

    expect(await db.select().from(schema.accounts).all()).toHaveLength(0);
    expect(await db.select().from(schema.accountTokens).all()).toHaveLength(0);
    expect(await db.select().from(schema.tokenRoutes).all()).toHaveLength(0);
    expect(await db.select().from(schema.routeChannels).all()).toHaveLength(0);
    expect(await db.select().from(schema.modelAvailability).all()).toHaveLength(0);
    expect(await db.select().from(schema.tokenModelAvailability).all()).toHaveLength(0);
    expect(await db.select().from(schema.proxyLogs).all()).toHaveLength(0);
    expect(await db.select().from(schema.proxyVideoTasks).all()).toHaveLength(0);
    expect(await db.select().from(schema.checkinLogs).all()).toHaveLength(0);
    expect(await db.select().from(schema.downstreamApiKeys).all()).toHaveLength(0);
    expect(await db.select().from(schema.events).all()).toHaveLength(0);
  });
});
