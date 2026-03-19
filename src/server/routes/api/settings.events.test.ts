import Fastify, { type FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { eq } from 'drizzle-orm';
import { resetRequestRateLimitStore } from '../../middleware/requestRateLimit.js';

type DbModule = typeof import('../../db/index.js');
type ConfigModule = typeof import('../../config.js');

describe('settings and auth events', () => {
  let app: FastifyInstance;
  let db: DbModule['db'];
  let schema: DbModule['schema'];
  let config: ConfigModule['config'];
  let dataDir = '';

  beforeAll(async () => {
    dataDir = mkdtempSync(join(tmpdir(), 'metapi-settings-events-'));
    process.env.DATA_DIR = dataDir;

    await import('../../db/migrate.js');
    const dbModule = await import('../../db/index.js');
    const configModule = await import('../../config.js');
    const settingsRoutesModule = await import('./settings.js');
    const authRoutesModule = await import('./auth.js');

    db = dbModule.db;
    schema = dbModule.schema;
    config = configModule.config;

    app = Fastify();
    await app.register(settingsRoutesModule.settingsRoutes);
    await app.register(authRoutesModule.authRoutes);
  });

  beforeEach(async () => {
    resetRequestRateLimitStore();
    await db.delete(schema.events).run();
    await db.delete(schema.settings).run();

    config.authToken = 'old-admin-token-123';
    config.proxyToken = 'sk-old-proxy-token-123';
    config.systemProxyUrl = '';
    config.checkinCron = '0 8 * * *';
    config.balanceRefreshCron = '0 * * * *';
    config.logCleanupConfigured = false;
    config.logCleanupCron = '0 6 * * *';
    config.logCleanupUsageLogsEnabled = false;
    config.logCleanupProgramLogsEnabled = false;
    config.logCleanupRetentionDays = 30;
    config.routingFallbackUnitCost = 1;
    (config as any).telegramEnabled = false;
    (config as any).telegramApiBaseUrl = 'https://api.telegram.org';
    (config as any).telegramBotToken = '';
    (config as any).telegramChatId = '';
  });

  afterAll(async () => {
    await app.close();
    delete process.env.DATA_DIR;
  });

  it('appends event when runtime settings are updated', async () => {
    const response = await app.inject({
      method: 'PUT',
      url: '/api/settings/runtime',
      payload: {
        proxyToken: 'sk-new-proxy-token-456',
        checkinCron: '5 9 * * *',
      },
    });

    expect(response.statusCode).toBe(200);

    const events = await db.select().from(schema.events).all();
    expect(events.length).toBe(1);
    expect(events[0]).toMatchObject({
      type: 'status',
      title: '运行时设置已更新',
      relatedType: 'settings',
    });
    expect(events[0].message || '').toContain('代理访问 Token');
    expect(events[0].message || '').toContain('签到 Cron');
  });

  it('returns current recognized admin IP in runtime settings response', async () => {
    const response = await app.inject({
      method: 'GET',
      url: '/api/settings/runtime',
      remoteAddress: '10.0.0.8',
      headers: {
        'x-forwarded-for': '203.0.113.5, 10.0.0.8',
      },
    });

    expect(response.statusCode).toBe(200);
    const body = response.json() as { currentAdminIp?: string };
    expect(body.currentAdminIp).toBe('203.0.113.5');
  });

  it('rejects proxy token that does not start with sk-', async () => {
    const response = await app.inject({
      method: 'PUT',
      url: '/api/settings/runtime',
      payload: {
        proxyToken: 'new-proxy-token-456',
      },
    });

    expect(response.statusCode).toBe(400);
    const body = response.json() as { message?: string };
    expect(body.message).toContain('sk-');
  });

  it('rejects invalid bark url when bark channel is enabled', async () => {
    const response = await app.inject({
      method: 'PUT',
      url: '/api/settings/runtime',
      payload: {
        barkEnabled: true,
        barkUrl: 'juricek.chen@gmail.com',
      },
    });

    expect(response.statusCode).toBe(400);
    const body = response.json() as { message?: string };
    expect(body.message).toContain('Bark URL');
  });

  it('rejects invalid webhook url when webhook channel is enabled', async () => {
    const response = await app.inject({
      method: 'PUT',
      url: '/api/settings/runtime',
      payload: {
        webhookEnabled: true,
        webhookUrl: 'not-a-url',
      },
    });

    expect(response.statusCode).toBe(400);
    const body = response.json() as { message?: string };
    expect(body.message).toContain('Webhook URL');
  });

  it('rejects telegram config when bot token is missing but telegram is enabled', async () => {
    const response = await app.inject({
      method: 'PUT',
      url: '/api/settings/runtime',
      payload: {
        telegramEnabled: true,
        telegramChatId: '-1001234567890',
        telegramBotToken: '',
      },
    });

    expect(response.statusCode).toBe(400);
    const body = response.json() as { message?: string };
    expect(body.message).toContain('Telegram Bot Token');
  });

  it('rejects telegram config when chat id is missing but telegram is enabled', async () => {
    const response = await app.inject({
      method: 'PUT',
      url: '/api/settings/runtime',
      payload: {
        telegramEnabled: true,
        telegramBotToken: '123456:telegram-token',
        telegramChatId: '',
      },
    });

    expect(response.statusCode).toBe(400);
    const body = response.json() as { message?: string };
    expect(body.message).toContain('Telegram Chat ID');
  });

  it('persists and returns telegram api base url from runtime settings', async () => {
    const updateResponse = await app.inject({
      method: 'PUT',
      url: '/api/settings/runtime',
      payload: {
        telegramApiBaseUrl: 'https://tg-proxy.example.com/custom/',
      },
    });

    expect(updateResponse.statusCode).toBe(200);
    const updated = updateResponse.json() as { telegramApiBaseUrl?: string };
    expect(updated.telegramApiBaseUrl).toBe('https://tg-proxy.example.com/custom');
    expect((config as any).telegramApiBaseUrl).toBe('https://tg-proxy.example.com/custom');

    const saved = await db.select().from(schema.settings).where(eq(schema.settings.key, 'telegram_api_base_url')).get();
    expect(saved?.value).toBe(JSON.stringify('https://tg-proxy.example.com/custom'));

    const getResponse = await app.inject({
      method: 'GET',
      url: '/api/settings/runtime',
    });
    expect(getResponse.statusCode).toBe(200);
    const runtime = getResponse.json() as { telegramApiBaseUrl?: string };
    expect(runtime.telegramApiBaseUrl).toBe('https://tg-proxy.example.com/custom');
  });

  it('rejects invalid telegram api base url when telegram is enabled', async () => {
    const response = await app.inject({
      method: 'PUT',
      url: '/api/settings/runtime',
      payload: {
        telegramEnabled: true,
        telegramBotToken: '123456:telegram-token',
        telegramChatId: '-1001234567890',
        telegramApiBaseUrl: 'not-a-url',
      },
    });

    expect(response.statusCode).toBe(400);
    const body = response.json() as { message?: string };
    expect(body.message).toContain('Telegram API Base URL');
  });

  it('persists and returns routing fallback unit cost from runtime settings', async () => {
    const updateResponse = await app.inject({
      method: 'PUT',
      url: '/api/settings/runtime',
      payload: {
        routingFallbackUnitCost: 0.25,
      },
    });

    expect(updateResponse.statusCode).toBe(200);
    const updated = updateResponse.json() as { routingFallbackUnitCost?: number };
    expect(updated.routingFallbackUnitCost).toBe(0.25);
    expect(config.routingFallbackUnitCost).toBe(0.25);

    const saved = await db.select().from(schema.settings).where(eq(schema.settings.key, 'routing_fallback_unit_cost')).get();
    expect(saved).toBeTruthy();
    expect(saved?.value).toBe(JSON.stringify(0.25));

    const getResponse = await app.inject({
      method: 'GET',
      url: '/api/settings/runtime',
    });
    expect(getResponse.statusCode).toBe(200);
    const runtime = getResponse.json() as { routingFallbackUnitCost?: number };
    expect(runtime.routingFallbackUnitCost).toBe(0.25);
  });

  it('persists and returns system proxy url from runtime settings', async () => {
    const updateResponse = await app.inject({
      method: 'PUT',
      url: '/api/settings/runtime',
      payload: {
        systemProxyUrl: 'http://127.0.0.1:7890',
      },
    });

    expect(updateResponse.statusCode).toBe(200);
    const updated = updateResponse.json() as { systemProxyUrl?: string };
    expect(updated.systemProxyUrl).toBe('http://127.0.0.1:7890');
    expect(config.systemProxyUrl).toBe('http://127.0.0.1:7890');

    const saved = await db.select().from(schema.settings).where(eq(schema.settings.key, 'system_proxy_url')).get();
    expect(saved).toBeTruthy();
    expect(saved?.value).toBe(JSON.stringify('http://127.0.0.1:7890'));

    const getResponse = await app.inject({
      method: 'GET',
      url: '/api/settings/runtime',
    });
    expect(getResponse.statusCode).toBe(200);
    const runtime = getResponse.json() as { systemProxyUrl?: string };
    expect(runtime.systemProxyUrl).toBe('http://127.0.0.1:7890');
  });

  it('splits proxy error keywords on newlines and commas when saving runtime settings', async () => {
    const updateResponse = await app.inject({
      method: 'PUT',
      url: '/api/settings/runtime',
      payload: {
        proxyErrorKeywords: 'quota exceeded\nbad gateway,too many requests',
        proxyEmptyContentFailEnabled: true,
      },
    });

    expect(updateResponse.statusCode).toBe(200);
    const updated = updateResponse.json() as {
      proxyErrorKeywords?: string[];
      proxyEmptyContentFailEnabled?: boolean;
    };
    expect(updated.proxyErrorKeywords).toEqual([
      'quota exceeded',
      'bad gateway',
      'too many requests',
    ]);
    expect(updated.proxyEmptyContentFailEnabled).toBe(true);
    expect(config.proxyErrorKeywords).toEqual([
      'quota exceeded',
      'bad gateway',
      'too many requests',
    ]);
    expect(config.proxyEmptyContentFailEnabled).toBe(true);

    const rows = await db.select().from(schema.settings).all();
    const settingsMap = new Map(rows.map((row) => [row.key, row.value]));
    expect(settingsMap.get('proxy_error_keywords')).toBe(JSON.stringify([
      'quota exceeded',
      'bad gateway',
      'too many requests',
    ]));
    expect(settingsMap.get('proxy_empty_content_fail_enabled')).toBe(JSON.stringify(true));

    const getResponse = await app.inject({
      method: 'GET',
      url: '/api/settings/runtime',
    });
    expect(getResponse.statusCode).toBe(200);
    const runtime = getResponse.json() as {
      proxyErrorKeywords?: string[];
      proxyEmptyContentFailEnabled?: boolean;
    };
    expect(runtime.proxyErrorKeywords).toEqual([
      'quota exceeded',
      'bad gateway',
      'too many requests',
    ]);
    expect(runtime.proxyEmptyContentFailEnabled).toBe(true);
  });

  it('persists and returns log cleanup settings from runtime settings', async () => {
    const updateResponse = await app.inject({
      method: 'PUT',
      url: '/api/settings/runtime',
      payload: {
        logCleanupCron: '15 4 * * *',
        logCleanupUsageLogsEnabled: true,
        logCleanupProgramLogsEnabled: true,
        logCleanupRetentionDays: 14,
      },
    });

    expect(updateResponse.statusCode).toBe(200);
    const updated = updateResponse.json() as {
      logCleanupCron?: string;
      logCleanupUsageLogsEnabled?: boolean;
      logCleanupProgramLogsEnabled?: boolean;
      logCleanupRetentionDays?: number;
    };
    expect(updated.logCleanupCron).toBe('15 4 * * *');
    expect(updated.logCleanupUsageLogsEnabled).toBe(true);
    expect(updated.logCleanupProgramLogsEnabled).toBe(true);
    expect(updated.logCleanupRetentionDays).toBe(14);
    expect(config.logCleanupCron).toBe('15 4 * * *');
    expect(config.logCleanupUsageLogsEnabled).toBe(true);
    expect(config.logCleanupProgramLogsEnabled).toBe(true);
    expect(config.logCleanupRetentionDays).toBe(14);

    const rows = await db.select().from(schema.settings).all();
    const settingsMap = new Map(rows.map((row) => [row.key, row.value]));
    expect(settingsMap.get('log_cleanup_cron')).toBe(JSON.stringify('15 4 * * *'));
    expect(settingsMap.get('log_cleanup_usage_logs_enabled')).toBe(JSON.stringify(true));
    expect(settingsMap.get('log_cleanup_program_logs_enabled')).toBe(JSON.stringify(true));
    expect(settingsMap.get('log_cleanup_retention_days')).toBe(JSON.stringify(14));

    const getResponse = await app.inject({
      method: 'GET',
      url: '/api/settings/runtime',
    });
    expect(getResponse.statusCode).toBe(200);
    const runtime = getResponse.json() as {
      logCleanupCron?: string;
      logCleanupUsageLogsEnabled?: boolean;
      logCleanupProgramLogsEnabled?: boolean;
      logCleanupRetentionDays?: number;
    };
    expect(runtime.logCleanupCron).toBe('15 4 * * *');
    expect(runtime.logCleanupUsageLogsEnabled).toBe(true);
    expect(runtime.logCleanupProgramLogsEnabled).toBe(true);
    expect(runtime.logCleanupRetentionDays).toBe(14);
  });

  it('rejects invalid log cleanup cron and retention days', async () => {
    const invalidCronResponse = await app.inject({
      method: 'PUT',
      url: '/api/settings/runtime',
      payload: {
        logCleanupCron: 'invalid cron',
      },
    });
    expect(invalidCronResponse.statusCode).toBe(400);
    expect((invalidCronResponse.json() as { message?: string }).message).toContain('日志清理 Cron');

    const invalidRetentionResponse = await app.inject({
      method: 'PUT',
      url: '/api/settings/runtime',
      payload: {
        logCleanupRetentionDays: 0,
      },
    });
    expect(invalidRetentionResponse.statusCode).toBe(400);
    expect((invalidRetentionResponse.json() as { message?: string }).message).toContain('保留天数');
  });

  it('invalidates cached site proxy resolution when system proxy url changes', async () => {
    await db.insert(schema.sites).values({
      name: 'proxy-site',
      url: 'https://proxy-site.example.com',
      platform: 'new-api',
      useSystemProxy: true,
    }).run();

    const { resolveSiteProxyUrlByRequestUrl } = await import('../../services/siteProxy.js');

    const firstUpdate = await app.inject({
      method: 'PUT',
      url: '/api/settings/runtime',
      payload: {
        systemProxyUrl: 'http://127.0.0.1:7890',
      },
    });
    expect(firstUpdate.statusCode).toBe(200);
    expect(await resolveSiteProxyUrlByRequestUrl('https://proxy-site.example.com/v1/chat/completions')).toBe('http://127.0.0.1:7890');

    const secondUpdate = await app.inject({
      method: 'PUT',
      url: '/api/settings/runtime',
      payload: {
        systemProxyUrl: 'http://127.0.0.1:7891',
      },
    });
    expect(secondUpdate.statusCode).toBe(200);
    expect(await resolveSiteProxyUrlByRequestUrl('https://proxy-site.example.com/v1/chat/completions')).toBe('http://127.0.0.1:7891');
  });

  it('rejects allowlist update that does not include current request IP', async () => {
    const response = await app.inject({
      method: 'PUT',
      url: '/api/settings/runtime',
      remoteAddress: '198.51.100.10',
      payload: {
        adminIpAllowlist: ['198.51.100.11'],
      },
    });

    expect(response.statusCode).toBe(400);
    const body = response.json() as { message?: string };
    expect(body.message).toContain('白名单');
    expect(body.message).toContain('198.51.100.10');

    const saved = await db.select().from(schema.settings).where(eq(schema.settings.key, 'admin_ip_allowlist')).get();
    expect(saved).toBeFalsy();
  });

  it('allows allowlist update when current request IP is included', async () => {
    const response = await app.inject({
      method: 'PUT',
      url: '/api/settings/runtime',
      remoteAddress: '198.51.100.10',
      payload: {
        adminIpAllowlist: ['198.51.100.10', '198.51.100.11'],
      },
    });

    expect(response.statusCode).toBe(200);
    const body = response.json() as { adminIpAllowlist?: string[] };
    expect(body.adminIpAllowlist).toEqual(['198.51.100.10', '198.51.100.11']);

    const saved = await db.select().from(schema.settings).where(eq(schema.settings.key, 'admin_ip_allowlist')).get();
    expect(saved?.value).toBe(JSON.stringify(['198.51.100.10', '198.51.100.11']));
  });

  it('appends event when admin auth token changes', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/settings/auth/change',
      payload: {
        oldToken: 'old-admin-token-123',
        newToken: 'new-admin-token-456',
      },
    });

    expect(response.statusCode).toBe(200);

    const events = await db.select().from(schema.events).all();
    expect(events.length).toBe(1);
    expect(events[0]).toMatchObject({
      type: 'token',
      title: '管理员登录令牌已更新',
      relatedType: 'settings',
    });
  });

  it('rate limits repeated admin auth token changes from the same client ip', async () => {
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const response = await app.inject({
        method: 'POST',
        url: '/api/settings/auth/change',
        remoteAddress: '198.51.100.12',
        payload: {
          oldToken: config.authToken,
          newToken: `new-admin-token-${attempt}-456`,
        },
      });

      expect(response.statusCode).toBe(200);
    }

    const limited = await app.inject({
      method: 'POST',
      url: '/api/settings/auth/change',
      remoteAddress: '198.51.100.12',
      payload: {
        oldToken: config.authToken,
        newToken: 'new-admin-token-rate-limit',
      },
    });

    expect(limited.statusCode).toBe(429);
    expect(limited.json()).toMatchObject({
      success: false,
      message: '请求过于频繁，请稍后再试',
    });
  });
});
