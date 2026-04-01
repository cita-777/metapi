import Fastify, { type FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { eq } from 'drizzle-orm';

type DbModule = typeof import('../../db/index.js');

describe('settings backup webdav api', () => {
  let app: FastifyInstance;
  let db: DbModule['db'];
  let schema: DbModule['schema'];
  let dataDir = '';

  beforeAll(async () => {
    dataDir = mkdtempSync(join(tmpdir(), 'metapi-settings-backup-webdav-'));
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
    await db.delete(schema.settings).run();
    await db.delete(schema.events).run();
  });

  afterAll(async () => {
    await app.close();
    delete process.env.DATA_DIR;
  });

  it('saves and returns masked webdav config', async () => {
    const response = await app.inject({
      method: 'PUT',
      url: '/api/settings/backup/webdav',
      payload: {
        enabled: true,
        fileUrl: 'https://dav.example.com/backups/metapi.json',
        username: 'alice',
        password: 'secret-pass',
        exportType: 'accounts',
        autoSyncEnabled: true,
        autoSyncCron: '0 */6 * * *',
      },
    });

    expect(response.statusCode).toBe(200);
    const body = response.json() as {
      success?: boolean;
      config?: {
        fileUrl?: string;
        username?: string;
        exportType?: string;
        autoSyncEnabled?: boolean;
        autoSyncCron?: string;
        hasPassword?: boolean;
        passwordMasked?: string;
      };
    };
    expect(body.success).toBe(true);
    expect(body.config).toMatchObject({
      fileUrl: 'https://dav.example.com/backups/metapi.json',
      username: 'alice',
      exportType: 'accounts',
      autoSyncEnabled: true,
      autoSyncCron: '0 */6 * * *',
      hasPassword: true,
    });
    expect(body.config?.passwordMasked).toBeTruthy();

    const saved = await db.select().from(schema.settings).where(eq(schema.settings.key, 'backup_webdav_config_v1')).get();
    expect(saved?.value).toContain('"fileUrl":"https://dav.example.com/backups/metapi.json"');
    expect(saved?.value).toContain('"password":"secret-pass"');
  });

  it('exports current backup to webdav through settings route', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    fetchSpy.mockResolvedValue(new Response(null, { status: 201 }));
    try {
      await db.insert(schema.settings).values({
        key: 'backup_webdav_config_v1',
        value: JSON.stringify({
          enabled: true,
          fileUrl: 'https://dav.example.com/backups/metapi.json',
          username: 'alice',
          password: 'secret-pass',
          exportType: 'all',
          autoSyncEnabled: false,
          autoSyncCron: '0 * * * *',
        }),
      }).run();

      const response = await app.inject({
        method: 'POST',
        url: '/api/settings/backup/webdav/export',
      });

      expect(response.statusCode).toBe(200);
      const body = response.json() as { success?: boolean; fileUrl?: string };
      expect(body.success).toBe(true);
      expect(body.fileUrl).toBe('https://dav.example.com/backups/metapi.json');
      expect(fetchSpy).toHaveBeenCalledTimes(1);
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it('rejects invalid exportType payload when saving webdav config', async () => {
    const response = await app.inject({
      method: 'PUT',
      url: '/api/settings/backup/webdav',
      payload: {
        enabled: true,
        fileUrl: 'https://dav.example.com/backups/metapi.json',
        exportType: 123,
      },
    });

    expect(response.statusCode).toBe(400);
    expect((response.json() as { message?: string }).message).toContain('exportType');
  });

  it('rejects invalid export body type instead of silently falling back', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    fetchSpy.mockResolvedValue(new Response(null, { status: 201 }));
    try {
      await db.insert(schema.settings).values({
        key: 'backup_webdav_config_v1',
        value: JSON.stringify({
          enabled: true,
          fileUrl: 'https://dav.example.com/backups/metapi.json',
          username: 'alice',
          password: 'secret-pass',
          exportType: 'all',
          autoSyncEnabled: false,
          autoSyncCron: '0 * * * *',
        }),
      }).run();

      const response = await app.inject({
        method: 'POST',
        url: '/api/settings/backup/webdav/export',
        payload: {
          type: 123,
        },
      });

      expect(response.statusCode).toBe(400);
      expect((response.json() as { message?: string }).message).toContain('type');
      expect(fetchSpy).not.toHaveBeenCalled();
    } finally {
      fetchSpy.mockRestore();
    }
  });
});
