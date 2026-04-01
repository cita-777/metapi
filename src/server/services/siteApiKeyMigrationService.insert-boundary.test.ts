import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { eq } from 'drizzle-orm';

vi.mock('../db/insertHelpers.js', async () => {
  const actual = await vi.importActual<typeof import('../db/insertHelpers.js')>('../db/insertHelpers.js');
  return {
    ...actual,
    insertAndGetById: vi.fn(async () => {
      throw new Error('failed to create migrated site account');
    }),
  };
});

type DbModule = typeof import('../db/index.js');
type MigrationModule = typeof import('./siteApiKeyMigrationService.js');

describe('siteApiKeyMigrationService insert boundary', () => {
  let db: DbModule['db'];
  let schema: DbModule['schema'];
  let migrateSiteApiKeysToAccounts: MigrationModule['migrateSiteApiKeysToAccounts'];
  let dataDir = '';

  beforeAll(async () => {
    dataDir = mkdtempSync(join(tmpdir(), 'metapi-site-api-key-migration-boundary-'));
    process.env.DATA_DIR = dataDir;

    await import('../db/migrate.js');
    const dbModule = await import('../db/index.js');
    const migrationModule = await import('./siteApiKeyMigrationService.js');
    db = dbModule.db;
    schema = dbModule.schema;
    migrateSiteApiKeysToAccounts = migrationModule.migrateSiteApiKeysToAccounts;
  });

  beforeEach(async () => {
    await db.delete(schema.accountTokens).run();
    await db.delete(schema.accounts).run();
    await db.delete(schema.sites).run();
  });

  afterAll(async () => {
    if (dataDir) {
      rmSync(dataDir, { recursive: true, force: true });
    }
    delete process.env.DATA_DIR;
  });

  it('does not clear the site apiKey when creating the replacement account cannot complete', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'boundary-site',
      url: 'https://boundary.example.com',
      platform: 'new-api',
      apiKey: 'sk-boundary-site-token',
    }).returning().get();

    await expect(migrateSiteApiKeysToAccounts()).rejects.toThrow('failed to create migrated site account');

    const persistedSite = await db.select().from(schema.sites).where(eq(schema.sites.id, site.id)).get();
    expect(persistedSite?.apiKey).toBe('sk-boundary-site-token');
    expect(await db.select().from(schema.accounts).all()).toHaveLength(0);
  });
});
