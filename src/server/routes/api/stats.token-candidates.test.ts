import Fastify, { type FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
const fetchModelPricingCatalogMock = vi.fn();

vi.mock('../../services/modelPricingService.js', async () => {
  const actual = await vi.importActual<typeof import('../../services/modelPricingService.js')>('../../services/modelPricingService.js');
  return {
    ...actual,
    fetchModelPricingCatalog: (...args: unknown[]) => fetchModelPricingCatalogMock(...args),
  };
});

type DbModule = typeof import('../../db/index.js');

describe('/api/models/token-candidates', () => {
  let app: FastifyInstance;
  let db: DbModule['db'];
  let schema: DbModule['schema'];
  let dataDir = '';

  beforeAll(async () => {
    dataDir = mkdtempSync(join(tmpdir(), 'metapi-stats-token-candidates-'));
    process.env.DATA_DIR = dataDir;

    await import('../../db/migrate.js');
    const dbModule = await import('../../db/index.js');
    const routesModule = await import('./stats.js');
    db = dbModule.db;
    schema = dbModule.schema;

    app = Fastify();
    await app.register(routesModule.statsRoutes);
  });

  beforeEach(async () => {
    fetchModelPricingCatalogMock.mockReset();
    fetchModelPricingCatalogMock.mockResolvedValue(null);
    await db.delete(schema.proxyLogs).run();
    await db.delete(schema.checkinLogs).run();
    await db.delete(schema.routeChannels).run();
    await db.delete(schema.tokenRoutes).run();
    await db.delete(schema.tokenModelAvailability).run();
    await db.delete(schema.modelAvailability).run();
    await db.delete(schema.accountTokens).run();
    await db.delete(schema.accounts).run();
    await db.delete(schema.sites).run();
  });

  afterAll(async () => {
    await app.close();
    delete process.env.DATA_DIR;
  });

  it('returns modelsWithoutToken for models available in account but not covered by enabled tokens', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'site-a',
      url: 'https://site-a.example.com',
      platform: 'new-api',
      status: 'active',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'alice',
      accessToken: 'acc-token',
      status: 'active',
    }).returning().get();

    const token = await db.insert(schema.accountTokens).values({
      accountId: account.id,
      name: 'default',
      token: 'tk-default',
      enabled: true,
      isDefault: true,
    }).returning().get();

    await db.insert(schema.modelAvailability).values([
      {
        accountId: account.id,
        modelName: 'claude-haiku-4-5-20251001',
        available: true,
      },
      {
        accountId: account.id,
        modelName: 'claude-opus-4-6',
        available: true,
      },
    ]).run();

    await db.insert(schema.tokenModelAvailability).values({
      tokenId: token.id,
      modelName: 'claude-haiku-4-5-20251001',
      available: true,
    }).run();

    const response = await app.inject({
      method: 'GET',
      url: '/api/models/token-candidates',
    });

    expect(response.statusCode).toBe(200);
    const body = response.json() as {
      models: Record<string, Array<{ tokenId: number }>>;
      modelsWithoutToken: Record<string, Array<{ accountId: number; username: string | null; siteId: number; siteName: string }>>;
    };

    expect(body.models['claude-haiku-4-5-20251001']?.map((item) => item.tokenId)).toEqual([token.id]);
    expect(body.modelsWithoutToken['claude-opus-4-6']).toEqual([
      {
        accountId: account.id,
        username: 'alice',
        siteId: site.id,
        siteName: 'site-a',
      },
    ]);
    expect(body.modelsWithoutToken['claude-haiku-4-5-20251001']).toBeUndefined();
  });

  it('does not report apikey connections as missing account tokens', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'site-apikey',
      url: 'https://site-apikey.example.com',
      platform: 'new-api',
      status: 'active',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'shenmo-direct',
      accessToken: '',
      apiToken: 'sk-shenmo-direct',
      status: 'active',
      extraConfig: JSON.stringify({ credentialMode: 'apikey' }),
    }).returning().get();

    await db.insert(schema.modelAvailability).values({
      accountId: account.id,
      modelName: 'gpt-5.2-codex',
      available: true,
    }).run();

    const response = await app.inject({
      method: 'GET',
      url: '/api/models/token-candidates',
    });

    expect(response.statusCode).toBe(200);
    const body = response.json() as {
      modelsWithoutToken: Record<string, Array<{ accountId: number }>>;
      modelsMissingTokenGroups: Record<string, Array<{ accountId: number }>>;
    };

    expect(body.modelsWithoutToken['gpt-5.2-codex']).toBeUndefined();
    expect(body.modelsMissingTokenGroups['gpt-5.2-codex']).toBeUndefined();
  });

  it('does not report oauth direct connections as missing account tokens', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'codex-site',
      url: 'https://chatgpt.com/backend-api/codex',
      platform: 'codex',
      status: 'active',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'codex-user@example.com',
      accessToken: 'oauth-access-token',
      apiToken: null,
      status: 'active',
      extraConfig: JSON.stringify({
        credentialMode: 'session',
        oauth: {
          provider: 'codex',
          accountId: 'chatgpt-account-123',
          email: 'codex-user@example.com',
          planType: 'team',
        },
      }),
    }).returning().get();

    await db.insert(schema.modelAvailability).values({
      accountId: account.id,
      modelName: 'gpt-5.2-codex',
      available: true,
    }).run();

    const response = await app.inject({
      method: 'GET',
      url: '/api/models/token-candidates',
    });

    expect(response.statusCode).toBe(200);
    const body = response.json() as {
      modelsWithoutToken: Record<string, Array<{ accountId: number }>>;
      modelsMissingTokenGroups: Record<string, Array<{ accountId: number }>>;
    };

    expect(body.modelsWithoutToken['gpt-5.2-codex']).toBeUndefined();
    expect(body.modelsMissingTokenGroups['gpt-5.2-codex']).toBeUndefined();
  });

  it('returns modelsMissingTokenGroups when account has partial group token coverage', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'site-b',
      url: 'https://site-b.example.com',
      platform: 'new-api',
      status: 'active',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'bob',
      accessToken: 'acc-token-b',
      status: 'active',
    }).returning().get();

    const defaultToken = await db.insert(schema.accountTokens).values({
      accountId: account.id,
      name: 'default-token',
      token: 'sk-default',
      tokenGroup: 'default',
      enabled: true,
      isDefault: true,
    }).returning().get();

    await db.insert(schema.modelAvailability).values({
      accountId: account.id,
      modelName: 'claude-opus-4-6',
      available: true,
    }).run();

    await db.insert(schema.tokenModelAvailability).values({
      tokenId: defaultToken.id,
      modelName: 'claude-opus-4-6',
      available: true,
    }).run();

    fetchModelPricingCatalogMock.mockResolvedValue({
      models: [
        {
          modelName: 'claude-opus-4-6',
          quotaType: 0,
          modelDescription: null,
          tags: [],
          supportedEndpointTypes: [],
          ownerBy: null,
          enableGroups: ['default', 'opus'],
          groupPricing: {},
        },
      ],
      groupRatio: { default: 1, opus: 2 },
    });

    const response = await app.inject({
      method: 'GET',
      url: '/api/models/token-candidates',
    });

    expect(response.statusCode).toBe(200);
    const body = response.json() as {
      modelsWithoutToken: Record<string, unknown>;
      modelsMissingTokenGroups: Record<string, Array<{
        accountId: number;
        missingGroups: string[];
        requiredGroups: string[];
        availableGroups: string[];
      }>>;
    };

    expect(body.modelsWithoutToken['claude-opus-4-6']).toBeUndefined();
    expect(body.modelsMissingTokenGroups['claude-opus-4-6']).toEqual([
      {
        accountId: account.id,
        username: 'bob',
        siteId: site.id,
        siteName: 'site-b',
        missingGroups: ['opus'],
        requiredGroups: ['default', 'opus'],
        availableGroups: ['default'],
      },
    ]);
  });

  it('infers default group from token name when token_group is empty', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'site-c',
      url: 'https://site-c.example.com',
      platform: 'new-api',
      status: 'active',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'charlie',
      accessToken: 'acc-token-c',
      status: 'active',
    }).returning().get();

    const token = await db.insert(schema.accountTokens).values({
      accountId: account.id,
      name: 'default',
      token: 'sk-default-c',
      tokenGroup: null,
      enabled: true,
      isDefault: true,
    }).returning().get();

    await db.insert(schema.modelAvailability).values({
      accountId: account.id,
      modelName: 'claude-sonnet-4-5-20250929',
      available: true,
    }).run();

    await db.insert(schema.tokenModelAvailability).values({
      tokenId: token.id,
      modelName: 'claude-sonnet-4-5-20250929',
      available: true,
    }).run();

    fetchModelPricingCatalogMock.mockResolvedValue({
      models: [
        {
          modelName: 'claude-sonnet-4-5-20250929',
          quotaType: 0,
          modelDescription: null,
          tags: [],
          supportedEndpointTypes: [],
          ownerBy: null,
          enableGroups: ['default', 'vip'],
          groupPricing: {},
        },
      ],
      groupRatio: { default: 1, vip: 2 },
    });

    const response = await app.inject({
      method: 'GET',
      url: '/api/models/token-candidates',
    });

    expect(response.statusCode).toBe(200);
    const body = response.json() as {
      modelsMissingTokenGroups: Record<string, Array<{
        accountId: number;
        missingGroups: string[];
        requiredGroups: string[];
        availableGroups: string[];
        groupCoverageUncertain?: boolean;
      }>>;
    };

    expect(body.modelsMissingTokenGroups['claude-sonnet-4-5-20250929']).toEqual([
      {
        accountId: account.id,
        username: 'charlie',
        siteId: site.id,
        siteName: 'site-c',
        missingGroups: ['vip'],
        requiredGroups: ['default', 'vip'],
        availableGroups: ['default'],
      },
    ]);
  });

  it('marks coverage as uncertain when token group cannot be inferred', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'site-d',
      url: 'https://site-d.example.com',
      platform: 'new-api',
      status: 'active',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'david',
      accessToken: 'acc-token-d',
      status: 'active',
    }).returning().get();

    const token = await db.insert(schema.accountTokens).values({
      accountId: account.id,
      name: 'token-1',
      token: 'sk-token-1',
      tokenGroup: null,
      enabled: true,
      isDefault: true,
    }).returning().get();

    await db.insert(schema.modelAvailability).values({
      accountId: account.id,
      modelName: 'claude-opus-4-5-20251101',
      available: true,
    }).run();

    await db.insert(schema.tokenModelAvailability).values({
      tokenId: token.id,
      modelName: 'claude-opus-4-5-20251101',
      available: true,
    }).run();

    fetchModelPricingCatalogMock.mockResolvedValue({
      models: [
        {
          modelName: 'claude-opus-4-5-20251101',
          quotaType: 0,
          modelDescription: null,
          tags: [],
          supportedEndpointTypes: [],
          ownerBy: null,
          enableGroups: ['default', 'vip'],
          groupPricing: {},
        },
      ],
      groupRatio: { default: 1, vip: 2 },
    });

    const response = await app.inject({
      method: 'GET',
      url: '/api/models/token-candidates',
    });

    expect(response.statusCode).toBe(200);
    const body = response.json() as {
      modelsMissingTokenGroups: Record<string, Array<{
        accountId: number;
        missingGroups: string[];
        requiredGroups: string[];
        availableGroups: string[];
        groupCoverageUncertain?: boolean;
      }>>;
    };

    expect(body.modelsMissingTokenGroups['claude-opus-4-5-20251101']).toEqual([
      {
        accountId: account.id,
        username: 'david',
        siteId: site.id,
        siteName: 'site-d',
        missingGroups: ['default', 'vip'],
        requiredGroups: ['default', 'vip'],
        availableGroups: [],
        groupCoverageUncertain: true,
      },
    ]);
  });

  it('does not request token-group hints for apikey connections', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'site-e',
      url: 'https://site-e.example.com',
      platform: 'new-api',
      status: 'active',
      apiKey: 'sk-site-fallback',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'erin',
      accessToken: '',
      apiToken: null,
      status: 'active',
      extraConfig: JSON.stringify({ credentialMode: 'apikey' }),
    }).returning().get();

    const token = await db.insert(schema.accountTokens).values({
      accountId: account.id,
      name: 'default',
      token: 'sk-default-e',
      tokenGroup: 'default',
      enabled: true,
      isDefault: true,
    }).returning().get();

    await db.insert(schema.modelAvailability).values({
      accountId: account.id,
      modelName: 'claude-opus-4-6',
      available: true,
    }).run();

    await db.insert(schema.tokenModelAvailability).values({
      tokenId: token.id,
      modelName: 'claude-opus-4-6',
      available: true,
    }).run();

    fetchModelPricingCatalogMock.mockResolvedValue({
      models: [
        {
          modelName: 'claude-opus-4-6',
          quotaType: 0,
          modelDescription: null,
          tags: [],
          supportedEndpointTypes: [],
          ownerBy: null,
          enableGroups: ['default', 'vip'],
          groupPricing: {},
        },
      ],
      groupRatio: { default: 1, vip: 2 },
    });

    const response = await app.inject({
      method: 'GET',
      url: '/api/models/token-candidates',
    });

    expect(response.statusCode).toBe(200);
    const body = response.json() as {
      modelsMissingTokenGroups: Record<string, Array<{ accountId: number }>>;
    };

    expect(fetchModelPricingCatalogMock).not.toHaveBeenCalled();
    expect(body.modelsMissingTokenGroups['claude-opus-4-6']).toBeUndefined();
  });
});
