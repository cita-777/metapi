import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { eq } from 'drizzle-orm';

const getApiTokenMock = vi.fn();
const getModelsMock = vi.fn();
const undiciFetchMock = vi.fn();

vi.mock('./platforms/index.js', () => ({
  getAdapter: () => ({
    getApiToken: (...args: unknown[]) => getApiTokenMock(...args),
    getModels: (...args: unknown[]) => getModelsMock(...args),
  }),
}));

vi.mock('undici', () => ({
  fetch: (...args: unknown[]) => undiciFetchMock(...args),
}));

type DbModule = typeof import('../db/index.js');
type ModelServiceModule = typeof import('./modelService.js');

describe('refreshModelsForAccount credential discovery', () => {
  let db: DbModule['db'];
  let schema: DbModule['schema'];
  let refreshModelsForAccount: ModelServiceModule['refreshModelsForAccount'];
  let refreshModelsAndRebuildRoutes: ModelServiceModule['refreshModelsAndRebuildRoutes'];
  let dataDir = '';

  beforeAll(async () => {
    dataDir = mkdtempSync(join(tmpdir(), 'metapi-model-discovery-'));
    process.env.DATA_DIR = dataDir;

    await import('../db/migrate.js');
    const dbModule = await import('../db/index.js');
    const modelService = await import('./modelService.js');

    db = dbModule.db;
    schema = dbModule.schema;
    refreshModelsForAccount = modelService.refreshModelsForAccount;
    refreshModelsAndRebuildRoutes = modelService.refreshModelsAndRebuildRoutes;
  });

  beforeEach(async () => {
    getApiTokenMock.mockReset();
    getModelsMock.mockReset();
    undiciFetchMock.mockReset();

    await db.delete(schema.routeChannels).run();
    await db.delete(schema.tokenRoutes).run();
    await db.delete(schema.tokenModelAvailability).run();
    await db.delete(schema.modelAvailability).run();
    await db.delete(schema.accountTokens).run();
    await db.delete(schema.accounts).run();
    await db.delete(schema.sites).run();
  });

  afterAll(() => {
    delete process.env.DATA_DIR;
  });

  it('discovers models from account session credential without account_tokens', async () => {
    getApiTokenMock.mockResolvedValue(null);
    getModelsMock.mockImplementation(async (_baseUrl: string, token: string) => (
      token === 'session-token' ? ['claude-sonnet-4-5-20250929', 'claude-opus-4-6'] : []
    ));

    const site = await db.insert(schema.sites).values({
      name: 'site-a',
      url: 'https://site-a.example.com',
      platform: 'new-api',
      status: 'active',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'alice',
      accessToken: 'session-token',
      apiToken: null,
      status: 'active',
    }).returning().get();

    const result = await refreshModelsForAccount(account.id);

    expect(result).toMatchObject({
      accountId: account.id,
      refreshed: true,
      status: 'success',
      errorCode: null,
      errorMessage: '',
      modelCount: 2,
      modelsPreview: ['claude-sonnet-4-5-20250929', 'claude-opus-4-6'],
      tokenScanned: 0,
      discoveredByCredential: true,
    });

    const rows = await db.select().from(schema.modelAvailability)
      .where(eq(schema.modelAvailability.accountId, account.id))
      .all();
    expect(rows.map((row) => row.modelName).sort()).toEqual([
      'claude-opus-4-6',
      'claude-sonnet-4-5-20250929',
    ]);

    const tokenRows = await db.select().from(schema.tokenModelAvailability).all();
    expect(tokenRows).toHaveLength(0);
  });

  it('deduplicates discovered model names before writing availability rows', async () => {
    getApiTokenMock.mockResolvedValue(null);
    getModelsMock.mockResolvedValue(['? ', '?', 'GPT-4.1', 'gpt-4.1']);

    const site = await db.insert(schema.sites).values({
      name: 'site-dedupe',
      url: 'https://site-dedupe.example.com',
      platform: 'new-api',
      status: 'active',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'dedupe-user',
      accessToken: 'session-token',
      apiToken: null,
      status: 'active',
    }).returning().get();

    const result = await refreshModelsForAccount(account.id);

    expect(result).toMatchObject({
      accountId: account.id,
      refreshed: true,
      status: 'success',
      modelCount: 2,
      modelsPreview: ['?', 'GPT-4.1'],
    });

    const rows = await db.select().from(schema.modelAvailability)
      .where(eq(schema.modelAvailability.accountId, account.id))
      .all();

    expect(rows.map((row) => row.modelName).sort()).toEqual(['?', 'GPT-4.1']);
  });

  it('reuses one in-flight full refresh when concurrent callers request a rebuild', async () => {
    getApiTokenMock.mockResolvedValue(null);

    let releaseGate: (() => void) | null = null;
    const gate = new Promise<void>((resolve) => {
      releaseGate = resolve;
    });

    getModelsMock.mockImplementation(async () => {
      await gate;
      return ['gpt-5-nano'];
    });

    const site = await db.insert(schema.sites).values({
      name: 'site-concurrent-refresh',
      url: 'https://site-concurrent-refresh.example.com',
      platform: 'new-api',
      status: 'active',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'concurrent-refresh-user',
      accessToken: 'shared-credential',
      apiToken: 'shared-credential',
      status: 'active',
      extraConfig: JSON.stringify({ credentialMode: 'session' }),
    }).returning().get();

    await db.insert(schema.accountTokens).values({
      accountId: account.id,
      name: 'default',
      token: 'shared-credential',
      source: 'manual',
      enabled: true,
      isDefault: true,
    }).run();

    const firstRefresh = refreshModelsAndRebuildRoutes();
    const secondRefresh = refreshModelsAndRebuildRoutes();
    await Promise.resolve();
    await Promise.resolve();
    releaseGate?.();

    const results = await Promise.allSettled([firstRefresh, secondRefresh]);
    expect(results.every((item) => item.status === 'fulfilled')).toBe(true);
    expect(getModelsMock).toHaveBeenCalledTimes(2);

    const modelRows = await db.select().from(schema.modelAvailability)
      .where(eq(schema.modelAvailability.accountId, account.id))
      .all();
    expect(modelRows.map((row) => row.modelName)).toEqual(['gpt-5-nano']);

    const token = await db.select().from(schema.accountTokens)
      .where(eq(schema.accountTokens.accountId, account.id))
      .get();
    const tokenRows = await db.select().from(schema.tokenModelAvailability)
      .where(eq(schema.tokenModelAvailability.tokenId, token!.id))
      .all();
    expect(tokenRows.map((row) => row.modelName)).toEqual(['gpt-5-nano']);
  });

  it('marks runtime health unhealthy when model discovery fails', async () => {
    getApiTokenMock.mockResolvedValue(null);
    getModelsMock.mockRejectedValue(new Error('HTTP 401: invalid token'));

    const site = await db.insert(schema.sites).values({
      name: 'site-fail',
      url: 'https://site-fail.example.com',
      platform: 'new-api',
      status: 'active',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'fail-user',
      accessToken: '',
      apiToken: 'sk-invalid',
      status: 'active',
      extraConfig: JSON.stringify({ credentialMode: 'apikey' }),
    }).returning().get();

    const result = await refreshModelsForAccount(account.id);

    expect(result).toMatchObject({
      accountId: account.id,
      refreshed: true,
      modelCount: 0,
      modelsPreview: [],
      tokenScanned: 0,
      status: 'failed',
      errorCode: 'unauthorized',
    });

    const latest = await db.select().from(schema.accounts)
      .where(eq(schema.accounts.id, account.id))
      .get();
    const parsed = JSON.parse(latest!.extraConfig || '{}');
    expect(parsed.runtimeHealth?.state).toBe('unhealthy');
    expect(parsed.runtimeHealth?.source).toBe('model-discovery');
    expect(parsed.runtimeHealth?.reason).toBe('模型获取失败，API Key 已无效');
    expect(parsed.runtimeHealth?.checkedAt).toMatch(/\d{4}-\d{2}-\d{2}T/);
  });

  it('returns structured result when account missing', async () => {
    const result = await refreshModelsForAccount(9999);

    expect(result).toMatchObject({
      accountId: 9999,
      refreshed: false,
      status: 'failed',
      errorCode: 'account_not_found',
      errorMessage: '账号不存在',
      modelCount: 0,
      modelsPreview: [],
      reason: 'account_not_found',
    });
  });

  it('returns structured result when site disabled', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'site-disabled',
      url: 'https://site-disabled.example.com',
      platform: 'new-api',
      status: 'disabled',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'disabled-user',
      accessToken: 'session-token',
      apiToken: null,
      status: 'active',
    }).returning().get();

    const result = await refreshModelsForAccount(account.id);

    expect(result).toMatchObject({
      accountId: account.id,
      refreshed: false,
      status: 'skipped',
      errorCode: 'site_disabled',
      errorMessage: '站点已禁用',
      modelCount: 0,
      modelsPreview: [],
      reason: 'site_disabled',
    });
  });

  it('returns structured result when account inactive', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'site-inactive',
      url: 'https://site-inactive.example.com',
      platform: 'new-api',
      status: 'active',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'inactive-user',
      accessToken: 'session-token',
      apiToken: null,
      status: 'disabled',
    }).returning().get();

    const result = await refreshModelsForAccount(account.id);

    expect(result).toMatchObject({
      accountId: account.id,
      refreshed: false,
      status: 'skipped',
      errorCode: 'adapter_or_status',
      errorMessage: '平台不可用或账号未激活',
      modelCount: 0,
      modelsPreview: [],
      reason: 'adapter_or_status',
    });
  });

  it('does not scan masked_pending placeholders as token credentials', async () => {
    getApiTokenMock.mockResolvedValue(null);
    getModelsMock.mockImplementation(async (_baseUrl: string, token: string) => (
      token === 'sk-mask***tail' ? ['gpt-5.2-codex'] : []
    ));

    const site = await db.insert(schema.sites).values({
      name: 'site-placeholder',
      url: 'https://site-placeholder.example.com',
      platform: 'new-api',
      status: 'active',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'placeholder-user',
      accessToken: '',
      apiToken: null,
      status: 'active',
      extraConfig: JSON.stringify({ credentialMode: 'session' }),
    }).returning().get();

    const placeholder = await db.insert(schema.accountTokens).values({
      accountId: account.id,
      name: 'masked-token',
      token: 'sk-mask***tail',
      source: 'sync',
      enabled: true,
      isDefault: false,
      valueStatus: 'masked_pending' as any,
    }).returning().get();

    const result = await refreshModelsForAccount(account.id);

    expect(result).toMatchObject({
      accountId: account.id,
      refreshed: true,
      status: 'failed',
      tokenScanned: 0,
    });

    const placeholderModels = await db.select().from(schema.tokenModelAvailability)
      .where(eq(schema.tokenModelAvailability.tokenId, placeholder.id))
      .all();
    expect(placeholderModels).toEqual([]);
    expect(getModelsMock).not.toHaveBeenCalledWith(site.url, 'sk-mask***tail', account.username);
  });

  it('discovers codex models from upstream cloud endpoint without adapter model fetch', async () => {
    getApiTokenMock.mockResolvedValue(null);
    getModelsMock.mockRejectedValue(new Error('codex plan discovery should not call adapter.getModels'));
    undiciFetchMock.mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        models: [
          { id: 'gpt-5.4' },
          { id: 'gpt-5.3-codex' },
          { id: 'gpt-5.2-codex' },
          { id: 'gpt-5.2' },
          { id: 'gpt-5.1-codex-max' },
          { id: 'gpt-5.1-codex' },
          { id: 'gpt-5.1' },
          { id: 'gpt-5-codex' },
          { id: 'gpt-5' },
          { id: 'gpt-5.1-codex-mini' },
          { id: 'gpt-5-codex-mini' },
        ],
      }),
      text: async () => JSON.stringify({ ok: true }),
    });

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
          planType: 'plus',
        },
      }),
    }).returning().get();

    const result = await refreshModelsForAccount(account.id);

    expect(result).toMatchObject({
      accountId: account.id,
      refreshed: true,
      status: 'success',
      errorCode: null,
      tokenScanned: 0,
      discoveredByCredential: true,
      modelCount: 11,
    });
    expect(result.modelsPreview).toEqual([
      'gpt-5.4',
      'gpt-5.3-codex',
      'gpt-5.2-codex',
      'gpt-5.2',
      'gpt-5.1-codex-max',
      'gpt-5.1-codex',
      'gpt-5.1',
      'gpt-5-codex',
      'gpt-5',
      'gpt-5.1-codex-mini',
    ]);
    expect(getModelsMock).not.toHaveBeenCalled();
    expect(undiciFetchMock).toHaveBeenCalledTimes(1);
    expect(String(undiciFetchMock.mock.calls[0]?.[0] || '')).toBe('https://chatgpt.com/backend-api/codex/models?client_version=1.0.0');
    expect(undiciFetchMock.mock.calls[0]?.[1]).toMatchObject({
      method: 'GET',
      headers: expect.objectContaining({
        Authorization: 'Bearer oauth-access-token',
        'Chatgpt-Account-Id': 'chatgpt-account-123',
        Originator: 'codex_cli_rs',
      }),
    });

    const rows = await db.select().from(schema.modelAvailability)
      .where(eq(schema.modelAvailability.accountId, account.id))
      .all();
    const modelNames = rows.map((row) => row.modelName);
    expect(modelNames.sort()).toEqual([
      'gpt-5',
      'gpt-5-codex',
      'gpt-5-codex-mini',
      'gpt-5.1',
      'gpt-5.1-codex',
      'gpt-5.1-codex-max',
      'gpt-5.1-codex-mini',
      'gpt-5.2',
      'gpt-5.2-codex',
      'gpt-5.3-codex',
      'gpt-5.4',
    ]);
  });

  it('marks codex oauth account abnormal when upstream cloud discovery fails', async () => {
    getApiTokenMock.mockResolvedValue(null);
    getModelsMock.mockRejectedValue(new Error('codex plan discovery should not call adapter.getModels'));
    undiciFetchMock.mockResolvedValue({
      ok: false,
      status: 403,
      json: async () => ({ error: 'forbidden' }),
      text: async () => 'forbidden',
    });

    const site = await db.insert(schema.sites).values({
      name: 'codex-team-site',
      url: 'https://chatgpt.com/backend-api/codex',
      platform: 'codex',
      status: 'active',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'team-user@example.com',
      accessToken: 'oauth-access-token',
      apiToken: null,
      status: 'active',
      extraConfig: JSON.stringify({
        credentialMode: 'session',
        oauth: {
          provider: 'codex',
          accountId: 'chatgpt-account-team',
          email: 'team-user@example.com',
          planType: 'team',
        },
      }),
    }).returning().get();

    await db.insert(schema.modelAvailability).values({
      accountId: account.id,
      modelName: 'gpt-5.2-codex',
      available: true,
      checkedAt: '2026-03-16T12:00:00.000Z',
    }).run();

    const result = await refreshModelsForAccount(account.id);

    expect(result).toMatchObject({
      accountId: account.id,
      refreshed: true,
      status: 'failed',
      errorCode: 'unauthorized',
      tokenScanned: 0,
      discoveredByCredential: false,
      modelCount: 0,
    });
    expect(getModelsMock).not.toHaveBeenCalled();
    expect(undiciFetchMock).toHaveBeenCalledTimes(1);

    const rows = await db.select().from(schema.modelAvailability)
      .where(eq(schema.modelAvailability.accountId, account.id))
      .all();
    expect(rows).toEqual([]);

    const latest = await db.select().from(schema.accounts)
      .where(eq(schema.accounts.id, account.id))
      .get();
    const parsed = JSON.parse(latest!.extraConfig || '{}');
    expect(parsed.oauth).toMatchObject({
      provider: 'codex',
      modelDiscoveryStatus: 'abnormal',
    });
    expect(parsed.oauth.lastModelSyncError).toContain('HTTP 403');
    expect(parsed.oauth.lastModelSyncAt).toMatch(/\d{4}-\d{2}-\d{2}T/);
    expect(parsed.runtimeHealth?.state).toBe('unhealthy');
  });

  it('discovers antigravity oauth models via fetchAvailableModels fallback using the oauth project id', async () => {
    getApiTokenMock.mockResolvedValue(null);
    getModelsMock.mockRejectedValue(new Error('antigravity oauth discovery should not call adapter.getModels'));
    undiciFetchMock
      .mockResolvedValueOnce({
        ok: false,
        status: 503,
        json: async () => ({ error: 'unavailable' }),
        text: async () => 'unavailable',
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          models: {
            'gemini-3-pro-preview': { displayName: 'Gemini 3 Pro Preview' },
            'claude-sonnet-4-5-20250929': { displayName: 'Claude Sonnet 4.5' },
          },
        }),
        text: async () => JSON.stringify({ ok: true }),
      });

    const site = await db.insert(schema.sites).values({
      name: 'antigravity-site',
      url: 'https://cloudcode-pa.googleapis.com',
      platform: 'antigravity',
      status: 'active',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'antigravity-user@example.com',
      accessToken: 'antigravity-access-token',
      apiToken: null,
      status: 'active',
      extraConfig: JSON.stringify({
        credentialMode: 'session',
        oauth: {
          provider: 'antigravity',
          email: 'antigravity-user@example.com',
          projectId: 'project-demo',
        },
      }),
    }).returning().get();

    const result = await refreshModelsForAccount(account.id);

    expect(result).toMatchObject({
      accountId: account.id,
      refreshed: true,
      status: 'success',
      errorCode: null,
      tokenScanned: 0,
      discoveredByCredential: true,
      discoveredApiToken: false,
      modelCount: 2,
      modelsPreview: ['gemini-3-pro-preview', 'claude-sonnet-4-5-20250929'],
    });
    expect(getModelsMock).not.toHaveBeenCalled();
    expect(undiciFetchMock).toHaveBeenCalledTimes(2);
    expect(String(undiciFetchMock.mock.calls[0]?.[0] || '')).toBe('https://cloudcode-pa.googleapis.com/v1internal:fetchAvailableModels');
    expect(String(undiciFetchMock.mock.calls[1]?.[0] || '')).toBe('https://daily-cloudcode-pa.googleapis.com/v1internal:fetchAvailableModels');
    expect(undiciFetchMock.mock.calls[0]?.[1]).toMatchObject({
      method: 'POST',
      headers: expect.objectContaining({
        Authorization: 'Bearer antigravity-access-token',
        Accept: 'application/json',
        'Content-Type': 'application/json',
        'User-Agent': 'antigravity/1.19.6 darwin/arm64',
      }),
    });
    const discoveryHeaders = undiciFetchMock.mock.calls[0]?.[1]?.headers as Record<string, string>;
    expect(discoveryHeaders).not.toHaveProperty('X-Goog-Api-Client');
    expect(discoveryHeaders).not.toHaveProperty('Client-Metadata');
    expect(JSON.parse(String(undiciFetchMock.mock.calls[0]?.[1]?.body || '{}'))).toEqual({
      project: 'project-demo',
    });

    const rows = await db.select().from(schema.modelAvailability)
      .where(eq(schema.modelAvailability.accountId, account.id))
      .all();
    expect(rows.map((row) => row.modelName).sort()).toEqual([
      'claude-sonnet-4-5-20250929',
      'gemini-3-pro-preview',
    ]);
  });
});
