import Fastify, { type FastifyInstance } from 'fastify';
import { describe, expect, it, beforeAll, beforeEach, afterAll, vi } from 'vitest';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { mkdtempSync } from 'node:fs';
import { and, eq, sql } from 'drizzle-orm';
import { mergeAccountExtraConfig } from '../../services/accountExtraConfig.js';

const getApiTokensMock = vi.fn();
const getApiTokenMock = vi.fn();
const createApiTokenMock = vi.fn();
const getUserGroupsMock = vi.fn();
const deleteApiTokenMock = vi.fn();

type AccountTokenServiceModule = typeof import('../../services/accountTokenService.js');

vi.mock('../../services/platforms/index.js', () => ({
  getAdapter: () => ({
    getApiTokens: (...args: unknown[]) => getApiTokensMock(...args),
    getApiToken: (...args: unknown[]) => getApiTokenMock(...args),
    createApiToken: (...args: unknown[]) => createApiTokenMock(...args),
    getUserGroups: (...args: unknown[]) => getUserGroupsMock(...args),
    deleteApiToken: (...args: unknown[]) => deleteApiTokenMock(...args),
  }),
}));

type DbModule = typeof import('../../db/index.js');

describe('account tokens sync routes with site status', () => {
  let app: FastifyInstance;
  let db: DbModule['db'];
  let schema: DbModule['schema'];
  let maskToken: AccountTokenServiceModule['maskToken'];
  let dataDir = '';
  let seedId = 0;

  const nextSeed = () => {
    seedId += 1;
    return seedId;
  };

  const seedAccount = async (input: { siteStatus?: 'active' | 'disabled'; accountStatus?: string; accessToken?: string | null }) => {
    const id = nextSeed();
    const site = await db.insert(schema.sites).values({
      name: `site-${id}`,
      url: `https://site-${id}.example.com`,
      platform: 'new-api',
    }).returning().get();
    if (input.siteStatus === 'disabled') {
      await db.run(sql`update sites set status = 'disabled' where id = ${site.id}`);
    }

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: `user-${id}`,
      accessToken: input.accessToken ?? `access-token-${id}`,
      status: input.accountStatus ?? 'active',
    }).returning().get();

    return { site, account };
  };

  beforeAll(async () => {
    dataDir = mkdtempSync(join(tmpdir(), 'metapi-account-tokens-sync-'));
    process.env.DATA_DIR = dataDir;

    await import('../../db/migrate.js');
    const dbModule = await import('../../db/index.js');
    const accountTokenServiceModule = await import('../../services/accountTokenService.js');
    const routesModule = await import('./accountTokens.js');
    db = dbModule.db;
    schema = dbModule.schema;
    maskToken = accountTokenServiceModule.maskToken;

    app = Fastify();
    await app.register(routesModule.accountTokensRoutes);
  });

  beforeEach(async () => {
    getApiTokensMock.mockReset();
    getApiTokenMock.mockReset();
    createApiTokenMock.mockReset();
    getUserGroupsMock.mockReset();
    deleteApiTokenMock.mockReset();
    seedId = 0;

    await db.delete(schema.accountTokens).run();
    await db.delete(schema.routeChannels).run();
    await db.delete(schema.tokenRoutes).run();
    await db.delete(schema.tokenModelAvailability).run();
    await db.delete(schema.modelAvailability).run();
    await db.delete(schema.checkinLogs).run();
    await db.delete(schema.accounts).run();
    await db.delete(schema.sites).run();
  });

  afterAll(async () => {
    await app.close();
    delete process.env.DATA_DIR;
  });

  it('returns skipped for single-account sync when site is disabled', async () => {
    const { account } = await seedAccount({ siteStatus: 'disabled' });

    const response = await app.inject({
      method: 'POST',
      url: `/api/account-tokens/sync/${account.id}`,
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      success: true,
      synced: false,
      status: 'skipped',
      reason: 'site_disabled',
    });
    expect(getApiTokensMock).not.toHaveBeenCalled();
    expect(getApiTokenMock).not.toHaveBeenCalled();
  });

  it('returns skipped when upstream has no api tokens', async () => {
    const { account } = await seedAccount({ siteStatus: 'active' });
    getApiTokensMock.mockResolvedValue([]);
    getApiTokenMock.mockResolvedValue(null);

    const response = await app.inject({
      method: 'POST',
      url: `/api/account-tokens/sync/${account.id}`,
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      success: true,
      synced: false,
      status: 'skipped',
      reason: 'no_upstream_tokens',
    });

    const tokenRows = await db.select()
      .from(schema.accountTokens)
      .where(eq(schema.accountTokens.accountId, account.id))
      .all();
    expect(tokenRows.length).toBe(0);
  });

  it('stores masked upstream token values as masked_pending placeholders', async () => {
    const { account } = await seedAccount({ siteStatus: 'active' });
    getApiTokensMock.mockResolvedValue([
      { name: 'masked-only', key: 'sk-abc***xyz', enabled: true },
    ]);
    getApiTokenMock.mockResolvedValue(null);

    const response = await app.inject({
      method: 'POST',
      url: `/api/account-tokens/sync/${account.id}`,
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      success: true,
      synced: true,
      status: 'synced',
      reason: 'upstream_masked_tokens',
      maskedPending: 1,
      pendingTokenIds: [expect.any(Number)],
      total: 1,
      created: 1,
      updated: 0,
    });

    const tokenRows = await db.select()
      .from(schema.accountTokens)
      .where(eq(schema.accountTokens.accountId, account.id))
      .all();
    expect(tokenRows).toHaveLength(1);
    expect(tokenRows[0]).toMatchObject({
      name: 'masked-only',
      token: 'sk-abc***xyz',
      source: 'sync',
      enabled: false,
      isDefault: false,
    });
    expect((tokenRows[0] as any).valueStatus).toBe('masked_pending');

    const owner = await db.select()
      .from(schema.accounts)
      .where(eq(schema.accounts.id, account.id))
      .get();
    expect(owner?.apiToken ?? null).toBeNull();

    const listResponse = await app.inject({
      method: 'GET',
      url: '/api/account-tokens',
    });
    expect(listResponse.statusCode).toBe(200);
    expect(listResponse.json()).toMatchObject([
      expect.objectContaining({
        id: tokenRows[0].id,
        valueStatus: 'masked_pending',
      }),
    ]);
  });

  it('reuses an existing ready token when upstream only returns the matching masked token', async () => {
    const { account } = await seedAccount({ siteStatus: 'active' });
    const fullToken = 'sk-real-token-1234';
    await db.insert(schema.accountTokens).values({
      accountId: account.id,
      name: 'masked-only',
      token: fullToken,
      source: 'manual',
      enabled: true,
      isDefault: true,
      tokenGroup: 'default',
      valueStatus: 'ready' as any,
    }).run();

    getApiTokensMock.mockResolvedValue([
      { name: 'masked-only', key: maskToken(fullToken), enabled: true, tokenGroup: 'default' },
    ]);
    getApiTokenMock.mockResolvedValue(null);

    const response = await app.inject({
      method: 'POST',
      url: `/api/account-tokens/sync/${account.id}`,
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      success: true,
      synced: true,
      status: 'synced',
      created: 0,
      updated: 1,
      maskedPending: 0,
      total: 1,
    });

    const tokenRows = await db.select()
      .from(schema.accountTokens)
      .where(eq(schema.accountTokens.accountId, account.id))
      .all();
    expect(tokenRows).toHaveLength(1);
    expect(tokenRows[0]).toMatchObject({
      name: 'masked-only',
      token: fullToken,
      source: 'sync',
      enabled: true,
      isDefault: true,
      tokenGroup: 'default',
    });
    expect((tokenRows[0] as any).valueStatus).toBe('ready');
  });

  it('removes matching masked_pending placeholders after reusing a ready token', async () => {
    const { account } = await seedAccount({ siteStatus: 'active' });
    const fullToken = 'sk-real-token-1234';
    const maskedToken = maskToken(fullToken);

    await db.insert(schema.accountTokens).values({
      accountId: account.id,
      name: 'masked-only',
      token: fullToken,
      source: 'manual',
      enabled: true,
      isDefault: true,
      tokenGroup: 'default',
      valueStatus: 'ready' as any,
    }).run();
    await db.insert(schema.accountTokens).values({
      accountId: account.id,
      name: 'masked-only',
      token: maskedToken,
      source: 'sync',
      enabled: false,
      isDefault: false,
      tokenGroup: 'default',
      valueStatus: 'masked_pending' as any,
    }).run();

    getApiTokensMock.mockResolvedValue([
      { name: 'masked-only', key: maskedToken, enabled: true, tokenGroup: 'default' },
    ]);
    getApiTokenMock.mockResolvedValue(null);

    const response = await app.inject({
      method: 'POST',
      url: `/api/account-tokens/sync/${account.id}`,
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      success: true,
      synced: true,
      status: 'synced',
      created: 0,
      updated: 1,
      maskedPending: 0,
      total: 1,
    });

    const tokenRows = await db.select()
      .from(schema.accountTokens)
      .where(eq(schema.accountTokens.accountId, account.id))
      .all();
    expect(tokenRows).toHaveLength(1);
    expect(tokenRows[0]).toMatchObject({
      name: 'masked-only',
      token: fullToken,
      source: 'sync',
      enabled: true,
      isDefault: true,
      tokenGroup: 'default',
    });
    expect((tokenRows[0] as any).valueStatus).toBe('ready');
  });

  it('does not reuse a different ready token when another logical token shares the same masked value', async () => {
    const { account } = await seedAccount({ siteStatus: 'active' });
    const firstFullToken = 'sk-real-token-1234';
    const secondFullToken = 'sk-real-zzzzz-1234';
    const sharedMaskedToken = maskToken(firstFullToken);

    expect(maskToken(secondFullToken)).toBe(sharedMaskedToken);

    await db.insert(schema.accountTokens).values({
      accountId: account.id,
      name: 'first-token',
      token: firstFullToken,
      source: 'manual',
      enabled: true,
      isDefault: true,
      tokenGroup: 'default',
      valueStatus: 'ready' as any,
    }).run();
    await db.insert(schema.accountTokens).values({
      accountId: account.id,
      name: 'second-token',
      token: sharedMaskedToken,
      source: 'sync',
      enabled: false,
      isDefault: false,
      tokenGroup: 'default',
      valueStatus: 'masked_pending' as any,
    }).run();

    getApiTokensMock.mockResolvedValue([
      { name: 'second-token', key: sharedMaskedToken, enabled: true, tokenGroup: 'default' },
    ]);
    getApiTokenMock.mockResolvedValue(null);

    const response = await app.inject({
      method: 'POST',
      url: `/api/account-tokens/sync/${account.id}`,
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      success: true,
      synced: true,
      status: 'synced',
      created: 0,
      updated: 1,
      maskedPending: 1,
      total: 2,
    });

    const tokenRows = await db.select()
      .from(schema.accountTokens)
      .where(eq(schema.accountTokens.accountId, account.id))
      .all();
    expect(tokenRows).toHaveLength(2);
    expect(tokenRows.find((row) => row.token === firstFullToken)).toMatchObject({
      name: 'first-token',
      token: firstFullToken,
      source: 'manual',
      enabled: true,
      isDefault: true,
      tokenGroup: 'default',
    });
    const maskedRow = tokenRows.find((row) => row.name === 'second-token');
    expect(maskedRow).toMatchObject({
      token: sharedMaskedToken,
      source: 'sync',
      enabled: false,
      isDefault: false,
      tokenGroup: 'default',
    });
    expect((maskedRow as any)?.valueStatus).toBe('masked_pending');
  });

  it('keeps fully ambiguous short masks as masked_pending instead of reusing a ready token', async () => {
    const { account } = await seedAccount({ siteStatus: 'active' });
    const fullToken = 'sk-abcd';
    await db.insert(schema.accountTokens).values({
      accountId: account.id,
      name: 'short-token',
      token: fullToken,
      source: 'manual',
      enabled: true,
      isDefault: true,
      tokenGroup: 'default',
      valueStatus: 'ready' as any,
    }).run();

    getApiTokensMock.mockResolvedValue([
      { name: 'short-token', key: maskToken(fullToken), enabled: true, tokenGroup: 'default' },
    ]);
    getApiTokenMock.mockResolvedValue(null);

    const response = await app.inject({
      method: 'POST',
      url: `/api/account-tokens/sync/${account.id}`,
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      success: true,
      synced: true,
      status: 'synced',
      reason: 'upstream_masked_tokens',
      created: 1,
      updated: 0,
      maskedPending: 1,
      total: 2,
    });

    const tokenRows = await db.select()
      .from(schema.accountTokens)
      .where(eq(schema.accountTokens.accountId, account.id))
      .all();
    expect(tokenRows).toHaveLength(2);
    expect(tokenRows.find((row) => row.token === fullToken)).toBeDefined();
    const maskedRow = tokenRows.find((row) => row.token === 'sk-***');
    expect(maskedRow).toMatchObject({
      name: 'short-token',
      source: 'sync',
      enabled: false,
      isDefault: false,
      tokenGroup: 'default',
    });
    expect((maskedRow as any)?.valueStatus).toBe('masked_pending');
  });

  it('rejects sync and token management for apikey connections', async () => {
    const { account } = await seedAccount({ siteStatus: 'active', accessToken: '' });
    await db.update(schema.accounts)
      .set({
        apiToken: 'sk-proxy-only',
        checkinEnabled: false,
        extraConfig: mergeAccountExtraConfig(null, { credentialMode: 'apikey' }),
      })
      .where(eq(schema.accounts.id, account.id))
      .run();

    const syncResponse = await app.inject({
      method: 'POST',
      url: `/api/account-tokens/sync/${account.id}`,
    });
    expect(syncResponse.statusCode).toBe(400);
    expect(syncResponse.json()).toMatchObject({
      success: false,
      message: 'API Key 连接不支持同步账号令牌',
    });

    const createResponse = await app.inject({
      method: 'POST',
      url: '/api/account-tokens',
      payload: {
        accountId: account.id,
        name: 'should-fail',
      },
    });
    expect(createResponse.statusCode).toBe(400);
    expect(createResponse.json()).toMatchObject({
      success: false,
      message: 'API Key 连接不支持创建账号令牌',
    });

    const groupsResponse = await app.inject({
      method: 'GET',
      url: `/api/account-tokens/groups/${account.id}`,
    });
    expect(groupsResponse.statusCode).toBe(400);
    expect(groupsResponse.json()).toMatchObject({
      success: false,
      message: 'API Key 连接不支持拉取账号令牌分组',
    });
  });

  it('hides legacy mirrored tokens for apikey connections from list API', async () => {
    const { account } = await seedAccount({ siteStatus: 'active', accessToken: '' });
    await db.update(schema.accounts)
      .set({
        apiToken: 'sk-hidden-legacy',
        checkinEnabled: false,
        extraConfig: mergeAccountExtraConfig(null, { credentialMode: 'apikey' }),
      })
      .where(eq(schema.accounts.id, account.id))
      .run();

    await db.insert(schema.accountTokens).values({
      accountId: account.id,
      name: 'default',
      token: 'sk-hidden-legacy',
      enabled: true,
      isDefault: true,
    }).run();

    const response = await app.inject({
      method: 'GET',
      url: '/api/account-tokens',
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual([]);
  });

  it('sync-all skips disabled-site accounts and syncs active-site accounts', async () => {
    const disabled = await seedAccount({ siteStatus: 'disabled' });
    const active = await seedAccount({ siteStatus: 'active' });

    getApiTokensMock.mockResolvedValue([
      { name: 'default', key: 'sk-synced-token', enabled: true },
    ]);

    const response = await app.inject({
      method: 'POST',
      url: '/api/account-tokens/sync-all',
      payload: { wait: true },
    });

    expect(response.statusCode).toBe(200);

    const body = response.json() as {
      success: boolean;
      summary: {
        total: number;
        synced: number;
        skipped: number;
        failed: number;
      };
      results: Array<{ accountId: number; status: string; reason?: string; synced?: boolean }>;
    };

    expect(body.success).toBe(true);
    expect(body.summary).toMatchObject({
      total: 2,
      synced: 1,
      skipped: 1,
      failed: 0,
    });

    const skipped = body.results.find((item) => item.accountId === disabled.account.id);
    const synced = body.results.find((item) => item.accountId === active.account.id);

    expect(skipped).toMatchObject({
      accountId: disabled.account.id,
      status: 'skipped',
      reason: 'site_disabled',
    });
    expect(synced).toMatchObject({
      accountId: active.account.id,
      status: 'synced',
      synced: true,
    });

    const syncedDefaultToken = await db.select()
      .from(schema.accountTokens)
      .where(and(eq(schema.accountTokens.accountId, active.account.id), eq(schema.accountTokens.isDefault, true)))
      .get();
    expect(syncedDefaultToken?.token).toBe('sk-synced-token');
  });

  it('creates token via upstream api and syncs into local store when manual token is omitted', async () => {
    const { account, site } = await seedAccount({ siteStatus: 'active' });
    createApiTokenMock.mockResolvedValue(true);
    getApiTokensMock.mockResolvedValue([
      { name: 'created-from-upstream', key: 'sk-created-upstream-token', enabled: true },
    ]);

    const response = await app.inject({
      method: 'POST',
      url: '/api/account-tokens',
      payload: {
        accountId: account.id,
        name: 'created-from-upstream',
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      success: true,
      createdViaUpstream: true,
      synced: true,
      status: 'synced',
    });
    expect(createApiTokenMock).toHaveBeenCalledTimes(1);
    expect(createApiTokenMock.mock.calls[0][0]).toBe(site.url);
    expect(createApiTokenMock.mock.calls[0][1]).toBe(account.accessToken);

    const tokenRows = await db.select()
      .from(schema.accountTokens)
      .where(eq(schema.accountTokens.accountId, account.id))
      .all();

    expect(tokenRows.length).toBe(1);
    expect(tokenRows[0].name).toBe('created-from-upstream');
    expect(tokenRows[0].token).toBe('sk-created-upstream-token');
    expect(tokenRows[0].source).toBe('sync');
  });

  it('passes token creation options to upstream adapter', async () => {
    const { account } = await seedAccount({ siteStatus: 'active' });
    createApiTokenMock.mockResolvedValue(true);
    getApiTokensMock.mockResolvedValue([
      { name: 'custom-token', key: 'sk-created-upstream-token', enabled: true },
    ]);

    const response = await app.inject({
      method: 'POST',
      url: '/api/account-tokens',
      payload: {
        accountId: account.id,
        name: 'custom-token',
        group: 'vip',
        unlimitedQuota: false,
        remainQuota: 123456,
        expiredTime: 2_000_000_000,
        allowIps: '1.1.1.1,2.2.2.2',
      },
    });

    expect(response.statusCode).toBe(200);
    expect(createApiTokenMock).toHaveBeenCalledTimes(1);
    expect(createApiTokenMock.mock.calls[0][3]).toMatchObject({
      name: 'custom-token',
      group: 'vip',
      unlimitedQuota: false,
      remainQuota: 123456,
      expiredTime: 2_000_000_000,
      allowIps: '1.1.1.1,2.2.2.2',
    });
  });

  it('returns 400 when limited token misses remainQuota', async () => {
    const { account } = await seedAccount({ siteStatus: 'active' });

    const response = await app.inject({
      method: 'POST',
      url: '/api/account-tokens',
      payload: {
        accountId: account.id,
        name: 'bad-token',
        unlimitedQuota: false,
      },
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({
      success: false,
      message: '有限额度令牌必须填写 remainQuota',
    });
    expect(createApiTokenMock).not.toHaveBeenCalled();
  });

  it('returns 502 when upstream token creation fails', async () => {
    const { account } = await seedAccount({ siteStatus: 'active' });
    createApiTokenMock.mockResolvedValue(false);

    const response = await app.inject({
      method: 'POST',
      url: '/api/account-tokens',
      payload: {
        accountId: account.id,
        name: 'created-from-upstream',
      },
    });

    expect(response.statusCode).toBe(502);
    expect(response.json()).toMatchObject({
      success: false,
      message: '站点创建令牌失败',
    });
  });

  it('fetches account token groups from upstream', async () => {
    const { account } = await seedAccount({ siteStatus: 'active' });
    getUserGroupsMock.mockResolvedValue(['default', 'vip']);

    const response = await app.inject({
      method: 'GET',
      url: `/api/account-tokens/groups/${account.id}`,
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      success: true,
      groups: ['default', 'vip'],
    });
    expect(getUserGroupsMock).toHaveBeenCalledTimes(1);
  });

  it('deletes upstream token before removing local token', async () => {
    const { account, site } = await seedAccount({ siteStatus: 'active' });
    const token = await db.insert(schema.accountTokens).values({
      accountId: account.id,
      name: 'upstream-token',
      token: 'sk-upstream-token',
      source: 'sync',
      enabled: true,
      isDefault: false,
    }).returning().get();
    deleteApiTokenMock.mockResolvedValue(true);

    const response = await app.inject({
      method: 'DELETE',
      url: `/api/account-tokens/${token.id}`,
    });

    expect(response.statusCode).toBe(200);
    expect(deleteApiTokenMock).toHaveBeenCalledTimes(1);
    expect(deleteApiTokenMock.mock.calls[0][0]).toBe(site.url);
    expect(deleteApiTokenMock.mock.calls[0][1]).toBe(account.accessToken);
    expect(deleteApiTokenMock.mock.calls[0][2]).toBe('sk-upstream-token');

    const removed = await db.select().from(schema.accountTokens).where(eq(schema.accountTokens.id, token.id)).get();
    expect(removed).toBeUndefined();
  });

  it('keeps local token when upstream deletion fails', async () => {
    const { account } = await seedAccount({ siteStatus: 'active' });
    const token = await db.insert(schema.accountTokens).values({
      accountId: account.id,
      name: 'upstream-token',
      token: 'sk-upstream-token',
      source: 'sync',
      enabled: true,
      isDefault: false,
    }).returning().get();
    deleteApiTokenMock.mockResolvedValue(false);

    const response = await app.inject({
      method: 'DELETE',
      url: `/api/account-tokens/${token.id}`,
    });

    expect(response.statusCode).toBe(502);
    expect(response.json()).toMatchObject({
      success: false,
      message: '站点删除令牌失败，本地未删除',
    });

    const existing = await db.select().from(schema.accountTokens).where(eq(schema.accountTokens.id, token.id)).get();
    expect(existing).toBeDefined();
  });

  it('rejects retrieving token value when stored token is masked', async () => {
    const { account } = await seedAccount({ siteStatus: 'active' });
    const token = await db.insert(schema.accountTokens).values({
      accountId: account.id,
      name: 'masked-token',
      token: 'sk-mask***tail',
      source: 'sync',
      enabled: true,
      isDefault: false,
      valueStatus: 'masked_pending' as any,
    }).returning().get();

    const response = await app.inject({
      method: 'GET',
      url: `/api/account-tokens/${token.id}/value`,
    });

    expect(response.statusCode).toBe(409);
    expect(response.json()).toMatchObject({
      success: false,
    });
  });

  it('upgrades an existing masked_pending placeholder when upstream later returns the full token', async () => {
    const { account } = await seedAccount({ siteStatus: 'active' });
    await db.insert(schema.accountTokens).values({
      accountId: account.id,
      name: 'masked-only',
      token: 'sk-abc***xyz',
      source: 'sync',
      enabled: false,
      isDefault: false,
      tokenGroup: 'default',
      valueStatus: 'masked_pending' as any,
    }).run();

    getApiTokensMock.mockResolvedValue([
      { name: 'masked-only', key: 'sk-real-token-1234', enabled: true, tokenGroup: 'default' },
    ]);
    getApiTokenMock.mockResolvedValue(null);

    const response = await app.inject({
      method: 'POST',
      url: `/api/account-tokens/sync/${account.id}`,
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      success: true,
      synced: true,
      status: 'synced',
      total: 1,
      created: 0,
      updated: 1,
    });

    const tokenRows = await db.select()
      .from(schema.accountTokens)
      .where(eq(schema.accountTokens.accountId, account.id))
      .all();
    expect(tokenRows).toHaveLength(1);
    expect(tokenRows[0]).toMatchObject({
      name: 'masked-only',
      token: 'sk-real-token-1234',
      enabled: true,
    });
    expect((tokenRows[0] as any).valueStatus).toBe('ready');
  });

  it('does not allow setting a masked_pending placeholder as default', async () => {
    const { account } = await seedAccount({ siteStatus: 'active' });
    const token = await db.insert(schema.accountTokens).values({
      accountId: account.id,
      name: 'masked-token',
      token: 'sk-mask***tail',
      source: 'sync',
      enabled: false,
      isDefault: false,
      valueStatus: 'masked_pending' as any,
    }).returning().get();

    const response = await app.inject({
      method: 'POST',
      url: `/api/account-tokens/${token.id}/default`,
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({
      success: false,
      message: expect.stringContaining('待补全令牌'),
    });
  });

  it('promotes a masked_pending placeholder to ready when a full token is saved', async () => {
    const { account } = await seedAccount({ siteStatus: 'active' });
    const token = await db.insert(schema.accountTokens).values({
      accountId: account.id,
      name: 'masked-token',
      token: 'sk-mask***tail',
      source: 'sync',
      enabled: false,
      isDefault: false,
      valueStatus: 'masked_pending' as any,
    }).returning().get();

    const response = await app.inject({
      method: 'PUT',
      url: `/api/account-tokens/${token.id}`,
      payload: {
        token: 'sk-real-token-updated',
        enabled: true,
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      success: true,
      token: expect.objectContaining({
        id: token.id,
        enabled: true,
        valueStatus: 'ready',
      }),
    });

    const latest = await db.select()
      .from(schema.accountTokens)
      .where(eq(schema.accountTokens.id, token.id))
      .get();
    expect(latest).toMatchObject({
      token: 'sk-real-token-updated',
      enabled: true,
    });
    expect((latest as any)?.valueStatus).toBe('ready');
  });

  it('deletes masked_pending placeholders locally without calling upstream delete', async () => {
    const { account } = await seedAccount({ siteStatus: 'active' });
    const token = await db.insert(schema.accountTokens).values({
      accountId: account.id,
      name: 'masked-token',
      token: 'sk-mask***tail',
      source: 'sync',
      enabled: false,
      isDefault: false,
      valueStatus: 'masked_pending' as any,
    }).returning().get();

    const response = await app.inject({
      method: 'DELETE',
      url: `/api/account-tokens/${token.id}`,
    });

    expect(response.statusCode).toBe(200);
    expect(deleteApiTokenMock).not.toHaveBeenCalled();
    const removed = await db.select().from(schema.accountTokens).where(eq(schema.accountTokens.id, token.id)).get();
    expect(removed).toBeUndefined();
  });
});
