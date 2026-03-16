import Fastify, { type FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const fetchMock = vi.fn();

vi.mock('undici', () => ({
  fetch: (...args: unknown[]) => fetchMock(...args),
}));

type DbModule = typeof import('../../db/index.js');

function buildJwt(payload: Record<string, unknown>) {
  const encode = (value: unknown) => Buffer.from(JSON.stringify(value))
    .toString('base64url');
  return `${encode({ alg: 'none', typ: 'JWT' })}.${encode(payload)}.signature`;
}

describe('oauth routes', { timeout: 15_000 }, () => {
  let app: FastifyInstance;
  let db: DbModule['db'];
  let schema: DbModule['schema'];
  let dataDir = '';

  beforeAll(async () => {
    dataDir = mkdtempSync(join(tmpdir(), 'metapi-oauth-routes-'));
    process.env.DATA_DIR = dataDir;

    await import('../../db/migrate.js');
    const dbModule = await import('../../db/index.js');
    const routesModule = await import('./oauth.js');
    db = dbModule.db;
    schema = dbModule.schema;

    app = Fastify();
    await app.register(routesModule.oauthRoutes);
  });

  beforeEach(async () => {
    fetchMock.mockReset();
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

  it('lists codex oauth provider metadata', async () => {
    const response = await app.inject({
      method: 'GET',
      url: '/api/oauth/providers',
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      providers: [
        expect.objectContaining({
          provider: 'codex',
          platform: 'codex',
          enabled: true,
          loginType: 'oauth',
        }),
      ],
    });
  });

  it('starts a codex oauth session and exposes pending status', async () => {
    const startResponse = await app.inject({
      method: 'POST',
      url: '/api/oauth/providers/codex/start',
      headers: {
        host: 'metapi.example',
        'x-forwarded-proto': 'https',
      },
    });

    expect(startResponse.statusCode).toBe(200);
    const startBody = startResponse.json() as {
      provider: string;
      state: string;
      authorizationUrl: string;
    };
    expect(startBody.provider).toBe('codex');
    expect(startBody.state).toMatch(/^[a-zA-Z0-9_-]{20,}$/);
    expect(startBody.authorizationUrl).toContain('https://auth.openai.com/oauth/authorize?');
    expect(startBody.authorizationUrl).toContain('client_id=');
    expect(startBody.authorizationUrl).toContain(encodeURIComponent('http://localhost:1455/auth/callback'));
    expect(startBody.authorizationUrl).toContain(`state=${encodeURIComponent(startBody.state)}`);
    expect(startBody.authorizationUrl).toContain('code_challenge=');

    const sessionResponse = await app.inject({
      method: 'GET',
      url: `/api/oauth/sessions/${startBody.state}`,
    });
    expect(sessionResponse.statusCode).toBe(200);
    expect(sessionResponse.json()).toMatchObject({
      provider: 'codex',
      state: startBody.state,
      status: 'pending',
    });
  });

  it('handles codex callback, creates oauth-backed account, and discovers plan models', async () => {
    const jwt = buildJwt({
      email: 'codex-user@example.com',
      'https://api.openai.com/auth': {
        chatgpt_account_id: 'chatgpt-account-123',
        chatgpt_plan_type: 'plus',
      },
    });
    fetchMock
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          access_token: 'oauth-access-token',
          refresh_token: 'oauth-refresh-token',
          id_token: jwt,
          expires_in: 3600,
          token_type: 'Bearer',
        }),
        text: async () => JSON.stringify({ ok: true }),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          models: [
            { id: 'gpt-5.2-codex' },
            { id: 'gpt-5' },
            { id: 'gpt-5.4' },
          ],
        }),
        text: async () => JSON.stringify({ ok: true }),
      });

    const startResponse = await app.inject({
      method: 'POST',
      url: '/api/oauth/providers/codex/start',
      headers: {
        host: 'metapi.example',
        'x-forwarded-proto': 'https',
      },
    });
    const startBody = startResponse.json() as { state: string };

    const callbackResponse = await app.inject({
      method: 'GET',
      url: `/api/oauth/callback/codex?state=${encodeURIComponent(startBody.state)}&code=oauth-code-123`,
      headers: {
        host: 'metapi.example',
        'x-forwarded-proto': 'https',
      },
    });
    expect(callbackResponse.statusCode).toBe(200);
    expect(callbackResponse.body).toContain('window.close()');

    const sessionResponse = await app.inject({
      method: 'GET',
      url: `/api/oauth/sessions/${startBody.state}`,
    });
    expect(sessionResponse.statusCode).toBe(200);
    const sessionBody = sessionResponse.json() as {
      provider: string;
      status: string;
      accountId?: number;
      siteId?: number;
    };
    expect(sessionBody).toMatchObject({
      provider: 'codex',
      status: 'success',
    });
    expect(sessionBody.accountId).toBeTypeOf('number');
    expect(sessionBody.siteId).toBeTypeOf('number');

    const sites = await db.select().from(schema.sites).all();
    expect(sites).toHaveLength(1);
    expect(sites[0]).toMatchObject({
      platform: 'codex',
      url: 'https://chatgpt.com/backend-api/codex',
      status: 'active',
    });

    const accounts = await db.select().from(schema.accounts).all();
    expect(accounts).toHaveLength(1);
    expect(accounts[0]).toMatchObject({
      siteId: sites[0]?.id,
      username: 'codex-user@example.com',
      accessToken: 'oauth-access-token',
      checkinEnabled: false,
      status: 'active',
    });
    expect(JSON.parse(accounts[0]?.extraConfig || '{}')).toMatchObject({
      credentialMode: 'session',
      oauth: {
        provider: 'codex',
        accountId: 'chatgpt-account-123',
        email: 'codex-user@example.com',
        planType: 'plus',
        refreshToken: 'oauth-refresh-token',
        idToken: jwt,
      },
    });

    const models = await db.select().from(schema.modelAvailability).all();
    const modelNames = models.map((row) => row.modelName);
    expect(modelNames.sort()).toEqual(['gpt-5', 'gpt-5.2-codex', 'gpt-5.4']);
  });

  it('marks oauth session as error and avoids creating a connection when codex model discovery fails', async () => {
    const jwt = buildJwt({
      email: 'codex-fail@example.com',
      'https://api.openai.com/auth': {
        chatgpt_account_id: 'chatgpt-account-fail',
        chatgpt_plan_type: 'team',
      },
    });
    fetchMock
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          access_token: 'oauth-access-token',
          refresh_token: 'oauth-refresh-token',
          id_token: jwt,
          expires_in: 3600,
          token_type: 'Bearer',
        }),
        text: async () => JSON.stringify({ ok: true }),
      })
      .mockResolvedValueOnce({
        ok: false,
        status: 403,
        json: async () => ({ error: 'forbidden' }),
        text: async () => 'forbidden',
      });

    const startResponse = await app.inject({
      method: 'POST',
      url: '/api/oauth/providers/codex/start',
      headers: {
        host: 'metapi.example',
        'x-forwarded-proto': 'https',
      },
    });
    const startBody = startResponse.json() as { state: string };

    const callbackResponse = await app.inject({
      method: 'GET',
      url: `/api/oauth/callback/codex?state=${encodeURIComponent(startBody.state)}&code=oauth-code-456`,
      headers: {
        host: 'metapi.example',
        'x-forwarded-proto': 'https',
      },
    });
    expect(callbackResponse.statusCode).toBe(200);
    expect(callbackResponse.body).toContain('OAuth authorization failed');

    const sessionResponse = await app.inject({
      method: 'GET',
      url: `/api/oauth/sessions/${startBody.state}`,
    });
    expect(sessionResponse.statusCode).toBe(200);
    expect(sessionResponse.json()).toMatchObject({
      provider: 'codex',
      status: 'error',
      error: expect.stringContaining('HTTP 403'),
    });

    const accounts = await db.select().from(schema.accounts).all();
    expect(accounts).toEqual([]);

    const connectionsResponse = await app.inject({
      method: 'GET',
      url: '/api/oauth/connections',
    });
    expect(connectionsResponse.statusCode).toBe(200);
    expect(connectionsResponse.json()).toEqual({ items: [] });
  });

  it('lists oauth connection health metadata and supports deleting the connection', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'ChatGPT Codex OAuth',
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
          modelDiscoveryStatus: 'abnormal',
          lastModelSyncAt: '2026-03-17T08:00:00.000Z',
          lastModelSyncError: 'Codex 模型获取失败（HTTP 403: forbidden）',
        },
      }),
    }).returning().get();

    await db.insert(schema.modelAvailability).values({
      accountId: account.id,
      modelName: 'gpt-5.2-codex',
      available: true,
      checkedAt: '2026-03-17T08:00:00.000Z',
    }).run();

    const route = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-5.2-codex',
      enabled: true,
    }).returning().get();
    await db.insert(schema.routeChannels).values({
      routeId: route.id,
      accountId: account.id,
      tokenId: null,
      priority: 0,
      weight: 10,
      enabled: true,
      manualOverride: false,
    }).run();

    const listResponse = await app.inject({
      method: 'GET',
      url: '/api/oauth/connections',
    });

    expect(listResponse.statusCode).toBe(200);
    expect(listResponse.json()).toEqual({
      items: [
        expect.objectContaining({
          accountId: account.id,
          provider: 'codex',
          email: 'codex-user@example.com',
          status: 'abnormal',
          routeChannelCount: 1,
          lastModelSyncAt: '2026-03-17T08:00:00.000Z',
          lastModelSyncError: 'Codex 模型获取失败（HTTP 403: forbidden）',
        }),
      ],
    });

    const deleteResponse = await app.inject({
      method: 'DELETE',
      url: `/api/oauth/connections/${account.id}`,
    });
    expect(deleteResponse.statusCode).toBe(200);
    expect(deleteResponse.json()).toEqual({ success: true });

    const accounts = await db.select().from(schema.accounts).all();
    expect(accounts).toEqual([]);
  });
});
