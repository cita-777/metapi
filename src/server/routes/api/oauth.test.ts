import Fastify, { type FastifyInstance } from 'fastify';
import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { config } from '../../config.js';

const fetchMock = vi.fn();
const undiciAgentCtorMock = vi.fn();
const undiciProxyAgentCtorMock = vi.fn();

vi.mock('undici', () => ({
  fetch: (...args: unknown[]) => fetchMock(...args),
  Agent: class MockUndiciAgent {
    constructor(...args: unknown[]) {
      undiciAgentCtorMock(...args);
    }
  },
  ProxyAgent: class MockUndiciProxyAgent {
    constructor(...args: unknown[]) {
      undiciProxyAgentCtorMock(...args);
    }
  },
}));

type DbModule = typeof import('../../db/index.js');
type RouteRefreshWorkflowModule = typeof import('../../services/routeRefreshWorkflow.js');

function buildJwt(payload: Record<string, unknown>) {
  const encode = (value: unknown) => Buffer.from(JSON.stringify(value))
    .toString('base64url');
  return `${encode({ alg: 'none', typ: 'JWT' })}.${encode(payload)}.signature`;
}

function buildCodexQuotaProbeResponse(input: {
  status?: number;
  headers?: Record<string, string>;
  text?: string;
}) {
  const status = input.status ?? 200;
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: new Headers(input.headers || {}),
    text: async () => input.text || '',
    body: {
      cancel: async () => undefined,
    },
  };
}

function createDeferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

describe('oauth routes', { timeout: 15_000 }, () => {
  let app: FastifyInstance;
  let db: DbModule['db'];
  let schema: DbModule['schema'];
  let rebuildRoutesOnly: RouteRefreshWorkflowModule['rebuildRoutesOnly'];
  let dataDir = '';

  beforeAll(async () => {
    dataDir = mkdtempSync(join(tmpdir(), 'metapi-oauth-routes-'));
    process.env.DATA_DIR = dataDir;

    await import('../../db/migrate.js');
    const dbModule = await import('../../db/index.js');
    const routesModule = await import('./oauth.js');
    const routeRefreshWorkflow = await import('../../services/routeRefreshWorkflow.js');
    db = dbModule.db;
    schema = dbModule.schema;
    rebuildRoutesOnly = routeRefreshWorkflow.rebuildRoutesOnly;

    app = Fastify();
    await app.register(routesModule.oauthRoutes);
  });

  beforeEach(async () => {
    fetchMock.mockReset();
    undiciAgentCtorMock.mockReset();
    undiciProxyAgentCtorMock.mockReset();
    config.systemProxyUrl = '';
    const { resetRequestRateLimitStore } = await import('../../middleware/requestRateLimit.js');
    const { resetOauthSensitiveRouteLimiterForTests } = await import('./oauth.js');
    resetRequestRateLimitStore();
    resetOauthSensitiveRouteLimiterForTests();
    await db.delete(schema.routeChannels).run();
    await db.delete(schema.tokenRoutes).run();
    await db.delete(schema.tokenModelAvailability).run();
    await db.delete(schema.modelAvailability).run();
    await db.delete(schema.accountTokens).run();
    await db.delete(schema.accounts).run();
    await db.delete(schema.settings).run();
    await db.delete(schema.sites).run();
    const { invalidateSiteProxyCache } = await import('../../services/siteProxy.js');
    invalidateSiteProxyCache();
  });

  afterAll(async () => {
    await app.close();
    delete process.env.DATA_DIR;
  });

  it('lists multi-provider oauth metadata', async () => {
    const response = await app.inject({
      method: 'GET',
      url: '/api/oauth/providers',
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      defaults: {
        systemProxyConfigured: false,
      },
      providers: expect.arrayContaining([
        expect.objectContaining({
          provider: 'codex',
          platform: 'codex',
          enabled: true,
          loginType: 'oauth',
        }),
        expect.objectContaining({
          provider: 'claude',
          platform: 'claude',
          enabled: true,
          loginType: 'oauth',
        }),
        expect.objectContaining({
          provider: 'gemini-cli',
          platform: 'gemini-cli',
          enabled: true,
          loginType: 'oauth',
          requiresProjectId: true,
        }),
        expect.objectContaining({
          provider: 'antigravity',
          platform: 'antigravity',
          enabled: true,
          loginType: 'oauth',
          requiresProjectId: false,
        }),
      ]),
    });
  });

  it('exposes system proxy defaults in oauth provider metadata when configured', async () => {
    config.systemProxyUrl = 'http://127.0.0.1:7890';

    const response = await app.inject({
      method: 'GET',
      url: '/api/oauth/providers',
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      defaults: {
        systemProxyConfigured: true,
      },
    });
  });

  it('reports when runtime system proxy is configured in oauth provider defaults', async () => {
    config.systemProxyUrl = 'http://127.0.0.1:7890';

    const response = await app.inject({
      method: 'GET',
      url: '/api/oauth/providers',
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      defaults: {
        systemProxyConfigured: true,
      },
    });
  });

  it('reports when the runtime system proxy is configured', async () => {
    config.systemProxyUrl = 'http://127.0.0.1:7890';

    const response = await app.inject({
      method: 'GET',
      url: '/api/oauth/providers',
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      defaults: {
        systemProxyConfigured: true,
      },
    });
  });

  it('rejects malformed oauth payloads at the route boundary', async () => {
    const invalidStartResponse = await app.inject({
      method: 'POST',
      url: '/api/oauth/providers/antigravity/start',
      payload: {
        accountId: '1',
      },
    });
    expect(invalidStartResponse.statusCode).toBe(400);
    expect(invalidStartResponse.json()).toMatchObject({
      message: 'Invalid accountId. Expected positive number.',
    });

    const startResponse = await app.inject({
      method: 'POST',
      url: '/api/oauth/providers/antigravity/start',
      headers: {
        host: 'metapi.example',
        'x-forwarded-proto': 'https',
      },
    });
    expect(startResponse.statusCode).toBe(200);
    const state = (startResponse.json() as { state: string }).state;

    const invalidCallbackResponse = await app.inject({
      method: 'POST',
      url: `/api/oauth/sessions/${encodeURIComponent(state)}/manual-callback`,
      payload: {
        callbackUrl: 123,
      },
    });
    expect(invalidCallbackResponse.statusCode).toBe(400);
    expect(invalidCallbackResponse.json()).toMatchObject({
      message: 'Invalid callbackUrl. Expected string.',
    });

    const invalidRebindResponse = await app.inject({
      method: 'POST',
      url: '/api/oauth/connections/1/rebind',
      payload: {
        proxyUrl: 123,
      },
    });
    expect(invalidRebindResponse.statusCode).toBe(400);
    expect(invalidRebindResponse.json()).toMatchObject({
      message: 'Invalid proxyUrl. Expected string or null.',
    });

    const invalidUseSystemProxyResponse = await app.inject({
      method: 'POST',
      url: '/api/oauth/providers/antigravity/start',
      payload: {
        useSystemProxy: 'yes',
      },
    });
    expect(invalidUseSystemProxyResponse.statusCode).toBe(400);
    expect(invalidUseSystemProxyResponse.json()).toMatchObject({
      message: 'Invalid useSystemProxy. Expected boolean.',
    });

    const invalidProxyPatchResponse = await app.inject({
      method: 'PATCH',
      url: '/api/oauth/connections/1/proxy',
      payload: {
        useSystemProxy: 'yes',
      },
    });
    expect(invalidProxyPatchResponse.statusCode).toBe(400);
    expect(invalidProxyPatchResponse.json()).toMatchObject({
      message: 'Invalid useSystemProxy. Expected boolean.',
    });
  });

  it('starts an antigravity oauth session and returns provider metadata', async () => {
    const startResponse = await app.inject({
      method: 'POST',
      url: '/api/oauth/providers/antigravity/start',
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
      instructions?: {
        redirectUri: string;
        callbackPort: number;
        callbackPath: string;
        manualCallbackDelayMs: number;
      };
    };
    expect(startBody.provider).toBe('antigravity');
    expect(startBody.state).toMatch(/^[a-zA-Z0-9_-]{20,}$/);
    expect(startBody.authorizationUrl).toContain('https://accounts.google.com/o/oauth2/v2/auth?');
    expect(startBody.authorizationUrl).toContain(encodeURIComponent('http://localhost:51121/oauth-callback'));
    expect(startBody.authorizationUrl).toContain(`state=${encodeURIComponent(startBody.state)}`);
    expect(startBody.instructions).toMatchObject({
      redirectUri: 'http://localhost:51121/oauth-callback',
      callbackPort: 51121,
      callbackPath: '/oauth-callback',
      manualCallbackDelayMs: 15000,
    });
  });

  it('discovers the Antigravity project via onboardUser polling when loadCodeAssist does not return one', async () => {
    fetchMock
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          access_token: 'antigravity-access-token',
          refresh_token: 'antigravity-refresh-token',
          expires_in: 3600,
          token_type: 'Bearer',
          scope: 'cloud-platform',
        }),
        text: async () => JSON.stringify({ ok: true }),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ email: 'antigravity-user@example.com' }),
        text: async () => JSON.stringify({ email: 'antigravity-user@example.com' }),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          allowedTiers: [
            { id: 'legacy-tier', isDefault: true },
          ],
        }),
        text: async () => JSON.stringify({ ok: true }),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          done: false,
        }),
        text: async () => JSON.stringify({ done: false }),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          done: true,
          response: {
            cloudaicompanionProject: {
              id: 'antigravity-auto-project',
            },
          },
        }),
        text: async () => JSON.stringify({ done: true }),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          models: {
            'gemini-3-pro-preview': { displayName: 'Gemini 3 Pro Preview' },
          },
        }),
        text: async () => JSON.stringify({ ok: true }),
      });

    const startResponse = await app.inject({
      method: 'POST',
      url: '/api/oauth/providers/antigravity/start',
      headers: {
        host: 'metapi.example',
        'x-forwarded-proto': 'https',
      },
    });
    expect(startResponse.statusCode).toBe(200);
    const startBody = startResponse.json() as { state: string };

    const callbackResponse = await app.inject({
      method: 'POST',
      url: `/api/oauth/sessions/${encodeURIComponent(startBody.state)}/manual-callback`,
      payload: {
        callbackUrl: `http://localhost:51121/oauth-callback?state=${encodeURIComponent(startBody.state)}&code=antigravity-oauth-code-123`,
      },
    });
    expect(callbackResponse.statusCode).toBe(200);
    expect(callbackResponse.json()).toEqual({ success: true });

    const sessionResponse = await app.inject({
      method: 'GET',
      url: `/api/oauth/sessions/${startBody.state}`,
    });
    expect(sessionResponse.statusCode).toBe(200);
    expect(sessionResponse.json()).toMatchObject({
      provider: 'antigravity',
      status: 'success',
    });

    const accounts = await db.select().from(schema.accounts).all();
    expect(accounts).toHaveLength(1);
    expect(accounts[0]).toMatchObject({
      oauthProvider: 'antigravity',
      oauthProjectId: 'antigravity-auto-project',
      username: 'antigravity-user@example.com',
      accessToken: 'antigravity-access-token',
    });

    const parsed = JSON.parse(accounts[0]?.extraConfig || '{}');
    expect(parsed.oauth).toMatchObject({
      email: 'antigravity-user@example.com',
      refreshToken: 'antigravity-refresh-token',
    });
    expect(parsed.oauth).not.toHaveProperty('provider');
    expect(parsed.oauth).not.toHaveProperty('projectId');

    expect(String(fetchMock.mock.calls[2]?.[0] || '')).toContain('/v1internal:loadCodeAssist');
    expect(String(fetchMock.mock.calls[3]?.[0] || '')).toContain('/v1internal:onboardUser');
    expect(String(fetchMock.mock.calls[4]?.[0] || '')).toContain('/v1internal:onboardUser');
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
      instructions?: {
        redirectUri: string;
        callbackPort: number;
        callbackPath: string;
        manualCallbackDelayMs: number;
        sshTunnelCommand?: string;
      };
    };
    expect(startBody.provider).toBe('codex');
    expect(startBody.state).toMatch(/^[a-zA-Z0-9_-]{20,}$/);
    expect(startBody.authorizationUrl).toContain('https://auth.openai.com/oauth/authorize?');
    expect(startBody.authorizationUrl).toContain('client_id=');
    expect(startBody.authorizationUrl).toContain(encodeURIComponent('http://localhost:1455/auth/callback'));
    expect(startBody.authorizationUrl).toContain(`state=${encodeURIComponent(startBody.state)}`);
    expect(startBody.authorizationUrl).toContain('code_challenge=');
    expect(startBody.instructions).toMatchObject({
      redirectUri: 'http://localhost:1455/auth/callback',
      callbackPort: 1455,
      callbackPath: '/auth/callback',
      manualCallbackDelayMs: 15000,
      sshTunnelCommand: 'ssh -L 1455:127.0.0.1:1455 root@metapi.example -p 22',
    });

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

  it('keeps the codex loopback callback for local origins', async () => {
    const startResponse = await app.inject({
      method: 'POST',
      url: '/api/oauth/providers/codex/start',
      headers: {
        host: 'localhost:4000',
      },
    });

    expect(startResponse.statusCode).toBe(200);
    const startBody = startResponse.json() as {
      provider: string;
      state: string;
      authorizationUrl: string;
    };
    expect(startBody.provider).toBe('codex');
    expect(startBody.authorizationUrl).toContain(encodeURIComponent('http://localhost:1455/auth/callback'));
    expect(startBody.authorizationUrl).not.toContain(encodeURIComponent('http://localhost:4000/api/oauth/callback/codex'));
  });

  it('handles manual codex callback submission, creates oauth-backed account, and discovers plan models', async () => {
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
      payload: {
        proxyUrl: 'http://127.0.0.1:7890',
      },
    });
    const startBody = startResponse.json() as { state: string };

    const callbackResponse = await app.inject({
      method: 'POST',
      url: `/api/oauth/sessions/${encodeURIComponent(startBody.state)}/manual-callback`,
      payload: {
        callbackUrl: `http://localhost:1455/auth/callback?state=${encodeURIComponent(startBody.state)}&code=oauth-code-123`,
      },
    });
    expect(callbackResponse.statusCode).toBe(200);
    expect(callbackResponse.json()).toEqual({ success: true });
    expect(String(fetchMock.mock.calls[0]?.[1]?.body || '')).toContain(
      'redirect_uri=http%3A%2F%2Flocalhost%3A1455%2Fauth%2Fcallback',
    );
    expect(fetchMock.mock.calls[0]?.[1]?.dispatcher).toBeDefined();

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
      proxyUrl: 'http://127.0.0.1:7890',
      oauth: {
        email: 'codex-user@example.com',
        planType: 'plus',
        refreshToken: 'oauth-refresh-token',
        idToken: jwt,
      },
    });
    const codexStoredOauth = JSON.parse(accounts[0]?.extraConfig || '{}').oauth;
    expect(codexStoredOauth).not.toHaveProperty('provider');
    expect(codexStoredOauth).not.toHaveProperty('accountId');

    const models = await db.select().from(schema.modelAvailability).all();
    const modelNames = models.map((row) => row.modelName);
    expect(modelNames.sort()).toEqual(['gpt-5', 'gpt-5.2-codex', 'gpt-5.4']);
  });

  it('uses the stored account proxy when refreshing a codex oauth access token', async () => {
    const oauthService = await import('../../services/oauth/service.js');
    const refreshJwt = buildJwt({
      email: 'codex-refreshed@example.com',
      'https://api.openai.com/auth': {
        chatgpt_account_id: 'chatgpt-account-refresh',
        chatgpt_plan_type: 'team',
      },
    });
    const site = await db.insert(schema.sites).values({
      name: 'ChatGPT Codex OAuth',
      url: 'https://chatgpt.com/backend-api/codex',
      platform: 'codex',
      status: 'active',
    }).returning().get();
    const existing = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'codex-existing@example.com',
      accessToken: 'oauth-access-token-old',
      apiToken: null,
      checkinEnabled: false,
      status: 'active',
      oauthProvider: 'codex',
      oauthAccountKey: 'chatgpt-account-refresh',
      extraConfig: JSON.stringify({
        credentialMode: 'session',
        proxyUrl: 'http://127.0.0.1:7890',
        oauth: {
          email: 'codex-existing@example.com',
          refreshToken: 'oauth-refresh-token-old',
          idToken: refreshJwt,
        },
      }),
    }).returning().get();
    fetchMock.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({
        access_token: 'oauth-access-token-new',
        refresh_token: 'oauth-refresh-token-new',
        id_token: refreshJwt,
        expires_in: 3600,
        token_type: 'Bearer',
      }),
      text: async () => JSON.stringify({ ok: true }),
    });

    const refreshed = await oauthService.refreshOauthAccessToken(existing.id);

    expect(refreshed.accessToken).toBe('oauth-access-token-new');
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0]?.[1]?.dispatcher).toBeDefined();

    const updated = await db.select().from(schema.accounts).where(eq(schema.accounts.id, existing.id)).get();
    expect(updated?.accessToken).toBe('oauth-access-token-new');
    expect(JSON.parse(updated?.extraConfig || '{}')).toMatchObject({
      proxyUrl: 'http://127.0.0.1:7890',
      oauth: {
        refreshToken: 'oauth-refresh-token-new',
      },
    });
  });

  it('includes dispatcher for codex token exchange when oauth site enables the system proxy', async () => {
    const jwt = buildJwt({
      email: 'codex-proxy@example.com',
      'https://api.openai.com/auth': {
        chatgpt_account_id: 'chatgpt-account-proxy',
        chatgpt_plan_type: 'plus',
      },
    });
    await db.insert(schema.settings).values({
      key: 'system_proxy_url',
      value: JSON.stringify('http://127.0.0.1:7890'),
    }).run();
    await db.insert(schema.sites).values({
      name: 'ChatGPT Codex OAuth',
      url: 'https://chatgpt.com/backend-api/codex',
      platform: 'codex',
      status: 'active',
      useSystemProxy: true,
    }).run();

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
          models: [{ id: 'gpt-5.4' }],
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
    expect(startResponse.statusCode).toBe(200);
    const startBody = startResponse.json() as { state: string };

    const callbackResponse = await app.inject({
      method: 'POST',
      url: `/api/oauth/sessions/${encodeURIComponent(startBody.state)}/manual-callback`,
      payload: {
        callbackUrl: `http://localhost:1455/auth/callback?state=${encodeURIComponent(startBody.state)}&code=oauth-code-proxy`,
      },
    });
    expect(callbackResponse.statusCode).toBe(200);
    const codexTokenCall = fetchMock.mock.calls.find((call) => String(call[0] || '') === 'https://auth.openai.com/oauth/token');
    const codexTokenFetchInit = codexTokenCall?.[1] as Record<string, unknown> | undefined;
    expect(codexTokenFetchInit).toEqual(expect.objectContaining({
      dispatcher: expect.anything(),
    }));
  });

  it('includes dispatcher for codex token exchange when oauth start explicitly requests the system proxy', async () => {
    const jwt = buildJwt({
      email: 'codex-system-proxy@example.com',
      'https://api.openai.com/auth': {
        chatgpt_account_id: 'chatgpt-account-system-proxy',
        chatgpt_plan_type: 'plus',
      },
    });
    config.systemProxyUrl = 'http://127.0.0.1:7890';

    fetchMock
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          access_token: 'oauth-access-token-system',
          refresh_token: 'oauth-refresh-token-system',
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
          models: [{ id: 'gpt-5.4' }],
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
      payload: {
        useSystemProxy: true,
      },
    });
    expect(startResponse.statusCode).toBe(200);
    const startBody = startResponse.json() as { state: string };

    const callbackResponse = await app.inject({
      method: 'POST',
      url: `/api/oauth/sessions/${encodeURIComponent(startBody.state)}/manual-callback`,
      payload: {
        callbackUrl: `http://localhost:1455/auth/callback?state=${encodeURIComponent(startBody.state)}&code=oauth-code-system-proxy`,
      },
    });
    expect(callbackResponse.statusCode).toBe(200);

    const codexTokenCall = fetchMock.mock.calls.find((call) => String(call[0] || '') === 'https://auth.openai.com/oauth/token');
    const codexTokenFetchInit = codexTokenCall?.[1] as Record<string, unknown> | undefined;
    expect(codexTokenFetchInit).toEqual(expect.objectContaining({
      dispatcher: expect.anything(),
    }));

    const accounts = await db.select().from(schema.accounts).all();
    expect(accounts).toHaveLength(1);
    expect(JSON.parse(accounts[0]?.extraConfig || '{}')).toMatchObject({
      useSystemProxy: true,
      oauth: {
        email: 'codex-system-proxy@example.com',
      },
    });
  });

  it('falls back to the site proxy during rebind exchange when clearing an account proxy override', async () => {
    const originalJwt = buildJwt({
      email: 'codex-clear@example.com',
      'https://api.openai.com/auth': {
        chatgpt_account_id: 'chatgpt-account-clear-existing',
        chatgpt_plan_type: 'plus',
      },
    });
    const reboundJwt = buildJwt({
      email: 'codex-clear@example.com',
      'https://api.openai.com/auth': {
        chatgpt_account_id: 'chatgpt-account-clear-rebound',
        chatgpt_plan_type: 'team',
      },
    });
    await db.insert(schema.settings).values({
      key: 'system_proxy_url',
      value: JSON.stringify('http://127.0.0.1:7890'),
    }).run();
    const site = await db.insert(schema.sites).values({
      name: 'ChatGPT Codex OAuth',
      url: 'https://chatgpt.com/backend-api/codex',
      platform: 'codex',
      status: 'active',
      useSystemProxy: true,
    }).returning().get();
    const existing = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'codex-clear@example.com',
      accessToken: 'stable-access-token',
      apiToken: null,
      checkinEnabled: false,
      status: 'active',
      oauthProvider: 'codex',
      oauthAccountKey: 'chatgpt-account-clear-existing',
      extraConfig: JSON.stringify({
        credentialMode: 'session',
        proxyUrl: 'http://127.0.0.1:9999',
        oauth: {
          provider: 'codex',
          accountId: 'chatgpt-account-clear-existing',
          accountKey: 'chatgpt-account-clear-existing',
          email: 'codex-clear@example.com',
          planType: 'plus',
          refreshToken: 'stable-refresh-token',
          idToken: originalJwt,
        },
      }),
    }).returning().get();

    fetchMock
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          access_token: 'rebound-access-token',
          refresh_token: 'rebound-refresh-token',
          id_token: reboundJwt,
          expires_in: 3600,
          token_type: 'Bearer',
        }),
        text: async () => JSON.stringify({ ok: true }),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          models: [{ id: 'gpt-5.4' }],
        }),
        text: async () => JSON.stringify({ ok: true }),
      });

    const startResponse = await app.inject({
      method: 'POST',
      url: `/api/oauth/connections/${existing.id}/rebind`,
      headers: {
        host: 'metapi.example',
        'x-forwarded-proto': 'https',
      },
      payload: {
        proxyUrl: null,
      },
    });
    expect(startResponse.statusCode).toBe(200);
    const startBody = startResponse.json() as { state: string };

    const callbackResponse = await app.inject({
      method: 'POST',
      url: `/api/oauth/sessions/${encodeURIComponent(startBody.state)}/manual-callback`,
      payload: {
        callbackUrl: `http://localhost:1455/auth/callback?state=${encodeURIComponent(startBody.state)}&code=oauth-code-clear-proxy`,
      },
    });
    expect(callbackResponse.statusCode).toBe(200);

    const codexTokenCall = fetchMock.mock.calls.find((call) => String(call[0] || '') === 'https://auth.openai.com/oauth/token');
    const codexTokenFetchInit = codexTokenCall?.[1] as Record<string, unknown> | undefined;
    expect(codexTokenFetchInit).toEqual(expect.objectContaining({
      dispatcher: expect.anything(),
    }));

    const stored = await db.select().from(schema.accounts).where(eq(schema.accounts.id, existing.id)).get();
    expect(stored?.accessToken).toBe('rebound-access-token');
    expect(stored?.oauthAccountKey).toBe('chatgpt-account-clear-rebound');
    expect(JSON.parse(stored?.extraConfig || '{}')).toMatchObject({
      proxyUrl: null,
      oauth: {
        refreshToken: 'rebound-refresh-token',
        idToken: reboundJwt,
      },
    });
  });

  it('updates oauth account proxy settings without starting reauthorization and refreshes route coverage', async () => {
    config.systemProxyUrl = 'http://127.0.0.1:7890';
    fetchMock.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({
        models: [{ id: 'gpt-5.4' }],
      }),
      text: async () => JSON.stringify({ ok: true }),
    });

    const site = await db.insert(schema.sites).values({
      name: 'ChatGPT Codex OAuth',
      url: 'https://chatgpt.com/backend-api/codex',
      platform: 'codex',
      status: 'active',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'proxy-save@example.com',
      accessToken: 'oauth-access-token',
      apiToken: null,
      status: 'active',
      oauthProvider: 'codex',
      oauthAccountKey: 'proxy-save-account',
      extraConfig: JSON.stringify({
        credentialMode: 'session',
        oauth: {
          provider: 'codex',
          accountId: 'proxy-save-account',
          accountKey: 'proxy-save-account',
          email: 'proxy-save@example.com',
          planType: 'plus',
          refreshToken: 'oauth-refresh-token',
        },
      }),
    }).returning().get();

    const response = await app.inject({
      method: 'PATCH',
      url: `/api/oauth/connections/${account.id}/proxy`,
      payload: {
        proxyUrl: null,
        useSystemProxy: true,
      },
    });

    expect(response.statusCode).toBe(200);
    const body = response.json() as Record<string, unknown>;
    expect(body).toMatchObject({
      success: true,
    });
    expect(body).not.toHaveProperty('state');
    expect(body).not.toHaveProperty('authorizationUrl');

    const stored = await db.select().from(schema.accounts).where(eq(schema.accounts.id, account.id)).get();
    expect(JSON.parse(stored?.extraConfig || '{}')).toMatchObject({
      useSystemProxy: true,
      proxyUrl: null,
    });

    const modelRows = await db.select().from(schema.modelAvailability).all();
    expect(modelRows).toEqual(expect.arrayContaining([
      expect.objectContaining({
        accountId: account.id,
        modelName: 'gpt-5.4',
        available: true,
      }),
    ]));

    const routeRows = await db.select().from(schema.routeChannels).all();
    expect(routeRows).toHaveLength(1);

    const connectionsResponse = await app.inject({
      method: 'GET',
      url: '/api/oauth/connections',
    });
    expect(connectionsResponse.statusCode).toBe(200);
    expect(connectionsResponse.json()).toMatchObject({
      items: [
        expect.objectContaining({
          accountId: account.id,
          useSystemProxy: true,
          routeChannelCount: 1,
        }),
      ],
    });
  });

  it('updates oauth account proxy settings without creating a new oauth session and rebuilds routes', async () => {
    config.systemProxyUrl = 'http://127.0.0.1:7890';
    fetchMock.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({
        models: [{ id: 'gpt-5.4' }],
      }),
      text: async () => JSON.stringify({ ok: true }),
    });

    const site = await db.insert(schema.sites).values({
      name: 'ChatGPT Codex OAuth',
      url: 'https://chatgpt.com/backend-api/codex',
      platform: 'codex',
      status: 'active',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'proxy-update@example.com',
      accessToken: 'oauth-access-token',
      apiToken: null,
      status: 'active',
      oauthProvider: 'codex',
      oauthAccountKey: 'chatgpt-proxy-update',
      extraConfig: JSON.stringify({
        credentialMode: 'session',
        oauth: {
          provider: 'codex',
          accountId: 'chatgpt-proxy-update',
          accountKey: 'chatgpt-proxy-update',
          email: 'proxy-update@example.com',
          refreshToken: 'oauth-refresh-token',
        },
      }),
    }).returning().get();

    const response = await app.inject({
      method: 'PATCH',
      url: `/api/oauth/connections/${account.id}/proxy`,
      payload: {
        proxyUrl: null,
        useSystemProxy: true,
      },
    });

    expect(response.statusCode).toBe(200);
    const body = response.json() as Record<string, unknown>;
    expect(body).toMatchObject({
      success: true,
      accountId: account.id,
      useSystemProxy: true,
      proxyUrl: null,
    });
    expect(body).not.toHaveProperty('state');
    expect(body).not.toHaveProperty('authorizationUrl');

    const updated = await db.select().from(schema.accounts).where(eq(schema.accounts.id, account.id)).get();
    expect(JSON.parse(updated?.extraConfig || '{}')).toMatchObject({
      useSystemProxy: true,
      proxyUrl: null,
      oauth: {
        email: 'proxy-update@example.com',
      },
    });

    const routes = await db.select().from(schema.tokenRoutes).all();
    const channels = await db.select().from(schema.routeChannels).all();
    expect(routes).toHaveLength(1);
    expect(channels).toHaveLength(1);
    expect(channels[0]).toMatchObject({
      accountId: account.id,
    });
  });

  it('marks oauth session as error and avoids creating a connection when manual codex callback model discovery fails', async () => {
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
      method: 'POST',
      url: `/api/oauth/sessions/${encodeURIComponent(startBody.state)}/manual-callback`,
      payload: {
        callbackUrl: `http://localhost:1455/auth/callback?state=${encodeURIComponent(startBody.state)}&code=oauth-code-456`,
      },
    });
    expect(callbackResponse.statusCode).toBe(500);
    expect(callbackResponse.json()).toMatchObject({
      message: expect.stringContaining('HTTP 403'),
    });

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
    expect(connectionsResponse.json()).toMatchObject({
      items: [],
      total: 0,
      limit: 50,
      offset: 0,
    });
  });

  it('keeps the existing codex connection intact when a rebind callback fails model discovery', async () => {
    const originalJwt = buildJwt({
      email: 'codex-existing@example.com',
      'https://api.openai.com/auth': {
        chatgpt_account_id: 'chatgpt-account-existing',
        chatgpt_plan_type: 'team',
      },
    });
    const site = await db.insert(schema.sites).values({
      name: 'ChatGPT Codex OAuth',
      url: 'https://chatgpt.com/backend-api/codex',
      platform: 'codex',
      status: 'active',
    }).returning().get();
    const existing = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'codex-existing@example.com',
      accessToken: 'stable-access-token',
      apiToken: null,
      status: 'active',
      oauthProvider: 'codex',
      oauthAccountKey: 'chatgpt-account-existing',
      extraConfig: JSON.stringify({
        credentialMode: 'session',
        oauth: {
          provider: 'codex',
          accountId: 'chatgpt-account-existing',
          accountKey: 'chatgpt-account-existing',
          email: 'codex-existing@example.com',
          planType: 'team',
          refreshToken: 'stable-refresh-token',
          idToken: originalJwt,
        },
      }),
    }).returning().get();
    const reboundJwt = buildJwt({
      email: 'codex-existing@example.com',
      'https://api.openai.com/auth': {
        chatgpt_account_id: 'chatgpt-account-rebound',
        chatgpt_plan_type: 'plus',
      },
    });
    fetchMock
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          access_token: 'rebound-access-token',
          refresh_token: 'rebound-refresh-token',
          id_token: reboundJwt,
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
      payload: {
        accountId: existing.id,
      },
    });
    const startBody = startResponse.json() as { state: string };

    const callbackResponse = await app.inject({
      method: 'POST',
      url: `/api/oauth/sessions/${encodeURIComponent(startBody.state)}/manual-callback`,
      payload: {
        callbackUrl: `http://localhost:1455/auth/callback?state=${encodeURIComponent(startBody.state)}&code=oauth-code-rebind-fail`,
      },
    });
    expect(callbackResponse.statusCode).toBe(500);

    const stored = await db.select().from(schema.accounts).where(eq(schema.accounts.id, existing.id)).get();
    expect(stored).toMatchObject({
      id: existing.id,
      username: 'codex-existing@example.com',
      accessToken: 'stable-access-token',
      oauthAccountKey: 'chatgpt-account-existing',
    });
    expect(JSON.parse(stored?.extraConfig || '{}')).toMatchObject({
      oauth: {
        accountId: 'chatgpt-account-existing',
        refreshToken: 'stable-refresh-token',
        idToken: originalJwt,
      },
    });

    const accounts = await db.select().from(schema.accounts).all();
    expect(accounts).toHaveLength(1);
    expect(accounts[0]?.oauthAccountKey).toBe('chatgpt-account-existing');
  });

  it('keeps the existing codex account non-active while rebind model discovery is still pending', async () => {
    const originalJwt = buildJwt({
      email: 'codex-existing@example.com',
      'https://api.openai.com/auth': {
        chatgpt_account_id: 'chatgpt-account-existing',
        chatgpt_plan_type: 'team',
      },
    });
    const site = await db.insert(schema.sites).values({
      name: 'ChatGPT Codex OAuth',
      url: 'https://chatgpt.com/backend-api/codex',
      platform: 'codex',
      status: 'active',
    }).returning().get();
    const existing = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'codex-existing@example.com',
      accessToken: 'stable-access-token',
      apiToken: null,
      status: 'active',
      oauthProvider: 'codex',
      oauthAccountKey: 'chatgpt-account-existing',
      extraConfig: JSON.stringify({
        credentialMode: 'session',
        oauth: {
          provider: 'codex',
          accountId: 'chatgpt-account-existing',
          accountKey: 'chatgpt-account-existing',
          email: 'codex-existing@example.com',
          planType: 'team',
          refreshToken: 'stable-refresh-token',
          idToken: originalJwt,
        },
      }),
    }).returning().get();
    const reboundJwt = buildJwt({
      email: 'codex-existing@example.com',
      'https://api.openai.com/auth': {
        chatgpt_account_id: 'chatgpt-account-rebound',
        chatgpt_plan_type: 'plus',
      },
    });
    const discoveryGate = createDeferred<ResponseLike>();
    fetchMock
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          access_token: 'rebound-access-token',
          refresh_token: 'rebound-refresh-token',
          id_token: reboundJwt,
          expires_in: 3600,
          token_type: 'Bearer',
        }),
        text: async () => JSON.stringify({ ok: true }),
      })
      .mockImplementationOnce(() => discoveryGate.promise);

    const startResponse = await app.inject({
      method: 'POST',
      url: '/api/oauth/providers/codex/start',
      headers: {
        host: 'metapi.example',
        'x-forwarded-proto': 'https',
      },
      payload: {
        accountId: existing.id,
      },
    });
    const startBody = startResponse.json() as { state: string };

    const callbackPromise = app.inject({
      method: 'POST',
      url: `/api/oauth/sessions/${encodeURIComponent(startBody.state)}/manual-callback`,
      payload: {
        callbackUrl: `http://localhost:1455/auth/callback?state=${encodeURIComponent(startBody.state)}&code=oauth-code-rebind-pending`,
      },
    });

    while (fetchMock.mock.calls.length < 2) {
      await new Promise((resolve) => setTimeout(resolve, 0));
    }

    const pendingRow = await db.select().from(schema.accounts).where(eq(schema.accounts.id, existing.id)).get();
    expect(pendingRow?.status).toBe('disabled');

    discoveryGate.resolve({
      ok: true,
      status: 200,
      json: async () => ({
        models: [{ id: 'gpt-5.4' }],
      }),
      text: async () => JSON.stringify({ ok: true }),
    } as ResponseLike);

    const callbackResponse = await callbackPromise;
    expect(callbackResponse.statusCode).toBe(200);

    const stored = await db.select().from(schema.accounts).where(eq(schema.accounts.id, existing.id)).get();
    expect(stored).toMatchObject({
      id: existing.id,
      status: 'active',
      accessToken: 'rebound-access-token',
      oauthAccountKey: 'chatgpt-account-rebound',
    });
  });

  it('rolls back a codex rebind when route rebuild fails after model discovery succeeds', async () => {
    const originalJwt = buildJwt({
      email: 'codex-existing@example.com',
      'https://api.openai.com/auth': {
        chatgpt_account_id: 'chatgpt-account-existing',
        chatgpt_plan_type: 'team',
      },
    });
    const site = await db.insert(schema.sites).values({
      name: 'ChatGPT Codex OAuth',
      url: 'https://chatgpt.com/backend-api/codex',
      platform: 'codex',
      status: 'active',
    }).returning().get();
    const existing = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'codex-existing@example.com',
      accessToken: 'stable-access-token',
      apiToken: null,
      status: 'active',
      oauthProvider: 'codex',
      oauthAccountKey: 'chatgpt-account-existing',
      extraConfig: JSON.stringify({
        credentialMode: 'session',
        oauth: {
          provider: 'codex',
          accountId: 'chatgpt-account-existing',
          accountKey: 'chatgpt-account-existing',
          email: 'codex-existing@example.com',
          planType: 'team',
          refreshToken: 'stable-refresh-token',
          idToken: originalJwt,
        },
      }),
    }).returning().get();
    await db.insert(schema.modelAvailability).values([
      {
        accountId: existing.id,
        modelName: 'gpt-4.1',
        available: true,
        isManual: false,
      },
      {
        accountId: existing.id,
        modelName: 'manual-kept',
        available: true,
        isManual: true,
      },
    ]).run();

    const reboundJwt = buildJwt({
      email: 'codex-existing@example.com',
      'https://api.openai.com/auth': {
        chatgpt_account_id: 'chatgpt-account-rebound',
        chatgpt_plan_type: 'plus',
      },
    });
    fetchMock
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          access_token: 'rebound-access-token',
          refresh_token: 'rebound-refresh-token',
          id_token: reboundJwt,
          expires_in: 3600,
          token_type: 'Bearer',
        }),
        text: async () => JSON.stringify({ ok: true }),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          models: [{ id: 'gpt-5.4' }],
        }),
        text: async () => JSON.stringify({ ok: true }),
      });

    const routeRefreshWorkflow = await import('../../services/routeRefreshWorkflow.js');
    const rebuildSpy = vi.spyOn(routeRefreshWorkflow, 'rebuildRoutesOnly');
    rebuildSpy.mockImplementationOnce(async () => {
      throw new Error('route rebuild failed');
    });

    try {
      const startResponse = await app.inject({
        method: 'POST',
        url: '/api/oauth/providers/codex/start',
        headers: {
          host: 'metapi.example',
          'x-forwarded-proto': 'https',
        },
        payload: {
          accountId: existing.id,
        },
      });
      const startBody = startResponse.json() as { state: string };

      const callbackResponse = await app.inject({
        method: 'POST',
        url: `/api/oauth/sessions/${encodeURIComponent(startBody.state)}/manual-callback`,
        payload: {
          callbackUrl: `http://localhost:1455/auth/callback?state=${encodeURIComponent(startBody.state)}&code=oauth-code-rebind-route-rebuild-fail`,
        },
      });

      expect(callbackResponse.statusCode).toBe(500);

      const stored = await db.select().from(schema.accounts).where(eq(schema.accounts.id, existing.id)).get();
      expect(stored).toMatchObject({
        id: existing.id,
        status: 'active',
        accessToken: 'stable-access-token',
        oauthAccountKey: 'chatgpt-account-existing',
      });
      expect(JSON.parse(stored?.extraConfig || '{}')).toMatchObject({
        oauth: {
          refreshToken: 'stable-refresh-token',
          idToken: originalJwt,
        },
      });
      const restoredModels = await db.select({
        modelName: schema.modelAvailability.modelName,
        isManual: schema.modelAvailability.isManual,
      }).from(schema.modelAvailability)
        .where(eq(schema.modelAvailability.accountId, existing.id))
        .all();
      expect(restoredModels).toEqual(expect.arrayContaining([
        expect.objectContaining({ modelName: 'gpt-4.1', isManual: false }),
        expect.objectContaining({ modelName: 'manual-kept', isManual: true }),
      ]));
    } finally {
      rebuildSpy.mockRestore();
    }
  });

  it('fails codex oauth onboarding when token exchange does not expose chatgpt_account_id', async () => {
    const jwt = buildJwt({
      email: 'codex-no-account@example.com',
      'https://api.openai.com/auth': {
        chatgpt_plan_type: 'plus',
      },
    });
    fetchMock.mockResolvedValueOnce({
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
      method: 'POST',
      url: `/api/oauth/sessions/${encodeURIComponent(startBody.state)}/manual-callback`,
      payload: {
        callbackUrl: `http://localhost:1455/auth/callback?state=${encodeURIComponent(startBody.state)}&code=oauth-code-no-account-id`,
      },
    });
    expect(callbackResponse.statusCode).toBe(500);
    expect(callbackResponse.json()).toMatchObject({
      message: expect.stringContaining('chatgpt_account_id'),
    });

    const accounts = await db.select().from(schema.accounts).all();
    expect(accounts).toEqual([]);
  });

  it('marks gemini oauth session as error when token exchange fails before account persistence', async () => {
    fetchMock.mockResolvedValueOnce({
      ok: false,
      status: 400,
      json: async () => ({
        error: 'invalid_grant',
        error_description: 'Bad Request',
      }),
      text: async () => '{"error":"invalid_grant","error_description":"Bad Request"}',
    });

    const startResponse = await app.inject({
      method: 'POST',
      url: '/api/oauth/providers/gemini-cli/start',
      payload: {
        projectId: 'demo-project',
      },
      headers: {
        host: 'metapi.example',
        'x-forwarded-proto': 'https',
      },
    });
    const startBody = startResponse.json() as { state: string };

    const callbackResponse = await app.inject({
      method: 'POST',
      url: `/api/oauth/sessions/${encodeURIComponent(startBody.state)}/manual-callback`,
      payload: {
        callbackUrl: `http://localhost:8085/oauth2callback?state=${encodeURIComponent(startBody.state)}&code=oauth-code-gemini-123`,
      },
    });
    expect(callbackResponse.statusCode).toBe(500);
    expect(callbackResponse.json()).toMatchObject({
      message: expect.stringContaining('invalid_grant'),
    });

    const sessionResponse = await app.inject({
      method: 'GET',
      url: `/api/oauth/sessions/${startBody.state}`,
    });
    expect(sessionResponse.statusCode).toBe(200);
    expect(sessionResponse.json()).toMatchObject({
      provider: 'gemini-cli',
      status: 'error',
      error: expect.stringContaining('invalid_grant'),
    });

    const accounts = await db.select().from(schema.accounts).all();
    expect(accounts).toEqual([]);
  });

  it('defaults Gemini CLI oauth to the first available Google Cloud project when projectId is omitted', async () => {
    fetchMock
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          access_token: 'gemini-access-token',
          refresh_token: 'gemini-refresh-token',
          expires_in: 3600,
          token_type: 'Bearer',
          scope: 'cloud-platform',
        }),
        text: async () => JSON.stringify({ ok: true }),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          projects: [
            { projectId: 'first-project-id' },
            { projectId: 'second-project-id' },
          ],
        }),
        text: async () => JSON.stringify({ ok: true }),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          cloudaicompanionProject: {
            id: 'first-project-id',
          },
          allowedTiers: [
            { id: 'legacy-tier', isDefault: true },
          ],
        }),
        text: async () => JSON.stringify({ ok: true }),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          done: true,
          response: {
            cloudaicompanionProject: {
              id: 'first-project-id',
            },
          },
        }),
        text: async () => JSON.stringify({ done: true }),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ state: 'ENABLED' }),
        text: async () => JSON.stringify({ state: 'ENABLED' }),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ email: 'gemini-user@example.com' }),
        text: async () => JSON.stringify({ email: 'gemini-user@example.com' }),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ state: 'ENABLED' }),
        text: async () => JSON.stringify({ state: 'ENABLED' }),
      });

    const startResponse = await app.inject({
      method: 'POST',
      url: '/api/oauth/providers/gemini-cli/start',
      headers: {
        host: 'metapi.example',
        'x-forwarded-proto': 'https',
      },
    });
    expect(startResponse.statusCode).toBe(200);
    const startBody = startResponse.json() as { state: string };

    const callbackResponse = await app.inject({
      method: 'POST',
      url: `/api/oauth/sessions/${encodeURIComponent(startBody.state)}/manual-callback`,
      payload: {
        callbackUrl: `http://localhost:8085/oauth2callback?state=${encodeURIComponent(startBody.state)}&code=gemini-oauth-code-123`,
      },
    });
    expect(callbackResponse.statusCode).toBe(200);
    expect(callbackResponse.json()).toEqual({ success: true });

    const sessionResponse = await app.inject({
      method: 'GET',
      url: `/api/oauth/sessions/${startBody.state}`,
    });
    expect(sessionResponse.statusCode).toBe(200);
    expect(sessionResponse.json()).toMatchObject({
      provider: 'gemini-cli',
      status: 'success',
    });

    const accounts = await db.select().from(schema.accounts).all();
    expect(accounts).toHaveLength(1);
    expect(accounts[0]).toMatchObject({
      oauthProvider: 'gemini-cli',
      oauthProjectId: 'first-project-id',
      username: 'gemini-user@example.com',
      accessToken: 'gemini-access-token',
    });

    const parsed = JSON.parse(accounts[0]?.extraConfig || '{}');
    expect(parsed.oauth).toMatchObject({
      email: 'gemini-user@example.com',
      refreshToken: 'gemini-refresh-token',
    });
    expect(parsed.oauth).not.toHaveProperty('provider');
    expect(parsed.oauth).not.toHaveProperty('projectId');

    expect(String(fetchMock.mock.calls[1]?.[0] || '')).toContain('cloudresourcemanager.googleapis.com/v1/projects');
    expect(String(fetchMock.mock.calls[2]?.[0] || '')).toContain('/v1internal:loadCodeAssist');
    expect(String(fetchMock.mock.calls[3]?.[0] || '')).toContain('/v1internal:onboardUser');
    expect(String(fetchMock.mock.calls[4]?.[0] || '')).toContain('/projects/first-project-id/services/cloudaicompanion.googleapis.com');
    expect(String(fetchMock.mock.calls[6]?.[0] || '')).toContain('/projects/first-project-id/services/cloudaicompanion.googleapis.com');
  });

  it('onboards Gemini CLI into the backend project and auto-enables Cloud AI API when Google returns a free-tier project remap', async () => {
    fetchMock
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          access_token: 'gemini-access-token',
          refresh_token: 'gemini-refresh-token',
          expires_in: 3600,
          token_type: 'Bearer',
          scope: 'cloud-platform',
        }),
        text: async () => JSON.stringify({ ok: true }),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          projects: [
            { projectId: 'gen-lang-client-source-project' },
          ],
        }),
        text: async () => JSON.stringify({ ok: true }),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          allowedTiers: [
            { id: 'legacy-tier', isDefault: true },
          ],
        }),
        text: async () => JSON.stringify({ ok: true }),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          done: true,
          response: {
            cloudaicompanionProject: {
              id: 'gen-lang-client-0123456789',
            },
          },
        }),
        text: async () => JSON.stringify({ done: true }),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ state: 'DISABLED' }),
        text: async () => JSON.stringify({ state: 'DISABLED' }),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ ok: true }),
        text: async () => JSON.stringify({ ok: true }),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ email: 'gemini-free-user@example.com' }),
        text: async () => JSON.stringify({ email: 'gemini-free-user@example.com' }),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ state: 'ENABLED' }),
        text: async () => JSON.stringify({ state: 'ENABLED' }),
      });

    const startResponse = await app.inject({
      method: 'POST',
      url: '/api/oauth/providers/gemini-cli/start',
      headers: {
        host: 'metapi.example',
        'x-forwarded-proto': 'https',
      },
    });
    expect(startResponse.statusCode).toBe(200);
    const startBody = startResponse.json() as { state: string };

    const callbackResponse = await app.inject({
      method: 'POST',
      url: `/api/oauth/sessions/${encodeURIComponent(startBody.state)}/manual-callback`,
      payload: {
        callbackUrl: `http://localhost:8085/oauth2callback?state=${encodeURIComponent(startBody.state)}&code=gemini-oauth-code-free-tier`,
      },
    });
    expect(callbackResponse.statusCode).toBe(200);
    expect(callbackResponse.json()).toEqual({ success: true });

    const accounts = await db.select().from(schema.accounts).all();
    expect(accounts).toHaveLength(1);
    expect(accounts[0]).toMatchObject({
      oauthProvider: 'gemini-cli',
      oauthProjectId: 'gen-lang-client-0123456789',
      username: 'gemini-free-user@example.com',
    });

    const parsed = JSON.parse(accounts[0]?.extraConfig || '{}');
    expect(parsed.oauth).toMatchObject({
      refreshToken: 'gemini-refresh-token',
    });
    expect(parsed.oauth).not.toHaveProperty('projectId');

    expect(String(fetchMock.mock.calls[2]?.[0] || '')).toContain('/v1internal:loadCodeAssist');
    expect(String(fetchMock.mock.calls[3]?.[0] || '')).toContain('/v1internal:onboardUser');
    expect(String(fetchMock.mock.calls[4]?.[0] || '')).toContain('/projects/gen-lang-client-0123456789/services/cloudaicompanion.googleapis.com');
    expect(String(fetchMock.mock.calls[5]?.[0] || '')).toContain('/projects/gen-lang-client-0123456789/services/cloudaicompanion.googleapis.com:enable');
    expect(String(fetchMock.mock.calls[7]?.[0] || '')).toContain('/projects/gen-lang-client-0123456789/services/cloudaicompanion.googleapis.com');
  });

  it('surfaces Cloud AI API enable failures during Gemini CLI oauth setup and keeps the account rolled back', async () => {
    fetchMock
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          access_token: 'gemini-access-token',
          refresh_token: 'gemini-refresh-token',
          expires_in: 3600,
          token_type: 'Bearer',
          scope: 'cloud-platform',
        }),
        text: async () => JSON.stringify({ ok: true }),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          projects: [
            { projectId: 'project-enable-failure' },
          ],
        }),
        text: async () => JSON.stringify({ ok: true }),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          cloudaicompanionProject: {
            id: 'project-enable-failure',
          },
          allowedTiers: [
            { id: 'legacy-tier', isDefault: true },
          ],
        }),
        text: async () => JSON.stringify({ ok: true }),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          done: true,
          response: {
            cloudaicompanionProject: {
              id: 'project-enable-failure',
            },
          },
        }),
        text: async () => JSON.stringify({ done: true }),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ state: 'DISABLED' }),
        text: async () => JSON.stringify({ state: 'DISABLED' }),
      })
      .mockResolvedValueOnce({
        ok: false,
        status: 403,
        json: async () => ({ error: { message: 'Permission denied for project-enable-failure' } }),
        text: async () => JSON.stringify({ error: { message: 'Permission denied for project-enable-failure' } }),
      });

    const startResponse = await app.inject({
      method: 'POST',
      url: '/api/oauth/providers/gemini-cli/start',
      headers: {
        host: 'metapi.example',
        'x-forwarded-proto': 'https',
      },
    });
    expect(startResponse.statusCode).toBe(200);
    const startBody = startResponse.json() as { state: string };

    const callbackResponse = await app.inject({
      method: 'POST',
      url: `/api/oauth/sessions/${encodeURIComponent(startBody.state)}/manual-callback`,
      payload: {
        callbackUrl: `http://localhost:8085/oauth2callback?state=${encodeURIComponent(startBody.state)}&code=gemini-oauth-code-enable-failure`,
      },
    });
    expect(callbackResponse.statusCode).toBe(500);
    expect(callbackResponse.json()).toMatchObject({
      message: expect.stringContaining('project activation required'),
    });

    const sessionResponse = await app.inject({
      method: 'GET',
      url: `/api/oauth/sessions/${startBody.state}`,
    });
    expect(sessionResponse.statusCode).toBe(200);
    expect(sessionResponse.json()).toMatchObject({
      provider: 'gemini-cli',
      status: 'error',
      error: expect.stringContaining('Permission denied for project-enable-failure'),
    });

    const accounts = await db.select().from(schema.accounts).all();
    expect(accounts).toEqual([]);
  });

  it('fails Gemini CLI oauth setup when the Google account has no available Cloud projects', async () => {
    fetchMock
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          access_token: 'gemini-access-token',
          refresh_token: 'gemini-refresh-token',
          expires_in: 3600,
          token_type: 'Bearer',
          scope: 'cloud-platform',
        }),
        text: async () => JSON.stringify({ ok: true }),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          projects: [],
        }),
        text: async () => JSON.stringify({ ok: true }),
      });

    const startResponse = await app.inject({
      method: 'POST',
      url: '/api/oauth/providers/gemini-cli/start',
      headers: {
        host: 'metapi.example',
        'x-forwarded-proto': 'https',
      },
    });
    expect(startResponse.statusCode).toBe(200);
    const startBody = startResponse.json() as { state: string };

    const callbackResponse = await app.inject({
      method: 'POST',
      url: `/api/oauth/sessions/${encodeURIComponent(startBody.state)}/manual-callback`,
      payload: {
        callbackUrl: `http://localhost:8085/oauth2callback?state=${encodeURIComponent(startBody.state)}&code=gemini-oauth-code-no-projects`,
      },
    });
    expect(callbackResponse.statusCode).toBe(500);
    expect(callbackResponse.json()).toMatchObject({
      message: 'no Google Cloud projects available for this account',
    });

    const sessionResponse = await app.inject({
      method: 'GET',
      url: `/api/oauth/sessions/${startBody.state}`,
    });
    expect(sessionResponse.statusCode).toBe(200);
    expect(sessionResponse.json()).toMatchObject({
      provider: 'gemini-cli',
      status: 'error',
      error: 'no Google Cloud projects available for this account',
    });

    const accounts = await db.select().from(schema.accounts).all();
    expect(accounts).toEqual([]);
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
      oauthProvider: 'codex',
      oauthAccountKey: 'chatgpt-account-123',
      extraConfig: JSON.stringify({
        credentialMode: 'session',
        oauth: {
          provider: 'codex',
          accountId: 'chatgpt-account-123',
          email: 'codex-user@example.com',
          planType: 'team',
          idToken: buildJwt({
            email: 'codex-user@example.com',
            'https://api.openai.com/auth': {
              chatgpt_account_id: 'chatgpt-account-123',
              chatgpt_plan_type: 'team',
              chatgpt_subscription_active_start: '2026-03-01T00:00:00.000Z',
              chatgpt_subscription_active_until: '2026-04-01T00:00:00.000Z',
            },
          }),
          quota: {
            status: 'supported',
            source: 'reverse_engineered',
            lastSyncAt: '2026-03-17T08:00:00.000Z',
            lastLimitResetAt: '2026-03-17T13:00:00.000Z',
            windows: {
              fiveHour: {
                supported: false,
                message: 'official 5h quota window is not exposed by current codex oauth artifacts',
              },
              sevenDay: {
                supported: false,
                message: 'official 7d quota window is not exposed by current codex oauth artifacts',
              },
            },
          },
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
    expect(listResponse.json()).toMatchObject({
      items: expect.arrayContaining([
        expect.objectContaining({
          accountId: account.id,
          provider: 'codex',
          email: 'codex-user@example.com',
          status: 'abnormal',
          quota: expect.objectContaining({
            status: 'supported',
            source: 'reverse_engineered',
            lastLimitResetAt: '2026-03-17T13:00:00.000Z',
            subscription: expect.objectContaining({
              planType: 'team',
              activeStart: '2026-03-01T00:00:00.000Z',
              activeUntil: '2026-04-01T00:00:00.000Z',
            }),
          }),
          routeChannelCount: 1,
          lastModelSyncAt: '2026-03-17T08:00:00.000Z',
          lastModelSyncError: 'Codex 模型获取失败（HTTP 403: forbidden）',
        }),
      ]),
      total: 1,
      limit: 50,
      offset: 0,
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

  it('refreshes oauth quota snapshots and marks unsupported providers explicitly', async () => {
    const codexSite = await db.insert(schema.sites).values({
      name: 'ChatGPT Codex OAuth',
      url: 'https://chatgpt.com/backend-api/codex',
      platform: 'codex',
      status: 'active',
    }).returning().get();
    const antigravitySite = await db.insert(schema.sites).values({
      name: 'Antigravity OAuth',
      url: 'https://example.com/antigravity',
      platform: 'antigravity',
      status: 'active',
    }).returning().get();

    const codexAccount = await db.insert(schema.accounts).values({
      siteId: codexSite.id,
      username: 'codex-user@example.com',
      accessToken: 'oauth-access-token',
      status: 'active',
      oauthProvider: 'codex',
      oauthAccountKey: 'chatgpt-account-123',
      extraConfig: JSON.stringify({
        credentialMode: 'session',
        oauth: {
          provider: 'codex',
          accountId: 'chatgpt-account-123',
          email: 'codex-user@example.com',
          planType: 'plus',
          idToken: buildJwt({
            email: 'codex-user@example.com',
            'https://api.openai.com/auth': {
              chatgpt_account_id: 'chatgpt-account-123',
              chatgpt_plan_type: 'plus',
              chatgpt_subscription_active_start: '2026-03-01T00:00:00.000Z',
              chatgpt_subscription_active_until: '2026-04-01T00:00:00.000Z',
            },
          }),
        },
      }),
    }).returning().get();

    const antigravityAccount = await db.insert(schema.accounts).values({
      siteId: antigravitySite.id,
      username: 'ag-user@example.com',
      accessToken: 'oauth-access-token',
      status: 'active',
      oauthProvider: 'antigravity',
      oauthAccountKey: 'ag-account-123',
      extraConfig: JSON.stringify({
        credentialMode: 'session',
        oauth: {
          provider: 'antigravity',
          accountId: 'ag-account-123',
          email: 'ag-user@example.com',
          planType: 'pro',
        },
      }),
    }).returning().get();

    fetchMock.mockResolvedValueOnce(buildCodexQuotaProbeResponse({
      headers: {
        'x-codex-primary-used-percent': '62',
        'x-codex-primary-reset-after-seconds': '604800',
        'x-codex-primary-window-minutes': '10080',
        'x-codex-secondary-used-percent': '14',
        'x-codex-secondary-reset-after-seconds': '7200',
        'x-codex-secondary-window-minutes': '300',
      },
    }));

    const codexRefresh = await app.inject({
      method: 'POST',
      url: `/api/oauth/connections/${codexAccount.id}/quota/refresh`,
    });
    expect(codexRefresh.statusCode).toBe(200);
    expect(codexRefresh.json()).toMatchObject({
      success: true,
      quota: expect.objectContaining({
        status: 'supported',
        providerMessage: 'codex usage windows inferred from rate limit response headers',
        subscription: expect.objectContaining({
          planType: 'plus',
          activeStart: '2026-03-01T00:00:00.000Z',
          activeUntil: '2026-04-01T00:00:00.000Z',
        }),
        windows: {
          fiveHour: expect.objectContaining({
            supported: true,
            used: 14,
            limit: 100,
            remaining: 86,
          }),
          sevenDay: expect.objectContaining({
            supported: true,
            used: 62,
            limit: 100,
            remaining: 38,
          }),
        },
      }),
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://chatgpt.com/backend-api/codex/responses',
      expect.objectContaining({
        method: 'POST',
        signal: expect.any(AbortSignal),
        headers: expect.objectContaining({
          Authorization: 'Bearer oauth-access-token',
          Originator: 'codex_cli_rs',
          'Chatgpt-Account-Id': 'chatgpt-account-123',
        }),
      }),
    );

    const antigravityRefresh = await app.inject({
      method: 'POST',
      url: `/api/oauth/connections/${antigravityAccount.id}/quota/refresh`,
    });
    expect(antigravityRefresh.statusCode).toBe(200);
    expect(antigravityRefresh.json()).toMatchObject({
      success: true,
      quota: expect.objectContaining({
        status: 'unsupported',
        providerMessage: 'official quota windows are not exposed for antigravity oauth',
      }),
    });
  });

  it('supports batch quota refresh for oauth connections', async () => {
    const codexSite = await db.insert(schema.sites).values({
      name: 'ChatGPT Codex OAuth',
      url: 'https://chatgpt.com/backend-api/codex',
      platform: 'codex',
      status: 'active',
    }).returning().get();

    const firstAccount = await db.insert(schema.accounts).values({
      siteId: codexSite.id,
      username: 'codex-a@example.com',
      accessToken: 'oauth-access-token-a',
      status: 'active',
      oauthProvider: 'codex',
      oauthAccountKey: 'chatgpt-account-a',
      extraConfig: JSON.stringify({
        credentialMode: 'session',
        oauth: {
          provider: 'codex',
          accountId: 'chatgpt-account-a',
          email: 'codex-a@example.com',
          planType: 'plus',
          idToken: buildJwt({
            email: 'codex-a@example.com',
            'https://api.openai.com/auth': {
              chatgpt_account_id: 'chatgpt-account-a',
              chatgpt_plan_type: 'plus',
            },
          }),
        },
      }),
    }).returning().get();

    const secondAccount = await db.insert(schema.accounts).values({
      siteId: codexSite.id,
      username: 'codex-b@example.com',
      accessToken: 'oauth-access-token-b',
      status: 'active',
      oauthProvider: 'codex',
      oauthAccountKey: 'chatgpt-account-b',
      extraConfig: JSON.stringify({
        credentialMode: 'session',
        oauth: {
          provider: 'codex',
          accountId: 'chatgpt-account-b',
          email: 'codex-b@example.com',
          planType: 'team',
          idToken: buildJwt({
            email: 'codex-b@example.com',
            'https://api.openai.com/auth': {
              chatgpt_account_id: 'chatgpt-account-b',
              chatgpt_plan_type: 'team',
            },
          }),
        },
      }),
    }).returning().get();

    fetchMock
      .mockResolvedValueOnce(buildCodexQuotaProbeResponse({
        headers: {
          'x-codex-primary-used-percent': '41',
          'x-codex-primary-reset-after-seconds': '86400',
          'x-codex-primary-window-minutes': '10080',
          'x-codex-secondary-used-percent': '9',
          'x-codex-secondary-reset-after-seconds': '1800',
          'x-codex-secondary-window-minutes': '300',
        },
      }))
      .mockResolvedValueOnce(buildCodexQuotaProbeResponse({
        headers: {
          'x-codex-primary-used-percent': '88',
          'x-codex-primary-reset-after-seconds': '43200',
          'x-codex-primary-window-minutes': '10080',
          'x-codex-secondary-used-percent': '27',
          'x-codex-secondary-reset-after-seconds': '900',
          'x-codex-secondary-window-minutes': '300',
        },
      }));

    const batchRefresh = await app.inject({
      method: 'POST',
      url: '/api/oauth/connections/quota/refresh-batch',
      payload: {
        accountIds: [firstAccount.id, secondAccount.id],
      },
    });

    expect(batchRefresh.statusCode).toBe(200);
    expect(batchRefresh.json()).toMatchObject({
      success: true,
      refreshed: 2,
      failed: 0,
      items: expect.arrayContaining([
        expect.objectContaining({
          accountId: firstAccount.id,
          success: true,
          quota: expect.objectContaining({
            status: 'supported',
            windows: expect.objectContaining({
              fiveHour: expect.objectContaining({
                supported: true,
                used: 9,
                limit: 100,
              }),
              sevenDay: expect.objectContaining({
                supported: true,
                used: 41,
                limit: 100,
              }),
            }),
          }),
        }),
        expect.objectContaining({
          accountId: secondAccount.id,
          success: true,
          quota: expect.objectContaining({
            status: 'supported',
            windows: expect.objectContaining({
              fiveHour: expect.objectContaining({
                supported: true,
                used: 27,
                limit: 100,
              }),
              sevenDay: expect.objectContaining({
                supported: true,
                used: 88,
                limit: 100,
              }),
            }),
          }),
        }),
      ]),
    });
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock.mock.calls[0]?.[1]).toMatchObject({
      signal: expect.any(AbortSignal),
    });
    expect(fetchMock.mock.calls[1]?.[1]).toMatchObject({
      signal: expect.any(AbortSignal),
    });
  });

  it('rejects oversized oauth quota refresh batches before dispatching upstream work', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/oauth/connections/quota/refresh-batch',
      payload: {
        accountIds: Array.from({ length: 101 }, (_, index) => index + 1),
      },
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({
      message: 'accountIds must contain at most 100 items',
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('runs batch quota refresh probes with bounded concurrency instead of fully serializing them', async () => {
    const codexSite = await db.insert(schema.sites).values({
      name: 'ChatGPT Codex OAuth',
      url: 'https://chatgpt.com/backend-api/codex',
      platform: 'codex',
      status: 'active',
    }).returning().get();

    const firstAccount = await db.insert(schema.accounts).values({
      siteId: codexSite.id,
      username: 'codex-concurrency-a@example.com',
      accessToken: 'oauth-access-token-a',
      status: 'active',
      oauthProvider: 'codex',
      oauthAccountKey: 'chatgpt-concurrency-account-a',
      extraConfig: JSON.stringify({
        credentialMode: 'session',
        oauth: {
          provider: 'codex',
          accountId: 'chatgpt-concurrency-account-a',
          email: 'codex-concurrency-a@example.com',
          planType: 'plus',
        },
      }),
    }).returning().get();

    const secondAccount = await db.insert(schema.accounts).values({
      siteId: codexSite.id,
      username: 'codex-concurrency-b@example.com',
      accessToken: 'oauth-access-token-b',
      status: 'active',
      oauthProvider: 'codex',
      oauthAccountKey: 'chatgpt-concurrency-account-b',
      extraConfig: JSON.stringify({
        credentialMode: 'session',
        oauth: {
          provider: 'codex',
          accountId: 'chatgpt-concurrency-account-b',
          email: 'codex-concurrency-b@example.com',
          planType: 'plus',
        },
      }),
    }).returning().get();

    const firstProbe = createDeferred<ReturnType<typeof buildCodexQuotaProbeResponse>>();
    const secondProbe = createDeferred<ReturnType<typeof buildCodexQuotaProbeResponse>>();
    fetchMock
      .mockImplementationOnce(() => firstProbe.promise)
      .mockImplementationOnce(() => secondProbe.promise);

    const batchRefreshPromise = app.inject({
      method: 'POST',
      url: '/api/oauth/connections/quota/refresh-batch',
      payload: {
        accountIds: [firstAccount.id, secondAccount.id],
      },
    });

    await vi.waitFor(() => {
      expect(fetchMock).toHaveBeenCalledTimes(2);
    });

    firstProbe.resolve(buildCodexQuotaProbeResponse({
      headers: {
        'x-codex-primary-used-percent': '51',
        'x-codex-primary-reset-after-seconds': '3600',
        'x-codex-primary-window-minutes': '10080',
        'x-codex-secondary-used-percent': '11',
        'x-codex-secondary-reset-after-seconds': '900',
        'x-codex-secondary-window-minutes': '300',
      },
    }));
    secondProbe.resolve(buildCodexQuotaProbeResponse({
      headers: {
        'x-codex-primary-used-percent': '61',
        'x-codex-primary-reset-after-seconds': '7200',
        'x-codex-primary-window-minutes': '10080',
        'x-codex-secondary-used-percent': '19',
        'x-codex-secondary-reset-after-seconds': '1200',
        'x-codex-secondary-window-minutes': '300',
      },
    }));

    const batchRefresh = await batchRefreshPromise;
    expect(batchRefresh.statusCode).toBe(200);
    expect(batchRefresh.json()).toMatchObject({
      success: true,
      refreshed: 2,
      failed: 0,
    });
  });

  it('imports a native codex oauth json object', async () => {
    fetchMock.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({
        models: [
          { id: 'gpt-5.4' },
        ],
      }),
      text: async () => JSON.stringify({ ok: true }),
    });

    const response = await app.inject({
      method: 'POST',
      url: '/api/oauth/import',
      payload: {
        data: {
          type: 'codex',
          access_token: 'imported-access-token',
          refresh_token: 'imported-refresh-token',
          expired: '2026-04-12T11:26:13+08:00',
          last_refresh: '2026-04-02T11:26:14+08:00',
          id_token: buildJwt({
            email: 'imported-codex@example.com',
            'https://api.openai.com/auth': {
              chatgpt_account_id: 'chatgpt-imported-123',
              chatgpt_plan_type: 'plus',
            },
          }),
        },
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      success: true,
      imported: 1,
      skipped: 0,
      failed: 0,
    });

    const accounts = await db.select().from(schema.accounts).all();
    expect(accounts).toHaveLength(1);
    expect(accounts[0]).toMatchObject({
      username: 'imported-codex@example.com',
      accessToken: 'imported-access-token',
      oauthProvider: 'codex',
      oauthAccountKey: 'chatgpt-imported-123',
      status: 'active',
    });

    const parsedExtra = JSON.parse(accounts[0]?.extraConfig || '{}') as {
      credentialMode?: string;
      oauth?: {
        provider?: string;
        refreshToken?: string;
        email?: string;
        planType?: string;
        tokenExpiresAt?: number;
      };
    };
    expect(parsedExtra.credentialMode).toBe('session');
    expect(parsedExtra.oauth).toMatchObject({
      refreshToken: 'imported-refresh-token',
      email: 'imported-codex@example.com',
      planType: 'plus',
    });
    expect(parsedExtra.oauth?.tokenExpiresAt).toBe(Date.parse('2026-04-12T11:26:13+08:00'));
    expect(fetchMock).toHaveBeenCalledWith(
      'https://chatgpt.com/backend-api/codex/models?client_version=1.0.0',
      expect.objectContaining({
        method: 'GET',
        headers: expect.objectContaining({
          Authorization: 'Bearer imported-access-token',
          Originator: 'codex_cli_rs',
        }),
      }),
    );
    const modelRows = await db.select().from(schema.modelAvailability).all();
    expect(modelRows).toEqual(expect.arrayContaining([
      expect.objectContaining({
        accountId: accounts[0]?.id,
        modelName: 'gpt-5.4',
        available: true,
      }),
    ]));
    const routeRows = await db.select().from(schema.routeChannels).all();
    expect(routeRows).toHaveLength(1);
    expect(routeRows[0]).toMatchObject({
      accountId: accounts[0]?.id,
    });
  });

  it('imports multiple native oauth json objects with shared proxy settings in one request', async () => {
    config.systemProxyUrl = 'http://127.0.0.1:7890';
    fetchMock
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          models: [{ id: 'gpt-5.4' }],
        }),
        text: async () => JSON.stringify({ ok: true }),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          models: [{ id: 'gpt-5.4-mini' }],
        }),
        text: async () => JSON.stringify({ ok: true }),
      });

    const response = await app.inject({
      method: 'POST',
      url: '/api/oauth/import',
      payload: {
        items: [
          {
            type: 'codex',
            access_token: 'imported-access-token-a',
            refresh_token: 'imported-refresh-token-a',
            email: 'imported-batch-a@example.com',
            account_id: 'chatgpt-imported-a',
          },
          {
            type: 'codex',
            access_token: 'imported-access-token-b',
            refresh_token: 'imported-refresh-token-b',
            email: 'imported-batch-b@example.com',
            account_id: 'chatgpt-imported-b',
          },
        ],
        useSystemProxy: true,
        proxyUrl: null,
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      success: true,
      imported: 2,
      failed: 0,
      skipped: 0,
    });

    const accounts = await db.select().from(schema.accounts).all();
    expect(accounts).toHaveLength(2);
    expect(accounts.map((row) => JSON.parse(row.extraConfig || '{}'))).toEqual(expect.arrayContaining([
      expect.objectContaining({
        useSystemProxy: true,
        proxyUrl: null,
      }),
      expect.objectContaining({
        useSystemProxy: true,
        proxyUrl: null,
      }),
    ]));

    const modelRows = await db.select().from(schema.modelAvailability).all();
    expect(modelRows).toHaveLength(2);
    const routeRows = await db.select().from(schema.routeChannels).all();
    expect(routeRows).toHaveLength(2);
  });

  it('prefers explicit identity fields from native oauth json and preserves disabled status', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/oauth/import',
      payload: {
        data: {
          type: 'codex',
          access_token: 'imported-access-token',
          refresh_token: 'imported-refresh-token',
          account_id: 'explicit-account-id',
          email: 'explicit-user@example.com',
          disabled: true,
          id_token: buildJwt({
            email: 'claim-user@example.com',
            'https://api.openai.com/auth': {
              chatgpt_account_id: 'claim-account-id',
              chatgpt_plan_type: 'plus',
            },
          }),
        },
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      success: true,
      imported: 1,
      skipped: 0,
      failed: 0,
    });

    const accounts = await db.select().from(schema.accounts).all();
    expect(accounts).toHaveLength(1);
    expect(accounts[0]).toMatchObject({
      username: 'explicit-user@example.com',
      accessToken: 'imported-access-token',
      oauthProvider: 'codex',
      oauthAccountKey: 'explicit-account-id',
      status: 'disabled',
    });
  });

  it('rejects a native oauth json object without access_token', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/oauth/import',
      payload: {
        data: {
          type: 'codex',
          refresh_token: 'imported-refresh-token',
        },
      },
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({
      message: 'oauth credentials missing access_token',
    });
  });

  it('rejects a native oauth json object with malformed expired', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/oauth/import',
      payload: {
        data: {
          type: 'codex',
          access_token: 'imported-access-token',
          expired: 'not-a-date',
        },
      },
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({
      message: 'invalid oauth expired timestamp',
    });
  });

  it('rejects legacy sub2api oauth envelopes', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/oauth/import',
      payload: {
        data: {
          type: 'sub2api-data',
          version: 1,
          accounts: [],
          proxies: [],
        },
      },
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({
      message: 'native oauth json expected; sub2api envelopes are no longer supported',
    });
  });

  it('rejects oauth import arrays', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/oauth/import',
      payload: {
        data: [
          {
            type: 'codex',
            access_token: 'imported-access-token',
          },
        ],
      },
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({
      message: 'data must be a native oauth json object',
    });
  });

  it('returns 500 and rolls back a newly imported oauth account when initial model discovery fails', async () => {
    fetchMock.mockResolvedValueOnce({
      ok: false,
      status: 503,
      json: async () => ({ error: 'unavailable' }),
      text: async () => 'unavailable',
    });

    const response = await app.inject({
      method: 'POST',
      url: '/api/oauth/import',
      payload: {
        data: {
          type: 'codex',
          access_token: 'broken-imported-access-token',
          refresh_token: 'broken-imported-refresh-token',
          id_token: buildJwt({
            email: 'broken-import@example.com',
            'https://api.openai.com/auth': {
              chatgpt_account_id: 'broken-import-account',
              chatgpt_plan_type: 'plus',
            },
          }),
        },
      },
    });

    expect(response.statusCode).toBe(500);
    expect(response.json()).toMatchObject({
      message: 'Codex 模型获取失败（HTTP 503: unavailable）',
    });
    expect(await db.select().from(schema.accounts).all()).toHaveLength(0);
    expect(await db.select().from(schema.modelAvailability).all()).toHaveLength(0);
  });

  it('continues batch oauth import after one item fails and returns a full summary', async () => {
    fetchMock
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          models: [{ id: 'gpt-5.4' }],
        }),
        text: async () => JSON.stringify({ ok: true }),
      })
      .mockResolvedValueOnce({
        ok: false,
        status: 503,
        json: async () => ({ error: 'unavailable' }),
        text: async () => 'unavailable',
      });

    const response = await app.inject({
      method: 'POST',
      url: '/api/oauth/import',
      payload: {
        items: [
          {
            type: 'codex',
            access_token: 'batch-success-access-token',
            refresh_token: 'batch-success-refresh-token',
            id_token: buildJwt({
              email: 'batch-success@example.com',
              'https://api.openai.com/auth': {
                chatgpt_account_id: 'batch-success-account',
                chatgpt_plan_type: 'plus',
              },
            }),
          },
          {
            type: 'codex',
            access_token: 'batch-failed-access-token',
            refresh_token: 'batch-failed-refresh-token',
            id_token: buildJwt({
              email: 'batch-failed@example.com',
              'https://api.openai.com/auth': {
                chatgpt_account_id: 'batch-failed-account',
                chatgpt_plan_type: 'plus',
              },
            }),
          },
        ],
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      success: false,
      imported: 1,
      failed: 1,
      items: [
        expect.objectContaining({
          name: 'batch-success@example.com',
          status: 'imported',
        }),
        expect.objectContaining({
          name: 'batch-failed@example.com',
          status: 'failed',
          message: 'Codex 模型获取失败（HTTP 503: unavailable）',
        }),
      ],
    });

    const accounts = await db.select().from(schema.accounts).all();
    expect(accounts).toHaveLength(1);
    expect(accounts[0]?.username).toBe('batch-success@example.com');
    expect(await db.select().from(schema.modelAvailability).all()).toHaveLength(1);
  });

  it('rate limits repeated oauth import requests', async () => {
    const { resetOauthSensitiveRouteLimiterForTests } = await import('./oauth.js');
    resetOauthSensitiveRouteLimiterForTests({ points: 1 });

    fetchMock.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({
        models: [{ id: 'gpt-5.4' }],
      }),
      text: async () => JSON.stringify({ ok: true }),
    });

    const payload = {
      data: {
        type: 'codex',
        access_token: 'limited-access-token',
        refresh_token: 'limited-refresh-token',
        id_token: buildJwt({
          email: 'limited@example.com',
          'https://api.openai.com/auth': {
            chatgpt_account_id: 'limited-account',
            chatgpt_plan_type: 'plus',
          },
        }),
      },
    };

    const first = await app.inject({
      method: 'POST',
      url: '/api/oauth/import',
      payload,
    });
    const second = await app.inject({
      method: 'POST',
      url: '/api/oauth/import',
      payload,
    });

    expect(first.statusCode).toBe(200);
    expect(second.statusCode).toBe(429);
    expect(second.json()).toMatchObject({
      message: '请求过于频繁，请稍后再试',
    });
  });

  it('creates and deletes an oauth route unit, collapsing grouped accounts into one route channel', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'ChatGPT Codex OAuth',
      url: 'https://chatgpt.com/backend-api/codex',
      platform: 'codex',
      status: 'active',
    }).returning().get();

    const accountA = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'pool-a@example.com',
      accessToken: 'oauth-access-token-a',
      apiToken: null,
      status: 'active',
      oauthProvider: 'codex',
      oauthAccountKey: 'chatgpt-pool-a',
      extraConfig: JSON.stringify({
        credentialMode: 'session',
        oauth: {
          provider: 'codex',
          accountId: 'chatgpt-pool-a',
          accountKey: 'chatgpt-pool-a',
          email: 'pool-a@example.com',
        },
      }),
    }).returning().get();
    const accountB = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'pool-b@example.com',
      accessToken: 'oauth-access-token-b',
      apiToken: null,
      status: 'active',
      oauthProvider: 'codex',
      oauthAccountKey: 'chatgpt-pool-b',
      extraConfig: JSON.stringify({
        credentialMode: 'session',
        oauth: {
          provider: 'codex',
          accountId: 'chatgpt-pool-b',
          accountKey: 'chatgpt-pool-b',
          email: 'pool-b@example.com',
        },
      }),
    }).returning().get();

    await db.insert(schema.modelAvailability).values([
      {
        accountId: accountA.id,
        modelName: 'gpt-5.4',
        available: true,
      },
      {
        accountId: accountB.id,
        modelName: 'gpt-5.4',
        available: true,
      },
    ]).run();

    const { rebuildRoutesOnly } = await import('../../services/routeRefreshWorkflow.js');
    await rebuildRoutesOnly();
    expect(await db.select().from(schema.routeChannels).all()).toHaveLength(2);

    const createResponse = await app.inject({
      method: 'POST',
      url: '/api/oauth/route-units',
      payload: {
        accountIds: [accountA.id, accountB.id],
        name: 'Codex Pool',
        strategy: 'round_robin',
      },
    });

    expect(createResponse.statusCode).toBe(200);
    expect(createResponse.json()).toMatchObject({
      success: true,
      routeUnit: expect.objectContaining({
        name: 'Codex Pool',
        strategy: 'round_robin',
        memberCount: 2,
      }),
    });

    const groupedChannels = await db.select().from(schema.routeChannels).all();
    expect(groupedChannels).toHaveLength(1);
    expect(groupedChannels[0]).toMatchObject({
      oauthRouteUnitId: expect.any(Number),
    });

    const listResponse = await app.inject({
      method: 'GET',
      url: '/api/oauth/connections',
    });
    expect(listResponse.statusCode).toBe(200);
    expect(listResponse.json()).toMatchObject({
      items: expect.arrayContaining([
        expect.objectContaining({
          accountId: accountA.id,
          routeUnit: expect.objectContaining({
            name: 'Codex Pool',
            strategy: 'round_robin',
            memberCount: 2,
          }),
        }),
        expect.objectContaining({
          accountId: accountB.id,
          routeUnit: expect.objectContaining({
            name: 'Codex Pool',
            strategy: 'round_robin',
            memberCount: 2,
          }),
        }),
      ]),
    });

    const deleteResponse = await app.inject({
      method: 'DELETE',
      url: `/api/oauth/route-units/${groupedChannels[0]?.oauthRouteUnitId}`,
    });
    expect(deleteResponse.statusCode).toBe(200);
    expect(deleteResponse.json()).toMatchObject({ success: true });

    const splitChannels = await db.select().from(schema.routeChannels).all();
    expect(splitChannels).toHaveLength(2);
    expect(splitChannels.every((row) => row.oauthRouteUnitId == null)).toBe(true);
  });

  it('rolls back oauth route unit creation when route rebuild fails', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'ChatGPT Codex OAuth',
      url: 'https://chatgpt.com/backend-api/codex',
      platform: 'codex',
      status: 'active',
    }).returning().get();

    const first = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'rollback-create-a@example.com',
      accessToken: 'rollback-create-access-a',
      status: 'active',
      oauthProvider: 'codex',
      oauthAccountKey: 'rollback-create-a',
      extraConfig: JSON.stringify({
        oauth: {
          provider: 'codex',
          accountId: 'rollback-create-a',
          accountKey: 'rollback-create-a',
          email: 'rollback-create-a@example.com',
          refreshToken: 'rollback-create-refresh-a',
        },
      }),
    }).returning().get();
    const second = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'rollback-create-b@example.com',
      accessToken: 'rollback-create-access-b',
      status: 'active',
      oauthProvider: 'codex',
      oauthAccountKey: 'rollback-create-b',
      extraConfig: JSON.stringify({
        oauth: {
          provider: 'codex',
          accountId: 'rollback-create-b',
          accountKey: 'rollback-create-b',
          email: 'rollback-create-b@example.com',
          refreshToken: 'rollback-create-refresh-b',
        },
      }),
    }).returning().get();

    await db.insert(schema.modelAvailability).values([
      { accountId: first.id, modelName: 'gpt-5.4', available: true },
      { accountId: second.id, modelName: 'gpt-5.4', available: true },
    ]).run();

    const routeRefreshWorkflow = await import('../../services/routeRefreshWorkflow.js');
    await routeRefreshWorkflow.rebuildRoutesOnly();
    const rebuildSpy = vi.spyOn(routeRefreshWorkflow, 'rebuildRoutesOnly');
    rebuildSpy.mockImplementationOnce(async () => {
      throw new Error('route rebuild failed');
    });

    try {
      const response = await app.inject({
        method: 'POST',
        url: '/api/oauth/route-units',
        payload: {
          accountIds: [first.id, second.id],
          name: 'Rollback Pool',
          strategy: 'round_robin',
        },
      });

      expect(response.statusCode).toBe(500);
      expect(response.json()).toMatchObject({
        message: 'route rebuild failed',
      });
      expect(await db.select().from(schema.oauthRouteUnits).all()).toHaveLength(0);
      expect(await db.select().from(schema.oauthRouteUnitMembers).all()).toHaveLength(0);
      const routeChannels = await db.select().from(schema.routeChannels).all();
      expect(routeChannels).toHaveLength(2);
      expect(routeChannels.every((row) => row.oauthRouteUnitId == null)).toBe(true);
    } finally {
      rebuildSpy.mockRestore();
    }
  });

  it('rolls back oauth route unit deletion when route rebuild fails', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'ChatGPT Codex OAuth',
      url: 'https://chatgpt.com/backend-api/codex',
      platform: 'codex',
      status: 'active',
    }).returning().get();

    const first = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'rollback-delete-a@example.com',
      accessToken: 'rollback-delete-access-a',
      status: 'active',
      oauthProvider: 'codex',
      oauthAccountKey: 'rollback-delete-a',
      extraConfig: JSON.stringify({
        oauth: {
          provider: 'codex',
          accountId: 'rollback-delete-a',
          accountKey: 'rollback-delete-a',
          email: 'rollback-delete-a@example.com',
          refreshToken: 'rollback-delete-refresh-a',
        },
      }),
    }).returning().get();
    const second = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'rollback-delete-b@example.com',
      accessToken: 'rollback-delete-access-b',
      status: 'active',
      oauthProvider: 'codex',
      oauthAccountKey: 'rollback-delete-b',
      extraConfig: JSON.stringify({
        oauth: {
          provider: 'codex',
          accountId: 'rollback-delete-b',
          accountKey: 'rollback-delete-b',
          email: 'rollback-delete-b@example.com',
          refreshToken: 'rollback-delete-refresh-b',
        },
      }),
    }).returning().get();

    await db.insert(schema.modelAvailability).values([
      { accountId: first.id, modelName: 'gpt-5.4', available: true },
      { accountId: second.id, modelName: 'gpt-5.4', available: true },
    ]).run();

    const routeRefreshWorkflow = await import('../../services/routeRefreshWorkflow.js');
    await routeRefreshWorkflow.rebuildRoutesOnly();

    const createResponse = await app.inject({
      method: 'POST',
      url: '/api/oauth/route-units',
      payload: {
        accountIds: [first.id, second.id],
        name: 'Rollback Delete Pool',
        strategy: 'round_robin',
      },
    });
    expect(createResponse.statusCode).toBe(200);
    const routeUnitId = createResponse.json().routeUnit?.id as number;

    const rebuildSpy = vi.spyOn(routeRefreshWorkflow, 'rebuildRoutesOnly');
    rebuildSpy.mockImplementationOnce(async () => {
      throw new Error('route rebuild failed');
    });

    try {
      const response = await app.inject({
        method: 'DELETE',
        url: `/api/oauth/route-units/${routeUnitId}`,
      });

      expect(response.statusCode).toBe(500);
      expect(response.json()).toMatchObject({
        message: 'route rebuild failed',
      });

      const routeUnits = await db.select().from(schema.oauthRouteUnits).all();
      expect(routeUnits).toHaveLength(1);
      const members = await db.select().from(schema.oauthRouteUnitMembers).all();
      expect(members).toHaveLength(2);
      const routeChannels = await db.select().from(schema.routeChannels).all();
      expect(routeChannels).toHaveLength(1);
      expect(routeChannels[0]?.oauthRouteUnitId).toBe(routeUnitId);
    } finally {
      rebuildSpy.mockRestore();
    }
  });

  it('accepts normalized route unit strategy values from the HTTP payload', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'ChatGPT Codex OAuth',
      url: 'https://chatgpt.com/backend-api/codex',
      platform: 'codex',
      status: 'active',
    }).returning().get();

    const first = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'normalized-strategy-a@example.com',
      accessToken: 'normalized-strategy-access-a',
      status: 'active',
      oauthProvider: 'codex',
      oauthAccountKey: 'normalized-strategy-a',
      extraConfig: JSON.stringify({
        oauth: {
          provider: 'codex',
          accountId: 'normalized-strategy-a',
          accountKey: 'normalized-strategy-a',
          email: 'normalized-strategy-a@example.com',
          refreshToken: 'normalized-strategy-refresh-a',
        },
      }),
    }).returning().get();
    const second = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'normalized-strategy-b@example.com',
      accessToken: 'normalized-strategy-access-b',
      status: 'active',
      oauthProvider: 'codex',
      oauthAccountKey: 'normalized-strategy-b',
      extraConfig: JSON.stringify({
        oauth: {
          provider: 'codex',
          accountId: 'normalized-strategy-b',
          accountKey: 'normalized-strategy-b',
          email: 'normalized-strategy-b@example.com',
          refreshToken: 'normalized-strategy-refresh-b',
        },
      }),
    }).returning().get();

    await db.insert(schema.modelAvailability).values([
      { accountId: first.id, modelName: 'gpt-5.4', available: true },
      { accountId: second.id, modelName: 'gpt-5.4', available: true },
    ]).run();

    const routeRefreshWorkflow = await import('../../services/routeRefreshWorkflow.js');
    await routeRefreshWorkflow.rebuildRoutesOnly();

    const createResponse = await app.inject({
      method: 'POST',
      url: '/api/oauth/route-units',
      payload: {
        accountIds: [first.id, second.id],
        name: 'Normalized Strategy Pool',
        strategy: '  STICK_UNTIL_UNAVAILABLE  ',
      },
    });

    expect(createResponse.statusCode).toBe(200);
    expect(createResponse.json()).toMatchObject({
      success: true,
      routeUnit: expect.objectContaining({
        strategy: 'stick_until_unavailable',
      }),
    });
  });

  it('imports multiple oauth json objects in one batch and applies the explicit system proxy setting', async () => {
    config.systemProxyUrl = 'http://127.0.0.1:7890';
    fetchMock.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({
        models: [{ id: 'gpt-5.4' }],
      }),
      text: async () => JSON.stringify({ ok: true }),
    });

    const response = await app.inject({
      method: 'POST',
      url: '/api/oauth/import',
      payload: {
        items: [
          {
            type: 'codex',
            access_token: 'batch-active-access-token',
            refresh_token: 'batch-active-refresh-token',
            email: 'batch-active@example.com',
            account_id: 'batch-active-account',
          },
          {
            type: 'codex',
            access_token: 'batch-disabled-access-token',
            refresh_token: 'batch-disabled-refresh-token',
            email: 'batch-disabled@example.com',
            account_id: 'batch-disabled-account',
            disabled: true,
          },
        ],
        useSystemProxy: true,
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      success: true,
      imported: 2,
      failed: 0,
    });

    const accounts = await db.select().from(schema.accounts).all();
    expect(accounts).toHaveLength(2);
    expect(accounts.map((account) => JSON.parse(account.extraConfig || '{}'))).toEqual(expect.arrayContaining([
      expect.objectContaining({
        useSystemProxy: true,
      }),
    ]));

    const routeRows = await db.select().from(schema.routeChannels).all();
    expect(routeRows).toHaveLength(1);
  });

  it('creates and deletes an oauth route unit, collapsing and restoring route channels', async () => {
    const buildOauthExtraConfig = (email: string, accountKey: string) => JSON.stringify({
      credentialMode: 'session',
      oauth: {
        provider: 'codex',
        accountId: accountKey,
        accountKey,
        email,
        planType: 'plus',
        refreshToken: `refresh-${accountKey}`,
      },
    });

    const site = await db.insert(schema.sites).values({
      name: 'ChatGPT Codex OAuth',
      url: 'https://chatgpt.com/backend-api/codex',
      platform: 'codex',
      status: 'active',
    }).returning().get();

    const first = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'pool-a@example.com',
      accessToken: 'access-a',
      apiToken: null,
      status: 'active',
      oauthProvider: 'codex',
      oauthAccountKey: 'pool-a',
      extraConfig: buildOauthExtraConfig('pool-a@example.com', 'pool-a'),
    }).returning().get();
    const second = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'pool-b@example.com',
      accessToken: 'access-b',
      apiToken: null,
      status: 'active',
      oauthProvider: 'codex',
      oauthAccountKey: 'pool-b',
      extraConfig: buildOauthExtraConfig('pool-b@example.com', 'pool-b'),
    }).returning().get();

    await db.insert(schema.modelAvailability).values([
      {
        accountId: first.id,
        modelName: 'gpt-5.4',
        available: true,
      },
      {
        accountId: second.id,
        modelName: 'gpt-5.4',
        available: true,
      },
    ]).run();

    const routeRefreshWorkflow = await import('../../services/routeRefreshWorkflow.js');
    await routeRefreshWorkflow.rebuildRoutesOnly();

    expect(await db.select().from(schema.routeChannels).all()).toHaveLength(2);

    const createResponse = await app.inject({
      method: 'POST',
      url: '/api/oauth/route-units',
      payload: {
        accountIds: [first.id, second.id],
        name: 'Codex Pool',
        strategy: 'round_robin',
      },
    });

    expect(createResponse.statusCode).toBe(200);
    const createBody = createResponse.json() as { success?: boolean; routeUnit?: { id?: number } };
    expect(createBody).toMatchObject({
      success: true,
      routeUnit: {
        name: 'Codex Pool',
        strategy: 'round_robin',
      },
    });

    const routeRows = await db.select().from(schema.routeChannels).all();
    expect(routeRows).toHaveLength(1);

    const connectionsResponse = await app.inject({
      method: 'GET',
      url: '/api/oauth/connections',
    });
    expect(connectionsResponse.statusCode).toBe(200);
    expect(connectionsResponse.json()).toMatchObject({
      items: expect.arrayContaining([
        expect.objectContaining({
          accountId: first.id,
          routeUnit: expect.objectContaining({
            name: 'Codex Pool',
            strategy: 'round_robin',
            memberCount: 2,
          }),
        }),
        expect.objectContaining({
          accountId: second.id,
          routeUnit: expect.objectContaining({
            name: 'Codex Pool',
            strategy: 'round_robin',
            memberCount: 2,
          }),
        }),
      ]),
    });

    const deleteResponse = await app.inject({
      method: 'DELETE',
      url: `/api/oauth/route-units/${createBody.routeUnit?.id}`,
    });

    expect(deleteResponse.statusCode).toBe(200);
    expect(deleteResponse.json()).toMatchObject({
      success: true,
    });
    expect(await db.select().from(schema.routeChannels).all()).toHaveLength(2);
  });

  it('updates oauth account proxy settings without starting a new oauth session and refreshes routes', async () => {
    fetchMock.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({
        models: [{ id: 'gpt-5.4' }],
      }),
      text: async () => JSON.stringify({ ok: true }),
    });

    const site = await db.insert(schema.sites).values({
      name: 'ChatGPT Codex OAuth',
      url: 'https://chatgpt.com/backend-api/codex',
      platform: 'codex',
      status: 'active',
    }).returning().get();
    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'codex-save-proxy@example.com',
      accessToken: 'oauth-access-token',
      apiToken: null,
      status: 'active',
      oauthProvider: 'codex',
      oauthAccountKey: 'codex-save-proxy-account',
      extraConfig: JSON.stringify({
        credentialMode: 'session',
        oauth: {
          provider: 'codex',
          accountId: 'codex-save-proxy-account',
          accountKey: 'codex-save-proxy-account',
          email: 'codex-save-proxy@example.com',
        },
      }),
    }).returning().get();

    const response = await app.inject({
      method: 'PATCH',
      url: `/api/oauth/connections/${account.id}/proxy`,
      payload: {
        useSystemProxy: true,
        proxyUrl: null,
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      success: true,
      useSystemProxy: true,
      proxyUrl: null,
      refreshedRoutes: true,
    });

    const stored = await db.select().from(schema.accounts).where(eq(schema.accounts.id, account.id)).get();
    expect(JSON.parse(stored?.extraConfig || '{}')).toMatchObject({
      useSystemProxy: true,
      proxyUrl: null,
    });

    const modelRows = await db.select().from(schema.modelAvailability).all();
    expect(modelRows).toEqual(expect.arrayContaining([
      expect.objectContaining({
        accountId: account.id,
        modelName: 'gpt-5.4',
        available: true,
      }),
    ]));

    const routeRows = await db.select().from(schema.tokenRoutes).all();
    expect(routeRows).toEqual(expect.arrayContaining([
      expect.objectContaining({
        modelPattern: 'gpt-5.4',
      }),
    ]));
    const routeChannels = await db.select().from(schema.routeChannels).all();
    expect(routeChannels).toHaveLength(1);
  });

  it('imports multiple native oauth json objects in one batch request and applies shared system proxy settings', async () => {
    fetchMock
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          models: [{ id: 'gpt-5.4' }],
        }),
        text: async () => JSON.stringify({ ok: true }),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          models: [{ id: 'gpt-5.4-mini' }],
        }),
        text: async () => JSON.stringify({ ok: true }),
      });

    const response = await app.inject({
      method: 'POST',
      url: '/api/oauth/import',
      payload: {
        items: [
          {
            type: 'codex',
            access_token: 'batch-import-access-a',
            refresh_token: 'batch-import-refresh-a',
            id_token: buildJwt({
              email: 'batch-a@example.com',
              'https://api.openai.com/auth': {
                chatgpt_account_id: 'batch-account-a',
                chatgpt_plan_type: 'plus',
              },
            }),
          },
          {
            type: 'codex',
            access_token: 'batch-import-access-b',
            refresh_token: 'batch-import-refresh-b',
            id_token: buildJwt({
              email: 'batch-b@example.com',
              'https://api.openai.com/auth': {
                chatgpt_account_id: 'batch-account-b',
                chatgpt_plan_type: 'team',
              },
            }),
          },
        ],
        useSystemProxy: true,
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      success: true,
      imported: 2,
      failed: 0,
    });

    const accounts = await db.select().from(schema.accounts).all();
    expect(accounts).toHaveLength(2);
    expect(accounts.map((row) => JSON.parse(row.extraConfig || '{}').useSystemProxy)).toEqual([true, true]);

    const modelRows = await db.select().from(schema.modelAvailability).all();
    expect(modelRows).toEqual(expect.arrayContaining([
      expect.objectContaining({ modelName: 'gpt-5.4', available: true }),
      expect.objectContaining({ modelName: 'gpt-5.4-mini', available: true }),
    ]));

    const routeRows = await db.select().from(schema.tokenRoutes).all();
    expect(routeRows.map((row) => row.modelPattern).sort()).toEqual(['gpt-5.4', 'gpt-5.4-mini']);
    const routeChannels = await db.select().from(schema.routeChannels).all();
    expect(routeChannels).toHaveLength(2);
  });

  it('creates an oauth route unit and collapses multiple oauth accounts into one route channel', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'ChatGPT Codex OAuth',
      url: 'https://chatgpt.com/backend-api/codex',
      platform: 'codex',
      status: 'active',
    }).returning().get();

    const accountA = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'pool-a@example.com',
      accessToken: 'oauth-access-pool-a',
      apiToken: null,
      status: 'active',
      oauthProvider: 'codex',
      oauthAccountKey: 'pool-account-a',
      extraConfig: JSON.stringify({
        credentialMode: 'session',
        oauth: {
          provider: 'codex',
          accountId: 'pool-account-a',
          accountKey: 'pool-account-a',
          email: 'pool-a@example.com',
        },
      }),
    }).returning().get();
    const accountB = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'pool-b@example.com',
      accessToken: 'oauth-access-pool-b',
      apiToken: null,
      status: 'active',
      oauthProvider: 'codex',
      oauthAccountKey: 'pool-account-b',
      extraConfig: JSON.stringify({
        credentialMode: 'session',
        oauth: {
          provider: 'codex',
          accountId: 'pool-account-b',
          accountKey: 'pool-account-b',
          email: 'pool-b@example.com',
        },
      }),
    }).returning().get();

    await db.insert(schema.modelAvailability).values([
      {
        accountId: accountA.id,
        modelName: 'gpt-5.4',
        available: true,
      },
      {
        accountId: accountB.id,
        modelName: 'gpt-5.4',
        available: true,
      },
    ]).run();
    await rebuildRoutesOnly();

    expect(await db.select().from(schema.routeChannels).all()).toHaveLength(2);

    const response = await app.inject({
      method: 'POST',
      url: '/api/oauth/route-units',
      payload: {
        accountIds: [accountA.id, accountB.id],
        name: 'Codex Pool',
        strategy: 'round_robin',
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      success: true,
      routeUnit: {
        name: 'Codex Pool',
        strategy: 'round_robin',
        memberCount: 2,
      },
    });

    const routeChannels = await db.select().from(schema.routeChannels).all();
    expect(routeChannels).toHaveLength(1);

    const connectionsResponse = await app.inject({
      method: 'GET',
      url: '/api/oauth/connections',
    });
    expect(connectionsResponse.statusCode).toBe(200);
    expect(connectionsResponse.json()).toMatchObject({
      items: expect.arrayContaining([
        expect.objectContaining({
          accountId: accountA.id,
          routeParticipation: expect.objectContaining({
            kind: 'route_unit',
            routeUnitId: expect.any(Number),
            name: 'Codex Pool',
            strategy: 'round_robin',
            memberCount: 2,
          }),
        }),
        expect.objectContaining({
          accountId: accountB.id,
          routeParticipation: expect.objectContaining({
            kind: 'route_unit',
            routeUnitId: expect.any(Number),
            name: 'Codex Pool',
            strategy: 'round_robin',
            memberCount: 2,
          }),
        }),
      ]),
    });
  });

  it('deletes an oauth route unit and restores single-account route channels', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'ChatGPT Codex OAuth',
      url: 'https://chatgpt.com/backend-api/codex',
      platform: 'codex',
      status: 'active',
    }).returning().get();

    const accountA = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'split-a@example.com',
      accessToken: 'oauth-access-split-a',
      apiToken: null,
      status: 'active',
      oauthProvider: 'codex',
      oauthAccountKey: 'split-account-a',
      extraConfig: JSON.stringify({
        credentialMode: 'session',
        oauth: {
          provider: 'codex',
          accountId: 'split-account-a',
          accountKey: 'split-account-a',
          email: 'split-a@example.com',
        },
      }),
    }).returning().get();
    const accountB = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'split-b@example.com',
      accessToken: 'oauth-access-split-b',
      apiToken: null,
      status: 'active',
      oauthProvider: 'codex',
      oauthAccountKey: 'split-account-b',
      extraConfig: JSON.stringify({
        credentialMode: 'session',
        oauth: {
          provider: 'codex',
          accountId: 'split-account-b',
          accountKey: 'split-account-b',
          email: 'split-b@example.com',
        },
      }),
    }).returning().get();

    await db.insert(schema.modelAvailability).values([
      {
        accountId: accountA.id,
        modelName: 'gpt-5.4',
        available: true,
      },
      {
        accountId: accountB.id,
        modelName: 'gpt-5.4',
        available: true,
      },
    ]).run();
    await rebuildRoutesOnly();

    const created = await app.inject({
      method: 'POST',
      url: '/api/oauth/route-units',
      payload: {
        accountIds: [accountA.id, accountB.id],
        name: 'Codex Split Pool',
        strategy: 'stick_until_unavailable',
      },
    });
    const routeUnitId = (created.json() as { routeUnit?: { id?: number } }).routeUnit?.id;
    expect(typeof routeUnitId).toBe('number');

    const deleteResponse = await app.inject({
      method: 'DELETE',
      url: `/api/oauth/route-units/${routeUnitId}`,
    });
    expect(deleteResponse.statusCode).toBe(200);
    expect(deleteResponse.json()).toMatchObject({
      success: true,
    });

    const routeChannels = await db.select().from(schema.routeChannels).all();
    expect(routeChannels).toHaveLength(2);

    const connectionsResponse = await app.inject({
      method: 'GET',
      url: '/api/oauth/connections',
    });
    expect(connectionsResponse.statusCode).toBe(200);
    const items = (connectionsResponse.json() as { items: Array<{ routeParticipation?: { kind?: string } | null }> }).items;
    expect(items.every((item) => item.routeParticipation?.kind !== 'route_unit')).toBe(true);
  });

  it('keeps multiple codex team workspaces with the same email as separate oauth connections', async () => {
    const buildTokenExchange = (accountId: string) => ({
      ok: true,
      status: 200,
      json: async () => ({
        access_token: `oauth-access-token-${accountId}`,
        refresh_token: `oauth-refresh-token-${accountId}`,
        id_token: buildJwt({
          email: 'team-user@example.com',
          'https://api.openai.com/auth': {
            chatgpt_account_id: accountId,
            chatgpt_plan_type: 'team',
          },
        }),
        expires_in: 3600,
        token_type: 'Bearer',
      }),
      text: async () => JSON.stringify({ ok: true }),
    });

    const buildModelDiscovery = (modelId: string) => ({
      ok: true,
      status: 200,
      json: async () => ({
        models: [{ id: modelId }],
      }),
      text: async () => JSON.stringify({ ok: true }),
    });

    fetchMock
      .mockResolvedValueOnce(buildTokenExchange('chatgpt-team-account-a'))
      .mockResolvedValueOnce(buildModelDiscovery('gpt-5.4'))
      .mockResolvedValueOnce(buildTokenExchange('chatgpt-team-account-b'))
      .mockResolvedValueOnce(buildModelDiscovery('gpt-5.4'));

    const startFirstResponse = await app.inject({
      method: 'POST',
      url: '/api/oauth/providers/codex/start',
      headers: {
        host: 'metapi.example',
        'x-forwarded-proto': 'https',
      },
    });
    const firstSession = startFirstResponse.json() as { state: string };

    const submitFirstCallback = await app.inject({
      method: 'POST',
      url: `/api/oauth/sessions/${encodeURIComponent(firstSession.state)}/manual-callback`,
      payload: {
        callbackUrl: `http://localhost:1455/auth/callback?state=${encodeURIComponent(firstSession.state)}&code=oauth-code-team-a`,
      },
    });
    expect(submitFirstCallback.statusCode).toBe(200);

    const startSecondResponse = await app.inject({
      method: 'POST',
      url: '/api/oauth/providers/codex/start',
      headers: {
        host: 'metapi.example',
        'x-forwarded-proto': 'https',
      },
    });
    const secondSession = startSecondResponse.json() as { state: string };

    const submitSecondCallback = await app.inject({
      method: 'POST',
      url: `/api/oauth/sessions/${encodeURIComponent(secondSession.state)}/manual-callback`,
      payload: {
        callbackUrl: `http://localhost:1455/auth/callback?state=${encodeURIComponent(secondSession.state)}&code=oauth-code-team-b`,
      },
    });
    expect(submitSecondCallback.statusCode).toBe(200);

    const accounts = await db.select().from(schema.accounts)
      .where(eq(schema.accounts.oauthProvider, 'codex'))
      .orderBy(schema.accounts.id)
      .all();

    expect(accounts).toHaveLength(2);
    expect(accounts.map((account) => account.oauthAccountKey)).toEqual([
      'chatgpt-team-account-a',
      'chatgpt-team-account-b',
    ]);

    const connectionsResponse = await app.inject({
      method: 'GET',
      url: '/api/oauth/connections',
    });

    expect(connectionsResponse.statusCode).toBe(200);
    expect(connectionsResponse.json()).toMatchObject({
      total: 2,
      items: expect.arrayContaining([
        expect.objectContaining({
          provider: 'codex',
          accountKey: 'chatgpt-team-account-a',
        }),
        expect.objectContaining({
          provider: 'codex',
          accountKey: 'chatgpt-team-account-b',
        }),
      ]),
    });
  });

  it('backfills structured oauth identity columns for legacy oauth rows before listing connections', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'Legacy Codex',
      url: 'https://codex.example.com',
      platform: 'codex',
      status: 'active',
      useSystemProxy: false,
      isPinned: false,
      globalWeight: 1,
      sortOrder: 0,
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'legacy-user@example.com',
      accessToken: 'legacy-oauth-access-token',
      status: 'active',
      extraConfig: JSON.stringify({
        oauth: {
          provider: 'codex',
          accountKey: 'legacy-chatgpt-account',
          projectId: 'legacy-project',
          refreshToken: 'legacy-refresh-token',
          modelDiscoveryStatus: 'healthy',
        },
      }),
      isPinned: false,
      sortOrder: 0,
    }).returning().get();

    expect(account.oauthProvider).toBeNull();
    expect(account.oauthAccountKey).toBeNull();
    expect(account.oauthProjectId).toBeNull();

    const response = await app.inject({
      method: 'GET',
      url: '/api/oauth/connections',
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      total: 1,
      items: [
        expect.objectContaining({
          provider: 'codex',
          accountKey: 'legacy-chatgpt-account',
          projectId: 'legacy-project',
          username: 'legacy-user@example.com',
        }),
      ],
    });

    const backfilled = await db.select().from(schema.accounts)
      .where(eq(schema.accounts.id, account.id))
      .get();

    expect(backfilled).toEqual(expect.objectContaining({
      oauthProvider: 'codex',
      oauthAccountKey: 'legacy-chatgpt-account',
      oauthProjectId: 'legacy-project',
    }));
  });

  it('rejects malformed manual callback submissions', async () => {
    const startResponse = await app.inject({
      method: 'POST',
      url: '/api/oauth/providers/claude/start',
      headers: {
        host: 'metapi.example',
        'x-forwarded-proto': 'https',
      },
    });
    const startBody = startResponse.json() as { state: string };

    const callbackResponse = await app.inject({
      method: 'POST',
      url: `/api/oauth/sessions/${encodeURIComponent(startBody.state)}/manual-callback`,
      payload: {
        callbackUrl: 'not-a-valid-url',
      },
    });

    expect(callbackResponse.statusCode).toBe(400);
    expect(callbackResponse.json()).toMatchObject({
      message: expect.stringContaining('invalid oauth callback url'),
    });
  });
});
