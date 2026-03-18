import Fastify, { type FastifyInstance } from 'fastify';
import { eq } from 'drizzle-orm';
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

  it('lists multi-provider oauth metadata', async () => {
    const response = await app.inject({
      method: 'GET',
      url: '/api/oauth/providers',
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
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
      provider: 'antigravity',
      email: 'antigravity-user@example.com',
      projectId: 'antigravity-auto-project',
      refreshToken: 'antigravity-refresh-token',
    });

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
      provider: 'gemini-cli',
      email: 'gemini-user@example.com',
      projectId: 'first-project-id',
      refreshToken: 'gemini-refresh-token',
    });

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
      projectId: 'gen-lang-client-0123456789',
    });

    expect(String(fetchMock.mock.calls[2]?.[0] || '')).toContain('/v1internal:loadCodeAssist');
    expect(String(fetchMock.mock.calls[3]?.[0] || '')).toContain('/v1internal:onboardUser');
    expect(String(fetchMock.mock.calls[4]?.[0] || '')).toContain('/projects/gen-lang-client-0123456789/services/cloudaicompanion.googleapis.com');
    expect(String(fetchMock.mock.calls[5]?.[0] || '')).toContain('/projects/gen-lang-client-0123456789/services/cloudaicompanion.googleapis.com:enable');
    expect(String(fetchMock.mock.calls[7]?.[0] || '')).toContain('/projects/gen-lang-client-0123456789/services/cloudaicompanion.googleapis.com');
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

    const codexRefresh = await app.inject({
      method: 'POST',
      url: `/api/oauth/connections/${codexAccount.id}/quota/refresh`,
    });
    expect(codexRefresh.statusCode).toBe(200);
    expect(codexRefresh.json()).toMatchObject({
      success: true,
      quota: expect.objectContaining({
        status: 'supported',
        subscription: expect.objectContaining({
          planType: 'plus',
          activeStart: '2026-03-01T00:00:00.000Z',
          activeUntil: '2026-04-01T00:00:00.000Z',
        }),
      }),
    });

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
          email: 'team-user@example.com',
          accountKey: 'chatgpt-team-account-a',
        }),
        expect.objectContaining({
          provider: 'codex',
          email: 'team-user@example.com',
          accountKey: 'chatgpt-team-account-b',
        }),
      ]),
    });
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
