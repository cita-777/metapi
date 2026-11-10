import Fastify, { type FastifyInstance } from 'fastify';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildConfig, buildFastifyOptions } from '../config.js';
import { isPublicApiRoute, registerDesktopRoutes } from '../desktop.js';
import { createAdminAuthHook, isOriginFormTarget, normalizeRequestPath } from './apiPath.js';

const TEST_TOKEN = 'unit-test-admin-token';
const ADMIN_ROUTES = ['/api/sites', '/api/settings/runtime', '/api/accounts/1'];

// Percent-encoding variants of a route, used to check that auth is decided on the
// normalized path rather than on the raw request target.
function percentEncodedForms(path: string): string[] {
  const encodeChar = (ch: string) => `%${ch.charCodeAt(0).toString(16).toUpperCase().padStart(2, '0')}`;
  const forms = new Set<string>();
  for (let i = 1; i < path.length; i += 1) {
    if (path[i] === '/') continue;
    forms.add(path.slice(0, i) + encodeChar(path[i]) + path.slice(i + 1));
  }
  forms.add(path.split('').map((ch, i) => (i === 0 || ch === '/' ? ch : encodeChar(ch))).join(''));
  return [...forms];
}

describe('admin API auth guard', () => {
  let app: FastifyInstance;
  let handlerHits = 0;

  beforeAll(async () => {
    app = Fastify({ ...buildFastifyOptions(buildConfig({})), logger: false });
    app.addHook('onRequest', createAdminAuthHook(async (request, reply) => {
      if (request.headers.authorization !== `Bearer ${TEST_TOKEN}`) {
        reply.code(401).send({ error: 'Missing Authorization header' });
      }
    }, isPublicApiRoute));
    await app.register(registerDesktopRoutes);
    for (const route of ['/api/sites', '/api/settings/runtime', '/api/accounts/:id']) {
      app.get(route, async () => {
        handlerHits += 1;
        return { ok: true };
      });
    }
    app.get('/api/oauth/callback/:provider', async () => ({ callback: true }));
    app.get('/public-page', async () => ({ page: true }));
    await app.ready();
  });

  afterAll(async () => {
    await app.close();
  });

  it('requires auth on canonical admin routes and accepts the token', async () => {
    for (const url of ADMIN_ROUTES) {
      expect((await app.inject({ method: 'GET', url })).statusCode).toBe(401);
      const ok = await app.inject({ method: 'GET', url, headers: { authorization: `Bearer ${TEST_TOKEN}` } });
      expect(ok.statusCode).toBe(200);
    }
  });

  it('never reaches an admin handler without auth for equivalent request targets', async () => {
    handlerHits = 0;
    for (const route of ADMIN_ROUTES) {
      for (const url of [...percentEncodedForms(route), `${route}?x=1`, `${route}/`]) {
        const response = await app.inject({ method: 'GET', url });
        expect([400, 401, 404], `unexpected ${response.statusCode} for ${url}`).toContain(response.statusCode);
      }
    }
    expect(handlerHits).toBe(0);
  });

  it('still serves equivalent request targets to authenticated callers', async () => {
    let resolved = 0;
    for (const url of percentEncodedForms('/api/sites')) {
      const response = await app.inject({ method: 'GET', url, headers: { authorization: `Bearer ${TEST_TOKEN}` } });
      if (response.statusCode === 200) resolved += 1;
    }
    expect(resolved).toBeGreaterThan(0);
  });

  it('only accepts origin-form request targets', () => {
    expect(isOriginFormTarget('/api/sites')).toBe(true);
    expect(isOriginFormTarget('*')).toBe(true);
    expect(isOriginFormTarget('http://localhost/api/sites')).toBe(false);
    expect(isOriginFormTarget('')).toBe(false);
  });

  it('keeps explicitly public API routes and non-API routes open', async () => {
    expect((await app.inject({ method: 'GET', url: '/api/desktop/health' })).statusCode).toBe(200);
    expect((await app.inject({ method: 'GET', url: '/api/oauth/callback/codex' })).statusCode).toBe(200);
    expect((await app.inject({ method: 'GET', url: '/public-page' })).statusCode).toBe(200);
  });

  it('does not treat a protected route as public because of its path shape', () => {
    expect(isPublicApiRoute('/api/oauth/callback/../../sites')).toBe(false);
    expect(isPublicApiRoute('/api/desktop/health')).toBe(true);
  });

  it('normalizes request paths the way the router resolves them', () => {
    expect(normalizeRequestPath('/api/sites?x=1')).toBe('/api/sites');
    expect(normalizeRequestPath('/API//sites/')).toBe('/api/sites/');
  });
});
