import Fastify from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';
import { oauthRoutes } from './oauth.js';
import { isPublicApiRoute } from '../../desktop.js';

describe('oauth route registration', () => {
  const apps: Array<Awaited<ReturnType<typeof Fastify>>> = [];

  afterEach(async () => {
    await Promise.all(apps.splice(0).map((app) => app.close()));
  });

  it('registers oauth routes on a Fastify instance at runtime', async () => {
    const app = Fastify();
    apps.push(app);
    await app.register(oauthRoutes);

    const routes = app.printRoutes();
    expect(routes).toContain('providers (GET, HEAD)');
    expect(routes).toContain(':provider');
    expect(routes).toContain('sessions/');
    expect(routes).toContain(':state (GET, HEAD)');
    expect(routes).toContain('onnections (GET, HEAD)');
    expect(routes).toContain('allback/');
  });

  it('treats oauth callback route as a public desktop API route', () => {
    expect(isPublicApiRoute('/api/oauth/callback/codex')).toBe(true);
    expect(isPublicApiRoute('/api/oauth/callback/claude')).toBe(true);
    expect(isPublicApiRoute('/api/oauth/providers')).toBe(false);
  });
});
