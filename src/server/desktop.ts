import type { FastifyInstance } from 'fastify';
import { normalizeRequestPath } from './middleware/apiPath.js';

const DESKTOP_HEALTH_ROUTE = '/api/desktop/health';

export function isPublicApiRoute(url: string): boolean {
  const path = normalizeRequestPath(url);
  return path === DESKTOP_HEALTH_ROUTE || path.startsWith('/api/oauth/callback/');
}

export async function registerDesktopRoutes(app: FastifyInstance) {
  app.get(DESKTOP_HEALTH_ROUTE, async () => ({ ok: true }));
}
