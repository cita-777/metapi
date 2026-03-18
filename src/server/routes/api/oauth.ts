import type { FastifyInstance, FastifyRequest } from 'fastify';
import { createRateLimitGuard } from '../../middleware/requestRateLimit.js';
import {
  deleteOauthConnection,
  getOauthSessionStatus,
  handleOauthCallback,
  listOauthConnections,
  listOauthProviders,
  refreshOauthConnectionQuota,
  startOauthProviderFlow,
  startOauthRebindFlow,
  submitOauthManualCallback,
} from '../../services/oauth/service.js';

const limitOauthProviderRead = createRateLimitGuard({
  bucket: 'oauth-provider-read',
  max: 60,
  windowMs: 60_000,
});

const limitOauthStart = createRateLimitGuard({
  bucket: 'oauth-start',
  max: 20,
  windowMs: 60_000,
});

const limitOauthSessionRead = createRateLimitGuard({
  bucket: 'oauth-session-read',
  max: 120,
  windowMs: 60_000,
});

const limitOauthSessionMutate = createRateLimitGuard({
  bucket: 'oauth-session-mutate',
  max: 30,
  windowMs: 60_000,
});

const limitOauthConnectionRead = createRateLimitGuard({
  bucket: 'oauth-connection-read',
  max: 60,
  windowMs: 60_000,
});

const limitOauthConnectionMutate = createRateLimitGuard({
  bucket: 'oauth-connection-mutate',
  max: 20,
  windowMs: 60_000,
});

const limitOauthCallback = createRateLimitGuard({
  bucket: 'oauth-callback',
  max: 30,
  windowMs: 60_000,
});

function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function renderCallbackPage(message: string): string {
  return `<!doctype html>
<html lang="zh-CN">
  <head>
    <meta charset="utf-8" />
    <title>OAuth Callback</title>
  </head>
  <body>
    <script>window.close();</script>
    ${escapeHtml(message)}
  </body>
</html>`;
}

function parsePositiveInteger(value: unknown): number | null {
  if (typeof value === 'number' && Number.isInteger(value) && value > 0) return value;
  if (typeof value !== 'string') return null;
  const parsed = Number.parseInt(value.trim(), 10);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : null;
}

function parseOptionalProjectId(value: unknown): string | undefined | null {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed || undefined;
}

function resolveRequestOrigin(request: FastifyRequest): string | undefined {
  const forwardedProto = typeof request.headers['x-forwarded-proto'] === 'string'
    ? request.headers['x-forwarded-proto'].split(',')[0]?.trim()
    : '';
  const protocol = forwardedProto || request.protocol || 'http';
  const forwardedHost = typeof request.headers['x-forwarded-host'] === 'string'
    ? request.headers['x-forwarded-host'].split(',')[0]?.trim()
    : '';
  const host = forwardedHost
    || (typeof request.headers.host === 'string' ? request.headers.host.trim() : '');
  if (!host) return undefined;
  return `${protocol}://${host}`;
}

export async function oauthRoutes(app: FastifyInstance) {
  app.get('/api/oauth/providers', { preHandler: [limitOauthProviderRead] }, async () => ({
    providers: listOauthProviders(),
  }));

  app.post<{ Params: { provider: string }; Body: { accountId?: number; projectId?: string } }>(
    '/api/oauth/providers/:provider/start',
    { preHandler: [limitOauthStart] },
    async (request, reply) => {
      const rebindAccountId = request.body?.accountId === undefined
        ? undefined
        : parsePositiveInteger(request.body.accountId);
      if (request.body?.accountId !== undefined && rebindAccountId === null) {
        return reply.code(400).send({ message: 'invalid account id' });
      }
      const projectId = parseOptionalProjectId(request.body?.projectId);
      if (request.body?.projectId !== undefined && projectId === null) {
        return reply.code(400).send({ message: 'invalid project id' });
      }

      try {
        return await startOauthProviderFlow({
          provider: request.params.provider,
          rebindAccountId: rebindAccountId ?? undefined,
          projectId: projectId ?? undefined,
          requestOrigin: resolveRequestOrigin(request),
        });
      } catch (error: any) {
        return reply.code(404).send({ message: error?.message || 'oauth provider not found' });
      }
    },
  );

  app.get<{ Params: { state: string } }>(
    '/api/oauth/sessions/:state',
    { preHandler: [limitOauthSessionRead] },
    async (request, reply) => {
      const session = getOauthSessionStatus(request.params.state);
      if (!session) {
        return reply.code(404).send({ message: 'oauth session not found' });
      }
      return session;
    },
  );

  app.post<{ Params: { state: string }; Body: { callbackUrl?: string } }>(
    '/api/oauth/sessions/:state/manual-callback',
    { preHandler: [limitOauthSessionMutate] },
    async (request, reply) => {
      const callbackUrl = typeof request.body?.callbackUrl === 'string'
        ? request.body.callbackUrl.trim()
        : '';
      if (!callbackUrl) {
        return reply.code(400).send({ message: 'invalid oauth callback url' });
      }
      try {
        return await submitOauthManualCallback({
          state: request.params.state,
          callbackUrl,
        });
      } catch (error: any) {
        const message = error?.message || 'oauth callback submission failed';
        if (message === 'invalid oauth callback url' || message === 'oauth callback state mismatch') {
          return reply.code(400).send({ message });
        }
        if (message === 'oauth session not found') {
          return reply.code(404).send({ message });
        }
        return reply.code(500).send({ message });
      }
    },
  );

  app.get<{ Querystring: { limit?: string; offset?: string } }>(
    '/api/oauth/connections',
    { preHandler: [limitOauthConnectionRead] },
    async (request, reply) => {
      const limit = request.query.limit === undefined ? undefined : parsePositiveInteger(request.query.limit);
      const offset = request.query.offset === undefined
        ? undefined
        : (() => {
          if (typeof request.query.offset !== 'string') return null;
          const parsed = Number.parseInt(request.query.offset.trim(), 10);
          return Number.isInteger(parsed) && parsed >= 0 ? parsed : null;
        })();
      if (request.query.limit !== undefined && limit === null) {
        return reply.code(400).send({ message: 'invalid limit' });
      }
      if (request.query.offset !== undefined && offset === null) {
        return reply.code(400).send({ message: 'invalid offset' });
      }
      return listOauthConnections({
        limit: limit ?? undefined,
        offset: offset ?? undefined,
      });
    },
  );

  app.post<{ Params: { accountId: string } }>(
    '/api/oauth/connections/:accountId/rebind',
    { preHandler: [limitOauthConnectionMutate] },
    async (request, reply) => {
      const accountId = parsePositiveInteger(request.params.accountId);
      if (accountId === null) {
        return reply.code(400).send({ message: 'invalid account id' });
      }
      try {
        return await startOauthRebindFlow(accountId, resolveRequestOrigin(request));
      } catch (error: any) {
        return reply.code(404).send({ message: error?.message || 'oauth account not found' });
      }
    },
  );

  app.delete<{ Params: { accountId: string } }>(
    '/api/oauth/connections/:accountId',
    { preHandler: [limitOauthConnectionMutate] },
    async (request, reply) => {
      const accountId = parsePositiveInteger(request.params.accountId);
      if (accountId === null) {
        return reply.code(400).send({ message: 'invalid account id' });
      }
      try {
        return await deleteOauthConnection(accountId);
      } catch (error: any) {
        return reply.code(404).send({ message: error?.message || 'oauth account not found' });
      }
    },
  );

  app.post<{ Params: { accountId: string } }>(
    '/api/oauth/connections/:accountId/quota/refresh',
    { preHandler: [limitOauthConnectionMutate] },
    async (request, reply) => {
      const accountId = parsePositiveInteger(request.params.accountId);
      if (accountId === null) {
        return reply.code(400).send({ message: 'invalid account id' });
      }
      try {
        return await refreshOauthConnectionQuota(accountId);
      } catch (error: any) {
        return reply.code(404).send({ message: error?.message || 'oauth account not found' });
      }
    },
  );

  app.get<{ Params: { provider: string }; Querystring: { state?: string; code?: string; error?: string } }>(
    '/api/oauth/callback/:provider',
    { preHandler: [limitOauthCallback] },
    async (request, reply) => {
      let message = 'OAuth callback received.';
      try {
        await handleOauthCallback({
          provider: request.params.provider,
          state: String(request.query.state || ''),
          code: request.query.code,
          error: request.query.error,
        });
        message = 'OAuth authorization succeeded. You can close this window.';
      } catch {
        message = 'OAuth authorization failed. Return to metapi and review the server logs.';
      }

      reply.type('text/html; charset=utf-8');
      return renderCallbackPage(message);
    },
  );
}
