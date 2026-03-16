import type { FastifyInstance, FastifyRequest } from 'fastify';
import {
  deleteOauthConnection,
  getOauthSessionStatus,
  handleOauthCallback,
  listOauthConnections,
  listOauthProviders,
  startOauthProviderFlow,
  startOauthRebindFlow,
} from '../../services/oauth/service.js';

function resolveRequestOrigin(request: FastifyRequest): string {
  const forwardedProto = typeof request.headers['x-forwarded-proto'] === 'string'
    ? request.headers['x-forwarded-proto'].split(',')[0]?.trim()
    : '';
  const protocol = forwardedProto || request.protocol || 'http';
  const forwardedHost = typeof request.headers['x-forwarded-host'] === 'string'
    ? request.headers['x-forwarded-host'].split(',')[0]?.trim()
    : '';
  const host = forwardedHost
    || (typeof request.headers.host === 'string' ? request.headers.host.trim() : '')
    || 'localhost';
  return `${protocol}://${host}`;
}

export async function oauthRoutes(app: FastifyInstance) {
  app.get('/api/oauth/providers', async () => ({
    providers: listOauthProviders(),
  }));

  app.post<{ Params: { provider: string }; Body: { accountId?: number } }>(
    '/api/oauth/providers/:provider/start',
    async (request, reply) => {
      try {
        return startOauthProviderFlow({
          provider: request.params.provider,
          redirectOrigin: resolveRequestOrigin(request),
          rebindAccountId: request.body?.accountId,
        });
      } catch (error: any) {
        return reply.code(404).send({ message: error?.message || 'oauth provider not found' });
      }
    },
  );

  app.get<{ Params: { state: string } }>('/api/oauth/sessions/:state', async (request, reply) => {
    const session = getOauthSessionStatus(request.params.state);
    if (!session) {
      return reply.code(404).send({ message: 'oauth session not found' });
    }
    return session;
  });

  app.get('/api/oauth/connections', async () => ({
    items: await listOauthConnections(),
  }));

  app.post<{ Params: { accountId: string } }>(
    '/api/oauth/connections/:accountId/rebind',
    async (request, reply) => {
      try {
        const accountId = Number.parseInt(request.params.accountId, 10);
        return await startOauthRebindFlow(accountId, resolveRequestOrigin(request));
      } catch (error: any) {
        return reply.code(404).send({ message: error?.message || 'oauth account not found' });
      }
    },
  );

  app.delete<{ Params: { accountId: string } }>(
    '/api/oauth/connections/:accountId',
    async (request, reply) => {
      try {
        const accountId = Number.parseInt(request.params.accountId, 10);
        return await deleteOauthConnection(accountId);
      } catch (error: any) {
        return reply.code(404).send({ message: error?.message || 'oauth account not found' });
      }
    },
  );

  app.get<{ Params: { provider: string }; Querystring: { state?: string; code?: string; error?: string } }>(
    '/api/oauth/callback/:provider',
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
      } catch (error: any) {
        message = `OAuth authorization failed: ${error?.message || 'unknown error'}`;
      }

    reply.type('text/html; charset=utf-8');
    return `<!doctype html>
<html lang="zh-CN">
  <head>
    <meta charset="utf-8" />
    <title>OAuth Callback</title>
  </head>
  <body>
    <script>window.close();</script>
    ${message}
  </body>
</html>`;
  });
}
