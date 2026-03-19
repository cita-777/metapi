import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { handleOpenAiResponsesSurfaceRequest } from '../../proxy-core/surfaces/openAiResponsesSurface.js';
import { ensureResponsesWebsocketTransport } from './responsesWebsocket.js';

export async function responsesProxyRoute(app: FastifyInstance) {
  ensureResponsesWebsocketTransport(app);

  app.post('/v1/responses', async (request: FastifyRequest, reply: FastifyReply) =>
    handleOpenAiResponsesSurfaceRequest(request, reply, '/v1/responses'));
  app.get('/v1/responses', async (_request: FastifyRequest, reply: FastifyReply) =>
    reply.code(426).send({
      error: {
        message: 'WebSocket upgrade required for GET /v1/responses',
        type: 'invalid_request_error',
      },
    }));
  app.post('/v1/responses/compact', async (request: FastifyRequest, reply: FastifyReply) =>
    handleOpenAiResponsesSurfaceRequest(request, reply, '/v1/responses/compact'));
}
