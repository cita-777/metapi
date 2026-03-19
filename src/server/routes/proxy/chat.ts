import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import {
  handleChatSurfaceRequest,
  handleClaudeCountTokensSurfaceRequest,
} from '../../proxy-core/surfaces/chatSurface.js';

export async function chatProxyRoute(app: FastifyInstance) {
  app.post('/v1/chat/completions', async (request: FastifyRequest, reply: FastifyReply) =>
    handleChatSurfaceRequest(request, reply, 'openai'));
}

export async function claudeMessagesProxyRoute(app: FastifyInstance) {
  app.post('/v1/messages', async (request: FastifyRequest, reply: FastifyReply) =>
    handleChatSurfaceRequest(request, reply, 'claude'));
  app.post('/v1/messages/count_tokens', async (request: FastifyRequest, reply: FastifyReply) =>
    handleClaudeCountTokensSurfaceRequest(request, reply));
}
