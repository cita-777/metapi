import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { ensureModelAllowedForDownstreamKey } from './downstreamPolicy.js';

/** Rerank 路由只负责输入校验和权限适配，实际代理编排由 proxy-core surface 负责。 */
export async function rerankProxyRoute(app: FastifyInstance) {
  app.post('/v1/rerank', async (request: FastifyRequest, reply: FastifyReply) => {
    const body = (request.body || {}) as Record<string, unknown>;
    const requestedModel = typeof body.model === 'string' ? body.model.trim() : '';
    if (!requestedModel) {
      return reply.code(400).send({
        error: { message: 'model is required', type: 'invalid_request_error' },
      });
    }
    if (!await ensureModelAllowedForDownstreamKey(request, reply, requestedModel)) return;

    // 通过校验后才加载完整代理编排，避免无效请求触发数据库和运行时执行器初始化。
    const { handleRerankSurfaceRequest } = await import('../../proxy-core/surfaces/rerankSurface.js');
    return handleRerankSurfaceRequest(request, reply, requestedModel);
  });
}
