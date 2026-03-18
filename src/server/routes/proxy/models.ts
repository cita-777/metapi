import { FastifyInstance } from 'fastify';
import { listModelsSurface } from '../../proxy-core/surfaces/modelsSurface.js';
import { refreshModelsAndRebuildRoutes } from '../../services/modelService.js';
import { getDownstreamRoutingPolicy } from './downstreamPolicy.js';
import { tokenRouter } from '../../services/tokenRouter.js';
import { isModelAllowedByPolicyOrAllowedRoutes } from '../../services/downstreamApiKeyService.js';

export async function modelsProxyRoute(app: FastifyInstance) {
  app.get('/v1/models', async (request) => {
    const downstreamPolicy = getDownstreamRoutingPolicy(request);
    const wantsClaudeFormat = typeof request.headers['anthropic-version'] === 'string'
      || typeof request.headers['x-api-key'] === 'string';
    return listModelsSurface({
      downstreamPolicy,
      responseFormat: wantsClaudeFormat ? 'claude' : 'openai',
      tokenRouter,
      refreshModelsAndRebuildRoutes,
      isModelAllowed: isModelAllowedByPolicyOrAllowedRoutes,
    });
  });
}
