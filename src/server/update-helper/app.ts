import Fastify, { type FastifyInstance } from 'fastify';

import {
  executeUpdateHelperDeploy,
  executeUpdateHelperRollback,
  getUpdateHelperStatus,
  type UpdateHelperDeployInput,
  type UpdateHelperDeploySummary,
  type UpdateHelperRollbackInput,
  type UpdateHelperRollbackSummary,
  type UpdateHelperStatus,
} from './service.js';

type BuildUpdateHelperAppOptions = {
  token: string;
  getStatus?: (input: { namespace: string; releaseName: string }) => Promise<UpdateHelperStatus>;
  deploy?: (
    input: UpdateHelperDeployInput,
    onLog?: (message: string) => void,
  ) => Promise<UpdateHelperDeploySummary>;
  rollback?: (
    input: UpdateHelperRollbackInput,
    onLog?: (message: string) => void,
  ) => Promise<UpdateHelperRollbackSummary>;
};

function requireBearerToken(requestAuthHeader: string | undefined, expectedToken: string) {
  const raw = String(requestAuthHeader || '').trim();
  if (!raw.startsWith('Bearer ')) return false;
  return raw.slice('Bearer '.length).trim() === expectedToken;
}

function writeSseEvent(reply: { raw: NodeJS.WritableStream & { write: (chunk: string) => void } }, event: string, data: unknown) {
  reply.raw.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
}

function toDeployInput(body: Record<string, unknown>): UpdateHelperDeployInput {
  return {
    namespace: String(body.namespace || '').trim(),
    releaseName: String(body.releaseName || '').trim(),
    chartRef: String(body.chartRef || '').trim(),
    imageRepository: String(body.imageRepository || '').trim(),
    targetSource: body.source === 'docker-hub-tag' ? 'docker-hub-tag' : 'github-release',
    targetTag: String(body.targetTag || body.targetVersion || '').trim(),
    targetDigest: String(body.targetDigest || '').trim() || null,
  };
}

function toRollbackInput(body: Record<string, unknown>): UpdateHelperRollbackInput {
  return {
    namespace: String(body.namespace || '').trim(),
    releaseName: String(body.releaseName || '').trim(),
    targetRevision: String(body.targetRevision || '').trim(),
  };
}

export async function buildUpdateHelperApp(options: BuildUpdateHelperAppOptions): Promise<FastifyInstance> {
  const app = Fastify();
  const getStatus = options.getStatus || (async (input) => await getUpdateHelperStatus(input));
  const deploy = options.deploy || (async (input, onLog) => await executeUpdateHelperDeploy(input, undefined, onLog));
  const rollback = options.rollback || (async (input, onLog) => await executeUpdateHelperRollback(input, undefined, onLog));

  app.addHook('onRequest', async (request, reply) => {
    const path = String(request.raw.url || '').split('?')[0];
    if (path === '/health') {
      return;
    }
    if (!requireBearerToken(String(request.headers.authorization || ''), options.token)) {
      return reply.code(401).send({
        success: false,
        message: 'unauthorized',
      });
    }
  });

  app.get('/health', async () => ({ ok: true }));

  app.get<{ Querystring: { namespace?: string; releaseName?: string } }>('/status', async (request, reply) => {
    const namespace = String(request.query.namespace || '').trim();
    const releaseName = String(request.query.releaseName || '').trim();
    if (!namespace || !releaseName) {
      return reply.code(400).send({
        success: false,
        message: 'namespace and releaseName are required',
      });
    }
    return await getStatus({ namespace, releaseName });
  });

  app.post<{ Body: Record<string, unknown> }>('/deploy', async (request, reply) => {
    const input = toDeployInput(request.body || {});
    if (!input.namespace || !input.releaseName || !input.chartRef || !input.imageRepository || !input.targetTag) {
      return reply.code(400).send({
        success: false,
        message: 'namespace, releaseName, chartRef, imageRepository, and targetTag are required',
      });
    }

    const wantsSse = String(request.headers.accept || '').includes('text/event-stream');
    if (!wantsSse) {
      return await deploy(input);
    }

    reply.hijack();
    reply.raw.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
    reply.raw.setHeader('Cache-Control', 'no-cache, no-transform');
    reply.raw.setHeader('Connection', 'keep-alive');

    const result = await deploy(input, (message) => {
      writeSseEvent(reply, 'log', { message });
    });
    writeSseEvent(reply, 'result', result);
    reply.raw.end();
  });

  app.post<{ Body: Record<string, unknown> }>('/rollback', async (request, reply) => {
    const input = toRollbackInput(request.body || {});
    if (!input.namespace || !input.releaseName || !input.targetRevision) {
      return reply.code(400).send({
        success: false,
        message: 'namespace, releaseName, and targetRevision are required',
      });
    }

    const wantsSse = String(request.headers.accept || '').includes('text/event-stream');
    if (!wantsSse) {
      return await rollback(input);
    }

    reply.hijack();
    reply.raw.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
    reply.raw.setHeader('Cache-Control', 'no-cache, no-transform');
    reply.raw.setHeader('Connection', 'keep-alive');

    const result = await rollback(input, (message) => {
      writeSseEvent(reply, 'log', { message });
    });
    writeSseEvent(reply, 'result', result);
    reply.raw.end();
  });

  return app;
}
