import { FastifyInstance } from 'fastify';
import { config as runtimeConfig } from '../../config.js';

import {
  appendBackgroundTaskLog,
  getBackgroundTask,
  startBackgroundTask,
  subscribeToBackgroundTaskLogs,
} from '../../services/backgroundTaskService.js';
import { type UpdateCenterVersionSource } from '../../services/updateCenterVersionService.js';
import {
  getUpdateCenterDeployBlockMessage,
  normalizeUpdateCenterTargetDigest,
} from '../../services/updateCenterDeployGuardService.js';
import {
  getDefaultUpdateCenterConfig,
  loadUpdateCenterConfig,
  normalizeUpdateCenterConfig,
  saveUpdateCenterConfig,
  type UpdateCenterConfig,
} from '../../services/updateCenterConfigService.js';
import {
  streamUpdateCenterDeploy,
  streamUpdateCenterRollback,
} from '../../services/updateCenterHelperClient.js';
import {
  getUpdateCenterStatus,
  refreshUpdateCenterStatusCache,
} from '../../services/updateCenterStatusService.js';
import {
  UPDATE_CENTER_DEPLOY_DEDUPE_KEY,
  UPDATE_CENTER_DEPLOY_TASK_TYPE,
} from '../../services/updateCenterTaskConstants.js';
import {
  parseUpdateCenterConfigPayload,
  parseUpdateCenterDeployPayload,
  parseUpdateCenterRollbackPayload,
} from '../../contracts/supportRoutePayloads.js';

type DeployBody = {
  source?: UpdateCenterVersionSource;
  targetVersion?: string;
  targetTag?: string;
  targetDigest?: string;
};

type RollbackBody = {
  targetRevision?: string;
};

function getUpdateCenterHelperToken(): string {
  return String(
    runtimeConfig.deployHelperToken
    || process.env.DEPLOY_HELPER_TOKEN
    || process.env.UPDATE_CENTER_HELPER_TOKEN
    || '',
  ).trim();
}

function assertHelperConfig(config: UpdateCenterConfig) {
  if (!config.enabled) throw new Error('update center is disabled');
  if (!config.helperBaseUrl) throw new Error('helperBaseUrl is required');
  if (!config.namespace) throw new Error('namespace is required');
  if (!config.releaseName) throw new Error('releaseName is required');
  if (!getUpdateCenterHelperToken()) throw new Error('DEPLOY_HELPER_TOKEN is required');
}

function assertDeployableConfig(config: UpdateCenterConfig) {
  assertHelperConfig(config);
  if (!config.chartRef) throw new Error('chartRef is required');
  if (!config.imageRepository) throw new Error('imageRepository is required');
}

function summarizeHelperError(error: unknown) {
  if (error instanceof Error && error.message) return error.message;
  return String(error || 'unknown helper error');
}

function writeSseEvent(reply: { raw: NodeJS.WritableStream & { write: (chunk: string) => void } }, event: string, data: unknown) {
  reply.raw.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
}

export async function updateCenterRoutes(app: FastifyInstance) {
  app.get('/api/update-center/status', async () => {
    return await getUpdateCenterStatus();
  });

  app.post('/api/update-center/check', async () => {
    return (await refreshUpdateCenterStatusCache()).status;
  });

  app.put<{ Body: unknown }>('/api/update-center/config', async (request, reply) => {
    const parsedBody = parseUpdateCenterConfigPayload(request.body);
    if (!parsedBody.success) {
      return reply.code(400).send({ success: false, message: parsedBody.error });
    }

    const next = normalizeUpdateCenterConfig(parsedBody.data || getDefaultUpdateCenterConfig());
    const saved = await saveUpdateCenterConfig(next);
    return {
      success: true,
      config: saved,
    };
  });

  app.post<{ Body: unknown }>('/api/update-center/deploy', async (request, reply) => {
    const parsedBody = parseUpdateCenterDeployPayload(request.body);
    if (!parsedBody.success) {
      return reply.code(400).send({
        success: false,
        message: parsedBody.error,
      });
    }

    const body = parsedBody.data;
    const config = await loadUpdateCenterConfig();
    try {
      assertDeployableConfig(config);
    } catch (error) {
      return reply.code(400).send({
        success: false,
        message: summarizeHelperError(error),
      });
    }
    const helperToken = getUpdateCenterHelperToken();

    const source = body.source === 'docker-hub-tag'
      ? 'docker-hub-tag'
      : body.source === 'github-release'
        ? 'github-release'
        : config.defaultDeploySource;
    const targetTag = String(body.targetTag || body.targetVersion || '').trim();
    const targetDigest = normalizeUpdateCenterTargetDigest(body.targetDigest);
    if (!targetTag) {
      return reply.code(400).send({
        success: false,
        message: 'targetTag is required',
      });
    }

    const deployBlockMessage = await getUpdateCenterDeployBlockMessage({
      config,
      helperToken,
      targetTag,
      targetDigest,
    });
    if (deployBlockMessage) {
      return reply.code(409).send({
        success: false,
        message: deployBlockMessage,
      });
    }

    let taskId = '';
    const { task, reused } = startBackgroundTask(
      {
        type: UPDATE_CENTER_DEPLOY_TASK_TYPE,
        title: '更新中心部署',
        dedupeKey: UPDATE_CENTER_DEPLOY_DEDUPE_KEY,
        successTitle: '更新中心部署已完成',
        failureTitle: '更新中心部署失败',
      },
      async () => {
        await Promise.resolve();
        appendBackgroundTaskLog(taskId, `Resolving target image: ${targetTag}${targetDigest ? ` @ ${targetDigest}` : ''}`);
        appendBackgroundTaskLog(taskId, `Contacting deploy helper: ${config.helperBaseUrl}`);

        const result = await streamUpdateCenterDeploy(
          {
            config,
            helperToken,
            source,
            targetTag,
            targetDigest,
          },
          (message) => {
            appendBackgroundTaskLog(taskId, message);
          },
        );

        if (!result.success) {
          throw new Error('deploy helper reported a failed deployment');
        }
        appendBackgroundTaskLog(taskId, result.rolledBack ? 'Deployment rolled back' : 'Deployment finished successfully');
        return result;
      },
    );
    taskId = task.id;

    return reply.code(202).send({
      success: true,
      reused,
      task,
    });
  });

  app.post<{ Body: unknown }>('/api/update-center/rollback', async (request, reply) => {
    const parsedBody = parseUpdateCenterRollbackPayload(request.body);
    if (!parsedBody.success) {
      return reply.code(400).send({
        success: false,
        message: parsedBody.error,
      });
    }

    const body = parsedBody.data;
    const config = await loadUpdateCenterConfig();
    try {
      assertHelperConfig(config);
    } catch (error) {
      return reply.code(400).send({
        success: false,
        message: summarizeHelperError(error),
      });
    }

    const targetRevision = String(body.targetRevision || '').trim();
    if (!targetRevision) {
      return reply.code(400).send({
        success: false,
        message: 'targetRevision is required',
      });
    }

    let taskId = '';
    const { task, reused } = startBackgroundTask(
      {
        type: UPDATE_CENTER_DEPLOY_TASK_TYPE,
        title: '更新中心回退',
        dedupeKey: UPDATE_CENTER_DEPLOY_DEDUPE_KEY,
        successTitle: '更新中心回退已完成',
        failureTitle: '更新中心回退失败',
      },
      async () => {
        await Promise.resolve();
        appendBackgroundTaskLog(taskId, `Resolving rollback revision: ${targetRevision}`);
        appendBackgroundTaskLog(taskId, `Contacting deploy helper: ${config.helperBaseUrl}`);

        const result = await streamUpdateCenterRollback(
          {
            config,
            helperToken: getUpdateCenterHelperToken(),
            targetRevision,
          },
          (message) => {
            appendBackgroundTaskLog(taskId, message);
          },
        );

        if (!result.success) {
          throw new Error('deploy helper reported a failed rollback');
        }
        appendBackgroundTaskLog(taskId, 'Rollback finished successfully');
        return result;
      },
    );
    taskId = task.id;

    return reply.code(202).send({
      success: true,
      reused,
      task,
    });
  });

  app.get<{ Params: { id: string } }>('/api/update-center/tasks/:id/stream', async (request, reply) => {
    const taskId = String(request.params.id || '').trim();
    const task = getBackgroundTask(taskId);
    if (!task) {
      return reply.code(404).send({
        success: false,
        message: 'task not found',
      });
    }

    reply.hijack();
    reply.raw.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
    reply.raw.setHeader('Cache-Control', 'no-cache, no-transform');
    reply.raw.setHeader('Connection', 'keep-alive');

    const writeDone = () => {
      const latest = getBackgroundTask(taskId);
      writeSseEvent(reply, 'done', {
        status: latest?.status || 'unknown',
      });
      reply.raw.end();
    };

    for (const entry of task.logs) {
      writeSseEvent(reply, 'log', entry);
    }

    if (task.status !== 'pending' && task.status !== 'running') {
      writeDone();
      return;
    }

    const unsubscribe = subscribeToBackgroundTaskLogs(taskId, (entry) => {
      writeSseEvent(reply, 'log', entry);
    });

    const interval = setInterval(() => {
      const latest = getBackgroundTask(taskId);
      if (!latest) {
        clearInterval(interval);
        unsubscribe();
        writeDone();
        return;
      }
      if (latest.status !== 'pending' && latest.status !== 'running') {
        clearInterval(interval);
        unsubscribe();
        writeDone();
      }
    }, 25);
    interval.unref?.();

    request.raw.on('close', () => {
      clearInterval(interval);
      unsubscribe();
    });
  });
}
