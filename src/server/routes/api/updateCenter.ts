import type { FastifyInstance } from 'fastify';

import {
  appendBackgroundTaskLog,
  getBackgroundTask,
  startBackgroundTask,
  subscribeToBackgroundTaskLogs,
} from '../../services/backgroundTaskService.js';
import {
  loadUpdateCenterConfig,
  normalizeUpdateCenterConfig,
  saveUpdateCenterConfig,
} from '../../services/updateCenterConfigService.js';
import {
  installUpdateCenterRelease,
  rollbackUpdateCenter,
  getUpdateCenterLocalStatus,
} from '../../services/updateCenterLocalUpdateService.js';
import {
  getUpdateCenterStatus,
  refreshUpdateCenterStatusCache,
} from '../../services/updateCenterStatusService.js';
import {
  UPDATE_CENTER_ROLLBACK_DEDUPE_KEY,
  UPDATE_CENTER_ROLLBACK_TASK_TYPE,
  UPDATE_CENTER_UPDATE_DEDUPE_KEY,
  UPDATE_CENTER_UPDATE_TASK_TYPE,
} from '../../services/updateCenterTaskConstants.js';
import { getCurrentRuntimeVersion, parseStableSemVer } from '../../services/updateCenterVersionService.js';
import {
  parseUpdateCenterCheckPayload,
  parseUpdateCenterConfigPayload,
  parseUpdateCenterDeployPayload,
  parseUpdateCenterRollbackPayload,
} from '../../contracts/supportRoutePayloads.js';

type RestartHandler = () => void;

function defaultRestartHandler(): void {
  const disabled = String(process.env.UPDATE_CENTER_DISABLE_RESTART || '').trim().toLowerCase();
  const isTest = process.env.NODE_ENV === 'test'
    || !!process.env.VITEST
    || !!process.env.VITEST_POOL_ID
    || !!process.env.VITEST_WORKER_ID;
  if (isTest || disabled === '1' || disabled === 'true' || disabled === 'yes') return;
  setTimeout(() => {
    try {
      process.kill(process.pid, 'SIGTERM');
    } catch {
      process.exitCode = 0;
    }
  }, 50).unref?.();
}

let restartHandler: RestartHandler = defaultRestartHandler;

export function setUpdateCenterRestartHandlerForTests(handler: RestartHandler | null): void {
  restartHandler = handler || defaultRestartHandler;
}

function summarizeError(error: unknown): string {
  if (error instanceof Error && error.message) return error.message;
  return String(error || 'update failed');
}

function normalizeTargetVersion(value: unknown): string | null {
  return parseStableSemVer(typeof value === 'string' ? value.trim() : '')?.normalized || null;
}

type SseRawResponse = NodeJS.WritableStream & {
  writableEnded?: boolean;
  destroyed?: boolean;
  closed?: boolean;
};

function isSseResponseClosed(raw: SseRawResponse): boolean {
  return raw.writableEnded === true || raw.destroyed === true || raw.closed === true;
}

export function writeSseEvent(
  reply: { raw: SseRawResponse },
  event: string,
  data: unknown,
): boolean {
  if (isSseResponseClosed(reply.raw)) return false;
  try {
    reply.raw.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
    return true;
  } catch {
    return false;
  }
}

function endSseResponse(raw: SseRawResponse): void {
  if (isSseResponseClosed(raw)) return;
  try {
    raw.end();
  } catch {}
}

function isTerminalTask(status: string): boolean {
  return status !== 'pending' && status !== 'running';
}

function shouldRestartAfterUpdate(): boolean {
  const value = String(process.env.UPDATE_CENTER_DISABLE_RESTART || '').trim().toLowerCase();
  return !['1', 'true', 'yes', 'on'].includes(value);
}

function requestRestart(taskId: string): void {
  try {
    restartHandler();
  } catch (error) {
    appendBackgroundTaskLog(taskId, `重启请求未发送：${summarizeError(error)}`);
  }
}

export async function updateCenterRoutes(app: FastifyInstance): Promise<void> {
  // Keep this probe outside the authenticated /api namespace so the stable
  // container runner can verify a candidate before declaring it healthy.
  app.get('/healthz', async () => ({
    status: 'ok',
    ready: true,
    version: getCurrentRuntimeVersion(),
  }));

  app.get('/api/update-center/status', async () => await getUpdateCenterStatus());

  app.post<{ Body: unknown }>('/api/update-center/check', async (request, reply) => {
    const parsed = parseUpdateCenterCheckPayload(request.body);
    if (!parsed.success) return reply.code(400).send({ success: false, message: parsed.error });
    return (await refreshUpdateCenterStatusCache()).status;
  });

  app.put<{ Body: unknown }>('/api/update-center/config', async (request, reply) => {
    const parsed = parseUpdateCenterConfigPayload(request.body);
    if (!parsed.success) return reply.code(400).send({ success: false, message: parsed.error });
    const current = await loadUpdateCenterConfig();
    const saved = await saveUpdateCenterConfig(normalizeUpdateCenterConfig({
      ...current,
      ...parsed.data,
    }));
    return { success: true, config: saved };
  });

  app.post<{ Body: unknown }>('/api/update-center/deploy', async (request, reply) => {
    const parsed = parseUpdateCenterDeployPayload(request.body);
    if (!parsed.success) return reply.code(400).send({ success: false, message: parsed.error });
    const body = parsed.data;
    const requestedTarget = body.targetVersion ?? body.targetTag;
    const targetVersion = requestedTarget === undefined ? undefined : normalizeTargetVersion(requestedTarget);
    if (requestedTarget !== undefined && !targetVersion) {
      return reply.code(400).send({ success: false, message: 'targetVersion must be a stable SemVer.' });
    }

    const config = await loadUpdateCenterConfig();
    if (!config.enabled) return reply.code(400).send({ success: false, message: 'update center is disabled' });
    let local;
    try {
      local = await getUpdateCenterLocalStatus();
    } catch (error) {
      return reply.code(409).send({ success: false, message: summarizeError(error) });
    }
    if (!local.capability.supported) {
      return reply.code(409).send({
        success: false,
        message: local.capability.reason || 'local update is not supported in this runtime',
      });
    }
    if (local.state.restartPending || local.pending) {
      return reply.code(409).send({ success: false, message: 'an update restart is already pending' });
    }

    let taskId = '';
    const { task, reused } = startBackgroundTask({
      type: UPDATE_CENTER_UPDATE_TASK_TYPE,
      title: '应用升级',
      dedupeKey: UPDATE_CENTER_UPDATE_DEDUPE_KEY,
      successTitle: '应用升级已准备完成',
      failureTitle: '应用升级失败',
    }, async () => {
      await Promise.resolve();
      appendBackgroundTaskLog(taskId, targetVersion
        ? `准备安装官方 Release ${targetVersion}`
        : '准备安装最新官方稳定 Release');
      const result = await installUpdateCenterRelease({
        ...(targetVersion ? { targetVersion } : {}),
        taskId,
        onProgress: ({ downloadedBytes, totalBytes }) => {
          const total = totalBytes ? `/${totalBytes}` : '';
          appendBackgroundTaskLog(taskId, `下载进度 ${downloadedBytes}${total} bytes`);
        },
      });
      appendBackgroundTaskLog(taskId, `已切换到 ${result.targetVersion}，等待应用进程重启并确认健康状态`);
      if (shouldRestartAfterUpdate()) requestRestart(taskId);
      return result;
    });
    taskId = task.id;
    return reply.code(202).send({ success: true, reused, task });
  });

  app.post<{ Body: unknown }>('/api/update-center/rollback', async (request, reply) => {
    const parsed = parseUpdateCenterRollbackPayload(request.body);
    if (!parsed.success) return reply.code(400).send({ success: false, message: parsed.error });
    const body = parsed.data;
    const requestedTarget = body.targetVersion ?? body.targetRevision;
    const targetVersion = requestedTarget === undefined ? undefined : normalizeTargetVersion(requestedTarget);
    if (requestedTarget !== undefined && !targetVersion) {
      return reply.code(400).send({ success: false, message: 'targetVersion must be a stable SemVer.' });
    }

    const config = await loadUpdateCenterConfig();
    if (!config.enabled) return reply.code(400).send({ success: false, message: 'update center is disabled' });
    let local;
    try {
      local = await getUpdateCenterLocalStatus();
    } catch (error) {
      return reply.code(409).send({ success: false, message: summarizeError(error) });
    }
    if (!local.capability.supported) {
      return reply.code(409).send({
        success: false,
        message: local.capability.reason || 'local update is not supported in this runtime',
      });
    }
    if (local.state.restartPending || local.pending) {
      return reply.code(409).send({ success: false, message: 'an update restart is already pending' });
    }

    let taskId = '';
    const { task, reused } = startBackgroundTask({
      type: UPDATE_CENTER_ROLLBACK_TASK_TYPE,
      title: '应用回滚',
      dedupeKey: UPDATE_CENTER_ROLLBACK_DEDUPE_KEY,
      successTitle: '应用回滚已准备完成',
      failureTitle: '应用回滚失败',
    }, async () => {
      await Promise.resolve();
      appendBackgroundTaskLog(taskId, targetVersion ? `准备回滚到 ${targetVersion}` : '准备回滚到上一版本');
      const result = await rollbackUpdateCenter({ ...(targetVersion ? { targetVersion } : {}), taskId });
      appendBackgroundTaskLog(taskId, `已切换到 ${result.targetVersion}，等待应用进程重启并确认健康状态`);
      if (shouldRestartAfterUpdate()) requestRestart(taskId);
      return result;
    });
    taskId = task.id;
    return reply.code(202).send({ success: true, reused, task });
  });

  app.get<{ Params: { id: string } }>('/api/update-center/tasks/:id/stream', async (request, reply) => {
    const taskId = String(request.params.id || '').trim();
    const task = getBackgroundTask(taskId);
    if (!task) return reply.code(404).send({ success: false, message: 'task not found' });

    reply.hijack();
    reply.raw.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
    reply.raw.setHeader('Cache-Control', 'no-cache, no-transform');
    reply.raw.setHeader('Connection', 'keep-alive');

    let streamClosed = false;
    let interval: ReturnType<typeof setInterval> | null = null;
    let unsubscribe: (() => void) | null = null;

    function cleanupStream(): void {
      if (interval) {
        clearInterval(interval);
        interval = null;
      }
      if (unsubscribe) {
        unsubscribe();
        unsubscribe = null;
      }
      request.raw.off?.('close', onClientClosed);
      reply.raw.off?.('close', onClientClosed);
    }

    function onClientClosed(): void {
      streamClosed = true;
      cleanupStream();
    }

    request.raw.on('close', onClientClosed);
    reply.raw.on('close', onClientClosed);

    const writeDone = () => {
      if (streamClosed) return;
      streamClosed = true;
      const latest = getBackgroundTask(taskId);
      cleanupStream();
      if (writeSseEvent(reply, 'done', { status: latest?.status || 'unknown' })) {
        endSseResponse(reply.raw);
      }
    };
    for (const entry of task.logs) {
      if (!writeSseEvent(reply, 'log', entry)) {
        onClientClosed();
        return;
      }
    }
    if (isTerminalTask(task.status)) {
      writeDone();
      return;
    }

    unsubscribe = subscribeToBackgroundTaskLogs(taskId, (entry) => {
      if (streamClosed || writeSseEvent(reply, 'log', entry)) return;
      onClientClosed();
    });
    interval = setInterval(() => {
      if (streamClosed) return;
      const latest = getBackgroundTask(taskId);
      if (!latest || isTerminalTask(latest.status)) {
        writeDone();
      }
    }, 25);
    interval.unref?.();
  });
}
