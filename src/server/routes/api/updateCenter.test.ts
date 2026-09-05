import Fastify, { type FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import { waitForBackgroundTaskToReachTerminalState } from '../../test-fixtures/backgroundTaskTestUtils.js';

const mocks = vi.hoisted(() => {
  const defaultConfig = {
    enabled: false,
    channel: 'stable' as const,
    autoCheck: false,
  };
  return {
    config: { ...defaultConfig },
    defaultConfig,
    loadConfig: vi.fn(),
    normalizeConfig: vi.fn((input: unknown) => {
      const value = input && typeof input === 'object' && !Array.isArray(input)
        ? input as Record<string, unknown>
        : {};
      return {
        enabled: typeof value.enabled === 'boolean' ? value.enabled : false,
        channel: 'stable' as const,
        autoCheck: typeof value.autoCheck === 'boolean' ? value.autoCheck : false,
      };
    }),
    saveConfig: vi.fn(),
    getLocalStatus: vi.fn(),
    installRelease: vi.fn(),
    rollbackRelease: vi.fn(),
    getStatus: vi.fn(),
    refreshStatus: vi.fn(),
  };
});

vi.mock('../../services/updateCenterConfigService.js', () => ({
  loadUpdateCenterConfig: (...args: unknown[]) => mocks.loadConfig(...args),
  normalizeUpdateCenterConfig: (...args: unknown[]) => mocks.normalizeConfig(...args),
  saveUpdateCenterConfig: (...args: unknown[]) => mocks.saveConfig(...args),
}));

vi.mock('../../services/updateCenterLocalUpdateService.js', () => ({
  getUpdateCenterLocalStatus: (...args: unknown[]) => mocks.getLocalStatus(...args),
  installUpdateCenterRelease: (...args: unknown[]) => mocks.installRelease(...args),
  rollbackUpdateCenter: (...args: unknown[]) => mocks.rollbackRelease(...args),
}));

vi.mock('../../services/updateCenterStatusService.js', () => ({
  getUpdateCenterStatus: (...args: unknown[]) => mocks.getStatus(...args),
  refreshUpdateCenterStatusCache: (...args: unknown[]) => mocks.refreshStatus(...args),
}));

type BackgroundTaskModule = typeof import('../../services/backgroundTaskService.js');

const defaultRuntimeState = {
  schemaVersion: 1,
  updateState: 'healthy' as const,
  currentVersion: '1.2.3',
  previousVersion: '1.1.0',
  installedVersions: ['1.2.3', '1.1.0'],
  restartPending: false,
  taskId: null,
  lastError: null,
  updatedAt: null,
  lastCheckedAt: null,
  lastCheckError: null,
  lastResolvedSource: null,
  lastResolvedDisplayVersion: null,
  lastResolvedCandidateKey: null,
  lastNotifiedCandidateKey: null,
  lastNotifiedAt: null,
  statusSnapshot: null,
};

function supportedLocalStatus(overrides: Record<string, unknown> = {}) {
  return {
    capability: {
      supported: true,
      mode: 'local-bundle',
      reason: null,
      runtimeDir: '/tmp/metapi-runtime',
      architecture: 'amd64',
      platform: 'linux',
      nodeMajor: 25,
      persistent: true,
      writable: true,
      currentVersion: '1.2.3',
    },
    state: { ...defaultRuntimeState },
    pending: null,
    installedVersions: [
      { version: '1.2.3', path: '/tmp/metapi-runtime/releases/1.2.3', manifest: {}, current: true, previous: false },
      { version: '1.1.0', path: '/tmp/metapi-runtime/releases/1.1.0', manifest: {}, current: false, previous: true },
    ],
    ...overrides,
  };
}

function successfulInstall() {
  return {
    success: true,
    taskId: 'task-placeholder',
    targetVersion: '1.3.0',
    previousVersion: '1.2.3',
    releasePath: '/tmp/metapi-runtime/releases/1.3.0',
    archiveSha256: 'a'.repeat(64),
    restartRequired: true,
    state: {
      ...defaultRuntimeState,
      updateState: 'restarting' as const,
      currentVersion: '1.3.0',
      previousVersion: '1.2.3',
      restartPending: true,
    },
  };
}

function successfulRollback() {
  return {
    success: true,
    taskId: 'task-placeholder',
    targetVersion: '1.1.0',
    previousVersion: '1.2.3',
    restartRequired: true,
    state: {
      ...defaultRuntimeState,
      updateState: 'restarting' as const,
      currentVersion: '1.1.0',
      previousVersion: '1.2.3',
      restartPending: true,
    },
  };
}

describe('update center routes', () => {
  let app: FastifyInstance;
  let resetBackgroundTasks: BackgroundTaskModule['__resetBackgroundTasksForTests'];
  let getBackgroundTask: BackgroundTaskModule['getBackgroundTask'];
  let routesModule: typeof import('./updateCenter.js');
  const restartHandler = vi.fn();

  beforeAll(async () => {
    process.env.NODE_ENV = 'test';
    const backgroundTaskModule = await import('../../services/backgroundTaskService.js');
    routesModule = await import('./updateCenter.js');
    resetBackgroundTasks = backgroundTaskModule.__resetBackgroundTasksForTests;
    getBackgroundTask = backgroundTaskModule.getBackgroundTask;
    routesModule.setUpdateCenterRestartHandlerForTests(restartHandler);
    app = Fastify();
    await app.register(routesModule.updateCenterRoutes);
  });

  beforeEach(() => {
    mocks.config.enabled = mocks.defaultConfig.enabled;
    mocks.config.channel = mocks.defaultConfig.channel;
    mocks.config.autoCheck = mocks.defaultConfig.autoCheck;
    mocks.loadConfig.mockReset().mockImplementation(async () => ({ ...mocks.config }));
    mocks.normalizeConfig.mockClear();
    mocks.saveConfig.mockReset().mockImplementation(async (input: unknown) => {
      const value = mocks.normalizeConfig(input);
      mocks.config.enabled = value.enabled;
      mocks.config.channel = value.channel;
      mocks.config.autoCheck = value.autoCheck;
      return { ...value };
    });
    mocks.getLocalStatus.mockReset().mockResolvedValue(supportedLocalStatus());
    mocks.installRelease.mockReset().mockResolvedValue(successfulInstall());
    mocks.rollbackRelease.mockReset().mockResolvedValue(successfulRollback());
    mocks.getStatus.mockReset().mockResolvedValue({ status: 'cached' });
    mocks.refreshStatus.mockReset().mockResolvedValue({ status: 'refreshed' });
    restartHandler.mockReset();
    resetBackgroundTasks();
  });

  afterAll(async () => {
    routesModule.setUpdateCenterRestartHandlerForTests(null);
    await app.close();
  });

  it('exposes a public health probe with the running release version', async () => {
    const response = await app.inject({ method: 'GET', url: '/healthz' });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({ status: 'ok', ready: true, version: expect.any(String) });
  });

  it('persists the small v2 config and rejects removed deployment fields', async () => {
    const response = await app.inject({
      method: 'PUT',
      url: '/api/update-center/config',
      payload: { enabled: true, channel: 'stable', autoCheck: true },
    });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      success: true,
      config: { enabled: true, channel: 'stable', autoCheck: true },
    });
    expect(mocks.saveConfig).toHaveBeenCalledWith({ enabled: true, channel: 'stable', autoCheck: true });

    const invalid = await app.inject({
      method: 'PUT',
      url: '/api/update-center/config',
      payload: { enabled: true, helperBaseUrl: 'http://old-helper.invalid' },
    });
    expect(invalid.statusCode).toBe(400);
    expect(mocks.saveConfig).toHaveBeenCalledTimes(1);
  });

  it('delegates cached status and explicit checks without owning discovery', async () => {
    const cached = { supported: true, currentVersion: '1.2.3', latestRelease: null };
    const refreshed = { supported: true, currentVersion: '1.3.0', latestRelease: null };
    mocks.getStatus.mockResolvedValue(cached);
    mocks.refreshStatus.mockResolvedValue({ status: refreshed });

    const status = await app.inject({ method: 'GET', url: '/api/update-center/status' });
    const check = await app.inject({ method: 'POST', url: '/api/update-center/check', payload: {} });
    expect(status.statusCode).toBe(200);
    expect(status.json()).toEqual(cached);
    expect(check.statusCode).toBe(200);
    expect(check.json()).toEqual(refreshed);
    expect(mocks.getStatus).toHaveBeenCalledTimes(1);
    expect(mocks.refreshStatus).toHaveBeenCalledTimes(1);

    const invalid = await app.inject({
      method: 'POST',
      url: '/api/update-center/check',
      payload: { unexpected: true },
    });
    expect(invalid.statusCode).toBe(400);
    expect(invalid.json()).toMatchObject({ success: false, message: expect.stringContaining('unexpected') });
    expect(mocks.refreshStatus).toHaveBeenCalledTimes(1);
  });

  it('rejects updates while disabled or when local runtime capability is unsupported', async () => {
    const disabled = await app.inject({
      method: 'POST',
      url: '/api/update-center/deploy',
      payload: { targetVersion: '1.3.0' },
    });
    expect(disabled.statusCode).toBe(400);
    expect(disabled.json()).toMatchObject({ success: false, message: 'update center is disabled' });
    expect(mocks.getLocalStatus).not.toHaveBeenCalled();

    mocks.config.enabled = true;
    const unsupported = supportedLocalStatus();
    unsupported.capability = {
      ...unsupported.capability,
      supported: false,
      mode: 'unsupported',
      reason: 'runtime directory is not marked as a persistent volume',
    };
    mocks.getLocalStatus.mockResolvedValue(unsupported);
    const response = await app.inject({
      method: 'POST',
      url: '/api/update-center/deploy',
      payload: { targetVersion: '1.3.0' },
    });
    expect(response.statusCode).toBe(409);
    expect(response.json()).toMatchObject({ success: false, message: expect.stringContaining('persistent') });
    expect(mocks.installRelease).not.toHaveBeenCalled();
  });

  it('normalizes a target version, starts a background install task, and keeps SSE logs', async () => {
    mocks.config.enabled = true;
    mocks.installRelease.mockImplementation(async (input: { taskId?: string; targetVersion?: string; onProgress?: (value: unknown) => void }) => {
      input.onProgress?.({ downloadedBytes: 12, totalBytes: 24 });
      return successfulInstall();
    });

    const response = await app.inject({
      method: 'POST',
      url: '/api/update-center/deploy',
      payload: { targetVersion: 'v1.3.0' },
    });
    expect(response.statusCode).toBe(202);
    const body = response.json() as { task: { id: string }; reused: boolean };
    expect(body.task.id).toBeTruthy();
    expect(body.reused).toBe(false);

    const task = await waitForBackgroundTaskToReachTerminalState(
      (taskId) => getBackgroundTask(taskId),
      body.task.id,
    );
    expect(task).toMatchObject({ status: 'succeeded' });
    expect(task?.logs).toEqual(expect.arrayContaining([
      expect.objectContaining({ message: '准备安装官方 Release 1.3.0' }),
      expect.objectContaining({ message: '下载进度 12/24 bytes' }),
      expect.objectContaining({ message: '已切换到 1.3.0，等待应用进程重启并确认健康状态' }),
    ]));
    expect(mocks.installRelease).toHaveBeenCalledWith(expect.objectContaining({
      targetVersion: '1.3.0',
      taskId: body.task.id,
    }));
    expect(restartHandler).toHaveBeenCalledTimes(1);

    const stream = await app.inject({
      method: 'GET',
      url: `/api/update-center/tasks/${encodeURIComponent(body.task.id)}/stream`,
    });
    expect(stream.statusCode).toBe(200);
    expect(stream.headers['content-type']).toContain('text/event-stream');
    expect(stream.body).toContain('event: log');
    expect(stream.body).toContain('准备安装官方 Release 1.3.0');
    expect(stream.body).toContain('event: done');
  });

  it('accepts the legacy targetTag alias and reuses a running update task', async () => {
    mocks.config.enabled = true;
    let releaseInstall: (() => void) | null = null;
    const gate = new Promise<void>((resolve) => { releaseInstall = resolve; });
    mocks.installRelease.mockImplementation(async () => {
      await gate;
      return successfulInstall();
    });

    const first = await app.inject({
      method: 'POST',
      url: '/api/update-center/deploy',
      payload: { targetTag: '1.3.0' },
    });
    const second = await app.inject({
      method: 'POST',
      url: '/api/update-center/deploy',
      payload: { targetVersion: 'v1.3.0' },
    });
    expect(first.statusCode).toBe(202);
    expect(second.statusCode).toBe(202);
    const firstBody = first.json() as { task: { id: string }; reused: boolean };
    const secondBody = second.json() as { task: { id: string }; reused: boolean };
    expect(secondBody).toMatchObject({ reused: true, task: { id: firstBody.task.id } });
    releaseInstall?.();
    await waitForBackgroundTaskToReachTerminalState((taskId) => getBackgroundTask(taskId), firstBody.task.id);
  });

  it('does not reuse an update task for a concurrent rollback request', async () => {
    mocks.config.enabled = true;
    let releaseInstall: (() => void) | null = null;
    let releaseRollback: (() => void) | null = null;
    const installGate = new Promise<void>((resolve) => { releaseInstall = resolve; });
    const rollbackGate = new Promise<void>((resolve) => { releaseRollback = resolve; });
    mocks.installRelease.mockImplementation(async () => {
      await installGate;
      return successfulInstall();
    });
    mocks.rollbackRelease.mockImplementation(async () => {
      await rollbackGate;
      return successfulRollback();
    });

    const updateResponse = await app.inject({
      method: 'POST',
      url: '/api/update-center/deploy',
      payload: { targetVersion: '1.3.0' },
    });
    const rollbackResponse = await app.inject({
      method: 'POST',
      url: '/api/update-center/rollback',
      payload: { targetVersion: '1.1.0' },
    });
    const updateBody = updateResponse.json() as { task: { id: string }; reused: boolean };
    const rollbackBody = rollbackResponse.json() as { task: { id: string }; reused: boolean };
    expect(updateResponse.statusCode).toBe(202);
    expect(rollbackResponse.statusCode).toBe(202);
    expect(updateBody.reused).toBe(false);
    expect(rollbackBody.reused).toBe(false);
    expect(rollbackBody.task.id).not.toBe(updateBody.task.id);

    releaseInstall?.();
    releaseRollback?.();
    await waitForBackgroundTaskToReachTerminalState((taskId) => getBackgroundTask(taskId), updateBody.task.id);
    await waitForBackgroundTaskToReachTerminalState((taskId) => getBackgroundTask(taskId), rollbackBody.task.id);
  });

  it('rejects an update while a previous restart is pending', async () => {
    mocks.config.enabled = true;
    mocks.getLocalStatus.mockResolvedValue(supportedLocalStatus({
      state: { ...defaultRuntimeState, restartPending: true, updateState: 'restarting' },
    }));
    const response = await app.inject({
      method: 'POST',
      url: '/api/update-center/deploy',
      payload: { targetVersion: '1.3.0' },
    });
    expect(response.statusCode).toBe(409);
    expect(response.json()).toMatchObject({ success: false, message: 'an update restart is already pending' });
  });

  it('starts a local rollback task through targetVersion and targetRevision aliases', async () => {
    mocks.config.enabled = true;
    const response = await app.inject({
      method: 'POST',
      url: '/api/update-center/rollback',
      payload: { targetRevision: 'v1.1.0' },
    });
    expect(response.statusCode).toBe(202);
    const body = response.json() as { task: { id: string } };
    const task = await waitForBackgroundTaskToReachTerminalState(
      (taskId) => getBackgroundTask(taskId),
      body.task.id,
    );
    expect(task).toMatchObject({ status: 'succeeded' });
    expect(mocks.rollbackRelease).toHaveBeenCalledWith(expect.objectContaining({
      targetVersion: '1.1.0',
      taskId: body.task.id,
    }));
  });

  it('allows omitted versions to select the latest release or previous local version', async () => {
    mocks.config.enabled = true;
    const updateResponse = await app.inject({
      method: 'POST',
      url: '/api/update-center/deploy',
      payload: {},
    });
    expect(updateResponse.statusCode).toBe(202);
    const updateBody = updateResponse.json() as { task: { id: string } };
    await waitForBackgroundTaskToReachTerminalState((taskId) => getBackgroundTask(taskId), updateBody.task.id);
    expect(mocks.installRelease).toHaveBeenCalledWith(expect.objectContaining({ taskId: updateBody.task.id }));
    expect(mocks.installRelease.mock.calls.at(-1)?.[0]).not.toHaveProperty('targetVersion');

    resetBackgroundTasks();
    const rollbackResponse = await app.inject({
      method: 'POST',
      url: '/api/update-center/rollback',
      payload: {},
    });
    expect(rollbackResponse.statusCode).toBe(202);
    const rollbackBody = rollbackResponse.json() as { task: { id: string } };
    await waitForBackgroundTaskToReachTerminalState((taskId) => getBackgroundTask(taskId), rollbackBody.task.id);
    expect(mocks.rollbackRelease.mock.calls.at(-1)?.[0]).not.toHaveProperty('targetVersion');
  });

  it('rejects removed fields and invalid stable versions at the boundary', async () => {
    mocks.config.enabled = true;
    const removed = await app.inject({
      method: 'POST',
      url: '/api/update-center/deploy',
      payload: { source: 'github-release', targetVersion: '1.3.0' },
    });
    expect(removed.statusCode).toBe(400);
    expect(removed.json()).toMatchObject({ success: false, message: expect.stringContaining('source') });

    const invalidVersion = await app.inject({
      method: 'POST',
      url: '/api/update-center/deploy',
      payload: { targetVersion: '1.3.0-rc.1' },
    });
    expect(invalidVersion.statusCode).toBe(400);
    expect(invalidVersion.json()).toMatchObject({ success: false, message: 'targetVersion must be a stable SemVer.' });

    const invalidType = await app.inject({
      method: 'POST',
      url: '/api/update-center/rollback',
      payload: { targetRevision: 11 },
    });
    expect(invalidType.statusCode).toBe(400);
    expect(invalidType.json()).toMatchObject({ success: false, message: 'Invalid targetRevision. Expected string.' });
  });

  it('returns 404 for unknown task streams', async () => {
    const response = await app.inject({
      method: 'GET',
      url: '/api/update-center/tasks/missing/stream',
    });
    expect(response.statusCode).toBe(404);
    expect(response.json()).toMatchObject({ success: false, message: 'task not found' });
  });

  it('does not write an SSE event after the response has closed', () => {
    const write = vi.fn();
    const raw = {
      writableEnded: true,
      destroyed: false,
      closed: false,
      write,
      end: vi.fn(),
    } as never;
    expect(routesModule.writeSseEvent({ raw }, 'log', { message: 'late' })).toBe(false);
    expect(write).not.toHaveBeenCalled();
  });
});
