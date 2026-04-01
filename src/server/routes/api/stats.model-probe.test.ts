import Fastify, { type FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const buildModelAvailabilityProbeTaskDedupeKeyMock = vi.fn();
const queueModelAvailabilityProbeTaskMock = vi.fn();
const getBackgroundTaskMock = vi.fn();
const getRunningTaskByDedupeKeyMock = vi.fn();
const waitForBackgroundTaskCompletionMock = vi.fn();

vi.mock('../../services/modelAvailabilityProbeService.js', async () => {
  const actual = await vi.importActual<typeof import('../../services/modelAvailabilityProbeService.js')>('../../services/modelAvailabilityProbeService.js');
  return {
    ...actual,
    buildModelAvailabilityProbeTaskDedupeKey: (...args: unknown[]) => buildModelAvailabilityProbeTaskDedupeKeyMock(...args),
    queueModelAvailabilityProbeTask: (...args: unknown[]) => queueModelAvailabilityProbeTaskMock(...args),
  };
});

vi.mock('../../services/backgroundTaskService.js', async () => {
  const actual = await vi.importActual<typeof import('../../services/backgroundTaskService.js')>('../../services/backgroundTaskService.js');
  return {
    ...actual,
    getBackgroundTask: (...args: unknown[]) => getBackgroundTaskMock(...args),
    getRunningTaskByDedupeKey: (...args: unknown[]) => getRunningTaskByDedupeKeyMock(...args),
    waitForBackgroundTaskCompletion: (...args: unknown[]) => waitForBackgroundTaskCompletionMock(...args),
  };
});

describe('/api/models/probe', () => {
  let app: FastifyInstance;
  let dataDir = '';
  let originalDataDir: string | undefined;

  beforeAll(async () => {
    dataDir = mkdtempSync(join(tmpdir(), 'metapi-stats-model-probe-'));
    originalDataDir = process.env.DATA_DIR;
    process.env.DATA_DIR = dataDir;

    await import('../../db/migrate.js');
    const routesModule = await import('./stats.js');
    app = Fastify();
    await app.register(routesModule.statsRoutes);
  });

  beforeEach(() => {
    buildModelAvailabilityProbeTaskDedupeKeyMock.mockReset();
    queueModelAvailabilityProbeTaskMock.mockReset();
    getBackgroundTaskMock.mockReset();
    getRunningTaskByDedupeKeyMock.mockReset();
    waitForBackgroundTaskCompletionMock.mockReset();
  });

  afterAll(async () => {
    await app.close();
    if (originalDataDir === undefined) {
      delete process.env.DATA_DIR;
    } else {
      process.env.DATA_DIR = originalDataDir;
    }
  });

  it('rejects non-object request bodies instead of defaulting to a full probe', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/models/probe',
      headers: {
        'content-type': 'application/json',
      },
      payload: '"oops"',
    });

    expect(response.statusCode).toBe(400);
    expect(queueModelAvailabilityProbeTaskMock).not.toHaveBeenCalled();
  });

  it('rejects loosely formatted account ids instead of truncating them', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/models/probe',
      payload: {
        accountId: '1e2',
      },
    });

    expect(response.statusCode).toBe(400);
    expect(queueModelAvailabilityProbeTaskMock).not.toHaveBeenCalled();
  });

  it('rejects account ids that exceed the safe integer range', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/models/probe',
      payload: {
        accountId: '9007199254740993',
      },
    });

    expect(response.statusCode).toBe(400);
    expect(queueModelAvailabilityProbeTaskMock).not.toHaveBeenCalled();
  });

  it('reuses the running deduped task for wait=true requests', async () => {
    buildModelAvailabilityProbeTaskDedupeKeyMock.mockReturnValue('model-availability-probe-7');
    getRunningTaskByDedupeKeyMock.mockReturnValue({
      id: 'task-7',
      status: 'running',
    });
    const completedTask = {
      id: 'task-7',
      status: 'succeeded',
      result: {
        results: [],
        summary: {
          totalAccounts: 1,
          success: 1,
          failed: 0,
          skipped: 0,
          scanned: 3,
          supported: 2,
          unsupported: 1,
          inconclusive: 0,
          skippedModels: 0,
          updatedRows: 1,
          rebuiltRoutes: true,
        },
      },
    };
    waitForBackgroundTaskCompletionMock.mockResolvedValue(completedTask);

    const response = await app.inject({
      method: 'POST',
      url: '/api/models/probe',
      payload: {
        accountId: 7,
        wait: true,
      },
    });

    expect(response.statusCode).toBe(200);
    expect(queueModelAvailabilityProbeTaskMock).not.toHaveBeenCalled();
    expect(waitForBackgroundTaskCompletionMock).toHaveBeenCalledWith('task-7');
    expect(response.json()).toMatchObject({
      success: true,
      reused: true,
      jobId: 'task-7',
      summary: {
        totalAccounts: 1,
        scanned: 3,
        supported: 2,
        unsupported: 1,
      },
    });
  });
});
