import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => {
  const runtime = {
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
  return {
    runtime,
    loadConfig: vi.fn(),
    refreshStatus: vi.fn(),
    sendNotification: vi.fn(),
    patchRuntime: vi.fn(),
    db: {
      insert: vi.fn(() => ({
        values: vi.fn(() => ({
          run: vi.fn(async () => undefined),
        })),
      })),
    },
    schema: { events: {} },
  };
});

vi.mock('../db/index.js', () => ({ db: mocks.db, schema: mocks.schema }));
vi.mock('./updateCenterConfigService.js', () => ({
  loadUpdateCenterConfig: (...args: unknown[]) => mocks.loadConfig(...args),
}));
vi.mock('./updateCenterStatusService.js', () => ({
  refreshUpdateCenterStatusCache: (...args: unknown[]) => mocks.refreshStatus(...args),
}));
vi.mock('./notifyService.js', () => ({
  sendNotification: (...args: unknown[]) => mocks.sendNotification(...args),
}));
vi.mock('./updateCenterRuntimeStateService.js', () => ({
  patchUpdateCenterRuntimeState: (...args: unknown[]) => mocks.patchRuntime(...args),
}));

import {
  __runUpdateCenterSyncForTests,
  startUpdateCenterPolling,
  stopUpdateCenterPolling,
} from './updateCenterPollingService.js';

const candidate = {
  source: 'github-release' as const,
  kind: 'new-version' as const,
  candidateKey: 'github-release:v1.3.0',
  displayVersion: '1.3.0',
  tagName: 'v1.3.0',
  digest: null,
};

function statusResult(previousRuntime = mocks.runtime) {
  return {
    candidate,
    previousRuntime,
    runtime: {
      ...mocks.runtime,
      lastResolvedCandidateKey: candidate.candidateKey,
    },
  };
}

describe('updateCenterPollingService', () => {
  beforeEach(() => {
    vi.useRealTimers();
    vi.clearAllMocks();
    mocks.loadConfig.mockResolvedValue({ enabled: false, channel: 'stable', autoCheck: false });
    mocks.patchRuntime.mockImplementation(async (patch: Record<string, unknown>) => ({ ...mocks.runtime, ...patch }));
    mocks.refreshStatus.mockResolvedValue(statusResult());
    mocks.sendNotification.mockResolvedValue(undefined);
  });

  afterEach(() => {
    stopUpdateCenterPolling();
    vi.useRealTimers();
  });

  it('does not perform external checks while disabled', async () => {
    await __runUpdateCenterSyncForTests();
    expect(mocks.refreshStatus).not.toHaveBeenCalled();
    expect(mocks.sendNotification).not.toHaveBeenCalled();
  });

  it('runs an enabled automatic check and records a new-release reminder', async () => {
    mocks.loadConfig.mockResolvedValue({ enabled: true, channel: 'stable', autoCheck: true });
    await __runUpdateCenterSyncForTests();

    expect(mocks.refreshStatus).toHaveBeenCalledTimes(1);
    expect(mocks.db.insert).toHaveBeenCalledTimes(1);
    expect(mocks.sendNotification).toHaveBeenCalledWith(
      '发现 Metapi 新版本',
      expect.stringContaining('1.3.0'),
      'info',
      { bypassThrottle: true },
    );
    expect(mocks.patchRuntime).toHaveBeenCalledWith(expect.objectContaining({
      lastNotifiedCandidateKey: candidate.candidateKey,
      lastNotifiedAt: expect.any(String),
    }));
    const notificationPatch = mocks.patchRuntime.mock.calls[0]?.[0] as Record<string, unknown>;
    expect(notificationPatch).not.toHaveProperty('updateState');
    expect(notificationPatch).not.toHaveProperty('currentVersion');
    expect(notificationPatch).not.toHaveProperty('restartPending');
  });

  it('notifies only once for the same candidate across repeated checks', async () => {
    mocks.loadConfig.mockResolvedValue({ enabled: true, channel: 'stable', autoCheck: true });
    let callCount = 0;
    mocks.refreshStatus.mockImplementation(async () => {
      callCount += 1;
      return statusResult(callCount === 1
        ? mocks.runtime
        : { ...mocks.runtime, lastNotifiedCandidateKey: candidate.candidateKey });
    });

    await __runUpdateCenterSyncForTests();
    await __runUpdateCenterSyncForTests();

    expect(mocks.sendNotification).toHaveBeenCalledTimes(1);
    expect(mocks.db.insert).toHaveBeenCalledTimes(1);
  });

  it('persists a check error without creating a reminder', async () => {
    mocks.loadConfig.mockResolvedValue({ enabled: true, channel: 'stable', autoCheck: true });
    mocks.refreshStatus.mockRejectedValue(new Error('GitHub releases lookup timed out'));

    await __runUpdateCenterSyncForTests();

    expect(mocks.sendNotification).not.toHaveBeenCalled();
    expect(mocks.db.insert).not.toHaveBeenCalled();
    expect(mocks.patchRuntime).toHaveBeenCalledWith(expect.objectContaining({
      lastCheckError: 'GitHub releases lookup timed out',
      lastCheckedAt: expect.any(String),
    }));
  });

  it('keeps scheduler failures contained when runtime diagnostics cannot be written', async () => {
    mocks.loadConfig.mockResolvedValue({ enabled: true, channel: 'stable', autoCheck: true });
    mocks.refreshStatus.mockRejectedValue(new Error('GitHub unavailable'));
    mocks.patchRuntime.mockRejectedValue(new Error('runtime read-only'));

    await expect(__runUpdateCenterSyncForTests()).resolves.toBeUndefined();
    expect(mocks.patchRuntime).toHaveBeenCalledTimes(1);
  });

  it('coalesces concurrent checks before the first await', async () => {
    mocks.loadConfig.mockResolvedValue({ enabled: true, channel: 'stable', autoCheck: true });
    let releaseGate!: () => void;
    const gate = new Promise<void>((resolve) => { releaseGate = resolve; });
    mocks.refreshStatus.mockImplementation(async () => {
      await gate;
      return statusResult();
    });

    const first = __runUpdateCenterSyncForTests();
    const second = __runUpdateCenterSyncForTests();
    await Promise.resolve();
    expect(mocks.refreshStatus).toHaveBeenCalledTimes(1);
    releaseGate();
    await Promise.all([first, second]);
  });

  it('clamps very short polling intervals to a safe minimum', () => {
    expect(startUpdateCenterPolling(1).intervalMs).toBe(10_000);
  });
});
