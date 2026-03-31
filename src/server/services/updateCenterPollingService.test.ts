import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

const {
  refreshUpdateCenterStatusCacheMock,
  sendNotificationMock,
} = vi.hoisted(() => ({
  refreshUpdateCenterStatusCacheMock: vi.fn(),
  sendNotificationMock: vi.fn(),
}));

vi.mock('./updateCenterStatusService.js', () => ({
  refreshUpdateCenterStatusCache: (...args: unknown[]) => refreshUpdateCenterStatusCacheMock(...args),
}));

vi.mock('./notifyService.js', () => ({
  sendNotification: (...args: unknown[]) => sendNotificationMock(...args),
}));

type DbModule = typeof import('../db/index.js');
type PollingModule = typeof import('./updateCenterPollingService.js');
type RuntimeStateModule = typeof import('./updateCenterRuntimeStateService.js');

describe('updateCenterPollingService', () => {
  let dataDir = '';
  let db: DbModule['db'];
  let schema: DbModule['schema'];
  let closeDbConnections: DbModule['closeDbConnections'];
  let startUpdateCenterPolling: PollingModule['startUpdateCenterPolling'];
  let stopUpdateCenterPolling: PollingModule['stopUpdateCenterPolling'];
  let loadUpdateCenterRuntimeState: RuntimeStateModule['loadUpdateCenterRuntimeState'];

  beforeAll(async () => {
    dataDir = mkdtempSync(join(tmpdir(), 'metapi-update-center-polling-'));
    process.env.DATA_DIR = dataDir;

    await import('../db/migrate.js');
    const dbModule = await import('../db/index.js');
    const pollingModule = await import('./updateCenterPollingService.js');
    const runtimeStateModule = await import('./updateCenterRuntimeStateService.js');

    db = dbModule.db;
    schema = dbModule.schema;
    closeDbConnections = dbModule.closeDbConnections;
    startUpdateCenterPolling = pollingModule.startUpdateCenterPolling;
    stopUpdateCenterPolling = pollingModule.stopUpdateCenterPolling;
    loadUpdateCenterRuntimeState = runtimeStateModule.loadUpdateCenterRuntimeState;
  });

  beforeEach(async () => {
    vi.useFakeTimers();
    refreshUpdateCenterStatusCacheMock.mockReset();
    sendNotificationMock.mockReset();

    await db.delete(schema.events).run();
    await db.delete(schema.settings).run();
  });

  afterEach(() => {
    stopUpdateCenterPolling();
    vi.useRealTimers();
  });

  afterAll(async () => {
    if (typeof closeDbConnections === 'function') {
      await closeDbConnections();
    }
    if (dataDir) {
      try {
        rmSync(dataDir, { recursive: true, force: true });
      } catch {}
    }
    delete process.env.DATA_DIR;
  });

  it('runs immediately, writes one event, and only notifies once for the same candidate', async () => {
    refreshUpdateCenterStatusCacheMock.mockImplementation(async () => {
      const previousRuntime = await loadUpdateCenterRuntimeState();
      const runtime = {
        ...previousRuntime,
        lastCheckedAt: '2026-03-31 12:00:00',
        lastCheckError: null,
        lastResolvedSource: 'github-release' as const,
        lastResolvedDisplayVersion: '1.3.0',
        lastResolvedCandidateKey: 'github-release:v1.3.0',
        statusSnapshot: {
          githubRelease: {
            source: 'github-release' as const,
            rawVersion: 'v1.3.0',
            normalizedVersion: '1.3.0',
            url: 'https://github.com/cita-777/metapi/releases/tag/v1.3.0',
            tagName: 'v1.3.0',
            digest: null,
            displayVersion: '1.3.0',
            publishedAt: '2026-03-31T12:00:00Z',
          },
          dockerHubTag: null,
          helper: {
            ok: true,
            releaseName: 'metapi',
            namespace: 'ai',
            revision: '12',
            imageRepository: '1467078763/metapi',
            imageTag: '1.2.3',
            imageDigest: null,
            healthy: true,
            history: [],
          },
        },
      };
      return {
        status: {
          currentVersion: '1.2.3',
          githubRelease: runtime.statusSnapshot.githubRelease,
          dockerHubTag: null,
          helper: runtime.statusSnapshot.helper,
          runtime,
        },
        candidate: {
          source: 'github-release',
          kind: 'new-version',
          candidateKey: 'github-release:v1.3.0',
          displayVersion: '1.3.0',
          tagName: 'v1.3.0',
          digest: null,
        },
        previousRuntime,
        runtime,
      };
    });

    startUpdateCenterPolling(60_000);
    await vi.advanceTimersByTimeAsync(0);

    expect(sendNotificationMock).toHaveBeenCalledTimes(1);
    expect(sendNotificationMock.mock.calls[0]?.[0]).toContain('更新中心');
    expect(sendNotificationMock.mock.calls[0]?.[1]).toContain('1.3.0');

    let events = await db.select().from(schema.events).all();
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      type: 'status',
      relatedType: 'update_center',
      level: 'info',
    });

    expect(await loadUpdateCenterRuntimeState()).toEqual(expect.objectContaining({
      lastCheckError: null,
      lastResolvedSource: 'github-release',
      lastResolvedCandidateKey: 'github-release:v1.3.0',
      lastNotifiedCandidateKey: 'github-release:v1.3.0',
      statusSnapshot: {
        githubRelease: expect.objectContaining({
          normalizedVersion: '1.3.0',
        }),
        dockerHubTag: null,
        helper: expect.objectContaining({
          imageTag: '1.2.3',
        }),
      },
    }));

    await vi.advanceTimersByTimeAsync(60_000);

    expect(sendNotificationMock).toHaveBeenCalledTimes(1);
    events = await db.select().from(schema.events).all();
    expect(events).toHaveLength(1);
  });

  it('stores the latest check error without creating events or notifications when the background check fails', async () => {
    refreshUpdateCenterStatusCacheMock.mockRejectedValue(new Error('GitHub releases lookup timed out'));

    startUpdateCenterPolling(60_000);
    await vi.advanceTimersByTimeAsync(0);

    expect(sendNotificationMock).not.toHaveBeenCalled();
    expect(await db.select().from(schema.events).all()).toEqual([]);
    expect(await loadUpdateCenterRuntimeState()).toEqual(expect.objectContaining({
      lastCheckError: 'GitHub releases lookup timed out',
      lastNotifiedCandidateKey: null,
    }));
  });

  it('persists the notified candidate even when the downstream notification send fails', async () => {
    refreshUpdateCenterStatusCacheMock.mockImplementation(async () => {
      const previousRuntime = await loadUpdateCenterRuntimeState();
      const runtime = {
        ...previousRuntime,
        lastCheckedAt: '2026-03-31 12:01:00',
        lastCheckError: null,
        lastResolvedSource: 'github-release' as const,
        lastResolvedDisplayVersion: '1.3.0',
        lastResolvedCandidateKey: 'github-release:v1.3.0',
        statusSnapshot: {
          githubRelease: {
            source: 'github-release' as const,
            rawVersion: 'v1.3.0',
            normalizedVersion: '1.3.0',
            url: 'https://github.com/cita-777/metapi/releases/tag/v1.3.0',
            tagName: 'v1.3.0',
            digest: null,
            displayVersion: '1.3.0',
            publishedAt: '2026-03-31T12:01:00Z',
          },
          dockerHubTag: null,
          helper: {
            ok: true,
            releaseName: 'metapi',
            namespace: 'ai',
            revision: '12',
            imageRepository: '1467078763/metapi',
            imageTag: '1.2.3',
            imageDigest: null,
            healthy: true,
            history: [],
          },
        },
      };
      return {
        status: {
          currentVersion: '1.2.3',
          githubRelease: runtime.statusSnapshot.githubRelease,
          dockerHubTag: null,
          helper: runtime.statusSnapshot.helper,
          runtime,
        },
        candidate: {
          source: 'github-release',
          kind: 'new-version',
          candidateKey: 'github-release:v1.3.0',
          displayVersion: '1.3.0',
          tagName: 'v1.3.0',
          digest: null,
        },
        previousRuntime,
        runtime,
      };
    });
    sendNotificationMock.mockRejectedValue(new Error('notification downstream failed'));

    startUpdateCenterPolling(60_000);
    await vi.advanceTimersByTimeAsync(0);
    await vi.advanceTimersByTimeAsync(60_000);

    expect(sendNotificationMock).toHaveBeenCalledTimes(1);
    expect(await db.select().from(schema.events).all()).toHaveLength(1);
    expect(await loadUpdateCenterRuntimeState()).toEqual(expect.objectContaining({
      lastCheckError: 'notification downstream failed',
      lastResolvedCandidateKey: 'github-release:v1.3.0',
      lastNotifiedCandidateKey: 'github-release:v1.3.0',
      lastNotifiedAt: expect.any(String),
      statusSnapshot: {
        githubRelease: expect.objectContaining({
          normalizedVersion: '1.3.0',
        }),
        dockerHubTag: null,
        helper: expect.objectContaining({
          imageTag: '1.2.3',
        }),
      },
    }));
  });
});
