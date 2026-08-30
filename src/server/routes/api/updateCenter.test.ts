import Fastify, { type FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { eq } from 'drizzle-orm';
import { resolveUpdateReminderCandidate } from '../../shared/updateCenterReminder.js';
import { waitForBackgroundTaskToReachTerminalState } from '../../test-fixtures/backgroundTaskTestUtils.js';

const {
  fetchLatestStableGitHubReleaseMock,
  fetchDockerHubTagCandidatesMock,
  getUpdateCenterHelperStatusMock,
  streamUpdateCenterDeployMock,
  streamUpdateCenterRollbackMock,
} = vi.hoisted(() => ({
  fetchLatestStableGitHubReleaseMock: vi.fn(),
  fetchDockerHubTagCandidatesMock: vi.fn(),
  getUpdateCenterHelperStatusMock: vi.fn(),
  streamUpdateCenterDeployMock: vi.fn(),
  streamUpdateCenterRollbackMock: vi.fn(),
}));

vi.mock('../../services/updateCenterVersionService.js', async () => {
  const actual = await vi.importActual<typeof import('../../services/updateCenterVersionService.js')>('../../services/updateCenterVersionService.js');
  return {
    ...actual,
    fetchLatestStableGitHubRelease: (...args: unknown[]) => fetchLatestStableGitHubReleaseMock(...args),
    fetchDockerHubTagCandidates: (...args: unknown[]) => fetchDockerHubTagCandidatesMock(...args),
  };
});

vi.mock('../../services/updateCenterHelperClient.js', () => ({
  getUpdateCenterHelperStatus: (...args: unknown[]) => getUpdateCenterHelperStatusMock(...args),
  streamUpdateCenterDeploy: (...args: unknown[]) => streamUpdateCenterDeployMock(...args),
  streamUpdateCenterRollback: (...args: unknown[]) => streamUpdateCenterRollbackMock(...args),
}));

type DbModule = typeof import('../../db/index.js');
type ConfigModule = typeof import('../../config.js');
type RuntimeStateModule = typeof import('../../services/updateCenterRuntimeStateService.js');

function getNextPatchVersion(version: string) {
  const match = String(version).trim().match(/^(\d+)\.(\d+)\.(\d+)$/);
  if (!match) return '999.0.0';
  return `${match[1]}.${match[2]}.${Number.parseInt(match[3], 10) + 1}`;
}

describe('update center routes', () => {
  let app: FastifyInstance;
  let db: DbModule['db'];
  let schema: DbModule['schema'];
  let appConfig: ConfigModule['config'];
  let saveUpdateCenterRuntimeState: RuntimeStateModule['saveUpdateCenterRuntimeState'];
  let loadUpdateCenterRuntimeState: RuntimeStateModule['loadUpdateCenterRuntimeState'];
  let dataDir = '';
  let resetBackgroundTasks: (() => void) | null = null;
  let getBackgroundTask: ((taskId: string) => { status: string; logs?: Array<{ message: string }> } | null) | null = null;

  async function saveValidConfig() {
    const response = await app.inject({
      method: 'PUT',
      url: '/api/update-center/config',
      payload: {
        enabled: true,
        helperBaseUrl: 'http://metapi-deploy-helper.ai.svc.cluster.local:9850',
        namespace: 'ai',
        releaseName: 'metapi',
        chartRef: 'oci://ghcr.io/cita-777/charts/metapi',
        imageRepository: '1467078763/metapi',
        githubReleasesEnabled: true,
        dockerHubTagsEnabled: true,
        defaultDeploySource: 'github-release',
      },
    });

    expect(response.statusCode).toBe(200);
  }

  beforeAll(async () => {
    dataDir = mkdtempSync(join(tmpdir(), 'metapi-update-center-'));
    process.env.DATA_DIR = dataDir;
    process.env.DEPLOY_HELPER_TOKEN = 'helper-token';

    await import('../../db/migrate.js');
    const configModule = await import('../../config.js');
    const dbModule = await import('../../db/index.js');
    const routesModule = await import('./updateCenter.js');
    const backgroundTaskModule = await import('../../services/backgroundTaskService.js');
    const runtimeStateModule = await import('../../services/updateCenterRuntimeStateService.js');

    appConfig = configModule.config;
    db = dbModule.db;
    schema = dbModule.schema;
    resetBackgroundTasks = backgroundTaskModule.__resetBackgroundTasksForTests;
    getBackgroundTask = backgroundTaskModule.getBackgroundTask;
    saveUpdateCenterRuntimeState = runtimeStateModule.saveUpdateCenterRuntimeState;
    loadUpdateCenterRuntimeState = runtimeStateModule.loadUpdateCenterRuntimeState;

    app = Fastify();
    await app.register(routesModule.updateCenterRoutes);
  });

  beforeEach(async () => {
    fetchLatestStableGitHubReleaseMock.mockReset();
    fetchDockerHubTagCandidatesMock.mockReset();
    getUpdateCenterHelperStatusMock.mockReset();
    streamUpdateCenterDeployMock.mockReset();
    streamUpdateCenterRollbackMock.mockReset();
    resetBackgroundTasks?.();

    await db.delete(schema.events).run();
    await db.delete(schema.settings).run();
  });

  afterAll(async () => {
    if (app) {
      await app.close();
    }
    delete process.env.DATA_DIR;
    delete process.env.DEPLOY_HELPER_TOKEN;
  });

  it('persists config and returns status with both version channels and helper summary', async () => {
    const currentVersion = (await import('../../services/updateCenterVersionService.js')).getCurrentRuntimeVersion();
    const githubRelease = {
      source: 'github-release',
      rawVersion: 'v1.3.0',
      normalizedVersion: '1.3.0',
      url: 'https://github.com/cita-777/metapi/releases/tag/v1.3.0',
    } as const;
    const dockerHubTag = {
      source: 'docker-hub-tag',
      rawVersion: 'latest',
      normalizedVersion: 'latest',
      tagName: 'latest',
      digest: 'sha256:efb2ee6553866bd3268dcc54c02fa5f9789728c51ed4af63328aaba6da67df35',
      displayVersion: 'latest @ sha256:efb2ee655386',
      publishedAt: '2026-03-29T11:54:35.591877Z',
      url: null,
    } as const;
    const dockerHubRecentTags = [
      {
        source: 'docker-hub-tag',
        rawVersion: 'dev',
        normalizedVersion: 'dev',
        tagName: 'dev',
        digest: 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        displayVersion: 'dev @ sha256:aaaaaaaaaaaa',
        publishedAt: '2026-03-29T12:54:35.591877Z',
        url: null,
      },
    ] as const;
    const helperStatus = {
      ok: true,
      releaseName: 'metapi',
      namespace: 'ai',
      revision: '12',
      imageRepository: '1467078763/metapi',
      imageTag: 'latest',
      imageDigest: 'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
      healthy: true,
      history: [
        {
          revision: '11',
          updatedAt: '2026-03-28T12:00:00Z',
          status: 'superseded',
          description: 'Rollback to stable digest',
          imageRepository: '1467078763/metapi',
          imageTag: 'main',
          imageDigest: 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        },
      ],
    } as const;
    fetchLatestStableGitHubReleaseMock.mockResolvedValue(githubRelease);
    fetchDockerHubTagCandidatesMock.mockResolvedValue({
      primary: dockerHubTag,
      recentNonStable: dockerHubRecentTags,
    });
    getUpdateCenterHelperStatusMock.mockResolvedValue(helperStatus);

    const saveResponse = await app.inject({
      method: 'PUT',
      url: '/api/update-center/config',
      payload: {
        enabled: true,
        helperBaseUrl: 'http://metapi-deploy-helper.ai.svc.cluster.local:9850',
        namespace: 'ai',
        releaseName: 'metapi',
        chartRef: 'oci://ghcr.io/cita-777/charts/metapi',
        imageRepository: '1467078763/metapi',
        githubReleasesEnabled: true,
        dockerHubTagsEnabled: true,
        defaultDeploySource: 'github-release',
      },
    });

    expect(saveResponse.statusCode).toBe(200);
    const savedRow = await db.select().from(schema.settings).where(eq(schema.settings.key, 'update_center_k3s_config_v1')).get();
    expect(savedRow?.value).toContain('metapi-deploy-helper.ai.svc.cluster.local');

    const statusResponse = await app.inject({
      method: 'GET',
      url: '/api/update-center/status',
    });

    expect(statusResponse.statusCode).toBe(200);
    const expectedReminder = resolveUpdateReminderCandidate({
      currentVersion,
      helper: {
        imageTag: helperStatus.imageTag,
        imageDigest: helperStatus.imageDigest,
      },
      githubRelease,
      dockerHubTag,
    });
    expect(expectedReminder).toBeTruthy();
    expect(statusResponse.json()).toMatchObject({
      currentVersion,
      config: {
        enabled: true,
        namespace: 'ai',
        releaseName: 'metapi',
        defaultDeploySource: 'github-release',
      },
      githubRelease: {
        normalizedVersion: '1.3.0',
      },
      dockerHubTag: {
        normalizedVersion: 'latest',
        displayVersion: 'latest @ sha256:efb2ee655386',
        digest: 'sha256:efb2ee6553866bd3268dcc54c02fa5f9789728c51ed4af63328aaba6da67df35',
      },
      dockerHubRecentTags: [
        {
          normalizedVersion: 'dev',
          displayVersion: 'dev @ sha256:aaaaaaaaaaaa',
          digest: 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        },
      ],
      helper: {
        ok: true,
        healthy: true,
        releaseName: 'metapi',
        imageDigest: 'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
        history: [
          {
            revision: '11',
            imageTag: 'main',
          },
        ],
      },
      runtime: {
        lastCheckedAt: expect.any(String),
        lastCheckError: null,
        lastResolvedSource: expectedReminder?.source,
        lastResolvedDisplayVersion: expectedReminder?.displayVersion,
        lastResolvedCandidateKey: expectedReminder?.candidateKey,
        lastNotifiedCandidateKey: null,
        lastNotifiedAt: null,
      },
    });
  });

  it('returns partial status when a single version source lookup fails', async () => {
    fetchLatestStableGitHubReleaseMock.mockRejectedValue(new Error('GitHub releases lookup timed out'));
    fetchDockerHubTagCandidatesMock.mockResolvedValue({
      primary: {
        source: 'docker-hub-tag',
        rawVersion: '1.3.1',
        normalizedVersion: '1.3.1',
        url: null,
      },
      recentNonStable: [],
    });
    getUpdateCenterHelperStatusMock.mockResolvedValue({
      ok: true,
      releaseName: 'metapi',
      namespace: 'ai',
      revision: '12',
      imageRepository: '1467078763/metapi',
      imageTag: '1.2.3',
      healthy: true,
    });

    await saveValidConfig();

    const statusResponse = await app.inject({
      method: 'GET',
      url: '/api/update-center/status',
    });

    expect(statusResponse.statusCode).toBe(200);
    expect(statusResponse.json()).toMatchObject({
      githubRelease: null,
      dockerHubTag: {
        normalizedVersion: '1.3.1',
      },
      helper: {
        ok: true,
        healthy: true,
      },
    });
  });

  it('rejects malformed config, deploy, and rollback payloads at the route boundary', async () => {
    const invalidConfigResponse = await app.inject({
      method: 'PUT',
      url: '/api/update-center/config',
      payload: {
        enabled: 'false',
      },
    });
    expect(invalidConfigResponse.statusCode).toBe(400);
    expect(invalidConfigResponse.json()).toMatchObject({
      success: false,
      message: 'Invalid enabled. Expected boolean.',
    });

    const invalidDeployResponse = await app.inject({
      method: 'POST',
      url: '/api/update-center/deploy',
      payload: {
        targetTag: 123,
      },
    });
    expect(invalidDeployResponse.statusCode).toBe(400);
    expect(invalidDeployResponse.json()).toMatchObject({
      success: false,
      message: 'Invalid targetTag. Expected string.',
    });

    const invalidRollbackResponse = await app.inject({
      method: 'POST',
      url: '/api/update-center/rollback',
      payload: {
        targetRevision: 123,
      },
    });
    expect(invalidRollbackResponse.statusCode).toBe(400);
    expect(invalidRollbackResponse.json()).toMatchObject({
      success: false,
      message: 'Invalid targetRevision. Expected string.',
    });
  });

  it('rejects invalid update-center source enums at the route boundary', async () => {
    const invalidConfigResponse = await app.inject({
      method: 'PUT',
      url: '/api/update-center/config',
      payload: {
        defaultDeploySource: 'nightly',
      },
    });
    expect(invalidConfigResponse.statusCode).toBe(400);
    expect(invalidConfigResponse.json()).toMatchObject({
      success: false,
      message: 'Invalid defaultDeploySource. Expected docker-hub-tag/github-release.',
    });

    const invalidDeployResponse = await app.inject({
      method: 'POST',
      url: '/api/update-center/deploy',
      payload: {
        source: 'nightly',
      },
    });
    expect(invalidDeployResponse.statusCode).toBe(400);
    expect(invalidDeployResponse.json()).toMatchObject({
      success: false,
      message: 'Invalid source. Expected docker-hub-tag/github-release.',
    });
  });

  it('uses the shared config helper token when request-time env lookup is unavailable', async () => {
    fetchLatestStableGitHubReleaseMock.mockResolvedValue({
      source: 'github-release',
      rawVersion: 'v1.3.0',
      normalizedVersion: '1.3.0',
      url: 'https://github.com/cita-777/metapi/releases/tag/v1.3.0',
    });
    getUpdateCenterHelperStatusMock.mockResolvedValue({
      ok: true,
      releaseName: 'metapi',
      namespace: 'ai',
      revision: '12',
      imageRepository: '1467078763/metapi',
      imageTag: '1.2.3',
      healthy: true,
    });

    await saveValidConfig();

    const originalEnvToken = process.env.DEPLOY_HELPER_TOKEN;
    delete process.env.DEPLOY_HELPER_TOKEN;
    (appConfig as typeof appConfig & { deployHelperToken?: string }).deployHelperToken = 'helper-token';

    try {
      const statusResponse = await app.inject({
        method: 'GET',
        url: '/api/update-center/status',
      });

      expect(statusResponse.statusCode).toBe(200);
      expect(getUpdateCenterHelperStatusMock).toHaveBeenCalledWith(
        expect.objectContaining({
          helperBaseUrl: 'http://metapi-deploy-helper.ai.svc.cluster.local:9850',
        }),
        'helper-token',
      );
      expect(statusResponse.json()).toMatchObject({
        helper: {
          ok: true,
          healthy: true,
        },
      });
    } finally {
      process.env.DEPLOY_HELPER_TOKEN = originalEnvToken;
      delete (appConfig as typeof appConfig & { deployHelperToken?: string }).deployHelperToken;
    }
  });

  it('reuses the persisted snapshot for status requests instead of re-querying external sources', async () => {
    await saveValidConfig();
    await saveUpdateCenterRuntimeState({
      lastCheckedAt: '2026-03-31 09:00:00',
      lastCheckError: null,
      lastResolvedSource: 'docker-hub-tag',
      lastResolvedDisplayVersion: 'latest @ sha256:efb2ee655386',
      lastResolvedCandidateKey: 'docker-hub-tag:latest@sha256:efb2ee6553866bd3268dcc54c02fa5f9789728c51ed4af63328aaba6da67df35',
      lastNotifiedCandidateKey: null,
      lastNotifiedAt: null,
      statusSnapshot: {
        githubRelease: {
          source: 'github-release',
          rawVersion: 'v1.3.0',
          normalizedVersion: '1.3.0',
          url: 'https://github.com/cita-777/metapi/releases/tag/v1.3.0',
          tagName: 'v1.3.0',
          digest: null,
          displayVersion: '1.3.0',
          publishedAt: '2026-03-31T09:00:00Z',
        },
        dockerHubTag: {
          source: 'docker-hub-tag',
          rawVersion: 'latest',
          normalizedVersion: 'latest',
          tagName: 'latest',
          digest: 'sha256:efb2ee6553866bd3268dcc54c02fa5f9789728c51ed4af63328aaba6da67df35',
          displayVersion: 'latest @ sha256:efb2ee655386',
          publishedAt: '2026-03-31T09:00:00Z',
          url: null,
        },
        dockerHubRecentTags: [
          {
            source: 'docker-hub-tag',
            rawVersion: 'dev',
            normalizedVersion: 'dev',
            tagName: 'dev',
            digest: 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            displayVersion: 'dev @ sha256:aaaaaaaaaaaa',
            publishedAt: '2026-03-31T09:05:00Z',
            url: null,
          },
        ],
        helper: {
          ok: true,
          releaseName: 'metapi',
          namespace: 'ai',
          revision: '12',
          imageRepository: '1467078763/metapi',
          imageTag: 'latest',
          imageDigest: 'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
          healthy: true,
          error: null,
          history: [],
        },
      },
    });

    const statusResponse = await app.inject({
      method: 'GET',
      url: '/api/update-center/status',
    });

    expect(statusResponse.statusCode).toBe(200);
    expect(statusResponse.json()).toMatchObject({
      githubRelease: {
        normalizedVersion: '1.3.0',
      },
      dockerHubTag: {
        displayVersion: 'latest @ sha256:efb2ee655386',
      },
      dockerHubRecentTags: [
        {
          normalizedVersion: 'dev',
          displayVersion: 'dev @ sha256:aaaaaaaaaaaa',
        },
      ],
      helper: {
        imageDigest: 'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
      },
      runtime: {
        lastCheckedAt: '2026-03-31 09:00:00',
      },
    });
    expect(fetchLatestStableGitHubReleaseMock).not.toHaveBeenCalled();
    expect(fetchDockerHubTagCandidatesMock).not.toHaveBeenCalled();
    expect(getUpdateCenterHelperStatusMock).not.toHaveBeenCalled();
  });

  it('forces a live refresh on manual check and persists the refreshed snapshot', async () => {
    await saveValidConfig();
    fetchLatestStableGitHubReleaseMock.mockResolvedValue({
      source: 'github-release',
      rawVersion: 'v1.3.1',
      normalizedVersion: '1.3.1',
      tagName: 'v1.3.1',
      displayVersion: '1.3.1',
      publishedAt: '2026-03-31T10:00:00Z',
      url: 'https://github.com/cita-777/metapi/releases/tag/v1.3.1',
    });
    fetchDockerHubTagCandidatesMock.mockResolvedValue({
      primary: {
        source: 'docker-hub-tag',
        rawVersion: 'latest',
        normalizedVersion: 'latest',
        tagName: 'latest',
        digest: 'sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
        displayVersion: 'latest @ sha256:dddddddddddd',
        publishedAt: '2026-03-31T10:00:00Z',
        url: null,
      },
      recentNonStable: [
        {
          source: 'docker-hub-tag',
          rawVersion: 'dev-20260417-f67ade2',
          normalizedVersion: 'dev-20260417-f67ade2',
          tagName: 'dev-20260417-f67ade2',
          digest: 'sha256:abababababababababababababababababababababababababababababababab',
          displayVersion: 'dev-20260417-f67ade2 @ sha256:abababababab',
          publishedAt: '2026-03-31T10:05:00Z',
          url: null,
        },
      ],
    });
    getUpdateCenterHelperStatusMock.mockResolvedValue({
      ok: true,
      releaseName: 'metapi',
      namespace: 'ai',
      revision: '13',
      imageRepository: '1467078763/metapi',
      imageTag: 'latest',
      imageDigest: 'sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
      healthy: true,
      history: [],
    });

    const checkResponse = await app.inject({
      method: 'POST',
      url: '/api/update-center/check',
    });

    expect(checkResponse.statusCode).toBe(200);
    expect(checkResponse.json()).toMatchObject({
      githubRelease: {
        normalizedVersion: '1.3.1',
      },
      dockerHubTag: {
        digest: 'sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
      },
      dockerHubRecentTags: [
        {
          normalizedVersion: 'dev-20260417-f67ade2',
          digest: 'sha256:abababababababababababababababababababababababababababababababab',
        },
      ],
      helper: {
        revision: '13',
      },
      runtime: {
        lastCheckedAt: expect.any(String),
      },
    });
    expect(fetchLatestStableGitHubReleaseMock).toHaveBeenCalledTimes(1);
    expect(fetchDockerHubTagCandidatesMock).toHaveBeenCalledTimes(1);
    expect(getUpdateCenterHelperStatusMock).toHaveBeenCalledTimes(1);
    expect(await loadUpdateCenterRuntimeState()).toEqual(expect.objectContaining({
      lastResolvedSource: 'github-release',
      lastResolvedDisplayVersion: '1.3.1',
      statusSnapshot: {
        githubRelease: expect.objectContaining({
          normalizedVersion: '1.3.1',
        }),
        dockerHubTag: expect.objectContaining({
          digest: 'sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
        }),
        dockerHubRecentTags: [
          expect.objectContaining({
            normalizedVersion: 'dev-20260417-f67ade2',
          }),
        ],
        helper: expect.objectContaining({
          revision: '13',
        }),
      },
    }));
  });

  it('dedupes deploy requests while a task is already running', async () => {
    const currentVersion = (await import('../../services/updateCenterVersionService.js')).getCurrentRuntimeVersion();
    const targetVersion = getNextPatchVersion(currentVersion);
    await saveValidConfig();

    let releaseDeploy: (() => void) | null = null;
    const deployGate = new Promise<void>((resolve) => {
      releaseDeploy = resolve;
    });

    streamUpdateCenterDeployMock.mockImplementation(async (_input: unknown, onLog?: (message: string) => void) => {
      onLog?.('Running helm upgrade');
      await deployGate;
      onLog?.('Deployment complete');
      return {
        success: true,
        targetSource: 'github-release',
        targetTag: targetVersion,
        targetDigest: null,
        previousRevision: '12',
        finalRevision: '13',
        rolledBack: false,
        logLines: ['Running helm upgrade', 'Deployment complete'],
      };
    });

    const firstResponse = await app.inject({
      method: 'POST',
      url: '/api/update-center/deploy',
      payload: {
        source: 'github-release',
        targetVersion,
      },
    });

    const secondResponse = await app.inject({
      method: 'POST',
      url: '/api/update-center/deploy',
      payload: {
        source: 'github-release',
        targetVersion,
      },
    });

    expect(firstResponse.statusCode).toBe(202);
    expect(secondResponse.statusCode).toBe(202);

    const firstBody = firstResponse.json() as { task?: { id: string }; reused?: boolean };
    const secondBody = secondResponse.json() as { task?: { id: string }; reused?: boolean };
    expect(firstBody.task?.id).toBeTruthy();
    expect(secondBody.task?.id).toBe(firstBody.task?.id);
    expect(secondBody.reused).toBe(true);

    releaseDeploy?.();
  });

  it('rejects deploy requests when the update center is disabled', async () => {
    const saveResponse = await app.inject({
      method: 'PUT',
      url: '/api/update-center/config',
      payload: {
        enabled: false,
        helperBaseUrl: 'http://metapi-deploy-helper.ai.svc.cluster.local:9850',
        namespace: 'ai',
        releaseName: 'metapi',
        chartRef: 'oci://ghcr.io/cita-777/charts/metapi',
        imageRepository: '1467078763/metapi',
        githubReleasesEnabled: true,
        dockerHubTagsEnabled: true,
        defaultDeploySource: 'github-release',
      },
    });
    expect(saveResponse.statusCode).toBe(200);

    const deployResponse = await app.inject({
      method: 'POST',
      url: '/api/update-center/deploy',
      payload: {
        source: 'github-release',
        targetVersion: '1.3.0',
      },
    });

    expect(deployResponse.statusCode).toBe(400);
    expect(deployResponse.json()).toMatchObject({
      success: false,
      message: 'update center is disabled',
    });
  });

  it('forwards digest-aware deploy requests to the helper client', async () => {
    await saveValidConfig();

    streamUpdateCenterDeployMock.mockResolvedValue({
      success: true,
      targetSource: 'docker-hub-tag',
      targetTag: 'latest',
      targetDigest: 'sha256:efb2ee6553866bd3268dcc54c02fa5f9789728c51ed4af63328aaba6da67df35',
      previousRevision: '13',
      finalRevision: '14',
      rolledBack: false,
      logLines: ['Running helm upgrade'],
    });

    const deployResponse = await app.inject({
      method: 'POST',
      url: '/api/update-center/deploy',
      payload: {
        source: 'docker-hub-tag',
        targetTag: 'latest',
        targetDigest: 'sha256:efb2ee6553866bd3268dcc54c02fa5f9789728c51ed4af63328aaba6da67df35',
      },
    });

    expect(deployResponse.statusCode).toBe(202);
    expect(streamUpdateCenterDeployMock).toHaveBeenCalledWith(expect.objectContaining({
      source: 'docker-hub-tag',
      targetTag: 'latest',
      targetDigest: 'sha256:efb2ee6553866bd3268dcc54c02fa5f9789728c51ed4af63328aaba6da67df35',
    }), expect.any(Function));
  });

  it('rejects deploy requests when the target image is already running', async () => {
    await saveValidConfig();

    getUpdateCenterHelperStatusMock.mockResolvedValue({
      ok: true,
      releaseName: 'metapi',
      namespace: 'ai',
      revision: '17',
      imageRepository: '1467078763/metapi',
      imageTag: 'latest',
      imageDigest: 'sha256:efb2ee6553866bd3268dcc54c02fa5f9789728c51ed4af63328aaba6da67df35',
      healthy: true,
    });

    const deployResponse = await app.inject({
      method: 'POST',
      url: '/api/update-center/deploy',
      payload: {
        source: 'docker-hub-tag',
        targetTag: 'latest',
        targetDigest: 'sha256:efb2ee6553866bd3268dcc54c02fa5f9789728c51ed4af63328aaba6da67df35',
      },
    });

    expect(deployResponse.statusCode).toBe(409);
    expect(deployResponse.json()).toMatchObject({
      success: false,
      message: 'target image is already running',
    });
    expect(streamUpdateCenterDeployMock).not.toHaveBeenCalled();
  });

  it('does not reject a same-version deploy when the requested digest differs from the running image', async () => {
    await saveValidConfig();

    getUpdateCenterHelperStatusMock.mockResolvedValue({
      ok: true,
      releaseName: 'metapi',
      namespace: 'ai',
      revision: '17',
      imageRepository: '1467078763/metapi',
      imageTag: '1.2.3',
      imageDigest: 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      healthy: true,
    });
    streamUpdateCenterDeployMock.mockResolvedValue({
      success: true,
      targetSource: 'docker-hub-tag',
      targetTag: '1.2.3',
      targetDigest: 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      previousRevision: '17',
      finalRevision: '18',
      rolledBack: false,
      logLines: ['Running helm upgrade'],
    });

    const deployResponse = await app.inject({
      method: 'POST',
      url: '/api/update-center/deploy',
      payload: {
        source: 'docker-hub-tag',
        targetTag: '1.2.3',
        targetDigest: 'sha256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',
      },
    });

    expect(deployResponse.statusCode).toBe(202);
    expect(streamUpdateCenterDeployMock).toHaveBeenCalledWith(expect.objectContaining({
      targetTag: '1.2.3',
      targetDigest: 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    }), expect.any(Function));
  });

  it('normalizes invalid target digests to null before forwarding the deploy request', async () => {
    await saveValidConfig();

    streamUpdateCenterDeployMock.mockResolvedValue({
      success: true,
      targetSource: 'docker-hub-tag',
      targetTag: 'latest',
      targetDigest: null,
      previousRevision: '13',
      finalRevision: '14',
      rolledBack: false,
      logLines: ['Running helm upgrade'],
    });

    const deployResponse = await app.inject({
      method: 'POST',
      url: '/api/update-center/deploy',
      payload: {
        source: 'docker-hub-tag',
        targetTag: 'latest',
        targetDigest: 'not-a-real-digest',
      },
    });

    expect(deployResponse.statusCode).toBe(202);
    expect(streamUpdateCenterDeployMock).toHaveBeenCalledWith(expect.objectContaining({
      targetTag: 'latest',
      targetDigest: null,
    }), expect.any(Function));
  });

  it('starts rollback tasks for explicit revision requests', async () => {
    await saveValidConfig();

    streamUpdateCenterRollbackMock.mockResolvedValue({
      success: true,
      targetRevision: '11',
      finalRevision: '15',
      logLines: ['Running helm rollback'],
    });

    const rollbackResponse = await app.inject({
      method: 'POST',
      url: '/api/update-center/rollback',
      payload: {
        targetRevision: '11',
      },
    });

    expect(rollbackResponse.statusCode).toBe(202);
    expect(streamUpdateCenterRollbackMock).toHaveBeenCalledWith(expect.objectContaining({
      targetRevision: '11',
    }), expect.any(Function));
  });

  it('streams deployment logs for known tasks and rejects unknown task ids', async () => {
    await saveValidConfig();

    const missingResponse = await app.inject({
      method: 'GET',
      url: '/api/update-center/tasks/missing-task/stream',
    });

    expect(missingResponse.statusCode).toBe(404);

    streamUpdateCenterDeployMock.mockImplementation(async (_input: unknown, onLog?: (message: string) => void) => {
      onLog?.('Resolving target version');
      onLog?.('Waiting for rollout');
      return {
        success: true,
        targetSource: 'docker-hub-tag',
        targetTag: '1.3.1',
        targetDigest: null,
        previousRevision: '13',
        finalRevision: '14',
        rolledBack: false,
        logLines: ['Resolving target version', 'Waiting for rollout'],
      };
    });

    const deployResponse = await app.inject({
      method: 'POST',
      url: '/api/update-center/deploy',
      payload: {
        source: 'docker-hub-tag',
        targetVersion: '1.3.1',
      },
    });

    const deployBody = deployResponse.json() as { task: { id: string } };

    const task = await waitForBackgroundTaskToReachTerminalState(
      (taskId) => getBackgroundTask?.(taskId) ?? null,
      deployBody.task.id,
    );
    expect(task).toMatchObject({ status: 'succeeded' });

    expect(getBackgroundTask?.(deployBody.task.id)?.logs).toEqual(expect.arrayContaining([
      expect.objectContaining({ message: 'Resolving target version' }),
      expect.objectContaining({ message: 'Waiting for rollout' }),
    ]));

    const streamResponse = await app.inject({
      method: 'GET',
      url: `/api/update-center/tasks/${deployBody.task.id}/stream`,
    });

    expect(streamResponse.statusCode).toBe(200);
    expect(streamResponse.headers['content-type']).toContain('text/event-stream');
    expect(streamResponse.body).toContain('event: log');
    expect(streamResponse.body).toContain('Resolving target version');
    expect(streamResponse.body).toContain('Waiting for rollout');
    expect(streamResponse.body).toContain('event: done');
  });
});
