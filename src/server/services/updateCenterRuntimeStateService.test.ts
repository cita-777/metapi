import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

type DbModule = typeof import('../db/index.js');
type RuntimeStateModule = typeof import('./updateCenterRuntimeStateService.js');

describe('updateCenterRuntimeStateService', () => {
  let dataDir = '';
  let db: DbModule['db'];
  let schema: DbModule['schema'];
  let closeDbConnections: DbModule['closeDbConnections'];
  let loadUpdateCenterRuntimeState: RuntimeStateModule['loadUpdateCenterRuntimeState'];
  let saveUpdateCenterRuntimeState: RuntimeStateModule['saveUpdateCenterRuntimeState'];

  beforeAll(async () => {
    dataDir = mkdtempSync(join(tmpdir(), 'metapi-update-center-runtime-state-'));
    process.env.DATA_DIR = dataDir;

    await import('../db/migrate.js');
    const dbModule = await import('../db/index.js');
    const runtimeStateModule = await import('./updateCenterRuntimeStateService.js');

    db = dbModule.db;
    schema = dbModule.schema;
    closeDbConnections = dbModule.closeDbConnections;
    loadUpdateCenterRuntimeState = runtimeStateModule.loadUpdateCenterRuntimeState;
    saveUpdateCenterRuntimeState = runtimeStateModule.saveUpdateCenterRuntimeState;
  });

  beforeEach(async () => {
    await db.delete(schema.settings).run();
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

  it('returns an empty default state when nothing has been persisted yet', async () => {
    await expect(loadUpdateCenterRuntimeState()).resolves.toEqual({
      lastCheckedAt: null,
      lastCheckError: null,
      lastResolvedSource: null,
      lastResolvedDisplayVersion: null,
      lastResolvedCandidateKey: null,
      lastNotifiedCandidateKey: null,
      lastNotifiedAt: null,
      statusSnapshot: null,
    });
  });

  it('persists and reloads reminder runtime metadata', async () => {
    await saveUpdateCenterRuntimeState({
      lastCheckedAt: '2026-03-30 20:30:00',
      lastCheckError: null,
      lastResolvedSource: 'docker-hub-tag',
      lastResolvedDisplayVersion: 'latest @ sha256:efb2ee655386',
      lastResolvedCandidateKey: 'docker-hub-tag:latest@sha256:efb2ee6553866bd3268dcc54c02fa5f9789728c51ed4af63328aaba6da67df35',
      lastNotifiedCandidateKey: 'docker-hub-tag:latest@sha256:efb2ee6553866bd3268dcc54c02fa5f9789728c51ed4af63328aaba6da67df35',
      lastNotifiedAt: '2026-03-30 20:31:00',
      statusSnapshot: {
        githubRelease: {
          source: 'github-release',
          rawVersion: 'v1.3.0',
          normalizedVersion: '1.3.0',
          url: 'https://github.com/cita-777/metapi/releases/tag/v1.3.0',
          tagName: 'v1.3.0',
          digest: null,
          displayVersion: '1.3.0',
          publishedAt: '2026-03-30T20:30:00Z',
        },
        dockerHubTag: {
          source: 'docker-hub-tag',
          rawVersion: 'latest',
          normalizedVersion: 'latest',
          url: null,
          tagName: 'latest',
          digest: 'sha256:efb2ee6553866bd3268dcc54c02fa5f9789728c51ed4af63328aaba6da67df35',
          displayVersion: 'latest @ sha256:efb2ee655386',
          publishedAt: '2026-03-30T20:30:00Z',
        },
        dockerHubRecentTags: [
          {
            source: 'docker-hub-tag',
            rawVersion: 'dev',
            normalizedVersion: 'dev',
            url: null,
            tagName: 'dev',
            digest: 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            displayVersion: 'dev @ sha256:aaaaaaaaaaaa',
            publishedAt: '2026-03-30T20:35:00Z',
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
          error: undefined,
          history: [
            {
              revision: '11',
              updatedAt: '2026-03-29T20:00:00Z',
              status: 'superseded',
              description: 'Rollback to stable digest',
              imageRepository: '1467078763/metapi',
              imageTag: 'main',
              imageDigest: 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            },
          ],
        },
      },
    });

    await expect(loadUpdateCenterRuntimeState()).resolves.toEqual({
      lastCheckedAt: '2026-03-30 20:30:00',
      lastCheckError: null,
      lastResolvedSource: 'docker-hub-tag',
      lastResolvedDisplayVersion: 'latest @ sha256:efb2ee655386',
      lastResolvedCandidateKey: 'docker-hub-tag:latest@sha256:efb2ee6553866bd3268dcc54c02fa5f9789728c51ed4af63328aaba6da67df35',
      lastNotifiedCandidateKey: 'docker-hub-tag:latest@sha256:efb2ee6553866bd3268dcc54c02fa5f9789728c51ed4af63328aaba6da67df35',
      lastNotifiedAt: '2026-03-30 20:31:00',
      statusSnapshot: {
        githubRelease: {
          source: 'github-release',
          rawVersion: 'v1.3.0',
          normalizedVersion: '1.3.0',
          url: 'https://github.com/cita-777/metapi/releases/tag/v1.3.0',
          tagName: 'v1.3.0',
          digest: null,
          displayVersion: '1.3.0',
          publishedAt: '2026-03-30T20:30:00Z',
        },
        dockerHubTag: {
          source: 'docker-hub-tag',
          rawVersion: 'latest',
          normalizedVersion: 'latest',
          url: null,
          tagName: 'latest',
          digest: 'sha256:efb2ee6553866bd3268dcc54c02fa5f9789728c51ed4af63328aaba6da67df35',
          displayVersion: 'latest @ sha256:efb2ee655386',
          publishedAt: '2026-03-30T20:30:00Z',
        },
        dockerHubRecentTags: [
          {
            source: 'docker-hub-tag',
            rawVersion: 'dev',
            normalizedVersion: 'dev',
            url: null,
            tagName: 'dev',
            digest: 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            displayVersion: 'dev @ sha256:aaaaaaaaaaaa',
            publishedAt: '2026-03-30T20:35:00Z',
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
          error: undefined,
          history: [
            {
              revision: '11',
              updatedAt: '2026-03-29T20:00:00Z',
              status: 'superseded',
              description: 'Rollback to stable digest',
              imageRepository: '1467078763/metapi',
              imageTag: 'main',
              imageDigest: 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            },
          ],
        },
      },
    });
  });
});
