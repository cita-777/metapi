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
    });

    await expect(loadUpdateCenterRuntimeState()).resolves.toEqual({
      lastCheckedAt: '2026-03-30 20:30:00',
      lastCheckError: null,
      lastResolvedSource: 'docker-hub-tag',
      lastResolvedDisplayVersion: 'latest @ sha256:efb2ee655386',
      lastResolvedCandidateKey: 'docker-hub-tag:latest@sha256:efb2ee6553866bd3268dcc54c02fa5f9789728c51ed4af63328aaba6da67df35',
      lastNotifiedCandidateKey: 'docker-hub-tag:latest@sha256:efb2ee6553866bd3268dcc54c02fa5f9789728c51ed4af63328aaba6da67df35',
      lastNotifiedAt: '2026-03-30 20:31:00',
    });
  });
});
