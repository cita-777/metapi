import { afterEach, describe, expect, it } from 'vitest';
import { mkdir, readFile, readlink, rm, symlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import {
  clearUpdateCenterPendingState,
  getDefaultUpdateCenterRuntimeState,
  loadUpdateCenterPendingState,
  loadUpdateCenterRuntimeState,
  normalizeUpdateCenterPendingState,
  patchUpdateCenterRuntimeState,
  readUpdateCenterPointer,
  saveUpdateCenterPendingState,
  saveUpdateCenterRuntimeState,
} from './updateCenterRuntimeStateService.js';

const roots: string[] = [];

async function tempRoot(): Promise<string> {
  const root = join(tmpdir(), `metapi-update-center-state-${Date.now()}-${Math.random().toString(16).slice(2)}`);
  roots.push(root);
  await mkdir(root, { recursive: true });
  return root;
}

afterEach(async () => {
  while (roots.length) await rm(roots.pop()!, { recursive: true, force: true });
});

describe('updateCenterRuntimeStateService', () => {
  it('returns a filesystem-backed default state', async () => {
    const root = await tempRoot();
    expect(await loadUpdateCenterRuntimeState(root)).toEqual(getDefaultUpdateCenterRuntimeState());
  });

  it('writes state atomically and preserves normalized update metadata', async () => {
    const root = await tempRoot();
    await saveUpdateCenterRuntimeState({
      updateState: 'restarting',
      currentVersion: '1.3.0',
      restartPending: true,
      taskId: 'task-1',
    }, root);
    const state = await loadUpdateCenterRuntimeState(root);
    expect(state).toMatchObject({ updateState: 'restarting', currentVersion: '1.3.0', restartPending: true, taskId: 'task-1' });
    expect(JSON.parse(await readFile(join(root, 'state.json'), 'utf8'))).toMatchObject({ updateState: 'restarting' });
    expect(await patchUpdateCenterRuntimeState({ updateState: 'healthy', restartPending: false }, root)).toMatchObject({ updateState: 'healthy', restartPending: false });
  });

  it('persists and clears pending transactions', async () => {
    const root = await tempRoot();
    await saveUpdateCenterPendingState({
      schemaVersion: 1,
      taskId: 'task-2',
      targetVersion: '1.4.0',
      previousVersion: '1.3.0',
      phase: 'restarting',
      rollbackBudget: 1,
      createdAt: '2026-09-04T00:00:00.000Z',
      updatedAt: '2026-09-04T00:00:00.000Z',
      reason: 'install',
    }, root);
    expect(await loadUpdateCenterPendingState(root)).toMatchObject({ taskId: 'task-2', targetVersion: '1.4.0' });
    await clearUpdateCenterPendingState(root);
    expect(await loadUpdateCenterPendingState(root)).toBeNull();
  });

  it('rejects pointers that escape the runtime root', async () => {
    const root = await tempRoot();
    await symlink('../../etc', join(root, 'current'));
    expect(readUpdateCenterPointer(root, 'current')).toBeNull();
  });

  it('rejects pointers that traverse a symlinked release directory', async () => {
    const root = await tempRoot();
    await mkdir(join(root, 'releases'), { recursive: true });
    await symlink('/tmp', join(root, 'releases', 'escape'));
    await symlink('releases/escape', join(root, 'current'));
    expect(readUpdateCenterPointer(root, 'current')).toBeNull();
  });

  it('accepts only a canonical release pointer whose manifest matches its directory', async () => {
    const root = await tempRoot();
    const release = join(root, 'releases', '1.2.3');
    await mkdir(release, { recursive: true });
    await writeFile(join(release, 'release.json'), JSON.stringify({
      schemaVersion: 1,
      version: '1.2.3',
      channel: 'stable',
      platform: 'linux',
      arch: process.arch === 'arm64' ? 'arm64' : 'amd64',
      nodeMajor: 25,
      entrypoint: 'dist/server/index.js',
      migrationEntrypoint: 'dist/server/db/migrate.js',
    }));
    await symlink('releases/1.2.3', join(root, 'current'));
    expect(readUpdateCenterPointer(root, 'current')).toBe(release);
    expect(await readlink(join(root, 'current'))).toBe('releases/1.2.3');

    await writeFile(join(release, 'release.json'), JSON.stringify({ version: '1.2.4' }));
    expect(readUpdateCenterPointer(root, 'current')).toBeNull();
  });

  it('rejects non-canonical pointer text even when it resolves to a valid release', async () => {
    const root = await tempRoot();
    const release = join(root, 'releases', '1.2.3');
    await mkdir(join(release, 'dist/server'), { recursive: true });
    await writeFile(join(release, 'release.json'), JSON.stringify({
      schemaVersion: 1,
      version: '1.2.3',
      channel: 'stable',
      platform: 'linux',
      arch: process.arch === 'arm64' ? 'arm64' : 'amd64',
      nodeMajor: 25,
      entrypoint: 'dist/server/index.js',
      migrationEntrypoint: 'dist/server/db/migrate.js',
    }));
    await symlink('releases/./1.2.3', join(root, 'current'));
    expect(readUpdateCenterPointer(root, 'current')).toBeNull();
  });

  it('rejects malformed pending schema, reason, and budget values', () => {
    const base = {
      schemaVersion: 1,
      taskId: 'task-1',
      targetVersion: '1.2.3',
      previousVersion: null,
      phase: 'restarting',
      rollbackBudget: 1,
      createdAt: '2026-09-04T00:00:00.000Z',
      updatedAt: '2026-09-04T00:00:00.000Z',
      reason: 'install',
    };
    expect(normalizeUpdateCenterPendingState(base)).toMatchObject({ schemaVersion: 1, rollbackBudget: 1 });
    expect(normalizeUpdateCenterPendingState({ ...base, schemaVersion: '1' })).toBeNull();
    expect(normalizeUpdateCenterPendingState({ ...base, reason: 'unknown' })).toBeNull();
    expect(normalizeUpdateCenterPendingState({ ...base, rollbackBudget: '1' })).toBeNull();
    expect(normalizeUpdateCenterPendingState({ ...base, previousVersion: undefined })).toBeNull();
    expect(normalizeUpdateCenterPendingState({ ...base, targetVersion: '1.2.3+build.1' })).toBeNull();
    expect(normalizeUpdateCenterPendingState({ ...base, createdAt: '' })).toBeNull();
    expect(normalizeUpdateCenterPendingState({ ...base, updatedAt: 'not-a-timestamp' })).toBeNull();
    expect(normalizeUpdateCenterPendingState({ ...base, rollbackBudget: 2 })).toBeNull();
  });

  it('removes a corrupted pending file instead of retrying it forever', async () => {
    const root = await tempRoot();
    await writeFile(join(root, 'pending.json'), '{broken');
    await expect(loadUpdateCenterPendingState(root)).resolves.toBeNull();
    await expect(readFile(join(root, 'pending.json'), 'utf8')).rejects.toThrow();
  });

  it('removes a pending file with invalid persisted fields', async () => {
    const root = await tempRoot();
    await writeFile(join(root, 'pending.json'), JSON.stringify({
      schemaVersion: 1,
      taskId: 'task-1',
      targetVersion: '1.2.3+build.1',
      previousVersion: null,
      phase: 'restarting',
      rollbackBudget: 1,
      createdAt: '2026-09-04T00:00:00.000Z',
      updatedAt: '2026-09-04T00:00:00.000Z',
      reason: 'install',
    }));
    await expect(loadUpdateCenterPendingState(root)).resolves.toBeNull();
    await expect(readFile(join(root, 'pending.json'), 'utf8')).rejects.toThrow();
  });

  it('removes a pending path that is not a regular file', async () => {
    const root = await tempRoot();
    await mkdir(join(root, 'pending.json'), { recursive: true });
    await writeFile(join(root, 'pending.json', 'stale'), 'stale');
    await expect(loadUpdateCenterPendingState(root)).resolves.toBeNull();
    await expect(readFile(join(root, 'pending.json', 'stale'), 'utf8')).rejects.toThrow();
  });

  it('removes a corrupted state file before returning defaults', async () => {
    const root = await tempRoot();
    await writeFile(join(root, 'state.json'), '{broken');
    await expect(loadUpdateCenterRuntimeState(root)).resolves.toEqual(getDefaultUpdateCenterRuntimeState());
    await expect(readFile(join(root, 'state.json'), 'utf8')).rejects.toThrow();
  });
});
