import { createServer } from 'node:http';
import { mkdir, readFile, readlink, rm, symlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { afterEach, describe, expect, it } from 'vitest';

import {
  bootstrapRuntime,
  finalizePendingFailure,
  markPendingHealthCheck,
  normalizePending,
  pruneRuntimeReleases,
  readPending,
  reconcilePending,
  resolveSymlinkPointer,
  switchPointers,
  waitForHealth,
} from './docker-runner.mjs';

const roots: string[] = [];

function runtimeArchitecture(): 'amd64' | 'arm64' {
  return process.arch === 'arm64' ? 'arm64' : 'amd64';
}

function runtimeNodeMajor(): number {
  return Number.parseInt(process.versions.node.split('.')[0] || '0', 10);
}

function releaseManifest(version: string, entrypoint = 'server.js') {
  return {
    schemaVersion: 1,
    version,
    channel: 'stable',
    platform: 'linux',
    arch: runtimeArchitecture(),
    nodeMajor: runtimeNodeMajor(),
    entrypoint,
    migrationEntrypoint: 'migrate.js',
  };
}

async function tempRoot(): Promise<string> {
  const root = join(tmpdir(), `metapi-runner-${Date.now()}-${Math.random().toString(16).slice(2)}`);
  roots.push(root);
  await mkdir(root, { recursive: true });
  return root;
}

afterEach(async () => {
  while (roots.length) await rm(roots.pop()!, { recursive: true, force: true });
});

describe('docker runner', () => {
  it('does not remove an existing update lock during bootstrap startup', async () => {
    const root = await tempRoot();
    const bootstrap = join(root, 'bootstrap');
    const runtime = join(root, 'runtime');
    await mkdir(bootstrap, { recursive: true });
    await writeFile(join(bootstrap, 'release.json'), JSON.stringify(releaseManifest('1.0.0')));
    await writeFile(join(bootstrap, 'server.js'), 'ok');
    await writeFile(join(bootstrap, 'migrate.js'), 'ok');
    await mkdir(runtime, { recursive: true });
    const lockPath = join(runtime, '.update.lock');
    await writeFile(lockPath, JSON.stringify({ taskId: 'active-update', pid: process.pid, token: 'active-token' }));

    bootstrapRuntime(runtime, bootstrap);

    await expect(readFile(lockPath, 'utf8')).resolves.toContain('active-update');
    const runnerSource = await readFile(new URL('./docker-runner.mjs', import.meta.url), 'utf8');
    expect(runnerSource).not.toMatch(/rmSync\(\s*join\(runtime,\s*['"]\.update\.lock['"]\s*\)/);
  });

  it('bootstraps an empty runtime and replaces an invalid existing release', async () => {
    const root = await tempRoot();
    const bootstrap = join(root, 'bootstrap');
    const runtime = join(root, 'runtime');
    await mkdir(bootstrap, { recursive: true });
    await writeFile(join(bootstrap, 'release.json'), JSON.stringify(releaseManifest('1.0.0')));
    await writeFile(join(bootstrap, 'server.js'), 'ok');
    await writeFile(join(bootstrap, 'migrate.js'), 'ok');

    const first = bootstrapRuntime(runtime, bootstrap);
    expect(first).toBe(join(runtime, 'releases', '1.0.0'));
    expect(await readlink(join(runtime, 'current'))).toBe('releases/1.0.0');

    await rm(join(runtime, 'releases', '1.0.0'), { recursive: true, force: true });
    await mkdir(join(runtime, 'releases', '1.0.0'), { recursive: true });
    await writeFile(join(runtime, 'releases', '1.0.0', 'stale.txt'), 'remove me');
    const second = bootstrapRuntime(runtime, bootstrap);
    expect(second).toBe(join(runtime, 'releases', '1.0.0'));
    expect(await readFile(join(second, 'server.js'), 'utf8')).toBe('ok');
    await expect(readFile(join(second, 'stale.txt'), 'utf8')).rejects.toThrow();
    expect(resolveSymlinkPointer(runtime, 'current')).toBe(second);
  });

  it('keeps pointer targets inside releases and switches current/previous atomically', async () => {
    const root = await tempRoot();
    await mkdir(join(root, 'releases', '1.0.0'), { recursive: true });
    await mkdir(join(root, 'releases', '1.1.0'), { recursive: true });
    await writeFile(join(root, 'releases', '1.0.0', 'release.json'), JSON.stringify(releaseManifest('1.0.0')));
    await writeFile(join(root, 'releases', '1.1.0', 'release.json'), JSON.stringify(releaseManifest('1.1.0')));
    await writeFile(join(root, 'releases', '1.0.0', 'server.js'), 'ok');
    await writeFile(join(root, 'releases', '1.0.0', 'migrate.js'), 'ok');
    await writeFile(join(root, 'releases', '1.1.0', 'server.js'), 'ok');
    await writeFile(join(root, 'releases', '1.1.0', 'migrate.js'), 'ok');
    switchPointers(root, join(root, 'releases', '1.0.0'));
    switchPointers(root, join(root, 'releases', '1.1.0'), join(root, 'releases', '1.0.0'));
    expect(await readlink(join(root, 'current'))).toBe('releases/1.1.0');
    expect(await readlink(join(root, 'previous'))).toBe('releases/1.0.0');
    expect(resolveSymlinkPointer(root, 'current')).toBe(join(root, 'releases', '1.1.0'));
  });

  it('promotes a newer image bootstrap without replacing a newer runtime release', async () => {
    const root = await tempRoot();
    const bootstrap = join(root, 'bootstrap');
    const runtime = join(root, 'runtime');
    await mkdir(bootstrap, { recursive: true });
    await mkdir(join(runtime, 'releases', '1.0.0'), { recursive: true });
    await writeFile(join(bootstrap, 'release.json'), JSON.stringify(releaseManifest('1.1.0')));
    await writeFile(join(bootstrap, 'server.js'), 'new');
    await writeFile(join(bootstrap, 'migrate.js'), 'ok');
    await writeFile(join(runtime, 'releases', '1.0.0', 'release.json'), JSON.stringify(releaseManifest('1.0.0')));
    await writeFile(join(runtime, 'releases', '1.0.0', 'server.js'), 'old');
    await writeFile(join(runtime, 'releases', '1.0.0', 'migrate.js'), 'ok');
    await symlink('releases/1.0.0', join(runtime, 'current'));

    const selected = bootstrapRuntime(runtime, bootstrap);
    expect(selected).toBe(join(runtime, 'releases', '1.1.0'));
    expect(await readlink(join(runtime, 'current'))).toBe('releases/1.1.0');
    expect(await readlink(join(runtime, 'previous'))).toBe('releases/1.0.0');
    expect(JSON.parse(await readFile(join(runtime, 'pending.json'), 'utf8'))).toMatchObject({
      targetVersion: '1.1.0',
      previousVersion: '1.0.0',
      reason: 'bootstrap',
      rollbackBudget: 1,
    });
  });

  it('drops malformed pending transactions and accepts only the complete schema', async () => {
    const root = await tempRoot();
    await writeFile(join(root, 'pending.json'), '{not-json');
    expect(readPending(root)).toBeNull();
    await expect(readFile(join(root, 'pending.json'), 'utf8')).rejects.toThrow();
    expect(normalizePending({
      schemaVersion: 1,
      taskId: 'task',
      targetVersion: '1.1.0',
      previousVersion: null,
      phase: 'restarting',
      rollbackBudget: 1,
      reason: 'install',
      createdAt: '2026-09-04T00:00:00.000Z',
      updatedAt: '2026-09-04T00:00:00.000Z',
    })).toMatchObject({ rollbackBudget: 1 });
    expect(normalizePending({
      taskId: 'task',
      targetVersion: '1.1.0',
      previousVersion: null,
      phase: 'restarting',
      rollbackBudget: 1,
      reason: 'install',
      createdAt: '2026-09-04T00:00:00.000Z',
      updatedAt: '2026-09-04T00:00:00.000Z',
    })).toBeNull();
    expect(normalizePending({
      schemaVersion: 1,
      taskId: 'task',
      targetVersion: '01.1.0',
      previousVersion: null,
      phase: 'restarting',
      rollbackBudget: 1,
      reason: 'install',
      createdAt: '2026-09-04T00:00:00.000Z',
      updatedAt: '2026-09-04T00:00:00.000Z',
    })).toBeNull();
    expect(normalizePending({
      schemaVersion: 1,
      taskId: 'task',
      targetVersion: '1.1.0',
      previousVersion: null,
      phase: 'restarting',
      rollbackBudget: '1',
      reason: 'install',
      createdAt: '2026-09-04T00:00:00.000Z',
      updatedAt: '2026-09-04T00:00:00.000Z',
    })).toBeNull();
    expect(normalizePending({
      schemaVersion: 1,
      taskId: 123,
      targetVersion: '1.1.0',
      previousVersion: null,
      phase: 'restarting',
      rollbackBudget: 1,
      reason: 'install',
      createdAt: '2026-09-04T00:00:00.000Z',
      updatedAt: '2026-09-04T00:00:00.000Z',
    })).toBeNull();
    expect(normalizePending({
      schemaVersion: 1,
      taskId: 'task',
      targetVersion: '1.1.0+build.1',
      previousVersion: null,
      phase: 'restarting',
      rollbackBudget: 1,
      reason: 'install',
      createdAt: '2026-09-04T00:00:00.000Z',
      updatedAt: '2026-09-04T00:00:00.000Z',
    })).toBeNull();
    expect(normalizePending({
      schemaVersion: 1,
      taskId: 'task',
      targetVersion: '1.1.0',
      previousVersion: null,
      phase: 'restarting',
      rollbackBudget: 2,
      reason: 'install',
      createdAt: '2026-09-04T00:00:00.000Z',
      updatedAt: '2026-09-04T00:00:00.000Z',
    })).toBeNull();
    expect(normalizePending({
      schemaVersion: 1,
      taskId: 'task',
      targetVersion: '1.1.0',
      previousVersion: null,
      phase: 'restarting',
      rollbackBudget: 1,
      reason: 'install',
      createdAt: 123,
      updatedAt: '2026-09-04T00:00:00.000Z',
    })).toBeNull();
  });

  it('rejects truncated manifest numeric fields', async () => {
    const root = await tempRoot();
    const bootstrap = join(root, 'bootstrap');
    await mkdir(bootstrap, { recursive: true });
    await writeFile(join(bootstrap, 'release.json'), JSON.stringify({
      ...releaseManifest('1.0.0'),
      nodeMajor: 22.9,
    }));
    await writeFile(join(bootstrap, 'server.js'), 'ok');
    await writeFile(join(bootstrap, 'migrate.js'), 'ok');
    expect(() => bootstrapRuntime(join(root, 'runtime'), bootstrap)).toThrow(/nodeMajor/);
  });

  it('marks a pending transaction as health-check without losing rollback metadata', async () => {
    const root = await tempRoot();
    const pending = normalizePending({
      schemaVersion: 1,
      taskId: 'health-check-task',
      targetVersion: '1.2.0',
      previousVersion: '1.1.0',
      phase: 'restarting',
      rollbackBudget: 0,
      rollbackApplied: true,
      reason: 'manual-rollback',
      createdAt: '2026-09-04T00:00:00.000Z',
      updatedAt: '2026-09-04T00:00:00.000Z',
    });
    expect(pending).not.toBeNull();
    await writeFile(join(root, 'pending.json'), JSON.stringify(pending));

    const updated = markPendingHealthCheck(root, pending!);
    expect(updated).toMatchObject({
      schemaVersion: 1,
      taskId: 'health-check-task',
      targetVersion: '1.2.0',
      previousVersion: '1.1.0',
      phase: 'health-check',
      rollbackBudget: 0,
      rollbackApplied: true,
      reason: 'manual-rollback',
    });
    expect(Date.parse(updated.updatedAt)).toBeGreaterThanOrEqual(Date.parse(updated.createdAt));
    expect(JSON.parse(await readFile(join(root, 'pending.json'), 'utf8'))).toMatchObject({
      phase: 'health-check',
      rollbackBudget: 0,
      rollbackApplied: true,
    });
  });

  it('rejects marking a pending transaction when another task replaced it', async () => {
    const root = await tempRoot();
    const original = normalizePending({
      schemaVersion: 1,
      taskId: 'original-task',
      targetVersion: '1.2.0',
      previousVersion: '1.1.0',
      phase: 'restarting',
      rollbackBudget: 1,
      reason: 'install',
      createdAt: '2026-09-04T00:00:00.000Z',
      updatedAt: '2026-09-04T00:00:00.000Z',
    });
    const replacement = { ...original, taskId: 'replacement-task' };
    await writeFile(join(root, 'pending.json'), JSON.stringify(replacement));

    expect(() => markPendingHealthCheck(root, original!)).toThrow('pending update transaction changed during startup');
    expect(JSON.parse(await readFile(join(root, 'pending.json'), 'utf8'))).toMatchObject({
      taskId: 'replacement-task',
      phase: 'restarting',
    });
  });

  it('clears an exhausted pending transaction before the runner exits', async () => {
    const root = await tempRoot();
    const current = join(root, 'releases', '1.2.0');
    const previous = join(root, 'releases', '1.1.0');
    for (const [releasePath, version] of [[current, '1.2.0'], [previous, '1.1.0']] as const) {
      await mkdir(releasePath, { recursive: true });
      await writeFile(join(releasePath, 'release.json'), JSON.stringify(releaseManifest(version)));
      await writeFile(join(releasePath, 'server.js'), 'ok');
      await writeFile(join(releasePath, 'migrate.js'), 'ok');
    }
    await symlink('releases/1.2.0', join(root, 'current'));
    await symlink('releases/1.1.0', join(root, 'previous'));
    const pending = normalizePending({
      schemaVersion: 1,
      taskId: 'exhausted-task',
      targetVersion: '1.1.0',
      previousVersion: '1.2.0',
      phase: 'restarting',
      rollbackBudget: 0,
      rollbackApplied: true,
      reason: 'install',
      createdAt: '2026-09-04T00:00:00.000Z',
      updatedAt: '2026-09-04T00:00:00.000Z',
    });
    await writeFile(join(root, 'pending.json'), JSON.stringify(pending));

    finalizePendingFailure(root, pending, 'previous release failed health check');

    await expect(readFile(join(root, 'pending.json'), 'utf8')).rejects.toThrow();
    expect(JSON.parse(await readFile(join(root, 'state.json'), 'utf8'))).toMatchObject({
      updateState: 'failed',
      currentVersion: '1.2.0',
      previousVersion: '1.1.0',
      taskId: 'exhausted-task',
      restartPending: false,
      lastError: 'previous release failed health check',
    });
  });

  it('removes malformed pending directories and dangling links', async () => {
    const root = await tempRoot();
    await mkdir(join(root, 'pending.json'), { recursive: true });
    await writeFile(join(root, 'pending.json', 'stale'), 'stale');
    expect(readPending(root)).toBeNull();
    await expect(readFile(join(root, 'pending.json', 'stale'), 'utf8')).rejects.toThrow();

    await symlink(join(root, 'missing-target'), join(root, 'pending.json'));
    expect(readPending(root)).toBeNull();
    await expect(readlink(join(root, 'pending.json'))).rejects.toThrow();
  });

  it('accepts only a ready health response for the requested version', async () => {
    const server = createServer((request, response) => {
      if (request.url === '/healthz') {
        response.setHeader('content-type', 'application/json');
        response.end(JSON.stringify({ status: 'ok', ready: true, version: '1.1.0' }));
        return;
      }
      response.statusCode = 404;
      response.end();
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const address = server.address();
    const port = typeof address === 'object' && address ? address.port : 0;
    try {
      await expect(waitForHealth('1.1.0', port, 500, 10)).resolves.toMatchObject({ ready: true, version: '1.1.0' });
      await expect(waitForHealth('1.2.0', port, 30, 10)).rejects.toThrow('health version mismatch');
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it('does not accept a pending transaction for an unrelated current release', async () => {
    const root = await tempRoot();
    const current = join(root, 'releases', '1.0.0');
    await mkdir(current, { recursive: true });
    await writeFile(join(current, 'release.json'), JSON.stringify(releaseManifest('1.0.0')));
    await writeFile(join(current, 'server.js'), 'ok');
    await writeFile(join(current, 'migrate.js'), 'ok');
    await symlink('releases/1.0.0', join(root, 'current'));
    const result = reconcilePending(root, current, normalizePending({
      schemaVersion: 1,
      taskId: 'task',
      targetVersion: '1.2.0',
      previousVersion: '0.9.0',
      phase: 'restarting',
      rollbackBudget: 1,
      reason: 'install',
      createdAt: '2026-09-04T00:00:00.000Z',
      updatedAt: '2026-09-04T00:00:00.000Z',
    }));
    expect(result.invalid).toBe(true);
    expect(result.pending).toBeNull();
  });

  it('completes a persisted rollback transaction after interruption before pointer switch', async () => {
    const root = await tempRoot();
    const candidate = join(root, 'releases', '1.2.0');
    const previous = join(root, 'releases', '1.1.0');
    await mkdir(candidate, { recursive: true });
    await mkdir(previous, { recursive: true });
    for (const [releasePath, version] of [[candidate, '1.2.0'], [previous, '1.1.0']] as const) {
      await writeFile(join(releasePath, 'release.json'), JSON.stringify(releaseManifest(version)));
      await writeFile(join(releasePath, 'server.js'), 'ok');
      await writeFile(join(releasePath, 'migrate.js'), 'ok');
    }
    await symlink('releases/1.2.0', join(root, 'current'));
    await symlink('releases/1.1.0', join(root, 'previous'));

    const pending = normalizePending({
      schemaVersion: 1,
      taskId: 'rollback-task',
      targetVersion: '1.1.0',
      previousVersion: '1.2.0',
      phase: 'restarting',
      rollbackBudget: 0,
      rollbackApplied: true,
      reason: 'install',
      createdAt: '2026-09-04T00:00:00.000Z',
      updatedAt: '2026-09-04T00:00:00.000Z',
    });
    const result = reconcilePending(root, candidate, pending);

    expect(result.pending).toMatchObject({ targetVersion: '1.1.0', rollbackBudget: 0, rollbackApplied: true });
    expect(result.current).toBe(previous);
    expect(await readlink(join(root, 'current'))).toBe('releases/1.1.0');
    expect(await readlink(join(root, 'previous'))).toBe('releases/1.2.0');
  });

  it('turns an unreadable current manifest into an invalid transaction instead of crashing', async () => {
    const root = await tempRoot();
    const current = join(root, 'releases', '1.0.0');
    await mkdir(current, { recursive: true });
    await writeFile(join(current, 'release.json'), '{broken');
    const result = reconcilePending(root, current, normalizePending({
      schemaVersion: 1,
      taskId: 'task',
      targetVersion: '1.1.0',
      previousVersion: '1.0.0',
      phase: 'restarting',
      rollbackBudget: 1,
      reason: 'install',
      createdAt: '2026-09-04T00:00:00.000Z',
      updatedAt: '2026-09-04T00:00:00.000Z',
    }));
    expect(result.invalid).toBe(true);
    expect(result.pending).toBeNull();
    expect(result.error).toContain('release manifest');
  });

  it('rejects a runtime releases symlink before bootstrap writes outside the runtime', async () => {
    const root = await tempRoot();
    const bootstrap = join(root, 'bootstrap');
    const outside = join(root, 'outside');
    await mkdir(bootstrap, { recursive: true });
    await mkdir(outside, { recursive: true });
    await writeFile(join(bootstrap, 'release.json'), JSON.stringify(releaseManifest('1.0.0')));
    await writeFile(join(bootstrap, 'server.js'), 'ok');
    await writeFile(join(bootstrap, 'migrate.js'), 'ok');
    await mkdir(root, { recursive: true });
    await symlink(outside, join(root, 'releases'));
    expect(() => bootstrapRuntime(root, bootstrap)).toThrow('runtime releases directory must not be a symbolic link');
  });

  it('rejects a non-canonical current pointer', async () => {
    const root = await tempRoot();
    const release = join(root, 'releases', '1.0.0');
    await mkdir(release, { recursive: true });
    await writeFile(join(release, 'release.json'), JSON.stringify(releaseManifest('1.0.0')));
    await writeFile(join(release, 'server.js'), 'ok');
    await writeFile(join(release, 'migrate.js'), 'ok');
    await symlink('releases/./1.0.0', join(root, 'current'));
    expect(resolveSymlinkPointer(root, 'current')).toBeNull();
  });

  it('rejects existing invalid current or previous pointers before bootstrap can overwrite them', async () => {
    for (const pointer of ['current', 'previous'] as const) {
      const root = await tempRoot();
      const bootstrap = join(root, 'bootstrap');
      await mkdir(bootstrap, { recursive: true });
      await writeFile(join(bootstrap, 'release.json'), JSON.stringify(releaseManifest('1.0.0')));
      await writeFile(join(bootstrap, 'server.js'), 'ok');
      await writeFile(join(bootstrap, 'migrate.js'), 'ok');
      await mkdir(join(root, 'releases'), { recursive: true });
      await mkdir(join(root, 'staging'), { recursive: true });
      const pointerPath = join(root, pointer);
      await writeFile(pointerPath, 'do not overwrite');

      expect(() => bootstrapRuntime(root, bootstrap)).toThrow(`runtime ${pointer} pointer is invalid or unsafe`);
      await expect(readFile(pointerPath, 'utf8')).resolves.toBe('do not overwrite');
    }
  });

  it('rejects dangling runtime pointers before bootstrap can repair them', async () => {
    const root = await tempRoot();
    const bootstrap = join(root, 'bootstrap');
    await mkdir(bootstrap, { recursive: true });
    await writeFile(join(bootstrap, 'release.json'), JSON.stringify(releaseManifest('1.0.0')));
    await writeFile(join(bootstrap, 'server.js'), 'ok');
    await writeFile(join(bootstrap, 'migrate.js'), 'ok');
    await mkdir(join(root, 'releases'), { recursive: true });
    await mkdir(join(root, 'staging'), { recursive: true });
    await symlink('releases/missing', join(root, 'current'));

    expect(() => bootstrapRuntime(root, bootstrap)).toThrow('runtime current pointer is invalid or unsafe');
    await expect(readlink(join(root, 'current'))).resolves.toBe('releases/missing');
  });

  it('prunes unprotected old releases while retaining current and previous', async () => {
    const root = await tempRoot();
    for (const version of ['1.0.0', '1.1.0', '1.2.0', '1.3.0']) {
      const release = join(root, 'releases', version);
      await mkdir(release, { recursive: true });
      await writeFile(join(release, 'release.json'), JSON.stringify(releaseManifest(version)));
      await writeFile(join(release, 'server.js'), 'ok');
      await writeFile(join(release, 'migrate.js'), 'ok');
    }
    await symlink('releases/1.3.0', join(root, 'current'));
    await symlink('releases/1.2.0', join(root, 'previous'));
    expect(pruneRuntimeReleases(root)).toEqual(['1.1.0', '1.0.0']);
    await expect(readFile(join(root, 'releases', '1.2.0', 'server.js'), 'utf8')).resolves.toBe('ok');
    await expect(readFile(join(root, 'releases', '1.3.0', 'server.js'), 'utf8')).resolves.toBe('ok');
    await expect(readFile(join(root, 'releases', '1.1.0', 'server.js'), 'utf8')).rejects.toThrow();
  });
});
