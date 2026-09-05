import { afterEach, describe, expect, it } from 'vitest';
import * as tar from 'tar';
import { createHash } from 'node:crypto';
import { copyFile, mkdir, readFile, readlink, rm, symlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import {
  acquireUpdateCenterLock,
  downloadUpdateCenterAsset,
  extractUpdateCenterArchive,
  getUpdateCenterRuntimeCapability,
  installUpdateCenterRelease,
  listInstalledUpdateCenterVersions,
  rollbackPendingUpdateCenter,
  rollbackUpdateCenter,
  UpdateCenterLocalUpdateError,
  validateUpdateCenterBundle,
} from './updateCenterLocalUpdateService.js';
import { clearUpdateCenterPendingState, loadUpdateCenterPendingState, loadUpdateCenterRuntimeState } from './updateCenterRuntimeStateService.js';

const temporaryRoots: string[] = [];

async function makeTempRoot(): Promise<string> {
  const root = join(tmpdir(), `metapi-update-center-local-${Date.now()}-${Math.random().toString(16).slice(2)}`);
  temporaryRoots.push(root);
  await mkdir(root, { recursive: true });
  return root;
}

async function makeArchive(root: string, version: string, nodeMajor = 22): Promise<string> {
  const source = join(root, `source-${version}`);
  await mkdir(join(source, 'dist/server'), { recursive: true });
  await writeFile(join(source, 'dist/server/index.js'), `console.log(${JSON.stringify(version)});\n`);
  await writeFile(join(source, 'dist/server/migrate.js'), 'module.exports = {};\n');
  await writeFile(join(source, 'release.json'), JSON.stringify({
    schemaVersion: 1,
    version,
    channel: 'stable',
    platform: 'linux',
    arch: 'amd64',
    nodeMajor,
    entrypoint: 'dist/server/index.js',
    migrationEntrypoint: 'dist/server/migrate.js',
  }));
  const archive = join(root, `metapi-server-v${version}-linux-amd64.tar.gz`);
  await tar.c({ cwd: source, file: archive, gzip: true, portable: true }, ['.']);
  return archive;
}

afterEach(async () => {
  while (temporaryRoots.length) {
    await rm(temporaryRoots.pop()!, { recursive: true, force: true });
  }
});

describe('updateCenterLocalUpdateService', () => {
  it('allowlists HTTPS GitHub release hosts and rejects arbitrary URLs', async () => {
    const root = await makeTempRoot();
    const payload = Buffer.from('metapi');
    const digest = createHash('sha256').update(payload).digest('hex');
    let fetchCount = 0;
    const fetchImpl = async (url: string) => {
      fetchCount += 1;
      if (fetchCount === 1) return new Response(null, { status: 302, headers: { location: 'https://objects.githubusercontent.com/release' } });
      expect(url).toBe('https://objects.githubusercontent.com/release');
      return new Response(payload, { status: 200, headers: { 'content-length': String(payload.length) } });
    };
    await expect(downloadUpdateCenterAsset({
      url: 'https://github.com/release',
      destination: join(root, 'asset'),
      expectedSha256: digest,
      fetchImpl: fetchImpl as never,
    })).resolves.toMatchObject({ sha256: digest, size: payload.length });
    await expect(downloadUpdateCenterAsset({
      url: 'http://github.com/release',
      destination: join(root, 'insecure'),
      fetchImpl: fetchImpl as never,
    })).rejects.toMatchObject({ code: 'INSECURE_DOWNLOAD_URL' });
    await expect(downloadUpdateCenterAsset({
      url: 'https://evil.example/release',
      destination: join(root, 'evil'),
      fetchImpl: fetchImpl as never,
    })).rejects.toMatchObject({ code: 'UNTRUSTED_DOWNLOAD_HOST' });
  });

  it('rejects symbolic links in release archives before extraction', async () => {
    const root = await makeTempRoot();
    const source = join(root, 'source');
    await mkdir(source, { recursive: true });
    await symlink('/tmp', join(source, 'escape'));
    const archive = join(root, 'unsafe.tar.gz');
    await tar.c({ cwd: source, file: archive, gzip: true }, ['escape']);
    await expect(extractUpdateCenterArchive(archive, join(root, 'out'))).rejects.toMatchObject({
      code: 'UNSAFE_ARCHIVE',
    });
  });

  it('installs atomically, persists pending state, and rolls back to a local version', async () => {
    const root = await makeTempRoot();
    const runtime = join(root, 'runtime');
    const first = await makeArchive(root, '1.2.3');
    const second = await makeArchive(root, '1.3.0');
    const options = {
      runtimeDir: runtime,
      platform: 'linux' as const,
      architecture: 'amd64' as const,
      enforcePersistent: false,
      validateNativeModules: false,
    };
    await installUpdateCenterRelease({ ...options, archivePath: first, targetVersion: '1.2.3' });
    // A real runner clears the bootstrap transaction after health confirmation
    // before accepting another install request.
    await clearUpdateCenterPendingState(runtime);
    const result = await installUpdateCenterRelease({ ...options, archivePath: second, targetVersion: '1.3.0' });
    expect(await readlink(join(runtime, 'current'))).toBe('releases/1.3.0');
    expect(await readlink(join(runtime, 'previous'))).toBe('releases/1.2.3');
    expect(result.state.updateState).toBe('restarting');
    expect((await loadUpdateCenterPendingState(runtime))?.targetVersion).toBe('1.3.0');
    expect((await loadUpdateCenterRuntimeState(runtime)).restartPending).toBe(true);
    await clearUpdateCenterPendingState(runtime);
    await rollbackUpdateCenter({ ...options, targetVersion: '1.2.3' });
    expect(await readlink(join(runtime, 'current'))).toBe('releases/1.2.3');
    expect((await listInstalledUpdateCenterVersions(runtime)).filter((entry) => entry.current)).toHaveLength(1);
  });

  it('does not delete an already-installed release when a duplicate install is requested', async () => {
    const root = await makeTempRoot();
    const runtime = join(root, 'runtime');
    const archive = await makeArchive(root, '1.2.3');
    const options = {
      runtimeDir: runtime,
      archivePath: archive,
      targetVersion: '1.2.3',
      platform: 'linux' as const,
      architecture: 'amd64' as const,
      enforcePersistent: false,
      validateNativeModules: false,
    };

    await installUpdateCenterRelease(options);
    await clearUpdateCenterPendingState(runtime);
    await expect(installUpdateCenterRelease(options)).rejects.toMatchObject({ code: 'VERSION_ALREADY_INSTALLED' });
    expect(await readlink(join(runtime, 'current'))).toBe('releases/1.2.3');
    expect(await readFile(join(runtime, 'releases', '1.2.3', 'dist/server/index.js'), 'utf8')).toContain('1.2.3');
  });

  it('rejects a new install while a persisted restart transaction is pending', async () => {
    const root = await makeTempRoot();
    const runtime = join(root, 'runtime');
    const first = await makeArchive(root, '1.2.3');
    const second = await makeArchive(root, '1.3.0');
    const options = {
      runtimeDir: runtime,
      platform: 'linux' as const,
      architecture: 'amd64' as const,
      enforcePersistent: false,
      validateNativeModules: false,
    };

    await installUpdateCenterRelease({ ...options, archivePath: first, targetVersion: '1.2.3' });
    await expect(installUpdateCenterRelease({ ...options, archivePath: second, targetVersion: '1.3.0' })).rejects.toMatchObject({
      code: 'RESTART_PENDING',
    });
    expect((await loadUpdateCenterPendingState(runtime))?.targetVersion).toBe('1.2.3');
    expect(await readlink(join(runtime, 'current'))).toBe('releases/1.2.3');
  });

  it('refuses a second writer while the update lock is held', async () => {
    const root = await makeTempRoot();
    const release = await acquireUpdateCenterLock(root, 'first');
    await expect(acquireUpdateCenterLock(root, 'second')).rejects.toMatchObject({
      code: 'UPDATE_IN_PROGRESS',
    });
    await release();
  });

  it('reclaims a lock owned by a process that no longer exists', async () => {
    const root = await makeTempRoot();
    await writeFile(join(root, '.update.lock'), JSON.stringify({ pid: 999999, taskId: 'dead' }));
    const release = await acquireUpdateCenterLock(root, 'replacement');
    await release();
  });

  it('does not release a lock that has been replaced by another owner', async () => {
    const root = await makeTempRoot();
    const release = await acquireUpdateCenterLock(root, 'first');
    await writeFile(join(root, '.update.lock'), JSON.stringify({ taskId: 'second', pid: process.pid, token: 'replacement' }));
    await release();
    expect(await readFile(join(root, '.update.lock'), 'utf8')).toContain('replacement');
  });

  it('does not overwrite runtime state when a concurrent install cannot acquire the lock', async () => {
    const root = await makeTempRoot();
    const runtime = join(root, 'runtime');
    const archive = await makeArchive(root, '1.3.0');
    const release = await acquireUpdateCenterLock(runtime, 'first');
    await expect(installUpdateCenterRelease({
      runtimeDir: runtime,
      archivePath: archive,
      targetVersion: '1.3.0',
      platform: 'linux',
      architecture: 'amd64',
      enforcePersistent: false,
      validateNativeModules: false,
    })).rejects.toMatchObject({ code: 'UPDATE_IN_PROGRESS' });
    expect((await loadUpdateCenterRuntimeState(runtime)).updateState).toBe('idle');
    await release();
  });

  it('reports unsupported capability when persistence is not opted in', async () => {
    const root = await makeTempRoot();
    const capability = await getUpdateCenterRuntimeCapability({
      runtimeDir: root,
      platform: 'linux',
      architecture: 'amd64',
      persistent: false,
    });
    expect(capability.supported).toBe(false);
    expect(capability.reason).toContain('persistent');
  });

  it('reports an unsafe runtime layout before writable checks', async () => {
    const root = await makeTempRoot();
    const outside = join(root, 'outside');
    await mkdir(outside, { recursive: true });
    const runtime = join(root, 'runtime');
    await mkdir(runtime, { recursive: true });
    await symlink(outside, join(runtime, 'releases'));

    await expect(installUpdateCenterRelease({
      runtimeDir: runtime,
      archivePath: await makeArchive(root, '1.2.3'),
      targetVersion: '1.2.3',
      platform: 'linux',
      architecture: 'amd64',
      enforcePersistent: false,
      validateNativeModules: false,
    })).rejects.toMatchObject({ code: 'RUNTIME_PATH_UNSAFE' });
    await expect(listInstalledUpdateCenterVersions(runtime)).resolves.toEqual([]);
  });

  it('rejects existing invalid current or previous pointers instead of overwriting them', async () => {
    for (const pointer of ['current', 'previous'] as const) {
      const root = await makeTempRoot();
      const runtime = join(root, 'runtime');
      await mkdir(join(runtime, 'releases'), { recursive: true });
      await mkdir(join(runtime, 'staging'), { recursive: true });
      const pointerPath = join(runtime, pointer);
      await writeFile(pointerPath, 'do not overwrite');

      await expect(installUpdateCenterRelease({
        runtimeDir: runtime,
        archivePath: await makeArchive(root, '1.2.3'),
        targetVersion: '1.2.3',
        platform: 'linux',
        architecture: 'amd64',
        enforcePersistent: false,
        validateNativeModules: false,
      })).rejects.toMatchObject({ code: 'RUNTIME_PATH_UNSAFE' });
      await expect(readFile(pointerPath, 'utf8')).resolves.toBe('do not overwrite');
    }
  });

  it('reports platform and architecture failures before persistence checks', async () => {
    const root = await makeTempRoot();
    await expect(installUpdateCenterRelease({
      runtimeDir: join(root, 'runtime'),
      platform: 'darwin',
      architecture: 'amd64',
      validateNativeModules: false,
    })).rejects.toMatchObject({ code: 'UNSUPPORTED_PLATFORM' });
  });

  it('validates manifest entrypoint and Node major', async () => {
    const root = await makeTempRoot();
    const bundle = join(root, 'bundle');
    await mkdir(join(bundle, 'dist/server'), { recursive: true });
    await writeFile(join(bundle, 'dist/server/index.js'), '');
    await writeFile(join(bundle, 'dist/server/migrate.js'), '');
    await writeFile(join(bundle, 'release.json'), JSON.stringify({
      schemaVersion: 1,
      version: '1.2.3',
      channel: 'stable',
      platform: 'linux',
      arch: 'amd64',
      nodeMajor: 99,
      entrypoint: 'dist/server/index.js',
      migrationEntrypoint: 'dist/server/migrate.js',
    }));
    await expect(validateUpdateCenterBundle({
      bundleDir: bundle,
      architecture: 'amd64',
      expectedNodeMajor: 22,
      validateNativeModules: false,
    })).rejects.toMatchObject({ code: 'NODE_VERSION_MISMATCH' });

    await writeFile(join(bundle, 'release.json'), JSON.stringify({
      schemaVersion: 1.9,
      version: '1.2.3',
      channel: 'stable',
      platform: 'linux',
      arch: 'amd64',
      nodeMajor: 22,
      entrypoint: 'dist/server/index.js',
      migrationEntrypoint: 'dist/server/migrate.js',
    }));
    await expect(validateUpdateCenterBundle({
      bundleDir: bundle,
      architecture: 'amd64',
      expectedNodeMajor: 22,
      validateNativeModules: false,
    })).rejects.toMatchObject({ code: 'INVALID_MANIFEST' });

    for (const nodeMajor of [22.5, '22foo']) {
      await writeFile(join(bundle, 'release.json'), JSON.stringify({
        schemaVersion: 1,
        version: '1.2.3',
        channel: 'stable',
        platform: 'linux',
        arch: 'amd64',
        nodeMajor,
        entrypoint: 'dist/server/index.js',
        migrationEntrypoint: 'dist/server/migrate.js',
      }));
      await expect(validateUpdateCenterBundle({
        bundleDir: bundle,
        architecture: 'amd64',
        expectedNodeMajor: 22,
        validateNativeModules: false,
      })).rejects.toMatchObject({ code: 'INVALID_MANIFEST' });
    }
  });

  it('rejects a symlinked bundle root or manifest before reading it', async () => {
    const root = await makeTempRoot();
    const realBundle = join(root, 'real-bundle');
    const linkedBundle = join(root, 'linked-bundle');
    await mkdir(realBundle, { recursive: true });
    await writeFile(join(realBundle, 'release.json'), '{}');
    await symlink(realBundle, linkedBundle);

    await expect(validateUpdateCenterBundle({
      bundleDir: linkedBundle,
      architecture: 'amd64',
      expectedNodeMajor: 22,
      validateNativeModules: false,
    })).rejects.toMatchObject({ code: 'UNSAFE_ARCHIVE' });

    const manifestTarget = join(root, 'manifest-outside.json');
    const regularBundle = join(root, 'regular-bundle');
    await mkdir(regularBundle, { recursive: true });
    await writeFile(manifestTarget, '{}');
    await symlink(manifestTarget, join(regularBundle, 'release.json'));
    await expect(validateUpdateCenterBundle({
      bundleDir: regularBundle,
      architecture: 'amd64',
      expectedNodeMajor: 22,
      validateNativeModules: false,
    })).rejects.toMatchObject({ code: 'UNSAFE_ARCHIVE' });
  });

  it('loads a bundled better-sqlite3 native addon before installation', async () => {
    const root = await makeTempRoot();
    const bundle = join(root, 'bundle-native');
    const addonDirectory = join(bundle, 'node_modules/better-sqlite3/build/Release');
    await mkdir(join(bundle, 'dist/server'), { recursive: true });
    await mkdir(addonDirectory, { recursive: true });
    await writeFile(join(bundle, 'dist/server/index.js'), '');
    await writeFile(join(bundle, 'dist/server/migrate.js'), '');
    await copyFile(
      join(process.cwd(), 'node_modules/better-sqlite3/build/Release/better_sqlite3.node'),
      join(addonDirectory, 'better_sqlite3.node'),
    );
    await writeFile(join(bundle, 'release.json'), JSON.stringify({
      schemaVersion: 1,
      version: '1.2.3',
      channel: 'stable',
      platform: 'linux',
      arch: process.arch === 'arm64' ? 'arm64' : 'amd64',
      nodeMajor: Number.parseInt(process.versions.node.split('.')[0] || '0', 10),
      entrypoint: 'dist/server/index.js',
      migrationEntrypoint: 'dist/server/migrate.js',
    }));

    await expect(validateUpdateCenterBundle({
      bundleDir: bundle,
      architecture: process.arch === 'arm64' ? 'arm64' : 'amd64',
    })).resolves.toMatchObject({ version: '1.2.3' });
  });

  it('does not treat the archive checksum as the manifest payload checksum', async () => {
    const root = await makeTempRoot();
    const archive = await makeArchive(root, '1.2.3');
    const source = join(root, 'source-1.2.3');
    const archiveDigest = createHash('sha256').update(await readFile(archive)).digest('hex');
    await writeFile(join(source, 'release.json'), JSON.stringify({
      schemaVersion: 1,
      version: '1.2.3',
      channel: 'stable',
      platform: 'linux',
      arch: 'amd64',
      nodeMajor: 22,
      entrypoint: 'dist/server/index.js',
      migrationEntrypoint: 'dist/server/migrate.js',
      artifactName: 'metapi-server-v1.2.3-linux-amd64.tar.gz',
      artifactSha256: archiveDigest,
    }));
    await tar.c({ cwd: source, file: archive, gzip: true, portable: true }, ['.']);

    await expect(installUpdateCenterRelease({
      runtimeDir: join(root, 'runtime'),
      archivePath: archive,
      targetVersion: '1.2.3',
      platform: 'linux',
      architecture: 'amd64',
      enforcePersistent: false,
      validateNativeModules: false,
      expectedNodeMajor: 22,
    })).rejects.toMatchObject({ code: 'CHECKSUM_MISMATCH' });
  });

  it('revalidates a local bundle before a manual rollback', async () => {
    const root = await makeTempRoot();
    const runtime = join(root, 'runtime');
    const first = await makeArchive(root, '1.2.3');
    const second = await makeArchive(root, '1.3.0');
    const options = {
      runtimeDir: runtime,
      platform: 'linux' as const,
      architecture: 'amd64' as const,
      enforcePersistent: false,
      validateNativeModules: false,
    };
    await installUpdateCenterRelease({ ...options, archivePath: first, targetVersion: '1.2.3' });
    await clearUpdateCenterPendingState(runtime);
    await installUpdateCenterRelease({ ...options, archivePath: second, targetVersion: '1.3.0' });
    await clearUpdateCenterPendingState(runtime);
    await writeFile(join(runtime, 'releases', '1.2.3', 'release.json'), JSON.stringify({
      ...JSON.parse(await readFile(join(runtime, 'releases', '1.2.3', 'release.json'), 'utf8')),
      nodeMajor: 99,
    }));

    await expect(rollbackUpdateCenter({ ...options, targetVersion: '1.2.3' })).rejects.toMatchObject({
      code: 'NODE_VERSION_MISMATCH',
    });
    expect(await readlink(join(runtime, 'current'))).toBe('releases/1.3.0');
  });

  it('re-reads and validates the pending transaction while holding the rollback lock', async () => {
    const root = await makeTempRoot();
    const runtime = join(root, 'runtime');
    const first = await makeArchive(root, '1.2.3');
    const second = await makeArchive(root, '1.3.0');
    const options = {
      runtimeDir: runtime,
      platform: 'linux' as const,
      architecture: 'amd64' as const,
      enforcePersistent: false,
      validateNativeModules: false,
    };
    await installUpdateCenterRelease({ ...options, archivePath: first, targetVersion: '1.2.3' });
    await clearUpdateCenterPendingState(runtime);
    await installUpdateCenterRelease({ ...options, archivePath: second, targetVersion: '1.3.0' });
    expect(await loadUpdateCenterPendingState(runtime)).toBeTruthy();
    await expect(rollbackPendingUpdateCenter(new Error('candidate failed'), runtime)).resolves.toMatchObject({
      updateState: 'rolled_back',
      currentVersion: '1.2.3',
    });
    expect(await readlink(join(runtime, 'current'))).toBe('releases/1.2.3');
    expect(await readlink(join(runtime, 'previous'))).toBe('releases/1.3.0');
    expect(await loadUpdateCenterPendingState(runtime)).toBeNull();
  });

  it('does not overwrite an existing pending transaction during manual rollback', async () => {
    const root = await makeTempRoot();
    const runtime = join(root, 'runtime');
    const first = await makeArchive(root, '1.2.3');
    const second = await makeArchive(root, '1.3.0');
    const options = {
      runtimeDir: runtime,
      platform: 'linux' as const,
      architecture: 'amd64' as const,
      enforcePersistent: false,
      validateNativeModules: false,
    };
    await installUpdateCenterRelease({ ...options, archivePath: first, targetVersion: '1.2.3' });
    await clearUpdateCenterPendingState(runtime);
    await installUpdateCenterRelease({ ...options, archivePath: second, targetVersion: '1.3.0' });
    const pending = await loadUpdateCenterPendingState(runtime);
    await expect(rollbackUpdateCenter({ ...options, targetVersion: '1.2.3' })).rejects.toMatchObject({ code: 'RESTART_PENDING' });
    await expect(loadUpdateCenterPendingState(runtime)).resolves.toMatchObject({ taskId: pending?.taskId, targetVersion: '1.3.0' });
  });
});
