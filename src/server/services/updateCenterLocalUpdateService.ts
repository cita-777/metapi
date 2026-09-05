import { createHash, randomUUID } from 'node:crypto';
import { access, copyFile, lstat, mkdir, open, readdir, readFile, rename, rm, symlink, unlink, writeFile } from 'node:fs/promises';
import { constants as fsConstants, createReadStream, existsSync, realpathSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, isAbsolute, join, posix, relative, resolve } from 'node:path';
import { fetch, type RequestInit as UndiciRequestInit } from 'undici';
import { extract as tarExtract, list as tarList } from 'tar';

import {
  buildServerReleaseAssetName,
  fetchStableGitHubRelease,
  findChecksumsAsset,
  findServerReleaseAsset,
  getCurrentUpdateCenterArchitecture,
  parseStableSemVer,
  type UpdateCenterReleaseAsset,
  type UpdateCenterVersionCandidate,
} from './updateCenterVersionService.js';
import {
  clearUpdateCenterPendingState,
  ensureUpdateCenterRuntimeDirectories,
  isPathInside,
  isUpdateCenterRuntimePersistent,
  loadUpdateCenterPendingState,
  loadUpdateCenterRuntimeState,
  patchUpdateCenterRuntimeState,
  readUpdateCenterPointer,
  resolveUpdateCenterRuntimeDir,
  saveUpdateCenterPendingState,
  type UpdateCenterPendingPhase,
  type UpdateCenterPendingState,
  type UpdateCenterRuntimeState,
} from './updateCenterRuntimeStateService.js';

export const UPDATE_CENTER_MAX_DOWNLOAD_BYTES = 512 * 1024 * 1024;
export const UPDATE_CENTER_MAX_EXTRACTED_BYTES = 2 * 1024 * 1024 * 1024;
export const UPDATE_CENTER_MAX_ARCHIVE_ENTRIES = 100_000;
export const UPDATE_CENTER_MAX_REDIRECTS = 5;
export const UPDATE_CENTER_HEALTH_TIMEOUT_MS = 60_000;
export const UPDATE_CENTER_REQUIRED_NODE_MAJOR = 25;
export const UPDATE_CENTER_RELEASE_HOSTS = Object.freeze([
  'github.com',
  'api.github.com',
  'objects.githubusercontent.com',
  'release-assets.githubusercontent.com',
  'github-releases.githubusercontent.com',
]);

const RELEASE_HOST_SET = new Set(UPDATE_CENTER_RELEASE_HOSTS);
const UPDATE_LOCK_FILE = '.update.lock';
const MANIFEST_FILE = 'release.json';
const ALLOWED_TAR_METADATA_TYPES = new Set([
  'GlobalExtendedHeader',
  'ExtendedHeader',
  'NextFileHasLongPath',
  'NextFileHasLongLinkpath',
  'OldExtendedHeader',
]);
const requireFromBundle = createRequire(import.meta.url);

export type UpdateCenterRuntimeCapability = {
  supported: boolean;
  mode: 'local-bundle' | 'unsupported';
  reason: string | null;
  runtimeDir: string;
  architecture: 'amd64' | 'arm64' | null;
  platform: NodeJS.Platform;
  nodeMajor: number;
  persistent: boolean;
  writable: boolean;
  currentVersion: string | null;
};

export type UpdateCenterReleaseManifest = {
  schemaVersion: number;
  version: string;
  channel: 'stable';
  platform: 'linux';
  arch: 'amd64' | 'arm64';
  nodeMajor: number;
  entrypoint: string;
  migrationEntrypoint: string | null;
  artifactName: string | null;
  artifactSha256: string | null;
  gitSha: string | null;
};

export type UpdateCenterInstalledVersion = {
  version: string;
  path: string;
  manifest: UpdateCenterReleaseManifest;
  current: boolean;
  previous: boolean;
};

export type UpdateCenterDownloadProgress = {
  downloadedBytes: number;
  totalBytes: number | null;
};

export type UpdateCenterInstallInput = {
  targetVersion?: string;
  version?: string;
  candidate?: UpdateCenterVersionCandidate | null;
  asset?: UpdateCenterReleaseAsset | null;
  checksumAsset?: UpdateCenterReleaseAsset | null;
  expectedSha256?: string | null;
  archivePath?: string;
  runtimeDir?: string;
  taskId?: string;
  signal?: AbortSignal;
  expectedNodeMajor?: number;
  architecture?: 'amd64' | 'arm64';
  platform?: NodeJS.Platform;
  enforcePersistent?: boolean;
  validateNativeModules?: boolean;
  requireChecksum?: boolean;
  onProgress?: (progress: UpdateCenterDownloadProgress) => void;
};

export type UpdateCenterInstallResult = {
  success: true;
  taskId: string;
  targetVersion: string;
  previousVersion: string | null;
  releasePath: string;
  archiveSha256: string;
  restartRequired: true;
  state: UpdateCenterRuntimeState;
};

export type UpdateCenterRollbackInput = {
  targetVersion?: string;
  runtimeDir?: string;
  taskId?: string;
  platform?: NodeJS.Platform;
  architecture?: 'amd64' | 'arm64';
  enforcePersistent?: boolean;
  validateNativeModules?: boolean;
};

export type UpdateCenterRollbackResult = {
  success: true;
  taskId: string;
  targetVersion: string;
  previousVersion: string | null;
  restartRequired: true;
  state: UpdateCenterRuntimeState;
};

export class UpdateCenterLocalUpdateError extends Error {
  readonly code: string;
  readonly cause?: unknown;

  constructor(code: string, message: string, cause?: unknown) {
    super(message);
    this.name = 'UpdateCenterLocalUpdateError';
    this.code = code;
    this.cause = cause;
  }
}

export class UpdateCenterUpdateInProgressError extends UpdateCenterLocalUpdateError {
  readonly lockOwner: Record<string, unknown> | null;

  constructor(lockOwner: Record<string, unknown> | null) {
    super('UPDATE_IN_PROGRESS', 'another update is already in progress');
    this.name = 'UpdateCenterUpdateInProgressError';
    this.lockOwner = lockOwner;
  }
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {};
}

function nonEmptyString(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const normalized = value.trim();
  return normalized || null;
}

function normalizeSha256(value: unknown): string | null {
  const normalized = nonEmptyString(value)?.toLowerCase() || '';
  return /^[a-f0-9]{64}$/.test(normalized) ? normalized : null;
}

function normalizeTaskId(value: unknown): string {
  const normalized = nonEmptyString(value) || randomUUID();
  if (!/^[a-zA-Z0-9._-]{1,96}$/.test(normalized)) {
    throw new UpdateCenterLocalUpdateError('INVALID_TASK_ID', 'invalid update task id');
  }
  return normalized;
}

function nodeMajor(value = process.versions.node): number {
  const parsed = Number.parseInt(String(value).split('.')[0] || '', 10);
  return Number.isFinite(parsed) ? parsed : 0;
}

function formatError(error: unknown): string {
  if (error instanceof Error && error.message) return error.message;
  return String(error || 'update failed');
}

function isRedirect(status: number): boolean {
  return status >= 300 && status < 400;
}

export function isAllowedUpdateCenterHost(hostname: string): boolean {
  const normalized = hostname.trim().toLowerCase().replace(/\.$/, '');
  return RELEASE_HOST_SET.has(normalized);
}

export function validateUpdateCenterDownloadUrl(input: string | URL): URL {
  let url: URL;
  try {
    url = input instanceof URL ? new URL(input.href) : new URL(input);
  } catch (error) {
    throw new UpdateCenterLocalUpdateError('INVALID_DOWNLOAD_URL', 'release asset URL is invalid', error);
  }
  if (url.protocol !== 'https:') {
    throw new UpdateCenterLocalUpdateError('INSECURE_DOWNLOAD_URL', 'release asset URL must use HTTPS');
  }
  if (url.username || url.password || url.port) {
    throw new UpdateCenterLocalUpdateError('INVALID_DOWNLOAD_URL', 'release asset URL contains credentials or a custom port');
  }
  if (!isAllowedUpdateCenterHost(url.hostname)) {
    throw new UpdateCenterLocalUpdateError('UNTRUSTED_DOWNLOAD_HOST', `release asset host is not allowlisted: ${url.hostname}`);
  }
  return url;
}

async function readLockOwner(lockPath: string): Promise<Record<string, unknown> | null> {
  try {
    return asRecord(JSON.parse(await readFile(lockPath, 'utf8')));
  } catch {
    return null;
  }
}

export async function acquireUpdateCenterLock(
  runtimeDir: string,
  taskId: string,
): Promise<() => Promise<void>> {
  const root = resolveUpdateCenterRuntimeDir(runtimeDir);
  await mkdir(root, { recursive: true });
  const lockPath = join(root, UPDATE_LOCK_FILE);
  const lockToken = randomUUID();
  const lockOwner = { taskId, pid: process.pid, acquiredAt: new Date().toISOString(), token: lockToken };
  let handle;
  try {
    handle = await open(lockPath, 'wx', 0o600);
  } catch (error) {
    if ((error as NodeJS.ErrnoException)?.code === 'EEXIST') {
      const owner = await readLockOwner(lockPath);
      const ownerPid = typeof owner?.pid === 'number' ? Math.trunc(owner.pid) : 0;
      if (ownerPid > 0 && ownerPid !== process.pid) {
        let stale = false;
        try {
          process.kill(ownerPid, 0);
        } catch (probeError) {
          const code = (probeError as NodeJS.ErrnoException)?.code;
          stale = code === 'ESRCH' || code === 'EINVAL' || code === 'ERR_INVALID_ARG_TYPE';
        }
        if (stale) {
          await unlink(lockPath).catch(() => undefined);
          return acquireUpdateCenterLock(root, taskId);
        }
      }
      throw new UpdateCenterUpdateInProgressError(owner);
    }
    throw new UpdateCenterLocalUpdateError('LOCK_FAILED', 'unable to acquire update lock', error);
  }
  try {
    await handle.writeFile(JSON.stringify(lockOwner));
  } finally {
    await handle.close();
  }
  let released = false;
  return async () => {
    if (released) return;
    released = true;
    const owner = await readLockOwner(lockPath);
    if (owner?.token !== lockToken || owner.pid !== process.pid || owner.taskId !== taskId) return;
    await unlink(lockPath).catch(() => undefined);
  };
}

export async function withUpdateCenterLock<T>(
  runtimeDir: string,
  taskId: string,
  callback: () => Promise<T>,
): Promise<T> {
  const release = await acquireUpdateCenterLock(runtimeDir, taskId);
  try {
    return await callback();
  } finally {
    await release();
  }
}

async function assertWritableDirectory(root: string): Promise<boolean> {
  try {
    await mkdir(root, { recursive: true });
    await access(root, fsConstants.W_OK | fsConstants.X_OK);
    const probe = join(root, `.write-probe-${process.pid}-${Math.random().toString(16).slice(2)}`);
    await writeFile(probe, '', { mode: 0o600 });
    await unlink(probe);
    return true;
  } catch {
    return false;
  }
}

async function isSafeRuntimeLayout(root: string): Promise<boolean> {
  const paths = [root, join(root, 'releases'), join(root, 'staging')];
  for (const path of paths) {
    try {
      const details = await lstat(path);
      if (!details.isDirectory() || details.isSymbolicLink()) return false;
    } catch (error) {
      if ((error as NodeJS.ErrnoException)?.code !== 'ENOENT') return false;
    }
  }
  for (const pointer of ['current', 'previous'] as const) {
    const pointerPath = join(root, pointer);
    try {
      const details = await lstat(pointerPath);
      if (!details.isSymbolicLink() || !readUpdateCenterPointer(root, pointer)) return false;
    } catch (error) {
      if ((error as NodeJS.ErrnoException)?.code !== 'ENOENT') return false;
    }
  }
  return true;
}

function pointerVersion(root: string, pointer: 'current' | 'previous'): string | null {
  const target = readUpdateCenterPointer(root, pointer);
  if (!target) return null;
  const releasesRoot = resolve(root, 'releases');
  if (!isPathInside(releasesRoot, target)) return null;
  const relativeTarget = relative(releasesRoot, target).replaceAll('\\', '/');
  return parseStableSemVer(relativeTarget)?.normalized || null;
}

export function getUpdateCenterPointerVersion(runtimeDir: string, pointer: 'current' | 'previous' = 'current'): string | null {
  return pointerVersion(resolveUpdateCenterRuntimeDir(runtimeDir), pointer);
}

export const getCurrentLocalUpdateCenterVersion = (runtimeDir?: string): string | null =>
  pointerVersion(resolveUpdateCenterRuntimeDir(runtimeDir), 'current');

export async function getUpdateCenterRuntimeCapability(input?: {
  runtimeDir?: string;
  platform?: NodeJS.Platform;
  architecture?: string;
  persistent?: boolean;
}): Promise<UpdateCenterRuntimeCapability> {
  const runtimeDir = resolveUpdateCenterRuntimeDir(input?.runtimeDir);
  const platform = input?.platform || process.platform;
  const architecture = getCurrentUpdateCenterArchitecture(input?.architecture || process.arch);
  const persistent = input?.persistent ?? isUpdateCenterRuntimePersistent(runtimeDir);
  const safeLayout = await isSafeRuntimeLayout(runtimeDir);
  const writable = safeLayout && await assertWritableDirectory(runtimeDir);
  const runningNodeMajor = nodeMajor();
  let reason: string | null = null;
  if (platform !== 'linux') reason = 'automatic server updates are supported only on Linux';
  else if (!architecture) reason = 'current architecture is not supported (amd64 or arm64 required)';
  else if (!persistent) reason = 'runtime directory is not marked as a persistent volume';
  else if (!safeLayout) reason = 'runtime directory contains an unsafe symbolic link';
  else if (!writable) reason = 'runtime directory is not writable';
  else if (runningNodeMajor !== UPDATE_CENTER_REQUIRED_NODE_MAJOR) reason = `automatic server updates require Node ${UPDATE_CENTER_REQUIRED_NODE_MAJOR}`;
  return {
    supported: !reason,
    mode: reason ? 'unsupported' : 'local-bundle',
    reason,
    runtimeDir,
    architecture,
    platform,
    nodeMajor: runningNodeMajor,
    persistent,
    writable,
    currentVersion: (() => {
      const value = pointerVersion(runtimeDir, 'current');
      return parseStableSemVer(value)?.normalized || value;
    })(),
  };
}

export const inspectUpdateCenterRuntime = getUpdateCenterRuntimeCapability;

async function assertRuntimeReady(input: {
  runtimeDir: string;
  platform?: NodeJS.Platform;
  architecture?: 'amd64' | 'arm64';
  enforcePersistent?: boolean;
}): Promise<{ root: string; architecture: 'amd64' | 'arm64'; nodeMajor: number }> {
  const root = resolveUpdateCenterRuntimeDir(input.runtimeDir);
  const capability = await getUpdateCenterRuntimeCapability({
    runtimeDir: root,
    platform: input.platform,
    architecture: input.architecture,
  });
  if (capability.platform !== 'linux') {
    throw new UpdateCenterLocalUpdateError('UNSUPPORTED_PLATFORM', capability.reason || 'unsupported platform');
  }
  if (!capability.architecture) {
    throw new UpdateCenterLocalUpdateError('UNSUPPORTED_ARCHITECTURE', capability.reason || 'unsupported architecture');
  }
  if (input.enforcePersistent !== false && !capability.persistent) {
    throw new UpdateCenterLocalUpdateError('RUNTIME_NOT_PERSISTENT', capability.reason || 'runtime is not persistent');
  }
  if (!await isSafeRuntimeLayout(root)) {
    throw new UpdateCenterLocalUpdateError('RUNTIME_PATH_UNSAFE', 'runtime directory contains an unsafe symbolic link');
  }
  if (!capability.writable) {
    throw new UpdateCenterLocalUpdateError('RUNTIME_NOT_WRITABLE', capability.reason || 'runtime is not writable');
  }
  if (input.enforcePersistent !== false && capability.persistent && capability.nodeMajor !== UPDATE_CENTER_REQUIRED_NODE_MAJOR) {
    throw new UpdateCenterLocalUpdateError(
      'NODE_VERSION_MISMATCH',
      capability.reason || `automatic server updates require Node ${UPDATE_CENTER_REQUIRED_NODE_MAJOR}`,
    );
  }
  await ensureUpdateCenterRuntimeDirectories(root);
  return { root, architecture: capability.architecture, nodeMajor: capability.nodeMajor };
}

function safeArchivePath(entryPath: string): boolean {
  if (!entryPath || entryPath.includes('\0') || entryPath.includes('\\')) return false;
  const withoutLeadingDot = entryPath.replace(/^\.\/+/, '');
  if (!withoutLeadingDot) return true;
  if (withoutLeadingDot.startsWith('/') || /^[a-zA-Z]:[\\/]/.test(withoutLeadingDot)) return false;
  const normalized = posix.normalize(withoutLeadingDot);
  if (normalized === '.' || normalized.startsWith('../') || normalized.includes('/../') || normalized === '..') return false;
  return normalized === withoutLeadingDot;
}

function validateTarEntry(entry: { path: string; type: string; size?: number }): void {
  if (!safeArchivePath(entry.path)) {
    throw new UpdateCenterLocalUpdateError('UNSAFE_ARCHIVE', `archive contains an unsafe path: ${entry.path}`);
  }
  if (!ALLOWED_TAR_METADATA_TYPES.has(entry.type) && entry.type !== 'File' && entry.type !== 'Directory') {
    throw new UpdateCenterLocalUpdateError('UNSAFE_ARCHIVE', `archive contains unsupported entry type: ${entry.type}`);
  }
  if (entry.type === 'File' && (typeof entry.size !== 'number' || !Number.isFinite(entry.size) || entry.size < 0)) {
    throw new UpdateCenterLocalUpdateError('ARCHIVE_INVALID', 'archive contains a file with an invalid size');
  }
  if (typeof entry.size === 'number' && entry.size > UPDATE_CENTER_MAX_EXTRACTED_BYTES) {
    throw new UpdateCenterLocalUpdateError('ARCHIVE_TOO_LARGE', 'archive contains an oversized entry');
  }
}

export async function extractUpdateCenterArchive(archivePath: string, destination: string): Promise<void> {
  let entryCount = 0;
  let extractedBytes = 0;
  let preflightError: UpdateCenterLocalUpdateError | null = null;
  try {
    await tarList({
      file: archivePath,
      strict: true,
      maxDecompressionRatio: 100,
      onentry: (entry) => {
        entryCount += 1;
        if (entryCount > UPDATE_CENTER_MAX_ARCHIVE_ENTRIES) {
          preflightError ||= new UpdateCenterLocalUpdateError('ARCHIVE_TOO_LARGE', 'archive contains too many entries');
          return;
        }
        try {
          validateTarEntry(entry);
        } catch (error) {
          if (error instanceof UpdateCenterLocalUpdateError) preflightError ||= error;
          else preflightError ||= new UpdateCenterLocalUpdateError('UNSAFE_ARCHIVE', formatError(error), error);
          return;
        }
        if (entry.type === 'File') extractedBytes += entry.size;
        if (extractedBytes > UPDATE_CENTER_MAX_EXTRACTED_BYTES) {
          preflightError ||= new UpdateCenterLocalUpdateError('ARCHIVE_TOO_LARGE', 'archive expands beyond the extraction limit');
        }
      },
    });
    if (preflightError) throw preflightError;
    await mkdir(destination, { recursive: true });
    const destinationDetails = await lstat(destination);
    if (!destinationDetails.isDirectory() || destinationDetails.isSymbolicLink()) {
      throw new UpdateCenterLocalUpdateError('UNSAFE_ARCHIVE', 'staging destination must be a real directory');
    }
    let extractionFilterError: UpdateCenterLocalUpdateError | null = null;
    await tarExtract({
      file: archivePath,
      cwd: destination,
      strict: true,
      preservePaths: false,
      preserveOwner: false,
      unlink: true,
      maxDepth: 64,
      maxDecompressionRatio: 100,
      filter: (entryPath, entry) => {
        const entryType = 'type' in entry ? entry.type : 'File';
        const entrySize = 'size' in entry && typeof entry.size === 'number' ? entry.size : 0;
        try {
          validateTarEntry({ path: entryPath, type: entryType, size: entrySize });
        } catch (error) {
          if (error instanceof UpdateCenterLocalUpdateError) extractionFilterError ||= error;
          else extractionFilterError ||= new UpdateCenterLocalUpdateError('UNSAFE_ARCHIVE', formatError(error), error);
          return false;
        }
        const resolvedEntry = resolve(destination, entryPath);
        if (!isPathInside(destination, resolvedEntry)) {
          extractionFilterError ||= new UpdateCenterLocalUpdateError('UNSAFE_ARCHIVE', `archive escapes staging directory: ${entryPath}`);
          return false;
        }
        return true;
      },
    });
    if (extractionFilterError) throw extractionFilterError;
  } catch (error) {
    await rm(destination, { recursive: true, force: true }).catch(() => undefined);
    if (error instanceof UpdateCenterLocalUpdateError) throw error;
    throw new UpdateCenterLocalUpdateError('ARCHIVE_INVALID', `unable to unpack release archive: ${formatError(error)}`, error);
  }
}

function normalizeManifest(input: unknown): UpdateCenterReleaseManifest | null {
  const record = asRecord(input);
  const version = nonEmptyString(record.version);
  const entrypoint = nonEmptyString(record.entrypoint);
  const migrationEntrypoint = nonEmptyString(record.migrationEntrypoint);
  const arch = record.arch === 'amd64' || record.arch === 'arm64' ? record.arch : null;
  const channel = record.channel === 'stable' ? 'stable' : null;
  const platform = record.platform === 'linux' ? 'linux' : null;
  const parsedNodeMajor = typeof record.nodeMajor === 'number' && Number.isSafeInteger(record.nodeMajor)
    ? record.nodeMajor
    : null;
  const schemaVersion = typeof record.schemaVersion === 'number' && Number.isSafeInteger(record.schemaVersion)
    ? record.schemaVersion
    : null;
  const artifactShaInput = nonEmptyString(record.artifactSha256);
  const parsedVersion = version ? parseStableSemVer(version) : null;
  if (!parsedVersion || !entrypoint || !migrationEntrypoint || !arch || !channel || !platform || parsedNodeMajor === null || parsedNodeMajor <= 0 || schemaVersion !== 1) return null;
  if (artifactShaInput && !normalizeSha256(artifactShaInput)) return null;
  const rawArtifactSha256 = record.artifactSha256;
  if (rawArtifactSha256 !== undefined && rawArtifactSha256 !== null && normalizeSha256(rawArtifactSha256) === null) {
    return null;
  }
  return {
    schemaVersion,
    version: parsedVersion.normalized,
    channel,
    platform,
    arch,
    nodeMajor: parsedNodeMajor,
    entrypoint,
    migrationEntrypoint,
    artifactName: nonEmptyString(record.artifactName),
    artifactSha256: normalizeSha256(rawArtifactSha256),
    gitSha: nonEmptyString(record.gitSha),
  };
}

function assertRelativeBundlePath(value: string, label: string): string {
  if (!safeArchivePath(value) || value.startsWith('./')) {
    throw new UpdateCenterLocalUpdateError('INVALID_MANIFEST', `${label} must be a safe relative path`);
  }
  return posix.normalize(value);
}

async function assertRegularFile(bundleRoot: string, relativePath: string, label: string): Promise<void> {
  const target = resolve(bundleRoot, relativePath);
  if (!isPathInside(bundleRoot, target)) {
    throw new UpdateCenterLocalUpdateError('INVALID_MANIFEST', `${label} escapes bundle root`);
  }
  try {
    const details = await lstat(target);
    if (!details.isFile()) throw new Error('not a regular file');
  } catch (error) {
    throw new UpdateCenterLocalUpdateError('INVALID_MANIFEST', `${label} does not exist`, error);
  }
}

async function validateNoSymlinks(root: string, current = root): Promise<void> {
  const entries = await readdir(current, { withFileTypes: true });
  for (const entry of entries) {
    const target = join(current, entry.name);
    if (entry.isSymbolicLink()) {
      throw new UpdateCenterLocalUpdateError('UNSAFE_ARCHIVE', `bundle contains a symbolic link: ${relative(root, target)}`);
    }
    if (entry.isDirectory()) await validateNoSymlinks(root, target);
  }
}

async function findNativeModules(root: string, current = root, result: string[] = []): Promise<string[]> {
  const entries = await readdir(current, { withFileTypes: true });
  for (const entry of entries) {
    const target = join(current, entry.name);
    if (entry.isDirectory()) await findNativeModules(root, target, result);
    else if (entry.isFile() && entry.name.endsWith('.node')) result.push(target);
  }
  return result;
}

async function updateBundlePayloadHash(root: string, current: string, hash: ReturnType<typeof createHash>): Promise<void> {
  const entries = (await readdir(current, { withFileTypes: true }))
    .filter((entry) => entry.name !== MANIFEST_FILE || current !== root)
    .sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0);
  for (const entry of entries) {
    const target = join(current, entry.name);
    const relativePath = relative(root, target).replaceAll('\\', '/');
    if (entry.isSymbolicLink()) {
      throw new UpdateCenterLocalUpdateError('UNSAFE_ARCHIVE', `bundle contains a symbolic link: ${relativePath}`);
    }
    if (entry.isDirectory()) {
      await updateBundlePayloadHash(root, target, hash);
      continue;
    }
    if (!entry.isFile()) continue;
    hash.update(relativePath);
    hash.update('\0');
    hash.update(await readFile(target));
    hash.update('\0');
  }
}

async function hashBundlePayload(root: string): Promise<string> {
  const hash = createHash('sha256');
  await updateBundlePayloadHash(root, root, hash);
  return hash.digest('hex');
}

async function validateNativeAddons(root: string): Promise<void> {
  for (const modulePath of await findNativeModules(root)) {
    try {
      requireFromBundle(modulePath);
    } catch (error) {
      throw new UpdateCenterLocalUpdateError(
        'NATIVE_MODULE_INVALID',
        `native addon cannot be loaded: ${relative(root, modulePath)}`,
        error,
      );
    }
  }
}

export async function validateUpdateCenterBundle(input: {
  bundleDir: string;
  targetVersion?: string;
  architecture?: 'amd64' | 'arm64';
  expectedNodeMajor?: number;
  artifactName?: string | null;
  validateNativeModules?: boolean;
}): Promise<UpdateCenterReleaseManifest> {
  const bundleDir = resolve(input.bundleDir);
  try {
    const bundleDetails = await lstat(bundleDir);
    if (!bundleDetails.isDirectory() || bundleDetails.isSymbolicLink()) {
      throw new UpdateCenterLocalUpdateError('UNSAFE_ARCHIVE', 'bundle root must be a real directory');
    }
  } catch (error) {
    if (error instanceof UpdateCenterLocalUpdateError) throw error;
    throw new UpdateCenterLocalUpdateError('INVALID_MANIFEST', 'release bundle directory is missing', error);
  }
  let manifestPayload: unknown;
  try {
    const manifestPath = join(bundleDir, MANIFEST_FILE);
    const manifestDetails = await lstat(manifestPath);
    if (!manifestDetails.isFile() || manifestDetails.isSymbolicLink()) {
      throw new UpdateCenterLocalUpdateError('UNSAFE_ARCHIVE', 'release.json must be a regular file');
    }
    manifestPayload = JSON.parse(await readFile(manifestPath, 'utf8')) as unknown;
  } catch (error) {
    if (error instanceof UpdateCenterLocalUpdateError) throw error;
    throw new UpdateCenterLocalUpdateError('INVALID_MANIFEST', 'release.json is missing or invalid', error);
  }
  const manifest = normalizeManifest(manifestPayload);
  if (!manifest) throw new UpdateCenterLocalUpdateError('INVALID_MANIFEST', 'release.json does not match the release schema');
  const parsedVersion = parseStableSemVer(manifest.version);
  if (!parsedVersion) throw new UpdateCenterLocalUpdateError('INVALID_MANIFEST', 'release version is not a stable SemVer');
  if (input.targetVersion) {
    const target = parseStableSemVer(input.targetVersion);
    if (!target || target.normalized !== parsedVersion.normalized) {
      throw new UpdateCenterLocalUpdateError('VERSION_MISMATCH', 'release manifest version does not match target version');
    }
  }
  if (input.architecture && manifest.arch !== input.architecture) {
    throw new UpdateCenterLocalUpdateError('ARCHITECTURE_MISMATCH', `release targets ${manifest.arch}, expected ${input.architecture}`);
  }
  const expectedNode = input.expectedNodeMajor ?? nodeMajor();
  if (manifest.nodeMajor !== expectedNode) {
    throw new UpdateCenterLocalUpdateError('NODE_VERSION_MISMATCH', `release requires Node ${manifest.nodeMajor}, running Node ${expectedNode}`);
  }
  if (input.artifactName && manifest.artifactName !== input.artifactName) {
    throw new UpdateCenterLocalUpdateError('ARTIFACT_MISMATCH', 'release manifest artifact name does not match downloaded asset');
  }
  if (input.artifactName && (!manifest.artifactName || !manifest.artifactSha256)) {
    throw new UpdateCenterLocalUpdateError('INVALID_MANIFEST', 'downloaded release manifest must include artifact metadata');
  }
  const entrypoint = assertRelativeBundlePath(manifest.entrypoint, 'entrypoint');
  await assertRegularFile(bundleDir, entrypoint, 'entrypoint');
  if (manifest.migrationEntrypoint) {
    await assertRegularFile(bundleDir, assertRelativeBundlePath(manifest.migrationEntrypoint, 'migrationEntrypoint'), 'migrationEntrypoint');
  }
  await validateNoSymlinks(bundleDir);
  if (manifest.artifactSha256 && manifest.artifactSha256 !== await hashBundlePayload(bundleDir)) {
    throw new UpdateCenterLocalUpdateError('CHECKSUM_MISMATCH', 'release manifest payload checksum does not match the bundle');
  }
  if (input.validateNativeModules !== false) await validateNativeAddons(bundleDir);
  return manifest;
}

async function fetchWithRedirects(
  initialUrl: string,
  init: UndiciRequestInit,
  fetchImpl: typeof fetch,
): Promise<Awaited<ReturnType<typeof fetch>>> {
  let url = validateUpdateCenterDownloadUrl(initialUrl);
  for (let redirectCount = 0; redirectCount <= UPDATE_CENTER_MAX_REDIRECTS; redirectCount += 1) {
    const response = await fetchImpl(url.href, { ...init, redirect: 'manual' });
    if (!isRedirect(response.status)) return response;
    const location = response.headers.get('location');
    await response.body?.cancel().catch(() => undefined);
    if (!location) throw new UpdateCenterLocalUpdateError('DOWNLOAD_REDIRECT', 'release server returned a redirect without a location');
    if (redirectCount === UPDATE_CENTER_MAX_REDIRECTS) {
      throw new UpdateCenterLocalUpdateError('DOWNLOAD_REDIRECT', 'release download exceeded redirect limit');
    }
    url = validateUpdateCenterDownloadUrl(new URL(location, url));
  }
  throw new UpdateCenterLocalUpdateError('DOWNLOAD_REDIRECT', 'release download redirect failed');
}

async function streamResponseToFile(
  response: Awaited<ReturnType<typeof fetch>>,
  destination: string,
  expectedSha256: string | null,
  signal: AbortSignal | undefined,
  onProgress: ((progress: UpdateCenterDownloadProgress) => void) | undefined,
): Promise<{ sha256: string; size: number }> {
  if (!response.ok) throw new UpdateCenterLocalUpdateError('DOWNLOAD_FAILED', `release download failed with HTTP ${response.status}`);
  const declaredLength = Number.parseInt(response.headers.get('content-length') || '', 10);
  const totalBytes = Number.isFinite(declaredLength) && declaredLength >= 0 ? declaredLength : null;
  if (totalBytes !== null && totalBytes > UPDATE_CENTER_MAX_DOWNLOAD_BYTES) {
    throw new UpdateCenterLocalUpdateError('DOWNLOAD_TOO_LARGE', 'release download exceeds the 512 MiB limit');
  }
  if (!response.body) throw new UpdateCenterLocalUpdateError('DOWNLOAD_FAILED', 'release response did not include a body');
  await mkdir(dirname(destination), { recursive: true });
  let output;
  try {
    output = await open(destination, 'wx', 0o600);
  } catch (error) {
    throw new UpdateCenterLocalUpdateError('DOWNLOAD_WRITE_FAILED', 'unable to create release staging file', error);
  }
  const hash = createHash('sha256');
  let downloadedBytes = 0;
  const reader = response.body.getReader();
  try {
    while (true) {
      if (signal?.aborted) throw new UpdateCenterLocalUpdateError('DOWNLOAD_ABORTED', 'release download was aborted');
      const { done, value } = await reader.read();
      if (done) break;
      const chunk = Buffer.from(value);
      downloadedBytes += chunk.byteLength;
      if (downloadedBytes > UPDATE_CENTER_MAX_DOWNLOAD_BYTES) {
        throw new UpdateCenterLocalUpdateError('DOWNLOAD_TOO_LARGE', 'release download exceeds the 512 MiB limit');
      }
      hash.update(chunk);
      await output.write(chunk);
      onProgress?.({ downloadedBytes, totalBytes });
    }
    await output.sync();
  } catch (error) {
    await output.close().catch(() => undefined);
    await reader.cancel().catch(() => undefined);
    throw error;
  }
  await output.close();
  const sha256 = hash.digest('hex');
  if (expectedSha256 && sha256 !== expectedSha256) {
    throw new UpdateCenterLocalUpdateError('CHECKSUM_MISMATCH', 'release checksum does not match checksums.txt');
  }
  return { sha256, size: downloadedBytes };
}

export async function downloadUpdateCenterAsset(input: {
  url: string;
  destination: string;
  expectedSha256?: string | null;
  signal?: AbortSignal;
  onProgress?: (progress: UpdateCenterDownloadProgress) => void;
  fetchImpl?: typeof fetch;
}): Promise<{ sha256: string; size: number }> {
  const expectedSha256 = input.expectedSha256 ? normalizeSha256(input.expectedSha256) : null;
  if (input.expectedSha256 && !expectedSha256) {
    throw new UpdateCenterLocalUpdateError('INVALID_CHECKSUM', 'expected checksum must be a SHA-256 hex digest');
  }
  try {
    const response = await fetchWithRedirects(
      input.url,
      {
        headers: {
          accept: 'application/octet-stream',
          'user-agent': 'metapi-update-center/2.0',
        },
        signal: input.signal,
      },
      input.fetchImpl || fetch,
    );
    return await streamResponseToFile(response, input.destination, expectedSha256, input.signal, input.onProgress);
  } catch (error) {
    await unlink(input.destination).catch(() => undefined);
    if (input.signal?.aborted || (error instanceof Error && error.name === 'AbortError')) {
      throw new UpdateCenterLocalUpdateError('DOWNLOAD_ABORTED', 'release download was aborted', error);
    }
    if (error instanceof UpdateCenterLocalUpdateError) throw error;
    throw new UpdateCenterLocalUpdateError('DOWNLOAD_FAILED', formatError(error), error);
  }
}

function parseChecksums(text: string, assetName: string): string | null {
  for (const line of text.split(/\r?\n/)) {
    const match = line.trim().match(/^([a-fA-F0-9]{64})\s+(?:\*?)(\S+)$/);
    if (!match) continue;
    if (match[2] === assetName || match[2].endsWith(`/${assetName}`)) return match[1].toLowerCase();
  }
  return null;
}

async function resolveInstallTarget(input: UpdateCenterInstallInput, architecture: 'amd64' | 'arm64') {
  const requestedVersion = nonEmptyString(input.targetVersion || input.version);
  let candidate = input.candidate || null;
  if (!candidate && input.archivePath && requestedVersion) {
    const parsed = parseStableSemVer(requestedVersion);
    if (!parsed) throw new UpdateCenterLocalUpdateError('VERSION_MISMATCH', 'requested release version is invalid');
    candidate = {
      source: 'github-release',
      rawVersion: parsed.raw,
      normalizedVersion: parsed.normalized,
      url: null,
      tagName: `v${parsed.normalized}`,
      digest: null,
      displayVersion: parsed.normalized,
      publishedAt: null,
      assets: [],
    };
  }
  if (!candidate) {
    candidate = requestedVersion ? await fetchStableGitHubRelease(requestedVersion) : await (await import('./updateCenterVersionService.js')).fetchLatestStableGitHubRelease();
  }
  if (!candidate) throw new UpdateCenterLocalUpdateError('RELEASE_NOT_FOUND', 'stable GitHub release was not found');
  if (candidate.source !== 'github-release') {
    throw new UpdateCenterLocalUpdateError('UNSUPPORTED_RELEASE_SOURCE', 'only official GitHub releases can be installed');
  }
  const parsed = parseStableSemVer(requestedVersion || candidate.normalizedVersion);
  if (!parsed || parsed.normalized !== candidate.normalizedVersion) {
    throw new UpdateCenterLocalUpdateError('VERSION_MISMATCH', 'requested release version is invalid or does not match the candidate');
  }
  const asset = input.asset || findServerReleaseAsset(candidate, architecture);
  const expectedAssetName = buildServerReleaseAssetName(parsed.normalized, architecture);
  if (asset && asset.name !== expectedAssetName) {
    throw new UpdateCenterLocalUpdateError('ASSET_MISMATCH', `release asset must be named ${expectedAssetName}`);
  }
  if (asset?.size !== null && asset?.size !== undefined && asset.size > UPDATE_CENTER_MAX_DOWNLOAD_BYTES) {
    throw new UpdateCenterLocalUpdateError('DOWNLOAD_TOO_LARGE', 'release asset exceeds the 512 MiB limit');
  }
  if (input.checksumAsset && input.checksumAsset.name !== 'checksums.txt') {
    throw new UpdateCenterLocalUpdateError('CHECKSUM_ASSET_INVALID', 'checksum asset must be checksums.txt');
  }
  if (input.checksumAsset?.size !== null && input.checksumAsset?.size !== undefined && input.checksumAsset.size > UPDATE_CENTER_MAX_DOWNLOAD_BYTES) {
    throw new UpdateCenterLocalUpdateError('DOWNLOAD_TOO_LARGE', 'checksum asset exceeds the 512 MiB limit');
  }
  if (!input.archivePath && !asset) {
    throw new UpdateCenterLocalUpdateError('ASSET_NOT_FOUND', `server asset ${buildServerReleaseAssetName(parsed.normalized, architecture)} is missing`);
  }
  if (!input.archivePath && !nonEmptyString(asset?.downloadUrl)) {
    throw new UpdateCenterLocalUpdateError('ASSET_INVALID', 'release asset does not provide a download URL');
  }
  if (input.checksumAsset && !nonEmptyString(input.checksumAsset.downloadUrl)) {
    throw new UpdateCenterLocalUpdateError('CHECKSUM_ASSET_INVALID', 'checksum asset does not provide a download URL');
  }
  return { candidate, version: parsed.normalized, asset, checksumAsset: input.checksumAsset || findChecksumsAsset(candidate) };
}

async function copyAndHashLocalArchive(source: string, destination: string, expectedSha256: string | null): Promise<{ sha256: string; size: number }> {
  let details;
  try {
    details = await lstat(source);
  } catch (error) {
    throw new UpdateCenterLocalUpdateError('ARCHIVE_NOT_FOUND', 'local release archive does not exist', error);
  }
  if (!details.isFile()) throw new UpdateCenterLocalUpdateError('ARCHIVE_NOT_FOUND', 'local release archive is not a regular file');
  if (details.size > UPDATE_CENTER_MAX_DOWNLOAD_BYTES) throw new UpdateCenterLocalUpdateError('DOWNLOAD_TOO_LARGE', 'release archive exceeds the 512 MiB limit');
  await copyFile(source, destination, fsConstants.COPYFILE_EXCL);
  const hash = createHash('sha256');
  let size = 0;
  for await (const chunk of createReadStream(destination)) {
    const buffer = Buffer.from(chunk as Uint8Array);
    size += buffer.length;
    if (size > UPDATE_CENTER_MAX_DOWNLOAD_BYTES) {
      throw new UpdateCenterLocalUpdateError('DOWNLOAD_TOO_LARGE', 'release archive exceeds the 512 MiB limit');
    }
    hash.update(buffer);
  }
  const sha256 = hash.digest('hex');
  if (expectedSha256 && sha256 !== expectedSha256) throw new UpdateCenterLocalUpdateError('CHECKSUM_MISMATCH', 'release checksum does not match expected digest');
  return { sha256, size };
}

function relativePointerTarget(root: string, releasePath: string): string {
  const resolvedReleasePath = resolve(releasePath);
  const releasesRoot = resolve(root, 'releases');
  if (!isPathInside(releasesRoot, resolvedReleasePath) || resolvedReleasePath === releasesRoot) {
    throw new UpdateCenterLocalUpdateError('INVALID_RELEASE_PATH', 'release path is outside runtime releases');
  }
  const target = relative(root, resolvedReleasePath);
  if (!target || target.startsWith('../') || isAbsolute(target)) throw new UpdateCenterLocalUpdateError('INVALID_RELEASE_PATH', 'release path is outside runtime');
  const relativeRelease = relative(releasesRoot, resolvedReleasePath).replaceAll('\\', '/');
  const version = parseStableSemVer(relativeRelease)?.normalized;
  if (!version || relativeRelease !== version || target !== `releases/${version}`) {
    throw new UpdateCenterLocalUpdateError('INVALID_RELEASE_PATH', 'release path is not a canonical version directory');
  }
  return target;
}

async function atomicallySetPointer(root: string, pointer: 'current' | 'previous', releasePath: string): Promise<void> {
  const target = relativePointerTarget(root, releasePath);
  const temporary = join(root, `.${pointer}.tmp-${process.pid}-${Math.random().toString(16).slice(2)}`);
  await unlink(temporary).catch(() => undefined);
  await symlink(target, temporary, 'dir');
  try {
    await rename(temporary, join(root, pointer));
  } catch (error) {
    await unlink(temporary).catch(() => undefined);
    throw new UpdateCenterLocalUpdateError('POINTER_SWITCH_FAILED', `unable to replace ${pointer} pointer`, error);
  }
}

async function switchCurrentPointer(root: string, targetPath: string): Promise<{ previousVersion: string | null }> {
  const currentPath = readUpdateCenterPointer(root, 'current');
  const previousPath = readUpdateCenterPointer(root, 'previous');
  const previousVersion = pointerVersion(root, 'current');
  try {
    if (currentPath && currentPath !== targetPath) await atomicallySetPointer(root, 'previous', currentPath);
    else if (!currentPath) await unlink(join(root, 'previous')).catch(() => undefined);
    await atomicallySetPointer(root, 'current', targetPath);
    return { previousVersion };
  } catch (error) {
    // Reconcile the two-link update if the second rename fails. This keeps a
    // failed install from leaving `previous` pointing at a candidate that was
    // never made current.
    await restorePointer(root, 'current', currentPath);
    await restorePointer(root, 'previous', previousPath);
    throw error;
  }
}

async function restorePointer(root: string, pointer: 'current' | 'previous', targetPath: string | null): Promise<void> {
  if (targetPath) {
    await atomicallySetPointer(root, pointer, targetPath).catch(() => undefined);
    return;
  }
  await unlink(join(root, pointer)).catch(() => undefined);
}

async function refreshState(root: string, patch: Partial<UpdateCenterRuntimeState>): Promise<UpdateCenterRuntimeState> {
  const installed = await listInstalledUpdateCenterVersions(root);
  return patchUpdateCenterRuntimeState({
    ...patch,
    currentVersion: patch.currentVersion ?? pointerVersion(root, 'current'),
    previousVersion: patch.previousVersion ?? pointerVersion(root, 'previous'),
    installedVersions: patch.installedVersions ?? installed.map((entry) => entry.version),
    updatedAt: new Date().toISOString(),
  }, root);
}

function buildPending(input: {
  taskId: string;
  targetVersion: string;
  previousVersion: string | null;
  phase: UpdateCenterPendingPhase;
  reason?: UpdateCenterPendingState['reason'];
  rollbackBudget?: number;
  createdAt?: string;
}): UpdateCenterPendingState {
  const now = new Date().toISOString();
  return {
    schemaVersion: 1,
    taskId: input.taskId,
    targetVersion: input.targetVersion,
    previousVersion: input.previousVersion,
    phase: input.phase,
    rollbackBudget: input.rollbackBudget ?? 1,
    createdAt: input.createdAt || now,
    updatedAt: now,
    reason: input.reason || 'install',
  };
}

async function assertNoPendingUpdate(root: string): Promise<void> {
  const pending = await loadUpdateCenterPendingState(root);
  if (pending) {
    throw new UpdateCenterLocalUpdateError('RESTART_PENDING', 'an update restart is already pending');
  }
}

async function assertReleasePathAvailable(root: string, releasePath: string): Promise<void> {
  let details;
  try {
    details = await lstat(releasePath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException)?.code === 'ENOENT') return;
    throw new UpdateCenterLocalUpdateError('RELEASE_PATH_UNAVAILABLE', 'unable to inspect the target release directory', error);
  }
  if (details.isSymbolicLink()) {
    throw new UpdateCenterLocalUpdateError('RUNTIME_PATH_UNSAFE', 'target release directory must not be a symbolic link');
  }
  if (!details.isDirectory()) {
    throw new UpdateCenterLocalUpdateError('RELEASE_PATH_UNAVAILABLE', 'target release path is not a directory');
  }
  const currentPath = readUpdateCenterPointer(root, 'current');
  const previousPath = readUpdateCenterPointer(root, 'previous');
  if (currentPath === resolve(releasePath) || previousPath === resolve(releasePath)) {
    throw new UpdateCenterLocalUpdateError('VERSION_ALREADY_INSTALLED', 'target release is already installed and protected');
  }
  throw new UpdateCenterLocalUpdateError('VERSION_ALREADY_INSTALLED', 'target release is already installed');
}

export async function listInstalledUpdateCenterVersions(runtimeDir?: string): Promise<UpdateCenterInstalledVersion[]> {
  const root = resolveUpdateCenterRuntimeDir(runtimeDir);
  const releasesRoot = join(root, 'releases');
  if (!await isSafeRuntimeLayout(root)) return [];
  try {
    const rootDetails = await lstat(root);
    const releasesDetails = await lstat(releasesRoot);
    if (!rootDetails.isDirectory() || rootDetails.isSymbolicLink() || !releasesDetails.isDirectory() || releasesDetails.isSymbolicLink()) {
      return [];
    }
    const realRoot = realpathSync(root);
    const realReleasesRoot = realpathSync(releasesRoot);
    if (!isPathInside(realRoot, realReleasesRoot)) return [];
  } catch {
    return [];
  }
  const currentPath = readUpdateCenterPointer(root, 'current');
  const previousPath = readUpdateCenterPointer(root, 'previous');
  let entries;
  try {
    entries = await readdir(releasesRoot, { withFileTypes: true });
  } catch {
    return [];
  }
  const result: UpdateCenterInstalledVersion[] = [];
  for (const entry of entries) {
    if (!entry.isDirectory() || entry.isSymbolicLink()) continue;
    const directoryVersion = parseStableSemVer(entry.name)?.normalized;
    if (!directoryVersion || directoryVersion !== entry.name) continue;
    const path = join(releasesRoot, entry.name);
    try {
      const manifestPath = join(path, MANIFEST_FILE);
      const manifestDetails = await lstat(manifestPath);
      if (!manifestDetails.isFile() || manifestDetails.isSymbolicLink()) continue;
      const payload = JSON.parse(await readFile(manifestPath, 'utf8')) as unknown;
      const manifest = normalizeManifest(payload);
      if (!manifest || manifest.version !== directoryVersion) continue;
      result.push({
        version: directoryVersion,
        path,
        manifest,
        current: currentPath === resolve(path),
        previous: previousPath === resolve(path),
      });
    } catch {
      // Ignore an incomplete/invalid directory left by an interrupted staging
      // operation.  It is never exposed as an installed version.
    }
  }
  result.sort((left, right) => {
    const a = parseStableSemVer(left.version);
    const b = parseStableSemVer(right.version);
    if (a && b) return b.major - a.major || b.minor - a.minor || b.patch - a.patch;
    return right.version.localeCompare(left.version);
  });
  return result;
}

export const listLocalUpdateCenterVersions = listInstalledUpdateCenterVersions;

export async function installUpdateCenterRelease(input: UpdateCenterInstallInput): Promise<UpdateCenterInstallResult> {
  const runtimeDir = resolveUpdateCenterRuntimeDir(input.runtimeDir);
  const taskId = normalizeTaskId(input.taskId);
  const ready = await assertRuntimeReady({
    runtimeDir,
    platform: input.platform,
    architecture: input.architecture,
    enforcePersistent: input.enforcePersistent,
  });
  let target: Awaited<ReturnType<typeof resolveInstallTarget>>;
  let releasePath = '';
  const stagingPath = join(ready.root, 'staging', taskId);
  let switched = false;
  let pointersSwitched = false;
  let currentPointerBeforeSwitch: string | null = null;
  let previousPointerBeforeSwitch: string | null = null;
  let lockAcquired = false;
  let attemptStarted = false;
  let releaseCreated = false;
  let pendingWritten = false;
  let releaseLockRelease: (() => Promise<void>) | null = null;
  try {
    releaseLockRelease = await acquireUpdateCenterLock(ready.root, taskId);
    lockAcquired = true;
    await assertNoPendingUpdate(ready.root);
    target = await resolveInstallTarget(input, ready.architecture);
    releasePath = join(ready.root, 'releases', target.version);
    await assertReleasePathAvailable(ready.root, releasePath);
    attemptStarted = true;
    await rm(stagingPath, { recursive: true, force: true });
    await mkdir(stagingPath, { recursive: true });
    const currentVersion = pointerVersion(ready.root, 'current');
    await refreshState(ready.root, {
      updateState: 'downloading',
      taskId,
      restartPending: false,
      lastError: null,
      currentVersion,
      previousVersion: pointerVersion(ready.root, 'previous'),
    });

    const archivePath = join(stagingPath, target.asset?.name || `${target.version}.tar.gz`);
    let expectedSha256 = normalizeSha256(input.expectedSha256);
    if (input.expectedSha256 && !expectedSha256) throw new UpdateCenterLocalUpdateError('INVALID_CHECKSUM', 'expected checksum must be a SHA-256 hex digest');
    if (!expectedSha256 && target.checksumAsset && !input.archivePath) {
      const checksumPath = join(stagingPath, 'checksums.txt');
      await downloadUpdateCenterAsset({ url: target.checksumAsset.downloadUrl, destination: checksumPath, signal: input.signal });
      expectedSha256 = parseChecksums(await readFile(checksumPath, 'utf8'), target.asset?.name || '') || null;
      if (!expectedSha256) throw new UpdateCenterLocalUpdateError('CHECKSUM_MISSING', 'checksums.txt does not contain the selected release asset');
    }
    if (!input.archivePath && input.requireChecksum !== false && !expectedSha256) {
      throw new UpdateCenterLocalUpdateError('CHECKSUM_MISSING', 'a SHA-256 checksum is required for release installation');
    }
    const archiveResult = input.archivePath
      ? await copyAndHashLocalArchive(input.archivePath, archivePath, expectedSha256)
      : await downloadUpdateCenterAsset({
        url: target.asset!.downloadUrl,
        destination: archivePath,
        expectedSha256,
        signal: input.signal,
        onProgress: input.onProgress,
      });

    await refreshState(ready.root, { updateState: 'staging', taskId });
    const bundlePath = join(stagingPath, 'bundle');
    await extractUpdateCenterArchive(archivePath, bundlePath);
    await validateUpdateCenterBundle({
      bundleDir: bundlePath,
      targetVersion: target.version,
      architecture: ready.architecture,
      expectedNodeMajor: input.expectedNodeMajor ?? ready.nodeMajor,
      artifactName: target.asset?.name,
      validateNativeModules: input.validateNativeModules,
    });
    if (existsSync(releasePath)) {
      throw new UpdateCenterLocalUpdateError('VERSION_ALREADY_INSTALLED', `release ${target.version} is already installed`);
    }
    await refreshState(ready.root, { updateState: 'switching', taskId });
    await rename(bundlePath, releasePath);
    releaseCreated = true;
    const pending = buildPending({
      taskId,
      targetVersion: target.version,
      previousVersion: currentVersion,
      phase: 'switching',
    });
    await saveUpdateCenterPendingState(pending, ready.root);
    pendingWritten = true;
    currentPointerBeforeSwitch = readUpdateCenterPointer(ready.root, 'current');
    previousPointerBeforeSwitch = readUpdateCenterPointer(ready.root, 'previous');
    await switchCurrentPointer(ready.root, releasePath);
    pointersSwitched = true;
    await saveUpdateCenterPendingState({ ...pending, phase: 'restarting', updatedAt: new Date().toISOString() }, ready.root);
    const state = await refreshState(ready.root, {
      updateState: 'restarting',
      taskId,
      currentVersion: target.version,
      previousVersion: currentVersion,
      restartPending: true,
      lastError: null,
    });
    switched = true;
    return {
      success: true,
      taskId,
      targetVersion: target.version,
      previousVersion: currentVersion,
      releasePath,
      archiveSha256: archiveResult.sha256,
      restartRequired: true,
      state,
    };
  } catch (error) {
    if (!switched && lockAcquired && attemptStarted) {
      if (pointersSwitched) {
        await restorePointer(ready.root, 'current', currentPointerBeforeSwitch);
        await restorePointer(ready.root, 'previous', previousPointerBeforeSwitch);
      }
      if (pendingWritten) await clearUpdateCenterPendingState(ready.root);
      if (releaseCreated) await rm(releasePath, { recursive: true, force: true }).catch(() => undefined);
      await refreshState(ready.root, {
        updateState: 'failed',
        taskId: null,
        restartPending: false,
        lastError: formatError(error),
      }).catch(() => undefined);
    }
    if (error instanceof UpdateCenterLocalUpdateError || error instanceof UpdateCenterUpdateInProgressError) throw error;
    throw new UpdateCenterLocalUpdateError('UPDATE_FAILED', formatError(error), error);
  } finally {
    await rm(stagingPath, { recursive: true, force: true }).catch(() => undefined);
    await releaseLock(releaseLockRelease);
  }
}

async function releaseLock(release: (() => Promise<void>) | null): Promise<void> {
  if (release) await release().catch(() => undefined);
}

export const installUpdate = installUpdateCenterRelease;

export async function rollbackUpdateCenter(input: UpdateCenterRollbackInput = {}): Promise<UpdateCenterRollbackResult> {
  const runtimeDir = resolveUpdateCenterRuntimeDir(input.runtimeDir);
  const taskId = normalizeTaskId(input.taskId);
  const ready = await assertRuntimeReady({
    runtimeDir,
    platform: input.platform,
    architecture: input.architecture,
    enforcePersistent: input.enforcePersistent,
  });
  try {
    return await withUpdateCenterLock(ready.root, taskId, async () => {
      await assertNoPendingUpdate(ready.root);
      const installed = await listInstalledUpdateCenterVersions(ready.root);
      const requestedTargetVersion = nonEmptyString(input.targetVersion) || pointerVersion(ready.root, 'previous');
      if (!requestedTargetVersion) throw new UpdateCenterLocalUpdateError('ROLLBACK_UNAVAILABLE', 'no previous release is installed');
      const parsedTargetVersion = parseStableSemVer(requestedTargetVersion);
      if (!parsedTargetVersion) throw new UpdateCenterLocalUpdateError('INVALID_VERSION', 'rollback target must be a stable SemVer');
      const target = installed.find((entry) => parseStableSemVer(entry.version)?.normalized === parsedTargetVersion.normalized);
      if (!target) throw new UpdateCenterLocalUpdateError('ROLLBACK_UNAVAILABLE', `release ${requestedTargetVersion} is not installed`);
      const currentPath = readUpdateCenterPointer(ready.root, 'current');
      const previousPath = readUpdateCenterPointer(ready.root, 'previous');
      if (target.current || (currentPath && resolve(currentPath) === resolve(target.path))) {
        throw new UpdateCenterLocalUpdateError('ROLLBACK_UNAVAILABLE', 'rollback target is already the current release');
      }

      await validateUpdateCenterBundle({
        bundleDir: target.path,
        targetVersion: parsedTargetVersion.normalized,
        architecture: ready.architecture,
        expectedNodeMajor: ready.nodeMajor,
        validateNativeModules: input.validateNativeModules,
      });

      const currentVersion = pointerVersion(ready.root, 'current');
      const pending = buildPending({
        taskId,
        targetVersion: parsedTargetVersion.normalized,
        previousVersion: currentVersion,
        phase: 'switching',
        reason: 'manual-rollback',
        rollbackBudget: 0,
      });
      let pendingWritten = false;
      let switched = false;
      let pointersSwitched = false;
      try {
        await saveUpdateCenterPendingState(pending, ready.root);
        pendingWritten = true;
        await switchCurrentPointer(ready.root, target.path);
        pointersSwitched = true;
        await saveUpdateCenterPendingState({ ...pending, phase: 'restarting', updatedAt: new Date().toISOString() }, ready.root);
        const state = await refreshState(ready.root, {
          updateState: 'restarting',
          taskId,
          currentVersion: target.version,
          previousVersion: currentVersion,
          restartPending: true,
          lastError: null,
        });
        switched = true;
        return {
          success: true,
          taskId,
          targetVersion: target.version,
          previousVersion: currentVersion,
          restartRequired: true,
          state,
        };
      } catch (error) {
        if (!switched) {
          if (pendingWritten) await clearUpdateCenterPendingState(ready.root);
          if (pointersSwitched) {
            await restorePointer(ready.root, 'current', currentPath);
            await restorePointer(ready.root, 'previous', previousPath);
          }
        }
        throw error;
      }
    });
  } catch (error) {
    if (error instanceof UpdateCenterLocalUpdateError || error instanceof UpdateCenterUpdateInProgressError) throw error;
    throw new UpdateCenterLocalUpdateError('UPDATE_FAILED', formatError(error), error);
  }
}

export const rollbackUpdate = rollbackUpdateCenter;

export async function markUpdateCenterHealthy(runtimeDir?: string): Promise<UpdateCenterRuntimeState> {
  const root = resolveUpdateCenterRuntimeDir(runtimeDir);
  const pending = await loadUpdateCenterPendingState(root);
  await clearUpdateCenterPendingState(root);
  await refreshState(root, {
    updateState: 'healthy',
    taskId: pending?.taskId || null,
    currentVersion: pointerVersion(root, 'current'),
    previousVersion: pointerVersion(root, 'previous'),
    restartPending: false,
    lastError: null,
  });
  await pruneUpdateCenterVersions(root).catch(() => undefined);
  return await refreshState(root, {
    updateState: 'healthy',
    taskId: pending?.taskId || null,
    currentVersion: pointerVersion(root, 'current'),
    previousVersion: pointerVersion(root, 'previous'),
    restartPending: false,
    lastError: null,
  });
}

export async function markUpdateCenterFailed(error: unknown, runtimeDir?: string): Promise<UpdateCenterRuntimeState> {
  const root = resolveUpdateCenterRuntimeDir(runtimeDir);
  return await refreshState(root, {
    updateState: 'failed',
    restartPending: false,
    lastError: formatError(error),
  });
}

export async function markUpdateCenterRolledBack(error: unknown = null, runtimeDir?: string): Promise<UpdateCenterRuntimeState> {
  const root = resolveUpdateCenterRuntimeDir(runtimeDir);
  const pending = await loadUpdateCenterPendingState(root);
  await clearUpdateCenterPendingState(root);
  return await refreshState(root, {
    updateState: 'rolled_back',
    taskId: pending?.taskId || null,
    currentVersion: pointerVersion(root, 'current'),
    previousVersion: pointerVersion(root, 'previous'),
    restartPending: false,
    lastError: error ? formatError(error) : null,
  });
}

/**
 * Recover a candidate selected by the stable runner.  The pending transaction
 * carries a one-shot rollback budget; consuming it here prevents a crash loop
 * when the previous release is also unhealthy.
 */
export async function rollbackPendingUpdateCenter(
  error: unknown = null,
  runtimeDir?: string,
): Promise<UpdateCenterRuntimeState> {
  const root = resolveUpdateCenterRuntimeDir(runtimeDir);
  const initialPending = await loadUpdateCenterPendingState(root);
  if (!initialPending) return await markUpdateCenterFailed(error || new Error('no pending update'), root);
  const taskId = normalizeTaskId(initialPending.taskId);
  return await withUpdateCenterLock(root, taskId, async () => {
    const pending = await loadUpdateCenterPendingState(root);
    if (!pending) return await markUpdateCenterFailed(error || new Error('no pending update'), root);
    if (pending.rollbackBudget <= 0) {
      await clearUpdateCenterPendingState(root);
      return await markUpdateCenterFailed(error || new Error('automatic rollback budget exhausted'), root);
    }
    const previousPath = readUpdateCenterPointer(root, 'previous');
    const candidatePath = readUpdateCenterPointer(root, 'current');
    if (!previousPath || !candidatePath) {
      await clearUpdateCenterPendingState(root);
      return await markUpdateCenterFailed(error || new Error('previous release is unavailable'), root);
    }
    const candidateVersion = pointerVersion(root, 'current');
    const previousVersion = pointerVersion(root, 'previous');
    if (candidateVersion !== pending.targetVersion || (pending.previousVersion && previousVersion !== pending.previousVersion)) {
      await clearUpdateCenterPendingState(root);
      return await markUpdateCenterFailed(error || new Error('pending release pointers do not match'), root);
    }
    try {
      await switchCurrentPointer(root, previousPath);
    } catch (switchError) {
      throw switchError;
    }
    await clearUpdateCenterPendingState(root);
    return await refreshState(root, {
      updateState: 'rolled_back',
      taskId: pending.taskId,
      currentVersion: pointerVersion(root, 'current'),
      previousVersion: pointerVersion(root, 'previous'),
      restartPending: false,
      lastError: error ? formatError(error) : null,
    });
  });
}

export const rollbackPendingUpdate = rollbackPendingUpdateCenter;

export async function pruneUpdateCenterVersions(runtimeDir?: string, keepCount = 2): Promise<string[]> {
  const root = resolveUpdateCenterRuntimeDir(runtimeDir);
  if (await loadUpdateCenterPendingState(root)) return [];
  const keep = Math.max(2, Math.trunc(keepCount));
  const installed = await listInstalledUpdateCenterVersions(root);
  const protectedPaths = new Set(installed.filter((entry) => entry.current || entry.previous).map((entry) => resolve(entry.path)));
  const removed: string[] = [];
  for (const entry of installed.slice(keep)) {
    if (protectedPaths.has(resolve(entry.path))) continue;
    await rm(entry.path, { recursive: true, force: true });
    removed.push(entry.version);
  }
  if (removed.length) await refreshState(root, {}).catch(() => undefined);
  return removed;
}

export async function getUpdateCenterLocalStatus(runtimeDir?: string): Promise<{
  capability: UpdateCenterRuntimeCapability;
  state: UpdateCenterRuntimeState;
  pending: UpdateCenterPendingState | null;
  installedVersions: UpdateCenterInstalledVersion[];
}> {
  const root = resolveUpdateCenterRuntimeDir(runtimeDir);
  const [capability, state, pending, installedVersions] = await Promise.all([
    getUpdateCenterRuntimeCapability({ runtimeDir: root }),
    loadUpdateCenterRuntimeState(root),
    loadUpdateCenterPendingState(root),
    listInstalledUpdateCenterVersions(root),
  ]);
  return { capability, state, pending, installedVersions };
}

export const getLocalUpdateCenterStatus = getUpdateCenterLocalStatus;
