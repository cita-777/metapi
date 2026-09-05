import { lstat, mkdir, readFile, rename, rm, unlink, writeFile } from 'node:fs/promises';
import { existsSync, lstatSync, readFileSync, readlinkSync, realpathSync } from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';

import { config } from '../config.js';
import { parseStableSemVer, type UpdateCenterVersionCandidate, type UpdateCenterVersionSource } from './updateCenterVersionService.js';

export const UPDATE_CENTER_RUNTIME_STATE_FILE = 'state.json';
export const UPDATE_CENTER_PENDING_STATE_FILE = 'pending.json';
export const UPDATE_CENTER_RUNTIME_PERSISTENT_MARKER = '.persistent';
export const UPDATE_CENTER_RUNTIME_SCHEMA_VERSION = 1;

export type UpdateCenterUpdateState =
  | 'idle'
  | 'checking'
  | 'downloading'
  | 'staging'
  | 'switching'
  | 'restarting'
  | 'healthy'
  | 'failed'
  | 'rolled_back'
  | 'unsupported';

export type UpdateCenterPendingPhase =
  | 'downloading'
  | 'staging'
  | 'switching'
  | 'restarting'
  | 'health-check';

export type UpdateCenterPendingState = {
  schemaVersion: number;
  taskId: string;
  targetVersion: string;
  previousVersion: string | null;
  phase: UpdateCenterPendingPhase;
  rollbackBudget: number;
  createdAt: string;
  updatedAt: string;
  reason: 'install' | 'manual-rollback' | 'bootstrap';
  /** Runner-only marker retained across a rollback restart. */
  rollbackApplied?: boolean;
};

/**
 * Release metadata is cached here so a process restart can render the last
 * check without contacting GitHub.  The index signature allows status owners
 * to add presentation-only fields without making this file a deployment API.
 */
export type UpdateCenterStatusSnapshot = {
  githubRelease: UpdateCenterVersionCandidate | null;
  installedVersions: string[];
  capability?: {
    supported: boolean;
    mode: string;
    reason: string | null;
  } | null;
  [key: string]: unknown;
};

export type UpdateCenterRuntimeState = {
  schemaVersion: number;
  updateState: UpdateCenterUpdateState;
  currentVersion: string | null;
  previousVersion: string | null;
  installedVersions: string[];
  restartPending: boolean;
  taskId: string | null;
  lastError: string | null;
  updatedAt: string | null;
  lastCheckedAt: string | null;
  lastCheckError: string | null;
  lastResolvedSource: UpdateCenterVersionSource | null;
  lastResolvedDisplayVersion: string | null;
  lastResolvedCandidateKey: string | null;
  lastNotifiedCandidateKey: string | null;
  lastNotifiedAt: string | null;
  statusSnapshot: UpdateCenterStatusSnapshot | null;
};

function envBoolean(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  const normalized = value.trim().toLowerCase();
  if (!normalized) return fallback;
  return normalized === '1' || normalized === 'true' || normalized === 'yes' || normalized === 'on';
}

function configuredDataDir(): string {
  return (process.env.DATA_DIR || config.dataDir || './data').trim() || './data';
}

/** Resolve the runtime root without creating it. */
export function resolveUpdateCenterRuntimeDir(input?: string | { runtimeDir?: string }): string {
  const requested = typeof input === 'string' ? input : input?.runtimeDir;
  const configured = (requested ?? process.env.UPDATE_CENTER_RUNTIME_DIR ?? config.updateCenterRuntimeDir ?? '').trim();
  const raw = configured || join(configuredDataDir(), 'runtime');
  return isAbsolute(raw) ? resolve(raw) : resolve(process.cwd(), raw);
}

export const getUpdateCenterRuntimeDir = resolveUpdateCenterRuntimeDir;

/**
 * Compose opts into persistence through the env flag.  A marker file is also
 * accepted for operators that cannot alter the process environment.
 */
export function isUpdateCenterRuntimePersistent(runtimeDir = resolveUpdateCenterRuntimeDir()): boolean {
  const envValue = process.env.UPDATE_CENTER_RUNTIME_PERSISTENT;
  const configuredValue = envValue === undefined
    ? (config.updateCenterRuntimePersistent ? 'true' : undefined)
    : envValue;
  if (configuredValue !== undefined) return envBoolean(configuredValue, false);

  const markerPath = join(runtimeDir, UPDATE_CENTER_RUNTIME_PERSISTENT_MARKER);
  if (!existsSync(markerPath)) return false;
  try {
    const details = lstatSync(markerPath);
    if (!details.isFile() || details.isSymbolicLink()) return false;
    const marker = readFileSync(markerPath, 'utf8').trim().toLowerCase();
    return !marker || envBoolean(marker, false);
  } catch {
    return false;
  }
}

export const hasPersistentUpdateCenterRuntime = isUpdateCenterRuntimePersistent;

export function getUpdateCenterRuntimeStatePath(runtimeDir = resolveUpdateCenterRuntimeDir()): string {
  return join(runtimeDir, UPDATE_CENTER_RUNTIME_STATE_FILE);
}

export function getUpdateCenterPendingStatePath(runtimeDir = resolveUpdateCenterRuntimeDir()): string {
  return join(runtimeDir, UPDATE_CENTER_PENDING_STATE_FILE);
}

function asRecord(input: unknown): Record<string, unknown> {
  return input && typeof input === 'object' && !Array.isArray(input)
    ? input as Record<string, unknown>
    : {};
}

function nullableString(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const normalized = value.trim();
  return normalized || null;
}

function pendingVersion(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const normalized = value.trim();
  if (!/^v?\d+\.\d+\.\d+$/i.test(normalized)) return null;
  return parseStableSemVer(normalized)?.normalized || null;
}

function pendingTimestamp(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const normalized = value.trim();
  if (!normalized || !Number.isFinite(Date.parse(normalized))) return null;
  return normalized;
}

function booleanValue(value: unknown, fallback: boolean): boolean {
  return typeof value === 'boolean' ? value : fallback;
}

function stateValue(value: unknown): UpdateCenterUpdateState {
  switch (value) {
    case 'checking':
    case 'downloading':
    case 'staging':
    case 'switching':
    case 'restarting':
    case 'healthy':
    case 'failed':
    case 'rolled_back':
    case 'unsupported':
    case 'idle':
      return value;
    default:
      return 'idle';
  }
}

function normalizeVersionList(input: unknown): string[] {
  if (!Array.isArray(input)) return [];
  const seen = new Set<string>();
  const versions: string[] = [];
  for (const item of input) {
    const value = nullableString(item);
    if (!value || seen.has(value)) continue;
    seen.add(value);
    versions.push(value);
  }
  return versions;
}

function normalizeCandidate(input: unknown): UpdateCenterVersionCandidate | null {
  const record = asRecord(input);
  const source = record.source === 'github-release' ? 'github-release' : null;
  const rawVersion = nullableString(record.rawVersion);
  const normalizedVersion = nullableString(record.normalizedVersion);
  const tagName = nullableString(record.tagName);
  if (!source || !rawVersion || !normalizedVersion || !tagName) return null;
  const assets = Array.isArray(record.assets)
    ? record.assets
      .map((asset) => {
        const value = asRecord(asset);
        const name = nullableString(value.name);
        const downloadUrl = nullableString(value.downloadUrl);
        if (!name || !downloadUrl) return null;
        return {
          name,
          downloadUrl,
          size: typeof value.size === 'number' && Number.isFinite(value.size) && value.size >= 0
            ? Math.trunc(value.size)
            : null,
          contentType: nullableString(value.contentType),
        };
      })
      .filter((asset): asset is NonNullable<typeof asset> => !!asset)
    : [];
  return {
    source,
    rawVersion,
    normalizedVersion,
    url: nullableString(record.url),
    tagName,
    digest: null,
    displayVersion: nullableString(record.displayVersion) || normalizedVersion,
    publishedAt: nullableString(record.publishedAt),
    assets,
  };
}

function normalizeStatusSnapshot(input: unknown): UpdateCenterStatusSnapshot | null {
  const record = asRecord(input);
  if (Object.keys(record).length === 0) return null;
  const capabilityRecord = asRecord(record.capability);
  const capability = Object.prototype.hasOwnProperty.call(record, 'capability')
    ? {
      supported: booleanValue(capabilityRecord.supported, false),
      mode: nullableString(capabilityRecord.mode) || 'unsupported',
      reason: nullableString(capabilityRecord.reason),
    }
    : undefined;
  return {
    githubRelease: normalizeCandidate(record.githubRelease),
    installedVersions: normalizeVersionList(record.installedVersions),
    ...(capability === undefined ? {} : { capability }),
  };
}

export function getDefaultUpdateCenterRuntimeState(): UpdateCenterRuntimeState {
  return {
    schemaVersion: UPDATE_CENTER_RUNTIME_SCHEMA_VERSION,
    updateState: 'idle',
    currentVersion: null,
    previousVersion: null,
    installedVersions: [],
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
}

export function normalizeUpdateCenterRuntimeState(input: unknown): UpdateCenterRuntimeState {
  const defaults = getDefaultUpdateCenterRuntimeState();
  const record = asRecord(input);
  const source = record.lastResolvedSource === 'github-release' ? 'github-release' : null;
  return {
    schemaVersion: typeof record.schemaVersion === 'number' && Number.isFinite(record.schemaVersion)
      ? Math.max(1, Math.trunc(record.schemaVersion))
      : defaults.schemaVersion,
    updateState: stateValue(record.updateState),
    currentVersion: nullableString(record.currentVersion),
    previousVersion: nullableString(record.previousVersion),
    installedVersions: normalizeVersionList(record.installedVersions),
    restartPending: booleanValue(record.restartPending, defaults.restartPending),
    taskId: nullableString(record.taskId),
    lastError: nullableString(record.lastError),
    updatedAt: nullableString(record.updatedAt),
    lastCheckedAt: nullableString(record.lastCheckedAt),
    lastCheckError: nullableString(record.lastCheckError),
    lastResolvedSource: source,
    lastResolvedDisplayVersion: nullableString(record.lastResolvedDisplayVersion),
    lastResolvedCandidateKey: nullableString(record.lastResolvedCandidateKey),
    lastNotifiedCandidateKey: nullableString(record.lastNotifiedCandidateKey),
    lastNotifiedAt: nullableString(record.lastNotifiedAt),
    statusSnapshot: Object.prototype.hasOwnProperty.call(record, 'statusSnapshot')
      ? normalizeStatusSnapshot(record.statusSnapshot)
      : defaults.statusSnapshot,
  };
}

type JsonFileReadResult = {
  value: unknown | null;
  parsed: boolean;
  remove: boolean;
};

async function readJsonFile(path: string): Promise<JsonFileReadResult> {
  let details;
  try {
    details = await lstat(path);
  } catch {
    return { value: null, parsed: false, remove: false };
  }
  if (details.isSymbolicLink() || !details.isFile()) {
    return { value: null, parsed: false, remove: true };
  }
  let contents: string;
  try {
    contents = await readFile(path, 'utf8');
  } catch {
    return { value: null, parsed: false, remove: false };
  }
  try {
    return { value: JSON.parse(contents) as unknown, parsed: true, remove: false };
  } catch {
    return { value: null, parsed: false, remove: true };
  }
}

async function removeInvalidJsonPath(path: string): Promise<void> {
  try {
    const details = await lstat(path);
    if (details.isDirectory() && !details.isSymbolicLink()) {
      await rm(path, { recursive: true, force: true });
      return;
    }
    await unlink(path);
  } catch {}
}

/** Write JSON by rename, so a crash cannot leave a half-written state file. */
export async function writeUpdateCenterJson(path: string, value: unknown): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const temporaryPath = `${path}.tmp-${process.pid}-${Math.random().toString(16).slice(2)}`;
  try {
    await writeFile(temporaryPath, `${JSON.stringify(value, null, 2)}\n`, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
    await rename(temporaryPath, path);
  } finally {
    await rm(temporaryPath, { force: true }).catch(() => undefined);
  }
}

export async function loadUpdateCenterRuntimeState(runtimeDir?: string): Promise<UpdateCenterRuntimeState> {
  const path = getUpdateCenterRuntimeStatePath(resolveUpdateCenterRuntimeDir(runtimeDir));
  const result = await readJsonFile(path);
  if (result.remove) await removeInvalidJsonPath(path);
  return normalizeUpdateCenterRuntimeState(result.value);
}

export async function saveUpdateCenterRuntimeState(
  input: unknown,
  runtimeDir?: string,
): Promise<UpdateCenterRuntimeState> {
  const next = normalizeUpdateCenterRuntimeState(input);
  await writeUpdateCenterJson(
    getUpdateCenterRuntimeStatePath(resolveUpdateCenterRuntimeDir(runtimeDir)),
    next,
  );
  return next;
}

export async function patchUpdateCenterRuntimeState(
  patch: Partial<UpdateCenterRuntimeState>,
  runtimeDir?: string,
): Promise<UpdateCenterRuntimeState> {
  const current = await loadUpdateCenterRuntimeState(runtimeDir);
  return saveUpdateCenterRuntimeState({
    ...current,
    ...patch,
    updatedAt: patch.updatedAt ?? new Date().toISOString(),
  }, runtimeDir);
}

function pendingPhase(value: unknown): UpdateCenterPendingPhase | null {
  return value === 'downloading'
    || value === 'staging'
    || value === 'switching'
    || value === 'restarting'
    || value === 'health-check'
    ? value
    : null;
}

function pendingReason(value: unknown): UpdateCenterPendingState['reason'] | null {
  return value === 'install' || value === 'manual-rollback' || value === 'bootstrap' ? value : null;
}

export function normalizeUpdateCenterPendingState(input: unknown): UpdateCenterPendingState | null {
  const record = asRecord(input);
  const taskId = nullableString(record.taskId);
  const targetVersion = pendingVersion(record.targetVersion);
  const previousVersionInput = record.previousVersion;
  const previousVersion = previousVersionInput === null ? null : pendingVersion(previousVersionInput);
  const phase = pendingPhase(record.phase);
  const reason = pendingReason(record.reason);
  const rollbackBudget = record.rollbackBudget;
  const hasPreviousVersion = Object.prototype.hasOwnProperty.call(record, 'previousVersion');
  const rollbackApplied = record.rollbackApplied;
  const createdAt = pendingTimestamp(record.createdAt);
  const updatedAt = pendingTimestamp(record.updatedAt);
  if (
    record.schemaVersion !== UPDATE_CENTER_RUNTIME_SCHEMA_VERSION
    || !hasPreviousVersion
    || (previousVersionInput !== null && !previousVersion)
    || !taskId
    || !/^[a-zA-Z0-9._-]{1,96}$/.test(taskId)
    || !targetVersion
    || !phase
    || !reason
    || typeof rollbackBudget !== 'number'
    || !Number.isFinite(rollbackBudget)
    || !Number.isSafeInteger(rollbackBudget)
    || rollbackBudget < 0
    || rollbackBudget > 1
    || !createdAt
    || !updatedAt
    || (rollbackApplied !== undefined && typeof rollbackApplied !== 'boolean')
  ) return null;
  return {
    schemaVersion: UPDATE_CENTER_RUNTIME_SCHEMA_VERSION,
    taskId,
    targetVersion,
    previousVersion,
    phase,
    rollbackBudget,
    createdAt,
    updatedAt,
    reason,
    ...(rollbackApplied === undefined ? {} : { rollbackApplied }),
  };
}

export async function loadUpdateCenterPendingState(runtimeDir?: string): Promise<UpdateCenterPendingState | null> {
  const path = getUpdateCenterPendingStatePath(resolveUpdateCenterRuntimeDir(runtimeDir));
  const result = await readJsonFile(path);
  if (result.remove) await removeInvalidJsonPath(path);
  const normalized = normalizeUpdateCenterPendingState(result.value);
  if (result.parsed && !normalized) await removeInvalidJsonPath(path);
  return normalized;
}

export async function saveUpdateCenterPendingState(
  input: UpdateCenterPendingState,
  runtimeDir?: string,
): Promise<UpdateCenterPendingState> {
  const next = normalizeUpdateCenterPendingState(input);
  if (!next) throw new Error('invalid update center pending state');
  await writeUpdateCenterJson(
    getUpdateCenterPendingStatePath(resolveUpdateCenterRuntimeDir(runtimeDir)),
    next,
  );
  return next;
}

export async function clearUpdateCenterPendingState(runtimeDir?: string): Promise<void> {
  await unlink(getUpdateCenterPendingStatePath(resolveUpdateCenterRuntimeDir(runtimeDir))).catch(() => undefined);
}

function readReleaseManifestVersion(releasePath: string): string | null {
  try {
    const manifestPath = join(releasePath, 'release.json');
    const details = lstatSync(manifestPath);
    if (!details.isFile() || details.isSymbolicLink()) return null;
    const payload = JSON.parse(readFileSync(manifestPath, 'utf8')) as { version?: unknown };
    return parseStableSemVer(nullableString(payload.version))?.normalized || null;
  } catch {
    return null;
  }
}

function linkTarget(runtimeDir: string, name: 'current' | 'previous'): string | null {
  const runtimeRoot = resolve(runtimeDir);
  const releasesRoot = join(runtimeRoot, 'releases');
  const pointerPath = join(runtimeRoot, name);
  try {
    const runtimeDetails = lstatSync(runtimeRoot);
    const releasesDetails = lstatSync(releasesRoot);
    if (!runtimeDetails.isDirectory() || runtimeDetails.isSymbolicLink()) return null;
    if (!releasesDetails.isDirectory() || releasesDetails.isSymbolicLink()) return null;

    const target = readlinkSync(pointerPath);
    if (!target || isAbsolute(target) || target.includes('\\')) return null;
    const resolvedTarget = resolve(runtimeRoot, target);
    if (!isPathInside(runtimeRoot, resolvedTarget)) return null;

    const releaseRelative = relative(releasesRoot, resolvedTarget).replaceAll('\\', '/');
    const targetVersion = parseStableSemVer(releaseRelative)?.normalized;
    const canonicalTarget = targetVersion ? `releases/${targetVersion}` : '';
    if (!targetVersion || target !== canonicalTarget || targetVersion !== releaseRelative) return null;

    const targetDetails = lstatSync(resolvedTarget);
    if (!targetDetails.isDirectory() || targetDetails.isSymbolicLink()) return null;
    const realRuntime = realpathSync(runtimeRoot);
    const realReleases = realpathSync(releasesRoot);
    const realTarget = realpathSync(resolvedTarget);
    if (!isPathInside(realRuntime, realReleases) || !isPathInside(realReleases, realTarget)) return null;
    if (readReleaseManifestVersion(resolvedTarget) !== targetVersion) return null;
    return resolvedTarget;
  } catch {
    return null;
  }
}

export function readUpdateCenterPointer(runtimeDir: string, name: 'current' | 'previous'): string | null {
  const target = linkTarget(resolveUpdateCenterRuntimeDir(runtimeDir), name);
  return target && existsSync(target) ? target : null;
}

export async function ensureUpdateCenterRuntimeDirectories(runtimeDir?: string): Promise<string> {
  const root = resolveUpdateCenterRuntimeDir(runtimeDir);
  await mkdir(root, { recursive: true });
  const rootDetails = await lstat(root);
  if (!rootDetails.isDirectory() || rootDetails.isSymbolicLink()) {
    throw new Error('update center runtime root must be a real directory');
  }
  for (const name of ['releases', 'staging'] as const) {
    const child = join(root, name);
    try {
      const details = await lstat(child);
      if (!details.isDirectory() || details.isSymbolicLink()) {
        throw new Error(`update center runtime ${name} directory must not be a symbolic link`);
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException)?.code !== 'ENOENT') throw error;
      await mkdir(child, { recursive: false });
    }
  }
  return root;
}

export function isPathInside(parent: string, child: string): boolean {
  const relativePath = relative(resolve(parent), resolve(child));
  return relativePath === '' || (!relativePath.startsWith('..' + requirePathSeparator()) && relativePath !== '..' && !isAbsolute(relativePath));
}

function requirePathSeparator(): string {
  return process.platform === 'win32' ? '\\' : '/';
}
