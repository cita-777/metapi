import { spawn } from 'node:child_process';
import { cpSync, existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, readlinkSync, realpathSync, renameSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const HEALTH_TIMEOUT_MS = 60_000;
export const HEALTH_INTERVAL_MS = 500;
const RELEASE_SCHEMA_VERSION = 1;

function normalize(value) {
  return String(value || '').trim();
}

function stableVersionParts(value) {
  const match = normalize(value).replace(/^v/i, '').match(/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/);
  if (!match) return null;
  const parts = match.slice(1).map((part) => Number.parseInt(part, 10));
  return parts.every((part) => Number.isSafeInteger(part)) ? parts : null;
}

function strictPendingString(value) {
  return typeof value === 'string' ? value.trim() : '';
}

function strictPendingTimestamp(value) {
  const normalized = strictPendingString(value);
  return normalized && Number.isFinite(Date.parse(normalized)) ? normalized : null;
}

function compareVersions(left, right) {
  const a = stableVersionParts(left);
  const b = stableVersionParts(right);
  if (!a || !b) return null;
  return a[0] - b[0] || a[1] - b[1] || a[2] - b[2];
}

function expectedArchitecture() {
  return process.arch === 'x64' ? 'amd64' : process.arch === 'arm64' ? 'arm64' : null;
}

function isSafeRelativePath(value) {
  const normalized = normalize(value);
  if (!normalized || normalized.startsWith('/') || normalized.includes('\\')) return false;
  if (/^[a-zA-Z]:[\\/]/.test(normalized)) return false;
  const segments = normalized.split('/');
  return segments.every((segment) => segment && segment !== '.' && segment !== '..');
}

function isPathInside(parent, child) {
  const relativePath = relative(resolve(parent), resolve(child)).replaceAll('\\', '/');
  return relativePath === '' || (!relativePath.startsWith('../') && relativePath !== '..' && !relativePath.startsWith('/'));
}

export function resolveRuntimeDir(env = process.env) {
  return resolve(normalize(env.UPDATE_CENTER_RUNTIME_DIR) || '/app/runtime');
}

export function resolveBootstrapDir(env = process.env) {
  return resolve(normalize(env.METAPI_BOOTSTRAP_DIR) || '/app/bootstrap');
}

function ensureRuntimeLayout(runtime) {
  mkdirSync(runtime, { recursive: true });
  const runtimeDetails = lstatSync(runtime);
  if (!runtimeDetails.isDirectory() || runtimeDetails.isSymbolicLink()) {
    throw new Error('runtime root must be a real directory');
  }
  for (const name of ['releases', 'staging']) {
    const path = join(runtime, name);
    if (existsSync(path)) {
      const details = lstatSync(path);
      if (!details.isDirectory() || details.isSymbolicLink()) {
        throw new Error(`runtime ${name} directory must not be a symbolic link`);
      }
    } else {
      mkdirSync(path);
    }
  }
  for (const name of ['current', 'previous']) {
    const path = pointerPath(runtime, name);
    let details;
    try {
      details = lstatSync(path);
    } catch (error) {
      if (error?.code === 'ENOENT') continue;
      throw new Error(`unable to inspect runtime ${name} pointer`);
    }
    if (!details.isSymbolicLink() || !isCanonicalRuntimePointer(runtime, name)) {
      throw new Error(`runtime ${name} pointer is invalid or unsafe`);
    }
  }
}

function readJson(path) {
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    return null;
  }
}

function normalizePending(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  if (value.schemaVersion !== RELEASE_SCHEMA_VERSION) return null;
  const targetVersion = strictPendingString(value.targetVersion);
  const taskId = strictPendingString(value.taskId);
  const phase = strictPendingString(value.phase);
  const parsedTargetVersion = targetVersion ? stableVersionParts(targetVersion) : null;
  const reason = strictPendingString(value.reason);
  const rollbackBudget = value.rollbackBudget;
  const hasPreviousVersion = Object.prototype.hasOwnProperty.call(value, 'previousVersion');
  const rollbackApplied = value.rollbackApplied;
  const createdAt = strictPendingTimestamp(value.createdAt);
  const updatedAt = strictPendingTimestamp(value.updatedAt);
  if (
    !parsedTargetVersion
    || !/^[a-zA-Z0-9._-]{1,96}$/.test(taskId)
    || !['downloading', 'staging', 'switching', 'restarting', 'health-check'].includes(phase)
    || !hasPreviousVersion
    || (value.previousVersion !== null && typeof value.previousVersion !== 'string')
    || !['install', 'manual-rollback', 'bootstrap'].includes(reason)
    || !createdAt
    || !updatedAt
    || typeof rollbackBudget !== 'number'
    || !Number.isFinite(rollbackBudget)
    || !Number.isSafeInteger(rollbackBudget)
    || rollbackBudget < 0
    || rollbackBudget > 1
    || (rollbackApplied !== undefined && typeof rollbackApplied !== 'boolean')
  ) return null;
  const previousVersionValue = strictPendingString(value.previousVersion);
  const parsedPreviousVersion = previousVersionValue ? stableVersionParts(previousVersionValue) : null;
  if (previousVersionValue && !parsedPreviousVersion) return null;
  return {
    schemaVersion: RELEASE_SCHEMA_VERSION,
    targetVersion: parsedTargetVersion.join('.'),
    previousVersion: parsedPreviousVersion ? parsedPreviousVersion.join('.') : null,
    taskId,
    phase,
    rollbackBudget,
    reason,
    createdAt,
    updatedAt,
    ...(rollbackApplied === undefined ? {} : { rollbackApplied }),
  };
}

function readPending(runtime) {
  const path = join(runtime, 'pending.json');
  let details;
  try {
    details = lstatSync(path);
  } catch {
    return null;
  }
  if (!details.isFile() || details.isSymbolicLink()) {
    removePending(runtime);
    return null;
  }
  let contents;
  try {
    contents = readFileSync(path, 'utf8');
  } catch {
    return null;
  }
  let payload;
  try {
    payload = JSON.parse(contents);
  } catch {
    removePending(runtime);
    return null;
  }
  const pending = normalizePending(payload);
  if (pending) return pending;
  removePending(runtime);
  return null;
}

function removePending(runtime) {
  const path = join(runtime, 'pending.json');
  try {
    const details = lstatSync(path);
    rmSync(path, { force: true, recursive: details.isDirectory() && !details.isSymbolicLink() });
  } catch {}
}

function writeJsonAtomic(path, value) {
  const temporary = `${path}.tmp-${process.pid}-${Math.random().toString(16).slice(2)}`;
  writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
  renameSync(temporary, path);
}

function readManifest(root) {
  const rootDetails = lstatSync(root);
  if (!rootDetails.isDirectory() || rootDetails.isSymbolicLink()) {
    throw new Error(`release root must be a real directory: ${root}`);
  }
  const manifestPath = join(root, 'release.json');
  const manifestDetails = lstatSync(manifestPath);
  if (!manifestDetails.isFile() || manifestDetails.isSymbolicLink()) {
    throw new Error(`release manifest must be a regular file in ${root}`);
  }
  const manifest = readJson(manifestPath);
  if (!manifest || typeof manifest !== 'object') throw new Error(`release manifest is missing in ${root}`);
  if (manifest.schemaVersion !== RELEASE_SCHEMA_VERSION) {
    throw new Error(`release manifest schema is unsupported in ${root}`);
  }
  const version = normalize(manifest.version);
  if (!version) throw new Error(`release manifest has no version in ${root}`);
  const parsedVersion = stableVersionParts(version);
  if (!parsedVersion) throw new Error(`release manifest version is not a stable SemVer in ${root}`);
  if (manifest.channel !== 'stable') throw new Error('release manifest channel is not stable');
  if (manifest.platform !== 'linux') throw new Error('release manifest platform is not linux');
  const expectedArch = expectedArchitecture();
  if (manifest.arch !== expectedArch) {
    throw new Error(`release manifest architecture does not match ${expectedArch || process.arch}`);
  }
  const entrypoint = normalize(manifest.entrypoint);
  const migrationEntrypoint = normalize(manifest.migrationEntrypoint);
  if (!entrypoint || !migrationEntrypoint) {
    throw new Error(`release manifest entrypoints are required in ${root}`);
  }
  for (const [label, value] of [['entrypoint', entrypoint], ['migrationEntrypoint', migrationEntrypoint]]) {
    if (!isSafeRelativePath(value)) {
      throw new Error(`${label} is not a safe relative path`);
    }
  }
  const manifestNodeMajor = manifest.nodeMajor;
  const runningNodeMajor = Number.parseInt(process.versions.node.split('.')[0] || '', 10);
  if (!Number.isSafeInteger(manifestNodeMajor) || manifestNodeMajor <= 0) {
    throw new Error('release manifest nodeMajor is required');
  }
  if (manifestNodeMajor !== runningNodeMajor) {
    throw new Error(`release manifest requires Node ${manifestNodeMajor}`);
  }
  for (const [label, value] of [['entrypoint', entrypoint], ['migrationEntrypoint', migrationEntrypoint]]) {
    const target = join(root, value);
    const details = lstatSync(target);
    if (!details.isFile() || details.isSymbolicLink()) throw new Error(`${label} is not a regular file in ${root}`);
  }
  return {
    ...manifest,
    version: parsedVersion.join('.'),
    entrypoint,
    migrationEntrypoint,
  };
}

function pointerPath(runtime, name) {
  return join(runtime, name);
}

function readlinkSafeSync(path) {
  try {
    return readlinkSync(path);
  } catch {
    return null;
  }
}

function isCanonicalRuntimePointer(runtime, name) {
  const target = readlinkSafeSync(pointerPath(runtime, name));
  if (!target || target.startsWith('/') || target.includes('\\') || !target.startsWith('releases/')) return false;
  const version = stableVersionParts(target.slice('releases/'.length))?.join('.');
  if (!version || target !== `releases/${version}`) return false;
  const runtimeRoot = resolve(runtime);
  const releaseRoot = resolve(runtimeRoot, target);
  if (!isPathInside(runtimeRoot, releaseRoot)) return false;
  try {
    const releaseDetails = lstatSync(releaseRoot);
    if (!releaseDetails.isDirectory() || releaseDetails.isSymbolicLink()) return false;
    const realRuntimeRoot = realpathSync(runtimeRoot);
    const realReleasesRoot = realpathSync(join(runtimeRoot, 'releases'));
    const realReleaseRoot = realpathSync(releaseRoot);
    return isPathInside(realRuntimeRoot, realReleasesRoot) && isPathInside(realReleasesRoot, realReleaseRoot);
  } catch {
    return false;
  }
}

function resolveSymlinkPointer(runtime, name) {
  const pointer = pointerPath(runtime, name);
  const target = readlinkSafeSync(pointer);
  if (!target || target.startsWith('/') || target.includes('\\') || !target.startsWith('releases/')) return null;
  const root = resolve(runtime, target);
  const runtimeRoot = resolve(runtime);
  let realRuntimeRoot;
  try {
    realRuntimeRoot = realpathSync(runtimeRoot);
  } catch {
    return null;
  }
  try {
    const releasesDetails = lstatSync(join(runtimeRoot, 'releases'));
    if (!releasesDetails.isDirectory() || releasesDetails.isSymbolicLink()) return null;
  } catch {
    return null;
  }
  let releaseDetails;
  try {
    releaseDetails = lstatSync(root);
  } catch {
    return null;
  }
  if (!releaseDetails.isDirectory() || releaseDetails.isSymbolicLink()) return null;
  if (!isPathInside(runtimeRoot, root)) return null;
  let realRoot;
  let realReleasesRoot;
  try {
    realRoot = realpathSync(root);
    realReleasesRoot = realpathSync(join(runtimeRoot, 'releases'));
  } catch {
    return null;
  }
  if (!isPathInside(realRuntimeRoot, realReleasesRoot) || !isPathInside(realRuntimeRoot, realRoot)) return null;
  const relativeRelease = relative(realReleasesRoot, realRoot).replaceAll('\\', '/');
  const relativeVersion = stableVersionParts(relativeRelease)?.join('.');
  if (!relativeVersion || relativeVersion !== relativeRelease || target !== `releases/${relativeVersion}`) return null;
  if (!existsSync(join(realRoot, 'release.json'))) return null;
  try {
    const manifest = readManifest(root);
    if (manifest.version !== relativeRelease) return null;
    return root;
  } catch {
    return null;
  }
}

function atomicPointer(runtime, name, target) {
  const targetVersion = target && target.startsWith('releases/')
    ? stableVersionParts(target.slice('releases/'.length))?.join('.')
    : null;
  if (!target || target !== `releases/${targetVersion || ''}`) {
    throw new Error(`invalid ${name} pointer target`);
  }
  const temporary = join(runtime, `.${name}.tmp-${process.pid}`);
  rmSync(temporary, { force: true });
  symlinkSync(target, temporary, 'dir');
  renameSync(temporary, pointerPath(runtime, name));
}

export function switchPointers(runtime, nextRoot, previousRoot = null) {
  const runtimeRoot = resolve(runtime);
  const toPointerTarget = (releaseRoot) => {
    const relativePath = relative(runtimeRoot, resolve(releaseRoot)).replaceAll('\\', '/');
    if (!relativePath.startsWith('releases/') || relativePath.split('/').includes('..')) {
      throw new Error('invalid release pointer target');
    }
    return relativePath;
  };
  const relativeNext = toPointerTarget(nextRoot);
  const currentSnapshot = resolveSymlinkPointer(runtime, 'current');
  const previousSnapshot = resolveSymlinkPointer(runtime, 'previous');
  try {
    if (previousRoot) {
      atomicPointer(runtime, 'previous', toPointerTarget(previousRoot));
    }
    atomicPointer(runtime, 'current', relativeNext);
  } catch (error) {
    restorePointer(runtime, 'current', currentSnapshot);
    restorePointer(runtime, 'previous', previousSnapshot);
    throw error;
  }
}

function restorePointer(runtime, name, releaseRoot) {
  if (releaseRoot) {
    const target = relative(resolve(runtime), resolve(releaseRoot)).replaceAll('\\', '/');
    atomicPointer(runtime, name, target);
    return;
  }
  rmSync(pointerPath(runtime, name), { force: true });
}

function bootstrapRuntime(runtime, bootstrap) {
  ensureRuntimeLayout(runtime);
  const current = resolveSymlinkPointer(runtime, 'current');
  const manifest = readManifest(bootstrap);
  const pending = readPending(runtime);
  if (current && pending) {
    const currentManifest = readManifest(current);
    if (pending.reason === 'bootstrap' && normalize(currentManifest.version) === normalize(pending.previousVersion)) {
      const target = resolveInstalledRelease(runtime, pending.targetVersion);
      if (target) {
        switchPointers(runtime, target, current);
        return target;
      }
      removePending(runtime);
    } else {
      return current;
    }
  }
  if (current) {
    const currentManifest = readManifest(current);
    const comparison = compareVersions(currentManifest.version, manifest.version);
    if (comparison === null || comparison >= 0) return current;
  }
  const destination = join(runtime, 'releases', manifest.version);
  let destinationReady = false;
  let destinationExists = false;
  let destinationDetails = null;
  try {
    destinationDetails = lstatSync(destination);
    destinationExists = true;
    if (!destinationDetails.isDirectory() || destinationDetails.isSymbolicLink()) {
      throw new Error('release destination is not a real directory');
    }
    readManifest(destination);
    destinationReady = true;
  } catch (error) {
    if (destinationExists) {
      if (destinationDetails?.isSymbolicLink()) throw error;
      rmSync(destination, { recursive: true, force: true });
    } else if ((error?.code ?? error?.cause?.code) !== 'ENOENT') {
      throw error;
    }
  }
  if (!destinationReady) cpSync(bootstrap, destination, { recursive: true, force: true });
  if (current) {
    writeJsonAtomic(join(runtime, 'pending.json'), {
      schemaVersion: 1,
      taskId: `bootstrap-${process.pid}`,
      targetVersion: manifest.version,
      previousVersion: readManifest(current).version,
      phase: 'health-check',
      rollbackBudget: 1,
      reason: 'bootstrap',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    });
    switchPointers(runtime, destination, current);
    return destination;
  }
  switchPointers(runtime, destination);
  return destination;
}

function setState(runtime, patch) {
  const statePath = join(runtime, 'state.json');
  const current = readJson(statePath) || {};
  writeJsonAtomic(statePath, {
    ...current,
    ...patch,
    schemaVersion: RELEASE_SCHEMA_VERSION,
    updatedAt: new Date().toISOString(),
  });
}

function finalizePendingFailure(runtime, pending, message) {
  removePending(runtime);
  setState(runtime, {
    updateState: 'failed',
    currentVersion: pointerVersion(runtime, 'current'),
    previousVersion: pointerVersion(runtime, 'previous'),
    taskId: pending?.taskId || null,
    restartPending: false,
    lastError: message,
  });
}

function resolveInstalledRelease(runtime, version) {
  const normalizedVersion = stableVersionParts(version)?.join('.');
  if (!normalizedVersion) return null;
  const root = join(runtime, 'releases', normalizedVersion);
  try {
    const details = lstatSync(root);
    if (!details.isDirectory() || details.isSymbolicLink()) return null;
    const realRoot = realpathSync(root);
    const releasesRoot = realpathSync(join(runtime, 'releases'));
    const relativeRelease = relative(releasesRoot, realRoot).replaceAll('\\', '/');
    if (!relativeRelease || relativeRelease.includes('/') || relativeRelease !== normalizedVersion) return null;
    const manifest = readManifest(root);
    if (manifest.version !== normalizedVersion) return null;
    return root;
  } catch {
    return null;
  }
}

function pointerVersion(runtime, name) {
  const release = resolveSymlinkPointer(runtime, name);
  if (!release) return null;
  try {
    return readManifest(release).version;
  } catch {
    return null;
  }
}

function pruneRuntimeReleases(runtime, keepCount = 2) {
  const keep = Math.max(2, Math.trunc(Number(keepCount) || 0));
  const releasesRoot = join(runtime, 'releases');
  const protectedPaths = new Set(
    ['current', 'previous']
      .map((name) => resolveSymlinkPointer(runtime, name))
      .filter(Boolean)
      .map((path) => resolve(path)),
  );
  const installed = [];
  for (const entry of readdirSync(releasesRoot, { withFileTypes: true })) {
    if (!entry.isDirectory() || entry.isSymbolicLink()) continue;
    const version = stableVersionParts(entry.name)?.join('.');
    if (!version || version !== entry.name) continue;
    const path = join(releasesRoot, entry.name);
    try {
      const manifest = readManifest(path);
      if (manifest.version !== version) continue;
      installed.push({ version, path });
    } catch {
      continue;
    }
  }
  installed.sort((left, right) => compareVersions(right.version, left.version) || right.version.localeCompare(left.version));
  const removed = [];
  for (const entry of installed.slice(keep)) {
    if (protectedPaths.has(resolve(entry.path))) continue;
    rmSync(entry.path, { recursive: true, force: true });
    removed.push(entry.version);
  }
  return removed;
}

function reconcilePending(runtime, current, pending) {
  if (!pending) return { current, pending: null };
  if (!current) return { current, pending: null, invalid: true };
  try {
    const currentManifest = readManifest(current);
    if (currentManifest.version === pending.targetVersion) {
      if (pending.previousVersion) {
        const previous = resolveSymlinkPointer(runtime, 'previous');
        if (!previous || readManifest(previous).version !== pending.previousVersion) {
          return { current, pending: null, invalid: true };
        }
      }
      return { current, pending };
    }
    if (pending.previousVersion && currentManifest.version === pending.previousVersion) {
      const target = resolveInstalledRelease(runtime, pending.targetVersion);
      if (target) {
        switchPointers(runtime, target, current);
        return { current: target, pending };
      }
    }
    return { current, pending: null, invalid: true };
  } catch (error) {
    return {
      current,
      pending: null,
      invalid: true,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

export function markPendingHealthCheck(runtime, pending) {
  const latestPending = readPending(runtime);
  if (!latestPending || latestPending.taskId !== pending.taskId || latestPending.targetVersion !== pending.targetVersion) {
    throw new Error('pending update transaction changed during startup');
  }
  const nextPending = {
    ...latestPending,
    phase: 'health-check',
    updatedAt: new Date().toISOString(),
  };
  writeJsonAtomic(join(runtime, 'pending.json'), nextPending);
  return nextPending;
}

async function waitForHealth(version, port, timeoutMs = HEALTH_TIMEOUT_MS, intervalMs = HEALTH_INTERVAL_MS, shouldStop = () => false) {
  const deadline = Date.now() + timeoutMs;
  let lastError = 'health check did not return ready';
  while (Date.now() < deadline) {
    if (shuttingDown || shouldStop()) throw new Error('health check was cancelled');
    try {
      const response = await fetch(`http://127.0.0.1:${port}/healthz`, {
        signal: AbortSignal.timeout(Math.max(100, Math.min(2_000, intervalMs * 4))),
      });
      if (response.ok) {
        const payload = await response.json();
        if (payload?.status === 'ok' && payload?.ready === true && normalize(payload.version) === normalize(version)) return payload;
        lastError = `health version mismatch (expected ${version})`;
      } else {
        lastError = `health HTTP ${response.status}`;
      }
    } catch (error) {
      lastError = error instanceof Error ? error.message : String(error);
    }
    await new Promise((resolvePromise) => setTimeout(resolvePromise, intervalMs));
  }
  throw new Error(lastError);
}

function runChild(command, args, options) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: options.env,
      stdio: 'inherit',
    });
    activeChild = child;
    child.once('error', reject);
    child.once('exit', (code, signal) => resolvePromise({ code: code ?? 1, signal: signal || null }));
  });
}

function stopActiveChild(signal = 'SIGTERM') {
  if (!activeChild || activeChild.killed) return;
  try {
    activeChild.kill(signal);
  } catch {}
}

let activeChild = null;
let shuttingDown = false;
for (const signal of ['SIGTERM', 'SIGINT']) {
  process.on(signal, () => {
    shuttingDown = true;
    if (activeChild && !activeChild.killed) activeChild.kill(signal);
  });
}

async function launchVersion(runtime, root, pending, startupError = null) {
  const manifest = readManifest(root);
  if (pending && manifest.version !== pending.targetVersion) {
    throw new Error(`pending update targets ${pending.targetVersion}, but current release is ${manifest.version}`);
  }
  const childEnv = {
    ...process.env,
    NODE_ENV: 'production',
    METAPI_RELEASE_ROOT: root,
    METAPI_RELEASE_VERSION: manifest.version,
    UPDATE_CENTER_RUNTIME_DIR: runtime,
  };
  setState(runtime, {
    updateState: pending ? 'restarting' : 'idle',
    currentVersion: manifest.version,
    restartPending: !!pending,
    taskId: pending?.taskId || null,
    lastError: startupError,
  });

  const migration = await runChild(process.execPath, [join(root, manifest.migrationEntrypoint)], { cwd: root, env: childEnv });
  if (migration.code !== 0 || migration.signal) throw new Error(`migration exited with ${migration.code || migration.signal}`);

  if (pending) {
    pending = markPendingHealthCheck(runtime, pending);
  }

  const serverPromise = runChild(process.execPath, [join(root, manifest.entrypoint)], { cwd: root, env: childEnv });
  let serverExited = false;
  const serverExitPromise = serverPromise.then((result) => {
    serverExited = true;
    return { type: 'exit', result };
  });
  try {
    const startup = await Promise.race([
      waitForHealth(
        manifest.version,
        Number(process.env.PORT || 4000),
        HEALTH_TIMEOUT_MS,
        HEALTH_INTERVAL_MS,
        () => serverExited,
      ).then((payload) => ({ type: 'healthy', payload })),
      serverExitPromise,
    ]);
    if (startup.type === 'exit') {
      throw new Error(`server exited before becoming healthy with ${startup.result.code ?? startup.result.signal ?? 'unknown status'}`);
    }
  } catch (error) {
    stopActiveChild();
    await serverPromise.catch(() => undefined);
    throw error;
  }
  // Retention is deliberately best-effort. A cleanup failure must never turn
  // an otherwise healthy candidate into a rollback.
  try {
    pruneRuntimeReleases(runtime);
  } catch {}
  if (pending) {
    setState(runtime, {
      updateState: pending?.rollbackApplied ? 'rolled_back' : 'healthy',
      currentVersion: manifest.version,
      previousVersion: pointerVersion(runtime, 'previous'),
      restartPending: false,
      lastError: pending?.rollbackApplied ? startupError : null,
    });
    removePending(runtime);
  } else {
    setState(runtime, {
      updateState: startupError ? 'failed' : 'healthy',
      currentVersion: manifest.version,
      previousVersion: pointerVersion(runtime, 'previous'),
      restartPending: false,
      lastError: startupError,
    });
  }
  const result = await serverPromise;
  if (shuttingDown) return result;
  if (readPending(runtime)) return { ...result, restartRequested: true };
  if (result.code !== 0 || result.signal) throw new Error(`server exited with ${result.code || result.signal}`);
  return result;
}

async function run() {
  const runtime = resolveRuntimeDir();
  const bootstrap = resolveBootstrapDir();
  if (!existsSync(bootstrap)) throw new Error(`bootstrap bundle is missing: ${bootstrap}`);
  mkdirSync(runtime, { recursive: true });
  let current = bootstrapRuntime(runtime, bootstrap);
  let pending = readPending(runtime);
  let startupError = null;
  if (pending) {
    const reconciled = reconcilePending(runtime, current, pending);
    current = reconciled.current || current;
    pending = reconciled.pending;
    if (reconciled.invalid) {
      removePending(runtime);
      startupError = reconciled.error || 'pending update transaction does not match the current release';
    }
  }
  let rollbackUsed = false;

  while (!shuttingDown) {
    try {
      const result = await launchVersion(runtime, current, pending, startupError);
      if (shuttingDown) return;
      if (result?.restartRequested) {
        current = resolveSymlinkPointer(runtime, 'current') || current;
        pending = readPending(runtime);
        startupError = null;
        continue;
      }
      return;
    } catch (error) {
      if (shuttingDown) return;
      const message = error instanceof Error ? error.message : String(error);
      pending = readPending(runtime);
      setState(runtime, { updateState: 'failed', restartPending: !!pending, lastError: message });
      const previous = resolveSymlinkPointer(runtime, 'previous');
      const budget = Number(pending?.rollbackBudget ?? pending?.autoRollbackBudget ?? 0);
      if (!rollbackUsed && pending && previous && budget > 0) {
        rollbackUsed = true;
        const failed = current;
        try {
          const previousManifest = readManifest(previous);
          const failedManifest = readManifest(failed);
          const rollbackPending = {
            ...pending,
            targetVersion: previousManifest.version,
            previousVersion: failedManifest.version,
            rollbackBudget: 0,
            phase: 'restarting',
            rollbackApplied: true,
            updatedAt: new Date().toISOString(),
          };
          writeJsonAtomic(join(runtime, 'pending.json'), rollbackPending);
          pending = rollbackPending;
          switchPointers(runtime, previous, failed);
          current = previous;
          startupError = message;
          setState(runtime, {
            updateState: 'rolled_back',
            currentVersion: previousManifest.version,
            previousVersion: failedManifest.version,
            restartPending: true,
            lastError: message,
          });
          continue;
        } catch (rollbackError) {
          const rollbackMessage = rollbackError instanceof Error ? rollbackError.message : String(rollbackError);
          try {
            finalizePendingFailure(runtime, pending, `${message}; automatic rollback failed: ${rollbackMessage}`);
          } catch {}
          throw rollbackError;
        }
      }
      if (pending) {
        try {
          finalizePendingFailure(runtime, pending, message);
        } catch {}
      }
      throw error;
    }
  }
}

const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (isMain) {
  run().catch((error) => {
    console.error(`[metapi-runner] ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 1;
  });
}

export {
  readManifest,
  normalizePending,
  readPending,
  reconcilePending,
  resolveSymlinkPointer,
  waitForHealth,
  bootstrapRuntime,
  pruneRuntimeReleases,
  finalizePendingFailure,
  run,
};
