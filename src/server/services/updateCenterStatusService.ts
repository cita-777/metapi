import { config as runtimeConfig } from '../config.js';
import { formatUtcSqlDateTime } from './localTimeService.js';
import { listBackgroundTasks } from './backgroundTaskService.js';
import {
  fetchLatestStableGitHubRelease,
  getCurrentRuntimeVersion,
  type UpdateCenterVersionCandidate,
} from './updateCenterVersionService.js';
import {
  loadUpdateCenterConfig,
  type UpdateCenterConfig,
} from './updateCenterConfigService.js';
import {
  getUpdateCenterLocalStatus,
  type UpdateCenterInstalledVersion,
  type UpdateCenterRuntimeCapability,
} from './updateCenterLocalUpdateService.js';
import {
  loadUpdateCenterRuntimeState,
  patchUpdateCenterRuntimeState,
  type UpdateCenterRuntimeState,
} from './updateCenterRuntimeStateService.js';
import {
  UPDATE_CENTER_ROLLBACK_TASK_TYPE,
  UPDATE_CENTER_UPDATE_TASK_TYPE,
} from './updateCenterTaskConstants.js';
import { resolveUpdateReminderCandidate, type UpdateReminderCandidate } from './updateCenterReminderService.js';

type UpdateCenterTask = ReturnType<typeof listBackgroundTasks>[number];

export type UpdateCenterInstalledVersionSummary = {
  version: string;
  current: boolean;
  previous: boolean;
  installedAt?: string | null;
};

export type UpdateCenterStatusResult = {
  supported: boolean;
  mode: string;
  reason: string | null;
  currentVersion: string;
  latestRelease: UpdateCenterVersionCandidate | null;
  installedVersions: UpdateCenterInstalledVersionSummary[];
  updateState: UpdateCenterRuntimeState['updateState'];
  restartPending: boolean;
  canUpdate: boolean;
  canRollback: boolean;
  lastError: string | null;
  config: UpdateCenterConfig;
  runningTask: UpdateCenterTask | null;
  lastFinishedTask: UpdateCenterTask | null;
  runtime: UpdateCenterRuntimeState;
};

function summarizeError(error: unknown): string {
  if (error instanceof Error && error.message) return error.message;
  return String(error || 'unknown update error');
}

function getUpdateTasks(): UpdateCenterTask[] {
  return listBackgroundTasks(50).filter((task) => (
    task.type === UPDATE_CENTER_UPDATE_TASK_TYPE || task.type === UPDATE_CENTER_ROLLBACK_TASK_TYPE
  ));
}

function taskSnapshot(): { runningTask: UpdateCenterTask | null; lastFinishedTask: UpdateCenterTask | null } {
  const tasks = getUpdateTasks();
  return {
    runningTask: tasks.find((task) => task.status === 'pending' || task.status === 'running') || null,
    lastFinishedTask: tasks.find((task) => task.status === 'succeeded' || task.status === 'failed') || null,
  };
}

function mapInstalledVersions(entries: UpdateCenterInstalledVersion[]): UpdateCenterInstalledVersionSummary[] {
  return entries.map((entry) => ({
    version: entry.version,
    current: entry.current,
    previous: entry.previous,
  }));
}

function fallbackCapability(runtimeDir?: string): UpdateCenterRuntimeCapability {
  return {
    supported: false,
    mode: 'unsupported',
    reason: '本地运行时目录不可用',
    runtimeDir: runtimeDir || runtimeConfig.updateCenterRuntimeDir || '',
    architecture: null,
    platform: process.platform,
    nodeMajor: Number.parseInt(process.versions.node.split('.')[0] || '0', 10),
    persistent: false,
    writable: false,
    currentVersion: null,
  };
}

async function inspectLocalState() {
  try {
    return await getUpdateCenterLocalStatus();
  } catch {
    return {
      capability: fallbackCapability(),
      state: await loadUpdateCenterRuntimeState(),
      pending: null,
      installedVersions: [],
    };
  }
}

function buildStatusResponse(
  config: UpdateCenterConfig,
  latestRelease: UpdateCenterVersionCandidate | null,
  local: Awaited<ReturnType<typeof inspectLocalState>>,
): UpdateCenterStatusResult {
  const currentVersion = local.capability.currentVersion
    || local.state.currentVersion
    || getCurrentRuntimeVersion();
  const installedVersions = mapInstalledVersions(local.installedVersions);
  const tasks = taskSnapshot();
  const hasNewRelease = !!latestRelease
    && resolveUpdateReminderCandidate({ currentVersion, latestRelease }) !== null;
  const busy = !!tasks.runningTask || local.state.restartPending || !!local.pending;
  const canUpdate = config.enabled && local.capability.supported && hasNewRelease && !busy;
  const canRollback = config.enabled
    && local.capability.supported
    && installedVersions.length > 1
    && !busy;
  const runtime = local.state;
  const lastError = runtime.lastError || runtime.lastCheckError || local.capability.reason;
  return {
    supported: local.capability.supported,
    mode: local.capability.mode,
    reason: local.capability.reason,
    currentVersion,
    latestRelease,
    installedVersions,
    updateState: runtime.updateState,
    restartPending: runtime.restartPending || !!local.pending,
    canUpdate,
    canRollback,
    lastError: lastError || null,
    config,
    runningTask: tasks.runningTask,
    lastFinishedTask: tasks.lastFinishedTask,
    runtime,
  };
}

export async function buildUpdateCenterStatus(): Promise<UpdateCenterStatusResult> {
  const [config, local] = await Promise.all([
    loadUpdateCenterConfig(),
    inspectLocalState(),
  ]);
  const latestRelease = local.state.statusSnapshot?.githubRelease || null;
  return buildStatusResponse(config, latestRelease, local);
}

export async function buildCachedUpdateCenterStatus(): Promise<UpdateCenterStatusResult> {
  return buildUpdateCenterStatus();
}

export async function refreshUpdateCenterStatusCache(
  checkedAt = formatUtcSqlDateTime(new Date()),
): Promise<{
  status: UpdateCenterStatusResult;
  candidate: UpdateReminderCandidate | null;
  previousRuntime: UpdateCenterRuntimeState;
  runtime: UpdateCenterRuntimeState;
}> {
  const config = await loadUpdateCenterConfig();
  const previousRuntime = await loadUpdateCenterRuntimeState();
  const cachedRelease = previousRuntime.statusSnapshot?.githubRelease || null;
  let latestRelease: UpdateCenterVersionCandidate | null = null;
  let checkError: string | null = null;
  if (config.enabled) {
    try {
      latestRelease = await fetchLatestStableGitHubRelease();
    } catch (error) {
      checkError = summarizeError(error);
      latestRelease = cachedRelease;
    }
  } else {
    latestRelease = cachedRelease;
  }

  const local = await inspectLocalState();
  const currentVersion = local.capability.currentVersion
    || local.state.currentVersion
    || getCurrentRuntimeVersion();
  const candidate = resolveUpdateReminderCandidate({ currentVersion, latestRelease });
  const runtime = await patchUpdateCenterRuntimeState({
    lastCheckedAt: checkedAt,
    lastCheckError: checkError,
    lastResolvedSource: candidate?.source || null,
    lastResolvedDisplayVersion: candidate?.displayVersion || null,
    lastResolvedCandidateKey: candidate?.candidateKey || null,
    statusSnapshot: {
      githubRelease: latestRelease,
      installedVersions: local.installedVersions.map((entry) => entry.version),
      capability: {
        supported: local.capability.supported,
        mode: local.capability.mode,
        reason: local.capability.reason,
      },
    },
  });
  const status = buildStatusResponse(config, latestRelease, {
    ...local,
    state: runtime,
  });
  return { status, candidate, previousRuntime, runtime };
}

export async function getUpdateCenterStatus(): Promise<UpdateCenterStatusResult> {
  const cached = await buildCachedUpdateCenterStatus();
  if (cached.latestRelease || cached.runtime.lastCheckedAt) return cached;
  return (await refreshUpdateCenterStatusCache()).status;
}
