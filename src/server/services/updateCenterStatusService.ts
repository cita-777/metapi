import { config as runtimeConfig } from '../config.js';
import { formatUtcSqlDateTime } from './localTimeService.js';
import { listBackgroundTasks } from './backgroundTaskService.js';
import {
  fetchLatestDockerHubTag,
  fetchLatestStableGitHubRelease,
  getCurrentRuntimeVersion,
  type UpdateCenterVersionCandidate,
} from './updateCenterVersionService.js';
import {
  type UpdateCenterConfig,
  loadUpdateCenterConfig,
} from './updateCenterConfigService.js';
import {
  getUpdateCenterHelperStatus,
  type UpdateCenterHelperStatus,
} from './updateCenterHelperClient.js';
import {
  loadUpdateCenterRuntimeState,
  saveUpdateCenterRuntimeState,
  type UpdateCenterRuntimeState,
  type UpdateCenterStatusSnapshot,
} from './updateCenterRuntimeStateService.js';
import { UPDATE_CENTER_DEPLOY_TASK_TYPE } from './updateCenterTaskConstants.js';
import { resolveUpdateReminderCandidate, type UpdateReminderCandidate } from './updateCenterReminderService.js';

function getUpdateCenterHelperToken(): string {
  return String(
    runtimeConfig.deployHelperToken
    || process.env.DEPLOY_HELPER_TOKEN
    || process.env.UPDATE_CENTER_HELPER_TOKEN
    || '',
  ).trim();
}

function summarizeHelperError(error: unknown) {
  if (error instanceof Error && error.message) return error.message;
  return String(error || 'unknown helper error');
}

async function settleOptional<T>(enabled: boolean, loader: () => Promise<T>): Promise<{
  value: T | null;
  error: string | null;
}> {
  if (!enabled) {
    return {
      value: null,
      error: null,
    };
  }

  try {
    return {
      value: await loader(),
      error: null,
    };
  } catch (error) {
    return {
      value: null,
      error: summarizeHelperError(error),
    };
  }
}

function getDeployTasks() {
  return listBackgroundTasks(50).filter((task) => task.type === UPDATE_CENTER_DEPLOY_TASK_TYPE);
}

export type UpdateCenterStatusResult = {
  currentVersion: string;
  config: UpdateCenterConfig;
  githubRelease: UpdateCenterVersionCandidate | null;
  dockerHubTag: UpdateCenterVersionCandidate | null;
  helper: UpdateCenterHelperStatus;
  runningTask: ReturnType<typeof getDeployTasks>[number] | null;
  lastFinishedTask: ReturnType<typeof getDeployTasks>[number] | null;
  runtime: UpdateCenterRuntimeState;
};

function buildUnavailableHelperStatus(error: string | null = null): UpdateCenterHelperStatus {
  return {
    ok: false,
    releaseName: null,
    namespace: null,
    revision: null,
    imageRepository: null,
    imageTag: null,
    imageDigest: null,
    healthy: false,
    error: error || undefined,
    history: [],
  };
}

function buildStatusSnapshot(status: Pick<UpdateCenterStatusResult, 'githubRelease' | 'dockerHubTag' | 'helper'>): UpdateCenterStatusSnapshot {
  return {
    githubRelease: status.githubRelease || null,
    dockerHubTag: status.dockerHubTag || null,
    helper: status.helper || null,
  };
}

function buildNextRuntimeState(
  status: Pick<UpdateCenterStatusResult, 'currentVersion' | 'githubRelease' | 'dockerHubTag' | 'helper'>,
  previousRuntime: UpdateCenterRuntimeState,
  checkedAt: string,
): { candidate: UpdateReminderCandidate | null; nextRuntime: UpdateCenterRuntimeState } {
  const candidate = resolveUpdateReminderCandidate({
    currentVersion: status.currentVersion,
    helper: status.helper,
    githubRelease: status.githubRelease,
    dockerHubTag: status.dockerHubTag,
  });

  return {
    candidate,
    nextRuntime: {
      ...previousRuntime,
      lastCheckedAt: checkedAt,
      lastCheckError: null,
      lastResolvedSource: candidate?.source || null,
      lastResolvedDisplayVersion: candidate?.displayVersion || null,
      lastResolvedCandidateKey: candidate?.candidateKey || null,
      statusSnapshot: buildStatusSnapshot(status),
    },
  };
}

function buildResponseFromState(config: UpdateCenterConfig, runtime: UpdateCenterRuntimeState): UpdateCenterStatusResult {
  const snapshot = runtime.statusSnapshot;
  const tasks = getDeployTasks();
  const runningTask = tasks.find((task) => task.status === 'pending' || task.status === 'running') || null;
  const lastFinishedTask = tasks.find((task) => task.status === 'succeeded' || task.status === 'failed') || null;

  return {
    currentVersion: getCurrentRuntimeVersion(),
    config,
    githubRelease: snapshot?.githubRelease || null,
    dockerHubTag: snapshot?.dockerHubTag || null,
    helper: snapshot?.helper || buildUnavailableHelperStatus(runtime.lastCheckError),
    runningTask,
    lastFinishedTask,
    runtime,
  };
}

export async function buildUpdateCenterStatus(): Promise<UpdateCenterStatusResult> {
  const config = await loadUpdateCenterConfig();
  const helperToken = getUpdateCenterHelperToken();

  const [githubLookup, dockerLookup, helperLookup, runtime] = await Promise.all([
    settleOptional(config.githubReleasesEnabled, async () => await fetchLatestStableGitHubRelease()),
    settleOptional(config.dockerHubTagsEnabled, async () => await fetchLatestDockerHubTag()),
    settleOptional(!!config.helperBaseUrl, async () => {
      if (!helperToken) {
        throw new Error('DEPLOY_HELPER_TOKEN is required');
      }
      return await getUpdateCenterHelperStatus(config, helperToken);
    }),
    loadUpdateCenterRuntimeState(),
  ]);

  const githubRelease = githubLookup.value as UpdateCenterVersionCandidate | null;
  const dockerHubTag = dockerLookup.value as UpdateCenterVersionCandidate | null;
  const helper = (helperLookup.value as UpdateCenterHelperStatus | null) || buildUnavailableHelperStatus(helperLookup.error);

  const tasks = getDeployTasks();
  const runningTask = tasks.find((task) => task.status === 'pending' || task.status === 'running') || null;
  const lastFinishedTask = tasks.find((task) => task.status === 'succeeded' || task.status === 'failed') || null;

  return {
    currentVersion: getCurrentRuntimeVersion(),
    config,
    githubRelease,
    dockerHubTag,
    helper,
    runningTask,
    lastFinishedTask,
    runtime,
  };
}

export async function buildCachedUpdateCenterStatus(): Promise<UpdateCenterStatusResult> {
  const [config, runtime] = await Promise.all([
    loadUpdateCenterConfig(),
    loadUpdateCenterRuntimeState(),
  ]);
  return buildResponseFromState(config, runtime);
}

export async function refreshUpdateCenterStatusCache(checkedAt = formatUtcSqlDateTime(new Date())): Promise<{
  status: UpdateCenterStatusResult;
  candidate: UpdateReminderCandidate | null;
  previousRuntime: UpdateCenterRuntimeState;
  runtime: UpdateCenterRuntimeState;
}> {
  const status = await buildUpdateCenterStatus();
  const previousRuntime = status.runtime || await loadUpdateCenterRuntimeState();
  const { candidate, nextRuntime } = buildNextRuntimeState(status, previousRuntime, checkedAt);
  const runtime = await saveUpdateCenterRuntimeState(nextRuntime);
  return {
    status: {
      ...status,
      runtime,
    },
    candidate,
    previousRuntime,
    runtime,
  };
}

export async function getUpdateCenterStatus(): Promise<UpdateCenterStatusResult> {
  const cached = await buildCachedUpdateCenterStatus();
  if (cached.runtime.statusSnapshot) {
    return cached;
  }
  return (await refreshUpdateCenterStatusCache()).status;
}
