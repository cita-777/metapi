import { config as runtimeConfig } from '../config.js';
import { listBackgroundTasks } from './backgroundTaskService.js';
import {
  fetchLatestDockerHubTag,
  fetchLatestStableGitHubRelease,
  getCurrentRuntimeVersion,
  type UpdateCenterVersionCandidate,
} from './updateCenterVersionService.js';
import {
  loadUpdateCenterConfig,
} from './updateCenterConfigService.js';
import {
  getUpdateCenterHelperStatus,
} from './updateCenterHelperClient.js';
import { loadUpdateCenterRuntimeState } from './updateCenterRuntimeStateService.js';
import { UPDATE_CENTER_DEPLOY_TASK_TYPE } from './updateCenterTaskConstants.js';

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

export async function buildUpdateCenterStatus() {
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
  const helper: Record<string, unknown> = helperLookup.value || {
    ok: false,
    healthy: false,
    error: helperLookup.error,
  };

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
