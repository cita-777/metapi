import { startBackgroundTask } from './backgroundTaskService.js';
import {
  rebuildTokenRoutesFromAvailability,
  refreshModelsAndRebuildRoutes as refreshModelsAndRebuildRoutesViaModelService,
} from './modelService.js';

export async function rebuildRoutesOnly() {
  return rebuildTokenRoutesFromAvailability();
}

export async function rebuildRoutesBestEffort() {
  try {
    await rebuildRoutesOnly();
    return true;
  } catch {
    return false;
  }
}

export async function refreshModelsAndRebuildRoutes() {
  return refreshModelsAndRebuildRoutesViaModelService();
}

export function queueRefreshModelsAndRebuildRoutesTask(input: {
  type: string;
  title: string;
  dedupeKey?: string;
  notifyOnFailure?: boolean;
  successMessage: (currentTask: { result?: unknown }) => string;
  failureMessage: (currentTask: { error?: string | null }) => string;
}) {
  return startBackgroundTask(
    {
      type: input.type,
      title: input.title,
      dedupeKey: input.dedupeKey || 'refresh-models-and-rebuild-routes',
      notifyOnFailure: input.notifyOnFailure ?? true,
      successMessage: input.successMessage,
      failureMessage: input.failureMessage,
    },
    async () => refreshModelsAndRebuildRoutes(),
  );
}
