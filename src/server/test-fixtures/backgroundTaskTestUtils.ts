import { type BackgroundTask } from '../services/backgroundTaskService.js';

type WaitForBackgroundTaskOptions = {
  timeoutMs?: number;
  pollMs?: number;
};

const DEFAULT_TIMEOUT_MS = 5_000;
const DEFAULT_POLL_MS = 10;

function isBackgroundTaskTerminal(task: BackgroundTask | null): boolean {
  return task?.status === 'succeeded' || task?.status === 'failed';
}

export async function waitForBackgroundTaskToReachTerminalState(
  getTask: (taskId: string) => BackgroundTask | null,
  taskId: string,
  options: WaitForBackgroundTaskOptions = {},
): Promise<BackgroundTask | null> {
  const timeoutMs = Math.max(1, Math.trunc(options.timeoutMs ?? DEFAULT_TIMEOUT_MS));
  const pollMs = Math.max(0, Math.trunc(options.pollMs ?? DEFAULT_POLL_MS));
  const deadlineMs = Date.now() + timeoutMs;

  let currentTask = getTask(taskId);
  while (!isBackgroundTaskTerminal(currentTask) && Date.now() < deadlineMs) {
    await new Promise((resolve) => setTimeout(resolve, pollMs));
    currentTask = getTask(taskId);
  }

  return currentTask;
}
