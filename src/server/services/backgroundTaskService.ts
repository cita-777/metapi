import { randomUUID } from 'node:crypto';
import { db, schema } from '../db/index.js';
import { sendNotification } from './notifyService.js';

export type BackgroundTaskStatus = 'pending' | 'running' | 'succeeded' | 'failed';

export type BackgroundTaskLogEntry = {
  seq: number;
  message: string;
  createdAt: string;
};

export type BackgroundTask = {
  id: string;
  type: string;
  title: string;
  status: BackgroundTaskStatus;
  message: string;
  error: string | null;
  result: unknown;
  dedupeKey: string | null;
  createdAt: string;
  updatedAt: string;
  startedAt: string | null;
  finishedAt: string | null;
  expiresAtMs: number;
  logs: BackgroundTaskLogEntry[];
};

type TaskMessageTemplate = string | ((task: BackgroundTask) => string);

type BackgroundTaskStartOptions = {
  type: string;
  title: string;
  dedupeKey?: string;
  keepMs?: number;
  notifyOnSuccess?: boolean;
  notifyOnFailure?: boolean;
  successTitle?: TaskMessageTemplate;
  failureTitle?: TaskMessageTemplate;
  successMessage?: TaskMessageTemplate;
  failureMessage?: TaskMessageTemplate;
};

const TASK_TTL_MS = 6 * 60 * 60 * 1000;
const TASK_CLEANUP_INTERVAL_MS = 60 * 1000;
const TASK_LOG_LIMIT = 200;

const tasks = new Map<string, BackgroundTask>();
const dedupeTaskIds = new Map<string, string>();
const taskLogSeq = new Map<string, number>();
const taskLogSubscribers = new Map<string, Set<(entry: BackgroundTaskLogEntry) => void>>();
let cleanupTimer: ReturnType<typeof setInterval> | null = null;

function nowIso() {
  return new Date().toISOString();
}

function summarizeError(error: unknown): string {
  if (error instanceof Error && error.message) return error.message;
  if (typeof error === 'string' && error.trim()) return error.trim();
  if (error && typeof error === 'object') {
    try {
      return JSON.stringify(error);
    } catch {
      return 'unknown error';
    }
  }
  return 'unknown error';
}

function resolveTaskMessage(template: TaskMessageTemplate | undefined, task: BackgroundTask, fallback: string): string {
  if (typeof template === 'function') {
    try {
      const value = template(task);
      if (typeof value === 'string' && value.trim()) return value.trim();
    } catch {}
    return fallback;
  }
  if (typeof template === 'string' && template.trim()) return template.trim();
  return fallback;
}

function setTaskStatus(task: BackgroundTask, patch: Partial<BackgroundTask>) {
  const currentTask = tasks.get(task.id) || task;
  const next: BackgroundTask = {
    ...currentTask,
    ...patch,
    updatedAt: nowIso(),
  };
  tasks.set(task.id, next);
  return next;
}

function cleanupTaskInternals(taskId: string) {
  taskLogSeq.delete(taskId);
  taskLogSubscribers.delete(taskId);
}

export function appendBackgroundTaskLog(taskId: string, message: string): BackgroundTaskLogEntry | null {
  const task = tasks.get(taskId);
  const normalizedMessage = String(message || '').trim();
  if (!task || !normalizedMessage) return null;

  const nextSeq = (taskLogSeq.get(taskId) || 0) + 1;
  taskLogSeq.set(taskId, nextSeq);

  const entry: BackgroundTaskLogEntry = {
    seq: nextSeq,
    message: normalizedMessage,
    createdAt: nowIso(),
  };

  const nextLogs = [...task.logs, entry];
  const trimmedLogs = nextLogs.length > TASK_LOG_LIMIT
    ? nextLogs.slice(nextLogs.length - TASK_LOG_LIMIT)
    : nextLogs;

  tasks.set(taskId, {
    ...task,
    logs: trimmedLogs,
    updatedAt: nowIso(),
  });

  const subscribers = taskLogSubscribers.get(taskId);
  if (subscribers) {
    for (const subscriber of subscribers) {
      subscriber(entry);
    }
  }

  return entry;
}

export function subscribeToBackgroundTaskLogs(
  taskId: string,
  listener: (entry: BackgroundTaskLogEntry) => void,
): () => void {
  let subscribers = taskLogSubscribers.get(taskId);
  if (!subscribers) {
    subscribers = new Set();
    taskLogSubscribers.set(taskId, subscribers);
  }
  subscribers.add(listener);

  return () => {
    const current = taskLogSubscribers.get(taskId);
    if (!current) return;
    current.delete(listener);
    if (current.size <= 0) {
      taskLogSubscribers.delete(taskId);
    }
  };
}

async function appendTaskEvent(level: 'info' | 'warning' | 'error', title: string, message: string, taskId: string) {
  try {
    await db.insert(schema.events).values({
      type: 'status',
      title,
      message,
      level,
      relatedType: 'task',
      createdAt: nowIso(),
    }).run();
  } catch {}
  void taskId;
}

async function runTask(taskId: string, options: BackgroundTaskStartOptions, runner: () => Promise<unknown>) {
  const initialTask = tasks.get(taskId);
  if (!initialTask) return;

  let task = setTaskStatus(initialTask, {
    status: 'running',
    startedAt: nowIso(),
    message: `${initialTask.title} 正在执行`,
  });

  try {
    const result = await runner();
    task = setTaskStatus(task, {
      status: 'succeeded',
      finishedAt: nowIso(),
      result,
      error: null,
    });

    const eventTitle = resolveTaskMessage(options.successTitle, task, `${task.title} 已完成`);
    const eventMessage = resolveTaskMessage(options.successMessage, task, `${task.title} 已完成`);
    task = setTaskStatus(task, { message: eventMessage });
    appendTaskEvent('info', eventTitle, eventMessage, task.id);

    if (options.notifyOnSuccess) {
      await sendNotification(eventTitle, eventMessage, 'info');
    }
  } catch (error) {
    const errorText = summarizeError(error);
    task = setTaskStatus(task, {
      status: 'failed',
      finishedAt: nowIso(),
      error: errorText,
      message: `${task.title} 失败：${errorText}`,
    });

    const eventTitle = resolveTaskMessage(options.failureTitle, task, `${task.title} 失败`);
    const eventMessage = resolveTaskMessage(options.failureMessage, task, task.message);
    task = setTaskStatus(task, { message: eventMessage });
    appendTaskEvent('error', eventTitle, eventMessage, task.id);

    if (options.notifyOnFailure ?? true) {
      await sendNotification(eventTitle, eventMessage, 'error');
    }
  } finally {
    if (task.dedupeKey && dedupeTaskIds.get(task.dedupeKey) === task.id) {
      dedupeTaskIds.delete(task.dedupeKey);
    }
  }
}

function cleanupExpiredTasks() {
  const now = Date.now();
  for (const [taskId, task] of tasks.entries()) {
    if (task.expiresAtMs <= now) {
      tasks.delete(taskId);
      if (task.dedupeKey && dedupeTaskIds.get(task.dedupeKey) === taskId) {
        dedupeTaskIds.delete(task.dedupeKey);
      }
      cleanupTaskInternals(taskId);
    }
  }
}

function ensureCleanupTimer() {
  if (cleanupTimer) return;
  cleanupTimer = setInterval(cleanupExpiredTasks, TASK_CLEANUP_INTERVAL_MS);
  cleanupTimer.unref?.();
}

export function startBackgroundTask(
  options: BackgroundTaskStartOptions,
  runner: () => Promise<unknown>,
): { task: BackgroundTask; reused: boolean } {
  ensureCleanupTimer();
  const dedupeKey = options.dedupeKey?.trim() || '';
  if (dedupeKey) {
    const existingTaskId = dedupeTaskIds.get(dedupeKey);
    if (existingTaskId) {
      const existing = tasks.get(existingTaskId);
      if (existing && (existing.status === 'pending' || existing.status === 'running')) {
        return { task: existing, reused: true };
      }
      dedupeTaskIds.delete(dedupeKey);
    }
  }

  const createdAt = nowIso();
  const task: BackgroundTask = {
    id: randomUUID(),
    type: options.type,
    title: options.title,
    status: 'pending',
    message: `${options.title} 已开始执行`,
    error: null,
    result: null,
    dedupeKey: dedupeKey || null,
    createdAt,
    updatedAt: createdAt,
    startedAt: null,
    finishedAt: null,
    expiresAtMs: Date.now() + Math.max(60_000, options.keepMs ?? TASK_TTL_MS),
    logs: [],
  };

  tasks.set(task.id, task);
  taskLogSeq.set(task.id, 0);
  if (dedupeKey) dedupeTaskIds.set(dedupeKey, task.id);

  appendTaskEvent('info', `${task.title}已开始`, `${task.title} 已开始执行`, task.id);
  void runTask(task.id, options, runner);
  return { task, reused: false };
}

export function getBackgroundTask(taskId: string): BackgroundTask | null {
  return tasks.get(taskId) || null;
}

export function listBackgroundTasks(limit = 50): BackgroundTask[] {
  const safeLimit = Number.isFinite(limit) ? Math.max(1, Math.min(200, Math.trunc(limit))) : 50;
  return Array.from(tasks.values())
    .sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt))
    .slice(0, safeLimit);
}

export function getRunningTaskByDedupeKey(key: string): BackgroundTask | null {
  const taskId = dedupeTaskIds.get(key.trim());
  if (!taskId) return null;
  const task = tasks.get(taskId);
  if (!task) return null;
  if (task.status !== 'pending' && task.status !== 'running') return null;
  return task;
}

export async function waitForBackgroundTaskCompletion(taskId: string, pollIntervalMs = 25): Promise<BackgroundTask | null> {
  const safePollIntervalMs = Math.max(5, Math.trunc(pollIntervalMs || 0));
  while (true) {
    const task = getBackgroundTask(taskId);
    if (!task) return null;
    if (task.status !== 'pending' && task.status !== 'running') {
      return task;
    }
    await new Promise<void>((resolve) => {
      const timer = setTimeout(resolve, safePollIntervalMs);
      timer.unref?.();
    });
  }
}

export function summarizeCheckinResults(results: Array<{ result?: any }>): { total: number; success: number; skipped: number; failed: number } {
  const summary = { total: results.length, success: 0, skipped: 0, failed: 0 };
  for (const item of results) {
    const status = item?.result?.status;
    if (status === 'skipped' || item?.result?.skipped) {
      summary.skipped += 1;
      continue;
    }
    if (item?.result?.success) {
      summary.success += 1;
      continue;
    }
    summary.failed += 1;
  }
  return summary;
}

export function __resetBackgroundTasksForTests() {
  tasks.clear();
  dedupeTaskIds.clear();
  taskLogSeq.clear();
  taskLogSubscribers.clear();
  if (cleanupTimer) {
    clearInterval(cleanupTimer);
    cleanupTimer = null;
  }
}
