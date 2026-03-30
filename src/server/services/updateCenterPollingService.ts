import { db, schema } from '../db/index.js';
import { formatUtcSqlDateTime } from './localTimeService.js';
import { sendNotification } from './notifyService.js';
import { buildUpdateCenterStatus } from './updateCenterStatusService.js';
import { loadUpdateCenterRuntimeState, saveUpdateCenterRuntimeState } from './updateCenterRuntimeStateService.js';
import { resolveUpdateReminderCandidate } from './updateCenterReminderService.js';

const DEFAULT_UPDATE_CENTER_INTERVAL_MS = 15 * 60 * 1000;

let pollingTimer: ReturnType<typeof setInterval> | null = null;
let syncRunning = false;

function summarizeError(error: unknown) {
  if (error instanceof Error && error.message) return error.message;
  return String(error || 'unknown error');
}

function buildReminderEvent(candidate: ReturnType<typeof resolveUpdateReminderCandidate>) {
  if (!candidate) return null;
  const title = candidate.kind === 'new-digest'
    ? '更新中心发现新 digest'
    : '更新中心发现新版本';
  const message = candidate.kind === 'new-digest'
    ? `检测到 ${candidate.displayVersion} 指向了新的镜像 digest，可前往更新中心查看并手动部署。`
    : `检测到 ${candidate.displayVersion} 已可部署，可前往更新中心查看并手动部署。`;
  return {
    title,
    message,
  };
}

async function runSyncOnce() {
  if (syncRunning) return;
  syncRunning = true;
  const checkedAt = formatUtcSqlDateTime(new Date());

  try {
    const status = await buildUpdateCenterStatus();
    const previousRuntime = status.runtime || await loadUpdateCenterRuntimeState();
    const candidate = resolveUpdateReminderCandidate({
      currentVersion: status.currentVersion,
      helper: status.helper as { imageTag?: string | null; imageDigest?: string | null } | null,
      githubRelease: status.githubRelease,
      dockerHubTag: status.dockerHubTag,
    });

    const nextRuntime = {
      ...previousRuntime,
      lastCheckedAt: checkedAt,
      lastCheckError: null,
      lastResolvedSource: candidate?.source || null,
      lastResolvedDisplayVersion: candidate?.displayVersion || null,
      lastResolvedCandidateKey: candidate?.candidateKey || null,
    };

    if (candidate && candidate.candidateKey !== previousRuntime.lastNotifiedCandidateKey) {
      const reminderEvent = buildReminderEvent(candidate);
      if (reminderEvent) {
        await db.insert(schema.events).values({
          type: 'status',
          title: reminderEvent.title,
          message: reminderEvent.message,
          level: 'info',
          relatedType: 'update_center',
          createdAt: checkedAt,
        }).run();
        nextRuntime.lastNotifiedCandidateKey = candidate.candidateKey;
        nextRuntime.lastNotifiedAt = checkedAt;
        await saveUpdateCenterRuntimeState(nextRuntime);
        await sendNotification(reminderEvent.title, reminderEvent.message, 'info', {
          bypassThrottle: true,
        });
      }
    }

    await saveUpdateCenterRuntimeState(nextRuntime);
  } catch (error) {
    const previousRuntime = await loadUpdateCenterRuntimeState();
    await saveUpdateCenterRuntimeState({
      ...previousRuntime,
      lastCheckedAt: checkedAt,
      lastCheckError: summarizeError(error),
    });
  } finally {
    syncRunning = false;
  }
}

export function startUpdateCenterPolling(intervalMs = DEFAULT_UPDATE_CENTER_INTERVAL_MS) {
  stopUpdateCenterPolling();
  pollingTimer = setInterval(() => {
    void runSyncOnce();
  }, Math.max(10_000, intervalMs));
  pollingTimer.unref?.();
  void runSyncOnce();
  return { intervalMs: Math.max(10_000, intervalMs) };
}

export function stopUpdateCenterPolling() {
  if (pollingTimer) {
    clearInterval(pollingTimer);
    pollingTimer = null;
  }
}
