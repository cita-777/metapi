import { db, schema } from '../db/index.js';
import { formatUtcSqlDateTime } from './localTimeService.js';
import { sendNotification } from './notifyService.js';
import { loadUpdateCenterConfig } from './updateCenterConfigService.js';
import { refreshUpdateCenterStatusCache } from './updateCenterStatusService.js';
import { patchUpdateCenterRuntimeState } from './updateCenterRuntimeStateService.js';
import type { UpdateReminderCandidate } from './updateCenterReminderService.js';

const DEFAULT_UPDATE_CENTER_INTERVAL_MS = 15 * 60 * 1000;

let pollingTimer: ReturnType<typeof setInterval> | null = null;
let syncRunning = false;

function summarizeError(error: unknown): string {
  if (error instanceof Error && error.message) return error.message;
  return String(error || 'unknown update error');
}

function buildReminderEvent(candidate: UpdateReminderCandidate | null) {
  if (!candidate) return null;
  return {
    title: '发现 Metapi 新版本',
    message: `官方稳定版 ${candidate.displayVersion} 已发布，可前往更新中心一键升级。`,
  };
}

async function runSyncOnce(): Promise<void> {
  if (syncRunning) return;
  syncRunning = true;
  const checkedAt = formatUtcSqlDateTime(new Date());
  try {
    const config = await loadUpdateCenterConfig();
    if (!config.enabled || !config.autoCheck) return;
    const { candidate, previousRuntime } = await refreshUpdateCenterStatusCache(checkedAt);
    if (candidate && candidate.candidateKey !== previousRuntime.lastNotifiedCandidateKey) {
      const event = buildReminderEvent(candidate);
      if (event) {
        await db.insert(schema.events).values({
          type: 'status',
          title: event.title,
          message: event.message,
          level: 'info',
          relatedType: 'update_center',
          createdAt: checkedAt,
        }).run();
        await patchUpdateCenterRuntimeState({
          lastNotifiedCandidateKey: candidate.candidateKey,
          lastNotifiedAt: checkedAt,
        });
        await sendNotification(event.title, event.message, 'info', { bypassThrottle: true });
      }
    }
  } catch (error) {
    // Polling is fire-and-forget from the scheduler.  Persisting diagnostics
    // is best-effort so a read-only/corrupt runtime cannot create an unhandled
    // rejection on the timer callback itself.
    try {
      await patchUpdateCenterRuntimeState({
        lastCheckedAt: checkedAt,
        lastCheckError: summarizeError(error),
      });
    } catch {
      // The original check failure remains the observable outcome.
    }
  } finally {
    syncRunning = false;
  }
}

export function startUpdateCenterPolling(intervalMs = DEFAULT_UPDATE_CENTER_INTERVAL_MS) {
  stopUpdateCenterPolling();
  const safeIntervalMs = Math.max(10_000, Math.trunc(intervalMs));
  pollingTimer = setInterval(() => {
    void runSyncOnce();
  }, safeIntervalMs);
  pollingTimer.unref?.();
  void runSyncOnce();
  return { intervalMs: safeIntervalMs };
}

export function stopUpdateCenterPolling() {
  if (!pollingTimer) return;
  clearInterval(pollingTimer);
  pollingTimer = null;
}

export const __runUpdateCenterSyncForTests = runSyncOnce;
