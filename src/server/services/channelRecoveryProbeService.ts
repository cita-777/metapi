import { and, eq, gt, inArray, isNotNull } from 'drizzle-orm';
import { db, schema } from '../db/index.js';
import { isUsableAccountToken } from './accountTokenService.js';
import { getOauthInfoFromAccount } from './oauth/oauthAccount.js';
import { proxyChannelCoordinator } from './proxyChannelCoordinator.js';
import { probeRuntimeModel } from './runtimeModelProbe.js';
import { tokenRouter } from './tokenRouter.js';
import { isExactTokenRouteModelPattern } from '../../shared/tokenRoutePatterns.js';

type RecoveryProbeSource = 'cooldown' | 'active';

type RecoveryProbeCandidate = {
  source: RecoveryProbeSource;
  channelId: number;
  modelName: string;
  tokenValue: string;
  account: typeof schema.accounts.$inferSelect;
  site: typeof schema.sites.$inferSelect;
};

const CHANNEL_RECOVERY_SWEEP_INTERVAL_MS = 30_000;
const CHANNEL_RECOVERY_PROBE_TIMEOUT_MS = 12_000;
// Keep recovery probes conservative so they do not look like bulk health checks to upstream providers.
const CHANNEL_RECOVERY_PROBE_CONCURRENCY = 1;
const CHANNEL_RECOVERY_MAX_BATCH = 4;
const CHANNEL_RECOVERY_COOLDOWN_RECHECK_MS = 30_000;
const CHANNEL_RECOVERY_ACTIVE_RECHECK_MS = 5 * 60_000;

let recoveryProbeSchedulerTimer: ReturnType<typeof setInterval> | null = null;
let recoveryProbeSweepInFlight: Promise<void> | null = null;
const recoveryProbeInFlightKeys = new Set<string>();
const recoveryProbeLastStartedAtByKey = new Map<string, number>();

function shouldUnrefTimer(timer: ReturnType<typeof setTimeout> | ReturnType<typeof setInterval>) {
  if (typeof (timer as { unref?: () => void }).unref === 'function') {
    (timer as { unref: () => void }).unref();
  }
}

function buildRecoveryProbeKey(channelId: number, modelName: string): string {
  return `${channelId}:${String(modelName || '').trim().toLowerCase()}`;
}

function resolveRecoveryProbeWindowMs(source: RecoveryProbeSource): number {
  return source === 'cooldown'
    ? CHANNEL_RECOVERY_COOLDOWN_RECHECK_MS
    : CHANNEL_RECOVERY_ACTIVE_RECHECK_MS;
}

function resolveProbeModelName(row: {
  route_channels: typeof schema.routeChannels.$inferSelect;
  token_routes: typeof schema.tokenRoutes.$inferSelect;
}): string {
  const sourceModel = String(row.route_channels.sourceModel || '').trim();
  if (sourceModel) return sourceModel;
  const routeModelPattern = String(row.token_routes.modelPattern || '').trim();
  return isExactTokenRouteModelPattern(routeModelPattern) ? routeModelPattern : '';
}

function resolveProbeTokenValue(row: {
  route_channels: typeof schema.routeChannels.$inferSelect;
  accounts: typeof schema.accounts.$inferSelect;
  account_tokens: typeof schema.accountTokens.$inferSelect | null;
}): string | null {
  if (typeof row.route_channels.tokenId === 'number' && row.route_channels.tokenId > 0) {
    if (!row.account_tokens || !isUsableAccountToken(row.account_tokens)) return null;
    const tokenValue = String(row.account_tokens.token || '').trim();
    return tokenValue || null;
  }

  if (getOauthInfoFromAccount(row.accounts)) {
    const accessToken = String(row.accounts.accessToken || '').trim();
    return accessToken || null;
  }

  const fallbackApiToken = String(row.accounts.apiToken || '').trim();
  return fallbackApiToken || null;
}

function isProviderDirectedCooldown(row: {
  route_channels: typeof schema.routeChannels.$inferSelect;
}): boolean {
  return !!row.route_channels.cooldownUntil
    && (row.route_channels.failCount ?? 0) <= 0
    && (row.route_channels.consecutiveFailCount ?? 0) <= 0
    && (row.route_channels.cooldownLevel ?? 0) <= 0;
}

async function mapWithConcurrency<T>(
  items: T[],
  concurrency: number,
  worker: (item: T, index: number) => Promise<void>,
): Promise<void> {
  const safeConcurrency = Math.max(1, Math.min(items.length || 1, Math.trunc(concurrency || 1)));
  let nextIndex = 0;
  const runWorker = async () => {
    while (true) {
      const currentIndex = nextIndex;
      nextIndex += 1;
      if (currentIndex >= items.length) return;
      await worker(items[currentIndex] as T, currentIndex);
    }
  };

  await Promise.all(Array.from({ length: safeConcurrency }, () => runWorker()));
}

async function loadCoolingProbeCandidates(nowIso: string): Promise<RecoveryProbeCandidate[]> {
  const rows = await db.select()
    .from(schema.routeChannels)
    .innerJoin(schema.accounts, eq(schema.routeChannels.accountId, schema.accounts.id))
    .innerJoin(schema.sites, eq(schema.accounts.siteId, schema.sites.id))
    .innerJoin(schema.tokenRoutes, eq(schema.routeChannels.routeId, schema.tokenRoutes.id))
    .leftJoin(schema.accountTokens, eq(schema.routeChannels.tokenId, schema.accountTokens.id))
    .where(and(
      eq(schema.routeChannels.enabled, true),
      eq(schema.accounts.status, 'active'),
      eq(schema.sites.status, 'active'),
      isNotNull(schema.routeChannels.cooldownUntil),
      gt(schema.routeChannels.cooldownUntil, nowIso),
    ))
    .all();

  return rows.flatMap((row) => {
    if (isProviderDirectedCooldown(row)) return [];
    const modelName = resolveProbeModelName(row);
    const tokenValue = resolveProbeTokenValue(row);
    if (!modelName || !tokenValue) return [];
    return [{
      source: 'cooldown' as const,
      channelId: row.route_channels.id,
      modelName,
      tokenValue,
      account: row.accounts,
      site: row.sites,
    }];
  });
}

async function loadActiveProbeCandidates(activeChannelIds: number[]): Promise<RecoveryProbeCandidate[]> {
  if (activeChannelIds.length <= 0) return [];

  const rows = await db.select()
    .from(schema.routeChannels)
    .innerJoin(schema.accounts, eq(schema.routeChannels.accountId, schema.accounts.id))
    .innerJoin(schema.sites, eq(schema.accounts.siteId, schema.sites.id))
    .innerJoin(schema.tokenRoutes, eq(schema.routeChannels.routeId, schema.tokenRoutes.id))
    .leftJoin(schema.accountTokens, eq(schema.routeChannels.tokenId, schema.accountTokens.id))
    .where(and(
      eq(schema.routeChannels.enabled, true),
      eq(schema.accounts.status, 'active'),
      eq(schema.sites.status, 'active'),
      inArray(schema.routeChannels.id, activeChannelIds),
    ))
    .all();

  return rows.flatMap((row) => {
    const modelName = resolveProbeModelName(row);
    const tokenValue = resolveProbeTokenValue(row);
    if (!modelName || !tokenValue) return [];
    return [{
      source: 'active' as const,
      channelId: row.route_channels.id,
      modelName,
      tokenValue,
      account: row.accounts,
      site: row.sites,
    }];
  });
}

function mergeRecoveryProbeCandidates(candidates: RecoveryProbeCandidate[]): RecoveryProbeCandidate[] {
  const merged = new Map<number, RecoveryProbeCandidate>();
  for (const candidate of candidates) {
    const existing = merged.get(candidate.channelId);
    if (!existing || (existing.source === 'active' && candidate.source === 'cooldown')) {
      merged.set(candidate.channelId, candidate);
    }
  }
  return Array.from(merged.values());
}

function shouldProbeCandidate(candidate: RecoveryProbeCandidate, nowMs: number): boolean {
  const key = buildRecoveryProbeKey(candidate.channelId, candidate.modelName);
  if (recoveryProbeInFlightKeys.has(key)) return false;
  const lastStartedAt = recoveryProbeLastStartedAtByKey.get(key) ?? 0;
  return (nowMs - lastStartedAt) >= resolveRecoveryProbeWindowMs(candidate.source);
}

function compareRecoveryProbeCandidatePriority(left: RecoveryProbeCandidate, right: RecoveryProbeCandidate): number {
  const leftKey = buildRecoveryProbeKey(left.channelId, left.modelName);
  const rightKey = buildRecoveryProbeKey(right.channelId, right.modelName);
  const leftLastStartedAt = recoveryProbeLastStartedAtByKey.get(leftKey);
  const rightLastStartedAt = recoveryProbeLastStartedAtByKey.get(rightKey);

  if (leftLastStartedAt == null && rightLastStartedAt == null) {
    return left.channelId - right.channelId;
  }
  if (leftLastStartedAt == null) return -1;
  if (rightLastStartedAt == null) return 1;
  if (leftLastStartedAt !== rightLastStartedAt) {
    return leftLastStartedAt - rightLastStartedAt;
  }
  return left.channelId - right.channelId;
}

async function runRecoveryProbeCandidate(candidate: RecoveryProbeCandidate, nowMs: number): Promise<void> {
  const key = buildRecoveryProbeKey(candidate.channelId, candidate.modelName);
  recoveryProbeInFlightKeys.add(key);
  recoveryProbeLastStartedAtByKey.set(key, nowMs);
  try {
    const result = await probeRuntimeModel({
      site: candidate.site,
      account: candidate.account,
      modelName: candidate.modelName,
      tokenValue: candidate.tokenValue,
      timeoutMs: CHANNEL_RECOVERY_PROBE_TIMEOUT_MS,
    });
    if (result.status === 'supported') {
      await tokenRouter.recordProbeSuccess(
        candidate.channelId,
        result.latencyMs ?? 0,
        candidate.modelName,
      );
    }
  } catch (error) {
    console.warn(`[channel-recovery-probe] channel ${candidate.channelId} probe failed`, error);
  } finally {
    recoveryProbeInFlightKeys.delete(key);
  }
}

export async function runChannelRecoveryProbeSweep(nowMs = Date.now()): Promise<void> {
  if (recoveryProbeSweepInFlight) {
    await recoveryProbeSweepInFlight;
    return;
  }

  recoveryProbeSweepInFlight = (async () => {
    const nowIso = new Date(nowMs).toISOString();
    const activeChannelIds = proxyChannelCoordinator.getActiveChannelIds();
    const [coolingCandidates, activeCandidates] = await Promise.all([
      loadCoolingProbeCandidates(nowIso),
      loadActiveProbeCandidates(activeChannelIds),
    ]);

    const merged = mergeRecoveryProbeCandidates([
      ...coolingCandidates,
      ...activeCandidates,
    ]);
    const dueCandidates = merged
      .filter((candidate) => shouldProbeCandidate(candidate, nowMs))
      .sort(compareRecoveryProbeCandidatePriority)
      .slice(0, CHANNEL_RECOVERY_MAX_BATCH);
    if (dueCandidates.length <= 0) return;

    await mapWithConcurrency(
      dueCandidates,
      CHANNEL_RECOVERY_PROBE_CONCURRENCY,
      async (candidate) => runRecoveryProbeCandidate(candidate, nowMs),
    );
  })().finally(() => {
    recoveryProbeSweepInFlight = null;
  });

  await recoveryProbeSweepInFlight;
}

export function startChannelRecoveryProbeScheduler(intervalMs = CHANNEL_RECOVERY_SWEEP_INTERVAL_MS) {
  stopChannelRecoveryProbeScheduler();
  const safeIntervalMs = Math.max(10_000, Math.trunc(intervalMs || 0));
  recoveryProbeSchedulerTimer = setInterval(() => {
    void runChannelRecoveryProbeSweep().catch((error) => {
      console.warn('[channel-recovery-probe] background sweep failed', error);
    });
  }, safeIntervalMs);
  shouldUnrefTimer(recoveryProbeSchedulerTimer);
  void runChannelRecoveryProbeSweep().catch((error) => {
    console.warn('[channel-recovery-probe] initial sweep failed', error);
  });
  return {
    enabled: true,
    intervalMs: safeIntervalMs,
  };
}

export function stopChannelRecoveryProbeScheduler() {
  if (recoveryProbeSchedulerTimer) {
    clearInterval(recoveryProbeSchedulerTimer);
    recoveryProbeSchedulerTimer = null;
  }
}

export function resetChannelRecoveryProbeState() {
  stopChannelRecoveryProbeScheduler();
  recoveryProbeSweepInFlight = null;
  recoveryProbeInFlightKeys.clear();
  recoveryProbeLastStartedAtByKey.clear();
}
