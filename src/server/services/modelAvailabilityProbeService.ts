import { and, asc, eq } from 'drizzle-orm';
import { config } from '../config.js';
import { db, schema } from '../db/index.js';
import { startBackgroundTask } from './backgroundTaskService.js';
import { isUsableAccountToken, ACCOUNT_TOKEN_VALUE_STATUS_READY } from './accountTokenService.js';
import { probeRuntimeModel } from './runtimeModelProbe.js';
import * as routeRefreshWorkflow from './routeRefreshWorkflow.js';

type ProbeStatus = 'supported' | 'unsupported' | 'inconclusive' | 'skipped';

type ProbeAccountTarget = {
  kind: 'account';
  rowId: number;
  modelName: string;
  lastKnownAvailable: boolean;
  account: typeof schema.accounts.$inferSelect;
  site: typeof schema.sites.$inferSelect;
};

type ProbeTokenTarget = {
  kind: 'token';
  rowId: number;
  tokenId: number;
  modelName: string;
  tokenValue: string;
  lastKnownAvailable: boolean;
  account: typeof schema.accounts.$inferSelect;
  site: typeof schema.sites.$inferSelect;
};

type ProbeTarget = ProbeAccountTarget | ProbeTokenTarget;
type ProbeAccountContext = {
  account: typeof schema.accounts.$inferSelect;
  site: typeof schema.sites.$inferSelect;
};

export type ModelAvailabilityProbeAccountResult = {
  accountId: number;
  siteId: number;
  status: 'success' | 'failed' | 'skipped';
  scanned: number;
  supported: number;
  unsupported: number;
  inconclusive: number;
  skipped: number;
  updatedRows: number;
  message: string;
};

export type ModelAvailabilityProbeExecutionResult = {
  results: ModelAvailabilityProbeAccountResult[];
  summary: {
    totalAccounts: number;
    success: number;
    failed: number;
    skipped: number;
    scanned: number;
    supported: number;
    unsupported: number;
    inconclusive: number;
    skippedModels: number;
    updatedRows: number;
    rebuiltRoutes: boolean;
  };
};

let probeSchedulerTimer: ReturnType<typeof setInterval> | null = null;
const probeAccountLeases = new Set<number>();

async function mapWithConcurrency<T, R>(
  items: T[],
  concurrency: number,
  worker: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const safeConcurrency = Math.max(1, Math.min(items.length || 1, Math.trunc(concurrency || 1)));
  const results = new Array<R>(items.length);
  let nextIndex = 0;

  const runWorker = async () => {
    while (true) {
      const currentIndex = nextIndex;
      nextIndex += 1;
      if (currentIndex >= items.length) return;
      results[currentIndex] = await worker(items[currentIndex] as T, currentIndex);
    }
  };

  await Promise.all(Array.from({ length: safeConcurrency }, () => runWorker()));
  return results;
}

async function probeSingleTarget(target: ProbeTarget): Promise<{
  status: ProbeStatus;
  latencyMs: number | null;
  reason: string;
}> {
  return await probeRuntimeModel({
    site: target.site,
    account: target.account,
    modelName: target.modelName,
    timeoutMs: config.modelAvailabilityProbeTimeoutMs,
    tokenValue: target.kind === 'token' ? target.tokenValue : undefined,
  });
}

async function updateProbeRow(target: ProbeTarget, status: ProbeStatus, latencyMs: number | null): Promise<{
  touched: boolean;
  availabilityChanged: boolean;
}> {
  if (status === 'inconclusive' || status === 'skipped') {
    return {
      touched: false,
      availabilityChanged: false,
    };
  }
  const nextAvailable = status === 'supported';
  const patch = {
    available: nextAvailable,
    latencyMs,
    checkedAt: new Date().toISOString(),
  };

  if (target.kind === 'account') {
    await db.update(schema.modelAvailability)
      .set(patch)
      .where(eq(schema.modelAvailability.id, target.rowId))
      .run();
    return {
      touched: true,
      availabilityChanged: target.lastKnownAvailable !== nextAvailable,
    };
  }

  await db.update(schema.tokenModelAvailability)
    .set(patch)
    .where(eq(schema.tokenModelAvailability.id, target.rowId))
    .run();
  return {
    touched: true,
    availabilityChanged: target.lastKnownAvailable !== nextAvailable,
  };
}

async function loadActiveProbeAccountContext(accountId: number): Promise<ProbeAccountContext | null> {
  const accountRow = await db.select()
    .from(schema.accounts)
    .innerJoin(schema.sites, eq(schema.accounts.siteId, schema.sites.id))
    .where(eq(schema.accounts.id, accountId))
    .get();
  if (!accountRow) return null;
  if ((accountRow.accounts.status || 'active') !== 'active') return null;
  if ((accountRow.sites.status || 'active') !== 'active') return null;
  return {
    account: accountRow.accounts,
    site: accountRow.sites,
  };
}

async function loadProbeTargetsForAccount(context: ProbeAccountContext): Promise<ProbeTarget[]> {
  const targets: ProbeTarget[] = [];
  const accountModels = await db.select()
    .from(schema.modelAvailability)
    .where(eq(schema.modelAvailability.accountId, context.account.id))
    .orderBy(asc(schema.modelAvailability.checkedAt))
    .all();
  for (const row of accountModels) {
    if (row.isManual) continue;
    targets.push({
      kind: 'account',
      rowId: row.id,
      modelName: row.modelName,
      lastKnownAvailable: !!row.available,
      account: context.account,
      site: context.site,
    });
  }

  const tokenRows = await db.select()
    .from(schema.tokenModelAvailability)
    .innerJoin(schema.accountTokens, eq(schema.tokenModelAvailability.tokenId, schema.accountTokens.id))
    .where(and(
      eq(schema.accountTokens.accountId, context.account.id),
      eq(schema.accountTokens.enabled, true),
      eq(schema.accountTokens.valueStatus, ACCOUNT_TOKEN_VALUE_STATUS_READY),
    ))
    .orderBy(asc(schema.tokenModelAvailability.checkedAt))
    .all();
  for (const row of tokenRows) {
    if (!isUsableAccountToken(row.account_tokens)) continue;
    const tokenValue = String(row.account_tokens.token || '').trim();
    if (!tokenValue) continue;
    targets.push({
      kind: 'token',
      rowId: row.token_model_availability.id,
      tokenId: row.account_tokens.id,
      modelName: row.token_model_availability.modelName,
      tokenValue,
      lastKnownAvailable: !!row.token_model_availability.available,
      account: context.account,
      site: context.site,
    });
  }

  return targets;
}

function tryAcquireProbeAccountLease(accountId: number): boolean {
  if (!Number.isFinite(accountId) || accountId <= 0) return false;
  if (probeAccountLeases.has(accountId)) return false;
  probeAccountLeases.add(accountId);
  return true;
}

function releaseProbeAccountLease(accountId: number): void {
  probeAccountLeases.delete(accountId);
}

function buildSkippedProbeAccountResult(input: {
  accountId: number;
  siteId: number;
  message: string;
}): ModelAvailabilityProbeAccountResult {
  return {
    accountId: input.accountId,
    siteId: input.siteId,
    status: 'skipped',
    scanned: 0,
    supported: 0,
    unsupported: 0,
    inconclusive: 0,
    skipped: 0,
    updatedRows: 0,
    message: input.message,
  };
}

function summarizeProbeResults(results: ModelAvailabilityProbeAccountResult[], rebuiltRoutes: boolean): ModelAvailabilityProbeExecutionResult {
  return {
    results,
    summary: {
      totalAccounts: results.length,
      success: results.filter((item) => item.status === 'success').length,
      failed: results.filter((item) => item.status === 'failed').length,
      skipped: results.filter((item) => item.status === 'skipped').length,
      scanned: results.reduce((sum, item) => sum + item.scanned, 0),
      supported: results.reduce((sum, item) => sum + item.supported, 0),
      unsupported: results.reduce((sum, item) => sum + item.unsupported, 0),
      inconclusive: results.reduce((sum, item) => sum + item.inconclusive, 0),
      skippedModels: results.reduce((sum, item) => sum + item.skipped, 0),
      updatedRows: results.reduce((sum, item) => sum + item.updatedRows, 0),
      rebuiltRoutes,
    },
  };
}

export async function executeModelAvailabilityProbe(input: {
  accountId?: number;
  rebuildRoutes?: boolean;
} = {}): Promise<ModelAvailabilityProbeExecutionResult> {
  const accountIds = input.accountId
    ? [input.accountId]
    : (await db.select({ id: schema.accounts.id })
      .from(schema.accounts)
      .where(eq(schema.accounts.status, 'active'))
      .all()).map((row) => row.id);

  const results: ModelAvailabilityProbeAccountResult[] = [];
  let shouldRebuildRoutes = false;

  for (const accountId of accountIds) {
    const context = await loadActiveProbeAccountContext(accountId);
    if (!context) {
      continue;
    }
    if (!tryAcquireProbeAccountLease(accountId)) {
      results.push(buildSkippedProbeAccountResult({
        accountId,
        siteId: context.site.id,
        message: 'model availability probe already running for account',
      }));
      continue;
    }

    try {
      const targets = await loadProbeTargetsForAccount(context);
      if (targets.length <= 0) {
        results.push(buildSkippedProbeAccountResult({
          accountId,
          siteId: context.site.id,
          message: 'no discovered models to probe',
        }));
        continue;
      }

      let supported = 0;
      let unsupported = 0;
      let inconclusive = 0;
      let skipped = 0;
      let updatedRows = 0;
      let failed = false;

      const probeOutcomes = await mapWithConcurrency(
        targets,
        config.modelAvailabilityProbeConcurrency,
        async (target) => {
          try {
            const probe = await probeSingleTarget(target);
            const update = await updateProbeRow(target, probe.status, probe.latencyMs);
            return {
              target,
              probe,
              touched: update.touched,
              availabilityChanged: update.availabilityChanged,
              failed: false,
            };
          } catch (error) {
            console.warn(`[model-probe] account ${accountId} model ${target.modelName} probe failed`, error);
            return {
              target,
              probe: {
                status: 'inconclusive' as const,
                latencyMs: null,
                reason: error instanceof Error ? error.message : 'probe failed',
              },
              touched: false,
              availabilityChanged: false,
              failed: true,
            };
          }
        },
      );

      for (const outcome of probeOutcomes) {
        if (outcome.probe.status === 'supported') supported += 1;
        if (outcome.probe.status === 'unsupported') unsupported += 1;
        if (outcome.probe.status === 'inconclusive') inconclusive += 1;
        if (outcome.probe.status === 'skipped') skipped += 1;
        if (outcome.touched) {
          updatedRows += 1;
        }
        if (outcome.availabilityChanged) {
          shouldRebuildRoutes = true;
        }
        if (outcome.failed) {
          failed = true;
        }
      }

      results.push({
        accountId,
        siteId: context.site.id,
        status: failed ? 'failed' : 'success',
        scanned: targets.length,
        supported,
        unsupported,
        inconclusive,
        skipped,
        updatedRows,
        message: failed
          ? 'model availability probe finished with partial failures'
          : 'model availability probe finished',
      });
    } finally {
      releaseProbeAccountLease(accountId);
    }
  }

  let rebuiltRoutes = false;
  if (input.rebuildRoutes !== false && shouldRebuildRoutes) {
    await routeRefreshWorkflow.rebuildRoutesOnly();
    rebuiltRoutes = true;
  }

  return summarizeProbeResults(results, rebuiltRoutes);
}

export function buildModelAvailabilityProbeTaskDedupeKey(accountId?: number | null): string {
  const normalizedAccountId = Number.isFinite(accountId as number) && Number(accountId) > 0
    ? Math.trunc(Number(accountId))
    : null;
  return normalizedAccountId
    ? `model-availability-probe-${normalizedAccountId}`
    : 'model-availability-probe-all';
}

export function queueModelAvailabilityProbeTask(input: {
  accountId?: number;
  title?: string;
}) {
  const accountId = Number.isFinite(input.accountId as number) ? Math.trunc(input.accountId as number) : null;
  const title = input.title || (accountId
    ? `探测模型可用性 #${accountId}`
    : '探测模型可用性');
  const dedupeKey = buildModelAvailabilityProbeTaskDedupeKey(accountId);

  return startBackgroundTask(
    {
      type: 'model-probe',
      title,
      dedupeKey,
      notifyOnFailure: true,
      successMessage: (currentTask) => {
        const summary = (currentTask.result as ModelAvailabilityProbeExecutionResult | undefined)?.summary;
        if (!summary) return `${title}已完成`;
        return `${title}完成：探测 ${summary.scanned}，可用 ${summary.supported}，不可用 ${summary.unsupported}，不确定 ${summary.inconclusive}`;
      },
      failureMessage: (currentTask) => `${title}失败：${currentTask.error || 'unknown error'}`,
    },
    async () => executeModelAvailabilityProbe({
      accountId: accountId ?? undefined,
      rebuildRoutes: true,
    }),
  );
}

export function startModelAvailabilityProbeScheduler(intervalMs = config.modelAvailabilityProbeIntervalMs) {
  stopModelAvailabilityProbeScheduler();
  if (!config.modelAvailabilityProbeEnabled) {
    return {
      enabled: false,
      intervalMs: 0,
    };
  }

  const safeIntervalMs = Math.max(60_000, Math.trunc(intervalMs || 0));
  probeSchedulerTimer = setInterval(() => {
    void queueModelAvailabilityProbeTask({
      title: '后台模型可用性探测',
    });
  }, safeIntervalMs);
  probeSchedulerTimer.unref?.();
  return {
    enabled: true,
    intervalMs: safeIntervalMs,
  };
}

export function stopModelAvailabilityProbeScheduler() {
  if (probeSchedulerTimer) {
    clearInterval(probeSchedulerTimer);
    probeSchedulerTimer = null;
  }
}

export function __resetModelAvailabilityProbeExecutionStateForTests(): void {
  probeAccountLeases.clear();
}
