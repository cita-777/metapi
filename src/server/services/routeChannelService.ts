import { eq, inArray } from 'drizzle-orm';
import { db, schema } from '../db/index.js';
import { invalidateTokenRouterCache } from './tokenRouter.js';
import { clearRouteDecisionSnapshots } from './routeDecisionSnapshotStore.js';

export type RouteChannelPriorityUpdate = {
  id: number;
  priority: number;
};

export type RouteChannelInsertCandidate = {
  tokenId: number | null;
  accountId: number;
  sourceModel: string;
  priority?: number;
  weight?: number;
  enabled?: boolean;
  manualOverride?: boolean;
};

export class RouteChannelNotFoundError extends Error {
  readonly channelId: number;

  constructor(channelId: number) {
    super(`通道不存在: ${channelId}`);
    this.name = 'RouteChannelNotFoundError';
    this.channelId = channelId;
  }
}

// 事务负责数据库原子性，串行尾巴负责同一进程内的“读最大优先级 + 写入”不可分割。
let routeChannelMutationTail: Promise<void> = Promise.resolve();

async function withRouteChannelMutation<T>(operation: () => Promise<T>): Promise<T> {
  const previous = routeChannelMutationTail;
  let release!: () => void;
  routeChannelMutationTail = new Promise<void>((resolve) => {
    release = resolve;
  });
  await previous;
  try {
    return await operation();
  } finally {
    release();
  }
}

function channelPairKey(input: {
  accountId: number;
  tokenId: number | null | undefined;
  sourceModel: string | null | undefined;
}): string {
  const tokenId = typeof input.tokenId === 'number' && Number.isFinite(input.tokenId) ? input.tokenId : 0;
  return `${input.accountId}::${tokenId}::${(input.sourceModel || '').trim().toLowerCase()}`;
}

function normalizePriority(value: number | null | undefined): number {
  return Math.max(0, Math.trunc(value ?? 0));
}

async function clearDependentRouteSnapshots(routeIds: number[]): Promise<void> {
  const normalizedRouteIds = Array.from(new Set(routeIds.filter((routeId) => Number.isFinite(routeId) && routeId > 0)));
  if (normalizedRouteIds.length === 0) return;
  const dependentRows = await db.select({ groupRouteId: schema.routeGroupSources.groupRouteId })
    .from(schema.routeGroupSources)
    .where(inArray(schema.routeGroupSources.sourceRouteId, normalizedRouteIds))
    .all();
  const allRouteIds = Array.from(new Set([
    ...normalizedRouteIds,
    ...dependentRows.map((row) => row.groupRouteId),
  ]));
  await clearRouteDecisionSnapshots(allRouteIds);
}

async function finishRouteChannelMutation(routeIds: number[]): Promise<void> {
  await clearDependentRouteSnapshots(routeIds);
  invalidateTokenRouterCache();
}

async function insertCandidatesInTransaction(
  tx: typeof db,
  routeId: number,
  candidates: RouteChannelInsertCandidate[],
  options: { ignoreManualOverridesForPriority?: boolean } = {},
): Promise<{ created: number; skipped: number; errors: string[] }> {
  const existingChannels = await tx.select().from(schema.routeChannels)
    .where(eq(schema.routeChannels.routeId, routeId))
    .all();
  const existingPairs = new Set(existingChannels.map(channelPairKey));
  let nextPriority = existingChannels
    .filter((channel) => !options.ignoreManualOverridesForPriority || channel.manualOverride !== true)
    .reduce(
    (max, channel) => Math.max(max, normalizePriority(channel.priority)),
    -1,
    ) + 1;
  let created = 0;
  let skipped = 0;
  const errors: string[] = [];

  for (const candidate of candidates) {
    const sourceModel = candidate.sourceModel.trim();
    const pairKey = channelPairKey({
      accountId: candidate.accountId,
      tokenId: candidate.tokenId,
      sourceModel,
    });
    if (existingPairs.has(pairKey)) {
      skipped += 1;
      continue;
    }

    const requestedPriority = typeof candidate.priority === 'number'
      ? normalizePriority(candidate.priority)
      : nextPriority;
    const priority = requestedPriority > 0
      ? Math.max(requestedPriority, nextPriority)
      : nextPriority;
    try {
      await tx.insert(schema.routeChannels).values({
        routeId,
        accountId: candidate.accountId,
        tokenId: candidate.tokenId,
        sourceModel: sourceModel || null,
        priority,
        weight: candidate.weight ?? 10,
        enabled: candidate.enabled ?? true,
        manualOverride: candidate.manualOverride ?? false,
      }).run();
      existingPairs.add(pairKey);
      nextPriority = Math.max(nextPriority, priority + 1);
      created += 1;
    } catch (error) {
      errors.push(error instanceof Error ? error.message : `添加通道失败: accountId=${candidate.accountId}`);
    }
  }

  return { created, skipped, errors };
}

export async function insertRouteChannelsWithAllocatedPriorities(input: {
  routeId: number;
  candidates: RouteChannelInsertCandidate[];
}): Promise<{ created: number; skipped: number; errors: string[] }> {
  const result = await withRouteChannelMutation<{ created: number; skipped: number; errors: string[] }>(() => db.transaction(async (tx) => (
    insertCandidatesInTransaction(tx as typeof db, input.routeId, input.candidates)
  )) as Promise<{ created: number; skipped: number; errors: string[] }>);
  if (result.created > 0) await finishRouteChannelMutation([input.routeId]);
  return result;
}

export async function replaceAutomaticRouteChannels(input: {
  routeId: number;
  candidates: RouteChannelInsertCandidate[];
}): Promise<{ removedChannels: number; createdChannels: number }> {
  const result = await withRouteChannelMutation<{ removedChannels: number; createdChannels: number }>(() => db.transaction(async (tx) => {
    const removableChannels = await tx.select().from(schema.routeChannels)
      .where(eq(schema.routeChannels.routeId, input.routeId))
      .all();
    const automaticChannels = removableChannels.filter((channel) => channel.manualOverride === false);
    for (const channel of automaticChannels) {
      await tx.delete(schema.routeChannels).where(eq(schema.routeChannels.id, channel.id)).run();
    }
    const inserted = await insertCandidatesInTransaction(tx as typeof db, input.routeId, input.candidates, {
      // 重建自动通道时，手工通道的优先级不应挤占自动通道的 P0/P1 层。
      ignoreManualOverridesForPriority: true,
    });
    return {
      removedChannels: automaticChannels.length,
      createdChannels: inserted.created,
    };
  }) as Promise<{ removedChannels: number; createdChannels: number }>);
  await finishRouteChannelMutation([input.routeId]);
  return result;
}

export async function createRouteChannel(input: {
  routeId: number;
  accountId: number;
  tokenId: number | null;
  sourceModel: string | null;
  priority?: number;
  weight?: number;
  enabled?: boolean;
}): Promise<typeof schema.routeChannels.$inferSelect> {
  const created = await withRouteChannelMutation<typeof schema.routeChannels.$inferSelect | undefined>(() => db.transaction(async (tx) => {
    const result = await insertCandidatesInTransaction(tx as typeof db, input.routeId, [{
      accountId: input.accountId,
      tokenId: input.tokenId,
      sourceModel: input.sourceModel || '',
      priority: input.priority,
      weight: input.weight,
      enabled: input.enabled,
      manualOverride: true,
    }]);
    if (result.created !== 1) {
      throw new Error(result.errors[0] || '创建通道失败');
    }
    const rows = await tx.select().from(schema.routeChannels)
      .where(eq(schema.routeChannels.routeId, input.routeId))
      .all();
    return rows
      .filter((channel) => channel.accountId === input.accountId
        && (channel.tokenId ?? null) === (input.tokenId ?? null)
        && (channel.sourceModel || '').trim().toLowerCase() === (input.sourceModel || '').trim().toLowerCase())
      .sort((left, right) => right.id - left.id)[0];
  }) as Promise<typeof schema.routeChannels.$inferSelect | undefined>);
  if (!created) throw new Error('创建通道失败');
  await finishRouteChannelMutation([input.routeId]);
  return created;
}

export async function updateRouteChannelPriorities(
  updates: RouteChannelPriorityUpdate[],
): Promise<typeof schema.routeChannels.$inferSelect[]> {
  const result = await withRouteChannelMutation<typeof schema.routeChannels.$inferSelect[]>(() => db.transaction(async (tx) => {
    const channelIds = Array.from(new Set(updates.map((update) => update.id)));
    const existingChannels = await tx.select().from(schema.routeChannels)
      .where(inArray(schema.routeChannels.id, channelIds))
      .all();
    if (existingChannels.length !== channelIds.length) {
      const existingIds = new Set(existingChannels.map((channel) => channel.id));
      const missingId = channelIds.find((id) => !existingIds.has(id));
      throw new RouteChannelNotFoundError(missingId || 0);
    }

    for (const update of updates) {
      await tx.update(schema.routeChannels).set({
        priority: update.priority,
        manualOverride: true,
      }).where(eq(schema.routeChannels.id, update.id)).run();
    }
    return await tx.select().from(schema.routeChannels)
      .where(inArray(schema.routeChannels.id, channelIds))
      .all();
  }) as Promise<typeof schema.routeChannels.$inferSelect[]>);
  await finishRouteChannelMutation(Array.from(new Set(result.map((channel) => channel.routeId))));
  return result;
}

export function resetRouteChannelMutationStateForTests(): void {
  routeChannelMutationTail = Promise.resolve();
}
