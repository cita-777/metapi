import { and, eq, inArray, sql } from 'drizzle-orm';
import { db, schema } from '../../db/index.js';
import { insertAndGetById } from '../../db/insertHelpers.js';
import * as routeRefreshWorkflow from '../routeRefreshWorkflow.js';
import { invalidateTokenRouterCache } from '../tokenRouter.js';

export type OAuthRouteUnitStrategy = 'round_robin' | 'stick_until_unavailable';

export type OAuthRouteUnitSummary = {
  id: number;
  siteId: number;
  provider: string;
  name: string;
  strategy: OAuthRouteUnitStrategy;
  enabled: boolean;
  memberCount: number;
};

export type OAuthRouteUnitAccountParticipation = {
  kind: 'route_unit';
  id: number;
  name: string;
  strategy: OAuthRouteUnitStrategy;
  memberCount: number;
};

export type OAuthRouteUnitMemberDetail = {
  member: typeof schema.oauthRouteUnitMembers.$inferSelect;
  unit: typeof schema.oauthRouteUnits.$inferSelect;
  account: typeof schema.accounts.$inferSelect;
  site: typeof schema.sites.$inferSelect;
};

function normalizeRouteUnitStrategy(value: unknown): OAuthRouteUnitStrategy | null {
  if (typeof value !== 'string') return null;
  const normalized = value.trim().toLowerCase();
  if (normalized === 'round_robin') return 'round_robin';
  if (normalized === 'stick_until_unavailable') return 'stick_until_unavailable';
  return null;
}

function uniquePositiveIds(accountIds: number[]): number[] {
  return Array.from(new Set(
    accountIds
      .filter((id) => Number.isFinite(id) && id > 0)
      .map((id) => Math.trunc(id)),
  ));
}

function assertRouteUnitStrategy(value: unknown): OAuthRouteUnitStrategy {
  const normalized = normalizeRouteUnitStrategy(value);
  if (!normalized) {
    throw new Error('invalid oauth route unit strategy');
  }
  return normalized;
}

function isOauthRouteUnitAccountUniqueConflict(error: unknown): boolean {
  if (!error || typeof error !== 'object') return false;
  const code = String((error as { code?: unknown }).code || '');
  const lowered = String((error as { message?: unknown }).message || '').toLowerCase();
  return (
    ((code === 'SQLITE_CONSTRAINT' || code === 'SQLITE_CONSTRAINT_UNIQUE')
      && lowered.includes('oauth_route_unit_members.account_id'))
    || (code === 'ER_DUP_ENTRY' && lowered.includes('oauth_route_unit_members_account_unique'))
    || (code === '23505' && lowered.includes('oauth_route_unit_members_account_unique'))
    || (lowered.includes('duplicate key value violates unique constraint')
      && lowered.includes('oauth_route_unit_members_account_unique'))
  );
}

export async function listOauthRouteUnitsByAccountIds(accountIds: number[]): Promise<Map<number, OAuthRouteUnitAccountParticipation>> {
  const uniqueIds = uniquePositiveIds(accountIds);
  if (uniqueIds.length === 0) return new Map();

  const rows = await db.select({
    accountId: schema.oauthRouteUnitMembers.accountId,
    unitId: schema.oauthRouteUnits.id,
    siteId: schema.oauthRouteUnits.siteId,
    provider: schema.oauthRouteUnits.provider,
    name: schema.oauthRouteUnits.name,
    strategy: schema.oauthRouteUnits.strategy,
    enabled: schema.oauthRouteUnits.enabled,
    memberCount: sql<number>`COUNT(*) OVER (PARTITION BY ${schema.oauthRouteUnits.id})`,
  }).from(schema.oauthRouteUnitMembers)
    .innerJoin(schema.oauthRouteUnits, eq(schema.oauthRouteUnitMembers.unitId, schema.oauthRouteUnits.id))
    .where(inArray(schema.oauthRouteUnitMembers.accountId, uniqueIds))
    .all();

  const result = new Map<number, OAuthRouteUnitAccountParticipation>();
  for (const row of rows) {
    const strategy = normalizeRouteUnitStrategy(row.strategy) || 'round_robin';
    result.set(row.accountId, {
      kind: 'route_unit',
      id: row.unitId,
      name: row.name,
      strategy,
      memberCount: Math.max(1, Number(row.memberCount || 0)),
    });
  }
  return result;
}

export async function listOauthRouteUnitMembersByUnitIds(unitIds: number[]): Promise<Map<number, OAuthRouteUnitMemberDetail[]>> {
  const normalizedUnitIds = uniquePositiveIds(unitIds);
  if (normalizedUnitIds.length === 0) return new Map();

  const rows = await db.select()
    .from(schema.oauthRouteUnitMembers)
    .innerJoin(schema.oauthRouteUnits, eq(schema.oauthRouteUnitMembers.unitId, schema.oauthRouteUnits.id))
    .innerJoin(schema.accounts, eq(schema.oauthRouteUnitMembers.accountId, schema.accounts.id))
    .innerJoin(schema.sites, eq(schema.accounts.siteId, schema.sites.id))
    .where(inArray(schema.oauthRouteUnitMembers.unitId, normalizedUnitIds))
    .all();

  const result = new Map<number, OAuthRouteUnitMemberDetail[]>();
  for (const row of rows) {
    if (!result.has(row.oauth_route_unit_members.unitId)) {
      result.set(row.oauth_route_unit_members.unitId, []);
    }
    result.get(row.oauth_route_unit_members.unitId)!.push({
      member: row.oauth_route_unit_members,
      unit: row.oauth_route_units,
      account: row.accounts,
      site: row.sites,
    });
  }

  for (const members of result.values()) {
    members.sort((left, right) => (
      (left.member.sortOrder ?? 0) - (right.member.sortOrder ?? 0)
      || left.member.id - right.member.id
    ));
  }

  return result;
}

async function rollbackCreatedOauthRouteUnit(routeUnitId: number): Promise<void> {
  await db.transaction(async (tx) => {
    await tx.delete(schema.routeChannels)
      .where(eq(schema.routeChannels.oauthRouteUnitId, routeUnitId))
      .run();
    await tx.delete(schema.oauthRouteUnitMembers)
      .where(eq(schema.oauthRouteUnitMembers.unitId, routeUnitId))
      .run();
    await tx.delete(schema.oauthRouteUnits)
      .where(eq(schema.oauthRouteUnits.id, routeUnitId))
      .run();
  });
}

async function restoreDeletedOauthRouteUnit(snapshot: {
  unit: typeof schema.oauthRouteUnits.$inferSelect;
  members: Array<typeof schema.oauthRouteUnitMembers.$inferSelect>;
}): Promise<void> {
  await db.transaction(async (tx) => {
    await tx.insert(schema.oauthRouteUnits).values({
      id: snapshot.unit.id,
      siteId: snapshot.unit.siteId,
      provider: snapshot.unit.provider,
      name: snapshot.unit.name,
      strategy: snapshot.unit.strategy,
      enabled: snapshot.unit.enabled,
      createdAt: snapshot.unit.createdAt,
      updatedAt: snapshot.unit.updatedAt,
    }).run();

    if (snapshot.members.length > 0) {
      await tx.insert(schema.oauthRouteUnitMembers).values(snapshot.members.map((member) => ({
        id: member.id,
        unitId: member.unitId,
        accountId: member.accountId,
        sortOrder: member.sortOrder,
        createdAt: member.createdAt,
        updatedAt: member.updatedAt,
      }))).run();
    }
  });
}

export async function listEnabledOauthRouteUnitsWithMembers(): Promise<Array<{
  unit: typeof schema.oauthRouteUnits.$inferSelect;
  members: OAuthRouteUnitMemberDetail[];
}>> {
  const units = await db.select().from(schema.oauthRouteUnits)
    .where(eq(schema.oauthRouteUnits.enabled, true))
    .all();
  if (units.length === 0) return [];

  const membersByUnitId = await listOauthRouteUnitMembersByUnitIds(units.map((unit) => unit.id));
  return units.map((unit) => ({
    unit,
    members: membersByUnitId.get(unit.id) || [],
  }));
}

export async function createOauthRouteUnit(input: {
  accountIds: number[];
  name: string;
  strategy: OAuthRouteUnitStrategy;
}) {
  const accountIds = uniquePositiveIds(input.accountIds);
  if (accountIds.length < 2) {
    throw new Error('oauth route unit requires at least 2 accounts');
  }
  const name = String(input.name || '').trim();
  if (!name) {
    throw new Error('oauth route unit name is required');
  }
  const strategy = assertRouteUnitStrategy(input.strategy);

  const rows = await db.select()
    .from(schema.accounts)
    .innerJoin(schema.sites, eq(schema.accounts.siteId, schema.sites.id))
    .where(inArray(schema.accounts.id, accountIds))
    .all();
  if (rows.length !== accountIds.length) {
    throw new Error('oauth route unit accounts not found');
  }

  const first = rows[0]!;
  const expectedSiteId = first.accounts.siteId;
  const expectedProvider = (first.accounts.oauthProvider || '').trim();
  if (!expectedProvider) {
    throw new Error('oauth route unit only supports oauth accounts');
  }

  for (const row of rows) {
    if (row.accounts.siteId !== expectedSiteId) {
      throw new Error('oauth route unit accounts must belong to the same site');
    }
    if ((row.accounts.oauthProvider || '').trim() !== expectedProvider) {
      throw new Error('oauth route unit accounts must share the same provider');
    }
  }

  let created;
  try {
    created = await db.transaction(async (tx) => {
      const existingMembers = await tx.select({
        accountId: schema.oauthRouteUnitMembers.accountId,
      }).from(schema.oauthRouteUnitMembers)
        .where(inArray(schema.oauthRouteUnitMembers.accountId, accountIds))
        .all();
      if (existingMembers.length > 0) {
        throw new Error('oauth route unit accounts already grouped');
      }

      const inserted = await insertAndGetById<typeof schema.oauthRouteUnits.$inferSelect>({
        txDb: tx,
        table: schema.oauthRouteUnits,
        idColumn: schema.oauthRouteUnits.id,
        values: {
          siteId: expectedSiteId,
          provider: expectedProvider,
          name,
          strategy,
          enabled: true,
        },
        insertErrorMessage: 'oauth route unit creation failed',
      });

      await tx.insert(schema.oauthRouteUnitMembers).values(
        accountIds.map((accountId, index) => ({
          unitId: inserted.id,
          accountId,
          sortOrder: index,
        })),
      ).run();
      return inserted;
    });
  } catch (error) {
    if ((error as Error)?.message === 'oauth route unit accounts already grouped' || isOauthRouteUnitAccountUniqueConflict(error)) {
      throw new Error('oauth route unit accounts already grouped');
    }
    throw error;
  }

  try {
    await routeRefreshWorkflow.rebuildRoutesOnly();
  } catch (error) {
    await rollbackCreatedOauthRouteUnit(created.id);
    try {
      await routeRefreshWorkflow.rebuildRoutesOnly();
    } catch {
      // Best-effort restore to the pre-create routing shape before surfacing the original failure.
    }
    throw error;
  }

  return {
    success: true as const,
    routeUnit: {
      id: created.id,
      siteId: created.siteId,
      provider: created.provider,
      name: created.name,
      strategy,
      enabled: created.enabled ?? true,
      memberCount: accountIds.length,
    },
  };
}

export async function updateOauthRouteUnit(input: {
  routeUnitId: number;
  name?: string;
  strategy?: OAuthRouteUnitStrategy;
}) {
  const existing = await db.select().from(schema.oauthRouteUnits)
    .where(eq(schema.oauthRouteUnits.id, input.routeUnitId))
    .get();
  if (!existing) {
    throw new Error('oauth route unit not found');
  }

  const updates: Partial<typeof schema.oauthRouteUnits.$inferInsert> = {
    updatedAt: new Date().toISOString(),
  };
  if (input.name !== undefined) {
    const nextName = String(input.name || '').trim();
    if (!nextName) {
      throw new Error('oauth route unit name is required');
    }
    updates.name = nextName;
  }
  if (input.strategy !== undefined) {
    updates.strategy = assertRouteUnitStrategy(input.strategy);
  }

  await db.update(schema.oauthRouteUnits).set(updates)
    .where(eq(schema.oauthRouteUnits.id, input.routeUnitId))
    .run();

  invalidateTokenRouterCache();

  const memberCountRow = await db.select({
    count: sql<number>`COUNT(*)`,
  }).from(schema.oauthRouteUnitMembers)
    .where(eq(schema.oauthRouteUnitMembers.unitId, input.routeUnitId))
    .get();

  const updated = await db.select().from(schema.oauthRouteUnits)
    .where(eq(schema.oauthRouteUnits.id, input.routeUnitId))
    .get();
  if (!updated) {
    throw new Error('oauth route unit not found');
  }

  return {
    success: true as const,
    routeUnit: {
      id: updated.id,
      siteId: updated.siteId,
      provider: updated.provider,
      name: updated.name,
      strategy: assertRouteUnitStrategy(updated.strategy),
      enabled: updated.enabled ?? true,
      memberCount: Number(memberCountRow?.count || 0),
    },
  };
}

export async function deleteOauthRouteUnit(routeUnitId: number) {
  const existing = await db.select().from(schema.oauthRouteUnits)
    .where(eq(schema.oauthRouteUnits.id, routeUnitId))
    .get();
  if (!existing) {
    throw new Error('oauth route unit not found');
  }

  const existingMembers = await db.select().from(schema.oauthRouteUnitMembers)
    .where(eq(schema.oauthRouteUnitMembers.unitId, routeUnitId))
    .all();

  await db.delete(schema.routeChannels)
    .where(eq(schema.routeChannels.oauthRouteUnitId, routeUnitId))
    .run();
  await db.delete(schema.oauthRouteUnitMembers)
    .where(eq(schema.oauthRouteUnitMembers.unitId, routeUnitId))
    .run();
  await db.delete(schema.oauthRouteUnits)
    .where(eq(schema.oauthRouteUnits.id, routeUnitId))
    .run();

  try {
    await routeRefreshWorkflow.rebuildRoutesOnly();
  } catch (error) {
    await restoreDeletedOauthRouteUnit({
      unit: existing,
      members: existingMembers,
    });
    try {
      await routeRefreshWorkflow.rebuildRoutesOnly();
    } catch {
      // Best-effort restore to the pre-delete routing shape before surfacing the original failure.
    }
    throw error;
  }
  return { success: true as const };
}

export async function loadOauthRouteUnitSummariesByIds(routeUnitIds: number[]): Promise<Map<number, OAuthRouteUnitSummary>> {
  const normalizedIds = uniquePositiveIds(routeUnitIds);
  if (normalizedIds.length === 0) return new Map();

  const rows = await db.select({
    id: schema.oauthRouteUnits.id,
    siteId: schema.oauthRouteUnits.siteId,
    provider: schema.oauthRouteUnits.provider,
    name: schema.oauthRouteUnits.name,
    strategy: schema.oauthRouteUnits.strategy,
    enabled: schema.oauthRouteUnits.enabled,
    memberCount: sql<number>`COUNT(${schema.oauthRouteUnitMembers.id})`,
  }).from(schema.oauthRouteUnits)
    .leftJoin(schema.oauthRouteUnitMembers, eq(schema.oauthRouteUnits.id, schema.oauthRouteUnitMembers.unitId))
    .where(inArray(schema.oauthRouteUnits.id, normalizedIds))
    .groupBy(schema.oauthRouteUnits.id)
    .all();

  const result = new Map<number, OAuthRouteUnitSummary>();
  for (const row of rows) {
    result.set(row.id, {
      id: row.id,
      siteId: row.siteId,
      provider: row.provider,
      name: row.name,
      strategy: normalizeRouteUnitStrategy(row.strategy) || 'round_robin',
      enabled: row.enabled ?? true,
      memberCount: Number(row.memberCount || 0),
    });
  }
  return result;
}

export async function loadOauthRouteUnitByAccountId(accountId: number): Promise<OAuthRouteUnitAccountParticipation | null> {
  const result = await listOauthRouteUnitsByAccountIds([accountId]);
  return result.get(accountId) || null;
}

export function getOauthRouteUnitStrategyLabel(strategy: OAuthRouteUnitStrategy): string {
  return strategy === 'stick_until_unavailable' ? '单个用到不可用再切' : '轮询';
}

export async function loadOauthRouteUnitMemberByChannelAndAccount(input: {
  routeUnitId: number;
  accountId: number;
}) {
  return await db.select()
    .from(schema.oauthRouteUnitMembers)
    .where(and(
      eq(schema.oauthRouteUnitMembers.unitId, input.routeUnitId),
      eq(schema.oauthRouteUnitMembers.accountId, input.accountId),
    ))
    .get();
}
