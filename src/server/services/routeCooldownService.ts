import { eq, inArray } from 'drizzle-orm';
import { db, schema } from '../db/index.js';
import {
  clearRouteDecisionSnapshot,
  clearRouteDecisionSnapshots,
} from './routeDecisionSnapshotStore.js';
import { tokenRouter } from './tokenRouter.js';
import { normalizeTokenRouteMode, type RouteMode } from '../../shared/tokenRouteContract.js';

type RouteRow = typeof schema.tokenRoutes.$inferSelect & {
  routeMode: RouteMode;
  sourceRouteIds: number[];
};

function isExactModelPattern(modelPattern: string): boolean {
  const normalized = modelPattern.trim();
  if (!normalized) return false;
  if (normalized.toLowerCase().startsWith('re:')) return false;
  return !/[\*\?]/.test(normalized);
}

function isExplicitGroupRoute(route: Pick<RouteRow, 'routeMode'> | Pick<typeof schema.tokenRoutes.$inferSelect, 'routeMode'>): boolean {
  return normalizeTokenRouteMode(route.routeMode) === 'explicit_group';
}

function normalizeSourceRouteIds(sourceRouteIds: number[]): number[] {
  return Array.from(new Set(
    sourceRouteIds
      .filter((routeId): routeId is number => Number.isFinite(routeId) && routeId > 0)
      .map((routeId) => Math.trunc(routeId)),
  ));
}

async function loadRouteSourceIdsMap(routeIds: number[]): Promise<Map<number, number[]>> {
  const normalizedRouteIds = normalizeSourceRouteIds(routeIds);
  if (normalizedRouteIds.length === 0) return new Map();

  const rows = await db.select().from(schema.routeGroupSources)
    .where(inArray(schema.routeGroupSources.groupRouteId, normalizedRouteIds))
    .all();
  const sourceRouteIdsByRouteId = new Map<number, number[]>();
  for (const row of rows) {
    if (!sourceRouteIdsByRouteId.has(row.groupRouteId)) {
      sourceRouteIdsByRouteId.set(row.groupRouteId, []);
    }
    sourceRouteIdsByRouteId.get(row.groupRouteId)!.push(row.sourceRouteId);
  }
  for (const [routeId, sourceRouteIds] of sourceRouteIdsByRouteId.entries()) {
    sourceRouteIdsByRouteId.set(routeId, normalizeSourceRouteIds(sourceRouteIds));
  }
  return sourceRouteIdsByRouteId;
}

function decorateRoutesWithSources(
  routes: Array<typeof schema.tokenRoutes.$inferSelect>,
  sourceRouteIdsByRouteId: Map<number, number[]>,
): RouteRow[] {
  return routes.map((route) => ({
    ...route,
    routeMode: normalizeTokenRouteMode(route.routeMode),
    sourceRouteIds: sourceRouteIdsByRouteId.get(route.id) ?? [],
  }));
}

async function getRouteWithSources(routeId: number): Promise<RouteRow | null> {
  const route = await db.select().from(schema.tokenRoutes).where(eq(schema.tokenRoutes.id, routeId)).get();
  if (!route) return null;
  const sourceRouteIdsByRouteId = await loadRouteSourceIdsMap([routeId]);
  return decorateRoutesWithSources([route], sourceRouteIdsByRouteId)[0] ?? null;
}

async function resolveCooldownClearRouteIds(route: RouteRow): Promise<number[]> {
  if (!isExplicitGroupRoute(route)) {
    return [route.id];
  }

  const sourceRouteIds = normalizeSourceRouteIds(route.sourceRouteIds);
  if (sourceRouteIds.length === 0) return [];

  const sourceRoutes = await db.select({
    id: schema.tokenRoutes.id,
    modelPattern: schema.tokenRoutes.modelPattern,
    routeMode: schema.tokenRoutes.routeMode,
    enabled: schema.tokenRoutes.enabled,
  }).from(schema.tokenRoutes)
    .where(inArray(schema.tokenRoutes.id, sourceRouteIds))
    .all();

  return sourceRoutes
    .filter((sourceRoute) => (
      sourceRoute.enabled
      && normalizeTokenRouteMode(sourceRoute.routeMode) !== 'explicit_group'
      && isExactModelPattern(sourceRoute.modelPattern)
    ))
    .map((sourceRoute) => sourceRoute.id);
}

async function clearDependentExplicitGroupSnapshotsBySourceRouteIds(sourceRouteIds: number[]): Promise<void> {
  const normalizedSourceRouteIds = normalizeSourceRouteIds(sourceRouteIds);
  if (normalizedSourceRouteIds.length === 0) return;

  const rows = await db.select({ groupRouteId: schema.routeGroupSources.groupRouteId })
    .from(schema.routeGroupSources)
    .where(inArray(schema.routeGroupSources.sourceRouteId, normalizedSourceRouteIds))
    .all();
  const dependentRouteIds: number[] = Array.from(new Set(
    rows
      .map((row) => row.groupRouteId)
      .filter((routeId): routeId is number => Number.isFinite(routeId) && routeId > 0),
  ));
  if (dependentRouteIds.length === 0) return;
  await clearRouteDecisionSnapshots(dependentRouteIds);
}

export async function clearRouteCooldown(routeId: number): Promise<{ success: true; clearedChannels: number } | null> {
  const route = await getRouteWithSources(routeId);
  if (!route) return null;

  const actualRouteIds = await resolveCooldownClearRouteIds(route);
  const channelRows: Array<{ id: number; routeId: number }> = actualRouteIds.length > 0
    ? await db.select({
      id: schema.routeChannels.id,
      routeId: schema.routeChannels.routeId,
    }).from(schema.routeChannels)
      .where(inArray(schema.routeChannels.routeId, actualRouteIds))
      .all()
    : [];

  const affectedRouteIds = Array.from(new Set(channelRows.map((row) => row.routeId)));
  const clearedChannels = await tokenRouter.clearChannelFailureState(channelRows.map((row) => row.id));

  await clearRouteDecisionSnapshot(route.id);
  if (affectedRouteIds.length > 0) {
    await clearRouteDecisionSnapshots(affectedRouteIds);
    await clearDependentExplicitGroupSnapshotsBySourceRouteIds(affectedRouteIds);
  }

  return {
    success: true,
    clearedChannels,
  };
}
