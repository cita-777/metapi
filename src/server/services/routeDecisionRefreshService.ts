import { eq } from 'drizzle-orm';
import { db, schema } from '../db/index.js';
import { saveRouteDecisionSnapshots } from './routeDecisionSnapshotStore.js';
import { matchesModelPattern, tokenRouter } from './tokenRouter.js';
import { ROUTE_DECISION_REFRESH_TASK_TYPE } from '../../shared/tokenRouteContract.js';

export { ROUTE_DECISION_REFRESH_TASK_TYPE };
export const ROUTE_DECISION_REFRESH_DEDUPE_KEY = 'refresh-route-decision-snapshots';

function isExactModelPattern(modelPattern: string): boolean {
  const normalized = modelPattern.trim();
  if (!normalized) return false;
  if (normalized.toLowerCase().startsWith('re:')) return false;
  return !/[\*\?]/.test(normalized);
}

function normalizeModels(models: string[]): string[] {
  return Array.from(new Set(
    models
      .map((model) => String(model || '').trim())
      .filter(Boolean),
  ));
}

function normalizeRouteIds(routeIds: number[]): number[] {
  return Array.from(new Set(
    routeIds
      .map((routeId) => Math.trunc(routeId))
      .filter((routeId) => routeId > 0),
  ));
}

type RefreshOptions = {
  refreshPricingCatalog?: boolean;
  onProgress?: (message: string) => void;
};

export async function refreshAllRouteDecisionSnapshots(options: RefreshOptions = {}): Promise<{
  exactModelCount: number;
  wildcardRouteCount: number;
}> {
  const routes = await db.select({
    id: schema.tokenRoutes.id,
    modelPattern: schema.tokenRoutes.modelPattern,
  }).from(schema.tokenRoutes)
    .where(eq(schema.tokenRoutes.enabled, true))
    .all();

  const exactModels = normalizeModels(
    routes
      .filter((route) => isExactModelPattern(route.modelPattern))
      .map((route) => route.modelPattern),
  );
  const wildcardRouteIds = normalizeRouteIds(
    routes
      .filter((route) => !isExactModelPattern(route.modelPattern))
      .map((route) => route.id),
  );
  const refreshedKeys = options.refreshPricingCatalog ? new Set<string>() : undefined;

  options.onProgress?.(`开始刷新路由概率：精确模型 ${exactModels.length}，通配符路由 ${wildcardRouteIds.length}`);

  for (const [index, model] of exactModels.entries()) {
    options.onProgress?.(`刷新精确模型概率 ${index + 1}/${exactModels.length}：${model}`);
    const matchingRoutes = routes.filter((route) => (
      isExactModelPattern(route.modelPattern) && matchesModelPattern(model, route.modelPattern)
    ));
    const snapshotWrites: Array<{ routeId: number; snapshot: unknown }> = [];
    for (const route of matchingRoutes) {
      if (options.refreshPricingCatalog) {
        await tokenRouter.refreshPricingReferenceCostsForRoute(route.id, model, { refreshedKeys });
      }
      const decision = await tokenRouter.explainSelectionForRoute(route.id, model);
      snapshotWrites.push({
        routeId: route.id,
        snapshot: decision,
      });
    }
    if (snapshotWrites.length > 0) {
      await saveRouteDecisionSnapshots(snapshotWrites);
    }
  }

  for (const [index, routeId] of wildcardRouteIds.entries()) {
    options.onProgress?.(`刷新通配符路由概率 ${index + 1}/${wildcardRouteIds.length}：#${routeId}`);
    if (options.refreshPricingCatalog) {
      await tokenRouter.refreshRouteWidePricingReferenceCosts(routeId, { refreshedKeys });
    }

    const decision = await tokenRouter.explainSelectionRouteWide(routeId);
    await saveRouteDecisionSnapshots([
      {
        routeId,
        snapshot: decision,
      },
    ]);
  }

  return {
    exactModelCount: exactModels.length,
    wildcardRouteCount: wildcardRouteIds.length,
  };
}
