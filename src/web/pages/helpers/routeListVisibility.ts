import { normalizeTokenRouteMode } from '../../../shared/tokenRouteContract.js';

export type RouteListVisibilityItem = {
  id: number;
  modelPattern: string;
  displayName?: string | null;
  routeMode?: string | null;
  sourceRouteIds?: number[];
  enabled: boolean;
};

function normalizeRouteMode(routeMode: string | null | undefined): 'pattern' | 'explicit_group' {
  return normalizeTokenRouteMode(routeMode);
}

function isExplicitGroupRoute(route: Pick<RouteListVisibilityItem, 'routeMode'>): boolean {
  return normalizeRouteMode(route.routeMode) === 'explicit_group';
}

function hasCustomDisplayName(route: Pick<RouteListVisibilityItem, 'modelPattern' | 'displayName'>): boolean {
  const displayName = (route.displayName || '').trim();
  const modelPattern = (route.modelPattern || '').trim();
  return !!displayName && displayName !== modelPattern;
}

export function buildVisibleRouteList<T extends RouteListVisibilityItem>(
  routes: T[],
  isExactModelPattern: (pattern: string) => boolean,
  matchesModelPattern: (model: string, pattern: string) => boolean,
): T[] {
  const coveringGroups = routes.filter((route) => (
    route.enabled
    && (
      (isExplicitGroupRoute(route) && ((route.displayName || '').trim().length > 0) && (route.sourceRouteIds || []).length > 0)
      || (!isExplicitGroupRoute(route) && !isExactModelPattern(route.modelPattern) && hasCustomDisplayName(route))
    )
  ));

  if (coveringGroups.length === 0) return routes;

  return routes.filter((route) => {
    if (isExplicitGroupRoute(route)) return true;
    if (!isExactModelPattern(route.modelPattern)) return true;
    if (hasCustomDisplayName(route)) return true;

    const exactModel = (route.modelPattern || '').trim();
    if (!exactModel) return true;

    return !coveringGroups.some((groupRoute) => {
      if (groupRoute.id === route.id) return false;
      if (!((groupRoute.displayName || '').trim())) return false;
      if (isExplicitGroupRoute(groupRoute)) {
        return (groupRoute.sourceRouteIds || []).includes(route.id);
      }
      return matchesModelPattern(exactModel, groupRoute.modelPattern);
    });
  });
}
