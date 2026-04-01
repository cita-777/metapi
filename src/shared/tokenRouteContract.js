export const ROUTE_DECISION_REFRESH_TASK_TYPE = 'route-decision.refresh';

export function normalizeTokenRouteMode(routeMode) {
    return routeMode === 'explicit_group' ? 'explicit_group' : 'pattern';
}
