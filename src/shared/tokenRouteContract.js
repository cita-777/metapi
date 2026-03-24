export function normalizeTokenRouteMode(routeMode) {
    return routeMode === 'explicit_group' ? 'explicit_group' : 'pattern';
}
