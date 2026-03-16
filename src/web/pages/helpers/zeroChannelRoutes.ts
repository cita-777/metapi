import type { MissingTokenModelsByName } from './routeMissingTokenHints.js';
import type { RouteSummaryRow } from '../token-routes/types.js';
import { isExactModelPattern } from '../token-routes/utils.js';

function buildStableVirtualRouteId(modelName: string): number {
  const normalized = modelName.trim().toLowerCase();
  let hash = 0;
  for (let index = 0; index < normalized.length; index += 1) {
    hash = ((hash * 131) + normalized.charCodeAt(index)) % 2_147_483_647;
  }
  return -Math.max(1, hash || normalized.length || 1);
}

export function buildZeroChannelPlaceholderRoutes(
  routes: RouteSummaryRow[],
  modelsWithoutToken: MissingTokenModelsByName,
  modelsMissingTokenGroups: MissingTokenModelsByName,
): RouteSummaryRow[] {
  const exactRouteNames = new Set(
    (routes || [])
      .filter((route) => isExactModelPattern(route.modelPattern))
      .map((route) => (route.modelPattern || '').trim().toLowerCase())
      .filter(Boolean),
  );

  const placeholderByModel = new Map<string, RouteSummaryRow>();
  const mergeMissingHints = (missingByModel: MissingTokenModelsByName) => {
    for (const [rawModelName, accounts] of Object.entries(missingByModel || {})) {
      const modelName = String(rawModelName || '').trim();
      if (!modelName) continue;
      if (!isExactModelPattern(modelName)) continue;
      if (exactRouteNames.has(modelName.toLowerCase())) continue;

      const routeKey = modelName.toLowerCase();
      const existing = placeholderByModel.get(routeKey);
      const siteNames = new Set<string>(existing?.siteNames || []);
      for (const account of accounts || []) {
        const siteName = String(account?.siteName || '').trim();
        if (siteName) siteNames.add(siteName);
      }

      placeholderByModel.set(routeKey, {
        id: buildStableVirtualRouteId(modelName),
        modelPattern: modelName,
        displayName: null,
        displayIcon: null,
        modelMapping: null,
        routingStrategy: null,
        enabled: false,
        channelCount: 0,
        enabledChannelCount: 0,
        siteNames: Array.from(siteNames).sort((left, right) => left.localeCompare(right, undefined, { sensitivity: 'base' })),
        decisionSnapshot: null,
        decisionRefreshedAt: null,
        kind: 'zero_channel',
        readOnly: true,
        isVirtual: true,
      });
    }
  };

  mergeMissingHints(modelsWithoutToken);
  mergeMissingHints(modelsMissingTokenGroups);

  return Array.from(placeholderByModel.values())
    .sort((left, right) => left.modelPattern.localeCompare(right.modelPattern, undefined, { sensitivity: 'base' }));
}
