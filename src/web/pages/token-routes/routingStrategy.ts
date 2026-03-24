import { tr } from '../../i18n.js';
import type { RouteRoutingStrategy } from './types.js';

export function normalizeRouteRoutingStrategyValue(value?: RouteRoutingStrategy | null): RouteRoutingStrategy {
  if (value === 'round_robin' || value === 'stable_first') return value;
  return 'weighted';
}

export function getRouteRoutingStrategyLabel(value?: RouteRoutingStrategy | null): string {
  const strategy = normalizeRouteRoutingStrategyValue(value);
  if (strategy === 'round_robin') return tr('轮询');
  if (strategy === 'stable_first') return tr('稳定优先');
  return tr('权重随机');
}
