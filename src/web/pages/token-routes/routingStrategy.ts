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

export function getRouteRoutingStrategyDescription(value?: RouteRoutingStrategy | null): string {
  const strategy = normalizeRouteRoutingStrategyValue(value);
  if (strategy === 'round_robin') {
    return tr('忽略 P 值，按全局顺序依次调用；连续失败 3 次后进入分级冷却');
  }
  if (strategy === 'stable_first') {
    return tr('先避开最近失败或不健康站点，再在稳定池里按顺序轮询；P 值表示轮询顺位');
  }
  return tr('P 值是硬优先级，只会在当前最高可用优先级内结合权重、成本和健康度随机选择');
}

export function getRouteRoutingStrategyHint(value?: RouteRoutingStrategy | null): string {
  const strategy = normalizeRouteRoutingStrategyValue(value);
  if (strategy === 'round_robin') {
    return tr('当前策略不看 P 值；如果之后切回其他策略，拖拽保存的顺序仍会保留。');
  }
  if (strategy === 'stable_first') {
    return tr('当前策略下，稳定站点会按 P 顺序轮换；不稳定站点会被自动降权或临时避让。');
  }
  return tr('只要更高优先级还有可用通道，后面的通道本次就不会参与选择。');
}
