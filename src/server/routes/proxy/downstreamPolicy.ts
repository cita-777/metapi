/**
 * Compatibility facade for route-local imports. Shared implementations live
 * in the service layer so proxy-core never depends on routes/proxy.
 */
export {
  ensureModelAllowedForDownstreamKey,
  getDownstreamRoutingPolicy,
  recordDownstreamCostUsage,
} from '../../services/downstreamPolicyService.js';
