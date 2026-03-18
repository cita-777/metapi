import type { ProxyConductorDependencies } from './types.js';

export async function recordSuccessfulAttempt(
  deps: ProxyConductorDependencies,
  channelId: number,
  metrics: { latencyMs?: number | null; cost?: number | null },
): Promise<void> {
  await deps.recordSuccess?.(channelId, {
    latencyMs: metrics.latencyMs ?? null,
    cost: metrics.cost ?? null,
  });
}

export async function recordFailedAttempt(
  deps: ProxyConductorDependencies,
  channelId: number,
  failure: { status?: number; rawErrorText?: string },
): Promise<void> {
  await deps.recordFailure?.(channelId, failure);
}
