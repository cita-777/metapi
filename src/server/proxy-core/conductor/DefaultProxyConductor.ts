import {
  failureActionOf,
  isTerminalFailure,
  shouldFailover,
  shouldRefreshAuth,
  shouldRetrySameChannel,
} from './retryPolicy.js';
import type { ExecuteInput, ExecuteResult, ProxyConductorDependencies, SelectedChannelLike } from './types.js';
import { recordFailedAttempt, recordSuccessfulAttempt } from './usageHooks.js';

export class DefaultProxyConductor {
  constructor(private readonly deps: ProxyConductorDependencies) {}

  async previewSelectedChannel(requestedModel: string, downstreamPolicy?: unknown): Promise<SelectedChannelLike | null> {
    if (this.deps.previewSelectedChannel) {
      return this.deps.previewSelectedChannel(requestedModel, downstreamPolicy);
    }
    return this.deps.selectChannel(requestedModel, downstreamPolicy);
  }

  async execute(input: ExecuteInput): Promise<ExecuteResult> {
    const excludeChannelIds: number[] = [];
    let attempts = 0;
    let selected = await this.deps.selectChannel(input.requestedModel, input.downstreamPolicy);
    if (!selected) {
      return {
        ok: false,
        reason: 'no_channel',
        attempts: 0,
      };
    }

    while (selected) {
      const result = await input.attempt({
        selected,
        attemptIndex: attempts,
        excludeChannelIds: [...excludeChannelIds],
      });
      attempts += 1;

      if (result.ok) {
        await recordSuccessfulAttempt(this.deps, selected.channel.id, {
          latencyMs: result.latencyMs ?? null,
          cost: result.cost ?? null,
        });
        return {
          ok: true,
          selected,
          response: result.response,
          attempts,
        };
      }

      const action = failureActionOf(result);
      await recordFailedAttempt(this.deps, selected.channel.id, {
        status: result.status,
        rawErrorText: result.rawErrorText,
      });

      if (isTerminalFailure(action)) {
        await input.onTerminalFailure?.(selected, {
          status: result.status,
          rawErrorText: result.rawErrorText,
        });
        return {
          ok: false,
          reason: 'terminal',
          selected,
          status: result.status,
          rawErrorText: result.rawErrorText,
          attempts,
        };
      }

      if (shouldRetrySameChannel(action)) {
        continue;
      }

      if (shouldRefreshAuth(action) && this.deps.refreshAuth) {
        const refreshed = await this.deps.refreshAuth(selected, {
          status: result.status,
          rawErrorText: result.rawErrorText,
        });
        if (refreshed) {
          selected = refreshed;
          continue;
        }
      }

      if (shouldFailover(action)) {
        excludeChannelIds.push(selected.channel.id);
        const next = await this.deps.selectNextChannel(
          input.requestedModel,
          excludeChannelIds,
          input.downstreamPolicy,
        );
        if (!next) {
          return {
            ok: false,
            reason: 'failed',
            selected,
            status: result.status,
            rawErrorText: result.rawErrorText,
            attempts,
          };
        }
        selected = next;
        continue;
      }

      return {
        ok: false,
        reason: 'failed',
        selected,
        status: result.status,
        rawErrorText: result.rawErrorText,
        attempts,
      };
    }

    return {
      ok: false,
      reason: 'failed',
      attempts,
    };
  }
}
