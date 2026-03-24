import { refreshBalance } from './balanceService.js';
import {
  ensureDefaultTokenForAccount,
  syncTokensFromUpstream,
} from './accountTokenService.js';
import {
  refreshModelsForAccount,
  type ModelRefreshResult,
} from './modelService.js';
import * as routeRefreshWorkflow from './routeRefreshWorkflow.js';

type UpstreamTokenLike = {
  name?: string | null;
  key?: string | null;
  enabled?: boolean | null;
  tokenGroup?: string | null;
};

export type CoverageBatchRebuildResult =
  | { success: true; result: Awaited<ReturnType<typeof routeRefreshWorkflow.rebuildRoutesOnly>> }
  | { success: false; error: string };

export async function rebuildRoutesBestEffort(): Promise<boolean> {
  return routeRefreshWorkflow.rebuildRoutesBestEffort();
}

export async function convergeAccountMutation(input: {
  accountId: number;
  preferredApiToken?: string | null;
  defaultTokenSource?: string;
  ensurePreferredTokenBeforeSync?: boolean;
  upstreamTokens?: UpstreamTokenLike[];
  refreshBalance?: boolean;
  refreshModels?: boolean;
  rebuildRoutes?: boolean;
  continueOnError?: boolean;
}): Promise<{
  defaultTokenId: number | null;
  tokenSync: Awaited<ReturnType<typeof syncTokensFromUpstream>> | null;
  refreshedBalance: boolean;
  refreshedModels: boolean;
  rebuiltRoutes: boolean;
  balanceResult: Awaited<ReturnType<typeof refreshBalance>> | null;
  modelRefreshResult: ModelRefreshResult | null;
  rebuildResult: Awaited<ReturnType<typeof routeRefreshWorkflow.rebuildRoutesOnly>> | null;
}> {
  const result = {
    defaultTokenId: null as number | null,
    tokenSync: null as Awaited<ReturnType<typeof syncTokensFromUpstream>> | null,
    refreshedBalance: false,
    refreshedModels: false,
    rebuiltRoutes: false,
    balanceResult: null as Awaited<ReturnType<typeof refreshBalance>> | null,
    modelRefreshResult: null as ModelRefreshResult | null,
    rebuildResult: null as Awaited<ReturnType<typeof routeRefreshWorkflow.rebuildRoutesOnly>> | null,
  };

  const runStep = async <T>(fn: () => Promise<T>): Promise<T | null> => {
    if (!input.continueOnError) return fn();
    try {
      return await fn();
    } catch {
      return null;
    }
  };

  if (input.ensurePreferredTokenBeforeSync && input.preferredApiToken?.trim()) {
    const defaultTokenId = await runStep(() => ensureDefaultTokenForAccount(
      input.accountId,
      input.preferredApiToken!,
      { name: 'default', source: input.defaultTokenSource || 'manual' },
    ));
    if (defaultTokenId != null) {
      result.defaultTokenId = defaultTokenId;
    }
  }

  if ((input.upstreamTokens?.length || 0) > 0) {
    const tokenSync = await runStep(() => syncTokensFromUpstream(input.accountId, input.upstreamTokens!));
    if (tokenSync) {
      result.tokenSync = tokenSync;
      result.defaultTokenId = tokenSync.defaultTokenId ?? result.defaultTokenId;
    }
    if (!input.ensurePreferredTokenBeforeSync && input.preferredApiToken?.trim()) {
      const defaultTokenId = await runStep(() => ensureDefaultTokenForAccount(
        input.accountId,
        input.preferredApiToken!,
        { name: 'default', source: input.defaultTokenSource || 'manual' },
      ));
      if (defaultTokenId != null) {
        result.defaultTokenId = defaultTokenId;
      }
    }
  } else if (!input.ensurePreferredTokenBeforeSync && input.preferredApiToken?.trim()) {
    const defaultTokenId = await runStep(() => ensureDefaultTokenForAccount(
      input.accountId,
      input.preferredApiToken!,
      { name: 'default', source: input.defaultTokenSource || 'manual' },
    ));
    if (defaultTokenId != null) {
      result.defaultTokenId = defaultTokenId;
    }
  }

  if (input.refreshBalance) {
    const balanceResult = await runStep(() => refreshBalance(input.accountId));
    if (balanceResult) {
      result.balanceResult = balanceResult;
      result.refreshedBalance = true;
    }
  }

  if (input.refreshModels) {
    const modelRefreshResult = await runStep(() => refreshModelsForAccount(input.accountId));
    if (modelRefreshResult) {
      result.modelRefreshResult = modelRefreshResult;
      result.refreshedModels = modelRefreshResult.refreshed === true;
    }
  }

  if (input.rebuildRoutes) {
    const rebuildResult = await runStep(() => routeRefreshWorkflow.rebuildRoutesOnly());
    if (rebuildResult) {
      result.rebuildResult = rebuildResult;
      result.rebuiltRoutes = true;
    }
  }

  return result;
}

export async function refreshAccountCoverageBatch<TFailure>(input: {
  accountIds: number[];
  batchSize: number;
  mapFailure: (accountId: number, errorMessage: string) => TFailure;
}): Promise<{
  refresh: Array<ModelRefreshResult | TFailure>;
  rebuild: CoverageBatchRebuildResult | null;
}> {
  if (!Number.isInteger(input.batchSize) || input.batchSize <= 0) {
    throw new Error('batchSize must be a positive integer');
  }

  const batchSize = input.batchSize;
  const uniqueAccountIds = Array.from(new Set(
    input.accountIds.filter((id) => Number.isFinite(id) && id > 0),
  ));

  if (uniqueAccountIds.length === 0) {
    return { refresh: [], rebuild: null };
  }

  const refresh: Array<ModelRefreshResult | TFailure> = [];
  for (let offset = 0; offset < uniqueAccountIds.length; offset += batchSize) {
    const batch = uniqueAccountIds.slice(offset, offset + batchSize);
    const settled = await Promise.allSettled(
      batch.map(async (accountId) => refreshModelsForAccount(accountId)),
    );
    settled.forEach((entry, index) => {
      if (entry.status === 'fulfilled') {
        refresh.push(entry.value);
        return;
      }

      const accountId = batch[index] || 0;
      const errorMessage = entry.reason instanceof Error
        ? entry.reason.message
        : String(entry.reason || 'coverage refresh failed');
      refresh.push(input.mapFailure(accountId, errorMessage));
    });
  }

  try {
    return {
      refresh,
      rebuild: {
        success: true,
        result: await routeRefreshWorkflow.rebuildRoutesOnly(),
      },
    };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error || 'route rebuild failed');
    return {
      refresh,
      rebuild: {
        success: false,
        error: errorMessage,
      },
    };
  }
}
