import { beforeEach, describe, expect, it, vi } from 'vitest';

const ensureDefaultTokenForAccountMock = vi.fn();
const syncTokensFromUpstreamMock = vi.fn();
const refreshBalanceMock = vi.fn();
const refreshModelsForAccountMock = vi.fn();
const rebuildTokenRoutesFromAvailabilityMock = vi.fn();

vi.mock('./accountTokenService.js', () => ({
  ensureDefaultTokenForAccount: (...args: unknown[]) => ensureDefaultTokenForAccountMock(...args),
  syncTokensFromUpstream: (...args: unknown[]) => syncTokensFromUpstreamMock(...args),
}));

vi.mock('./balanceService.js', () => ({
  refreshBalance: (...args: unknown[]) => refreshBalanceMock(...args),
}));

vi.mock('./modelService.js', () => ({
  refreshModelsForAccount: (...args: unknown[]) => refreshModelsForAccountMock(...args),
  rebuildTokenRoutesFromAvailability: (...args: unknown[]) => rebuildTokenRoutesFromAvailabilityMock(...args),
}));

describe('accountMutationWorkflow', () => {
  beforeEach(() => {
    ensureDefaultTokenForAccountMock.mockReset();
    syncTokensFromUpstreamMock.mockReset();
    refreshBalanceMock.mockReset();
    refreshModelsForAccountMock.mockReset();
    rebuildTokenRoutesFromAvailabilityMock.mockReset();
  });

  it('can ensure a preferred token before syncing upstream tokens', async () => {
    ensureDefaultTokenForAccountMock.mockResolvedValue(10);
    syncTokensFromUpstreamMock.mockResolvedValue({ total: 2, created: 1, updated: 1 });
    refreshBalanceMock.mockResolvedValue({ balance: 1 });
    refreshModelsForAccountMock.mockResolvedValue({ accountId: 1, refreshed: true });
    rebuildTokenRoutesFromAvailabilityMock.mockResolvedValue({ createdRoutes: 1 });

    const { convergeAccountMutation } = await import('./accountMutationWorkflow.js');
    const upstreamTokens = [{ name: 'default', key: 'sk-upstream', enabled: true }];
    const result = await convergeAccountMutation({
      accountId: 1,
      preferredApiToken: 'sk-preferred',
      defaultTokenSource: 'manual',
      ensurePreferredTokenBeforeSync: true,
      upstreamTokens,
      refreshBalance: true,
      refreshModels: true,
      rebuildRoutes: true,
    });

    expect(ensureDefaultTokenForAccountMock).toHaveBeenCalledWith(1, 'sk-preferred', {
      name: 'default',
      source: 'manual',
    });
    expect(syncTokensFromUpstreamMock).toHaveBeenCalledWith(1, upstreamTokens);
    expect(refreshBalanceMock).toHaveBeenCalledWith(1);
    expect(refreshModelsForAccountMock).toHaveBeenCalledWith(1);
    expect(rebuildTokenRoutesFromAvailabilityMock).toHaveBeenCalledTimes(1);
    expect(ensureDefaultTokenForAccountMock.mock.invocationCallOrder[0]).toBeLessThan(
      syncTokensFromUpstreamMock.mock.invocationCallOrder[0]!,
    );
    expect(result.defaultTokenId).toBe(10);
    expect(result.tokenSync).toEqual({ total: 2, created: 1, updated: 1 });
    expect(result.refreshedBalance).toBe(true);
    expect(result.refreshedModels).toBe(true);
    expect(result.rebuiltRoutes).toBe(true);
  });

  it('falls back to ensuring the preferred token when upstream tokens are absent', async () => {
    ensureDefaultTokenForAccountMock.mockResolvedValue(22);

    const { convergeAccountMutation } = await import('./accountMutationWorkflow.js');
    const result = await convergeAccountMutation({
      accountId: 2,
      preferredApiToken: 'sk-fallback',
      defaultTokenSource: 'sync',
    });

    expect(syncTokensFromUpstreamMock).not.toHaveBeenCalled();
    expect(ensureDefaultTokenForAccountMock).toHaveBeenCalledWith(2, 'sk-fallback', {
      name: 'default',
      source: 'sync',
    });
    expect(result.defaultTokenId).toBe(22);
    expect(result.tokenSync).toBeNull();
  });

  it('continues through later refresh steps when continueOnError is enabled', async () => {
    refreshBalanceMock.mockRejectedValue(new Error('balance failed'));
    refreshModelsForAccountMock.mockResolvedValue({ accountId: 3, refreshed: true });
    rebuildTokenRoutesFromAvailabilityMock.mockResolvedValue({ createdRoutes: 0 });

    const { convergeAccountMutation } = await import('./accountMutationWorkflow.js');
    const result = await convergeAccountMutation({
      accountId: 3,
      refreshBalance: true,
      refreshModels: true,
      rebuildRoutes: true,
      continueOnError: true,
    });

    expect(result.refreshedBalance).toBe(false);
    expect(result.refreshedModels).toBe(true);
    expect(result.rebuiltRoutes).toBe(true);
    expect(refreshModelsForAccountMock).toHaveBeenCalledWith(3);
    expect(rebuildTokenRoutesFromAvailabilityMock).toHaveBeenCalledTimes(1);
  });

  it('only marks refreshedModels when the refresh result explicitly says it refreshed', async () => {
    refreshModelsForAccountMock.mockResolvedValue({ accountId: 4, refreshed: false, status: 'skipped' });

    const { convergeAccountMutation } = await import('./accountMutationWorkflow.js');
    const result = await convergeAccountMutation({
      accountId: 4,
      refreshModels: true,
    });

    expect(result.modelRefreshResult).toEqual({ accountId: 4, refreshed: false, status: 'skipped' });
    expect(result.refreshedModels).toBe(false);
  });

  it('refreshes model coverage in batches and maps failures', async () => {
    refreshModelsForAccountMock
      .mockResolvedValueOnce({ accountId: 1, refreshed: true, status: 'success' })
      .mockRejectedValueOnce(new Error('coverage failed'));
    rebuildTokenRoutesFromAvailabilityMock.mockResolvedValue({ createdRoutes: 2 });

    const { refreshAccountCoverageBatch } = await import('./accountMutationWorkflow.js');
    const result = await refreshAccountCoverageBatch({
      accountIds: [1, 2],
      batchSize: 1,
      mapFailure: (accountId, errorMessage) => ({ accountId, errorMessage }),
    });

    expect(result.refresh).toEqual([
      { accountId: 1, refreshed: true, status: 'success' },
      { accountId: 2, errorMessage: 'coverage failed' },
    ]);
    expect(result.rebuild).toEqual({
      success: true,
      result: { createdRoutes: 2 },
    });
  });

  it('rejects invalid batch sizes before starting the batch loop', async () => {
    const { refreshAccountCoverageBatch } = await import('./accountMutationWorkflow.js');

    await expect(refreshAccountCoverageBatch({
      accountIds: [1, 2],
      batchSize: 1.5,
      mapFailure: (accountId, errorMessage) => ({ accountId, errorMessage }),
    })).rejects.toThrow('batchSize must be a positive integer');

    expect(refreshModelsForAccountMock).not.toHaveBeenCalled();
  });

  it('exposes a best-effort route rebuild helper for controller callers', async () => {
    rebuildTokenRoutesFromAvailabilityMock.mockResolvedValueOnce({ createdRoutes: 1 });

    const { rebuildRoutesBestEffort } = await import('./accountMutationWorkflow.js');
    await expect(rebuildRoutesBestEffort()).resolves.toBe(true);

    rebuildTokenRoutesFromAvailabilityMock.mockRejectedValueOnce(new Error('rebuild failed'));
    await expect(rebuildRoutesBestEffort()).resolves.toBe(false);
  });
});
