import { eq } from 'drizzle-orm';
import { db, schema } from '../db/index.js';
import {
  convergeAccountMutation,
  rebuildRoutesBestEffort,
} from './accountMutationWorkflow.js';

type AccountUpdateWorkflowInput = {
  accountId: number;
  updates: Partial<typeof schema.accounts.$inferInsert>;
  preferredApiToken?: string | null;
  refreshModels: boolean;
  preserveExpiredStatus?: boolean;
  allowInactiveModelRefresh?: boolean;
  reactivateAfterSuccessfulModelRefresh?: boolean;
  continueOnError?: boolean;
};

export async function applyAccountUpdateWorkflow(input: AccountUpdateWorkflowInput) {
  const isExpiredApiKeyRecoveryFlow = Boolean(
    input.preserveExpiredStatus
    && input.allowInactiveModelRefresh
    && input.reactivateAfterSuccessfulModelRefresh,
  );
  const persistedUpdates: Partial<typeof schema.accounts.$inferInsert> = {
    ...input.updates,
    ...(input.preserveExpiredStatus ? { status: 'expired' } : {}),
    updatedAt: new Date().toISOString(),
  };

  await db.update(schema.accounts)
    .set(persistedUpdates)
    .where(eq(schema.accounts.id, input.accountId))
    .run();

  const convergence = await convergeAccountMutation({
    accountId: input.accountId,
    preferredApiToken: input.preferredApiToken,
    defaultTokenSource: 'manual',
    refreshModels: input.refreshModels,
    allowInactiveModelRefresh: input.allowInactiveModelRefresh,
    rebuildRoutes: false,
    continueOnError: input.continueOnError,
  });

  if (
    input.reactivateAfterSuccessfulModelRefresh
    && convergence.modelRefreshResult?.status === 'success'
  ) {
    await db.update(schema.accounts)
      .set({
        status: 'active',
        updatedAt: new Date().toISOString(),
      })
      .where(eq(schema.accounts.id, input.accountId))
      .run();
  }

  const shouldRebuildRoutes = !isExpiredApiKeyRecoveryFlow
    || convergence.modelRefreshResult?.status === 'success';
  if (shouldRebuildRoutes) {
    await rebuildRoutesBestEffort();
  }

  const account = await db.select()
    .from(schema.accounts)
    .where(eq(schema.accounts.id, input.accountId))
    .get();

  return {
    account,
    convergence,
  };
}
