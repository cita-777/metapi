import { and, eq, inArray } from 'drizzle-orm';
import { db, schema } from '../db/index.js';
import { rebuildRoutesBestEffort } from './accountMutationWorkflow.js';

export class AccountManualModelServiceError extends Error {
  readonly statusCode: number;

  constructor(message: string, statusCode: number) {
    super(message);
    this.name = 'AccountManualModelServiceError';
    this.statusCode = statusCode;
  }
}

export async function ensureManualModelAccountExists(accountId: number): Promise<void> {
  const account = await db
    .select({ id: schema.accounts.id })
    .from(schema.accounts)
    .where(eq(schema.accounts.id, accountId))
    .get();

  if (!account) {
    throw new AccountManualModelServiceError('账号不存在', 404);
  }
}

export async function removeManualModelsFromAccount(
  accountId: number,
  modelNames: string[],
): Promise<{ deletedCount: number }> {
  const normalizedModelNames = Array.from(new Set(
    modelNames.map((modelName) => String(modelName || '').trim()).filter((modelName) => modelName.length > 0),
  ));

  const deletedCount = await db.transaction(async (tx) => {
    const account = await tx
      .select({ id: schema.accounts.id })
      .from(schema.accounts)
      .where(eq(schema.accounts.id, accountId))
      .get();

    if (!account) {
      throw new AccountManualModelServiceError('账号不存在', 404);
    }

    if (normalizedModelNames.length === 0) {
      return 0;
    }

    const result = await tx
      .delete(schema.modelAvailability)
      .where(and(
        eq(schema.modelAvailability.accountId, accountId),
        eq(schema.modelAvailability.isManual, true),
        inArray(schema.modelAvailability.modelName, normalizedModelNames),
      ))
      .run();

    return result.changes ?? 0;
  });

  await rebuildRoutesBestEffort();

  return { deletedCount };
}
