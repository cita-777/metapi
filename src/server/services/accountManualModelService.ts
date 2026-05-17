import { and, eq, inArray } from 'drizzle-orm';
import { db, schema } from '../db/index.js';
import { rebuildRoutesBestEffort } from './accountMutationWorkflow.js';

export async function removeManualModelsFromAccount(
  accountId: number,
  modelNames: string[],
): Promise<{ deletedCount: number }> {
  const normalizedModelNames = Array.from(new Set(
    modelNames.map((modelName) => String(modelName || '').trim()).filter((modelName) => modelName.length > 0),
  ));

  if (normalizedModelNames.length === 0) {
    return { deletedCount: 0 };
  }

  const deletedCount = await db.transaction(async (tx) => {
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
