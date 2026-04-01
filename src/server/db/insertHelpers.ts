import { eq } from 'drizzle-orm';
import { db } from './index.js';

type InsertRunResult = {
  changes?: number;
  lastInsertRowid?: number;
} | null | undefined;

export function getInsertedRowId(result: InsertRunResult): number | null {
  const insertedId = Number(result?.lastInsertRowid || 0);
  return insertedId > 0 ? insertedId : null;
}

export function requireInsertedRowId(result: InsertRunResult, errorMessage: string): number {
  const insertedId = getInsertedRowId(result);
  if (insertedId == null) {
    throw new Error(errorMessage);
  }
  return insertedId;
}

export async function insertAndGetById<T>(input: {
  txDb?: typeof db;
  table: any;
  idColumn: any;
  values: Record<string, unknown>;
  insertErrorMessage: string;
  loadErrorMessage?: string;
}): Promise<T> {
  const txDb = input.txDb ?? db;
  const inserted = await txDb.insert(input.table).values(input.values).run();
  const insertedId = requireInsertedRowId(inserted, input.insertErrorMessage);
  const created = await txDb.select().from(input.table).where(eq(input.idColumn, insertedId)).get();
  if (!created) {
    throw new Error(input.loadErrorMessage ?? input.insertErrorMessage);
  }
  return created as T;
}
