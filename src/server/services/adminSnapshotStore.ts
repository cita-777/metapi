import { and, eq, lt } from "drizzle-orm";
import { db, runtimeDbDialect, schema } from "../db/index.js";
import type {
  PersistedSnapshotRecord,
  SnapshotPersistenceAdapter,
} from "./snapshotCacheService.js";

type AdminSnapshotIdentity = {
  namespace: string;
  key: string;
};

type AdminSnapshotRow = typeof schema.adminSnapshots.$inferSelect;

function serializeSnapshotKey(key: string) {
  return JSON.stringify(key);
}

function buildSnapshotWhere(identity: AdminSnapshotIdentity) {
  return and(
    eq(schema.adminSnapshots.namespace, identity.namespace),
    eq(schema.adminSnapshots.snapshotKey, serializeSnapshotKey(identity.key)),
  );
}

function normalizeTimestamp(value: string, fallbackIso: string) {
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? new Date(parsed).toISOString() : fallbackIso;
}

function coercePersistedRecord<T>(
  row: AdminSnapshotRow,
): PersistedSnapshotRecord<T> | null {
  const fallbackIso = new Date().toISOString();

  try {
    return {
      payload: JSON.parse(row.payload) as T,
      generatedAt: normalizeTimestamp(row.generatedAt, fallbackIso),
      expiresAt: normalizeTimestamp(row.expiresAt, fallbackIso),
      staleUntil: normalizeTimestamp(row.staleUntil, fallbackIso),
    };
  } catch {
    return null;
  }
}

export async function readAdminSnapshot<T>(
  identity: AdminSnapshotIdentity,
): Promise<PersistedSnapshotRecord<T> | null> {
  const row = await db
    .select()
    .from(schema.adminSnapshots)
    .where(buildSnapshotWhere(identity))
    .get();

  if (!row) return null;

  const record = coercePersistedRecord<T>(row);
  if (record) return record;

  await db
    .delete(schema.adminSnapshots)
    .where(eq(schema.adminSnapshots.id, row.id))
    .run();
  return null;
}

export async function writeAdminSnapshot<T>(
  identity: AdminSnapshotIdentity,
  record: PersistedSnapshotRecord<T>,
): Promise<void> {
  const payload = JSON.stringify(record.payload);
  const values = {
    namespace: identity.namespace,
    snapshotKey: serializeSnapshotKey(identity.key),
    payload,
    generatedAt: record.generatedAt,
    expiresAt: record.expiresAt,
    staleUntil: record.staleUntil,
    updatedAt: new Date().toISOString(),
  };

  if (runtimeDbDialect === "mysql") {
    await (db
      .insert(schema.adminSnapshots)
      .values(values) as any)
      .onDuplicateKeyUpdate({
        set: {
          payload: values.payload,
          generatedAt: values.generatedAt,
          expiresAt: values.expiresAt,
          staleUntil: values.staleUntil,
          updatedAt: values.updatedAt,
        },
      })
      .run();
    return;
  }

  await (db
    .insert(schema.adminSnapshots)
    .values(values) as any)
    .onConflictDoUpdate({
      target: [
        schema.adminSnapshots.namespace,
        schema.adminSnapshots.snapshotKey,
      ],
      set: {
        payload: values.payload,
        generatedAt: values.generatedAt,
        expiresAt: values.expiresAt,
        staleUntil: values.staleUntil,
        updatedAt: values.updatedAt,
      },
    })
    .run();
}

export async function deleteExpiredAdminSnapshots(beforeIso?: string) {
  const cutoffIso = beforeIso || new Date().toISOString();
  await db
    .delete(schema.adminSnapshots)
    .where(lt(schema.adminSnapshots.staleUntil, cutoffIso))
    .run();
}

export function createAdminSnapshotPersistence<T>(
  identity: AdminSnapshotIdentity,
): SnapshotPersistenceAdapter<T> {
  return {
    read: () => readAdminSnapshot<T>(identity),
    write: (record) => writeAdminSnapshot(identity, record),
  };
}
