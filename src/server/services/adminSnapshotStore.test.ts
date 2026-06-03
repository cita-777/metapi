import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

type DbModule = typeof import("../db/index.js");
type AdminSnapshotStoreModule = typeof import("./adminSnapshotStore.js");

describe("adminSnapshotStore", () => {
  let db: DbModule["db"];
  let closeDbConnections: DbModule["closeDbConnections"];
  let schema: DbModule["schema"];
  let readAdminSnapshot: AdminSnapshotStoreModule["readAdminSnapshot"];
  let writeAdminSnapshot: AdminSnapshotStoreModule["writeAdminSnapshot"];
  let deleteExpiredAdminSnapshots: AdminSnapshotStoreModule["deleteExpiredAdminSnapshots"];
  let dataDir = "";
  let previousDataDir: string | undefined;

  beforeAll(async () => {
    previousDataDir = process.env.DATA_DIR;
    dataDir = mkdtempSync(join(tmpdir(), "metapi-admin-snapshot-store-"));
    process.env.DATA_DIR = dataDir;

    await import("../db/migrate.js");
    const dbModule = await import("../db/index.js");
    const storeModule = await import("./adminSnapshotStore.js");
    db = dbModule.db;
    closeDbConnections = dbModule.closeDbConnections;
    schema = dbModule.schema;
    readAdminSnapshot = storeModule.readAdminSnapshot;
    writeAdminSnapshot = storeModule.writeAdminSnapshot;
    deleteExpiredAdminSnapshots = storeModule.deleteExpiredAdminSnapshots;
  });

  beforeEach(async () => {
    await db.delete(schema.adminSnapshots).run();
  });

  afterAll(() => {
    return (async () => {
      await closeDbConnections();
      if (previousDataDir === undefined) {
        delete process.env.DATA_DIR;
      } else {
        process.env.DATA_DIR = previousDataDir;
      }
      rmSync(dataDir, { recursive: true, force: true });
    })();
  });

  it("persists and reloads admin snapshot payloads from the runtime database", async () => {
    await writeAdminSnapshot(
      { namespace: "dashboard-summary", key: "default" },
      {
        payload: { totalBalance: 12.5, totalAccounts: 3 },
        generatedAt: "2026-04-09T00:00:00.000Z",
        expiresAt: "2026-04-09T00:00:10.000Z",
        staleUntil: "2026-04-09T00:01:00.000Z",
      },
    );

    const record = await readAdminSnapshot<{
      totalBalance: number;
      totalAccounts: number;
    }>({
      namespace: "dashboard-summary",
      key: "default",
    });

    expect(record).toEqual({
      payload: { totalBalance: 12.5, totalAccounts: 3 },
      generatedAt: "2026-04-09T00:00:00.000Z",
      expiresAt: "2026-04-09T00:00:10.000Z",
      staleUntil: "2026-04-09T00:01:00.000Z",
    });
  });

  it("prunes snapshot rows whose stale window has elapsed", async () => {
    await writeAdminSnapshot(
      { namespace: "dashboard-summary", key: "expired" },
      {
        payload: { stale: true },
        generatedAt: "2026-04-09T00:00:00.000Z",
        expiresAt: "2026-04-09T00:00:10.000Z",
        staleUntil: "2026-04-09T00:00:11.000Z",
      },
    );
    await writeAdminSnapshot(
      { namespace: "dashboard-summary", key: "fresh" },
      {
        payload: { stale: false },
        generatedAt: "2026-04-09T00:00:00.000Z",
        expiresAt: "2026-04-09T00:00:10.000Z",
        staleUntil: "2026-04-09T00:10:00.000Z",
      },
    );

    await deleteExpiredAdminSnapshots("2026-04-09T00:05:00.000Z");

    const rows = await db.select().from(schema.adminSnapshots).all();
    expect(rows).toHaveLength(1);
    expect(rows[0]?.snapshotKey).toBe(JSON.stringify("fresh"));
  });
});
