import { beforeEach, describe, expect, it, vi } from "vitest";
import { integer, sqliteTable, text } from "drizzle-orm/sqlite-core";

const adminSnapshots = sqliteTable("admin_snapshots", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  namespace: text("namespace").notNull(),
  snapshotKey: text("snapshot_key").notNull(),
  payload: text("payload").notNull(),
  generatedAt: text("generated_at").notNull(),
  expiresAt: text("expires_at").notNull(),
  staleUntil: text("stale_until").notNull(),
  createdAt: text("created_at"),
  updatedAt: text("updated_at"),
});

const schema = { adminSnapshots };

type SnapshotRow = {
  id: number;
  namespace: string;
  snapshotKey: string;
  payload: string;
  generatedAt: string;
  expiresAt: string;
  staleUntil: string;
  createdAt?: string | null;
  updatedAt?: string | null;
};

const state: {
  rows: SnapshotRow[];
  onDuplicateKeyUpdateCalls: number;
} = {
  rows: [],
  onDuplicateKeyUpdateCalls: 0,
};

function resetMockState() {
  state.rows = [];
  state.onDuplicateKeyUpdateCalls = 0;
}

function makeInsertChain() {
  let values: Omit<SnapshotRow, "id"> | null = null;
  let duplicateSet: Partial<SnapshotRow> | null = null;

  const chain = {
    values(nextValues: Omit<SnapshotRow, "id">) {
      values = nextValues;
      return chain;
    },
    onDuplicateKeyUpdate(input: { set: Partial<SnapshotRow> }) {
      state.onDuplicateKeyUpdateCalls += 1;
      duplicateSet = input.set;
      return chain;
    },
    run: vi.fn(async () => {
      if (!values) throw new Error("values() must be called before run()");

      const existingIndex = state.rows.findIndex((row) =>
        row.namespace === values!.namespace
        && row.snapshotKey === values!.snapshotKey,
      );

      if (existingIndex === -1) {
        state.rows.push({
          id: state.rows.length + 1,
          ...values,
        });
        return { changes: 1 };
      }

      state.rows[existingIndex] = {
        ...state.rows[existingIndex],
        ...(duplicateSet ?? {}),
      };
      return { changes: 1 };
    }),
  };

  return chain;
}

function makeSelectChain() {
  const chain = {
    from() {
      return chain;
    },
    where() {
      return chain;
    },
    get: vi.fn(async () => {
      const row = state.rows[0];
      return row ? { ...row } : undefined;
    }),
  };

  return chain;
}

const db = {
  insert: vi.fn(() => makeInsertChain()),
  select: vi.fn(() => makeSelectChain()),
};

vi.mock("../db/index.js", () => ({
  db,
  runtimeDbDialect: "mysql",
  schema,
}));

type AdminSnapshotStoreModule = typeof import("./adminSnapshotStore.js");

describe("adminSnapshotStore mysql conflict handling", () => {
  let storeModule: AdminSnapshotStoreModule;

  beforeEach(async () => {
    resetMockState();
    vi.resetModules();
    storeModule = await import("./adminSnapshotStore.js");
  });

  it("uses mysql duplicate-key upsert when persisting snapshot rows", async () => {
    await storeModule.writeAdminSnapshot(
      { namespace: "dashboard-summary", key: "default" },
      {
        payload: { totalBalance: 12.5, totalAccounts: 3 },
        generatedAt: "2026-04-09T00:00:00.000Z",
        expiresAt: "2026-04-09T00:00:10.000Z",
        staleUntil: "2026-04-09T00:01:00.000Z",
      },
    );

    await storeModule.writeAdminSnapshot(
      { namespace: "dashboard-summary", key: "default" },
      {
        payload: { totalBalance: 18.75, totalAccounts: 4 },
        generatedAt: "2026-04-09T00:02:00.000Z",
        expiresAt: "2026-04-09T00:02:10.000Z",
        staleUntil: "2026-04-09T00:03:00.000Z",
      },
    );

    const record = await storeModule.readAdminSnapshot<{
      totalBalance: number;
      totalAccounts: number;
    }>({
      namespace: "dashboard-summary",
      key: "default",
    });

    expect(state.onDuplicateKeyUpdateCalls).toBe(2);
    expect(state.rows).toHaveLength(1);
    expect(record).toEqual({
      payload: { totalBalance: 18.75, totalAccounts: 4 },
      generatedAt: "2026-04-09T00:02:00.000Z",
      expiresAt: "2026-04-09T00:02:10.000Z",
      staleUntil: "2026-04-09T00:03:00.000Z",
    });
  });
});
