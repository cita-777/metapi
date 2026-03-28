import { eq } from 'drizzle-orm';
import { db, schema } from '../db/index.js';
import { formatUtcSqlDateTime } from './localTimeService.js';

export type SaveProxyVideoTaskInput = {
  publicId?: string;
  upstreamVideoId: string;
  siteUrl: string;
  tokenValue: string;
  requestedModel: string;
  actualModel: string;
  channelId: number | null;
  accountId: number | null;
  statusSnapshot?: unknown;
  upstreamResponseMeta?: unknown;
  lastUpstreamStatus?: number | null;
  lastPolledAt?: string | null;
};

export type ProxyVideoTaskRecord = {
  publicId: string;
  upstreamVideoId: string;
  siteUrl: string;
  tokenValue: string;
  requestedModel: string | null;
  actualModel: string | null;
  channelId: number | null;
  accountId: number | null;
  statusSnapshot: unknown | null;
  upstreamResponseMeta: unknown | null;
  lastUpstreamStatus: number | null;
  lastPolledAt: string | null;
};

function buildPublicVideoId(): string {
  const timePart = Date.now().toString(36);
  const randomPart = Math.random().toString(36).slice(2, 10);
  return `vid_${timePart}_${randomPart}`;
}

export async function saveProxyVideoTask(input: SaveProxyVideoTaskInput): Promise<{
  publicId: string;
  upstreamVideoId: string;
}> {
  const publicId = input.publicId?.trim() || buildPublicVideoId();
  const now = formatUtcSqlDateTime(new Date());

  await db.insert(schema.proxyVideoTasks).values({
    publicId,
    upstreamVideoId: input.upstreamVideoId,
    siteUrl: input.siteUrl,
    tokenValue: input.tokenValue,
    requestedModel: input.requestedModel,
    actualModel: input.actualModel,
    channelId: input.channelId,
    accountId: input.accountId,
    statusSnapshot: input.statusSnapshot === undefined ? null : JSON.stringify(input.statusSnapshot),
    upstreamResponseMeta: input.upstreamResponseMeta === undefined ? null : JSON.stringify(input.upstreamResponseMeta),
    lastUpstreamStatus: input.lastUpstreamStatus ?? null,
    lastPolledAt: input.lastPolledAt ?? (input.lastUpstreamStatus == null ? null : now),
    createdAt: now,
    updatedAt: now,
  }).run();

  return {
    publicId,
    upstreamVideoId: input.upstreamVideoId,
  };
}

export async function getProxyVideoTaskByPublicId(publicId: string): Promise<ProxyVideoTaskRecord | null> {
  const row = await db.select().from(schema.proxyVideoTasks)
    .where(eq(schema.proxyVideoTasks.publicId, publicId))
    .get();
  if (!row) return null;
  return {
    publicId: row.publicId,
    upstreamVideoId: row.upstreamVideoId,
    siteUrl: row.siteUrl,
    tokenValue: row.tokenValue,
    requestedModel: row.requestedModel,
    actualModel: row.actualModel,
    channelId: row.channelId,
    accountId: row.accountId,
    statusSnapshot: parseJsonColumn(row.statusSnapshot),
    upstreamResponseMeta: parseJsonColumn(row.upstreamResponseMeta),
    lastUpstreamStatus: row.lastUpstreamStatus,
    lastPolledAt: row.lastPolledAt,
  };
}

export async function deleteProxyVideoTaskByPublicId(publicId: string): Promise<void> {
  await db.delete(schema.proxyVideoTasks)
    .where(eq(schema.proxyVideoTasks.publicId, publicId))
    .run();
}

export async function refreshProxyVideoTaskSnapshot(
  publicId: string,
  input: {
    statusSnapshot?: unknown;
    upstreamResponseMeta?: unknown;
    lastUpstreamStatus?: number | null;
    lastPolledAt?: string | null;
  },
): Promise<void> {
  const now = formatUtcSqlDateTime(new Date());
  await db.update(schema.proxyVideoTasks)
    .set({
      statusSnapshot: input.statusSnapshot === undefined ? null : JSON.stringify(input.statusSnapshot),
      upstreamResponseMeta: input.upstreamResponseMeta === undefined ? null : JSON.stringify(input.upstreamResponseMeta),
      lastUpstreamStatus: input.lastUpstreamStatus ?? null,
      lastPolledAt: input.lastPolledAt ?? now,
      updatedAt: now,
    })
    .where(eq(schema.proxyVideoTasks.publicId, publicId))
    .run();
}

function parseJsonColumn(value: unknown): unknown | null {
  if (value && typeof value === 'object') return value;
  if (typeof value !== 'string' || value.trim().length === 0) return null;
  try {
    return JSON.parse(value);
  } catch {
    return value;
  }
}

export const __proxyVideoTaskStoreTestUtils = {
  parseJsonColumn,
};
