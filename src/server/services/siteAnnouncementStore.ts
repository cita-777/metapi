import { and, desc, eq } from 'drizzle-orm';
import { db, schema } from '../db/index.js';

/**
 * The announcements page does not inspect the upstream payload.  Keeping this
 * projection explicit also means a damaged TOAST value in `raw_payload` does
 * not make an otherwise readable announcement list fail.
 */
export function getSiteAnnouncementListSelectFields() {
  return {
    id: schema.siteAnnouncements.id,
    siteId: schema.siteAnnouncements.siteId,
    platform: schema.siteAnnouncements.platform,
    sourceKey: schema.siteAnnouncements.sourceKey,
    title: schema.siteAnnouncements.title,
    content: schema.siteAnnouncements.content,
    level: schema.siteAnnouncements.level,
    sourceUrl: schema.siteAnnouncements.sourceUrl,
    startsAt: schema.siteAnnouncements.startsAt,
    endsAt: schema.siteAnnouncements.endsAt,
    upstreamCreatedAt: schema.siteAnnouncements.upstreamCreatedAt,
    upstreamUpdatedAt: schema.siteAnnouncements.upstreamUpdatedAt,
    firstSeenAt: schema.siteAnnouncements.firstSeenAt,
    lastSeenAt: schema.siteAnnouncements.lastSeenAt,
    readAt: schema.siteAnnouncements.readAt,
    dismissedAt: schema.siteAnnouncements.dismissedAt,
  } as const;
}

export type SiteAnnouncementListRow = Omit<
  typeof schema.siteAnnouncements.$inferSelect,
  'rawPayload'
>;

export type SiteAnnouncementListFilters = {
  siteId?: number;
  platform?: string;
};

type ToastFallbackLogger = Pick<Console, 'warn'>;

const POSTGRES_TOAST_CORRUPTION_PATTERN = /missing chunk number \d+ for toast value \d+ in pg_toast_\d+/i;

function readErrorProperty(value: unknown, property: string): unknown {
  if (!value || typeof value !== 'object') return undefined;
  try {
    return (value as Record<string, unknown>)[property];
  } catch {
    return undefined;
  }
}

/**
 * Drizzle wraps the native PostgreSQL error, so inspect a small, cycle-safe
 * cause chain.  The exact PostgreSQL TOAST diagnostic is required; a generic
 * `XX001` data-corruption error must still propagate to the caller.
 */
export function isPostgresToastCorruptionError(error: unknown): boolean {
  const messages: string[] = [];
  const codes: string[] = [];
  const queue: unknown[] = [error];
  const seen = new Set<object>();

  while (queue.length > 0) {
    const current = queue.shift();
    if (typeof current === 'string') {
      messages.push(current);
      continue;
    }
    if (!current || typeof current !== 'object') continue;

    if (seen.has(current)) continue;
    seen.add(current);

    const message = readErrorProperty(current, 'message');
    if (typeof message === 'string') messages.push(message);
    const detail = readErrorProperty(current, 'detail');
    if (typeof detail === 'string') messages.push(detail);
    const code = readErrorProperty(current, 'code');
    if (typeof code === 'string' && code.trim()) codes.push(code.trim().toUpperCase());

    for (const property of ['cause', 'originalError', 'error']) {
      const nested = readErrorProperty(current, property);
      if (nested && nested !== current) queue.push(nested);
    }
  }

  if (!messages.some((message) => POSTGRES_TOAST_CORRUPTION_PATTERN.test(message))) {
    return false;
  }

  return codes.length === 0 || codes.every((code) => code === 'XX001');
}

/**
 * Run a normal list query and, only for a PostgreSQL missing-TOAST-chunk
 * failure, retry one row at a time.  A row that still raises the same precise
 * corruption diagnostic is omitted; every other error is rethrown unchanged.
 * This generic seam keeps the recovery behavior straightforward to test
 * without requiring a live PostgreSQL instance.
 */
export async function loadRowsWithPostgresToastFallback<T extends { id: number }>(
  loadAll: () => Promise<T[]>,
  loadIds: () => Promise<number[]>,
  loadOne: (id: number) => Promise<T | undefined>,
  logger: ToastFallbackLogger = console,
): Promise<T[]> {
  try {
    return await loadAll();
  } catch (error) {
    if (!isPostgresToastCorruptionError(error)) {
      throw error;
    }
  }

  const ids = await loadIds();
  const rows: T[] = [];
  const skippedIds: number[] = [];

  for (const id of ids) {
    try {
      const row = await loadOne(id);
      if (row) rows.push(row);
    } catch (error) {
      if (!isPostgresToastCorruptionError(error)) {
        throw error;
      }
      skippedIds.push(id);
    }
  }

  if (skippedIds.length > 0) {
    logger.warn('[SiteAnnouncements] skipped rows with PostgreSQL TOAST corruption', {
      announcementIds: skippedIds,
    });
  }

  return rows;
}

function buildFilters(filters: SiteAnnouncementListFilters): any[] {
  const conditions: any[] = [];
  if (Number.isFinite(filters.siteId) && (filters.siteId || 0) > 0) {
    conditions.push(eq(schema.siteAnnouncements.siteId, filters.siteId as number));
  }
  const platform = String(filters.platform || '').trim();
  if (platform) {
    conditions.push(eq(schema.siteAnnouncements.platform, platform));
  }
  return conditions;
}

function buildListQuery(filters: SiteAnnouncementListFilters) {
  const conditions = buildFilters(filters);
  const base = db.select(getSiteAnnouncementListSelectFields()).from(schema.siteAnnouncements);
  return conditions.length > 0
    ? base.where(and(...conditions)).orderBy(desc(schema.siteAnnouncements.firstSeenAt))
    : base.orderBy(desc(schema.siteAnnouncements.firstSeenAt));
}

async function loadAnnouncementIds(filters: SiteAnnouncementListFilters): Promise<number[]> {
  const conditions = buildFilters(filters);
  const base = db.select({ id: schema.siteAnnouncements.id }).from(schema.siteAnnouncements);
  const query = conditions.length > 0
    ? base.where(and(...conditions)).orderBy(desc(schema.siteAnnouncements.firstSeenAt))
    : base.orderBy(desc(schema.siteAnnouncements.firstSeenAt));
  const rows = await query.all();
  return rows
    .map((row) => Number(row.id))
    .filter((id) => Number.isFinite(id) && id > 0);
}

async function loadAnnouncementById(id: number): Promise<SiteAnnouncementListRow | undefined> {
  const rows = await db.select(getSiteAnnouncementListSelectFields())
    .from(schema.siteAnnouncements)
    .where(eq(schema.siteAnnouncements.id, id))
    .limit(1)
    .all();
  return rows[0] as SiteAnnouncementListRow | undefined;
}

export async function loadSiteAnnouncements(
  filters: SiteAnnouncementListFilters = {},
): Promise<SiteAnnouncementListRow[]> {
  return loadRowsWithPostgresToastFallback(
    () => buildListQuery(filters).all() as Promise<SiteAnnouncementListRow[]>,
    () => loadAnnouncementIds(filters),
    (id) => loadAnnouncementById(id),
  );
}
