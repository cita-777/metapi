import { FastifyInstance } from 'fastify';
import { eq } from 'drizzle-orm';
import { db, schema } from '../../db/index.js';
import { startBackgroundTask } from '../../services/backgroundTaskService.js';
import { formatUtcSqlDateTime, getResolvedTimeZone } from '../../services/localTimeService.js';
import { syncSiteAnnouncements } from '../../services/siteAnnouncementService.js';
import {
  loadSiteAnnouncements,
  type SiteAnnouncementListRow,
} from '../../services/siteAnnouncementStore.js';

type SiteAnnouncementRow = SiteAnnouncementListRow;
type SiteAnnouncementsResponseFilters = {
  read?: string;
  status?: string;
  timeZone?: string;
};

function formatDateTimePartsInTimeZone(value: Date, timeZone: string): string | null {
  if (Number.isNaN(value.getTime())) return null;
  const formatter = new Intl.DateTimeFormat('en-CA', {
    timeZone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });
  const parts = formatter.formatToParts(value);
  const lookup = new Map(parts.map((part) => [part.type, part.value]));
  const year = lookup.get('year');
  const month = lookup.get('month');
  const day = lookup.get('day');
  const hour = lookup.get('hour');
  const minute = lookup.get('minute');
  const second = lookup.get('second');
  if (!year || !month || !day || !hour || !minute || !second) return null;
  return `${year}-${month}-${day} ${hour}:${minute}:${second}`;
}

function normalizeManagedDateTimeValue(input: unknown, timeZone = getResolvedTimeZone()): string | null {
  if (input == null) return null;
  if (input instanceof Date) {
    return formatDateTimePartsInTimeZone(input, timeZone);
  }
  const raw = String(input).trim();
  return raw || null;
}

function parseTimeValue(input?: unknown): number | null {
  if (input instanceof Date) {
    return Number.isNaN(input.getTime()) ? null : input.getTime();
  }
  const raw = String(input || '').trim();
  if (!raw) return null;
  const parsed = Date.parse(raw.includes('T') ? raw : raw.replace(' ', 'T') + 'Z');
  return Number.isFinite(parsed) ? parsed : null;
}

function hasDateTimeValue(input: unknown): boolean {
  if (input instanceof Date) {
    return !Number.isNaN(input.getTime());
  }
  return typeof input === 'string' && input.trim().length > 0;
}

export function normalizeSiteAnnouncementRowForResponse(row: SiteAnnouncementRow, timeZone = getResolvedTimeZone()) {
  return {
    ...row,
    firstSeenAt: normalizeManagedDateTimeValue((row as { firstSeenAt?: unknown }).firstSeenAt, timeZone),
    lastSeenAt: normalizeManagedDateTimeValue((row as { lastSeenAt?: unknown }).lastSeenAt, timeZone),
    readAt: normalizeManagedDateTimeValue((row as { readAt?: unknown }).readAt, timeZone),
    dismissedAt: normalizeManagedDateTimeValue((row as { dismissedAt?: unknown }).dismissedAt, timeZone),
  };
}

function applyReadFilter(rows: SiteAnnouncementRow[], read?: string): SiteAnnouncementRow[] {
  if (read === 'true') {
    return rows.filter((row) => hasDateTimeValue((row as { readAt?: unknown }).readAt));
  }
  if (read === 'false') {
    return rows.filter((row) => !hasDateTimeValue((row as { readAt?: unknown }).readAt));
  }
  return rows;
}

function applyStatusFilter(rows: SiteAnnouncementRow[], status?: string): SiteAnnouncementRow[] {
  const normalized = String(status || '').trim().toLowerCase();
  if (!normalized) return rows;
  const now = Date.now();
  if (normalized === 'dismissed') {
    return rows.filter((row) => hasDateTimeValue((row as { dismissedAt?: unknown }).dismissedAt));
  }
  if (normalized === 'expired') {
    return rows.filter((row) => !row.dismissedAt && (() => {
      const endsAt = parseTimeValue((row as { endsAt?: unknown }).endsAt);
      return endsAt !== null && endsAt < now;
    })());
  }
  if (normalized === 'active') {
    return rows.filter((row) => !row.dismissedAt && (() => {
      const endsAt = parseTimeValue((row as { endsAt?: unknown }).endsAt);
      return endsAt === null || endsAt >= now;
    })());
  }
  return rows;
}

export function buildSiteAnnouncementsResponseRows(
  rows: SiteAnnouncementRow[],
  options?: SiteAnnouncementsResponseFilters,
) {
  const normalizedRows = rows.map((row) => normalizeSiteAnnouncementRowForResponse(row, options?.timeZone));
  return applyStatusFilter(applyReadFilter(normalizedRows, options?.read), options?.status);
}

export async function siteAnnouncementsRoutes(app: FastifyInstance) {
  app.get<{
    Querystring: {
      limit?: string;
      offset?: string;
      siteId?: string;
      platform?: string;
      read?: string;
      status?: string;
    };
  }>('/api/site-announcements', async (request) => {
    const limit = Math.max(1, Math.min(500, Number.parseInt(request.query.limit || '50', 10)));
    const offset = Math.max(0, Number.parseInt(request.query.offset || '0', 10));
    const siteId = Number.parseInt(String(request.query.siteId || ''), 10);
    const platform = String(request.query.platform || '').trim();

    const rows = await loadSiteAnnouncements({
      siteId: Number.isFinite(siteId) && siteId > 0 ? siteId : undefined,
      platform: platform || undefined,
    });

    const filtered = buildSiteAnnouncementsResponseRows(rows, {
      read: request.query.read,
      status: request.query.status,
    });
    return filtered.slice(offset, offset + limit);
  });

  app.post<{ Params: { id: string } }>('/api/site-announcements/:id/read', async (request) => {
    const id = Number.parseInt(request.params.id, 10);
    const readAt = formatUtcSqlDateTime(new Date());
    await db.update(schema.siteAnnouncements)
      .set({ readAt })
      .where(eq(schema.siteAnnouncements.id, id))
      .run();
    return { success: true };
  });

  app.post('/api/site-announcements/read-all', async () => {
    const readAt = formatUtcSqlDateTime(new Date());
    await db.update(schema.siteAnnouncements)
      .set({ readAt })
      .run();
    return { success: true };
  });

  app.delete('/api/site-announcements', async () => {
    await db.delete(schema.siteAnnouncements).run();
    return { success: true };
  });

  app.post<{ Body: { siteId?: number | string | null } }>('/api/site-announcements/sync', async (request) => {
    const parsedSiteId = Number.parseInt(String(request.body?.siteId ?? ''), 10);
    const siteId = Number.isFinite(parsedSiteId) && parsedSiteId > 0 ? parsedSiteId : null;
    const { task, reused } = startBackgroundTask(
      {
        type: 'site-announcements-sync',
        title: siteId ? `同步站点公告 #${siteId}` : '同步站点公告',
        dedupeKey: siteId ? `site-announcements:${siteId}` : 'site-announcements:all',
        notifyOnSuccess: false,
        notifyOnFailure: false,
      },
      () => syncSiteAnnouncements(siteId ? { siteId } : undefined),
    );

    return {
      success: true,
      queued: true,
      reused,
      taskId: task.id,
    };
  });
}
