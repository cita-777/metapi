import { and, asc, eq } from 'drizzle-orm';
import { db, schema } from '../db/index.js';
import { requireInsertedRowId } from '../db/insertHelpers.js';
import { getAdapter } from './platforms/index.js';
import { sendNotification } from './notifyService.js';
import { formatUtcSqlDateTime } from './localTimeService.js';
import type { SiteAnnouncement } from './platforms/base.js';

export type SiteAnnouncementSyncResult = {
  scannedSites: number;
  inserted: number;
  updated: number;
  unsupported: number;
  notifications: number;
  events: number;
  failed: number;
  failedSites: Array<{ siteId: number; siteName: string; message: string }>;
};

function toStoredPayload(rawPayload: unknown): string | null {
  if (rawPayload === undefined) return null;
  try {
    return JSON.stringify(rawPayload);
  } catch {
    return null;
  }
}

function buildAnnouncementMessage(row: SiteAnnouncement): string {
  const title = String(row.title || '').trim();
  const content = String(row.content || '').trim();
  if (title && content && title !== content && title.toLowerCase() !== 'site notice') {
    return `${title}\n${content}`;
  }
  return content || title;
}

async function resolveSiteAccessToken(siteId: number, siteApiKey?: string | null): Promise<string> {
  const direct = String(siteApiKey || '').trim();
  if (direct) return direct;

  const account = await db.select()
    .from(schema.accounts)
    .where(and(
      eq(schema.accounts.siteId, siteId),
      eq(schema.accounts.status, 'active'),
    ))
    .orderBy(asc(schema.accounts.id))
    .limit(1)
    .get();

  return String(account?.accessToken || '').trim();
}

async function listTargetSites(siteId?: number | null) {
  if (siteId && Number.isFinite(siteId) && siteId > 0) {
    return await db.select()
      .from(schema.sites)
      .where(eq(schema.sites.id, siteId))
      .all();
  }

  return await db.select()
    .from(schema.sites)
    .where(eq(schema.sites.status, 'active'))
    .all();
}

export async function syncSiteAnnouncements(options?: { siteId?: number | null }): Promise<SiteAnnouncementSyncResult> {
  const result: SiteAnnouncementSyncResult = {
    scannedSites: 0,
    inserted: 0,
    updated: 0,
    unsupported: 0,
    notifications: 0,
    events: 0,
    failed: 0,
    failedSites: [],
  };

  const sites = await listTargetSites(options?.siteId ?? null);

  for (const site of sites) {
    result.scannedSites += 1;
    const adapter = getAdapter(String(site.platform || ''));
    if (!adapter || typeof adapter.getSiteAnnouncements !== 'function') {
      result.unsupported += 1;
      continue;
    }

    try {
      const accessToken = await resolveSiteAccessToken(site.id, site.apiKey);
      const announcements = await adapter.getSiteAnnouncements(site.url, accessToken);
      const seenAt = formatUtcSqlDateTime(new Date());

      for (const announcement of announcements) {
        const existing = await db.select()
          .from(schema.siteAnnouncements)
          .where(and(
            eq(schema.siteAnnouncements.siteId, site.id),
            eq(schema.siteAnnouncements.sourceKey, announcement.sourceKey),
          ))
          .limit(1)
          .get();

        const patch = {
          platform: String(site.platform || '').trim(),
          title: announcement.title,
          content: announcement.content,
          level: announcement.level,
          sourceUrl: announcement.sourceUrl ?? null,
          startsAt: announcement.startsAt ?? null,
          endsAt: announcement.endsAt ?? null,
          upstreamCreatedAt: announcement.upstreamCreatedAt ?? null,
          upstreamUpdatedAt: announcement.upstreamUpdatedAt ?? null,
          lastSeenAt: seenAt,
          rawPayload: toStoredPayload(announcement.rawPayload),
        };

        if (existing) {
          await db.update(schema.siteAnnouncements)
            .set(patch)
            .where(eq(schema.siteAnnouncements.id, existing.id))
            .run();
          result.updated += 1;
          continue;
        }

        const inserted = await db.insert(schema.siteAnnouncements).values({
          siteId: site.id,
          sourceKey: announcement.sourceKey,
          firstSeenAt: seenAt,
          ...patch,
        }).run();
        const announcementId = requireInsertedRowId(
          inserted,
          `failed to create site announcement for site ${site.id}`,
        );
        result.inserted += 1;

        const title = `站点公告：${site.name}`;
        const message = buildAnnouncementMessage(announcement);
        await db.insert(schema.events).values({
          type: 'site_notice',
          title,
          message,
          level: announcement.level,
          relatedId: announcementId,
          relatedType: 'site_announcement',
          createdAt: seenAt,
        }).run();
        result.events += 1;

        await sendNotification(title, message, announcement.level);
        result.notifications += 1;
      }
    } catch (error) {
      result.failed += 1;
      result.failedSites.push({
        siteId: site.id,
        siteName: site.name,
        message: error instanceof Error && error.message ? error.message : 'unknown error',
      });
    }
  }

  return result;
}
