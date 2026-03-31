import { FastifyInstance, FastifyReply } from 'fastify';
import { db, schema } from '../../db/index.js';
import { and, eq } from 'drizzle-orm';
import { detectSite } from '../../services/siteDetector.js';
import { invalidateSiteProxyCache, normalizeSiteUrl, parseSiteProxyUrlInput } from '../../services/siteProxy.js';
import { formatUtcSqlDateTime } from '../../services/localTimeService.js';
import { invalidateTokenRouterCache } from '../../services/tokenRouter.js';
import { parseSiteCustomHeadersInput } from '../../services/siteCustomHeaders.js';
import { getSub2ApiSubscriptionFromExtraConfig } from '../../services/accountExtraConfig.js';
import {
  parseSiteBatchPayload,
  parseSiteCreatePayload,
  parseSiteDetectPayload,
  parseSiteDisabledModelsPayload,
  parseSiteUpdatePayload,
} from '../../contracts/siteRoutePayloads.js';
import { getSiteInitializationPreset } from '../../../shared/siteInitializationPresets.js';

function normalizeSiteStatus(input: unknown): 'active' | 'disabled' | null {
  if (input === undefined || input === null) return null;
  if (typeof input !== 'string') return null;
  const status = input.trim().toLowerCase();
  if (status === 'active' || status === 'disabled') return status;
  return null;
}

function normalizePinnedFlag(input: unknown): boolean | null {
  if (input === undefined || input === null) return null;
  if (typeof input === 'boolean') return input;
  if (typeof input === 'number') return input !== 0;
  if (typeof input === 'string') {
    const normalized = input.trim().toLowerCase();
    if (normalized === 'true' || normalized === '1') return true;
    if (normalized === 'false' || normalized === '0') return false;
  }
  return null;
}

function normalizeUseSystemProxyFlag(input: unknown): boolean | null {
  return normalizePinnedFlag(input);
}

function normalizeSortOrder(input: unknown): number | null {
  if (input === undefined || input === null || input === '') return null;
  const parsed = Number.parseInt(String(input), 10);
  if (!Number.isFinite(parsed)) return null;
  return Math.max(0, parsed);
}

function normalizeGlobalWeight(input: unknown): number | null {
  if (input === undefined || input === null || input === '') return null;
  const parsed = Number(input);
  if (!Number.isFinite(parsed) || parsed <= 0) return null;
  return Math.max(0.01, Math.min(100, Number(parsed.toFixed(3))));
}

function normalizeOptionalExternalCheckinUrl(input: unknown): {
  valid: boolean;
  present: boolean;
  url: string | null;
} {
  if (input === undefined) {
    return { valid: true, present: false, url: null };
  }
  if (input === null) {
    return { valid: true, present: true, url: null };
  }
  if (typeof input !== 'string') {
    return { valid: false, present: true, url: null };
  }
  const trimmed = input.trim();
  if (!trimmed) {
    return { valid: true, present: true, url: null };
  }
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return { valid: false, present: true, url: null };
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { valid: false, present: true, url: null };
  }
  return { valid: true, present: true, url: parsed.toString().replace(/\/+$/, '') };
}

type ErrorLike = {
  message?: string;
  code?: string | number;
  cause?: unknown;
};

function normalizeCanonicalSiteUrl(value: string): string {
  const trimmed = value.trim();
  const withScheme = trimmed.includes('://') ? trimmed : `https://${trimmed}`;
  return normalizeSiteUrl(withScheme);
}

function normalizeSitePlatform(value: string | undefined): string | null {
  if (value === undefined) return null;
  const normalized = value.trim().toLowerCase();
  return normalized || null;
}

function getErrorChain(error: unknown): ErrorLike[] {
  const chain: ErrorLike[] = [];
  const seen = new Set<unknown>();
  let current: unknown = error;
  while (current && typeof current === 'object' && !seen.has(current)) {
    seen.add(current);
    chain.push(current as ErrorLike);
    current = (current as ErrorLike).cause;
  }
  return chain;
}

function isSitesPlatformUrlConflict(error: unknown): boolean {
  return getErrorChain(error).some((entry) => {
    const message = String(entry.message || '');
    const lowered = message.toLowerCase();
    const code = String(entry.code || '');
    const isSqliteSitesUnique = (
      (code === 'SQLITE_CONSTRAINT' || code === 'SQLITE_CONSTRAINT_UNIQUE')
      && lowered.includes('unique constraint failed: sites.platform, sites.url')
    );
    return (code === '23505' && lowered.includes('sites_platform_url_unique'))
      || (code === 'ER_DUP_ENTRY' && lowered.includes('sites_platform_url_unique'))
      || isSqliteSitesUnique
      || (lowered.includes('duplicate key value violates unique constraint') && lowered.includes('sites_platform_url_unique'))
      || (lowered.includes('duplicate entry') && lowered.includes('sites_platform_url_unique'));
  });
}

function findExistingSiteBinding(
  siteRows: Array<{ id: number; url: string; platform: string }>,
  platform: string,
  normalizedUrl: string,
  excludedSiteId?: number,
) {
  return siteRows.find((site) => (
    site.platform === platform
    && site.url === normalizedUrl
    && site.id !== excludedSiteId
  ));
}

function sendSiteBindingConflict(reply: FastifyReply, platform: string, normalizedUrl: string) {
  return reply.code(409).send({
    error: `A ${platform} site with URL ${normalizedUrl} already exists.`,
  });
}

type SiteSubscriptionAggregate = {
  activeCount: number;
  totalUsedUsd: number;
  totalMonthlyLimitUsd: number | null;
  totalRemainingUsd: number | null;
  nextExpiresAt: string | null;
  planNames: string[];
  updatedAt: number | null;
};

function roundMetric(value: number): number {
  return Math.round(value * 1_000_000) / 1_000_000;
}

function pickEarlierIsoDate(current?: string | null, next?: string | null): string | null {
  if (!current) return next || null;
  if (!next) return current;
  const currentMs = Date.parse(current);
  const nextMs = Date.parse(next);
  if (!Number.isFinite(currentMs)) return next;
  if (!Number.isFinite(nextMs)) return current;
  return nextMs < currentMs ? next : current;
}

function aggregateSiteSubscription(
  current: SiteSubscriptionAggregate | undefined,
  extraConfig?: string | null,
): SiteSubscriptionAggregate | undefined {
  const stored = getSub2ApiSubscriptionFromExtraConfig(extraConfig);
  if (!stored) return current;

  const planNames = new Set(current?.planNames || []);
  let totalMonthlyLimitUsd = current?.totalMonthlyLimitUsd ?? null;
  let nextExpiresAt = current?.nextExpiresAt ?? null;

  for (const item of stored.subscriptions) {
    if (item.groupName) planNames.add(item.groupName);
    if (typeof item.monthlyLimitUsd === 'number' && Number.isFinite(item.monthlyLimitUsd)) {
      totalMonthlyLimitUsd = roundMetric((totalMonthlyLimitUsd ?? 0) + item.monthlyLimitUsd);
    }
    nextExpiresAt = pickEarlierIsoDate(nextExpiresAt, item.expiresAt);
  }

  const totalUsedUsd = roundMetric((current?.totalUsedUsd || 0) + stored.totalUsedUsd);
  const totalRemainingUsd = totalMonthlyLimitUsd == null
    ? null
    : roundMetric(Math.max(0, totalMonthlyLimitUsd - totalUsedUsd));

  return {
    activeCount: (current?.activeCount || 0) + stored.activeCount,
    totalUsedUsd,
    totalMonthlyLimitUsd,
    totalRemainingUsd,
    nextExpiresAt,
    planNames: Array.from(planNames),
    updatedAt: Math.max(current?.updatedAt || 0, stored.updatedAt || 0) || null,
  };
}

export async function sitesRoutes(app: FastifyInstance) {
  function invalidateSiteCaches() {
    invalidateSiteProxyCache();
    invalidateTokenRouterCache();
  }

  async function applySiteStatusSideEffects(
    siteId: number,
    existingSiteName: string,
    normalizedStatus: 'active' | 'disabled',
  ) {
    const now = new Date().toISOString();
    if (normalizedStatus === 'disabled') {
      await db.update(schema.accounts)
        .set({ status: 'disabled', updatedAt: now })
        .where(eq(schema.accounts.siteId, siteId))
        .run();

      try {
        const createdAt = formatUtcSqlDateTime(new Date());
        await db.insert(schema.events).values({
          type: 'status',
          title: '站点已禁用',
          message: `${existingSiteName} 已禁用，关联账号已全部置为禁用`,
          level: 'warning',
          relatedId: siteId,
          relatedType: 'site',
          createdAt,
        }).run();
      } catch { }
      return;
    }

    await db.update(schema.accounts)
      .set({ status: 'active', updatedAt: now })
      .where(and(eq(schema.accounts.siteId, siteId), eq(schema.accounts.status, 'disabled')))
      .run();

    try {
      const createdAt = formatUtcSqlDateTime(new Date());
      await db.insert(schema.events).values({
        type: 'status',
        title: '站点已启用',
        message: `${existingSiteName} 已启用，关联禁用账号已恢复为活跃`,
        level: 'info',
        relatedId: siteId,
        relatedType: 'site',
        createdAt,
      }).run();
    } catch { }
  }

  function normalizeBatchIds(input: unknown): number[] {
    if (!Array.isArray(input)) return [];
    return input
      .map((item) => Number.parseInt(String(item), 10))
      .filter((id) => Number.isFinite(id) && id > 0);
  }

  // List all sites
  app.get('/api/sites', async () => {
    const siteRows = await db.select().from(schema.sites).all();
    const accountRows = await db.select({
      siteId: schema.accounts.siteId,
      balance: schema.accounts.balance,
      extraConfig: schema.accounts.extraConfig,
    }).from(schema.accounts).all();

    const totalBalanceBySiteId: Record<number, number> = {};
    const subscriptionBySiteId: Record<number, SiteSubscriptionAggregate | undefined> = {};
    for (const row of accountRows) {
      totalBalanceBySiteId[row.siteId] = roundMetric((totalBalanceBySiteId[row.siteId] || 0) + Number(row.balance || 0));
      subscriptionBySiteId[row.siteId] = aggregateSiteSubscription(subscriptionBySiteId[row.siteId], row.extraConfig);
    }

    return siteRows.map((site) => ({
      ...site,
      totalBalance: Math.round((totalBalanceBySiteId[site.id] || 0) * 1_000_000) / 1_000_000,
      subscriptionSummary: subscriptionBySiteId[site.id] || null,
    }));
  });

  // Add a site
  app.post<{ Body: unknown }>('/api/sites', async (request, reply) => {
    const parsedBody = parseSiteCreatePayload(request.body);
    if (!parsedBody.success) {
      return reply.code(400).send({ error: parsedBody.error });
    }

    const {
      name,
      url,
      platform,
      initializationPresetId,
      proxyUrl,
      useSystemProxy,
      customHeaders,
      externalCheckinUrl,
      status,
      isPinned,
      sortOrder,
      globalWeight,
    } = parsedBody.data;
    const normalizedStatus = normalizeSiteStatus(status);
    if (status !== undefined && !normalizedStatus) {
      return reply.code(400).send({ error: 'Invalid site status. Expected active or disabled.' });
    }
    const normalizedUseSystemProxy = normalizeUseSystemProxyFlag(useSystemProxy);
    if (useSystemProxy !== undefined && normalizedUseSystemProxy === null) {
      return reply.code(400).send({ error: 'Invalid useSystemProxy value. Expected boolean.' });
    }
    const normalizedProxyUrl = parseSiteProxyUrlInput(proxyUrl);
    if (!normalizedProxyUrl.valid) {
      return reply.code(400).send({ error: 'Invalid proxyUrl. Expected a valid http(s)/socks proxy URL.' });
    }
    const normalizedExternalCheckinUrl = normalizeOptionalExternalCheckinUrl(externalCheckinUrl);
    if (!normalizedExternalCheckinUrl.valid) {
      return reply.code(400).send({ error: 'Invalid externalCheckinUrl. Expected a valid http(s) URL.' });
    }
    const normalizedPinned = normalizePinnedFlag(isPinned);
    if (isPinned !== undefined && normalizedPinned === null) {
      return reply.code(400).send({ error: 'Invalid isPinned value. Expected boolean.' });
    }
    const normalizedSortOrder = normalizeSortOrder(sortOrder);
    if (sortOrder !== undefined && normalizedSortOrder === null) {
      return reply.code(400).send({ error: 'Invalid sortOrder value. Expected non-negative integer.' });
    }
    const normalizedGlobalWeight = normalizeGlobalWeight(globalWeight);
    if (globalWeight !== undefined && normalizedGlobalWeight === null) {
      return reply.code(400).send({ error: 'Invalid globalWeight value. Expected a positive number.' });
    }
    const normalizedCustomHeaders = parseSiteCustomHeadersInput(customHeaders);
    if (!normalizedCustomHeaders.valid) {
      return reply.code(400).send({ error: normalizedCustomHeaders.error || 'Invalid customHeaders.' });
    }
    const explicitInitializationPreset = initializationPresetId == null || initializationPresetId === ''
      ? null
      : getSiteInitializationPreset(initializationPresetId);
    if (initializationPresetId != null && initializationPresetId !== '' && !explicitInitializationPreset) {
      return reply.code(400).send({ error: 'Invalid initializationPresetId.' });
    }

    const existingSites = await db.select().from(schema.sites).all();
    const maxSortOrder = existingSites.reduce((max, site) => Math.max(max, site.sortOrder || 0), -1);
    const canonicalUrl = normalizeCanonicalSiteUrl(url);
    const canonicalPlatform = normalizeSitePlatform(platform);
    let detectedPlatform = canonicalPlatform;
    let responseInitializationPresetId: string | null = explicitInitializationPreset?.id || null;
    if (!detectedPlatform) {
      if (explicitInitializationPreset) {
        detectedPlatform = explicitInitializationPreset.platform;
      } else {
        const detected = await detectSite(canonicalUrl);
        detectedPlatform = detected?.platform ?? null;
        responseInitializationPresetId = detected?.initializationPresetId || null;
      }
    }
    if (explicitInitializationPreset && explicitInitializationPreset.platform !== detectedPlatform) {
      return reply.code(400).send({ error: 'initializationPresetId does not match the selected platform.' });
    }
    if (!detectedPlatform) {
      return { error: 'Could not detect platform. Please specify manually.' };
    }
    const conflictingSite = findExistingSiteBinding(existingSites, detectedPlatform, canonicalUrl);
    if (conflictingSite) {
      return sendSiteBindingConflict(reply, detectedPlatform, canonicalUrl);
    }

    let inserted;
    try {
      inserted = await db.insert(schema.sites).values({
        name,
        url: canonicalUrl,
        platform: detectedPlatform,
        proxyUrl: normalizedProxyUrl.proxyUrl,
        useSystemProxy: normalizedUseSystemProxy ?? false,
        customHeaders: normalizedCustomHeaders.customHeaders,
        externalCheckinUrl: normalizedExternalCheckinUrl.url,
        status: normalizedStatus ?? 'active',
        isPinned: normalizedPinned ?? false,
        sortOrder: normalizedSortOrder ?? (maxSortOrder + 1),
        globalWeight: normalizedGlobalWeight ?? 1,
      }).run();
    } catch (error) {
      if (isSitesPlatformUrlConflict(error)) {
        return sendSiteBindingConflict(reply, detectedPlatform, canonicalUrl);
      }
      throw error;
    }
    const siteId = Number(inserted.lastInsertRowid || 0);
    if (siteId <= 0) {
      return reply.code(500).send({ error: 'Create site failed' });
    }
    const result = await db.select().from(schema.sites).where(eq(schema.sites.id, siteId)).get();
    if (!result) {
      return reply.code(500).send({ error: 'Create site failed' });
    }
    invalidateSiteCaches();
    return {
      ...result,
      ...(responseInitializationPresetId ? { initializationPresetId: responseInitializationPresetId } : {}),
    };
  });

  // Update a site
  app.put<{ Params: { id: string }; Body: unknown }>('/api/sites/:id', async (request, reply) => {
    const id = parseInt(request.params.id);
    if (Number.isNaN(id)) {
      return reply.code(400).send({ error: 'Invalid site id' });
    }

    const existingSite = await db.select().from(schema.sites).where(eq(schema.sites.id, id)).get();
    if (!existingSite) {
      return reply.code(404).send({ error: 'Site not found' });
    }

    const parsedBody = parseSiteUpdatePayload(request.body);
    if (!parsedBody.success) {
      return reply.code(400).send({ error: parsedBody.error });
    }

    const updates: any = {};
    const body = parsedBody.data;
    const normalizedStatus = normalizeSiteStatus(body.status);
    if (body.status !== undefined && !normalizedStatus) {
      return reply.code(400).send({ error: 'Invalid site status. Expected active or disabled.' });
    }
    const normalizedUseSystemProxy = normalizeUseSystemProxyFlag(body.useSystemProxy);
    if (body.useSystemProxy !== undefined && normalizedUseSystemProxy === null) {
      return reply.code(400).send({ error: 'Invalid useSystemProxy value. Expected boolean.' });
    }
    const normalizedProxyUrl = parseSiteProxyUrlInput(body.proxyUrl);
    if (!normalizedProxyUrl.valid) {
      return reply.code(400).send({ error: 'Invalid proxyUrl. Expected a valid http(s)/socks proxy URL.' });
    }
    const normalizedExternalCheckinUrl = normalizeOptionalExternalCheckinUrl(body.externalCheckinUrl);
    if (!normalizedExternalCheckinUrl.valid) {
      return reply.code(400).send({ error: 'Invalid externalCheckinUrl. Expected a valid http(s) URL.' });
    }
    const normalizedPinned = normalizePinnedFlag(body.isPinned);
    if (body.isPinned !== undefined && normalizedPinned === null) {
      return reply.code(400).send({ error: 'Invalid isPinned value. Expected boolean.' });
    }
    const normalizedSortOrder = normalizeSortOrder(body.sortOrder);
    if (body.sortOrder !== undefined && normalizedSortOrder === null) {
      return reply.code(400).send({ error: 'Invalid sortOrder value. Expected non-negative integer.' });
    }
    const normalizedGlobalWeight = normalizeGlobalWeight(body.globalWeight);
    if (body.globalWeight !== undefined && normalizedGlobalWeight === null) {
      return reply.code(400).send({ error: 'Invalid globalWeight value. Expected a positive number.' });
    }
    const normalizedCustomHeaders = parseSiteCustomHeadersInput(body.customHeaders);
    if (!normalizedCustomHeaders.valid) {
      return reply.code(400).send({ error: normalizedCustomHeaders.error || 'Invalid customHeaders.' });
    }

    const canonicalPlatform = normalizeSitePlatform(body.platform);
    const nextUrl = body.url !== undefined ? normalizeCanonicalSiteUrl(body.url) : existingSite.url;
    const nextPlatform = body.platform !== undefined
      ? canonicalPlatform
      : existingSite.platform;
    if (body.platform !== undefined && !nextPlatform) {
      return reply.code(400).send({ error: 'Invalid platform. Expected non-empty string.' });
    }
    const siteIdentityChanged = nextUrl !== existingSite.url || nextPlatform !== existingSite.platform;
    if (siteIdentityChanged) {
      const siteRows = await db.select({
        id: schema.sites.id,
        url: schema.sites.url,
        platform: schema.sites.platform,
      }).from(schema.sites).all();
      const conflictingSite = findExistingSiteBinding(siteRows, nextPlatform, nextUrl, id);
      if (conflictingSite) {
        return sendSiteBindingConflict(reply, nextPlatform, nextUrl);
      }
    }

    if (body.name !== undefined) updates.name = body.name;
    if (body.url !== undefined) updates.url = nextUrl;
    if (body.platform !== undefined) updates.platform = nextPlatform;
    if (normalizedProxyUrl.present) updates.proxyUrl = normalizedProxyUrl.proxyUrl;
    if (body.useSystemProxy !== undefined) updates.useSystemProxy = normalizedUseSystemProxy;
    if (normalizedCustomHeaders.present) updates.customHeaders = normalizedCustomHeaders.customHeaders;
    if (normalizedExternalCheckinUrl.present) updates.externalCheckinUrl = normalizedExternalCheckinUrl.url;
    if (body.status !== undefined) updates.status = normalizedStatus;
    if (body.isPinned !== undefined) updates.isPinned = normalizedPinned;
    if (body.sortOrder !== undefined) updates.sortOrder = normalizedSortOrder;
    if (body.globalWeight !== undefined) updates.globalWeight = normalizedGlobalWeight;
    updates.updatedAt = new Date().toISOString();
    try {
      await db.update(schema.sites).set(updates).where(eq(schema.sites.id, id)).run();
    } catch (error) {
      if (isSitesPlatformUrlConflict(error)) {
        return sendSiteBindingConflict(reply, nextPlatform, nextUrl);
      }
      throw error;
    }

    if (body.status !== undefined && normalizedStatus) {
      await applySiteStatusSideEffects(id, existingSite.name, normalizedStatus);
    }

    invalidateSiteCaches();

    return await db.select().from(schema.sites).where(eq(schema.sites.id, id)).get();
  });

  // Delete a site
  app.delete<{ Params: { id: string } }>('/api/sites/:id', async (request) => {
    const id = parseInt(request.params.id);
    await db.delete(schema.sites).where(eq(schema.sites.id, id)).run();
    invalidateSiteCaches();
    return { success: true };
  });

  app.post<{ Body: unknown }>('/api/sites/batch', async (request, reply) => {
    const parsedBody = parseSiteBatchPayload(request.body);
    if (!parsedBody.success) {
      return reply.code(400).send({ message: parsedBody.error });
    }

    const ids = normalizeBatchIds(parsedBody.data.ids);
    const action = String(parsedBody.data.action || '').trim();
    if (ids.length === 0) {
      return reply.code(400).send({ message: 'ids is required' });
    }
    if (!['enable', 'disable', 'delete', 'enableSystemProxy', 'disableSystemProxy'].includes(action)) {
      return reply.code(400).send({ message: 'Invalid action' });
    }

    const successIds: number[] = [];
    const failedItems: Array<{ id: number; message: string }> = [];

    for (const id of ids) {
      const existingSite = await db.select().from(schema.sites).where(eq(schema.sites.id, id)).get();
      if (!existingSite) {
        failedItems.push({ id, message: 'Site not found' });
        continue;
      }

      try {
        if (action === 'delete') {
          await db.delete(schema.sites).where(eq(schema.sites.id, id)).run();
        } else if (action === 'enableSystemProxy') {
          await db.update(schema.sites)
            .set({ useSystemProxy: true, updatedAt: new Date().toISOString() })
            .where(eq(schema.sites.id, id))
            .run();
        } else if (action === 'disableSystemProxy') {
          await db.update(schema.sites)
            .set({ useSystemProxy: false, updatedAt: new Date().toISOString() })
            .where(eq(schema.sites.id, id))
            .run();
        } else {
          const nextStatus = action === 'enable' ? 'active' : 'disabled';
          await db.update(schema.sites)
            .set({ status: nextStatus, updatedAt: new Date().toISOString() })
            .where(eq(schema.sites.id, id))
            .run();
          await applySiteStatusSideEffects(id, existingSite.name, nextStatus);
        }
        successIds.push(id);
      } catch (error: any) {
        failedItems.push({ id, message: error?.message || 'Batch operation failed' });
      }
    }

    invalidateSiteCaches();
    return {
      success: true,
      successIds,
      failedItems,
    };
  });

  // Get disabled models for a site
  app.get<{ Params: { id: string } }>('/api/sites/:id/disabled-models', async (request, reply) => {
    const id = parseInt(request.params.id);
    if (Number.isNaN(id)) {
      return reply.code(400).send({ error: 'Invalid site id' });
    }
    const existingSite = await db.select().from(schema.sites).where(eq(schema.sites.id, id)).get();
    if (!existingSite) {
      return reply.code(404).send({ error: 'Site not found' });
    }
    const rows = await db.select({ modelName: schema.siteDisabledModels.modelName })
      .from(schema.siteDisabledModels)
      .where(eq(schema.siteDisabledModels.siteId, id))
      .all();
    return { siteId: id, models: rows.map((r) => r.modelName) };
  });

  // Update disabled models for a site (full replace)
  app.put<{ Params: { id: string }; Body: unknown }>('/api/sites/:id/disabled-models', async (request, reply) => {
    const parsedBody = parseSiteDisabledModelsPayload(request.body);
    if (!parsedBody.success) {
      return reply.code(400).send({ error: parsedBody.error });
    }

    const id = parseInt(request.params.id);
    if (Number.isNaN(id)) {
      return reply.code(400).send({ error: 'Invalid site id' });
    }
    const existingSite = await db.select().from(schema.sites).where(eq(schema.sites.id, id)).get();
    if (!existingSite) {
      return reply.code(404).send({ error: 'Site not found' });
    }
    const rawModels = parsedBody.data.models;
    if (!Array.isArray(rawModels)) {
      return reply.code(400).send({ error: 'models must be an array of strings' });
    }
    const models = rawModels
      .filter((m): m is string => typeof m === 'string')
      .map((m) => m.trim())
      .filter((m) => m.length > 0);
    const uniqueModels = Array.from(new Set(models));

    await db.delete(schema.siteDisabledModels)
      .where(eq(schema.siteDisabledModels.siteId, id))
      .run();

    if (uniqueModels.length > 0) {
      await db.insert(schema.siteDisabledModels).values(
        uniqueModels.map((modelName) => ({ siteId: id, modelName })),
      ).run();
    }

    invalidateSiteCaches();
    return { siteId: id, models: uniqueModels };
  });

  // Get all discovered models for a site (from model_availability and token_model_availability)
  app.get<{ Params: { id: string } }>('/api/sites/:id/available-models', async (request, reply) => {
    const id = parseInt(request.params.id);
    if (Number.isNaN(id)) {
      return reply.code(400).send({ error: 'Invalid site id' });
    }
    const existingSite = await db.select().from(schema.sites).where(eq(schema.sites.id, id)).get();
    if (!existingSite) {
      return reply.code(404).send({ error: 'Site not found' });
    }

    // Get models from model_availability (account-level)
    const accountModels = await db.select({ modelName: schema.modelAvailability.modelName })
      .from(schema.modelAvailability)
      .innerJoin(schema.accounts, eq(schema.modelAvailability.accountId, schema.accounts.id))
      .where(
        and(
          eq(schema.accounts.siteId, id),
          eq(schema.modelAvailability.available, true),
        ),
      )
      .all();

    // Get models from token_model_availability (token-level)
    const tokenModels = await db.select({ modelName: schema.tokenModelAvailability.modelName })
      .from(schema.tokenModelAvailability)
      .innerJoin(schema.accountTokens, eq(schema.tokenModelAvailability.tokenId, schema.accountTokens.id))
      .innerJoin(schema.accounts, eq(schema.accountTokens.accountId, schema.accounts.id))
      .where(
        and(
          eq(schema.accounts.siteId, id),
          eq(schema.tokenModelAvailability.available, true),
        ),
      )
      .all();

    const models = Array.from(new Set([
      ...accountModels.map((r) => r.modelName.trim()),
      ...tokenModels.map((r) => r.modelName.trim()),
    ])).filter((m) => m.length > 0).sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base' }));

    return { siteId: id, models };
  });

  // Detect platform for a URL
  app.post<{ Body: unknown }>('/api/sites/detect', async (request, reply) => {
    const parsedBody = parseSiteDetectPayload(request.body);
    if (!parsedBody.success) {
      return reply.code(400).send({ error: parsedBody.error });
    }

    const result = await detectSite(parsedBody.data.url);
    return result || { error: 'Could not detect platform' };
  });
}
