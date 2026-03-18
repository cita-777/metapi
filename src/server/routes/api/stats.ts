import { FastifyInstance } from 'fastify';
import { db, schema } from '../../db/index.js';
import { and, desc, eq, gte, lt, sql } from 'drizzle-orm';
import {
  refreshModelsForAccount,
  refreshModelsAndRebuildRoutes,
  rebuildTokenRoutesFromAvailability,
} from '../../services/modelService.js';
import { buildModelAnalysis } from '../../services/modelAnalysisService.js';
import { fallbackTokenCost, fetchModelPricingCatalog } from '../../services/modelPricingService.js';
import { getUpstreamModelDescriptionsCached } from '../../services/upstreamModelDescriptionService.js';
import { getRunningTaskByDedupeKey, startBackgroundTask } from '../../services/backgroundTaskService.js';
import { parseCheckinRewardAmount } from '../../services/checkinRewardParser.js';
import { estimateRewardWithTodayIncomeFallback } from '../../services/todayIncomeRewardService.js';
import {
  getProxyLogBaseSelectFields,
  parseProxyLogBillingDetails,
  withProxyLogSelectFields,
} from '../../services/proxyLogStore.js';
import { requiresManagedAccountTokens } from '../../services/accountExtraConfig.js';
import { ACCOUNT_TOKEN_VALUE_STATUS_READY } from '../../services/accountTokenService.js';
import {
  formatLocalDateTime,
  formatUtcSqlDateTime,
  getLocalDayRangeUtc,
  getLocalRangeStartUtc,
  parseStoredUtcDateTime,
  toLocalDayKeyFromStoredUtc,
} from '../../services/localTimeService.js';
import { createRateLimitGuard } from '../../middleware/requestRateLimit.js';

function parseBooleanFlag(raw?: string): boolean {
  if (!raw) return false;
  const normalized = raw.trim().toLowerCase();
  return normalized === '1' || normalized === 'true' || normalized === 'yes';
}

const MODELS_MARKETPLACE_BASE_TTL_MS = 15_000;
const MODELS_MARKETPLACE_PRICING_TTL_MS = 90_000;
const limitModelTokenCandidatesRead = createRateLimitGuard({
  bucket: 'models-token-candidates-read',
  max: 30,
  windowMs: 60_000,
});

type ModelsMarketplaceCacheEntry = {
  expiresAt: number;
  models: any[];
};

const modelsMarketplaceCache = new Map<'base' | 'pricing', ModelsMarketplaceCacheEntry>();

function readModelsMarketplaceCache(includePricing: boolean): any[] | null {
  const key = includePricing ? 'pricing' : 'base';
  const cached = modelsMarketplaceCache.get(key);
  if (!cached) return null;
  if (Date.now() >= cached.expiresAt) {
    modelsMarketplaceCache.delete(key);
    return null;
  }
  return cached.models;
}

function writeModelsMarketplaceCache(includePricing: boolean, models: any[]): void {
  const ttl = includePricing ? MODELS_MARKETPLACE_PRICING_TTL_MS : MODELS_MARKETPLACE_BASE_TTL_MS;
  const key = includePricing ? 'pricing' : 'base';
  modelsMarketplaceCache.set(key, {
    expiresAt: Date.now() + ttl,
    models,
  });
}

function proxyCostSqlExpression() {
  return sql<number>`
    coalesce(
      ${schema.proxyLogs.estimatedCost},
      case
        when lower(coalesce(${schema.sites.platform}, 'new-api')) = 'veloera'
          then coalesce(${schema.proxyLogs.totalTokens}, 0) / 1000000.0
        else coalesce(${schema.proxyLogs.totalTokens}, 0) / 500000.0
      end
    )
  `;
}

type ProxyLogStatusFilter = 'all' | 'success' | 'failed';

function normalizeProxyLogPageSize(raw?: string): number {
  const parsed = Number.parseInt(raw || '50', 10);
  if (!Number.isFinite(parsed)) return 50;
  return Math.max(1, Math.min(100, parsed));
}

function normalizeProxyLogOffset(raw?: string): number {
  const parsed = Number.parseInt(raw || '0', 10);
  if (!Number.isFinite(parsed)) return 0;
  return Math.max(0, parsed);
}

function normalizeProxyLogStatusFilter(raw?: string): ProxyLogStatusFilter {
  const normalized = (raw || '').trim().toLowerCase();
  if (normalized === 'success') return 'success';
  if (normalized === 'failed') return 'failed';
  return 'all';
}

function normalizeProxyLogSearch(raw?: string): string {
  return (raw || '').trim().toLowerCase();
}

function normalizeProxyLogSiteId(raw?: string): number | null {
  const parsed = Number.parseInt(raw || '', 10);
  if (!Number.isFinite(parsed) || parsed <= 0) return null;
  return parsed;
}

function normalizeProxyLogTimeBoundary(raw?: string): string | null {
  const text = (raw || '').trim();
  if (!text) return null;
  const parsed = new Date(text);
  if (Number.isNaN(parsed.getTime())) return null;
  return formatUtcSqlDateTime(parsed);
}

function parseDownstreamKeyTags(raw: unknown): string[] {
  if (typeof raw !== 'string' || !raw.trim()) return [];
  try {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    const seen = new Set<string>();
    const result: string[] = [];
    for (const value of parsed) {
      const text = String(value || '').trim();
      if (!text) continue;
      const dedupeKey = text.toLowerCase();
      if (seen.has(dedupeKey)) continue;
      seen.add(dedupeKey);
      result.push(text);
    }
    return result;
  } catch {
    return [];
  }
}

function buildProxyLogSearchCondition(search: string) {
  if (!search) return null;
  const likeTerm = `%${search}%`;
  return sql<boolean>`(
    lower(coalesce(${schema.proxyLogs.modelRequested}, '')) like ${likeTerm}
    or lower(coalesce(${schema.proxyLogs.modelActual}, '')) like ${likeTerm}
    or lower(coalesce(${schema.downstreamApiKeys.name}, '')) like ${likeTerm}
    or lower(coalesce(${schema.downstreamApiKeys.groupName}, '')) like ${likeTerm}
    or lower(coalesce(${schema.downstreamApiKeys.tags}, '')) like ${likeTerm}
  )`;
}

function buildProxyLogStatusCondition(status: ProxyLogStatusFilter) {
  if (status === 'success') {
    return eq(schema.proxyLogs.status, 'success');
  }
  if (status === 'failed') {
    return sql<boolean>`coalesce(${schema.proxyLogs.status}, '') <> 'success'`;
  }
  return null;
}

function buildProxyLogWhereClause(params: {
  status?: ProxyLogStatusFilter;
  search?: string;
  siteId?: number | null;
  fromUtc?: string | null;
  toUtc?: string | null;
}) {
  const conditions = [
    params.status ? buildProxyLogStatusCondition(params.status) : null,
    params.search ? buildProxyLogSearchCondition(params.search) : null,
    params.siteId ? eq(schema.sites.id, params.siteId) : null,
    params.fromUtc ? gte(schema.proxyLogs.createdAt, params.fromUtc) : null,
    params.toUtc ? lt(schema.proxyLogs.createdAt, params.toUtc) : null,
  ].filter((condition): condition is NonNullable<typeof condition> => condition !== null);

  if (conditions.length === 0) return undefined;
  return conditions.length === 1 ? conditions[0] : and(...conditions);
}

function toRoundedMicroNumber(value: number | null | undefined): number {
  return Math.round(Number(value || 0) * 1_000_000) / 1_000_000;
}

const SITE_AVAILABILITY_BUCKET_COUNT = 24;
const SITE_AVAILABILITY_BUCKET_MS = 60 * 60 * 1000;

type SiteAvailabilitySiteRow = {
  id: number;
  name: string;
  url: string | null;
  platform: string | null;
  sortOrder: number | null;
  isPinned: boolean | null;
};

type SiteAvailabilityLogRow = {
  siteId: number | null;
  createdAt: string | null;
  status: string | null;
  latencyMs: number | null;
};

type SiteAvailabilityBucketAccumulator = {
  startUtc: string;
  label: string;
  totalRequests: number;
  successCount: number;
  failedCount: number;
  latencyTotalMs: number;
  latencyCount: number;
};

function roundPercent(value: number | null): number | null {
  if (value == null || !Number.isFinite(value)) return null;
  return Math.round(value * 10) / 10;
}

function buildSiteAvailabilitySummaries(
  sites: SiteAvailabilitySiteRow[],
  logs: SiteAvailabilityLogRow[],
  now = new Date(),
) {
  const endLocal = new Date(now.getFullYear(), now.getMonth(), now.getDate(), now.getHours(), 0, 0, 0);
  const startLocal = new Date(endLocal.getTime() - (SITE_AVAILABILITY_BUCKET_COUNT - 1) * SITE_AVAILABILITY_BUCKET_MS);
  const startMs = startLocal.getTime();
  const rangeMs = SITE_AVAILABILITY_BUCKET_COUNT * SITE_AVAILABILITY_BUCKET_MS;

  const createBucketTemplate = (): SiteAvailabilityBucketAccumulator[] => (
    Array.from({ length: SITE_AVAILABILITY_BUCKET_COUNT }, (_, index) => {
      const bucketStart = new Date(startMs + index * SITE_AVAILABILITY_BUCKET_MS);
      return {
        startUtc: bucketStart.toISOString(),
        label: formatLocalDateTime(bucketStart),
        totalRequests: 0,
        successCount: 0,
        failedCount: 0,
        latencyTotalMs: 0,
        latencyCount: 0,
      };
    })
  );

  const siteMap = new Map<number, {
    site: SiteAvailabilitySiteRow;
    totalRequests: number;
    successCount: number;
    failedCount: number;
    latencyTotalMs: number;
    latencyCount: number;
    buckets: SiteAvailabilityBucketAccumulator[];
  }>();

  for (const site of sites) {
    siteMap.set(site.id, {
      site,
      totalRequests: 0,
      successCount: 0,
      failedCount: 0,
      latencyTotalMs: 0,
      latencyCount: 0,
      buckets: createBucketTemplate(),
    });
  }

  for (const log of logs) {
    if (log.siteId == null) continue;
    const target = siteMap.get(log.siteId);
    if (!target) continue;

    const parsed = parseStoredUtcDateTime(log.createdAt);
    if (!parsed) continue;
    const timestampMs = parsed.getTime();
    const diffMs = timestampMs - startMs;
    if (diffMs < 0 || diffMs >= rangeMs) continue;

    const bucketIndex = Math.floor(diffMs / SITE_AVAILABILITY_BUCKET_MS);
    const bucket = target.buckets[bucketIndex];
    const isSuccess = (log.status || '').trim().toLowerCase() === 'success';

    target.totalRequests += 1;
    bucket.totalRequests += 1;
    if (isSuccess) {
      target.successCount += 1;
      bucket.successCount += 1;
    } else {
      target.failedCount += 1;
      bucket.failedCount += 1;
    }

    const latencyMs = Number(log.latencyMs);
    if (Number.isFinite(latencyMs) && latencyMs >= 0) {
      target.latencyTotalMs += latencyMs;
      target.latencyCount += 1;
      bucket.latencyTotalMs += latencyMs;
      bucket.latencyCount += 1;
    }
  }

  return sites.map((site) => {
    const aggregate = siteMap.get(site.id)!;
    return {
      siteId: site.id,
      siteName: site.name,
      siteUrl: site.url,
      platform: site.platform,
      totalRequests: aggregate.totalRequests,
      successCount: aggregate.successCount,
      failedCount: aggregate.failedCount,
      availabilityPercent: aggregate.totalRequests > 0
        ? roundPercent((aggregate.successCount / aggregate.totalRequests) * 100)
        : null,
      averageLatencyMs: aggregate.latencyCount > 0
        ? Math.round(aggregate.latencyTotalMs / aggregate.latencyCount)
        : null,
      buckets: aggregate.buckets.map((bucket) => ({
        startUtc: bucket.startUtc,
        label: bucket.label,
        totalRequests: bucket.totalRequests,
        successCount: bucket.successCount,
        failedCount: bucket.failedCount,
        availabilityPercent: bucket.totalRequests > 0
          ? roundPercent((bucket.successCount / bucket.totalRequests) * 100)
          : null,
        averageLatencyMs: bucket.latencyCount > 0
          ? Math.round(bucket.latencyTotalMs / bucket.latencyCount)
          : null,
      })),
    };
  });
}

function mapProxyLogRow(
  row: {
    proxy_logs: Record<string, unknown> & { billingDetails?: string | null };
    accounts: { username?: string | null } | null;
    sites: { id?: number | null; name?: string | null; url?: string | null } | null;
    downstream_api_keys: {
      id?: number | null;
      name?: string | null;
      groupName?: string | null;
      tags?: string | null;
    } | null;
  },
  options?: { includeBillingDetails?: boolean },
) {
  return {
    ...row.proxy_logs,
    ...(options?.includeBillingDetails
      ? { billingDetails: parseProxyLogBillingDetails(row.proxy_logs.billingDetails) }
      : {}),
    username: row.accounts?.username || null,
    siteId: row.sites?.id || null,
    siteName: row.sites?.name || null,
    siteUrl: row.sites?.url || null,
    downstreamKeyId: row.downstream_api_keys?.id || null,
    downstreamKeyName: row.downstream_api_keys?.name || null,
    downstreamKeyGroupName: row.downstream_api_keys?.groupName || null,
    downstreamKeyTags: parseDownstreamKeyTags(row.downstream_api_keys?.tags),
  };
}

export async function statsRoutes(app: FastifyInstance) {
  const proxyLogBaseFields = getProxyLogBaseSelectFields();

  // Dashboard summary
  app.get('/api/stats/dashboard', async () => {
    const accountRows = await db.select().from(schema.accounts)
      .innerJoin(schema.sites, eq(schema.accounts.siteId, schema.sites.id))
      .where(eq(schema.sites.status, 'active'))
      .all();
    const accounts = accountRows.map((row) => row.accounts);
    const totalBalance = accounts.reduce((sum, a) => sum + (a.balance || 0), 0);
    const activeCount = accounts.filter((a) => a.status === 'active').length;

    const { localDay: today, startUtc: todayStartUtc, endUtc: todayEndUtc } = getLocalDayRangeUtc();
    const todayCheckinRows = await db.select().from(schema.checkinLogs)
      .innerJoin(schema.accounts, eq(schema.checkinLogs.accountId, schema.accounts.id))
      .innerJoin(schema.sites, eq(schema.accounts.siteId, schema.sites.id))
      .where(and(
        gte(schema.checkinLogs.createdAt, todayStartUtc),
        lt(schema.checkinLogs.createdAt, todayEndUtc),
        eq(schema.sites.status, 'active'),
      ))
      .all();
    const todayCheckins = todayCheckinRows.map((row) => row.checkin_logs);
    const checkinFailed = todayCheckins.filter((c) => c.status === 'failed').length;
    const checkinSuccess = todayCheckins.length - checkinFailed;
    const rewardByAccount: Record<number, number> = {};
    const successCountByAccount: Record<number, number> = {};
    const parsedRewardCountByAccount: Record<number, number> = {};
    for (const row of todayCheckinRows) {
      const checkin = row.checkin_logs;
      if (checkin.status !== 'success') continue;
      const accountId = row.accounts.id;
      successCountByAccount[accountId] = (successCountByAccount[accountId] || 0) + 1;
      const rewardValue = parseCheckinRewardAmount(checkin.reward) || parseCheckinRewardAmount(checkin.message);
      if (rewardValue <= 0) continue;
      rewardByAccount[accountId] = (rewardByAccount[accountId] || 0) + rewardValue;
      parsedRewardCountByAccount[accountId] = (parsedRewardCountByAccount[accountId] || 0) + 1;
    }

    const nowTs = Date.now();
    const last24hDate = formatUtcSqlDateTime(new Date(nowTs - 86400000));
    const lastMinuteDate = formatUtcSqlDateTime(new Date(nowTs - 60_000));
    const last7dDate = getLocalRangeStartUtc(7);
    const recentProxyLogs = (await db.select({
      proxy_logs: proxyLogBaseFields,
      accounts: schema.accounts,
      sites: schema.sites,
    }).from(schema.proxyLogs)
      .leftJoin(schema.accounts, eq(schema.proxyLogs.accountId, schema.accounts.id))
      .leftJoin(schema.sites, eq(schema.accounts.siteId, schema.sites.id))
      .where(and(gte(schema.proxyLogs.createdAt, last7dDate), eq(schema.sites.status, 'active')))
      .all())
      .map((row) => row.proxy_logs);
    const totalUsedRow = await db.select({
      totalUsed: sql<number>`coalesce(sum(${proxyCostSqlExpression()}), 0)`,
    })
      .from(schema.proxyLogs)
      .leftJoin(schema.accounts, eq(schema.proxyLogs.accountId, schema.accounts.id))
      .leftJoin(schema.sites, eq(schema.accounts.siteId, schema.sites.id))
      .where(eq(schema.sites.status, 'active'))
      .get();
    const proxy24hRow = await db.select({
      total: sql<number>`count(*)`,
      success: sql<number>`coalesce(sum(case when ${schema.proxyLogs.status} = 'success' then 1 else 0 end), 0)`,
      failed: sql<number>`coalesce(sum(case when ${schema.proxyLogs.status} = 'failed' then 1 else 0 end), 0)`,
      totalTokens: sql<number>`coalesce(sum(coalesce(${schema.proxyLogs.totalTokens}, 0)), 0)`,
    })
      .from(schema.proxyLogs)
      .leftJoin(schema.accounts, eq(schema.proxyLogs.accountId, schema.accounts.id))
      .leftJoin(schema.sites, eq(schema.accounts.siteId, schema.sites.id))
      .where(and(gte(schema.proxyLogs.createdAt, last24hDate), eq(schema.sites.status, 'active')))
      .get();
    const proxyPerformanceRow = await db.select({
      total: sql<number>`count(*)`,
      totalTokens: sql<number>`coalesce(sum(coalesce(${schema.proxyLogs.totalTokens}, 0)), 0)`,
    })
      .from(schema.proxyLogs)
      .leftJoin(schema.accounts, eq(schema.proxyLogs.accountId, schema.accounts.id))
      .leftJoin(schema.sites, eq(schema.accounts.siteId, schema.sites.id))
      .where(and(gte(schema.proxyLogs.createdAt, lastMinuteDate), eq(schema.sites.status, 'active')))
      .get();
    const todaySpendRow = await db.select({
      todaySpend: sql<number>`coalesce(sum(coalesce(${schema.proxyLogs.estimatedCost}, 0)), 0)`,
    })
      .from(schema.proxyLogs)
      .leftJoin(schema.accounts, eq(schema.proxyLogs.accountId, schema.accounts.id))
      .leftJoin(schema.sites, eq(schema.accounts.siteId, schema.sites.id))
      .where(and(
        gte(schema.proxyLogs.createdAt, todayStartUtc),
        lt(schema.proxyLogs.createdAt, todayEndUtc),
        eq(schema.sites.status, 'active'),
      ))
      .get();

    const proxySuccess = Number(proxy24hRow?.success || 0);
    const proxyFailed = Number(proxy24hRow?.failed || 0);
    const proxyTotal = Number(proxy24hRow?.total || 0);
    const totalTokens = Number(proxy24hRow?.totalTokens || 0);
    const requestsPerMinute = Number(proxyPerformanceRow?.total || 0);
    const tokensPerMinute = Number(proxyPerformanceRow?.totalTokens || 0);
    const totalUsed = Number(totalUsedRow?.totalUsed || 0);
    const todaySpend = Number(todaySpendRow?.todaySpend || 0);
    const todayReward = accounts.reduce((sum, account) => sum + estimateRewardWithTodayIncomeFallback({
      day: today,
      successCount: successCountByAccount[account.id] || 0,
      parsedRewardCount: parsedRewardCountByAccount[account.id] || 0,
      rewardSum: rewardByAccount[account.id] || 0,
      extraConfig: account.extraConfig,
    }), 0);
    const modelAnalysis = buildModelAnalysis(recentProxyLogs, { days: 7 });
    const activeSites = (await db.select({
      id: schema.sites.id,
      name: schema.sites.name,
      url: schema.sites.url,
      platform: schema.sites.platform,
      sortOrder: schema.sites.sortOrder,
      isPinned: schema.sites.isPinned,
    }).from(schema.sites)
      .where(eq(schema.sites.status, 'active'))
      .all())
      .sort((left: SiteAvailabilitySiteRow, right: SiteAvailabilitySiteRow) => {
        const leftPinned = left.isPinned ? 1 : 0;
        const rightPinned = right.isPinned ? 1 : 0;
        if (leftPinned !== rightPinned) return rightPinned - leftPinned;
        const leftOrder = Number(left.sortOrder || 0);
        const rightOrder = Number(right.sortOrder || 0);
        if (leftOrder !== rightOrder) return leftOrder - rightOrder;
        return String(left.name || '').localeCompare(String(right.name || ''));
      });
    const siteAvailabilityNow = new Date();
    const siteAvailabilitySinceUtc = formatUtcSqlDateTime(new Date(
      siteAvailabilityNow.getFullYear(),
      siteAvailabilityNow.getMonth(),
      siteAvailabilityNow.getDate(),
      siteAvailabilityNow.getHours() - (SITE_AVAILABILITY_BUCKET_COUNT - 1),
      0,
      0,
      0,
    ));
    const siteAvailabilityLogs = await db.select({
      siteId: schema.sites.id,
      createdAt: schema.proxyLogs.createdAt,
      status: schema.proxyLogs.status,
      latencyMs: schema.proxyLogs.latencyMs,
    }).from(schema.proxyLogs)
      .innerJoin(schema.accounts, eq(schema.proxyLogs.accountId, schema.accounts.id))
      .innerJoin(schema.sites, eq(schema.accounts.siteId, schema.sites.id))
      .where(and(
        gte(schema.proxyLogs.createdAt, siteAvailabilitySinceUtc),
        eq(schema.sites.status, 'active'),
      ))
      .all();
    const siteAvailability = buildSiteAvailabilitySummaries(activeSites, siteAvailabilityLogs, siteAvailabilityNow);

    return {
      totalBalance,
      totalUsed: Math.round(totalUsed * 1_000_000) / 1_000_000,
      todaySpend: Math.round(todaySpend * 1_000_000) / 1_000_000,
      todayReward: Math.round(todayReward * 1_000_000) / 1_000_000,
      activeAccounts: activeCount,
      totalAccounts: accounts.length,
      todayCheckin: { success: checkinSuccess, failed: checkinFailed, total: todayCheckins.length },
      proxy24h: { success: proxySuccess, failed: proxyFailed, total: proxyTotal, totalTokens },
      performance: {
        windowSeconds: 60,
        requestsPerMinute,
        tokensPerMinute,
      },
      siteAvailability,
      modelAnalysis,
    };
  });

  // Proxy logs
  app.get<{ Querystring: {
    limit?: string;
    offset?: string;
    status?: string;
    search?: string;
    siteId?: string;
    from?: string;
    to?: string;
  } }>('/api/stats/proxy-logs', async (request) => {
    const limit = normalizeProxyLogPageSize(request.query.limit);
    const offset = normalizeProxyLogOffset(request.query.offset);
    const status = normalizeProxyLogStatusFilter(request.query.status);
    const search = normalizeProxyLogSearch(request.query.search);
    const siteId = normalizeProxyLogSiteId(request.query.siteId);
    const fromUtc = normalizeProxyLogTimeBoundary(request.query.from);
    const toUtc = normalizeProxyLogTimeBoundary(request.query.to);
    const listWhere = buildProxyLogWhereClause({ status, search, siteId, fromUtc, toUtc });
    const summaryWhere = buildProxyLogWhereClause({ search, siteId, fromUtc, toUtc });

    const listRows = await withProxyLogSelectFields(({ fields }) => {
      let query = db.select({
        proxy_logs: fields,
        accounts: schema.accounts,
        sites: schema.sites,
        downstream_api_keys: {
          id: schema.downstreamApiKeys.id,
          name: schema.downstreamApiKeys.name,
          groupName: schema.downstreamApiKeys.groupName,
          tags: schema.downstreamApiKeys.tags,
        },
      }).from(schema.proxyLogs)
        .leftJoin(schema.accounts, eq(schema.proxyLogs.accountId, schema.accounts.id))
        .leftJoin(schema.sites, eq(schema.accounts.siteId, schema.sites.id))
        .leftJoin(schema.downstreamApiKeys, eq(schema.proxyLogs.downstreamApiKeyId, schema.downstreamApiKeys.id));

      if (listWhere) {
        query = query.where(listWhere) as typeof query;
      }

      return query
        .orderBy(desc(schema.proxyLogs.createdAt))
        .limit(limit)
        .offset(offset)
        .all();
    }, { includeBillingDetails: false }) as Array<{
      proxy_logs: Record<string, unknown> & { billingDetails?: string | null };
      accounts: { username?: string | null } | null;
      sites: { id?: number | null; name?: string | null; url?: string | null } | null;
      downstream_api_keys: { id?: number | null; name?: string | null; groupName?: string | null; tags?: string | null } | null;
    }>;

    let totalQuery = db.select({
      total: sql<number>`count(*)`,
    }).from(schema.proxyLogs)
      .leftJoin(schema.accounts, eq(schema.proxyLogs.accountId, schema.accounts.id))
      .leftJoin(schema.sites, eq(schema.accounts.siteId, schema.sites.id))
      .leftJoin(schema.downstreamApiKeys, eq(schema.proxyLogs.downstreamApiKeyId, schema.downstreamApiKeys.id));
    if (listWhere) {
      totalQuery = totalQuery.where(listWhere) as typeof totalQuery;
    }
    const totalRow = await totalQuery.get();

    let summaryQuery = db.select({
      totalCount: sql<number>`count(*)`,
      successCount: sql<number>`coalesce(sum(case when ${schema.proxyLogs.status} = 'success' then 1 else 0 end), 0)`,
      failedCount: sql<number>`coalesce(sum(case when coalesce(${schema.proxyLogs.status}, '') <> 'success' then 1 else 0 end), 0)`,
      totalCost: sql<number>`coalesce(sum(coalesce(${schema.proxyLogs.estimatedCost}, 0)), 0)`,
      totalTokensAll: sql<number>`coalesce(sum(coalesce(${schema.proxyLogs.totalTokens}, 0)), 0)`,
    }).from(schema.proxyLogs)
      .leftJoin(schema.accounts, eq(schema.proxyLogs.accountId, schema.accounts.id))
      .leftJoin(schema.sites, eq(schema.accounts.siteId, schema.sites.id))
      .leftJoin(schema.downstreamApiKeys, eq(schema.proxyLogs.downstreamApiKeyId, schema.downstreamApiKeys.id));
    if (summaryWhere) {
      summaryQuery = summaryQuery.where(summaryWhere) as typeof summaryQuery;
    }
    const summaryRow = await summaryQuery.get();

    return {
      items: listRows.map((row) => mapProxyLogRow(row)),
      total: Number(totalRow?.total || 0),
      page: Math.floor(offset / limit) + 1,
      pageSize: limit,
      summary: {
        totalCount: Number(summaryRow?.totalCount || 0),
        successCount: Number(summaryRow?.successCount || 0),
        failedCount: Number(summaryRow?.failedCount || 0),
        totalCost: toRoundedMicroNumber(summaryRow?.totalCost),
        totalTokensAll: Number(summaryRow?.totalTokensAll || 0),
      },
    };
  });

  app.get<{ Params: { id: string } }>('/api/stats/proxy-logs/:id', async (request, reply) => {
    const id = Number.parseInt(request.params.id, 10);
    if (!Number.isFinite(id) || id <= 0) {
      return reply.code(400).send({ message: 'proxy log id is invalid' });
    }

    const row = await withProxyLogSelectFields(({ fields }) => (
      db.select({
        proxy_logs: fields,
        accounts: schema.accounts,
        sites: schema.sites,
        downstream_api_keys: {
          id: schema.downstreamApiKeys.id,
          name: schema.downstreamApiKeys.name,
          groupName: schema.downstreamApiKeys.groupName,
          tags: schema.downstreamApiKeys.tags,
        },
      }).from(schema.proxyLogs)
        .leftJoin(schema.accounts, eq(schema.proxyLogs.accountId, schema.accounts.id))
        .leftJoin(schema.sites, eq(schema.accounts.siteId, schema.sites.id))
        .leftJoin(schema.downstreamApiKeys, eq(schema.proxyLogs.downstreamApiKeyId, schema.downstreamApiKeys.id))
        .where(eq(schema.proxyLogs.id, id))
        .get()
    ), { includeBillingDetails: true }) as {
      proxy_logs: Record<string, unknown> & { billingDetails?: string | null };
      accounts: { username?: string | null } | null;
      sites: { id?: number | null; name?: string | null; url?: string | null } | null;
      downstream_api_keys: { id?: number | null; name?: string | null; groupName?: string | null; tags?: string | null } | null;
    } | undefined;

    if (!row) {
      return reply.code(404).send({ message: 'proxy log not found' });
    }

    return mapProxyLogRow(row, { includeBillingDetails: true });
  });

  // Models marketplace - refresh upstream models and aggregate.
  app.get<{ Querystring: { refresh?: string; includePricing?: string } }>('/api/models/marketplace', async (request) => {
    const refreshRequested = parseBooleanFlag(request.query.refresh);
    const includePricing = parseBooleanFlag(request.query.includePricing);

    let refreshQueued = false;
    let refreshReused = false;
    let refreshJobId: string | null = null;

    if (refreshRequested) {
      modelsMarketplaceCache.clear();
      const { task, reused } = startBackgroundTask(
        {
          type: 'model',
          title: '刷新模型广场数据',
          dedupeKey: 'refresh-models-and-rebuild-routes',
          notifyOnFailure: true,
          successMessage: (currentTask) => {
            const rebuild = (currentTask.result as any)?.rebuild;
            if (!rebuild) return '模型广场刷新已完成';
            return `模型广场刷新完成：新增路由 ${rebuild.createdRoutes}，移除旧路由 ${rebuild.removedRoutes ?? 0}，新增通道 ${rebuild.createdChannels}，移除通道 ${rebuild.removedChannels}`;
          },
          failureMessage: (currentTask) => `模型广场刷新失败：${currentTask.error || 'unknown error'}`,
        },
        async () => refreshModelsAndRebuildRoutes(),
      );
      refreshQueued = !reused;
      refreshReused = reused;
      refreshJobId = task.id;
    }
    const runningRefreshTask = getRunningTaskByDedupeKey('refresh-models-and-rebuild-routes');
    if (!refreshJobId && runningRefreshTask) refreshJobId = runningRefreshTask.id;

    if (!refreshRequested) {
      const cachedModels = readModelsMarketplaceCache(includePricing);
      if (cachedModels) {
        return {
          models: cachedModels,
          meta: {
            refreshRequested,
            refreshQueued,
            refreshReused,
            refreshRunning: !!runningRefreshTask,
            refreshJobId,
            includePricing,
            cacheHit: true,
          },
        };
      }
    }

    const availability = await db.select().from(schema.tokenModelAvailability)
      .innerJoin(schema.accountTokens, eq(schema.tokenModelAvailability.tokenId, schema.accountTokens.id))
      .innerJoin(schema.accounts, eq(schema.accountTokens.accountId, schema.accounts.id))
      .innerJoin(schema.sites, eq(schema.accounts.siteId, schema.sites.id))
      .where(
        and(
          eq(schema.tokenModelAvailability.available, true),
          eq(schema.accountTokens.enabled, true),
          eq(schema.accountTokens.valueStatus, ACCOUNT_TOKEN_VALUE_STATUS_READY),
          eq(schema.accounts.status, 'active'),
          eq(schema.sites.status, 'active'),
        ),
      )
      .all();
    const accountAvailability = await db.select().from(schema.modelAvailability)
      .innerJoin(schema.accounts, eq(schema.modelAvailability.accountId, schema.accounts.id))
      .innerJoin(schema.sites, eq(schema.accounts.siteId, schema.sites.id))
      .where(
        and(
          eq(schema.modelAvailability.available, true),
          eq(schema.accounts.status, 'active'),
          eq(schema.sites.status, 'active'),
        ),
      )
      .all();

    const last7d = getLocalRangeStartUtc(7);
    const recentLogs = await db.select(proxyLogBaseFields).from(schema.proxyLogs)
      .where(gte(schema.proxyLogs.createdAt, last7d))
      .all();

    const modelLogStats: Record<string, { success: number; total: number; totalLatency: number }> = {};
    for (const log of recentLogs) {
      const model = log.modelActual || log.modelRequested || '';
      if (!modelLogStats[model]) modelLogStats[model] = { success: 0, total: 0, totalLatency: 0 };
      modelLogStats[model].total++;
      if (log.status === 'success') modelLogStats[model].success++;
      modelLogStats[model].totalLatency += log.latencyMs || 0;
    }

    type ModelMetadataAggregate = {
      description: string | null;
      tags: Set<string>;
      supportedEndpointTypes: Set<string>;
      pricingSources: Array<{
        siteId: number;
        siteName: string;
        accountId: number;
        username: string | null;
        ownerBy: string | null;
        enableGroups: string[];
        groupPricing: Record<string, {
          quotaType: number;
          inputPerMillion?: number;
          outputPerMillion?: number;
          perCallInput?: number;
          perCallOutput?: number;
          perCallTotal?: number;
        }>;
      }>;
    };

    const modelMetadataMap = new Map<string, ModelMetadataAggregate>();
    if (includePricing) {
      const activeAccountRows = await db.select().from(schema.accounts)
        .innerJoin(schema.sites, eq(schema.accounts.siteId, schema.sites.id))
        .where(and(eq(schema.accounts.status, 'active'), eq(schema.sites.status, 'active')))
        .all();

      const metadataResults = await Promise.all(activeAccountRows.map(async (row) => {
        const catalog = await fetchModelPricingCatalog({
          site: {
            id: row.sites.id,
            url: row.sites.url,
            platform: row.sites.platform,
          },
          account: {
            id: row.accounts.id,
            accessToken: row.accounts.accessToken,
            apiToken: row.accounts.apiToken,
          },
          modelName: '__metadata__',
          totalTokens: 0,
        });

        return {
          account: row.accounts,
          site: row.sites,
          catalog,
        };
      }));

      for (const result of metadataResults) {
        if (!result.catalog) continue;

        for (const model of result.catalog.models) {
          const key = model.modelName.toLowerCase();
          if (!modelMetadataMap.has(key)) {
            modelMetadataMap.set(key, {
              description: null,
              tags: new Set<string>(),
              supportedEndpointTypes: new Set<string>(),
              pricingSources: [],
            });
          }

          const aggregate = modelMetadataMap.get(key)!;
          if (!aggregate.description && model.modelDescription) {
            aggregate.description = model.modelDescription;
          }

          for (const tag of model.tags) aggregate.tags.add(tag);
          for (const endpointType of model.supportedEndpointTypes) {
            aggregate.supportedEndpointTypes.add(endpointType);
          }

          aggregate.pricingSources.push({
            siteId: result.site.id,
            siteName: result.site.name,
            accountId: result.account.id,
            username: result.account.username,
            ownerBy: model.ownerBy,
            enableGroups: model.enableGroups,
            groupPricing: model.groupPricing,
          });
        }
      }
    }

    const modelMap: Record<string, {
      name: string;
      accountsById: Map<number, {
        id: number;
        site: string;
        username: string | null;
        latency: number | null;
        unitCost: number | null;
        balance: number;
        tokens: Array<{ id: number; name: string; isDefault: boolean }>;
      }>;
    }> = {};

    for (const row of availability) {
      const m = row.token_model_availability;
      const t = row.account_tokens;
      const a = row.accounts;
      const s = row.sites;
      if (!m.available || !t.enabled || a.status !== 'active' || s.status !== 'active') continue;

      if (!modelMap[m.modelName]) {
        modelMap[m.modelName] = { name: m.modelName, accountsById: new Map() };
      }

      const existingAccount = modelMap[m.modelName].accountsById.get(a.id);
      if (!existingAccount) {
        modelMap[m.modelName].accountsById.set(a.id, {
          id: a.id,
          site: s.name,
          username: a.username,
          latency: m.latencyMs,
          unitCost: a.unitCost,
          balance: a.balance || 0,
          tokens: [{ id: t.id, name: t.name, isDefault: !!t.isDefault }],
        });
      } else {
        const nextLatency = (() => {
          if (existingAccount.latency == null) return m.latencyMs;
          if (m.latencyMs == null) return existingAccount.latency;
          return Math.min(existingAccount.latency, m.latencyMs);
        })();
        existingAccount.latency = nextLatency;
        if (!existingAccount.tokens.some((token) => token.id === t.id)) {
          existingAccount.tokens.push({ id: t.id, name: t.name, isDefault: !!t.isDefault });
        }
      }
    }

    for (const row of accountAvailability) {
      const m = row.model_availability;
      const a = row.accounts;
      const s = row.sites;
      if (!m.available || a.status !== 'active' || s.status !== 'active') continue;

      if (!modelMap[m.modelName]) {
        modelMap[m.modelName] = { name: m.modelName, accountsById: new Map() };
      }

      const existingAccount = modelMap[m.modelName].accountsById.get(a.id);
      if (!existingAccount) {
        modelMap[m.modelName].accountsById.set(a.id, {
          id: a.id,
          site: s.name,
          username: a.username,
          latency: m.latencyMs,
          unitCost: a.unitCost,
          balance: a.balance || 0,
          tokens: [],
        });
        continue;
      }

      const nextLatency = (() => {
        if (existingAccount.latency == null) return m.latencyMs;
        if (m.latencyMs == null) return existingAccount.latency;
        return Math.min(existingAccount.latency, m.latencyMs);
      })();
      existingAccount.latency = nextLatency;
    }

    let upstreamDescriptionMap = new Map<string, string>();
    if (includePricing) {
      const hasMissingDescription = Object.keys(modelMap).some((modelName) => {
        const metadata = modelMetadataMap.get(modelName.toLowerCase());
        return !metadata?.description;
      });
      if (hasMissingDescription) {
        upstreamDescriptionMap = await getUpstreamModelDescriptionsCached();
      }
    }

    const models = Object.values(modelMap).map((m) => {
      const logStats = modelLogStats[m.name];
      const accounts = Array.from(m.accountsById.values());
      const avgLatency = accounts.reduce((sum, a) => sum + (a.latency || 0), 0) / (accounts.length || 1);
      const metadata = modelMetadataMap.get(m.name.toLowerCase());
      const fallbackDescription = metadata?.description ? null : upstreamDescriptionMap.get(m.name.toLowerCase()) || null;
      return {
        name: m.name,
        accountCount: accounts.length,
        tokenCount: accounts.reduce((sum, account) => sum + account.tokens.length, 0),
        avgLatency: Math.round(avgLatency),
        successRate: logStats ? Math.round((logStats.success / logStats.total) * 1000) / 10 : null,
        description: metadata?.description || fallbackDescription,
        tags: metadata ? Array.from(metadata.tags).sort((a, b) => a.localeCompare(b)) : [],
        supportedEndpointTypes: metadata ? Array.from(metadata.supportedEndpointTypes).sort((a, b) => a.localeCompare(b)) : [],
        pricingSources: metadata?.pricingSources || [],
        accounts,
      };
    });

    models.sort((a, b) => b.accountCount - a.accountCount);
    writeModelsMarketplaceCache(includePricing, models);
    return {
      models,
      meta: {
        refreshRequested,
        refreshQueued,
        refreshReused,
        refreshRunning: !!runningRefreshTask,
        refreshJobId,
        includePricing,
      },
    };
  });

  app.get('/api/models/token-candidates', { preHandler: [limitModelTokenCandidatesRead] }, async () => {
    const resolveTokenGroupLabel = (tokenGroup: string | null, tokenName: string | null): string | null => {
      const explicit = (tokenGroup || '').trim();
      if (explicit) return explicit;

      const name = (tokenName || '').trim();
      if (!name) return null;
      const normalized = name.toLowerCase();
      if (normalized === 'default' || normalized === '默认' || /^default($|[-_\s])/.test(normalized)) {
        return 'default';
      }
      if (/^token-\d+$/.test(normalized)) return null;
      return name;
    };

    const rows = await db.select().from(schema.tokenModelAvailability)
      .innerJoin(schema.accountTokens, eq(schema.tokenModelAvailability.tokenId, schema.accountTokens.id))
      .innerJoin(schema.accounts, eq(schema.accountTokens.accountId, schema.accounts.id))
      .innerJoin(schema.sites, eq(schema.accounts.siteId, schema.sites.id))
      .where(
        and(
          eq(schema.tokenModelAvailability.available, true),
          eq(schema.accountTokens.enabled, true),
          eq(schema.accountTokens.valueStatus, ACCOUNT_TOKEN_VALUE_STATUS_READY),
          eq(schema.accounts.status, 'active'),
          eq(schema.sites.status, 'active'),
        ),
      )
      .all();
    const availableModelRows = await db.select({
      modelName: schema.modelAvailability.modelName,
      accountId: schema.accounts.id,
      username: schema.accounts.username,
      siteId: schema.sites.id,
      siteName: schema.sites.name,
      accessToken: schema.accounts.accessToken,
      apiToken: schema.accounts.apiToken,
      extraConfig: schema.accounts.extraConfig,
    })
      .from(schema.modelAvailability)
      .innerJoin(schema.accounts, eq(schema.modelAvailability.accountId, schema.accounts.id))
      .innerJoin(schema.sites, eq(schema.accounts.siteId, schema.sites.id))
      .where(
        and(
          eq(schema.modelAvailability.available, true),
          eq(schema.accounts.status, 'active'),
          eq(schema.sites.status, 'active'),
        ),
      )
      .all();

    const result: Record<string, Array<{
      accountId: number;
      tokenId: number;
      tokenName: string;
      isDefault: boolean;
      username: string | null;
      siteId: number;
      siteName: string;
    }>> = {};
    const coveredAccountModelSet = new Set<string>();
    const coveredGroupsByAccountModel = new Map<string, Map<string, string>>();
    const unknownGroupCoverageByAccountModel = new Set<string>();
    const modelsWithoutToken: Record<string, Array<{
      accountId: number;
      username: string | null;
      siteId: number;
      siteName: string;
    }>> = {};
    const modelsMissingTokenGroups: Record<string, Array<{
      accountId: number;
      username: string | null;
      siteId: number;
      siteName: string;
      missingGroups: string[];
      requiredGroups: string[];
      availableGroups: string[];
      groupCoverageUncertain?: boolean;
    }>> = {};
    let hasAnyTokenGroupSignals = false;

    for (const row of rows) {
      const modelName = (row.token_model_availability.modelName || '').trim();
      if (!modelName) continue;
      const accountModelKey = `${row.accounts.id}::${modelName.toLowerCase()}`;
      coveredAccountModelSet.add(accountModelKey);

      const resolvedTokenGroup = resolveTokenGroupLabel(row.account_tokens.tokenGroup, row.account_tokens.name);
      if (resolvedTokenGroup) {
        hasAnyTokenGroupSignals = true;
        if (!coveredGroupsByAccountModel.has(accountModelKey)) {
          coveredGroupsByAccountModel.set(accountModelKey, new Map<string, string>());
        }
        const groupKey = resolvedTokenGroup.toLowerCase();
        if (!coveredGroupsByAccountModel.get(accountModelKey)!.has(groupKey)) {
          coveredGroupsByAccountModel.get(accountModelKey)!.set(groupKey, resolvedTokenGroup);
        }
      } else {
        unknownGroupCoverageByAccountModel.add(accountModelKey);
      }

      if (!result[modelName]) result[modelName] = [];
      if (result[modelName].some((item) => item.tokenId === row.account_tokens.id)) continue;
      result[modelName].push({
        accountId: row.accounts.id,
        tokenId: row.account_tokens.id,
        tokenName: row.account_tokens.name,
        isDefault: !!row.account_tokens.isDefault,
        username: row.accounts.username,
        siteId: row.sites.id,
        siteName: row.sites.name,
      });
    }

    for (const row of availableModelRows) {
      if (!requiresManagedAccountTokens(row)) continue;
      const modelName = (row.modelName || '').trim();
      if (!modelName) continue;
      const coverageKey = `${row.accountId}::${modelName.toLowerCase()}`;
      if (coveredAccountModelSet.has(coverageKey)) continue;
      if (!modelsWithoutToken[modelName]) modelsWithoutToken[modelName] = [];
      if (modelsWithoutToken[modelName].some((item) => item.accountId === row.accountId)) continue;
      modelsWithoutToken[modelName].push({
        accountId: row.accountId,
        username: row.username,
        siteId: row.siteId,
        siteName: row.siteName,
      });
    }

    const accountIdsForGroupHints = new Set(
      availableModelRows
        .filter((row) => requiresManagedAccountTokens(row))
        .map((row) => row.accountId),
    );
    const requiredGroupsByAccountModel = new Map<string, Map<string, string>>();
    const hasPotentialGroupHints = hasAnyTokenGroupSignals || unknownGroupCoverageByAccountModel.size > 0;

    if (hasPotentialGroupHints && accountIdsForGroupHints.size > 0) {
      const accountRows = await db.select().from(schema.accounts)
        .innerJoin(schema.sites, eq(schema.accounts.siteId, schema.sites.id))
        .where(
          and(
            eq(schema.accounts.status, 'active'),
            eq(schema.sites.status, 'active'),
          ),
        )
        .all();

      const metadataResults = await Promise.all(
        accountRows
          .filter((row) => accountIdsForGroupHints.has(row.accounts.id))
          .map(async (row) => {
            try {
              const catalog = await fetchModelPricingCatalog({
                site: {
                  id: row.sites.id,
                  url: row.sites.url,
                  platform: row.sites.platform,
                },
                account: {
                  id: row.accounts.id,
                  accessToken: row.accounts.accessToken,
                  apiToken: row.accounts.apiToken,
                },
                modelName: '__metadata__',
                totalTokens: 0,
              });
              return { accountId: row.accounts.id, catalog };
            } catch {
              return { accountId: row.accounts.id, catalog: null as Awaited<ReturnType<typeof fetchModelPricingCatalog>> };
            }
          }),
      );

      for (const result of metadataResults) {
        if (!result.catalog) continue;
        for (const model of result.catalog.models) {
          const modelName = (model.modelName || '').trim();
          if (!modelName) continue;
          const groups = new Map<string, string>();
          for (const rawGroup of model.enableGroups || []) {
            const group = String(rawGroup || '').trim();
            if (!group) continue;
            const groupKey = group.toLowerCase();
            if (!groups.has(groupKey)) groups.set(groupKey, group);
          }
          if (groups.size === 0) continue;
          requiredGroupsByAccountModel.set(`${result.accountId}::${modelName.toLowerCase()}`, groups);
        }
      }
    }

    for (const row of availableModelRows) {
      if (!requiresManagedAccountTokens(row)) continue;
      const modelName = (row.modelName || '').trim();
      if (!modelName) continue;
      const accountModelKey = `${row.accountId}::${modelName.toLowerCase()}`;

      const requiredGroups = requiredGroupsByAccountModel.get(accountModelKey);
      if (!requiredGroups || requiredGroups.size === 0) continue;

      const availableGroups = coveredGroupsByAccountModel.get(accountModelKey) || new Map<string, string>();
      const missingGroups = Array.from(requiredGroups.entries())
        .filter(([groupKey]) => !availableGroups.has(groupKey))
        .map(([, label]) => label);
      if (missingGroups.length === 0) continue;

      if (!modelsMissingTokenGroups[modelName]) modelsMissingTokenGroups[modelName] = [];
      if (modelsMissingTokenGroups[modelName].some((item) => item.accountId === row.accountId)) continue;
      const hintRow = {
        accountId: row.accountId,
        username: row.username,
        siteId: row.siteId,
        siteName: row.siteName,
        missingGroups: missingGroups.sort((a, b) => a.localeCompare(b)),
        requiredGroups: Array.from(requiredGroups.values()).sort((a, b) => a.localeCompare(b)),
        availableGroups: Array.from(availableGroups.values()).sort((a, b) => a.localeCompare(b)),
      } as {
        accountId: number;
        username: string | null;
        siteId: number;
        siteName: string;
        missingGroups: string[];
        requiredGroups: string[];
        availableGroups: string[];
        groupCoverageUncertain?: boolean;
      };
      if (unknownGroupCoverageByAccountModel.has(accountModelKey)) {
        hintRow.groupCoverageUncertain = true;
      }
      modelsMissingTokenGroups[modelName].push(hintRow);
    }

    const endpointTypesByModel: Record<string, string[]> = {};
    const cachedPricing = readModelsMarketplaceCache(true);
    const cachedBase = cachedPricing || readModelsMarketplaceCache(false);
    if (cachedBase) {
      for (const model of cachedBase) {
        if (Array.isArray(model.supportedEndpointTypes) && model.supportedEndpointTypes.length > 0) {
          endpointTypesByModel[model.name] = model.supportedEndpointTypes;
        }
      }
    }

    return {
      models: result,
      modelsWithoutToken,
      modelsMissingTokenGroups,
      endpointTypesByModel,
    };
  });

  // Refresh models for one account and rebuild routes.
  app.post<{ Params: { accountId: string } }>('/api/models/check/:accountId', async (request) => {
    const accountId = Number.parseInt(request.params.accountId, 10);
    if (Number.isNaN(accountId)) {
      return { success: false, error: 'Invalid account id' };
    }

    const refresh = await refreshModelsForAccount(accountId);
    const rebuild = rebuildTokenRoutesFromAvailability();
    return { success: true, refresh, rebuild };
  });

  // Site distribution – per-site aggregate data
  app.get('/api/stats/site-distribution', async () => {
    const accountRows = await db.select({
      siteId: schema.sites.id,
      siteName: schema.sites.name,
      platform: schema.sites.platform,
      totalBalance: sql<number>`coalesce(sum(coalesce(${schema.accounts.balance}, 0)), 0)`,
      accountCount: sql<number>`count(*)`,
    })
      .from(schema.accounts)
      .innerJoin(schema.sites, eq(schema.accounts.siteId, schema.sites.id))
      .where(eq(schema.sites.status, 'active'))
      .groupBy(schema.sites.id, schema.sites.name, schema.sites.platform)
      .all();

    const spendRows = await db.select({
      siteId: schema.sites.id,
      totalSpend: sql<number>`coalesce(sum(${proxyCostSqlExpression()}), 0)`,
    })
      .from(schema.proxyLogs)
      .leftJoin(schema.accounts, eq(schema.proxyLogs.accountId, schema.accounts.id))
      .leftJoin(schema.sites, eq(schema.accounts.siteId, schema.sites.id))
      .where(eq(schema.sites.status, 'active'))
      .groupBy(schema.sites.id)
      .all();

    const spendBySiteId = new Map<number, number>();
    for (const row of spendRows) {
      if (row.siteId == null) continue;
      spendBySiteId.set(row.siteId, Number(row.totalSpend || 0));
    }

    const distribution = accountRows.map((row) => ({
      siteId: row.siteId,
      siteName: row.siteName,
      platform: row.platform,
      totalBalance: Math.round(Number(row.totalBalance || 0) * 1_000_000) / 1_000_000,
      totalSpend: Math.round((spendBySiteId.get(row.siteId) || 0) * 1_000_000) / 1_000_000,
      accountCount: Number(row.accountCount || 0),
    }));

    return { distribution };
  });

  // Site trend – daily spend/calls broken down by site
  app.get<{ Querystring: { days?: string } }>('/api/stats/site-trend', async (request) => {
    const days = Math.max(1, parseInt(request.query.days || '7', 10));
    const sinceDate = getLocalRangeStartUtc(days);

    const rows = await db.select({
      proxy_logs: proxyLogBaseFields,
      accounts: schema.accounts,
      sites: schema.sites,
    }).from(schema.proxyLogs)
      .leftJoin(schema.accounts, eq(schema.proxyLogs.accountId, schema.accounts.id))
      .leftJoin(schema.sites, eq(schema.accounts.siteId, schema.sites.id))
      .where(and(gte(schema.proxyLogs.createdAt, sinceDate), eq(schema.sites.status, 'active')))
      .all();

    // Group by date + site name
    const dayMap: Record<string, Record<string, { spend: number; calls: number }>> = {};

    for (const row of rows) {
      const log = row.proxy_logs;
      const siteName = row.sites?.name || 'unknown';
      const platform = row.sites?.platform || 'new-api';
      const date = toLocalDayKeyFromStoredUtc(log.createdAt);
      if (!date) continue;

      if (!dayMap[date]) dayMap[date] = {};
      if (!dayMap[date][siteName]) dayMap[date][siteName] = { spend: 0, calls: 0 };

      const explicitCost = typeof log.estimatedCost === 'number' ? log.estimatedCost : 0;
      const cost = explicitCost > 0 ? explicitCost : fallbackTokenCost(log.totalTokens || 0, platform);
      dayMap[date][siteName].spend += cost;
      dayMap[date][siteName].calls++;
    }

    // Round spend values and sort by date
    const trend = Object.entries(dayMap)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([date, sites]) => {
        const rounded: Record<string, { spend: number; calls: number }> = {};
        for (const [name, stats] of Object.entries(sites)) {
          rounded[name] = {
            spend: Math.round(stats.spend * 1_000_000) / 1_000_000,
            calls: stats.calls,
          };
        }
        return { date, sites: rounded };
      });

    return { trend };
  });

  // Model stats by site
  app.get<{ Querystring: { siteId?: string; days?: string } }>('/api/stats/model-by-site', async (request) => {
    const siteId = request.query.siteId ? parseInt(request.query.siteId, 10) : null;
    const days = Math.max(1, parseInt(request.query.days || '7', 10));
    const sinceDate = getLocalRangeStartUtc(days);

    // Get account IDs belonging to the site (if filtered)
    let accountIds: Set<number> | null = null;
    if (siteId != null && !Number.isNaN(siteId)) {
      const siteAccounts = await db.select().from(schema.accounts)
        .where(eq(schema.accounts.siteId, siteId)).all();
      accountIds = new Set(siteAccounts.map((a) => a.id));
    }

    const rows = await db.select({
      proxy_logs: proxyLogBaseFields,
      accounts: schema.accounts,
      sites: schema.sites,
    }).from(schema.proxyLogs)
      .leftJoin(schema.accounts, eq(schema.proxyLogs.accountId, schema.accounts.id))
      .leftJoin(schema.sites, eq(schema.accounts.siteId, schema.sites.id))
      .where(and(gte(schema.proxyLogs.createdAt, sinceDate), eq(schema.sites.status, 'active')))
      .all();

    const modelMap: Record<string, { calls: number; spend: number; tokens: number }> = {};

    for (const row of rows) {
      const log = row.proxy_logs;
      // Filter by site if siteId is specified
      if (accountIds != null && (log.accountId == null || !accountIds.has(log.accountId))) continue;

      const model = log.modelActual || log.modelRequested || 'unknown';
      const platform = row.sites?.platform || 'new-api';

      if (!modelMap[model]) modelMap[model] = { calls: 0, spend: 0, tokens: 0 };
      modelMap[model].calls++;
      modelMap[model].tokens += log.totalTokens || 0;

      const explicitCost = typeof log.estimatedCost === 'number' ? log.estimatedCost : 0;
      const cost = explicitCost > 0 ? explicitCost : fallbackTokenCost(log.totalTokens || 0, platform);
      modelMap[model].spend += cost;
    }

    const models = Object.entries(modelMap)
      .map(([model, stats]) => ({
        model,
        calls: stats.calls,
        spend: Math.round(stats.spend * 1_000_000) / 1_000_000,
        tokens: stats.tokens,
      }))
      .sort((a, b) => b.calls - a.calls);

    return { models };
  });
}
