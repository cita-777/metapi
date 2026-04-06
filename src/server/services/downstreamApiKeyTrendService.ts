import { and, asc, eq, sql, type SQL, type SQLWrapper } from 'drizzle-orm';
import { db, runtimeDbDialect, schema } from '../db/index.js';
import {
  formatUtcSqlDateTime,
  getResolvedTimeZone,
  parseStoredUtcDateTime,
  type StoredUtcDateTimeInput,
} from './localTimeService.js';

export type DownstreamKeyTrendRange = '24h' | '7d' | 'all';

export type DownstreamKeyTrendBucket = {
  startUtc: string | null;
  totalRequests: number;
  successRequests: number;
  failedRequests: number;
  successRate: number | null;
  totalTokens: number;
  totalCost: number;
};

type DownstreamTrendLogRow = {
  id: number;
  createdAt: StoredUtcDateTimeInput;
  status: string | null;
  totalTokens: number | null;
  totalCost: number | null;
};

type DownstreamTrendBucketAccumulator = {
  startUtc: string;
  totalRequests: number;
  successRequests: number;
  failedRequests: number;
  totalTokens: number;
  totalCost: number;
};

type TimeZoneDateTimeParts = {
  year: number;
  month: number;
  day: number;
  hour: number;
  minute: number;
  second: number;
};

type DownstreamTrendCursor = {
  createdAt: StoredUtcDateTimeInput;
  id: number;
};

const ALL_RANGE_CHUNK_SIZE = 5_000;

export function resolveDownstreamTrendRangeSinceUtc(range: DownstreamKeyTrendRange): string | null {
  const nowTs = Date.now();
  if (range === '24h') return formatUtcSqlDateTime(new Date(nowTs - 24 * 60 * 60 * 1000));
  if (range === '7d') return formatUtcSqlDateTime(new Date(nowTs - 7 * 24 * 60 * 60 * 1000));
  return null;
}

export function resolveDownstreamTrendBucketSeconds(range: DownstreamKeyTrendRange): number {
  return range === 'all' ? 86400 : 3600;
}

export function buildBucketTsExpressionForDialect(
  dialect: 'sqlite' | 'mysql' | 'postgres',
  createdAtColumn: SQLWrapper,
  bucketSeconds: number,
) {
  if (dialect === 'mysql') {
    return sql<number>`floor(unix_timestamp(${createdAtColumn}) / ${bucketSeconds}) * ${bucketSeconds}`;
  }
  if (dialect === 'postgres') {
    const createdAtTimestamp = sql`cast(${createdAtColumn} as timestamp)`;
    if (bucketSeconds === 86400) {
      return sql<number>`extract(epoch from date_trunc('day', ${createdAtTimestamp}))::bigint`;
    }
    return sql<number>`extract(epoch from date_trunc('hour', ${createdAtTimestamp}))::bigint`;
  }
  return sql<number>`cast(cast(strftime('%s', ${createdAtColumn}) as integer) / ${bucketSeconds} as integer) * ${bucketSeconds}`;
}

function resolveBucketTsExpression(bucketSeconds: number) {
  return buildBucketTsExpressionForDialect(runtimeDbDialect, schema.proxyLogs.createdAt, bucketSeconds);
}

export function resolveDownstreamTrendTimeZone(raw?: string | null): string {
  const text = String(raw || '').trim();
  if (text) {
    try {
      new Intl.DateTimeFormat('en-CA', { timeZone: text }).format(new Date());
      return text;
    } catch {
      // fall through to server default
    }
  }
  return getResolvedTimeZone();
}

function formatDateTimePartsInTimeZone(value: Date, timeZone: string): TimeZoneDateTimeParts | null {
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
  const year = Number(lookup.get('year'));
  const month = Number(lookup.get('month'));
  const day = Number(lookup.get('day'));
  const hour = Number(lookup.get('hour'));
  const minute = Number(lookup.get('minute'));
  const second = Number(lookup.get('second'));
  if (![year, month, day, hour, minute, second].every(Number.isFinite)) return null;
  return { year, month, day, hour, minute, second };
}

function toUtcComparableValue(parts: TimeZoneDateTimeParts): number {
  return Date.UTC(parts.year, parts.month - 1, parts.day, parts.hour, parts.minute, parts.second, 0);
}

function sameDateTimeParts(left: TimeZoneDateTimeParts, right: TimeZoneDateTimeParts): boolean {
  return left.year === right.year
    && left.month === right.month
    && left.day === right.day
    && left.hour === right.hour
    && left.minute === right.minute
    && left.second === right.second;
}

function resolveTargetBucketParts(parts: TimeZoneDateTimeParts, bucketSeconds: number): TimeZoneDateTimeParts {
  if (bucketSeconds >= 86400) {
    return { ...parts, hour: 0, minute: 0, second: 0 };
  }
  return { ...parts, minute: 0, second: 0 };
}

function convertZonedPartsToUtcDate(parts: TimeZoneDateTimeParts, timeZone: string): Date | null {
  let candidateMs = toUtcComparableValue(parts);
  // Iterate toward the UTC instant that renders back to the requested local wall time.
  // Rare DST gaps/ambiguities may never converge; callers skip null buckets safely.
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const candidate = new Date(candidateMs);
    const rendered = formatDateTimePartsInTimeZone(candidate, timeZone);
    if (!rendered) return null;
    if (sameDateTimeParts(rendered, parts)) return candidate;
    candidateMs += toUtcComparableValue(parts) - toUtcComparableValue(rendered);
  }
  const finalCandidate = new Date(candidateMs);
  const finalRendered = formatDateTimePartsInTimeZone(finalCandidate, timeZone);
  return finalRendered && sameDateTimeParts(finalRendered, parts) ? finalCandidate : null;
}

function resolveLocalBucketStartUtc(
  raw: StoredUtcDateTimeInput,
  bucketSeconds: number,
  timeZone: string,
): string | null {
  const parsed = parseStoredUtcDateTime(raw);
  if (!parsed) return null;
  const localParts = formatDateTimePartsInTimeZone(parsed, timeZone);
  if (!localParts) return null;
  const targetParts = resolveTargetBucketParts(localParts, bucketSeconds);
  const bucketStart = convertZonedPartsToUtcDate(targetParts, timeZone);
  return bucketStart ? bucketStart.toISOString() : null;
}

function accumulateTrendRows(
  accumulator: Map<string, DownstreamTrendBucketAccumulator>,
  rows: DownstreamTrendLogRow[],
  bucketSeconds: number,
  timeZone: string,
) {
  for (const row of rows) {
    const startUtc = resolveLocalBucketStartUtc(row.createdAt, bucketSeconds, timeZone);
    if (!startUtc) continue;
    const bucket = accumulator.get(startUtc) || {
      startUtc,
      totalRequests: 0,
      successRequests: 0,
      failedRequests: 0,
      totalTokens: 0,
      totalCost: 0,
    };
    const isSuccess = (row.status || '').trim().toLowerCase() === 'success';
    bucket.totalRequests += 1;
    bucket.successRequests += isSuccess ? 1 : 0;
    bucket.failedRequests += isSuccess ? 0 : 1;
    bucket.totalTokens += Number(row.totalTokens || 0);
    bucket.totalCost += Number(row.totalCost || 0);
    accumulator.set(startUtc, bucket);
  }
}

function finalizeTrendBuckets(accumulator: Map<string, DownstreamTrendBucketAccumulator>): DownstreamKeyTrendBucket[] {
  return Array.from(accumulator.values())
    .sort((left, right) => left.startUtc.localeCompare(right.startUtc))
    .map((bucket) => ({
      startUtc: bucket.startUtc,
      totalRequests: bucket.totalRequests,
      successRequests: bucket.successRequests,
      failedRequests: bucket.failedRequests,
      successRate: bucket.totalRequests > 0 ? Math.round((bucket.successRequests / bucket.totalRequests) * 1000) / 10 : null,
      totalTokens: bucket.totalTokens,
      totalCost: Math.round(bucket.totalCost * 1_000_000) / 1_000_000,
    }));
}

function buildTrendCursorClause(cursor: DownstreamTrendCursor): SQL {
  return sql`(
    ${schema.proxyLogs.createdAt} > ${cursor.createdAt}
    or (${schema.proxyLogs.createdAt} = ${cursor.createdAt} and ${schema.proxyLogs.id} > ${cursor.id})
  )`;
}

async function readAllRangeTrendBuckets(
  downstreamApiKeyId: number,
  bucketSeconds: number,
  timeZone: string,
  sinceUtc: string | null,
): Promise<DownstreamKeyTrendBucket[]> {
  const accumulator = new Map<string, DownstreamTrendBucketAccumulator>();
  let cursor: DownstreamTrendCursor | null = null;

  for (;;) {
    const whereClauses: SQL[] = [eq(schema.proxyLogs.downstreamApiKeyId, downstreamApiKeyId)];
    if (sinceUtc) {
      whereClauses.push(sql`${schema.proxyLogs.createdAt} >= ${sinceUtc}`);
    }
    if (cursor) {
      whereClauses.push(buildTrendCursorClause(cursor));
    }

    const rows = await db.select({
      id: schema.proxyLogs.id,
      createdAt: schema.proxyLogs.createdAt,
      status: schema.proxyLogs.status,
      totalTokens: schema.proxyLogs.totalTokens,
      totalCost: schema.proxyLogs.estimatedCost,
    })
      .from(schema.proxyLogs)
      .where(and(...whereClauses))
      .orderBy(asc(schema.proxyLogs.createdAt), asc(schema.proxyLogs.id))
      .limit(ALL_RANGE_CHUNK_SIZE)
      .all();

    if (rows.length <= 0) break;
    accumulateTrendRows(accumulator, rows, bucketSeconds, timeZone);
    const lastRow = rows.at(-1);
    if (rows.length < ALL_RANGE_CHUNK_SIZE || !lastRow) break;
    cursor = {
      createdAt: lastRow.createdAt,
      id: lastRow.id,
    };
  }

  return finalizeTrendBuckets(accumulator);
}

async function readWindowedTrendBuckets(
  downstreamApiKeyId: number,
  bucketSeconds: number,
  sinceUtc: string | null,
  timeZone: string,
): Promise<DownstreamKeyTrendBucket[]> {
  if (timeZone.toUpperCase() !== 'UTC') {
    return readAllRangeTrendBuckets(downstreamApiKeyId, bucketSeconds, timeZone, sinceUtc);
  }

  const bucketTs = resolveBucketTsExpression(bucketSeconds);
  const whereClauses: SQL[] = [eq(schema.proxyLogs.downstreamApiKeyId, downstreamApiKeyId)];
  if (sinceUtc) {
    whereClauses.push(sql`${schema.proxyLogs.createdAt} >= ${sinceUtc}`);
  }

  const rows = await db.select({
    bucketTs,
    totalRequests: sql<number>`count(*)`,
    successRequests: sql<number>`coalesce(sum(case when ${schema.proxyLogs.status} = 'success' then 1 else 0 end), 0)`,
    failedRequests: sql<number>`coalesce(sum(case when ${schema.proxyLogs.status} = 'success' then 0 else 1 end), 0)`,
    totalTokens: sql<number>`coalesce(sum(coalesce(${schema.proxyLogs.totalTokens}, 0)), 0)`,
    totalCost: sql<number>`coalesce(sum(coalesce(${schema.proxyLogs.estimatedCost}, 0)), 0)`,
  })
    .from(schema.proxyLogs)
    .where(and(...whereClauses))
    .groupBy(bucketTs)
    .orderBy(bucketTs)
    .all();

  return rows.map((row: any) => {
    const tsSeconds = Number(row.bucketTs || 0);
    const totalRequests = Number(row.totalRequests || 0);
    const successRequests = Number(row.successRequests || 0);
    return {
      startUtc: tsSeconds > 0 ? new Date(tsSeconds * 1000).toISOString() : null,
      totalRequests,
      successRequests,
      failedRequests: Number(row.failedRequests || 0),
      successRate: totalRequests > 0 ? Math.round((successRequests / totalRequests) * 1000) / 10 : null,
      totalTokens: Number(row.totalTokens || 0),
      totalCost: Math.round(Number(row.totalCost || 0) * 1_000_000) / 1_000_000,
    };
  });
}

export async function readDownstreamApiKeyTrendBuckets(input: {
  downstreamApiKeyId: number;
  range: DownstreamKeyTrendRange;
  timeZone?: string | null;
}): Promise<{
  bucketSeconds: number;
  timeZone: string;
  buckets: DownstreamKeyTrendBucket[];
}> {
  const bucketSeconds = resolveDownstreamTrendBucketSeconds(input.range);
  const sinceUtc = resolveDownstreamTrendRangeSinceUtc(input.range);
  const timeZone = resolveDownstreamTrendTimeZone(input.timeZone);
  const buckets = input.range === 'all'
    ? await readAllRangeTrendBuckets(input.downstreamApiKeyId, bucketSeconds, timeZone, sinceUtc)
    : await readWindowedTrendBuckets(input.downstreamApiKeyId, bucketSeconds, sinceUtc, timeZone);

  return {
    bucketSeconds,
    timeZone,
    buckets,
  };
}
