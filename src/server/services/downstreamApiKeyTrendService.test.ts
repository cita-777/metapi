import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

type DbModule = typeof import('../db/index.js');
type TrendServiceModule = typeof import('./downstreamApiKeyTrendService.js');

const INSERT_BATCH_SIZE = 100;

describe('downstreamApiKeyTrendService', () => {
  let db: DbModule['db'];
  let schema: DbModule['schema'];
  let trendService: TrendServiceModule;
  let dataDir = '';

  beforeAll(async () => {
    dataDir = mkdtempSync(join(tmpdir(), 'metapi-downstream-trend-'));
    process.env.DATA_DIR = dataDir;

    await import('../db/migrate.js');
    const dbModule = await import('../db/index.js');
    const trendServiceModule = await import('./downstreamApiKeyTrendService.js');

    db = dbModule.db;
    schema = dbModule.schema;
    trendService = trendServiceModule;
  });

  beforeEach(async () => {
    await db.delete(schema.proxyLogs).run();
    await db.delete(schema.downstreamApiKeys).run();
  });

  afterAll(() => {
    delete process.env.DATA_DIR;
  });

  it('reads all-range buckets across cursor pages when many rows share the same createdAt', async () => {
    const inserted = await db.insert(schema.downstreamApiKeys).values({
      name: 'cursor-key',
      key: 'sk-cursor-key-001',
      enabled: true,
    }).returning().get();

    const sharedCreatedAt = '2026-04-05T00:15:00.000Z';
    const sharedRows = Array.from({ length: 5_001 }, () => ({
      downstreamApiKeyId: inserted.id,
      status: 'success',
      totalTokens: 1,
      estimatedCost: 0.001,
      createdAt: sharedCreatedAt,
    }));

    for (let index = 0; index < sharedRows.length; index += INSERT_BATCH_SIZE) {
      await db.insert(schema.proxyLogs).values(sharedRows.slice(index, index + INSERT_BATCH_SIZE)).run();
    }

    await db.insert(schema.proxyLogs).values({
      downstreamApiKeyId: inserted.id,
      status: 'failed',
      totalTokens: 2,
      estimatedCost: 0.002,
      createdAt: '2026-04-06T00:30:00.000Z',
    }).run();

    const trend = await trendService.readDownstreamApiKeyTrendBuckets({
      downstreamApiKeyId: inserted.id,
      range: 'all',
      timeZone: 'UTC',
    });

    expect(trend.bucketSeconds).toBe(86400);
    expect(trend.timeZone).toBe('UTC');
    expect(trend.buckets).toHaveLength(2);
    expect(trend.buckets[0]).toMatchObject({
      startUtc: '2026-04-05T00:00:00.000Z',
      totalRequests: 5_001,
      successRequests: 5_001,
      failedRequests: 0,
      totalTokens: 5_001,
    });
    expect(trend.buckets[0]?.totalCost).toBeCloseTo(5.001, 6);
    expect(trend.buckets[1]).toMatchObject({
      startUtc: '2026-04-06T00:00:00.000Z',
      totalRequests: 1,
      successRequests: 0,
      failedRequests: 1,
      totalTokens: 2,
    });
    expect(trend.buckets[1]?.totalCost).toBeCloseTo(0.002, 6);
  });

  it('normalizes trend time zones consistently for explicit and invalid values', () => {
    const fallback = trendService.resolveDownstreamTrendTimeZone();

    expect(trendService.resolveDownstreamTrendTimeZone('UTC')).toBe('UTC');
    expect(trendService.resolveDownstreamTrendTimeZone('Invalid/Zone')).toBe(fallback);
    expect(trendService.resolveDownstreamTrendTimeZone('  ')).toBe(fallback);
  });
});
