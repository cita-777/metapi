import Fastify, { type FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { waitForBackgroundTaskToReachTerminalState } from '../../test-fixtures/backgroundTaskTestUtils.js';

type DbModule = typeof import('../../db/index.js');
type BackgroundTaskModule = typeof import('../../services/backgroundTaskService.js');
type TokenRouterModule = typeof import('../../services/tokenRouter.js');

describe('POST /api/routes/decision/refresh', () => {
  let app: FastifyInstance;
  let previousDataDir: string | undefined;
  let db: DbModule['db'];
  let schema: DbModule['schema'];
  let invalidateTokenRouterCache: TokenRouterModule['invalidateTokenRouterCache'];
  let tokenRouter: TokenRouterModule['tokenRouter'];
  let getBackgroundTask: BackgroundTaskModule['getBackgroundTask'];
  let resetBackgroundTasks: BackgroundTaskModule['__resetBackgroundTasksForTests'];
  let dataDir = '';

  beforeAll(async () => {
    previousDataDir = process.env.DATA_DIR;
    vi.resetModules();
    dataDir = mkdtempSync(join(tmpdir(), 'metapi-route-decision-refresh-task-'));
    process.env.DATA_DIR = dataDir;

    await import('../../db/migrate.js');
    const dbModule = await import('../../db/index.js');
    const routesModule = await import('./tokens.js');
    const tokenRouterModule = await import('../../services/tokenRouter.js');
    const backgroundTaskModule = await import('../../services/backgroundTaskService.js');
    db = dbModule.db;
    schema = dbModule.schema;
    invalidateTokenRouterCache = tokenRouterModule.invalidateTokenRouterCache;
    tokenRouter = tokenRouterModule.tokenRouter;
    getBackgroundTask = backgroundTaskModule.getBackgroundTask;
    resetBackgroundTasks = backgroundTaskModule.__resetBackgroundTasksForTests;
    vi.spyOn(tokenRouter, 'refreshPricingReferenceCosts').mockResolvedValue(undefined);
    vi.spyOn(tokenRouter, 'refreshRouteWidePricingReferenceCosts').mockResolvedValue(undefined);

    app = Fastify();
    await app.register(routesModule.tokensRoutes);
  });

  beforeEach(async () => {
    resetBackgroundTasks();
    await db.delete(schema.routeChannels).run();
    await db.delete(schema.tokenRoutes).run();
    await db.delete(schema.accountTokens).run();
    await db.delete(schema.accounts).run();
    await db.delete(schema.sites).run();
    await db.delete(schema.settings).run();
    await db.delete(schema.events).run();
    invalidateTokenRouterCache();
  });

  afterAll(async () => {
    await app.close();
    invalidateTokenRouterCache();
    vi.restoreAllMocks();
    if (dataDir) {
      try {
        rmSync(dataDir, { recursive: true, force: true });
      } catch {}
    }
    if (previousDataDir === undefined) {
      delete process.env.DATA_DIR;
    } else {
      process.env.DATA_DIR = previousDataDir;
    }
    vi.resetModules();
  });

  it('queues a background refresh task and persists refreshed snapshots for exact and wildcard routes', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'refresh-task-site',
      url: 'https://refresh-task-site.example.com',
      platform: 'new-api',
      status: 'active',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'refresh-task-user',
      accessToken: 'refresh-task-access',
      apiToken: 'refresh-task-api',
      status: 'active',
    }).returning().get();

    const exactRoute = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-4o-mini',
      enabled: true,
    }).returning().get();

    const duplicateExactRoute = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'gpt-4o-mini',
      enabled: true,
    }).returning().get();

    const wildcardRoute = await db.insert(schema.tokenRoutes).values({
      modelPattern: 're:^claude-(opus|sonnet)-4-6$',
      enabled: true,
    }).returning().get();

    const disabledRoute = await db.insert(schema.tokenRoutes).values({
      modelPattern: 'disabled-model',
      enabled: false,
    }).returning().get();

    await db.insert(schema.routeChannels).values([
      {
        routeId: exactRoute.id,
        accountId: account.id,
        tokenId: null,
        priority: 0,
        weight: 10,
        enabled: true,
      },
      {
        routeId: duplicateExactRoute.id,
        accountId: account.id,
        tokenId: null,
        sourceModel: 'gpt-4o-mini',
        priority: 0,
        weight: 5,
        enabled: true,
      },
      {
        routeId: wildcardRoute.id,
        accountId: account.id,
        tokenId: null,
        sourceModel: 'claude-opus-4-6',
        priority: 0,
        weight: 10,
        enabled: true,
      },
      {
        routeId: disabledRoute.id,
        accountId: account.id,
        tokenId: null,
        priority: 0,
        weight: 10,
        enabled: true,
      },
    ]).run();

    const response = await app.inject({
      method: 'POST',
      url: '/api/routes/decision/refresh',
      payload: {},
    });

    expect(response.statusCode).toBe(202);
    const body = response.json() as {
      success: boolean;
      queued: boolean;
      jobId: string;
      status: string;
    };
    expect(body.success).toBe(true);
    expect(body.queued).toBe(true);
    expect(body.jobId.length).toBeGreaterThan(10);
    expect(body.status).toBe('pending');

    const task = await waitForBackgroundTaskToReachTerminalState(getBackgroundTask, body.jobId);
    expect(task).toMatchObject({ status: 'succeeded' });

    const routesResponse = await app.inject({
      method: 'GET',
      url: '/api/routes',
    });

    expect(routesResponse.statusCode).toBe(200);
    const routes = routesResponse.json() as Array<{
      id: number;
      decisionSnapshot?: { matched?: boolean; routeId?: number; candidates?: Array<unknown> } | null;
    }>;

    const refreshedExactRoute = routes.find((route) => route.id === exactRoute.id);
    const refreshedDuplicateExactRoute = routes.find((route) => route.id === duplicateExactRoute.id);
    const refreshedWildcardRoute = routes.find((route) => route.id === wildcardRoute.id);
    const refreshedDisabledRoute = routes.find((route) => route.id === disabledRoute.id);

    expect(refreshedExactRoute?.decisionSnapshot?.matched).toBe(true);
    expect(refreshedExactRoute?.decisionSnapshot?.routeId).toBe(exactRoute.id);
    expect(Array.isArray(refreshedExactRoute?.decisionSnapshot?.candidates)).toBe(true);
    expect(refreshedDuplicateExactRoute?.decisionSnapshot?.matched).toBe(true);
    expect(refreshedDuplicateExactRoute?.decisionSnapshot?.routeId).toBe(duplicateExactRoute.id);
    expect(refreshedWildcardRoute?.decisionSnapshot?.matched).toBe(true);
    expect(refreshedWildcardRoute?.decisionSnapshot?.routeId).toBe(wildcardRoute.id);
    expect(refreshedDisabledRoute?.decisionSnapshot).toBeNull();
  });
});
