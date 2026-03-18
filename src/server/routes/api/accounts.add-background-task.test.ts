import Fastify, { type FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const verifyTokenMock = vi.fn();
const getApiTokensMock = vi.fn();
const refreshBalanceMock = vi.fn();
const refreshModelsForAccountMock = vi.fn();
const rebuildTokenRoutesFromAvailabilityMock = vi.fn();
const ensureDefaultTokenForAccountMock = vi.fn();
const syncTokensFromUpstreamMock = vi.fn();

vi.mock('../../services/platforms/index.js', () => ({
  getAdapter: () => ({
    verifyToken: (...args: unknown[]) => verifyTokenMock(...args),
    getApiTokens: (...args: unknown[]) => getApiTokensMock(...args),
  }),
}));

vi.mock('../../services/balanceService.js', () => ({
  refreshBalance: (...args: unknown[]) => refreshBalanceMock(...args),
}));

vi.mock('../../services/modelService.js', () => ({
  refreshModelsForAccount: (...args: unknown[]) => refreshModelsForAccountMock(...args),
  rebuildTokenRoutesFromAvailability: (...args: unknown[]) => rebuildTokenRoutesFromAvailabilityMock(...args),
}));

vi.mock('../../services/accountTokenService.js', () => ({
  ensureDefaultTokenForAccount: (...args: unknown[]) => ensureDefaultTokenForAccountMock(...args),
  syncTokensFromUpstream: (...args: unknown[]) => syncTokensFromUpstreamMock(...args),
}));

type DbModule = typeof import('../../db/index.js');

describe('accounts background initialization', () => {
  let app: FastifyInstance;
  let db: DbModule['db'];
  let schema: DbModule['schema'];
  let dataDir = '';
  let resetBackgroundTasks: (() => void) | null = null;
  let getBackgroundTask: ((taskId: string) => { status: string } | null) | null = null;

  beforeAll(async () => {
    dataDir = mkdtempSync(join(tmpdir(), 'metapi-accounts-background-init-'));
    process.env.DATA_DIR = dataDir;

    await import('../../db/migrate.js');
    const dbModule = await import('../../db/index.js');
    const routesModule = await import('./accounts.js');
    const backgroundTaskModule = await import('../../services/backgroundTaskService.js');
    db = dbModule.db;
    schema = dbModule.schema;
    resetBackgroundTasks = backgroundTaskModule.__resetBackgroundTasksForTests;
    getBackgroundTask = backgroundTaskModule.getBackgroundTask;

    app = Fastify();
    await app.register(routesModule.accountsRoutes);
  });

  beforeEach(async () => {
    verifyTokenMock.mockReset();
    getApiTokensMock.mockReset();
    refreshBalanceMock.mockReset();
    refreshModelsForAccountMock.mockReset();
    rebuildTokenRoutesFromAvailabilityMock.mockReset();
    ensureDefaultTokenForAccountMock.mockReset();
    syncTokensFromUpstreamMock.mockReset();
    resetBackgroundTasks?.();

    await db.delete(schema.proxyLogs).run();
    await db.delete(schema.checkinLogs).run();
    await db.delete(schema.routeChannels).run();
    await db.delete(schema.tokenRoutes).run();
    await db.delete(schema.tokenModelAvailability).run();
    await db.delete(schema.modelAvailability).run();
    await db.delete(schema.accountTokens).run();
    await db.delete(schema.events).run();
    await db.delete(schema.accounts).run();
    await db.delete(schema.sites).run();
  });

  afterAll(async () => {
    await app.close();
    if (dataDir) {
      try {
        rmSync(dataDir, { recursive: true, force: true });
      } catch {}
    }
    delete process.env.DATA_DIR;
  });

  it('returns immediately and queues background initialization when token sync is slow', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'Session Site',
      url: 'https://session.example.com',
      platform: 'new-api',
    }).returning().get();

    verifyTokenMock.mockResolvedValue({
      tokenType: 'session',
      userInfo: { username: 'demo-user' },
      apiToken: 'sk-demo',
    });
    ensureDefaultTokenForAccountMock.mockResolvedValue(undefined);
    refreshBalanceMock.mockResolvedValue({ balance: 1, used: 0, quota: 1 });
    refreshModelsForAccountMock.mockResolvedValue(undefined);
    rebuildTokenRoutesFromAvailabilityMock.mockResolvedValue(undefined);
    syncTokensFromUpstreamMock.mockResolvedValue(undefined);

    let releaseTokens: ((value: Array<{ name: string; value: string }>) => void) | null = null;
    const pendingTokens = new Promise<Array<{ name: string; value: string }>>((resolve) => {
      releaseTokens = resolve;
    });
    getApiTokensMock.mockReturnValue(pendingTokens);

    const responsePromise = app.inject({
      method: 'POST',
      url: '/api/accounts',
      payload: {
        siteId: site.id,
        accessToken: 'session-token',
      },
    });

    try {
      const raceResult = await Promise.race([
        responsePromise.then(() => 'response'),
        new Promise<'timeout'>((resolve) => setTimeout(() => resolve('timeout'), 25)),
      ]);

      expect(raceResult).toBe('response');

      const response = await responsePromise;
      expect(response.statusCode).toBe(200);

      const body = response.json() as {
        id: number;
        queued?: boolean;
        jobId?: string;
        usernameDetected?: boolean;
        apiTokenFound?: boolean;
      };

      expect(body).toMatchObject({
        queued: true,
        usernameDetected: true,
        apiTokenFound: true,
      });
      expect(body.jobId).toBeTruthy();

      const insertedAccounts = await db.select().from(schema.accounts).all();
      expect(insertedAccounts).toHaveLength(1);
      expect(getBackgroundTask?.(body.jobId!)).toMatchObject({
        status: expect.stringMatching(/pending|running/),
      });

      releaseTokens?.([{ name: 'default', value: 'sk-demo' }]);

      for (let attempt = 0; attempt < 20; attempt += 1) {
        const task = getBackgroundTask?.(body.jobId!);
        if (task?.status === 'succeeded') break;
        await new Promise((resolve) => setTimeout(resolve, 0));
      }

      expect(syncTokensFromUpstreamMock).toHaveBeenCalledTimes(1);
      expect(refreshBalanceMock).toHaveBeenCalledTimes(1);
      expect(refreshModelsForAccountMock).toHaveBeenCalledTimes(1);
      expect(rebuildTokenRoutesFromAvailabilityMock).toHaveBeenCalledTimes(1);
      expect(getBackgroundTask?.(body.jobId!)).toMatchObject({ status: 'succeeded' });
    } finally {
      releaseTokens?.([]);
      await responsePromise.catch(() => undefined);
    }
  });
});
