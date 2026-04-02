import Fastify from 'fastify';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const checkinAllMock = vi.fn();
const checkinAccountMock = vi.fn();

vi.mock('../../services/checkinService.js', () => ({
  checkinAll: (...args: unknown[]) => checkinAllMock(...args),
  checkinAccount: (...args: unknown[]) => checkinAccountMock(...args),
}));

vi.mock('../../services/checkinScheduler.js', () => ({
  updateCheckinSchedule: vi.fn(),
}));

vi.mock('../../db/index.js', () => {
  const insertChain = {
    values: () => insertChain,
    onConflictDoUpdate: () => insertChain,
    run: () => ({ changes: 1 }),
  };

  const queryChain = {
    where: () => queryChain,
    all: () => [],
    limit: () => queryChain,
    offset: () => queryChain,
    orderBy: () => queryChain,
    innerJoin: () => queryChain,
    from: () => queryChain,
  };

  return {
    db: {
      insert: () => insertChain,
      select: () => queryChain,
    },
    hasProxyLogStreamTimingColumns: async () => false,
    schema: {
      settings: { key: 'key' },
      checkinLogs: { accountId: 'accountId', createdAt: 'createdAt' },
      accounts: { id: 'id' },
      events: { id: 'id' },
    },
  };
});

describe('POST /api/checkin/trigger background task dedupe', () => {
  beforeEach(async () => {
    checkinAllMock.mockReset();
    checkinAccountMock.mockReset();
    checkinAccountMock.mockResolvedValue({ success: true, message: 'ok' });
    const { __resetBackgroundTasksForTests } = await import('../../services/backgroundTaskService.js');
    __resetBackgroundTasksForTests();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('reuses the same background task while checkin-all is already running', async () => {
    let resolveFirst: (value: Array<unknown>) => void = () => {};
    const firstRun = new Promise<Array<unknown>>((resolve) => {
      resolveFirst = resolve;
    });
    checkinAllMock.mockImplementation(() => firstRun);

    const { checkinRoutes } = await import('./checkin.js');
    const app = Fastify();
    await app.register(checkinRoutes);

    const firstResponse = await app.inject({ method: 'POST', url: '/api/checkin/trigger' });
    expect(firstResponse.statusCode).toBe(202);
    const firstBody = firstResponse.json() as { success: boolean; queued: boolean; jobId: string };
    expect(firstBody.success).toBe(true);
    expect(firstBody.queued).toBe(true);
    expect(typeof firstBody.jobId).toBe('string');
    expect(firstBody.jobId.length).toBeGreaterThan(10);

    const secondResponse = await app.inject({ method: 'POST', url: '/api/checkin/trigger' });
    expect(secondResponse.statusCode).toBe(202);
    const secondBody = secondResponse.json() as { reused: boolean; jobId: string };
    expect(secondBody.reused).toBe(true);
    expect(secondBody.jobId).toBe(firstBody.jobId);
    expect(checkinAllMock).toHaveBeenCalledTimes(1);

    resolveFirst([]);
    await new Promise((resolve) => setTimeout(resolve, 20));
    await app.close();
  });

  it('accepts the legacy cron-only schedule payload', async () => {
    const { checkinRoutes } = await import('./checkin.js');
    const schedulerModule = await import('../../services/checkinScheduler.js');
    const app = Fastify();
    await app.register(checkinRoutes);

    const response = await app.inject({
      method: 'PUT',
      url: '/api/checkin/schedule',
      payload: { cron: '0 8 * * *' },
    });

    expect(response.statusCode).toBe(200);
    expect((schedulerModule as any).updateCheckinSchedule).toHaveBeenCalledWith({
      mode: 'cron',
      cronExpr: '0 8 * * *',
      intervalHours: undefined,
    });
    await app.close();
  });
});
