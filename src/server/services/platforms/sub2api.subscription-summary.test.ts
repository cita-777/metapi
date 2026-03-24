import { describe, expect, it } from 'vitest';
import { Sub2ApiAdapter } from './sub2api.js';

class MockSub2ApiAdapter extends Sub2ApiAdapter {
  constructor(private readonly responses: Record<string, unknown>) {
    super();
  }

  protected override async fetchJson<T>(url: string): Promise<T> {
    const parsed = new URL(url);
    const key = `${parsed.pathname}${parsed.search}`;
    const value = this.responses[key];
    if (value instanceof Error) throw value;
    if (value === undefined) throw new Error(`Unexpected request: ${key}`);
    return value as T;
  }
}

describe('Sub2ApiAdapter subscription summary parsing', () => {
  it('returns summary data from /api/v1/subscriptions/summary', async () => {
    const adapter = new MockSub2ApiAdapter({
      '/api/v1/auth/me': {
        code: 0,
        message: 'success',
        data: { id: 1, username: 'demo', email: 'demo@example.com', balance: 8.5 },
      },
      '/api/v1/subscriptions/summary': {
        code: 0,
        message: 'success',
        data: {
          active_count: 1,
          total_used_usd: 3.2,
          subscriptions: [
            {
              id: 9,
              group_name: 'Pro',
              status: 'active',
              expires_at: '2026-04-01T00:00:00Z',
              monthly_used_usd: 3.2,
              monthly_limit_usd: 20,
            },
          ],
        },
      },
    });

    const balance = await adapter.getBalance('https://sub2api.example.com', 'jwt-token');
    expect(balance.subscriptionSummary).toEqual({
      activeCount: 1,
      totalUsedUsd: 3.2,
      subscriptions: [
        {
          id: 9,
          groupName: 'Pro',
          status: 'active',
          expiresAt: '2026-04-01T00:00:00.000Z',
          monthlyUsedUsd: 3.2,
          monthlyLimitUsd: 20,
        },
      ],
    });
  });

  it('falls back to /api/v1/subscriptions/active when summary endpoint fails', async () => {
    const adapter = new MockSub2ApiAdapter({
      '/api/v1/auth/me': {
        code: 0,
        message: 'success',
        data: { id: 1, username: 'demo', email: 'demo@example.com', balance: 8.5 },
      },
      '/api/v1/subscriptions/summary': new Error('HTTP 404'),
      '/api/v1/subscriptions/active': {
        code: 0,
        message: 'success',
        data: [
          {
            id: 10,
            group_name: 'Fallback',
            expires_at: '2026-05-01T00:00:00Z',
            monthly_used_usd: 1.5,
            monthly_limit_usd: 10,
          },
        ],
      },
    });

    const balance = await adapter.getBalance('https://sub2api.example.com', 'jwt-token');
    expect(balance.subscriptionSummary).toEqual({
      activeCount: 1,
      totalUsedUsd: 1.5,
      subscriptions: [
        {
          id: 10,
          groupName: 'Fallback',
          expiresAt: '2026-05-01T00:00:00.000Z',
          monthlyUsedUsd: 1.5,
          monthlyLimitUsd: 10,
        },
      ],
    });
  });

  it('preserves explicit zero activeCount from summary payload', async () => {
    const adapter = new MockSub2ApiAdapter({
      '/api/v1/auth/me': {
        code: 0,
        message: 'success',
        data: { id: 1, username: 'demo', email: 'demo@example.com', balance: 8.5 },
      },
      '/api/v1/subscriptions/summary': {
        code: 0,
        message: 'success',
        data: {
          active_count: 0,
          total_used_usd: 0,
          subscriptions: [
            {
              id: 11,
              group_name: 'Expired',
              status: 'expired',
            },
          ],
        },
      },
    });

    const balance = await adapter.getBalance('https://sub2api.example.com', 'jwt-token');
    expect(balance.subscriptionSummary).toEqual({
      activeCount: 0,
      totalUsedUsd: 0,
      subscriptions: [
        {
          id: 11,
          groupName: 'Expired',
          status: 'expired',
        },
      ],
    });
  });
});
