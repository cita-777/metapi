import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, create } from 'react-test-renderer';
import { ToastProvider } from '../components/Toast.js';
import Dashboard from './Dashboard.js';

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    getDashboard: vi.fn(),
    getSiteDistribution: vi.fn(),
    getSiteTrend: vi.fn(),
    getSites: vi.fn(),
    getAccounts: vi.fn(),
    getAccountTokens: vi.fn(),
    getRoutes: vi.fn(),
    startTestChatJob: vi.fn(),
    getTestChatJob: vi.fn(),
  },
}));

vi.mock('../api.js', () => ({
  api: apiMock,
}));

describe('Dashboard hook order', () => {
  let consoleErrorSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    apiMock.getSiteDistribution.mockResolvedValue({ distribution: [] });
    apiMock.getSiteTrend.mockResolvedValue({ trend: [] });
    apiMock.getSites.mockResolvedValue([]);
    apiMock.getAccounts.mockResolvedValue([]);
    apiMock.getAccountTokens.mockResolvedValue([]);
    apiMock.getRoutes.mockResolvedValue([]);
  });

  afterEach(() => {
    consoleErrorSpy.mockRestore();
    vi.clearAllMocks();
  });

  it('keeps hook order stable when switching from loading to loaded render', async () => {
    let root!: WebTestRenderer;
    let renderedTree = '';
    const dashboardData = {
      totalBalance: 0,
      totalUsed: 0,
      todaySpend: 0,
      todayReward: 0,
      activeAccounts: 0,
      totalAccounts: 0,
      todayCheckin: { success: 0, total: 0 },
      proxy24h: { success: 0, total: 0, totalTokens: 0 },
      modelAnalysis: null,
    };
    let resolveFirstDashboard: ((value: typeof dashboardData) => void) | null = null;

    apiMock.getDashboard.mockImplementation(() => {
      if (!resolveFirstDashboard) {
        return new Promise((resolve) => {
          resolveFirstDashboard = resolve as (value: typeof dashboardData) => void;
        });
      }
      return Promise.resolve(dashboardData);
    });

    try {
      await act(async () => {
        root = create(
          <ToastProvider>
            <Dashboard />
          </ToastProvider>,
        );
      });

      await act(async () => {
        resolveFirstDashboard?.(dashboardData);
        await Promise.resolve();
      });

      renderedTree = JSON.stringify(root?.toJSON() ?? null);
    } finally {
      root?.unmount();
    }

    const errorOutput = consoleErrorSpy.mock.calls
      .map((args) => args.map((item) => String(item)).join(' '))
      .join('\n');

    expect(errorOutput).not.toContain('change in the order of Hooks called by Dashboard');
    expect(renderedTree).not.toContain('快速上手');
  });
});
