import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, create, type ReactTestInstance } from 'react-test-renderer';
import { MemoryRouter } from 'react-router-dom';
import { ToastProvider } from '../components/Toast.js';
import Accounts from './Accounts.js';

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    getAccounts: vi.fn(),
    getSites: vi.fn(),
    refreshBalance: vi.fn(),
  },
}));

vi.mock('../api.js', () => ({
  api: apiMock,
}));

function collectText(node: ReactTestInstance): string {
  const children = node.children || [];
  return children.map((child) => {
    if (typeof child === 'string') return child;
    return collectText(child);
  }).join('');
}

async function flushMicrotasks() {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
  });
}

describe('Accounts refresh action', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('reloads account list even when refresh balance fails', async () => {
    apiMock.getAccounts
      .mockResolvedValueOnce([
        {
          id: 1,
          username: 'tester',
          balance: 100,
          balanceUsed: 0,
          todayReward: 0,
          todaySpend: 0,
          accessToken: 'session-token',
          status: 'active',
          checkinEnabled: true,
          site: { id: 10, name: 'Demo Site', status: 'active', url: 'https://example.com' },
          runtimeHealth: { state: 'healthy', reason: 'ok' },
        },
      ])
      .mockResolvedValueOnce([
        {
          id: 1,
          username: 'tester',
          balance: 100,
          balanceUsed: 0,
          todayReward: 0,
          todaySpend: 0,
          accessToken: 'session-token',
          status: 'expired',
          checkinEnabled: true,
          site: { id: 10, name: 'Demo Site', status: 'active', url: 'https://example.com' },
          runtimeHealth: { state: 'unhealthy', reason: '访问令牌失效' },
        },
      ]);
    apiMock.getSites.mockResolvedValue([{ id: 10, name: 'Demo Site', platform: 'new-api', status: 'active' }]);
    apiMock.refreshBalance.mockRejectedValueOnce(new Error('无权进行此操作，access token 无效'));

    let root!: WebTestRenderer;
    try {
      await act(async () => {
        root = create(
          <MemoryRouter initialEntries={['/accounts']}>
            <ToastProvider>
              <Accounts />
            </ToastProvider>
          </MemoryRouter>,
        );
      });
      await flushMicrotasks();

      const refreshButtons = root.root.findAll((node) => (
        node.type === 'button'
        && typeof node.props.onClick === 'function'
        && typeof node.props.className === 'string'
        && node.props.className.includes('btn-link-primary')
        && collectText(node).trim() === '刷新'
      ));
      expect(refreshButtons.length).toBeGreaterThan(0);
      const refreshButton = refreshButtons[0]!;

      await act(async () => {
        await refreshButton.props.onClick();
      });
      await flushMicrotasks();

      expect(apiMock.getAccounts).toHaveBeenCalledTimes(2);
      const rendered = JSON.stringify(root.toJSON());
      expect(rendered).toContain('异常');
    } finally {
      root?.unmount();
    }
  });
});
