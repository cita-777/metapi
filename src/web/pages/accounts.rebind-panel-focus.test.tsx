import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, create, type ReactTestInstance } from 'react-test-renderer';
import { MemoryRouter } from 'react-router-dom';
import { ToastProvider } from '../components/Toast.js';
import Accounts from './Accounts.js';

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    getAccounts: vi.fn(),
    getSites: vi.fn(),
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

describe('Accounts rebind modal', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('opens centered rebind modal when clicking rebind action', async () => {
    apiMock.getAccounts.mockResolvedValue([
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
        siteId: 10,
        site: { id: 10, name: 'Demo Site', status: 'active', url: 'https://example.com' },
        runtimeHealth: { state: 'unhealthy', reason: '访问令牌失效' },
      },
    ]);
    apiMock.getSites.mockResolvedValue([{ id: 10, name: 'Demo Site', platform: 'new-api', status: 'active' }]);

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

      const rebindButton = root.root.find((node) => (
        node.type === 'button'
        && typeof node.props.onClick === 'function'
        && collectText(node).trim() === '重新绑定'
      ));

      await act(async () => {
        rebindButton.props.onClick();
      });
      await flushMicrotasks();

      const modal = root.root.find((node) => (
        node.type === 'div'
        && typeof node.props.className === 'string'
        && node.props.className.includes('modal-content')
      ));
      expect(String(modal.props.className)).toContain('modal-content');
      expect(JSON.stringify(root.toJSON())).toContain('重新绑定 Session Token');
      expect(JSON.stringify(root.toJSON())).toContain('粘贴新的 Session Token');
    } finally {
      root?.unmount();
    }
  });
});
