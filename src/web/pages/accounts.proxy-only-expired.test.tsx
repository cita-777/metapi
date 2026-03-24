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

describe('Accounts proxy-only expired state', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('does not show session-expired health copy or rebind action for proxy-only accounts', async () => {
    apiMock.getAccounts.mockResolvedValue([
      {
        id: 1,
        username: '',
        balance: 0,
        balanceUsed: 0,
        todayReward: 0,
        todaySpend: 0,
        accessToken: 'api-key-only-token',
        status: 'expired',
        checkinEnabled: false,
        capabilities: {
          canCheckin: false,
          canRefreshBalance: false,
          proxyOnly: true,
        },
        siteId: 10,
        site: { id: 10, name: '小呆api', status: 'active', url: 'https://example.com' },
      },
    ]);
    apiMock.getSites.mockResolvedValue([{ id: 10, name: '小呆api', platform: 'new-api', status: 'active' }]);

    let root!: WebTestRenderer;
    try {
      await act(async () => {
        root = create(
          <MemoryRouter initialEntries={['/accounts?segment=apikey']}>
            <ToastProvider>
              <Accounts />
            </ToastProvider>
          </MemoryRouter>,
        );
      });
      await flushMicrotasks();

      const rendered = JSON.stringify(root.toJSON());
      expect(rendered).not.toContain('仅代理');
      expect(rendered).not.toContain('访问令牌已过期');

      const actionTexts = root.root.findAll((node) => node.type === 'button').map((node) => collectText(node));
      expect(actionTexts).not.toContain('重新绑定');
    } finally {
      root?.unmount();
    }
  });
});
