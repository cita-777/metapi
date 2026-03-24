import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, create } from 'react-test-renderer';
import { MemoryRouter } from 'react-router-dom';
import { ToastProvider } from '../components/Toast.js';
import Accounts from './Accounts.js';

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    getAccounts: vi.fn(),
    getSites: vi.fn(),
    batchUpdateAccounts: vi.fn(),
    refreshAccountHealth: vi.fn(),
  },
}));

vi.mock('../api.js', () => ({
  api: apiMock,
}));

vi.mock('../components/useIsMobile.js', () => ({
  useIsMobile: () => true,
}));

async function flushMicrotasks() {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
  });
}

function collectText(node: any): string {
  return (node.children || []).map((child: any) => {
    if (typeof child === 'string') return child;
    return collectText(child);
  }).join('');
}

function findButtonByText(root: any, text: string) {
  return root.find((node: any) => (
    node.type === 'button'
    && typeof node.props.onClick === 'function'
    && collectText(node).includes(text)
  ));
}

describe('Accounts mobile actions', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    apiMock.getSites.mockResolvedValue([
      { id: 1, name: 'Site A', platform: 'new-api', status: 'active' },
    ]);
    apiMock.getAccounts.mockResolvedValue([
      {
        id: 1,
        siteId: 1,
        username: 'alpha',
        accessToken: 'session-alpha',
        status: 'active',
        site: { id: 1, name: 'Site A', status: 'active', platform: 'new-api' },
      },
      {
        id: 2,
        siteId: 1,
        username: 'beta',
        accessToken: 'session-beta',
        status: 'active',
        site: { id: 1, name: 'Site A', status: 'active', platform: 'new-api' },
      },
    ]);
    apiMock.batchUpdateAccounts.mockResolvedValue({
      success: true,
      successIds: [1, 2],
      failedItems: [],
    });
    apiMock.refreshAccountHealth.mockResolvedValue({ success: true });
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('supports select-all-visible from the mobile toolbar', async () => {
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

      const selectAllButton = root.root.find((node) => node.props['data-testid'] === 'accounts-mobile-select-all');
      await act(async () => {
        selectAllButton.props.onClick();
      });
      await flushMicrotasks();

      const batchButton = root.root.find((node) => node.props['data-testid'] === 'accounts-batch-refresh-balance');
      await act(async () => {
        batchButton.props.onClick();
      });
      await flushMicrotasks();

      expect(apiMock.batchUpdateAccounts).toHaveBeenCalledWith({
        ids: [1, 2],
        action: 'refreshBalance',
      });
    } finally {
      root?.unmount();
    }
  });

  it('clears only the visible segment selection when toggling mobile select-all off', async () => {
    let root!: WebTestRenderer;
    try {
      apiMock.getAccounts.mockResolvedValue([
        {
          id: 1,
          siteId: 1,
          username: 'alpha',
          accessToken: 'session-alpha',
          status: 'active',
          site: { id: 1, name: 'Site A', status: 'active', platform: 'new-api' },
        },
        {
          id: 2,
          siteId: 1,
          username: 'beta',
          accessToken: '',
          status: 'active',
          site: { id: 1, name: 'Site A', status: 'active', platform: 'new-api' },
        },
      ]);

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

      const sessionCheckbox = root.root.find((node) => (
        node.type === 'input'
        && node.props.type === 'checkbox'
        && node.props['aria-label'] === '选择账号 alpha'
      ));
      await act(async () => {
        sessionCheckbox.props.onChange({ target: { checked: true } });
      });
      await flushMicrotasks();

      const apiKeySegmentButton = findButtonByText(root.root, 'API Key管理');
      await act(async () => {
        apiKeySegmentButton.props.onClick();
      });
      await flushMicrotasks();

      const selectAllButton = root.root.find((node) => node.props['data-testid'] === 'accounts-mobile-select-all');
      await act(async () => {
        selectAllButton.props.onClick();
      });
      await flushMicrotasks();
      expect(collectText(root.root)).toContain('已选 2 项');

      const clearVisibleButton = root.root.find((node) => node.props['data-testid'] === 'accounts-mobile-select-all');
      await act(async () => {
        clearVisibleButton.props.onClick();
      });
      await flushMicrotasks();

      expect(collectText(root.root)).toContain('已选 1 项');

      const batchButton = root.root.find((node) => node.props['data-testid'] === 'accounts-batch-refresh-balance');
      await act(async () => {
        batchButton.props.onClick();
      });
      await flushMicrotasks();

      expect(apiMock.batchUpdateAccounts).toHaveBeenLastCalledWith({
        ids: [1],
        action: 'refreshBalance',
      });
    } finally {
      root?.unmount();
    }
  });
});
