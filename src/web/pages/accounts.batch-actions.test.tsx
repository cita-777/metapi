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

async function flushMicrotasks() {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
  });
}

describe('Accounts batch actions', () => {
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

  it('refreshes balance for selected accounts through the batch toolbar', async () => {
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

      const checkboxA = root.root.find((node) => node.props['data-testid'] === 'account-select-1');
      const checkboxB = root.root.find((node) => node.props['data-testid'] === 'account-select-2');
      await act(async () => {
        checkboxA.props.onChange({ target: { checked: true } });
        checkboxB.props.onChange({ target: { checked: true } });
      });

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

  it('selects an account when clicking the row instead of only the checkbox', async () => {
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

      const row = root.root.find((node) => node.props['data-testid'] === 'account-row-1');
      await act(async () => {
        row.props.onClick({ target: { closest: () => null } });
      });
      await flushMicrotasks();

      const checkbox = root.root.find((node) => node.props['data-testid'] === 'account-select-1');
      expect(checkbox.props.checked).toBe(true);
    } finally {
      root?.unmount();
    }
  });

  it('selects an apikey connection when clicking the row in the apikey segment', async () => {
    apiMock.getAccounts.mockResolvedValue([
      {
        id: 1,
        siteId: 1,
        username: 'session-user',
        accessToken: 'session-alpha',
        apiToken: 'sk-session',
        credentialMode: 'session',
        status: 'active',
        site: { id: 1, name: 'Site A', status: 'active', platform: 'new-api' },
      },
      {
        id: 2,
        siteId: 1,
        username: '',
        accessToken: '',
        apiToken: 'sk-apikey',
        credentialMode: 'apikey',
        status: 'active',
        site: { id: 1, name: 'Site A', status: 'active', platform: 'new-api' },
      },
    ]);

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

      const row = root.root.find((node) => node.props['data-testid'] === 'account-row-2');
      await act(async () => {
        row.props.onClick({ target: { closest: () => null } });
      });
      await flushMicrotasks();

      const checkbox = root.root.find((node) => node.props['data-testid'] === 'account-select-2');
      expect(checkbox.props.checked).toBe(true);
    } finally {
      root?.unmount();
    }
  });
});
