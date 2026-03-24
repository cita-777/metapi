import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, create } from 'react-test-renderer';
import { MemoryRouter } from 'react-router-dom';
import { ToastProvider } from '../components/Toast.js';
import { TokensPanel } from './Tokens.js';

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    getAccountTokens: vi.fn(),
    getAccounts: vi.fn(),
    getAccountTokenGroups: vi.fn(),
    batchUpdateAccountTokens: vi.fn(),
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

describe('Tokens batch actions', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    apiMock.getAccountTokens.mockResolvedValue([
      {
        id: 1,
        accountId: 1,
        name: 'token-1',
        tokenMasked: 'sk-***1',
        enabled: true,
        isDefault: false,
        account: { username: 'alpha' },
        site: { name: 'Site A', url: 'https://site-a.example.com' },
      },
      {
        id: 2,
        accountId: 1,
        name: 'token-2',
        tokenMasked: 'sk-***2',
        enabled: true,
        isDefault: false,
        account: { username: 'alpha' },
        site: { name: 'Site A', url: 'https://site-a.example.com' },
      },
    ]);
    apiMock.getAccounts.mockResolvedValue([
      {
        id: 1,
        username: 'alpha',
        accessToken: 'session-alpha',
        status: 'active',
        site: { id: 1, name: 'Site A', status: 'active' },
      },
    ]);
    apiMock.getAccountTokenGroups.mockResolvedValue({ groups: ['default'] });
    apiMock.batchUpdateAccountTokens.mockResolvedValue({
      success: true,
      successIds: [1, 2],
      failedItems: [],
    });
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('deletes selected tokens through the batch toolbar', async () => {
    let root!: WebTestRenderer;
    try {
      await act(async () => {
        root = create(
          <ToastProvider>
            <MemoryRouter initialEntries={['/accounts?segment=tokens']}>
              <TokensPanel />
            </MemoryRouter>
          </ToastProvider>,
        );
      });
      await flushMicrotasks();

      const checkboxA = root.root.find((node) => node.props['data-testid'] === 'token-select-1');
      const checkboxB = root.root.find((node) => node.props['data-testid'] === 'token-select-2');
      await act(async () => {
        checkboxA.props.onChange({ target: { checked: true } });
        checkboxB.props.onChange({ target: { checked: true } });
      });

      const batchButton = root.root.find((node) => node.props['data-testid'] === 'tokens-batch-delete');
      await act(async () => {
        batchButton.props.onClick();
      });
      await flushMicrotasks();

      const confirmButton = root.root
        .findAll((node) => node.type === 'button')
        .find((node) => Array.isArray(node.children) && node.children.some((child) => child === '确认删除'));
      expect(confirmButton).toBeTruthy();

      await act(async () => {
        confirmButton!.props.onClick();
      });
      await flushMicrotasks();

      expect(apiMock.batchUpdateAccountTokens).toHaveBeenCalledWith({
        ids: [1, 2],
        action: 'delete',
      });
    } finally {
      root?.unmount();
    }
  });

  it('selects a token when clicking the row instead of only the checkbox', async () => {
    let root!: WebTestRenderer;
    try {
      await act(async () => {
        root = create(
          <ToastProvider>
            <MemoryRouter initialEntries={['/accounts?segment=tokens']}>
              <TokensPanel />
            </MemoryRouter>
          </ToastProvider>,
        );
      });
      await flushMicrotasks();

      const row = root.root.find((node) => node.props['data-testid'] === 'token-row-1');
      await act(async () => {
        row.props.onClick({ target: { closest: () => null } });
      });
      await flushMicrotasks();

      const checkbox = root.root.find((node) => node.props['data-testid'] === 'token-select-1');
      expect(checkbox.props.checked).toBe(true);
    } finally {
      root?.unmount();
    }
  });
});
