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

vi.mock('../components/useIsMobile.js', () => ({
  useIsMobile: () => true,
}));

async function flushMicrotasks() {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
  });
}

describe('Tokens mobile actions', () => {
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
        updatedAt: '2026-03-21T10:00:00.000Z',
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
        updatedAt: '2026-03-21T11:00:00.000Z',
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

  it('supports select-all-visible and expandable mobile token details', async () => {
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

      const detailsButton = root.root
        .findAll((node) => node.type === 'button')
        .find((node) => Array.isArray(node.children) && node.children.includes('详情'));
      expect(detailsButton).toBeTruthy();

      await act(async () => {
        detailsButton!.props.onClick();
      });
      await flushMicrotasks();

      const selectAllButton = root.root.find((node) => node.props['data-testid'] === 'tokens-mobile-select-all');
      await act(async () => {
        selectAllButton.props.onClick();
      });
      await flushMicrotasks();
      expect(Array.isArray(selectAllButton.children) ? selectAllButton.children.join('') : '').toContain('取消全选');

      const clearVisibleButton = root.root.find((node) => node.props['data-testid'] === 'tokens-mobile-select-all');
      await act(async () => {
        clearVisibleButton.props.onClick();
      });
      await flushMicrotasks();
      expect(Array.isArray(clearVisibleButton.children) ? clearVisibleButton.children.join('') : '').toContain('全选可见项');

      const reselectVisibleButton = root.root.find((node) => node.props['data-testid'] === 'tokens-mobile-select-all');
      await act(async () => {
        reselectVisibleButton.props.onClick();
      });
      await flushMicrotasks();

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

      const expandedText = root.root.findAll(() => true)
        .flatMap((instance) => instance.children)
        .filter((child): child is string => typeof child === 'string')
        .join('');
      expect(expandedText).toContain('更新时间');
    } finally {
      root?.unmount();
    }
  });
});
