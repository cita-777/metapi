import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, create } from 'react-test-renderer';
import { MemoryRouter } from 'react-router-dom';
import { ToastProvider } from '../components/Toast.js';
import Sites from './Sites.js';

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    getSites: vi.fn(),
    batchUpdateSites: vi.fn(),
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

describe('Sites mobile actions', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    apiMock.getSites.mockResolvedValue([
      {
        id: 1,
        name: 'Site A',
        url: 'https://a.example.com',
        platform: 'new-api',
        status: 'active',
        useSystemProxy: false,
      },
      {
        id: 2,
        name: 'Site B',
        url: 'https://b.example.com',
        platform: 'new-api',
        status: 'active',
        useSystemProxy: false,
      },
    ]);
    apiMock.batchUpdateSites.mockResolvedValue({
      success: true,
      successIds: [1, 2],
      failedItems: [],
    });
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('supports select-all-visible and preserves the primary site url in mobile cards', async () => {
    let root!: WebTestRenderer;
    try {
      await act(async () => {
        root = create(
          <MemoryRouter initialEntries={['/sites']}>
            <ToastProvider>
              <Sites />
            </ToastProvider>
          </MemoryRouter>,
        );
      });
      await flushMicrotasks();

      const selectAllButton = root.root.find((node) => node.props['data-testid'] === 'sites-mobile-select-all');
      await act(async () => {
        selectAllButton.props.onClick();
      });
      await flushMicrotasks();
      expect(Array.isArray(selectAllButton.children) ? selectAllButton.children.join('') : '').toContain('取消全选');

      const clearVisibleButton = root.root.find((node) => node.props['data-testid'] === 'sites-mobile-select-all');
      await act(async () => {
        clearVisibleButton.props.onClick();
      });
      await flushMicrotasks();
      expect(Array.isArray(clearVisibleButton.children) ? clearVisibleButton.children.join('') : '').toContain('全选可见项');

      const reselectVisibleButton = root.root.find((node) => node.props['data-testid'] === 'sites-mobile-select-all');
      await act(async () => {
        reselectVisibleButton.props.onClick();
      });
      await flushMicrotasks();

      const batchButton = root.root.find((node) => node.props['data-testid'] === 'sites-batch-enable-system-proxy');
      await act(async () => {
        batchButton.props.onClick();
      });
      await flushMicrotasks();

      expect(apiMock.batchUpdateSites).toHaveBeenCalledWith({
        ids: [1, 2],
        action: 'enableSystemProxy',
      });

      const primaryLink = root.root.find((node) => node.type === 'a' && node.props.href === 'https://a.example.com');
      expect(primaryLink.props.target).toBe('_blank');
    } finally {
      root?.unmount();
    }
  });
});
