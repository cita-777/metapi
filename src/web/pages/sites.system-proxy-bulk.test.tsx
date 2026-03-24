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

async function flushMicrotasks() {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
  });
}

describe('Sites system proxy bulk actions', () => {
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

  it('sends selected site ids to enable system proxy', async () => {
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

      const checkboxA = root.root.find((node) => node.props['data-testid'] === 'site-select-1');
      const checkboxB = root.root.find((node) => node.props['data-testid'] === 'site-select-2');

      await act(async () => {
        checkboxA.props.onChange({ target: { checked: true } });
        checkboxB.props.onChange({ target: { checked: true } });
      });

      const batchButton = root.root.find((node) => node.props['data-testid'] === 'sites-batch-enable-system-proxy');
      await act(async () => {
        batchButton.props.onClick();
      });
      await flushMicrotasks();

      expect(apiMock.batchUpdateSites).toHaveBeenCalledWith({
        ids: [1, 2],
        action: 'enableSystemProxy',
      });
    } finally {
      root?.unmount();
    }
  });

  it('selects a site when clicking the row instead of only the checkbox', async () => {
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

      const row = root.root.find((node) => node.props['data-testid'] === 'site-row-1');
      await act(async () => {
        row.props.onClick({ target: { closest: () => null } });
      });
      await flushMicrotasks();

      const checkbox = root.root.find((node) => node.props['data-testid'] === 'site-select-1');
      expect(checkbox.props.checked).toBe(true);
    } finally {
      root?.unmount();
    }
  });
});
