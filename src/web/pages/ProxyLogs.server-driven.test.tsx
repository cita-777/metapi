import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, create, type ReactTestInstance } from 'react-test-renderer';
import { MemoryRouter } from 'react-router-dom';
import { ToastProvider } from '../components/Toast.js';
import ProxyLogs from './ProxyLogs.js';

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    getProxyLogs: vi.fn(),
    getProxyLogDetail: vi.fn(),
    getSites: vi.fn(),
  },
}));

vi.mock('../api.js', () => ({
  api: apiMock,
}));

function collectText(node: ReactTestInstance): string {
  return (node.children || []).map((child) => {
    if (typeof child === 'string') return child;
    return collectText(child);
  }).join('');
}

async function flushMicrotasks() {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();
  });
}

function buildListResponse(overrides?: Partial<{
  items: any[];
  total: number;
  page: number;
  pageSize: number;
  summary: {
    totalCount: number;
    successCount: number;
    failedCount: number;
    totalCost: number;
    totalTokensAll: number;
  };
}>) {
  return {
    items: [
      {
        id: 101,
        createdAt: '2026-03-09 16:00:00',
        modelRequested: 'gpt-4o',
        modelActual: 'gpt-4o',
        status: 'success',
        latencyMs: 120,
        promptTokens: 10,
        completionTokens: 5,
        totalTokens: 15,
        retryCount: 0,
        estimatedCost: 1.23,
        errorMessage: 'downstream: /v1/chat upstream: /api/chat',
        username: 'tester',
        siteName: 'main-site',
        siteUrl: 'https://main-site.example.com',
      },
    ],
    total: 1,
    page: 1,
    pageSize: 50,
    summary: {
      totalCount: 12,
      successCount: 8,
      failedCount: 4,
      totalCost: 1.23,
      totalTokensAll: 15,
    },
    ...overrides,
  };
}

describe('ProxyLogs server-driven page', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    apiMock.getSites.mockResolvedValue([
      { id: 9, name: 'main-site', status: 'active' },
      { id: 12, name: 'backup-site', status: 'active' },
    ]);
    apiMock.getProxyLogs.mockResolvedValue(buildListResponse());
    apiMock.getProxyLogDetail.mockResolvedValue({
      id: 101,
      createdAt: '2026-03-09 16:00:00',
      modelRequested: 'gpt-4o',
      modelActual: 'gpt-4o',
      status: 'success',
      latencyMs: 120,
      promptTokens: 10,
      completionTokens: 5,
      totalTokens: 15,
      retryCount: 0,
      estimatedCost: 1.23,
      errorMessage: 'downstream: /v1/chat upstream: /api/chat',
      username: 'tester',
      siteName: 'main-site',
      siteUrl: 'https://main-site.example.com',
      billingDetails: {
        breakdown: {
          inputPerMillion: 1,
          outputPerMillion: 2,
          cacheReadPerMillion: 0,
          cacheCreationPerMillion: 0,
          inputCost: 0.1,
          outputCost: 0.2,
          cacheReadCost: 0,
          cacheCreationCost: 0,
          totalCost: 0.3,
        },
        pricing: {
          modelRatio: 1,
          completionRatio: 1,
          cacheRatio: 0,
          cacheCreationRatio: 0,
          groupRatio: 1,
        },
        usage: {
          promptTokens: 10,
          completionTokens: 5,
          totalTokens: 15,
          cacheReadTokens: 0,
          cacheCreationTokens: 0,
          billablePromptTokens: 10,
          promptTokensIncludeCache: false,
        },
      },
    });
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('requests paginated data from the server and renders server summary counts', async () => {
    let root: ReturnType<typeof create> | null = null;

    try {
      await act(async () => {
        root = create(
          <MemoryRouter initialEntries={['/logs']}>
            <ToastProvider>
              <ProxyLogs />
            </ToastProvider>
          </MemoryRouter>,
        );
      });
      await flushMicrotasks();

      expect(apiMock.getProxyLogs).toHaveBeenCalledWith({
        limit: 50,
        offset: 0,
        status: 'all',
        search: '',
      });

      const text = collectText(root!.root);
      expect(text).toContain('消耗总额 $1.2300');
      expect(text).toContain('全部 12');
      expect(text).toContain('成功 8');
      expect(text).toContain('失败 4');
    } finally {
      root?.unmount();
    }
  });

  it('re-queries the server for status and search changes instead of filtering locally', async () => {
    let root: ReturnType<typeof create> | null = null;

    try {
      await act(async () => {
        root = create(
          <MemoryRouter initialEntries={['/logs']}>
            <ToastProvider>
              <ProxyLogs />
            </ToastProvider>
          </MemoryRouter>,
        );
      });
      await flushMicrotasks();

      const failedTab = root!.root.findAll((node) => (
        node.type === 'button' && collectText(node).includes('失败')
      ))[0];
      await act(async () => {
        failedTab.props.onClick();
      });
      await flushMicrotasks();

      const searchInput = root!.root.find((node) => (
        node.type === 'input' && node.props.placeholder === '搜索模型名称...'
      ));
      await act(async () => {
        searchInput.props.onChange({ target: { value: 'mini' } });
      });
      await flushMicrotasks();

      expect(apiMock.getProxyLogs).toHaveBeenNthCalledWith(2, {
        limit: 50,
        offset: 0,
        status: 'failed',
        search: '',
      });
      expect(apiMock.getProxyLogs).toHaveBeenLastCalledWith({
        limit: 50,
        offset: 0,
        status: 'failed',
        search: 'mini',
      });
    } finally {
      root?.unmount();
    }
  });

  it('loads detail on first expand and reuses the cached detail on re-expand', async () => {
    let root: ReturnType<typeof create> | null = null;

    try {
      await act(async () => {
        root = create(
          <MemoryRouter initialEntries={['/logs']}>
            <ToastProvider>
              <ProxyLogs />
            </ToastProvider>
          </MemoryRouter>,
        );
      });
      await flushMicrotasks();

      const row = root!.root.find((node) => (
        node.type === 'tr' && node.props['data-testid'] === 'proxy-log-row-101'
      ));

      await act(async () => {
        row.props.onClick();
      });
      await flushMicrotasks();

      expect(apiMock.getProxyLogDetail).toHaveBeenCalledTimes(1);

      await act(async () => {
        row.props.onClick();
      });
      await flushMicrotasks();

      await act(async () => {
        row.props.onClick();
      });
      await flushMicrotasks();

      expect(apiMock.getProxyLogDetail).toHaveBeenCalledTimes(1);
      expect(apiMock.getProxyLogDetail).toHaveBeenCalledWith(101);
    } finally {
      root?.unmount();
    }
  });

  it('hydrates site and time filters from the route query', async () => {
    let root: ReturnType<typeof create> | null = null;

    try {
      await act(async () => {
        root = create(
          <MemoryRouter initialEntries={['/logs?siteId=9&from=2026-03-09T08:00&to=2026-03-09T09:00']}>
            <ToastProvider>
              <ProxyLogs />
            </ToastProvider>
          </MemoryRouter>,
        );
      });
      await flushMicrotasks();

      const expectedFrom = new Date(2026, 2, 9, 8, 0).toISOString();
      const expectedTo = new Date(2026, 2, 9, 9, 0).toISOString();
      expect(apiMock.getProxyLogs).toHaveBeenCalledWith({
        limit: 50,
        offset: 0,
        status: 'all',
        search: '',
        siteId: 9,
        from: expectedFrom,
        to: expectedTo,
      });

      const rendered = JSON.stringify(root!.toJSON());
      expect(rendered).toContain('main-site');
    } finally {
      root?.unmount();
    }
  });
});
