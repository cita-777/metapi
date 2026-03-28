import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, create, type ReactTestInstance } from 'react-test-renderer';
import { MemoryRouter } from 'react-router-dom';
import { ToastProvider } from '../components/Toast.js';
import TokenRoutes from './TokenRoutes.js';

const { apiMock, getBrandMock } = vi.hoisted(() => ({
  apiMock: {
    getRoutesSummary: vi.fn(),
    getRouteChannels: vi.fn(),
    getModelTokenCandidates: vi.fn(),
    getRouteDecisionsBatch: vi.fn(),
    getRouteWideDecisionsBatch: vi.fn(),
    batchUpdateRoutes: vi.fn(),
    updateRoute: vi.fn(),
    addRoute: vi.fn(),
  },
  getBrandMock: vi.fn(),
}));

vi.mock('../api.js', () => ({
  api: apiMock,
}));

vi.mock('react-dom', async () => {
  const actual = await vi.importActual<typeof import('react-dom')>('react-dom');
  return {
    ...actual,
    createPortal: (node: unknown) => node,
  };
});

vi.mock('../components/useIsMobile.js', () => ({
  useIsMobile: () => true,
}));

vi.mock('../components/BrandIcon.js', () => ({
  BrandGlyph: ({ brand, icon, model }: { brand?: { name?: string } | null; icon?: string | null; model?: string | null }) => (
    <span>{brand?.name || icon || model || ''}</span>
  ),
  InlineBrandIcon: ({ model }: { model: string }) => model ? <span>{model}</span> : null,
  getBrand: (...args: unknown[]) => getBrandMock(...args),
  hashColor: () => 'linear-gradient(135deg,#4f46e5,#818cf8)',
  normalizeBrandIconKey: (icon: string) => icon,
}));

function collectText(node: ReactTestInstance): string {
  return (node.children || []).map((child) => {
    if (typeof child === 'string') return child;
    return collectText(child);
  }).join('');
}

function findButtonByText(root: ReactTestInstance, text: string): ReactTestInstance {
  return root.find((node) => (
    node.type === 'button'
    && typeof node.props.onClick === 'function'
    && collectText(node).includes(text)
  ));
}

async function flushMicrotasks() {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
  });
}

describe('TokenRoutes mobile actions', () => {
  const originalIntersectionObserver = globalThis.IntersectionObserver;
  const originalWindow = (globalThis as { window?: { confirm?: (message?: string) => boolean } }).window;

  beforeEach(() => {
    vi.clearAllMocks();
    getBrandMock.mockReset();
    getBrandMock.mockReturnValue(null);
    globalThis.IntersectionObserver = class {
      observe() {}
      disconnect() {}
      unobserve() {}
    } as unknown as typeof IntersectionObserver;

    apiMock.getRoutesSummary.mockResolvedValue([
      {
        id: 1,
        modelPattern: 'gpt-4o-mini',
        displayName: 'gpt-4o-mini',
        displayIcon: null,
        modelMapping: null,
        routeMode: 'pattern',
        routingStrategy: 'weighted',
        enabled: true,
        channelCount: 1,
        enabledChannelCount: 1,
        siteNames: ['site-a'],
        decisionSnapshot: null,
        decisionRefreshedAt: null,
      },
    ]);
    apiMock.getRouteChannels.mockResolvedValue([
      {
        id: 11,
        accountId: 101,
        tokenId: 1001,
        sourceModel: 'gpt-4o-mini',
        priority: 0,
        weight: 1,
        enabled: true,
        manualOverride: false,
        successCount: 0,
        failCount: 0,
        account: { username: 'user_a' },
        site: { name: 'site-a' },
        token: { id: 1001, name: 'token-a', accountId: 101, enabled: true, isDefault: true },
      },
    ]);
    apiMock.getModelTokenCandidates.mockResolvedValue({ models: {} });
    apiMock.getRouteDecisionsBatch.mockResolvedValue({ decisions: {} });
    apiMock.getRouteWideDecisionsBatch.mockResolvedValue({ decisions: {} });
    apiMock.batchUpdateRoutes.mockResolvedValue({ success: true, updatedCount: 1 });
    apiMock.updateRoute.mockResolvedValue({});
    apiMock.addRoute.mockResolvedValue({});
    (globalThis as { window?: { confirm?: (message?: string) => boolean } }).window = {
      ...(originalWindow || {}),
      confirm: vi.fn(() => true),
    };
  });

  afterEach(() => {
    vi.clearAllMocks();
    globalThis.IntersectionObserver = originalIntersectionObserver;
    if (originalWindow) {
      (globalThis as { window?: { confirm?: (message?: string) => boolean } }).window = originalWindow;
    } else {
      delete (globalThis as { window?: { confirm?: (message?: string) => boolean } }).window;
    }
  });

  it('shows mobile detail expansion and direct management actions', async () => {
    let root!: WebTestRenderer;

    try {
      await act(async () => {
        root = create(
          <MemoryRouter initialEntries={['/routes']}>
            <ToastProvider>
              <TokenRoutes />
            </ToastProvider>
          </MemoryRouter>,
        );
      });
      await flushMicrotasks();

      expect(collectText(root!.root)).toContain('筛选');
      expect(collectText(root!.root)).toContain('详情');
      expect(collectText(root!.root)).toContain('编辑');
      expect(collectText(root!.root)).toContain('添加通道');

      const disableButton = findButtonByText(root!.root, '禁用');
      await act(async () => {
        disableButton.props.onClick();
      });
      await flushMicrotasks();

      expect(apiMock.updateRoute).toHaveBeenCalledWith(1, { enabled: false });

      const detailButton = findButtonByText(root!.root, '详情');
      await act(async () => {
        detailButton.props.onClick();
      });
      await flushMicrotasks();

      const text = collectText(root!.root);
      expect(text).toContain('user_a');
      expect(text).toContain('token-a');
      expect(text).toContain('site-a');
    } finally {
      root?.unmount();
    }
  });

  it('lets mobile users select a route and batch disable it', async () => {
    let root!: WebTestRenderer;

    try {
      await act(async () => {
        root = create(
          <MemoryRouter initialEntries={['/routes']}>
            <ToastProvider>
              <TokenRoutes />
            </ToastProvider>
          </MemoryRouter>,
        );
      });
      await flushMicrotasks();

      const batchModeButton = findButtonByText(root!.root, '批量操作');
      await act(async () => {
        batchModeButton.props.onClick();
      });
      await flushMicrotasks();

      const routeCheckbox = root!.root.find((node) => (
        node.type === 'input'
        && node.props.type === 'checkbox'
        && node.props['data-testid'] === 'route-select-1'
      ));

      await act(async () => {
        routeCheckbox.props.onChange({ target: { checked: true } });
      });
      await flushMicrotasks();

      const batchDisableButton = findButtonByText(root!.root, '批量禁用');
      await act(async () => {
        batchDisableButton.props.onClick();
      });
      await flushMicrotasks();

      expect(globalThis.window.confirm).toHaveBeenCalledWith('确认批量禁用 1 条路由？');
      expect(apiMock.batchUpdateRoutes).toHaveBeenCalledWith({ ids: [1], action: 'disable' });
      expect(collectText(root!.root)).toContain('批量操作');
    } finally {
      root?.unmount();
    }
  });
});
