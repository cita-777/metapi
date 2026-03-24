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
    updateRoute: vi.fn(),
    rebuildRoutes: vi.fn(),
    deleteRoute: vi.fn(),
    deleteChannel: vi.fn(),
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

async function flushMicrotasks() {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
  });
}

describe('TokenRoutes mobile layout', () => {
  const originalIntersectionObserver = globalThis.IntersectionObserver;

  beforeEach(() => {
    vi.clearAllMocks();
    globalThis.IntersectionObserver = class {
      observe() {}
      disconnect() {}
      unobserve() {}
      takeRecords() { return []; }
      readonly root = null;
      readonly rootMargin = '0px';
      readonly thresholds = [];
    } as unknown as typeof IntersectionObserver;
    getBrandMock.mockReset();
    getBrandMock.mockReturnValue(null);
    apiMock.getRoutesSummary.mockResolvedValue([
      {
        id: 1,
        modelPattern: 'gpt-4o-mini',
        displayName: 'gpt-4o-mini',
        displayIcon: null,
        modelMapping: null,
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
    apiMock.getModelTokenCandidates.mockResolvedValue({
      models: {
        'gpt-4o-mini': [
          {
            accountId: 101,
            tokenId: 1001,
            tokenName: 'token-a',
            isDefault: true,
            username: 'user_a',
            siteId: 1,
            siteName: 'site-a',
          },
        ],
      },
    });
    apiMock.getRouteDecisionsBatch.mockResolvedValue({ decisions: {} });
    apiMock.getRouteWideDecisionsBatch.mockResolvedValue({ decisions: {} });
    apiMock.updateRoute.mockResolvedValue({});
    apiMock.rebuildRoutes.mockResolvedValue({ rebuild: { createdRoutes: 0, createdChannels: 0 } });
    apiMock.deleteRoute.mockResolvedValue({});
    apiMock.deleteChannel.mockResolvedValue({});
  });

  afterEach(() => {
    vi.clearAllMocks();
    globalThis.IntersectionObserver = originalIntersectionObserver;
  });

  it('shows direct mobile actions and reveals the management panel after expansion', async () => {
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

      const summaryText = collectText(root!.root);
      expect(summaryText).toContain('详情');
      expect(summaryText).toContain('禁用');
      expect(summaryText).toContain('添加通道');

      const expandButton = root!.root.find((node) => (
        node.type === 'button'
        && typeof node.props.onClick === 'function'
        && collectText(node) === '详情'
      ));

      await act(async () => {
        await expandButton.props.onClick();
      });
      await flushMicrotasks();

      const expandedText = collectText(root!.root);
      expect(expandedText).toContain('路由策略');
      expect(expandedText).toContain('权重随机');
      expect(expandedText).toContain('user_a');
      expect(expandedText).toContain('token-a');
    } finally {
      root?.unmount();
    }
  });

  it('lets mobile users toggle route enabled state from the summary card', async () => {
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

      const toggleButton = root!.root.find((node) => (
        node.type === 'button'
        && typeof node.props.onClick === 'function'
        && collectText(node) === '禁用'
      ));

      await act(async () => {
        await toggleButton.props.onClick();
      });
      await flushMicrotasks();

      expect(apiMock.updateRoute).toHaveBeenCalledWith(1, { enabled: false });
      expect(collectText(root!.root)).toContain('启用');
    } finally {
      root?.unmount();
    }
  });
});
