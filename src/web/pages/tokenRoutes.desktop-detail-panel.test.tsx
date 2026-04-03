import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, create, type ReactTestInstance, type ReactTestRenderer } from 'react-test-renderer';
import { MemoryRouter } from 'react-router-dom';
import { ToastProvider } from '../components/Toast.js';
import TokenRoutes, { DesktopDetailPanelPresence } from './TokenRoutes.js';

const { apiMock, getBrandMock } = vi.hoisted(() => ({
  apiMock: {
    getRoutesSummary: vi.fn(),
    getRouteChannels: vi.fn(),
    getModelTokenCandidates: vi.fn(),
    getRouteDecision: vi.fn(),
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
  useIsMobile: () => false,
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

describe('TokenRoutes desktop detail panel', () => {
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
      {
        id: 2,
        modelPattern: 'claude-3.7-sonnet',
        displayName: 'claude-3.7-sonnet',
        displayIcon: null,
        modelMapping: null,
        routingStrategy: 'weighted',
        enabled: true,
        channelCount: 1,
        enabledChannelCount: 1,
        siteNames: ['site-b'],
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
        site: { id: 1, name: 'site-a', platform: 'openai' },
        token: { id: 1001, name: 'token-a', accountId: 101, enabled: true, isDefault: true },
      },
    ]);
    apiMock.getModelTokenCandidates.mockResolvedValue({ models: {} });
    apiMock.getRouteDecision.mockResolvedValue({ decision: null });
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

  it('keeps summary cards stable and opens a separate desktop detail panel', async () => {
    let root!: ReactTestRenderer;

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

      expect(root.root.findAll((node) => (
        node.type === 'div'
        && String(node.props.className || '').includes('route-card-collapsed')
      ))).toHaveLength(2);

      const firstSummaryCard = root.root.find((node) => (
        node.type === 'div'
        && String(node.props.className || '').includes('route-card-collapsed')
        && collectText(node).includes('gpt-4o-mini')
      ));

      await act(async () => {
        await firstSummaryCard.props.onClick();
      });
      await flushMicrotasks();

      const collapsedCardsAfterExpand = root.root.findAll((node) => (
        node.type === 'div'
        && String(node.props.className || '').includes('route-card-collapsed')
      ));
      expect(collapsedCardsAfterExpand).toHaveLength(2);

      const detailPanels = root.root.findAll((node) => (
        node.type === 'div'
        && String(node.props.className || '').includes('route-card-detail-panel')
      ));
      expect(detailPanels).toHaveLength(1);
      const detailPanelText = collectText(detailPanels[0]!);
      expect(detailPanelText).toContain('gpt-4o-mini');
      expect(detailPanelText).toContain('路由策略');
    } finally {
      root?.unmount();
    }
  });

  it('animates the desktop detail panel closed before unmounting it', async () => {
    vi.useFakeTimers();
    let root!: ReactTestRenderer;

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

      const firstSummaryCard = root.root.find((node) => (
        node.type === 'div'
        && String(node.props.className || '').includes('route-card-collapsed')
        && collectText(node).includes('gpt-4o-mini')
      ));

      await act(async () => {
        await firstSummaryCard.props.onClick();
      });
      await flushMicrotasks();

      const closeButton = root.root.find((node) => (
        node.type === 'button'
        && collectText(node).includes('收起详情')
      ));

      await act(async () => {
        await closeButton.props.onClick();
      });
      await flushMicrotasks();

      let detailPanelPresence = root.root.findAll((node) => (
        node.type === 'div'
        && String(node.props.className || '').includes('route-detail-panel-presence')
      ));
      expect(detailPanelPresence).toHaveLength(1);
      expect(String(detailPanelPresence[0]!.props.className || '')).toContain('anim-collapse');
      expect(String(detailPanelPresence[0]!.props.className || '')).not.toContain('is-open');
      expect(String(detailPanelPresence[0]!.props.className || '')).toContain('is-closing');
      const detailPanelsWhileClosing = root.root.findAll((node) => (
        node.type === 'div'
        && String(node.props.className || '').includes('route-card-detail-panel')
      ));
      expect(detailPanelsWhileClosing).toHaveLength(1);
      const summaryCardWhileClosing = root.root.find((node) => (
        node.type === 'div'
        && String(node.props.className || '').includes('route-card-collapsed')
        && collectText(node).includes('gpt-4o-mini')
      ));
      expect(String(summaryCardWhileClosing.props.className || '')).toContain('is-active');

      await act(async () => {
        vi.advanceTimersByTime(260);
      });

      detailPanelPresence = root.root.findAll((node) => (
        node.type === 'div'
        && String(node.props.className || '').includes('route-detail-panel-presence')
      ));
      expect(detailPanelPresence).toHaveLength(0);
      const summaryCardAfterClosing = root.root.find((node) => (
        node.type === 'div'
        && String(node.props.className || '').includes('route-card-collapsed')
        && collectText(node).includes('gpt-4o-mini')
      ));
      expect(String(summaryCardAfterClosing.props.className || '')).not.toContain('is-active');
    } finally {
      root?.unmount();
      vi.useRealTimers();
    }
  });

  it('does not schedule a close timer before the desktop detail panel has ever opened', async () => {
    vi.useFakeTimers();
    const setTimeoutSpy = vi.spyOn(globalThis, 'setTimeout');
    let root!: ReactTestRenderer;

    try {
      await act(async () => {
        root = create(
          <DesktopDetailPanelPresence open={false}>
            {() => <div>detail</div>}
          </DesktopDetailPanelPresence>,
        );
      });
      await flushMicrotasks();

      expect(root.toJSON()).toBeNull();
      expect(setTimeoutSpy).not.toHaveBeenCalled();
    } finally {
      root?.unmount();
      vi.useRealTimers();
    }
  });
});
