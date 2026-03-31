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
  },
  getBrandMock: vi.fn(),
}));

vi.mock('../api.js', () => ({
  api: apiMock,
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

describe('TokenRoutes routing strategy updates', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getBrandMock.mockReset();
    getBrandMock.mockReturnValue(null);
    apiMock.getRoutesSummary
      .mockResolvedValue([
        {
          id: 1,
          modelPattern: 'gpt-4o-mini',
          displayName: 'gpt-4o-mini',
          displayIcon: null,
          modelMapping: null,
          routingStrategy: 'weighted',
          enabled: true,
          channelCount: 0,
          enabledChannelCount: 0,
          siteNames: [],
          decisionSnapshot: null,
          decisionRefreshedAt: null,
        },
      ]);
    apiMock.getRouteChannels.mockResolvedValue([]);
    apiMock.getModelTokenCandidates.mockResolvedValue({ models: {} });
    apiMock.getRouteDecisionsBatch.mockResolvedValue({ decisions: {} });
    apiMock.getRouteWideDecisionsBatch.mockResolvedValue({ decisions: {} });
    apiMock.updateRoute.mockResolvedValue({});
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('keeps the optimistic routing strategy when refresh fails after a successful save', async () => {
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

      const expandButton = root.root.find((node) => (
        node.type === 'div'
        && String(node.props.className || '').includes('route-card-collapsed')
      ));
      await act(async () => {
        expandButton.props.onClick();
      });
      await flushMicrotasks();

      apiMock.getRoutesSummary.mockRejectedValueOnce(new Error('refresh failed'));

      const roundRobinOption = root.root.find((node) => (
        node.type === 'button'
        && typeof node.props.className === 'string'
        && node.props.className.includes('modern-select-option')
        && collectText(node).startsWith('轮询')
      ));

      await act(async () => {
        roundRobinOption.props.onClick();
      });
      await flushMicrotasks();

      expect(apiMock.updateRoute).toHaveBeenCalledWith(1, { routingStrategy: 'round_robin' });
      expect(apiMock.getRoutesSummary).toHaveBeenCalledTimes(2);

      const strategyTrigger = root.root.find((node) => (
        node.type === 'button'
        && typeof node.props.className === 'string'
        && node.props.className.includes('modern-select-trigger')
        && collectText(node).includes('轮询')
      ));
      expect(collectText(strategyTrigger)).toContain('轮询');
    } finally {
      root?.unmount();
    }
  });

  it('supports switching to stable_first and keeps the optimistic label when refresh fails', async () => {
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

      const expandButton = root.root.find((node) => (
        node.type === 'div'
        && String(node.props.className || '').includes('route-card-collapsed')
      ));
      await act(async () => {
        expandButton.props.onClick();
      });
      await flushMicrotasks();

      apiMock.getRoutesSummary.mockRejectedValueOnce(new Error('refresh failed'));

      const stableFirstOption = root.root.find((node) => (
        node.type === 'button'
        && typeof node.props.className === 'string'
        && node.props.className.includes('modern-select-option')
        && collectText(node).startsWith('稳定优先')
      ));

      await act(async () => {
        stableFirstOption.props.onClick();
      });
      await flushMicrotasks();

      expect(apiMock.updateRoute).toHaveBeenCalledWith(1, { routingStrategy: 'stable_first' });

      const strategyTrigger = root.root.find((node) => (
        node.type === 'button'
        && typeof node.props.className === 'string'
        && node.props.className.includes('modern-select-trigger')
        && collectText(node).startsWith('稳定优先')
      ));
      expect(collectText(strategyTrigger)).toContain('稳定优先');
    } finally {
      root?.unmount();
    }
  });
});
