import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, create, type ReactTestInstance, type ReactTestRenderer } from 'react-test-renderer';
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

describe('TokenRoutes cached snapshot load', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getBrandMock.mockReset();
    getBrandMock.mockReturnValue(null);
    apiMock.getModelTokenCandidates.mockResolvedValue({ models: {} });
    apiMock.getRouteDecisionsBatch.mockResolvedValue({ decisions: {} });
    apiMock.getRouteWideDecisionsBatch.mockResolvedValue({ decisions: {} });
    apiMock.getRoutesSummary.mockResolvedValue([
      {
        id: 1,
        modelPattern: 'gpt-4o-mini',
        displayName: 'gpt-4o-mini',
        displayIcon: null,
        modelMapping: null,
        enabled: true,
        channelCount: 1,
        enabledChannelCount: 1,
        siteNames: ['cached-site'],
        decisionSnapshot: {
          requestedModel: 'gpt-4o-mini',
          actualModel: 'gpt-4o-mini',
          matched: true,
          selectedChannelId: 11,
          selectedLabel: 'cached-user @ cached-site / cached-token',
          summary: ['命中路由：gpt-4o-mini'],
          candidates: [
            {
              channelId: 11,
              accountId: 101,
              username: 'cached-user',
              siteName: 'cached-site',
              tokenName: 'cached-token',
              priority: 0,
              weight: 10,
              eligible: true,
              recentlyFailed: false,
              avoidedByRecentFailure: false,
              probability: 88.8,
              reason: '缓存命中',
            },
          ],
        },
        decisionRefreshedAt: '2026-03-08T01:23:45.000Z',
      },
    ]);
    apiMock.getRouteChannels.mockResolvedValue([
      {
        id: 11,
        accountId: 101,
        tokenId: 1001,
        sourceModel: 'gpt-4o-mini',
        priority: 0,
        weight: 10,
        enabled: true,
        manualOverride: false,
        successCount: 0,
        failCount: 0,
        account: { username: 'cached-user' },
        site: { name: 'cached-site' },
        token: { id: 1001, name: 'cached-token', accountId: 101, enabled: true, isDefault: true },
      },
    ]);
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('shows cached probabilities immediately from getRoutes snapshot data', async () => {
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

      expect(collectText(root.root)).toContain('已缓存');

      // Expand the route card to see channel details with probability
      const expandBtn = root.root.find((node) =>
        node.type === 'div' && String(node.props.className || '').includes('route-card-collapsed'),
      );
      await act(async () => {
        expandBtn.props.onClick();
      });
      await flushMicrotasks();

      const text = collectText(root.root);
      expect(text).toContain('88.8%');
      expect(text).toContain('cached-user');
    } finally {
      root?.unmount();
    }
  });

  it('keeps showing the cached snapshot marker after revisiting the page', async () => {
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
      expect(collectText(root.root)).toContain('已缓存');

      root.unmount();

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

      expect(collectText(root.root)).toContain('已缓存');
    } finally {
      root?.unmount();
    }
  });
});
