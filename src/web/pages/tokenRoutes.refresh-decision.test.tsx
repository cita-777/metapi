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

describe('TokenRoutes refresh decision action', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getBrandMock.mockReset();
    getBrandMock.mockReturnValue(null);
    apiMock.getRoutesSummary.mockResolvedValue([
      {
        id: 1, modelPattern: 'gpt-4o-mini', displayName: 'gpt-4o-mini',
        displayIcon: null, modelMapping: null, enabled: true,
        channelCount: 0, enabledChannelCount: 0, siteNames: [],
        decisionSnapshot: null, decisionRefreshedAt: null,
      },
      {
        id: 2, modelPattern: 're:^claude-(opus|sonnet)-4-6$', displayName: 'claude-group',
        displayIcon: null, modelMapping: null, enabled: true,
        channelCount: 0, enabledChannelCount: 0, siteNames: [],
        decisionSnapshot: null, decisionRefreshedAt: null,
      },
    ]);
    apiMock.getRouteChannels.mockResolvedValue([]);
    apiMock.getModelTokenCandidates.mockResolvedValue({ models: {} });
    apiMock.getRouteDecisionsBatch.mockResolvedValue({ decisions: {} });
    apiMock.getRouteWideDecisionsBatch.mockResolvedValue({ decisions: {} });
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('passes refreshPricingCatalog and persistSnapshots when user clicks refresh selection probability', async () => {
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

      const refreshButton = findButtonByText(root.root, '刷新选中概率');
      await act(async () => {
        await refreshButton.props.onClick();
      });
      await flushMicrotasks();

      expect(apiMock.getRouteDecisionsBatch).toHaveBeenCalledWith(['gpt-4o-mini'], { refreshPricingCatalog: true, persistSnapshots: true });
      expect(apiMock.getRouteWideDecisionsBatch).toHaveBeenCalledWith([2], { refreshPricingCatalog: true, persistSnapshots: true });
    } finally {
      root?.unmount();
    }
  });
});
