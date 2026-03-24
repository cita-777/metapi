import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, create, type ReactTestInstance } from 'react-test-renderer';
import { MemoryRouter } from 'react-router-dom';
import { ToastProvider } from '../components/Toast.js';
import DownstreamKeys from './DownstreamKeys.js';

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    getDownstreamApiKeysSummary: vi.fn(),
    getDownstreamApiKeys: vi.fn(),
    getRoutesLite: vi.fn(),
    getDownstreamApiKeyOverview: vi.fn(),
    getDownstreamApiKeyTrend: vi.fn(),
    createDownstreamApiKey: vi.fn(),
    batchDownstreamApiKeys: vi.fn(),
    updateDownstreamApiKey: vi.fn(),
    deleteDownstreamApiKey: vi.fn(),
    resetDownstreamApiKeyUsage: vi.fn(),
  },
}));

vi.mock('../api.js', () => ({ api: apiMock }));

vi.mock('react-dom', async () => {
  const actual = await vi.importActual<typeof import('react-dom')>('react-dom');
  return {
    ...actual,
    createPortal: (node: unknown) => node,
  };
});

vi.mock('../components/useAnimatedVisibility.js', () => ({
  useAnimatedVisibility: (open: boolean) => ({
    shouldRender: open,
    isVisible: open,
  }),
}));

vi.mock('../components/useIsMobile.js', () => ({
  useIsMobile: () => true,
}));

vi.mock('../components/charts/DownstreamKeyTrendChart.js', () => ({
  default: ({ buckets }: { buckets: Array<{ totalTokens: number }> }) => (
    <div data-testid="downstream-trend-chart">{`trend:${buckets.length}`}</div>
  ),
}));

vi.mock('../components/ModernSelect.js', () => ({
  default: ({ value, onChange, options }: { value: string; onChange: (value: string) => void; options: Array<{ value: string; label: string }> }) => (
    <select value={value} onChange={(e) => onChange(e.target.value)}>
      {options.map((option) => (
        <option key={option.value} value={option.value}>{option.label}</option>
      ))}
    </select>
  ),
}));

function buildSummaryItem(id: number, overrides?: Partial<any>) {
  return {
    id,
    name: `mobile-key-${id}`,
    keyMasked: `sk-m****0${id}`,
    enabled: true,
    description: `mobile item ${id}`,
    groupName: '项目A',
    tags: ['移动端'],
    expiresAt: null,
    maxCost: null,
    usedCost: 0,
    maxRequests: null,
    usedRequests: 0,
    supportedModels: ['gpt-4.1-mini'],
    allowedRouteIds: [11],
    siteWeightMultipliers: {},
    lastUsedAt: '2026-03-15T08:27:25.378Z',
    createdAt: '2026-03-15T08:27:25.378Z',
    updatedAt: '2026-03-15T08:27:25.378Z',
    rangeUsage: {
      totalRequests: 3,
      successRequests: 2,
      failedRequests: 1,
      successRate: 66.7,
      totalTokens: 4200,
      totalCost: 0.42,
    },
    ...overrides,
  };
}

function buildRawItem(id: number, overrides?: Partial<any>) {
  return {
    id,
    name: `mobile-key-${id}`,
    key: `sk-mobile-0${id}`,
    keyMasked: `sk-m****0${id}`,
    description: `mobile item ${id}`,
    groupName: '项目A',
    tags: ['移动端'],
    enabled: true,
    expiresAt: null,
    maxCost: null,
    usedCost: 0,
    maxRequests: null,
    usedRequests: 0,
    supportedModels: ['gpt-4.1-mini'],
    allowedRouteIds: [11],
    siteWeightMultipliers: {},
    lastUsedAt: '2026-03-15T08:27:25.378Z',
    ...overrides,
  };
}

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
    && collectText(node) === text
  ));
}

async function flushMicrotasks() {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();
  });
}

describe('DownstreamKeys mobile layout', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (globalThis as any).document = {
      body: { style: {} },
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
    };

    apiMock.getDownstreamApiKeysSummary.mockResolvedValue({
      success: true,
      items: [buildSummaryItem(1), buildSummaryItem(2)],
    });
    apiMock.getDownstreamApiKeys.mockResolvedValue({
      success: true,
      items: [buildRawItem(1), buildRawItem(2)],
    });
    apiMock.getRoutesLite.mockResolvedValue([
      { id: 11, modelPattern: 'claude-*', displayName: '默认群组', enabled: true },
    ]);
    apiMock.getDownstreamApiKeyOverview.mockResolvedValue({
      success: true,
      item: buildSummaryItem(1),
      usage: {
        last24h: { totalRequests: 3, successRequests: 2, failedRequests: 1, successRate: 66.7, totalTokens: 4200, totalCost: 0.42 },
        last7d: { totalRequests: 9, successRequests: 8, failedRequests: 1, successRate: 88.9, totalTokens: 12400, totalCost: 1.24 },
        all: { totalRequests: 20, successRequests: 18, failedRequests: 2, successRate: 90, totalTokens: 55200, totalCost: 5.52 },
      },
    });
    apiMock.getDownstreamApiKeyTrend.mockResolvedValue({
      success: true,
      buckets: [],
    });
    apiMock.createDownstreamApiKey.mockResolvedValue({ success: true });
    apiMock.batchDownstreamApiKeys.mockResolvedValue({ success: true, successIds: [1, 2], failedItems: [] });
    apiMock.updateDownstreamApiKey.mockResolvedValue({ success: true });
    apiMock.deleteDownstreamApiKey.mockResolvedValue({ success: true });
    apiMock.resetDownstreamApiKeyUsage.mockResolvedValue({ success: true });
  });

  afterEach(() => {
    vi.clearAllMocks();
    delete (globalThis as any).document;
  });

  it('renders mobile cards and supports select-all-visible batch actions', async () => {
    let root!: WebTestRenderer;

    try {
      await act(async () => {
        root = create(
          <MemoryRouter initialEntries={['/downstream-keys']}>
            <ToastProvider>
              <DownstreamKeys />
            </ToastProvider>
          </MemoryRouter>,
        );
      });
      await flushMicrotasks();

      expect(collectText(root!.root)).toContain('筛选');
      expect(collectText(root!.root)).toContain('全选可见');

      const mobileCards = root!.root.findAll((node) => node.props?.className === 'mobile-card');
      expect(mobileCards).toHaveLength(2);

      const selectAllButton = findButtonByText(root!.root, '全选可见');
      await act(async () => {
        selectAllButton.props.onClick();
      });
      await flushMicrotasks();

      const batchEnableButton = findButtonByText(root!.root, '启用');
      await act(async () => {
        batchEnableButton.props.onClick();
      });
      await flushMicrotasks();

      expect(apiMock.batchDownstreamApiKeys).toHaveBeenCalledWith({
        ids: [1, 2],
        action: 'enable',
      });
    } finally {
      root?.unmount();
    }
  });
});
