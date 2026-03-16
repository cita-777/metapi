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

function buildSummaryItem(overrides?: Partial<any>) {
  return {
    id: 1,
    name: 'smoke-key',
    keyMasked: 'sk-s****0315',
    enabled: true,
    description: 'local smoke',
    groupName: '项目A',
    tags: ['移动端', 'VIP'],
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

function buildRawItem(overrides?: Partial<any>) {
  return {
    id: 1,
    name: 'smoke-key',
    key: 'sk-smoke-0315',
    keyMasked: 'sk-s****0315',
    description: 'local smoke',
    groupName: '项目A',
    tags: ['移动端', 'VIP'],
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

beforeEach(() => {
  vi.clearAllMocks();
  (globalThis as any).document = {
    body: { style: {} },
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
  };
  apiMock.getDownstreamApiKeysSummary.mockResolvedValue({ success: true, items: [buildSummaryItem()] });
  apiMock.getDownstreamApiKeys.mockResolvedValue({ success: true, items: [buildRawItem()] });
  apiMock.getRoutesLite.mockResolvedValue([
    { id: 11, modelPattern: 'claude-*', displayName: '默认群组', enabled: true },
    { id: 12, modelPattern: 'gpt-4.1-mini', displayName: 'GPT 4.1 Mini', enabled: true },
  ]);
  apiMock.getDownstreamApiKeyOverview.mockResolvedValue({
    success: true,
    item: buildSummaryItem(),
    usage: {
      last24h: { totalRequests: 3, successRequests: 2, failedRequests: 1, successRate: 66.7, totalTokens: 4200, totalCost: 0.42 },
      last7d: { totalRequests: 9, successRequests: 8, failedRequests: 1, successRate: 88.9, totalTokens: 12400, totalCost: 1.24 },
      all: { totalRequests: 20, successRequests: 18, failedRequests: 2, successRate: 90, totalTokens: 55200, totalCost: 5.52 },
    },
  });
  apiMock.getDownstreamApiKeyTrend.mockResolvedValue({
    success: true,
    buckets: [
      { startUtc: '2026-03-15T08:00:00.000Z', totalRequests: 2, totalTokens: 1200, totalCost: 0.12, successRate: 100 },
      { startUtc: '2026-03-15T09:00:00.000Z', totalRequests: 1, totalTokens: 3000, totalCost: 0.3, successRate: 0 },
    ],
  });
  apiMock.createDownstreamApiKey.mockResolvedValue({ success: true });
  apiMock.batchDownstreamApiKeys.mockResolvedValue({ success: true, successIds: [1], failedItems: [] });
  apiMock.updateDownstreamApiKey.mockResolvedValue({ success: true });
  apiMock.deleteDownstreamApiKey.mockResolvedValue({ success: true });
  apiMock.resetDownstreamApiKeyUsage.mockResolvedValue({ success: true });
});

afterEach(() => {
  vi.clearAllMocks();
  delete (globalThis as any).document;
});

describe('DownstreamKeys page', () => {
  it('loads management data and renders merged row content', async () => {
    let root: ReturnType<typeof create> | null = null;
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

      expect(apiMock.getDownstreamApiKeysSummary).toHaveBeenCalledWith({ range: '24h' });
      expect(apiMock.getDownstreamApiKeys).toHaveBeenCalled();
      expect(apiMock.getRoutesLite).toHaveBeenCalled();

      const text = collectText(root!.root);
      expect(text).toContain('下游密钥');
      expect(text).toContain('范围概览');
      expect(text).toContain('筛选与列表');
      expect(text).toContain('smoke-key');
      expect(text).toContain('sk-s****0315');
      expect(text).toContain('默认群组');
      expect(text).toContain('4.2K');
      expect(text).toContain('主分组');
      expect(text).toContain('移动端');
    } finally {
      root?.unmount();
    }
  });

  it('filters rows locally by search and status', async () => {
    apiMock.getDownstreamApiKeysSummary.mockResolvedValue({
      success: true,
      items: [
        buildSummaryItem(),
        buildSummaryItem({ id: 2, name: 'batch-key', enabled: false, description: 'other project', keyMasked: 'sk-b****0315' }),
      ],
    });
    apiMock.getDownstreamApiKeys.mockResolvedValue({
      success: true,
      items: [
        buildRawItem(),
        buildRawItem({ id: 2, name: 'batch-key', enabled: false, description: 'other project', key: 'sk-batch-0315', keyMasked: 'sk-b****0315', supportedModels: ['gpt-4o-mini'], allowedRouteIds: [] }),
      ],
    });

    let root: ReturnType<typeof create> | null = null;
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

      const input = root!.root.findAllByType('input').find((node) => node.props.placeholder === '搜索名称、备注、模型、主分组或标签');
      await act(async () => {
        input!.props.onChange({ target: { value: 'batch' } });
      });
      await flushMicrotasks();
      expect(collectText(root!.root)).toContain('batch-key');
      expect(collectText(root!.root)).not.toContain('smoke-key');

      const select = root!.root.findAllByType('select').find((node) => collectText(node).includes('仅禁用'));
      await act(async () => {
        select.props.onChange({ target: { value: 'disabled' } });
      });
      await flushMicrotasks();
      expect(collectText(root!.root)).toContain('batch-key');
      expect(collectText(root!.root)).not.toContain('smoke-key');
    } finally {
      root?.unmount();
    }
  });

  it('supports create flow and drawer trend loading', async () => {
    let root: ReturnType<typeof create> | null = null;
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

      const createBtn = root!.root.findAll((node) => node.type === 'button' && collectText(node).includes('新增下游密钥'))[0];
      await act(async () => {
        createBtn.props.onClick();
      });
      await flushMicrotasks();

      expect(collectText(root!.root)).toContain('高级配置');
      expect(collectText(root!.root)).not.toContain('站点倍率 JSON');

      const inputs = root!.root.findAllByType('input');
      const tagInput = inputs.find((node) => node.props.placeholder === '输入标签后按回车或逗号，例如：移动端、VIP、项目A');
      const nameInput = inputs.find((node) => node.props.placeholder === '例如：项目 A / 移动端');
      const keyInput = inputs.find((node) => node.props.placeholder === 'sk-...');
      expect(tagInput?.props.style?.fontSize).toBe(13);
      await act(async () => {
        nameInput!.props.onChange({ target: { value: 'new-key' } });
        keyInput!.props.onChange({ target: { value: 'sk-new-key-0315' } });
      });
      await flushMicrotasks();

      const saveBtn = root!.root.findAll((node) => node.type === 'button' && collectText(node).includes('创建密钥'))[0];
      await act(async () => {
        saveBtn.props.onClick();
      });
      await flushMicrotasks();

      expect(apiMock.createDownstreamApiKey).toHaveBeenCalledWith(expect.objectContaining({
        name: 'new-key',
        key: 'sk-new-key-0315',
        siteWeightMultipliers: {},
      }));

      const row = root!.root.findAll((node) => node.type === 'tr' && typeof node.props.onClick === 'function')[0];
      await act(async () => {
        row.props.onClick();
      });
      await flushMicrotasks();

      expect(apiMock.getDownstreamApiKeyOverview).toHaveBeenCalledWith(1);
      expect(apiMock.getDownstreamApiKeyTrend).toHaveBeenCalledWith(1, { range: '24h' });
      expect(collectText(root!.root)).toContain('trend:2');

      const range7d = root!.root.findAll((node) => node.type === 'button' && collectText(node) === '7d')[0];
      await act(async () => {
        range7d.props.onClick();
      });
      await flushMicrotasks();

      expect(apiMock.getDownstreamApiKeyTrend).toHaveBeenCalledWith(1, { range: '7d' });
      expect(collectText(root!.root)).toContain('12.4K');
      expect(collectText(root!.root)).toContain('9');
      expect(collectText(root!.root)).toContain('88.9%');
    } finally {
      root?.unmount();
    }
  });

  it('does not refetch drawer trend repeatedly after a trend error toast', async () => {
    apiMock.getDownstreamApiKeyTrend
      .mockRejectedValueOnce(new Error('function date_trunc(unknown, text) does not exist'))
      .mockResolvedValue({
        success: true,
        buckets: [
          { startUtc: '2026-03-15T08:00:00.000Z', totalRequests: 2, totalTokens: 1200, totalCost: 0.12, successRate: 100 },
        ],
      });

    let root: ReturnType<typeof create> | null = null;
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

      const row = root!.root.findAll((node) => node.type === 'tr' && typeof node.props.onClick === 'function')[0];
      await act(async () => {
        row.props.onClick();
      });
      await flushMicrotasks();
      await flushMicrotasks();

      expect(apiMock.getDownstreamApiKeyOverview).toHaveBeenCalledTimes(1);
      expect(apiMock.getDownstreamApiKeyTrend).toHaveBeenCalledTimes(1);

      const toastMessages = root!.root.findAll((node) => {
        if (typeof node.props.className !== 'string') return false;
        return node.props.className.includes('toast-error') && collectText(node).includes('function date_trunc(unknown, text) does not exist');
      });
      expect(toastMessages).toHaveLength(1);
    } finally {
      root?.unmount();
    }
  });

  it('separates exact models from group routes in advanced config and uses single-column layout', async () => {
    let root: ReturnType<typeof create> | null = null;
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

      const createBtn = root!.root.findAll((node) => node.type === 'button' && collectText(node).includes('新增下游密钥'))[0];
      await act(async () => {
        createBtn.props.onClick();
      });
      await flushMicrotasks();

      const advancedBtn = root!.root.findAll((node) => node.type === 'button' && collectText(node).includes('高级配置'))[0];
      await act(async () => {
        advancedBtn.props.onClick();
      });
      await flushMicrotasks();

      const panels = root!.root.findAll((node) => node.props.className === 'downstream-key-advanced-panel');
      const modelPanel = panels.find((node) => collectText(node).includes('模型白名单'));
      const groupPanel = panels.find((node) => collectText(node).includes('群组范围'));
      const advancedGrid = root!.root.findAll((node) => node.props.className === 'downstream-key-advanced-grid')[0];

      expect(modelPanel).toBeTruthy();
      expect(groupPanel).toBeTruthy();
      expect(collectText(modelPanel!)).toContain('gpt-4.1-mini');
      expect(collectText(modelPanel!)).not.toContain('默认群组');
      expect(collectText(modelPanel!)).not.toContain('claude-*');
      expect(collectText(groupPanel!)).toContain('默认群组');
      expect(collectText(groupPanel!)).not.toContain('GPT 4.1 Mini');
      expect(advancedGrid.props.style?.gridTemplateColumns).toBe('1fr');
    } finally {
      root?.unmount();
    }
  });

  it('uses backend batch api for selected rows', async () => {
    let root: ReturnType<typeof create> | null = null;
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

      const checkbox = root!.root.findAllByType('input').find((node) => node.props.type === 'checkbox' && typeof node.props.onChange === 'function' && node.props.checked === false);
      await act(async () => {
        checkbox!.props.onChange({ target: { checked: true } });
      });
      await flushMicrotasks();
      expect(collectText(root!.root)).toContain('已选 1 个密钥');

      const batchButton = root!.root.findAll((node) => node.type === 'button' && collectText(node).includes('批量启用'))[0];
      await act(async () => {
        batchButton.props.onClick();
      });
      await flushMicrotasks();

      expect(apiMock.batchDownstreamApiKeys).toHaveBeenCalledWith({
        ids: [1],
        action: 'enable',
      });
    } finally {
      root?.unmount();
    }
  });

  it('supports group and tag editing plus batch metadata update', async () => {
    let root: ReturnType<typeof create> | null = null;
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

      const createBtn = root!.root.findAll((node) => node.type === 'button' && collectText(node).includes('新增下游密钥'))[0];
      await act(async () => {
        createBtn.props.onClick();
      });
      await flushMicrotasks();

      const advancedBtn = root!.root.findAll((node) => node.type === 'button' && collectText(node).includes('高级配置'))[0];
      await act(async () => {
        advancedBtn.props.onClick();
      });
      await flushMicrotasks();

      const inputs = root!.root.findAllByType('input');
      const nameInput = inputs.find((node) => node.props.placeholder === '例如：项目 A / 移动端');
      const keyInput = inputs.find((node) => node.props.placeholder === 'sk-...');
      const groupInput = inputs.find((node) => node.props.placeholder === '例如：VIP / 内部项目 / A组');
      const tagInput = inputs.find((node) => node.props.placeholder === '输入标签后按回车或逗号，例如：移动端、VIP、项目A');
      await act(async () => {
        nameInput!.props.onChange({ target: { value: 'grouped-key' } });
        keyInput!.props.onChange({ target: { value: 'sk-grouped-key-0315' } });
        groupInput!.props.onChange({ target: { value: '项目B' } });
        tagInput!.props.onChange({ target: { value: '灰度,高优' } });
      });
      await flushMicrotasks();
      await act(async () => {
        tagInput!.props.onKeyDown({ key: 'Enter', preventDefault: vi.fn() });
      });
      await flushMicrotasks();

      const saveBtn = root!.root.findAll((node) => node.type === 'button' && collectText(node).includes('创建密钥'))[0];
      await act(async () => {
        saveBtn.props.onClick();
      });
      await flushMicrotasks();

      expect(apiMock.createDownstreamApiKey).toHaveBeenCalledWith(expect.objectContaining({
        groupName: '项目B',
        tags: ['灰度', '高优'],
      }));

      const checkbox = root!.root.findAllByType('input').find((node) => node.props.type === 'checkbox' && typeof node.props.onChange === 'function' && node.props.checked === false);
      await act(async () => {
        checkbox!.props.onChange({ target: { checked: true } });
      });
      await flushMicrotasks();

      const batchMetadataBtn = root!.root.findAll((node) => node.type === 'button' && collectText(node).includes('批量归类/标签'))[0];
      await act(async () => {
        batchMetadataBtn.props.onClick();
      });
      await flushMicrotasks();

      const groupModeSelect = root!.root.findAllByType('select').find((node) => Array.isArray(node.props.children) && collectText(node).includes('统一设为主分组'));
      const tagModeSelect = root!.root.findAllByType('select').find((node) => Array.isArray(node.props.children) && collectText(node).includes('追加标签'));
      await act(async () => {
        groupModeSelect!.props.onChange({ target: { value: 'set' } });
        tagModeSelect!.props.onChange({ target: { value: 'append' } });
      });
      await flushMicrotasks();

      const batchGroupInput = root!.root.findAllByType('input').find((node) => node.props.placeholder === '例如：VIP / 内部项目');
      const batchTagInput = root!.root.findAllByType('input').find((node) => node.props.placeholder === '批量追加标签');
      await act(async () => {
        batchGroupInput!.props.onChange({ target: { value: '统一项目组' } });
        batchTagInput!.props.onChange({ target: { value: '批量标签' } });
      });
      await flushMicrotasks();
      await act(async () => {
        batchTagInput!.props.onKeyDown({ key: 'Enter', preventDefault: vi.fn() });
      });
      await flushMicrotasks();

      const applyBtn = root!.root.findAll((node) => node.type === 'button' && collectText(node).includes('应用到所选密钥'))[0];
      await act(async () => {
        applyBtn.props.onClick();
      });
      await flushMicrotasks();

      expect(apiMock.batchDownstreamApiKeys).toHaveBeenCalledWith(expect.objectContaining({
        ids: [1],
        action: 'updateMetadata',
        groupOperation: 'set',
        groupName: '统一项目组',
        tagOperation: 'append',
        tags: ['批量标签'],
      }));
    } finally {
      root?.unmount();
    }
  });
});
