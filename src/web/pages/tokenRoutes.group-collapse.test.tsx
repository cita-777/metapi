import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, create, type ReactTestInstance } from 'react-test-renderer';
import { MemoryRouter } from 'react-router-dom';
import { ToastProvider } from '../components/Toast.js';
import TokenRoutes from './TokenRoutes.js';
import { ROUTE_ICON_NONE_VALUE } from './token-routes/utils.js';

const { apiMock, getBrandMock } = vi.hoisted(() => ({
  apiMock: {
    getRoutesSummary: vi.fn(),
    getRouteChannels: vi.fn(),
    getModelTokenCandidates: vi.fn(),
    getRouteDecisionsBatch: vi.fn(),
    getRouteWideDecisionsBatch: vi.fn(),
    updateRoute: vi.fn(),
    addRoute: vi.fn(),
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
  const children = node.children || [];
  return children.map((child) => {
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

function findButtonByClassAndText(root: ReactTestInstance, className: string, text: string): ReactTestInstance {
  return root.find((node) => (
    node.type === 'button'
    && typeof node.props.onClick === 'function'
    && String(node.props.className || '').includes(className)
    && collectText(node).includes(text)
  ));
}

function findButtonByAriaLabel(root: ReactTestInstance, label: string): ReactTestInstance {
  return root.find((node) => (
    node.type === 'button'
    && typeof node.props['aria-label'] === 'string'
    && node.props['aria-label'] === label
  ));
}

function findInputByPlaceholder(root: ReactTestInstance, placeholderText: string): ReactTestInstance {
  return root.find((node) => (
    node.type === 'input'
    && typeof node.props.placeholder === 'string'
    && node.props.placeholder.includes(placeholderText)
  ));
}

function findCheckboxByLabelText(root: ReactTestInstance, text: string): ReactTestInstance {
  return root.find((node) => (
    node.type === 'input'
    && node.props.type === 'checkbox'
    && !!node.parent
    && collectText(node.parent).includes(text)
  ));
}

async function flushMicrotasks() {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
  });
}

describe('TokenRoutes grouped source models', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getBrandMock.mockReset();
    getBrandMock.mockReturnValue(null);
    apiMock.getModelTokenCandidates.mockResolvedValue({ models: {} });
    apiMock.getRouteChannels.mockResolvedValue([]);
    apiMock.getRouteDecisionsBatch.mockResolvedValue({ decisions: {} });
    apiMock.getRouteWideDecisionsBatch.mockResolvedValue({ decisions: {} });
    apiMock.updateRoute.mockResolvedValue({});
    apiMock.addRoute.mockResolvedValue({});
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('does not treat bracket-prefixed exact model routes as group filters', async () => {
    apiMock.getRoutesSummary.mockResolvedValue([
      {
        id: 4386, modelPattern: '[NV]deepseek-v3.1-terminus', displayName: null,
        displayIcon: null, modelMapping: null, enabled: true,
        channelCount: 1, enabledChannelCount: 1, siteNames: ['test'],
        decisionSnapshot: null, decisionRefreshedAt: null,
      },
      {
        id: 3383, modelPattern: 're:^claude-(opus|sonnet)-4-5$', displayName: 'claude-opus-4-6',
        displayIcon: null, modelMapping: null, enabled: true,
        channelCount: 4, enabledChannelCount: 4, siteNames: ['site-a', 'site-b'],
        decisionSnapshot: null, decisionRefreshedAt: null,
      },
    ]);

    let root: ReturnType<typeof create> | null = null;
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

      const filterToggle = findButtonByText(root.root, '筛选');
      await act(async () => {
        filterToggle.props.onClick();
      });
      await flushMicrotasks();

      const text = collectText(root.root);
      expect(text).toContain('全部群组1');

      const bracketGroupButtons = root.root.findAll((node) => (
        node.type === 'button'
        && collectText(node).includes('[NV]deepseek-v3.1-terminus')
      ));
      expect(bracketGroupButtons).toHaveLength(0);
    } finally {
      root?.unmount();
    }
  });

  it('collapses source-model groups by default for wildcard routes', async () => {
    const channels = [
      {
        id: 11, accountId: 101, tokenId: 1001, sourceModel: 'claude-opus-4-5',
        priority: 0, weight: 1, enabled: true, manualOverride: false,
        successCount: 0, failCount: 0,
        account: { username: 'user_a' }, site: { name: 'site-a' },
        token: { id: 1001, name: 'token-a', accountId: 101, enabled: true, isDefault: true },
      },
      {
        id: 12, accountId: 102, tokenId: 1002, sourceModel: 'claude-opus-4-6',
        priority: 0, weight: 1, enabled: true, manualOverride: false,
        successCount: 0, failCount: 0,
        account: { username: 'user_b' }, site: { name: 'site-b' },
        token: { id: 1002, name: 'token-b', accountId: 102, enabled: true, isDefault: true },
      },
    ];
    apiMock.getRoutesSummary.mockResolvedValue([
      {
        id: 1, modelPattern: 're:^claude-opus-(4-6|4-5)$', displayName: 'claude-opus-4-6',
        displayIcon: null, modelMapping: null, enabled: true,
        channelCount: 2, enabledChannelCount: 2, siteNames: ['site-a', 'site-b'],
        decisionSnapshot: null, decisionRefreshedAt: null,
      },
    ]);
    apiMock.getRouteChannels.mockResolvedValue(channels);

    let root: ReturnType<typeof create> | null = null;
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

      // Card is collapsed by default, so channel detail is not visible
      const text = collectText(root.root);
      expect(text).toContain('claude-opus-4-6');
      expect(text).not.toContain('user_a');
      expect(text).not.toContain('user_b');

      // Expand the card to load channels
      const expandBtn = root.root.find((node) =>
        node.type === 'div' && String(node.props.className || '').includes('route-card-collapsed'),
      );
      await act(async () => {
        expandBtn.props.onClick();
      });
      await flushMicrotasks();

      // After expansion, source models are visible but groups collapsed for wildcard
      const expandedText = collectText(root.root);
      expect(expandedText).toContain('claude-opus-4-5');
      expect(expandedText).toContain('claude-opus-4-6');
      // Users are inside collapsed source groups
      expect(expandedText).not.toContain('user_a');
      expect(expandedText).not.toContain('user_b');
    } finally {
      root?.unmount();
    }
  });

  it('expands a source-model group after user click', async () => {
    const channels = [
      {
        id: 11, accountId: 101, tokenId: 1001, sourceModel: 'claude-opus-4-5',
        priority: 0, weight: 1, enabled: true, manualOverride: false,
        successCount: 0, failCount: 0,
        account: { username: 'user_a' }, site: { name: 'site-a' },
        token: { id: 1001, name: 'token-a', accountId: 101, enabled: true, isDefault: true },
      },
    ];
    apiMock.getRoutesSummary.mockResolvedValue([
      {
        id: 1, modelPattern: 're:^claude-opus-(4-6|4-5)$', displayName: 'claude-opus-4-6',
        displayIcon: null, modelMapping: null, enabled: true,
        channelCount: 1, enabledChannelCount: 1, siteNames: ['site-a'],
        decisionSnapshot: null, decisionRefreshedAt: null,
      },
    ]);
    apiMock.getRouteChannels.mockResolvedValue(channels);

    let root: ReturnType<typeof create> | null = null;
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

      // Expand the card first
      const expandBtn = root.root.find((node) =>
        node.type === 'div' && String(node.props.className || '').includes('route-card-collapsed'),
      );
      await act(async () => {
        expandBtn.props.onClick();
      });
      await flushMicrotasks();

      expect(collectText(root.root)).not.toContain('user_a');

      const toggleButton = findButtonByText(root.root, 'claude-opus-4-5');
      await act(async () => {
        toggleButton.props.onClick();
      });
      await flushMicrotasks();

      expect(collectText(root.root)).toContain('user_a');
    } finally {
      root?.unmount();
    }
  });

  it('renders missing-token site tags with interactive hover class', async () => {
    apiMock.getRoutesSummary.mockResolvedValue([
      {
        id: 1, modelPattern: 'gpt-5.2-codex', displayName: 'gpt-5.2-codex',
        displayIcon: null, modelMapping: null, enabled: true,
        channelCount: 0, enabledChannelCount: 0, siteNames: [],
        decisionSnapshot: null, decisionRefreshedAt: null,
      },
    ]);
    apiMock.getModelTokenCandidates.mockResolvedValue({
      models: {},
      modelsWithoutToken: {
        'gpt-5.2-codex': [
          { accountId: 101, username: 'linuxdo_11494', siteId: 11, siteName: 'Wong' },
        ],
      },
    });
    apiMock.getRouteChannels.mockResolvedValue([]);

    let root: ReturnType<typeof create> | null = null;
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

      // Expand card to see missing token hints
      const expandBtn = root.root.find((node) =>
        node.type === 'div' && String(node.props.className || '').includes('route-card-collapsed'),
      );
      await act(async () => {
        expandBtn.props.onClick();
      });
      await flushMicrotasks();

      const siteButton = findButtonByText(root.root, 'Wong');
      expect(String(siteButton.props.className || '')).toContain('missing-token-site-tag');
    } finally {
      root?.unmount();
    }
  });

  it('keeps zero-channel placeholder routes hidden by default', async () => {
    apiMock.getRoutesSummary.mockResolvedValue([]);
    apiMock.getModelTokenCandidates.mockResolvedValue({
      models: {},
      modelsWithoutToken: {
        'gpt-5.2-codex': [
          { accountId: 101, username: 'linuxdo_11494', siteId: 11, siteName: 'Wong' },
        ],
      },
    });

    let root: ReturnType<typeof create> | null = null;
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

      const text = collectText(root.root);
      expect(text).toContain('显示 0 通道路由');
      expect(text).not.toContain('gpt-5.2-codex');
      expect(text).not.toContain('未生成');
    } finally {
      root?.unmount();
    }
  });

  it('shows read-only zero-channel placeholder routes after toggle without loading channels', async () => {
    apiMock.getRoutesSummary.mockResolvedValue([]);
    apiMock.getModelTokenCandidates.mockResolvedValue({
      models: {},
      modelsWithoutToken: {
        'gpt-5.2-codex': [
          { accountId: 101, username: 'linuxdo_11494', siteId: 11, siteName: 'Wong' },
        ],
      },
      modelsMissingTokenGroups: {
        'claude-opus-4-6': [
          {
            accountId: 201,
            username: 'linuxdo_4677',
            siteId: 12,
            siteName: '香草api',
            missingGroups: ['opus'],
            requiredGroups: ['default', 'opus'],
            availableGroups: ['default'],
          },
        ],
      },
    });

    let root: ReturnType<typeof create> | null = null;
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

      const toggle = findButtonByText(root.root, '显示 0 通道路由');
      await act(async () => {
        toggle.props.onClick();
      });
      await flushMicrotasks();

      expect(collectText(root.root)).toContain('隐藏 0 通道路由');
      expect(collectText(root.root)).toContain('gpt-5.2-codex');
      expect(collectText(root.root)).toContain('claude-opus-4-6');
      expect(collectText(root.root)).toContain('未生成');
      expect(collectText(root.root)).toContain('0 通道');

      const expandCards = root.root.findAll((node) =>
        node.type === 'div' && String(node.props.className || '').includes('route-card-collapsed'),
      );
      const gptCard = expandCards.find((node) => collectText(node).includes('gpt-5.2-codex'));
      expect(gptCard).toBeTruthy();

      await act(async () => {
        gptCard!.props.onClick();
      });
      await flushMicrotasks();

      const expandedText = collectText(root.root);
      expect(expandedText).toContain('待注册站点');
      expect(expandedText).toContain('Wong');
      expect(expandedText).toContain('暂无通道，先补齐连接配置后再重建路由。');
      expect(expandedText).not.toContain('添加通道');
      expect(expandedText).not.toContain('删除路由');
      expect(expandedText).not.toContain('编辑群组');
      expect(apiMock.getRouteChannels).not.toHaveBeenCalled();
    } finally {
      root?.unmount();
    }
  });

  it('does not render missing-token site tags when the hint lacks a valid account id', async () => {
    apiMock.getRoutesSummary.mockResolvedValue([
      {
        id: 1, modelPattern: 'gpt-5.2-codex', displayName: 'gpt-5.2-codex',
        displayIcon: null, modelMapping: null, enabled: true,
        channelCount: 0, enabledChannelCount: 0, siteNames: [],
        decisionSnapshot: null, decisionRefreshedAt: null,
      },
    ]);
    apiMock.getModelTokenCandidates.mockResolvedValue({
      models: {},
      modelsWithoutToken: {
        'gpt-5.2-codex': [
          { accountId: 0, username: 'shenmo-direct', siteId: 12, siteName: '神墨' },
        ],
      },
    });

    let root: ReturnType<typeof create> | null = null;
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

      const text = collectText(root.root);
      expect(text).not.toContain('待注册站点');
      expect(text).not.toContain('神墨');
    } finally {
      root?.unmount();
    }
  });

  it('renders missing-token-group hints separately from missing-token site tags', async () => {
    apiMock.getRoutesSummary.mockResolvedValue([
      {
        id: 1, modelPattern: 'claude-opus-4-6', displayName: 'claude-opus-4-6',
        displayIcon: null, modelMapping: null, enabled: true,
        channelCount: 0, enabledChannelCount: 0, siteNames: [],
        decisionSnapshot: null, decisionRefreshedAt: null,
      },
    ]);
    apiMock.getModelTokenCandidates.mockResolvedValue({
      models: {},
      modelsMissingTokenGroups: {
        'claude-opus-4-6': [
          {
            accountId: 101,
            username: 'linuxdo_4677',
            siteId: 11,
            siteName: '香草api',
            missingGroups: ['opus'],
            requiredGroups: ['default', 'opus'],
            availableGroups: ['default'],
          },
        ],
      },
    });
    apiMock.getRouteChannels.mockResolvedValue([]);

    let root: ReturnType<typeof create> | null = null;
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

      const expandBtn = root.root.find((node) =>
        node.type === 'div' && String(node.props.className || '').includes('route-card-collapsed'),
      );
      await act(async () => {
        expandBtn.props.onClick();
      });
      await flushMicrotasks();

      const text = collectText(root.root);
      expect(text).toContain('缺少分组');
      expect(text).toContain('香草api');
      expect(text).not.toContain('待注册站点');
    } finally {
      root?.unmount();
    }
  });

  it('maps endpoint types to expected brand icons in filter panel', async () => {
    apiMock.getRoutesSummary.mockResolvedValue([
      {
        id: 1, modelPattern: 'gpt-5.2-codex', displayName: 'gpt-5.2-codex',
        displayIcon: null, modelMapping: null, enabled: true,
        channelCount: 1, enabledChannelCount: 1, siteNames: ['Wong'],
        decisionSnapshot: null, decisionRefreshedAt: null,
      },
    ]);
    apiMock.getModelTokenCandidates.mockResolvedValue({
      models: {},
      endpointTypesByModel: {
        'gpt-5.2-codex': ['openai', 'gemini', 'anthropic'],
      },
    });

    let root: ReturnType<typeof create> | null = null;
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

      // Expand filter bar to see endpoint types
      const filterSummary = root.root.find((node) =>
        node.type === 'button' && String(node.props.className || '').includes('route-filter-bar-summary'),
      );
      await act(async () => {
        filterSummary.props.onClick();
      });
      await flushMicrotasks();

      const text = collectText(root.root);
      expect(text).toContain('chatgpt');
      expect(text).toContain('gemini');
      expect(text).toContain('claude');
    } finally {
      root?.unmount();
    }
  });

  it('shows newly categorized brands in the route brand filter', async () => {
    getBrandMock.mockImplementation((modelName: string) => {
      if (String(modelName).includes('nvidia/vila')) {
        return {
          name: 'NVIDIA',
          icon: 'nvidia-color',
          color: 'linear-gradient(135deg,#76b900,#4a8c0b)',
        };
      }
      return null;
    });
    apiMock.getRoutesSummary.mockResolvedValue([
      {
        id: 91, modelPattern: 'nvidia/vila', displayName: 'nvidia/vila',
        displayIcon: null, modelMapping: null, enabled: true,
        channelCount: 0, enabledChannelCount: 0, siteNames: [],
        decisionSnapshot: null, decisionRefreshedAt: null,
      },
    ]);

    let root: ReturnType<typeof create> | null = null;
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

      // Expand filter bar
      const filterSummary = root.root.find((node) =>
        node.type === 'button' && String(node.props.className || '').includes('route-filter-bar-summary'),
      );
      await act(async () => {
        filterSummary.props.onClick();
      });
      await flushMicrotasks();

      expect(collectText(root.root)).toContain('NVIDIA');
    } finally {
      root?.unmount();
    }
  });

  it('falls back to site platform endpoint grouping when endpoint metadata cache is empty', async () => {
    // With summary-based loading, we can't infer platform from channels in the summary.
    // The endpoint type should come from endpointTypesByModel data.
    // When endpointTypesByModel is empty and channels aren't loaded, no fallback is possible.
    // This test verifies the endpoint type section renders correctly.
    apiMock.getRoutesSummary.mockResolvedValue([
      {
        id: 1, modelPattern: 'gpt-4o-mini', displayName: 'gpt-4o-mini',
        displayIcon: null, modelMapping: null, enabled: true,
        channelCount: 1, enabledChannelCount: 1, siteNames: ['site-a'],
        decisionSnapshot: null, decisionRefreshedAt: null,
      },
    ]);
    apiMock.getModelTokenCandidates.mockResolvedValue({
      models: {},
      endpointTypesByModel: {},
    });

    let root: ReturnType<typeof create> | null = null;
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

      // Expand filter bar
      const filterSummary = root.root.find((node) =>
        node.type === 'button' && String(node.props.className || '').includes('route-filter-bar-summary'),
      );
      await act(async () => {
        filterSummary.props.onClick();
      });
      await flushMicrotasks();

      const text = collectText(root.root);
      expect(text).toContain('能力');
    } finally {
      root?.unmount();
    }
  });

  it('still shows endpoint group section with empty hint when no endpoint data can be inferred', async () => {
    apiMock.getRoutesSummary.mockResolvedValue([
      {
        id: 1, modelPattern: 'custom-model-without-channel', displayName: 'custom-model-without-channel',
        displayIcon: null, modelMapping: null, enabled: true,
        channelCount: 0, enabledChannelCount: 0, siteNames: [],
        decisionSnapshot: null, decisionRefreshedAt: null,
      },
    ]);
    apiMock.getModelTokenCandidates.mockResolvedValue({
      models: {},
      endpointTypesByModel: {},
    });

    let root: ReturnType<typeof create> | null = null;
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

      // Expand filter bar
      const filterSummary = root.root.find((node) =>
        node.type === 'button' && String(node.props.className || '').includes('route-filter-bar-summary'),
      );
      await act(async () => {
        filterSummary.props.onClick();
      });
      await flushMicrotasks();

      const text = collectText(root.root);
      expect(text).toContain('能力');
      expect(text).toContain('暂无接口能力数据');
    } finally {
      root?.unmount();
    }
  });

  it('hides exact routes covered by a group route from the main route list', async () => {
    apiMock.getRoutesSummary.mockResolvedValue([
      {
        id: 1, modelPattern: 'minimax-m2.1', displayName: 'minimax-m2.1',
        displayIcon: null, modelMapping: null, enabled: true,
        channelCount: 0, enabledChannelCount: 0, siteNames: [],
        decisionSnapshot: null, decisionRefreshedAt: null,
      },
      {
        id: 2, modelPattern: 'minimaxai/minimax-m2.1', displayName: 'minimaxai/minimax-m2.1',
        displayIcon: null, modelMapping: null, enabled: true,
        channelCount: 0, enabledChannelCount: 0, siteNames: [],
        decisionSnapshot: null, decisionRefreshedAt: null,
      },
      {
        id: 3, modelPattern: 're:^(minimax-m2\\.1|minimaxai/minimax-m2\\.1)$', displayName: 'minimax2.1',
        displayIcon: null, modelMapping: null, enabled: true,
        channelCount: 0, enabledChannelCount: 0, siteNames: [],
        decisionSnapshot: null, decisionRefreshedAt: null,
      },
    ]);

    let root: ReturnType<typeof create> | null = null;
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

      const normalizedText = collectText(root.root).replace(/\s+/g, '');
      expect(normalizedText).toContain('共1条路由');
      expect(normalizedText).not.toContain('共3条路由');
    } finally {
      root?.unmount();
    }
  });

  it('still hides zero-channel placeholders when a named group route covers the exact model', async () => {
    apiMock.getRoutesSummary.mockResolvedValue([
      {
        id: 3, modelPattern: 're:^(gpt-5\\.2-codex)$', displayName: 'Codex',
        displayIcon: null, modelMapping: null, enabled: true,
        channelCount: 0, enabledChannelCount: 0, siteNames: [],
        decisionSnapshot: null, decisionRefreshedAt: null,
      },
    ]);
    apiMock.getModelTokenCandidates.mockResolvedValue({
      models: {},
      modelsWithoutToken: {
        'gpt-5.2-codex': [
          { accountId: 101, username: 'linuxdo_11494', siteId: 11, siteName: 'Wong' },
        ],
      },
    });

    let root: ReturnType<typeof create> | null = null;
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

      const toggle = findButtonByText(root.root, '显示 0 通道路由');
      await act(async () => {
        toggle.props.onClick();
      });
      await flushMicrotasks();

      const normalizedText = collectText(root.root).replace(/\s+/g, '');
      expect(normalizedText).toContain('共1条路由');
      expect(normalizedText).toContain('Codex');
      expect(normalizedText).not.toContain('gpt-5.2-codex0通道');
    } finally {
      root?.unmount();
    }
  });

  it('keeps exact routes visible when a group display name collides with a real exact model', async () => {
    apiMock.getRoutesSummary.mockResolvedValue([
      {
        id: 1, modelPattern: 'gpt-4o-mini', displayName: 'gpt-4o-mini',
        displayIcon: null, modelMapping: null, enabled: true,
        channelCount: 0, enabledChannelCount: 0, siteNames: [],
        decisionSnapshot: null, decisionRefreshedAt: null,
      },
      {
        id: 2, modelPattern: 'official/gpt-4o-mini', displayName: 'official/gpt-4o-mini',
        displayIcon: null, modelMapping: null, enabled: true,
        channelCount: 0, enabledChannelCount: 0, siteNames: [],
        decisionSnapshot: null, decisionRefreshedAt: null,
      },
      {
        id: 3, modelPattern: 're:^(gpt-4o-mini|official/gpt-4o-mini)$', displayName: 'gpt-4o-mini',
        displayIcon: null, modelMapping: null, enabled: true,
        channelCount: 0, enabledChannelCount: 0, siteNames: [],
        decisionSnapshot: null, decisionRefreshedAt: null,
      },
    ]);

    let root: ReturnType<typeof create> | null = null;
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

      const normalizedText = collectText(root.root).replace(/\s+/g, '');
      expect(normalizedText).toContain('共3条路由');
      expect(normalizedText).not.toContain('共1条路由');
    } finally {
      root?.unmount();
    }
  });

  it('searches routes by display name as well as model pattern', async () => {
    apiMock.getRoutesSummary.mockResolvedValue([
      {
        id: 31, modelPattern: 're:^claude-(opus|sonnet)-4-6$', displayName: 'claude-4-6-group',
        displayIcon: null, modelMapping: null, enabled: true,
        channelCount: 0, enabledChannelCount: 0, siteNames: [],
        decisionSnapshot: null, decisionRefreshedAt: null,
      },
    ]);

    let root: ReturnType<typeof create> | null = null;
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

      const searchInput = findInputByPlaceholder(root.root, '搜索模型路由');
      await act(async () => {
        searchInput.props.onChange({ target: { value: 'claude-4-6-group' } });
      });
      await flushMicrotasks();

      const normalizedText = collectText(root.root).replace(/\s+/g, '');
      expect(normalizedText).toContain('共1条路由');
      expect(normalizedText).not.toContain('没有匹配的路由');
    } finally {
      root?.unmount();
    }
  });

  it('renders the source picker like the route page with brand, site, ability filters and a card grid', async () => {
    getBrandMock.mockImplementation((modelName: string) => {
      const model = String(modelName);
      if (model.includes('gpt')) {
        return { name: 'OpenAI', icon: 'openai', color: 'linear-gradient(135deg,#111,#555)' };
      }
      if (model.includes('claude')) {
        return { name: 'Anthropic', icon: 'anthropic', color: 'linear-gradient(135deg,#d97706,#f59e0b)' };
      }
      if (model.includes('gemini')) {
        return { name: 'Gemini', icon: 'gemini', color: 'linear-gradient(135deg,#2563eb,#7c3aed)' };
      }
      return null;
    });
    apiMock.getRoutesSummary.mockResolvedValue([
      {
        id: 11, modelPattern: 'gpt-5.4', displayName: null,
        displayIcon: null, modelMapping: null, enabled: true,
        routeMode: 'pattern', sourceRouteIds: [],
        channelCount: 3, enabledChannelCount: 3, siteNames: ['Wong'],
        decisionSnapshot: null, decisionRefreshedAt: null,
      },
      {
        id: 12, modelPattern: 'claude-sonnet-4-5', displayName: null,
        displayIcon: null, modelMapping: null, enabled: true,
        routeMode: 'pattern', sourceRouteIds: [],
        channelCount: 2, enabledChannelCount: 2, siteNames: ['Alpha'],
        decisionSnapshot: null, decisionRefreshedAt: null,
      },
      {
        id: 13, modelPattern: 'gemini-2.5-pro', displayName: null,
        displayIcon: null, modelMapping: null, enabled: true,
        routeMode: 'pattern', sourceRouteIds: [],
        channelCount: 1, enabledChannelCount: 1, siteNames: ['Wong'],
        decisionSnapshot: null, decisionRefreshedAt: null,
      },
    ]);
    apiMock.getModelTokenCandidates.mockResolvedValue({
      models: {},
      endpointTypesByModel: {
        'gpt-5.4': ['openai'],
        'claude-sonnet-4-5': ['anthropic'],
        'gemini-2.5-pro': ['gemini'],
      },
    });

    let root: ReturnType<typeof create> | null = null;
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

      await act(async () => {
        findButtonByText(root.root, '新建群组').props.onClick();
      });
      await flushMicrotasks();

      await act(async () => {
        findButtonByText(root.root, '选择来源模型').props.onClick();
      });
      await flushMicrotasks();

      const pickerGrid = root.root.find((node) => (
        node.type === 'div'
        && String(node.props.className || '').includes('source-route-picker-grid')
      ));
      expect(String(pickerGrid.props.style?.display || '')).toBe('grid');
      expect(String(pickerGrid.props.style?.gridTemplateColumns || '')).toContain('repeat(');

      expect(findButtonByClassAndText(root.root, 'filter-chip', 'OpenAI')).toBeTruthy();
      expect(findButtonByClassAndText(root.root, 'filter-chip', 'Wong')).toBeTruthy();
      expect(findButtonByClassAndText(root.root, 'filter-chip', 'gemini')).toBeTruthy();

      await act(async () => {
        findButtonByClassAndText(root.root, 'filter-chip', 'Wong').props.onClick();
      });
      await flushMicrotasks();
      expect(collectText(pickerGrid)).toContain('gpt-5.4');
      expect(collectText(pickerGrid)).toContain('gemini-2.5-pro');
      expect(collectText(pickerGrid)).not.toContain('claude-sonnet-4-5');

      await act(async () => {
        findButtonByClassAndText(root.root, 'filter-chip', 'Wong').props.onClick();
      });
      await flushMicrotasks();

      await act(async () => {
        findButtonByClassAndText(root.root, 'filter-chip', 'OpenAI').props.onClick();
      });
      await flushMicrotasks();
      expect(collectText(pickerGrid)).toContain('OpenAI');
      expect(collectText(pickerGrid)).toContain('gpt-5.4');
      expect(collectText(pickerGrid)).not.toContain('claude-sonnet-4-5');
      expect(collectText(pickerGrid)).not.toContain('gemini-2.5-pro');

      await act(async () => {
        findButtonByClassAndText(root.root, 'filter-chip', 'OpenAI').props.onClick();
      });
      await flushMicrotasks();

      await act(async () => {
        findButtonByClassAndText(root.root, 'filter-chip', 'anthropic').props.onClick();
      });
      await flushMicrotasks();
      expect(collectText(pickerGrid)).toContain('Anthropic');
      expect(collectText(pickerGrid)).toContain('claude-sonnet-4-5');
      expect(collectText(pickerGrid)).not.toContain('gpt-5.4');
      expect(collectText(pickerGrid)).not.toContain('gemini-2.5-pro');
    } finally {
      root?.unmount();
    }
  });

  it('shows explicit-group source counts instead of aggregated channel counts in the route list and filter chips', async () => {
    apiMock.getRoutesSummary.mockResolvedValue([
      {
        id: 11, modelPattern: 'deepseek-chat', displayName: null,
        displayIcon: null, modelMapping: null, enabled: true,
        routeMode: 'pattern', sourceRouteIds: [],
        channelCount: 40, enabledChannelCount: 40, siteNames: ['Wong'],
        decisionSnapshot: null, decisionRefreshedAt: null,
      },
      {
        id: 12, modelPattern: 'deepseek-reasoner', displayName: null,
        displayIcon: null, modelMapping: null, enabled: true,
        routeMode: 'pattern', sourceRouteIds: [],
        channelCount: 55, enabledChannelCount: 55, siteNames: ['Wong'],
        decisionSnapshot: null, decisionRefreshedAt: null,
      },
      {
        id: 21, modelPattern: 'deepseekv1', displayName: 'deepseekv1',
        displayIcon: '', modelMapping: null, enabled: true,
        routeMode: 'explicit_group', sourceRouteIds: [11, 12],
        channelCount: 95, enabledChannelCount: 95, siteNames: ['Wong'],
        decisionSnapshot: null, decisionRefreshedAt: null,
      },
    ]);
    apiMock.getRouteChannels.mockResolvedValue([
      {
        id: 101, accountId: 1, tokenId: 1, sourceModel: 'deepseek-chat',
        priority: 0, weight: 1, enabled: true, manualOverride: false,
        successCount: 0, failCount: 0,
        account: { username: 'user-a' }, site: { name: 'Wong' }, token: null,
      },
    ]);

    let root: ReturnType<typeof create> | null = null;
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

      const filterSummary = root.root.find((node) =>
        node.type === 'button' && String(node.props.className || '').includes('route-filter-bar-summary'),
      );
      await act(async () => {
        filterSummary.props.onClick();
      });
      await flushMicrotasks();

      const groupChip = findButtonByClassAndText(root.root, 'filter-chip', 'deepseekv1');
      expect(collectText(groupChip)).toContain('2');
      expect(collectText(groupChip)).not.toContain('95');

      const routeCard = root.root.find((node) =>
        node.type === 'div'
        && String(node.props.className || '').includes('route-card-collapsed')
        && collectText(node).includes('deepseekv1'),
      );
      expect(collectText(routeCard).replace(/\s+/g, '')).toContain('2来源模型');
    } finally {
      root?.unmount();
    }
  });

  it('uses a dedicated source picker modal and submits explicit-group sourceRouteIds', async () => {
    apiMock.getRoutesSummary.mockResolvedValue([
      {
        id: 11, modelPattern: 'claude-opus-4-5', displayName: null,
        displayIcon: null, modelMapping: null, enabled: true,
        routeMode: 'pattern', sourceRouteIds: [],
        channelCount: 1, enabledChannelCount: 1, siteNames: ['site-a'],
        decisionSnapshot: null, decisionRefreshedAt: null,
      },
      {
        id: 12, modelPattern: 'claude-sonnet-4-5', displayName: null,
        displayIcon: null, modelMapping: null, enabled: true,
        routeMode: 'pattern', sourceRouteIds: [],
        channelCount: 0, enabledChannelCount: 0, siteNames: [],
        decisionSnapshot: null, decisionRefreshedAt: null,
      },
    ]);

    let root: ReturnType<typeof create> | null = null;
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

      await act(async () => {
        findButtonByText(root.root, '新建群组').props.onClick();
      });
      await flushMicrotasks();

      await act(async () => {
        findInputByPlaceholder(root.root, '对外模型名').props.onChange({ target: { value: 'claude-opus-4-6' } });
      });
      await flushMicrotasks();

      expect(root.root.findAll((node) => typeof node.props?.placeholder === 'string' && node.props.placeholder.includes('搜索来源模型'))).toHaveLength(0);

      await act(async () => {
        findButtonByText(root.root, '选择来源模型').props.onClick();
      });
      await flushMicrotasks();

      expect(findInputByPlaceholder(root.root, '搜索来源模型')).toBeTruthy();

      await act(async () => {
        findButtonByText(root.root, 'claude-opus-4-5').props.onClick();
        findButtonByText(root.root, 'claude-sonnet-4-5').props.onClick();
      });
      await flushMicrotasks();

      await act(async () => {
        findButtonByText(root.root, '确认选择').props.onClick();
      });
      await flushMicrotasks();

      await act(async () => {
        findButtonByText(root.root, '创建群组').props.onClick();
      });
      await flushMicrotasks();

      expect(collectText(root.root)).toContain('模型重定向');
      expect(apiMock.addRoute).toHaveBeenCalledWith(expect.objectContaining({
        routeMode: 'explicit_group',
        displayName: 'claude-opus-4-6',
        sourceRouteIds: [11, 12],
      }));
    } finally {
      root?.unmount();
    }
  });

  it('saves explicit groups with auto brand icon disabled as a no-icon sentinel', async () => {
    apiMock.getRoutesSummary.mockResolvedValue([
      {
        id: 11, modelPattern: 'claude-opus-4-5', displayName: null,
        displayIcon: null, modelMapping: null, enabled: true,
        routeMode: 'pattern', sourceRouteIds: [],
        channelCount: 1, enabledChannelCount: 1, siteNames: ['site-a'],
        decisionSnapshot: null, decisionRefreshedAt: null,
      },
    ]);

    let root: ReturnType<typeof create> | null = null;
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

      await act(async () => {
        findButtonByText(root.root, '新建群组').props.onClick();
      });
      await flushMicrotasks();

      await act(async () => {
        findInputByPlaceholder(root.root, '对外模型名').props.onChange({ target: { value: 'claude-opus-4-6' } });
      });
      await flushMicrotasks();

      await act(async () => {
        findButtonByText(root.root, '选择来源模型').props.onClick();
      });
      await flushMicrotasks();

      await act(async () => {
        findButtonByText(root.root, 'claude-opus-4-5').props.onClick();
      });
      await flushMicrotasks();

      await act(async () => {
        findButtonByText(root.root, '确认选择').props.onClick();
      });
      await flushMicrotasks();

      await act(async () => {
        findCheckboxByLabelText(root.root, '自动品牌图标').props.onChange({ target: { checked: false } });
      });
      await flushMicrotasks();

      await act(async () => {
        findButtonByText(root.root, '创建群组').props.onClick();
      });
      await flushMicrotasks();

      expect(apiMock.addRoute).toHaveBeenCalledWith(expect.objectContaining({
        routeMode: 'explicit_group',
        displayName: 'claude-opus-4-6',
        sourceRouteIds: [11],
        displayIcon: ROUTE_ICON_NONE_VALUE,
      }));
    } finally {
      root?.unmount();
    }
  });

  it('edits legacy regex groups in advanced mode only', async () => {
    apiMock.getRoutesSummary
      .mockResolvedValueOnce([
        {
          id: 51, modelPattern: 're:^claude-.*$', displayName: 'group-a',
          displayIcon: '', modelMapping: null, enabled: true,
          routeMode: 'pattern', sourceRouteIds: [],
          channelCount: 0, enabledChannelCount: 0, siteNames: [],
          decisionSnapshot: null, decisionRefreshedAt: null,
        },
      ]);
    apiMock.getRouteChannels.mockResolvedValue([]);

    let root: ReturnType<typeof create> | null = null;
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

      // Expand the card
      const expandBtn = root.root.find((node) =>
        node.type === 'div' && String(node.props.className || '').includes('route-card-collapsed'),
      );
      await act(async () => {
        expandBtn.props.onClick();
      });
      await flushMicrotasks();

      await act(async () => {
        findButtonByText(root.root, '编辑群组').props.onClick();
      });
      await flushMicrotasks();

      expect(collectText(root.root)).toContain('高级规则群组');
      expect(findInputByPlaceholder(root.root, '模型匹配').props.value).toBe('re:^claude-.*$');
      expect(root.root.findAll((node) => typeof node.props?.placeholder === 'string' && node.props.placeholder.includes('搜索来源模型'))).toHaveLength(0);
      expect(root.root.findAll((node) => typeof node.props?.placeholder === 'string' && node.props.placeholder.includes('对外模型名'))).toHaveLength(0);
    } finally {
      root?.unmount();
    }
  });

  it('updates explicit-group sources from the modal and reloads routes afterwards', async () => {
    apiMock.getRoutesSummary
      .mockResolvedValueOnce([
        {
          id: 11, modelPattern: 'claude-opus-4-5', displayName: null,
          displayIcon: null, modelMapping: null, enabled: true,
          routeMode: 'pattern', sourceRouteIds: [],
          channelCount: 1, enabledChannelCount: 1, siteNames: ['site-a'],
          decisionSnapshot: null, decisionRefreshedAt: null,
        },
        {
          id: 12, modelPattern: 'claude-sonnet-4-5', displayName: null,
          displayIcon: null, modelMapping: null, enabled: true,
          routeMode: 'pattern', sourceRouteIds: [],
          channelCount: 1, enabledChannelCount: 1, siteNames: ['site-b'],
          decisionSnapshot: null, decisionRefreshedAt: null,
        },
        {
          id: 21, modelPattern: 'claude-opus-4-6', displayName: 'claude-opus-4-6',
          displayIcon: '', modelMapping: null, enabled: true,
          routeMode: 'explicit_group', sourceRouteIds: [11],
          channelCount: 1, enabledChannelCount: 1, siteNames: ['site-a'],
          decisionSnapshot: null, decisionRefreshedAt: null,
        },
      ])
      .mockResolvedValueOnce([
        {
          id: 11, modelPattern: 'claude-opus-4-5', displayName: null,
          displayIcon: null, modelMapping: null, enabled: true,
          routeMode: 'pattern', sourceRouteIds: [],
          channelCount: 1, enabledChannelCount: 1, siteNames: ['site-a'],
          decisionSnapshot: null, decisionRefreshedAt: null,
        },
        {
          id: 12, modelPattern: 'claude-sonnet-4-5', displayName: null,
          displayIcon: null, modelMapping: null, enabled: true,
          routeMode: 'pattern', sourceRouteIds: [],
          channelCount: 1, enabledChannelCount: 1, siteNames: ['site-b'],
          decisionSnapshot: null, decisionRefreshedAt: null,
        },
        {
          id: 21, modelPattern: 'claude-opus-4-6', displayName: 'claude-opus-4-6',
          displayIcon: '', modelMapping: null, enabled: true,
          routeMode: 'explicit_group', sourceRouteIds: [11, 12],
          channelCount: 2, enabledChannelCount: 2, siteNames: ['site-a', 'site-b'],
          decisionSnapshot: null, decisionRefreshedAt: null,
        },
      ]);
    apiMock.getRouteChannels.mockResolvedValue([]);

    let root: ReturnType<typeof create> | null = null;
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

      const expandBtn = root.root.find((node) =>
        node.type === 'div'
        && String(node.props.className || '').includes('route-card-collapsed')
        && collectText(node).includes('claude-opus-4-6'),
      );
      await act(async () => {
        expandBtn.props.onClick();
      });
      await flushMicrotasks();

      await act(async () => {
        findButtonByText(root.root, '编辑群组').props.onClick();
      });
      await flushMicrotasks();

      await act(async () => {
        findButtonByText(root.root, '选择来源模型').props.onClick();
      });
      await flushMicrotasks();

      await act(async () => {
        findButtonByText(root.root, 'claude-sonnet-4-5').props.onClick();
      });
      await flushMicrotasks();

      await act(async () => {
        findButtonByText(root.root, '确认选择').props.onClick();
      });
      await flushMicrotasks();

      await act(async () => {
        findButtonByText(root.root, '保存群组').props.onClick();
      });
      await flushMicrotasks();

      expect(apiMock.updateRoute).toHaveBeenCalledWith(21, expect.objectContaining({
        routeMode: 'explicit_group',
        displayName: 'claude-opus-4-6',
        sourceRouteIds: [11, 12],
      }));
      expect(apiMock.getRoutesSummary).toHaveBeenCalledTimes(2);
    } finally {
      root?.unmount();
    }
  });

  it('reuses the standard channel row presentation for explicit-group details in read-only mode', async () => {
    apiMock.getRoutesSummary.mockResolvedValue([
      {
        id: 11, modelPattern: 'claude-haiku-4-5-20251001', displayName: null,
        displayIcon: null, modelMapping: null, enabled: true,
        routeMode: 'pattern', sourceRouteIds: [],
        channelCount: 6, enabledChannelCount: 6, siteNames: ['Wong'],
        decisionSnapshot: null, decisionRefreshedAt: null,
      },
      {
        id: 21, modelPattern: 'claude-haiku-proxy', displayName: 'claude-haiku-proxy',
        displayIcon: '', modelMapping: null, enabled: true,
        routeMode: 'explicit_group', sourceRouteIds: [11],
        channelCount: 6, enabledChannelCount: 6, siteNames: ['Wong'],
        decisionSnapshot: null, decisionRefreshedAt: null,
      },
    ]);
    apiMock.getRouteChannels.mockResolvedValue([
      {
        id: 101,
        routeId: 11,
        accountId: 301,
        tokenId: 401,
        sourceModel: 'claude-haiku-4-5-20251001',
        priority: 0,
        weight: 10,
        enabled: true,
        manualOverride: false,
        successCount: 6,
        failCount: 1,
        account: { username: 'linuxdo_131936' },
        site: { name: 'Wong' },
        token: { id: 401, name: 'token-a', accountId: 301, enabled: true, isDefault: true },
      },
    ]);

    let root: ReturnType<typeof create> | null = null;
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

      const expandBtn = root.root.find((node) =>
        node.type === 'div'
        && String(node.props.className || '').includes('route-card-collapsed')
        && collectText(node).includes('claude-haiku-proxy'),
      );
      await act(async () => {
        expandBtn.props.onClick();
      });
      await flushMicrotasks();

      await act(async () => {
        findButtonByText(root.root, 'claude-haiku-4-5-20251001').props.onClick();
      });
      await flushMicrotasks();

      const expandedText = collectText(root.root);
      expect(expandedText).toContain('P0');
      expect(expandedText).toContain('当前生效：token-a');
      expect(expandedText).toContain('选中概率');
      expect(findButtonByAriaLabel(root.root, '拖拽调整优先级').props.disabled).toBe(true);
      expect(expandedText).not.toContain('保存');
      expect(expandedText).not.toContain('移除');
    } finally {
      root?.unmount();
    }
  });
});
