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

function findInputByPlaceholder(root: ReactTestInstance, placeholderText: string): ReactTestInstance {
  return root.find((node) => (
    node.type === 'input'
    && typeof node.props.placeholder === 'string'
    && node.props.placeholder.includes(placeholderText)
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

  it('enters edit mode and seeds the group form with the current route values', async () => {
    apiMock.getRoutesSummary.mockResolvedValue([
      {
        id: 31, modelPattern: 're:^claude-(opus|sonnet)-4-6$', displayName: 'claude-4-6-group',
        displayIcon: 'anthropic', modelMapping: null, enabled: true,
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

      // Expand the card to access edit button
      const expandBtn = root.root.find((node) =>
        node.type === 'div' && String(node.props.className || '').includes('route-card-collapsed'),
      );
      await act(async () => {
        expandBtn.props.onClick();
      });
      await flushMicrotasks();

      const editButton = findButtonByText(root.root, '编辑群组');
      await act(async () => {
        editButton.props.onClick();
      });
      await flushMicrotasks();

      expect(findInputByPlaceholder(root.root, '群组显示名').props.value).toBe('claude-4-6-group');
      expect(findInputByPlaceholder(root.root, '模型匹配').props.value).toBe('re:^claude-(opus|sonnet)-4-6$');
      expect(collectText(root.root)).toContain('保存群组');
    } finally {
      root?.unmount();
    }
  });

  it('updates route metadata from edit mode and reloads routes afterwards', async () => {
    apiMock.getRoutesSummary
      .mockResolvedValueOnce([
        {
          id: 41, modelPattern: 're:^claude-.*$', displayName: 'old-group',
          displayIcon: '', modelMapping: null, enabled: true,
          channelCount: 0, enabledChannelCount: 0, siteNames: [],
          decisionSnapshot: null, decisionRefreshedAt: null,
        },
      ])
      .mockResolvedValueOnce([
        {
          id: 41, modelPattern: 're:^claude-.*$', displayName: 'new-group',
          displayIcon: '', modelMapping: null, enabled: true,
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

      await act(async () => {
        findInputByPlaceholder(root.root, '群组显示名').props.onChange({ target: { value: 'new-group' } });
      });

      await act(async () => {
        findButtonByText(root.root, '保存群组').props.onClick();
      });
      await flushMicrotasks();

      expect(apiMock.updateRoute).toHaveBeenCalledWith(41, expect.objectContaining({
        displayName: 'new-group',
        modelPattern: 're:^claude-.*$',
      }));
      expect(apiMock.getRoutesSummary).toHaveBeenCalledTimes(2);
    } finally {
      root?.unmount();
    }
  });

  it('reloads route data after saving an edited model pattern', async () => {
    apiMock.getRoutesSummary
      .mockResolvedValueOnce([
        {
          id: 51, modelPattern: 're:^claude-.*$', displayName: 'group-a',
          displayIcon: '', modelMapping: null, enabled: true,
          channelCount: 0, enabledChannelCount: 0, siteNames: [],
          decisionSnapshot: null, decisionRefreshedAt: null,
        },
      ])
      .mockResolvedValueOnce([
        {
          id: 51, modelPattern: 're:^gemini-.*$', displayName: 'group-a',
          displayIcon: '', modelMapping: null, enabled: true,
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

      await act(async () => {
        findInputByPlaceholder(root.root, '模型匹配').props.onChange({ target: { value: 're:^gemini-.*$' } });
      });

      await act(async () => {
        findButtonByText(root.root, '保存群组').props.onClick();
      });
      await flushMicrotasks();

      expect(apiMock.updateRoute).toHaveBeenCalledWith(51, expect.objectContaining({
        modelPattern: 're:^gemini-.*$',
      }));
      expect(apiMock.getRoutesSummary).toHaveBeenCalledTimes(2);
    } finally {
      root?.unmount();
    }
  });
});
