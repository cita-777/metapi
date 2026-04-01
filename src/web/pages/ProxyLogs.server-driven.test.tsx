import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, create, type ReactTestInstance } from 'react-test-renderer';
import { MemoryRouter } from 'react-router-dom';
import ModernSelect from '../components/ModernSelect.js';
import { ToastProvider } from '../components/Toast.js';
import ProxyLogs from './ProxyLogs.js';

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    getProxyLogs: vi.fn(),
    getProxyLogDetail: vi.fn(),
    getProxyDebugTraces: vi.fn(),
    getProxyDebugTraceDetail: vi.fn(),
    getRuntimeSettings: vi.fn(),
    getSites: vi.fn(),
    updateRuntimeSettings: vi.fn(),
  },
}));

vi.mock('../api.js', () => ({
  api: apiMock,
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

function buildListResponse(overrides?: Partial<{
  items: any[];
  total: number;
  page: number;
  pageSize: number;
  summary: {
    totalCount: number;
    successCount: number;
    failedCount: number;
    totalCost: number;
    totalTokensAll: number;
  };
}>) {
  return {
    items: [
      {
        id: 101,
        createdAt: '2026-03-09 16:00:00',
        modelRequested: 'gpt-4o',
        modelActual: 'gpt-4o',
        status: 'success',
        latencyMs: 120,
        firstByteLatencyMs: 35,
        isStream: true,
        promptTokens: 10,
        completionTokens: 5,
        totalTokens: 15,
        retryCount: 0,
        estimatedCost: 1.23,
        errorMessage: 'downstream: /v1/chat upstream: /api/chat',
        username: 'tester',
        siteName: 'main-site',
        siteUrl: 'https://main-site.example.com',
        clientFamily: 'codex',
        clientAppId: 'cherry_studio',
        clientAppName: 'Cherry Studio',
        clientConfidence: 'heuristic',
        downstreamKeyName: '移动端灰度',
        downstreamKeyGroupName: '项目A',
        downstreamKeyTags: ['VIP', '灰度'],
      },
    ],
    total: 1,
    page: 1,
    pageSize: 50,
    summary: {
      totalCount: 12,
      successCount: 8,
      failedCount: 4,
      totalCost: 1.23,
      totalTokensAll: 15,
    },
    clientOptions: [
      { value: 'app:cherry_studio', label: '应用 · Cherry Studio' },
      { value: 'family:codex', label: '协议 · Codex' },
    ],
    ...overrides,
  };
}

describe('ProxyLogs server-driven page', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    const localStorageState = new Map<string, string>();
    Object.defineProperty(globalThis, 'navigator', {
      value: {
        clipboard: {
          writeText: vi.fn().mockResolvedValue(undefined),
        },
      },
      configurable: true,
      writable: true,
    });
    Object.defineProperty(globalThis, 'localStorage', {
      value: {
        getItem: vi.fn((key: string) => (localStorageState.has(key) ? localStorageState.get(key)! : null)),
        setItem: vi.fn((key: string, value: string) => {
          localStorageState.set(String(key), String(value));
        }),
        removeItem: vi.fn((key: string) => {
          localStorageState.delete(String(key));
        }),
        clear: vi.fn(() => {
          localStorageState.clear();
        }),
      },
      configurable: true,
      writable: true,
    });
    apiMock.getSites.mockResolvedValue([
      { id: 9, name: 'main-site', status: 'active' },
      { id: 12, name: 'backup-site', status: 'active' },
    ]);
    apiMock.getRuntimeSettings.mockResolvedValue({
      proxyDebugTraceEnabled: false,
      proxyDebugCaptureHeaders: true,
      proxyDebugCaptureBodies: false,
      proxyDebugCaptureStreamChunks: false,
      proxyDebugTargetSessionId: '',
      proxyDebugTargetClientKind: '',
      proxyDebugTargetModel: '',
      proxyDebugRetentionHours: 24,
      proxyDebugMaxBodyBytes: 262144,
    });
    apiMock.getProxyLogs.mockResolvedValue(buildListResponse());
    apiMock.getProxyLogDetail.mockResolvedValue({
      id: 101,
      createdAt: '2026-03-09 16:00:00',
      modelRequested: 'gpt-4o',
      modelActual: 'gpt-4o',
      status: 'success',
      latencyMs: 120,
      firstByteLatencyMs: 35,
      isStream: true,
      promptTokens: 10,
      completionTokens: 5,
      totalTokens: 15,
      retryCount: 0,
      estimatedCost: 1.23,
      errorMessage: 'downstream: /v1/chat upstream: /api/chat',
      username: 'tester',
      siteName: 'main-site',
      siteUrl: 'https://main-site.example.com',
      clientFamily: 'codex',
      clientAppId: 'cherry_studio',
      clientAppName: 'Cherry Studio',
      clientConfidence: 'heuristic',
      downstreamKeyName: '移动端灰度',
      downstreamKeyGroupName: '项目A',
      downstreamKeyTags: ['VIP', '灰度'],
      billingDetails: {
        breakdown: {
          inputPerMillion: 1,
          outputPerMillion: 2,
          cacheReadPerMillion: 0,
          cacheCreationPerMillion: 0,
          inputCost: 0.1,
          outputCost: 0.2,
          cacheReadCost: 0,
          cacheCreationCost: 0,
          totalCost: 0.3,
        },
        pricing: {
          modelRatio: 1,
          completionRatio: 1,
          cacheRatio: 0,
          cacheCreationRatio: 0,
          groupRatio: 1,
        },
        usage: {
          promptTokens: 10,
          completionTokens: 5,
          totalTokens: 15,
          cacheReadTokens: 0,
          cacheCreationTokens: 0,
          billablePromptTokens: 10,
          promptTokensIncludeCache: false,
        },
      },
    });
    apiMock.getProxyDebugTraces.mockResolvedValue({
      items: [
        {
          id: 701,
          createdAt: '2026-03-28 18:00:00',
          requestedModel: 'gpt-4o',
          downstreamPath: '/v1/responses',
          finalStatus: 'failed',
          finalUpstreamPath: '/responses',
          clientKind: 'codex',
          sessionId: 'sess-debug-1',
        },
      ],
    });
    apiMock.getProxyDebugTraceDetail.mockResolvedValue({
      trace: {
        id: 701,
        requestedModel: 'gpt-4o',
        sessionId: 'sess-debug-1',
        requestHeadersJson: '{\n  "authorization": "Bearer demo"\n}',
      },
      attempts: [],
    });
    apiMock.updateRuntimeSettings.mockResolvedValue({
      success: true,
      proxyDebugTraceEnabled: true,
      proxyDebugCaptureHeaders: true,
      proxyDebugCaptureBodies: true,
      proxyDebugCaptureStreamChunks: false,
      proxyDebugTargetSessionId: 'sess-debug-1',
      proxyDebugTargetClientKind: 'codex',
      proxyDebugTargetModel: 'gpt-4o',
      proxyDebugRetentionHours: 12,
      proxyDebugMaxBodyBytes: 131072,
    });
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('requests paginated data from the server and renders server summary counts', async () => {
    let root!: WebTestRenderer;

    try {
      await act(async () => {
        root = create(
          <MemoryRouter initialEntries={['/logs']}>
            <ToastProvider>
              <ProxyLogs />
            </ToastProvider>
          </MemoryRouter>,
        );
      });
      await flushMicrotasks();

      expect(apiMock.getProxyLogs).toHaveBeenCalledWith({
        limit: 50,
        offset: 0,
        status: 'all',
        search: '',
      });

      const text = collectText(root!.root);
      expect(text).toContain('消耗总额 $1.2300');
      expect(text).toContain('全部 12');
      expect(text).toContain('成功 8');
      expect(text).toContain('失败 4');
      expect(text).toContain('Cherry Studio');
      expect(text).toContain('Codex');
      expect(text).toContain('推测');
      expect(text).toContain('下游 Key: 移动端灰度');
      expect(text).toContain('流式');
      expect(text).toContain('首字');
    } finally {
      await act(async () => {
        root?.unmount();
      });
    }
  });

  it('shows proxy debug traces inline and edits settings through the modal', async () => {
    let root!: WebTestRenderer;

    try {
      await act(async () => {
        root = create(
          <MemoryRouter initialEntries={['/logs']}>
            <ToastProvider>
              <ProxyLogs />
            </ToastProvider>
          </MemoryRouter>,
        );
      });
      await flushMicrotasks();

      expect(apiMock.getRuntimeSettings).toHaveBeenCalled();
      expect(apiMock.getProxyDebugTraces).toHaveBeenCalled();
      expect(collectText(root.root)).toContain('最近调试追踪');
      expect(collectText(root.root)).toContain('sess-debug-1');

      const debugSettingsButton = root.root.find((node) => (
        node.type === 'button'
        && typeof node.props.onClick === 'function'
        && collectText(node).trim() === '调试设置'
      ));

      await act(async () => {
        debugSettingsButton.props.onClick();
      });
      await flushMicrotasks();

      const traceEnabledToggle = root.root.find((node) => (
        node.type === 'input'
        && node.props.type === 'checkbox'
        && node.props['data-debug-setting'] === 'trace-enabled'
      ));
      const captureBodiesToggle = root.root.find((node) => (
        node.type === 'input'
        && node.props.type === 'checkbox'
        && node.props['data-debug-setting'] === 'capture-bodies'
      ));
      const sessionInput = root.root.find((node) => (
        node.type === 'input'
        && node.props['data-debug-setting'] === 'target-session-id'
      ));
      const retentionInput = root.root.find((node) => (
        node.type === 'input'
        && node.props['data-debug-setting'] === 'retention-hours'
      ));

      await act(async () => {
        traceEnabledToggle.props.onChange({ target: { checked: true } });
        captureBodiesToggle.props.onChange({ target: { checked: true } });
        sessionInput.props.onChange({ target: { value: 'sess-debug-1' } });
        retentionInput.props.onChange({ target: { value: '12' } });
      });

      const saveButton = root.root.find((node) => (
        node.type === 'button'
        && typeof node.props.onClick === 'function'
        && collectText(node).trim() === '保存调试设置'
      ));

      await act(async () => {
        saveButton.props.onClick();
      });
      await flushMicrotasks();

      expect(apiMock.updateRuntimeSettings).toHaveBeenCalledWith(expect.objectContaining({
        proxyDebugTraceEnabled: true,
        proxyDebugCaptureBodies: true,
        proxyDebugTargetSessionId: 'sess-debug-1',
        proxyDebugRetentionHours: 12,
      }));
    } finally {
      root?.unmount();
    }
  });

  it('paginates debug traces in groups of five instead of rendering the whole trace list at once', async () => {
    apiMock.getProxyDebugTraces.mockResolvedValue({
      items: Array.from({ length: 7 }, (_, index) => ({
        id: 701 + index,
        createdAt: `2026-03-28 18:0${index}:00`,
        requestedModel: `gpt-4o-mini-${index + 1}`,
        downstreamPath: '/v1/responses',
        finalStatus: index % 2 === 0 ? 'failed' : 'success',
        finalUpstreamPath: '/responses',
        clientKind: 'codex',
        sessionId: `sess-debug-${index + 1}`,
      })),
    });

    let root!: WebTestRenderer;

    try {
      await act(async () => {
        root = create(
          <MemoryRouter initialEntries={['/logs']}>
            <ToastProvider>
              <ProxyLogs />
            </ToastProvider>
          </MemoryRouter>,
        );
      });
      await flushMicrotasks();

      expect(collectText(root.root)).toContain('显示第 1 - 5 条，共 7 条');
      expect(collectText(root.root)).toContain('sess-debug-1');
      expect(collectText(root.root)).not.toContain('sess-debug-6');

      const detailButtons = root.root.findAll((node) => (
        node.type === 'button'
        && typeof node.props.onClick === 'function'
        && collectText(node).trim() === '查看详情'
      ));
      expect(detailButtons).toHaveLength(5);

      const nextPageButton = root.root.find((node) => (
        node.type === 'button'
        && node.props['aria-label'] === '调试追踪下一页'
      ));

      await act(async () => {
        nextPageButton.props.onClick();
      });
      await flushMicrotasks();

      expect(collectText(root.root)).toContain('显示第 6 - 7 条，共 7 条');
      expect(collectText(root.root)).toContain('sess-debug-6');
      expect(collectText(root.root)).not.toContain('sess-debug-1');
    } finally {
      root?.unmount();
    }
  });

  it('allows collapsing and expanding the debug trace panel to reduce page footprint', async () => {
    let root!: WebTestRenderer;

    try {
      await act(async () => {
        root = create(
          <MemoryRouter initialEntries={['/logs']}>
            <ToastProvider>
              <ProxyLogs />
            </ToastProvider>
          </MemoryRouter>,
        );
      });
      await flushMicrotasks();

      const toggleButton = root.root.find((node) => (
        node.type === 'button'
        && typeof node.props.onClick === 'function'
        && node.props['data-debug-trace-panel-toggle'] === true
      ));
      const panelBody = root.root.find((node) => (
        node.type === 'div'
        && node.props['data-debug-trace-panel-body'] === true
      ));

      expect(toggleButton.props['aria-expanded']).toBe(true);
      expect(String(panelBody.props.className || '')).toContain('is-open');

      await act(async () => {
        toggleButton.props.onClick();
      });
      await flushMicrotasks();

      const collapsedToggleButton = root.root.find((node) => (
        node.type === 'button'
        && typeof node.props.onClick === 'function'
        && node.props['data-debug-trace-panel-toggle'] === true
      ));
      const collapsedPanelBody = root.root.find((node) => (
        node.type === 'div'
        && node.props['data-debug-trace-panel-body'] === true
      ));

      expect(collapsedToggleButton.props['aria-expanded']).toBe(false);
      expect(String(collapsedPanelBody.props.className || '')).not.toContain('is-open');

      await act(async () => {
        collapsedToggleButton.props.onClick();
      });
      await flushMicrotasks();

      const expandedToggleButton = root.root.find((node) => (
        node.type === 'button'
        && typeof node.props.onClick === 'function'
        && node.props['data-debug-trace-panel-toggle'] === true
      ));
      const expandedPanelBody = root.root.find((node) => (
        node.type === 'div'
        && node.props['data-debug-trace-panel-body'] === true
      ));

      expect(expandedToggleButton.props['aria-expanded']).toBe(true);
      expect(String(expandedPanelBody.props.className || '')).toContain('is-open');
    } finally {
      root?.unmount();
    }
  });

  it('remembers the collapsed debug trace panel state across remounts', async () => {
    let root!: WebTestRenderer;

    try {
      await act(async () => {
        root = create(
          <MemoryRouter initialEntries={['/logs']}>
            <ToastProvider>
              <ProxyLogs />
            </ToastProvider>
          </MemoryRouter>,
        );
      });
      await flushMicrotasks();

      const toggleButton = root.root.find((node) => (
        node.type === 'button'
        && typeof node.props.onClick === 'function'
        && node.props['data-debug-trace-panel-toggle'] === true
      ));

      await act(async () => {
        toggleButton.props.onClick();
      });
      await flushMicrotasks();

      expect(globalThis.localStorage.setItem).toHaveBeenCalledWith('metapi.proxyLogs.debugTracePanelExpanded', 'false');

      await act(async () => {
        root.unmount();
      });

      await act(async () => {
        root = create(
          <MemoryRouter initialEntries={['/logs']}>
            <ToastProvider>
              <ProxyLogs />
            </ToastProvider>
          </MemoryRouter>,
        );
      });
      await flushMicrotasks();

      const restoredToggleButton = root.root.find((node) => (
        node.type === 'button'
        && typeof node.props.onClick === 'function'
        && node.props['data-debug-trace-panel-toggle'] === true
      ));
      const restoredPanelBody = root.root.find((node) => (
        node.type === 'div'
        && node.props['data-debug-trace-panel-body'] === true
      ));

      expect(globalThis.localStorage.getItem).toHaveBeenCalledWith('metapi.proxyLogs.debugTracePanelExpanded');
      expect(restoredToggleButton.props['aria-expanded']).toBe(false);
      expect(String(restoredPanelBody.props.className || '')).not.toContain('is-open');
    } finally {
      root?.unmount();
    }
  });

  it('opens debug trace detail on demand instead of preloading the first trace inline', async () => {
    let root!: WebTestRenderer;

    try {
      await act(async () => {
        root = create(
          <MemoryRouter initialEntries={['/logs']}>
            <ToastProvider>
              <ProxyLogs />
            </ToastProvider>
          </MemoryRouter>,
        );
      });
      await flushMicrotasks();

      expect(apiMock.getProxyDebugTraceDetail).not.toHaveBeenCalled();

      const viewDetailButton = root.root.find((node) => (
        node.type === 'button'
        && typeof node.props.onClick === 'function'
        && collectText(node).trim() === '查看详情'
      ));

      await act(async () => {
        viewDetailButton.props.onClick();
      });
      await flushMicrotasks();

      expect(apiMock.getProxyDebugTraceDetail).toHaveBeenCalledWith(701);
      expect(collectText(root.root)).toContain('原始下游请求头');
      expect(collectText(root.root)).toContain('Attempt 记录');
    } finally {
      root?.unmount();
    }
  });

  it('polls debug traces after tracing is enabled so new results are not hidden behind the settings modal', async () => {
    vi.useFakeTimers();
    apiMock.getRuntimeSettings.mockResolvedValue({
      proxyDebugTraceEnabled: true,
      proxyDebugCaptureHeaders: true,
      proxyDebugCaptureBodies: false,
      proxyDebugCaptureStreamChunks: false,
      proxyDebugTargetSessionId: '',
      proxyDebugTargetClientKind: '',
      proxyDebugTargetModel: '',
      proxyDebugRetentionHours: 24,
      proxyDebugMaxBodyBytes: 262144,
    });

    let root!: WebTestRenderer;

    try {
      await act(async () => {
        root = create(
          <MemoryRouter initialEntries={['/logs']}>
            <ToastProvider>
              <ProxyLogs />
            </ToastProvider>
          </MemoryRouter>,
        );
      });
      await flushMicrotasks();

      const initialCalls = apiMock.getProxyDebugTraces.mock.calls.length;

      await act(async () => {
        vi.advanceTimersByTime(2100);
      });
      await flushMicrotasks();

      expect(apiMock.getProxyDebugTraces.mock.calls.length).toBeGreaterThan(initialCalls);
    } finally {
      await act(async () => {
        root?.unmount();
      });
      vi.runOnlyPendingTimers();
      vi.useRealTimers();
    }
  });

  it('keeps debug trace detail visible during polling refresh instead of flashing back to loading', async () => {
    vi.useFakeTimers();
    apiMock.getRuntimeSettings.mockResolvedValue({
      proxyDebugTraceEnabled: true,
      proxyDebugCaptureHeaders: true,
      proxyDebugCaptureBodies: false,
      proxyDebugCaptureStreamChunks: false,
      proxyDebugTargetSessionId: '',
      proxyDebugTargetClientKind: '',
      proxyDebugTargetModel: '',
      proxyDebugRetentionHours: 24,
      proxyDebugMaxBodyBytes: 262144,
    });

    let resolveDetail!: (value: any) => void;
    apiMock.getProxyDebugTraceDetail
      .mockResolvedValueOnce({
        trace: {
          id: 701,
          requestedModel: 'gpt-4o',
          sessionId: 'sess-debug-1',
          requestHeadersJson: '{\"before\":true}',
        },
        attempts: [],
      })
      .mockImplementationOnce(() => new Promise((resolve) => {
        resolveDetail = resolve;
      }));

    let root!: WebTestRenderer;

    try {
      await act(async () => {
        root = create(
          <MemoryRouter initialEntries={['/logs']}>
            <ToastProvider>
              <ProxyLogs />
            </ToastProvider>
          </MemoryRouter>,
        );
      });
      await flushMicrotasks();

      const viewDetailButton = root.root.find((node) => (
        node.type === 'button'
        && typeof node.props.onClick === 'function'
        && collectText(node).trim() === '查看详情'
      ));

      await act(async () => {
        viewDetailButton.props.onClick();
      });
      await flushMicrotasks();

      expect(collectText(root.root)).toContain('原始下游请求头');
      expect(collectText(root.root)).not.toContain('加载追踪详情中...');

      await act(async () => {
        vi.advanceTimersByTime(2100);
      });
      await flushMicrotasks();

      expect(collectText(root.root)).toContain('原始下游请求头');
      expect(collectText(root.root)).not.toContain('加载追踪详情中...');

      await act(async () => {
        resolveDetail({
          trace: {
            id: 701,
            requestedModel: 'gpt-4o',
            sessionId: 'sess-debug-1',
            requestHeadersJson: '{\"after\":true}',
          },
          attempts: [],
        });
      });
      await flushMicrotasks();

      expect(collectText(root.root)).toContain('原始下游请求头');
      expect(collectText(root.root)).not.toContain('加载追踪详情中...');
    } finally {
      await act(async () => {
        root?.unmount();
      });
      vi.runOnlyPendingTimers();
      vi.useRealTimers();
    }
  });

  it('copies the saved request headers content from the trace detail modal', async () => {
    let root!: WebTestRenderer;

    try {
      await act(async () => {
        root = create(
          <MemoryRouter initialEntries={['/logs']}>
            <ToastProvider>
              <ProxyLogs />
            </ToastProvider>
          </MemoryRouter>,
        );
      });
      await flushMicrotasks();

      const viewDetailButton = root.root.find((node) => (
        node.type === 'button'
        && typeof node.props.onClick === 'function'
        && collectText(node).trim() === '查看详情'
      ));

      await act(async () => {
        viewDetailButton.props.onClick();
      });
      await flushMicrotasks();

      expect(collectText(root.root)).not.toContain('Bearer demo');

      const expandHeadersButton = root.root.find((node) => (
        node.type === 'button'
        && typeof node.props.onClick === 'function'
        && node.props['aria-label'] === '展开原始下游请求头'
      ));

      await act(async () => {
        expandHeadersButton.props.onClick();
      });
      await flushMicrotasks();

      expect(collectText(root.root)).toContain('Bearer demo');

      const copyButton = root.root.find((node) => (
        node.type === 'button'
        && typeof node.props.onClick === 'function'
        && node.props['aria-label'] === '复制原始下游请求头'
      ));

      await act(async () => {
        copyButton.props.onClick({ stopPropagation: () => undefined, preventDefault: () => undefined });
      });
      await flushMicrotasks();

      expect(globalThis.navigator.clipboard.writeText).toHaveBeenCalledWith('{\n  "authorization": "Bearer demo"\n}');
    } finally {
      root?.unmount();
    }
  });

  it('keeps the model badge sized to the model name in desktop rows', async () => {
    let root!: WebTestRenderer;

    try {
      await act(async () => {
        root = create(
          <MemoryRouter initialEntries={['/logs']}>
            <ToastProvider>
              <ProxyLogs />
            </ToastProvider>
          </MemoryRouter>,
        );
      });
      await flushMicrotasks();

      const modelBadge = root!.root.find((node) => (
        node.type === 'span'
        && collectText(node) === 'gpt-4o'
        && node.props.style?.display === 'inline-flex'
      ));

      expect(modelBadge.props.style?.alignSelf).toBe('flex-start');
    } finally {
      root?.unmount();
    }
  });

  it('renders explicit client self-reports before protocol-family fallback labels', async () => {
    apiMock.getProxyLogs.mockResolvedValue(buildListResponse({
      items: [
        {
          id: 101,
          createdAt: '2026-03-09 16:00:00',
          modelRequested: 'gpt-4o',
          modelActual: 'gpt-4o',
          status: 'success',
          latencyMs: 120,
          firstByteLatencyMs: 22,
          isStream: false,
          promptTokens: 10,
          completionTokens: 5,
          totalTokens: 15,
          retryCount: 0,
          estimatedCost: 1.23,
          errorMessage: 'downstream: /v1/responses upstream: /v1/responses',
          username: 'tester',
          siteName: 'main-site',
          siteUrl: 'https://main-site.example.com',
          clientFamily: 'codex',
          clientAppId: 'openclaw',
          clientAppName: 'openclaw',
          clientConfidence: 'exact',
          downstreamKeyName: '移动端灰度',
          downstreamKeyGroupName: '项目A',
          downstreamKeyTags: ['VIP', '灰度'],
        },
      ],
    }));

    let root!: WebTestRenderer;

    try {
      await act(async () => {
        root = create(
          <MemoryRouter initialEntries={['/logs']}>
            <ToastProvider>
              <ProxyLogs />
            </ToastProvider>
          </MemoryRouter>,
        );
      });
      await flushMicrotasks();

      const row = root!.root.find((node) => (
        node.type === 'tr' && node.props['data-testid'] === 'proxy-log-row-101'
      ));
      const rowText = collectText(row);
      expect(rowText).toContain('openclaw');
      expect(rowText).toContain('Codex');
      expect(rowText).not.toContain('推测');
    } finally {
      root?.unmount();
    }
  });

  it('re-queries the server for status, client, and search changes instead of filtering locally', async () => {
    let root!: WebTestRenderer;

    try {
      await act(async () => {
        root = create(
          <MemoryRouter initialEntries={['/logs']}>
            <ToastProvider>
              <ProxyLogs />
            </ToastProvider>
          </MemoryRouter>,
        );
      });
      await flushMicrotasks();

      const failedTab = root!.root.findAll((node) => (
        node.type === 'button' && collectText(node).includes('失败')
      ))[0];
      await act(async () => {
        failedTab.props.onClick();
      });
      await flushMicrotasks();

      const selects = root!.root.findAllByType(ModernSelect);
      const clientSelect = selects.find((node) => node.props.placeholder === '全部客户端');
      expect(clientSelect).toBeDefined();

      await act(async () => {
        clientSelect!.props.onChange('app:cherry_studio');
      });
      await flushMicrotasks();

      const searchInput = root!.root.find((node) => (
        node.type === 'input' && node.props.placeholder === '搜索模型、下游 Key、主分组、标签...'
      ));
      await act(async () => {
        searchInput.props.onChange({ target: { value: 'mini' } });
      });
      await flushMicrotasks();

      expect(apiMock.getProxyLogs).toHaveBeenNthCalledWith(2, {
        limit: 50,
        offset: 0,
        status: 'failed',
        search: '',
      });
      expect(apiMock.getProxyLogs).toHaveBeenNthCalledWith(3, {
        limit: 50,
        offset: 0,
        status: 'failed',
        search: '',
        client: 'app:cherry_studio',
      });
      expect(apiMock.getProxyLogs).toHaveBeenLastCalledWith({
        limit: 50,
        offset: 0,
        status: 'failed',
        search: 'mini',
        client: 'app:cherry_studio',
      });
    } finally {
      root?.unmount();
    }
  });

  it('loads detail on first expand and reuses the cached detail on re-expand', async () => {
    let root!: WebTestRenderer;

    try {
      await act(async () => {
        root = create(
          <MemoryRouter initialEntries={['/logs']}>
            <ToastProvider>
              <ProxyLogs />
            </ToastProvider>
          </MemoryRouter>,
        );
      });
      await flushMicrotasks();

      const row = root!.root.find((node) => (
        node.type === 'tr' && node.props['data-testid'] === 'proxy-log-row-101'
      ));

      await act(async () => {
        row.props.onClick();
      });
      await flushMicrotasks();

      expect(apiMock.getProxyLogDetail).toHaveBeenCalledTimes(1);

      await act(async () => {
        row.props.onClick();
      });
      await flushMicrotasks();

      await act(async () => {
        row.props.onClick();
      });
      await flushMicrotasks();

      expect(apiMock.getProxyLogDetail).toHaveBeenCalledTimes(1);
      expect(apiMock.getProxyLogDetail).toHaveBeenCalledWith(101);
    } finally {
      root?.unmount();
    }
  });

  it('renders unknown usage as -- instead of 0 in the server-driven table', async () => {
    apiMock.getProxyLogs.mockResolvedValue(buildListResponse({
      items: [
        {
          id: 101,
          createdAt: '2026-03-09 16:00:00',
          modelRequested: 'gpt-5',
          modelActual: 'gpt-5',
          status: 'success',
          latencyMs: 120,
          promptTokens: null,
          completionTokens: null,
          totalTokens: null,
          usageSource: 'unknown',
          retryCount: 0,
          estimatedCost: 0,
          errorMessage: '[downstream:/v1/chat/completions] [upstream:/v1/chat/completions] [usage:unknown]',
          username: 'tester',
          siteName: 'main-site',
          siteUrl: 'https://main-site.example.com',
          clientFamily: 'codex',
          clientAppId: 'cherry_studio',
          clientAppName: 'Cherry Studio',
          clientConfidence: 'heuristic',
        },
      ],
      summary: {
        totalCount: 1,
        successCount: 1,
        failedCount: 0,
        totalCost: 0,
        totalTokensAll: 0,
      },
    }));

    let root!: WebTestRenderer;

    try {
      await act(async () => {
        root = create(
          <MemoryRouter initialEntries={['/logs']}>
            <ToastProvider>
              <ProxyLogs />
            </ToastProvider>
          </MemoryRouter>,
        );
      });
      await flushMicrotasks();

      const row = root!.root.find((node) => (
        node.type === 'tr' && node.props['data-testid'] === 'proxy-log-row-101'
      ));
      const rowText = collectText(row);
      expect(rowText).toContain('--');
      expect(rowText).not.toContain('输入0');
    } finally {
      root?.unmount();
    }
  });

  it('hydrates site and time filters from the route query', async () => {
    let root!: WebTestRenderer;

    try {
      await act(async () => {
        root = create(
          <MemoryRouter initialEntries={['/logs?siteId=9&client=family%3Acodex&from=2026-03-09T08:00&to=2026-03-09T09:00']}>
            <ToastProvider>
              <ProxyLogs />
            </ToastProvider>
          </MemoryRouter>,
        );
      });
      await flushMicrotasks();

      const expectedFrom = new Date(2026, 2, 9, 8, 0).toISOString();
      const expectedTo = new Date(2026, 2, 9, 9, 0).toISOString();
      expect(apiMock.getProxyLogs).toHaveBeenCalledWith({
        limit: 50,
        offset: 0,
        status: 'all',
        search: '',
        siteId: 9,
        client: 'family:codex',
        from: expectedFrom,
        to: expectedTo,
      });

      const rendered = JSON.stringify(root!.toJSON());
      expect(rendered).toContain('main-site');
    } finally {
      root?.unmount();
    }
  });
});
