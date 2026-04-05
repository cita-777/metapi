import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, create } from 'react-test-renderer';
import { MemoryRouter } from 'react-router-dom';
import { ToastProvider } from '../components/Toast.js';
import OAuthManagement from './OAuthManagement.js';

const { apiMock, openMock, focusMock, confirmMock, promptMock } = vi.hoisted(() => ({
  apiMock: {
    getOAuthProviders: vi.fn(),
    getOAuthConnections: vi.fn(),
    startOAuthProvider: vi.fn(),
    getOAuthSession: vi.fn(),
    submitOAuthManualCallback: vi.fn(),
    refreshOAuthConnectionQuota: vi.fn(),
    refreshOAuthConnectionQuotaBatch: vi.fn(),
    rebindOAuthConnection: vi.fn(),
    deleteOAuthConnection: vi.fn(),
    importOAuthConnections: vi.fn(),
    getAccountModels: vi.fn(),
    checkModels: vi.fn(),
  },
  openMock: vi.fn(),
  focusMock: vi.fn(),
  confirmMock: vi.fn(),
  promptMock: vi.fn(),
}));

vi.mock('../api.js', () => ({
  api: apiMock,
}));

function collectText(node: any): string {
  const children = node?.children || [];
  return children.map((child: any) => {
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

function findButton(root: WebTestRenderer, label: string) {
  return root.root.find((node) => (
    node.type === 'button'
    && typeof node.props.onClick === 'function'
    && collectText(node).includes(label)
  ));
}

function findOauthSettingInput(root: WebTestRenderer, key: string) {
  return root.root.find((node) => (
    node.type === 'input'
    && node.props['data-oauth-setting'] === key
  ));
}

function findAllByClassName(root: WebTestRenderer, className: string) {
  return root.root.findAll((node) => (
    typeof node.props?.className === 'string'
    && node.props.className.split(' ').includes(className)
  ));
}

function findHeaders(root: WebTestRenderer, label: string) {
  return root.root.findAll((node) => node.type === 'th' && collectText(node) === label);
}

async function clickButton(root: WebTestRenderer, label: string) {
  const button = findButton(root, label);
  await act(async () => {
    await button.props.onClick();
  });
  await flushMicrotasks();
  return button;
}

describe('OAuthManagement page', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.clearAllMocks();
    Object.values(apiMock).forEach((mock) => mock.mockReset());
    openMock.mockReturnValue({ focus: focusMock });
    confirmMock.mockReturnValue(true);
    promptMock.mockReturnValue('project-demo');
    vi.stubGlobal('window', {
      open: openMock,
      confirm: confirmMock,
      prompt: promptMock,
      setTimeout,
      clearTimeout,
    } as unknown as Window & typeof globalThis);
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
    vi.clearAllMocks();
  });

  it('renders available oauth providers and existing oauth connections', async () => {
    apiMock.getOAuthProviders.mockResolvedValue({
      providers: [
        {
          provider: 'codex',
          label: 'Codex',
          platform: 'codex',
          enabled: true,
          loginType: 'oauth',
          requiresProjectId: false,
          supportsDirectAccountRouting: true,
          supportsCloudValidation: true,
          supportsNativeProxy: true,
        },
        {
          provider: 'gemini-cli',
          label: 'Gemini CLI',
          platform: 'gemini-cli',
          enabled: true,
          loginType: 'oauth',
          requiresProjectId: true,
          supportsDirectAccountRouting: true,
          supportsCloudValidation: true,
          supportsNativeProxy: true,
        },
      ],
    });
    apiMock.getOAuthConnections.mockResolvedValue({
      items: [
        {
          accountId: 7,
          provider: 'codex',
          email: 'codex-user@example.com',
          accountKey: 'chatgpt-account-123',
          planType: 'plus',
          modelCount: 3,
          modelsPreview: ['gpt-5', 'gpt-5-mini', 'gpt-5.2-codex'],
          status: 'healthy',
        },
      ],
      total: 1,
      limit: 100,
      offset: 0,
    });

    let root!: WebTestRenderer;
    try {
      await act(async () => {
        root = create(
          <ToastProvider>
            <MemoryRouter>
              <OAuthManagement />
            </MemoryRouter>
          </ToastProvider>,
        );
      });
      await vi.waitFor(async () => {
        await flushMicrotasks();
        const text = collectText(root!.root);
        expect(text).toContain('OAuth 管理');
        expect(text).toContain('Codex');
        expect(text).toContain('Gemini CLI');
        expect(text).toContain('codex-user@example.com');
        expect(text).toContain('plus');
        expect(text).toContain('3 个模型');
        expect(text).toContain('chatgpt-account-123');
      });
    } finally {
      root?.unmount();
    }
  });

  it('renders the oauth workbench toolbar and supports batch quota refresh', async () => {
    apiMock.getOAuthProviders.mockResolvedValue({
      providers: [
        {
          provider: 'codex',
          label: 'Codex',
          platform: 'codex',
          enabled: true,
          loginType: 'oauth',
          requiresProjectId: false,
          supportsDirectAccountRouting: true,
          supportsCloudValidation: true,
          supportsNativeProxy: true,
        },
      ],
    });
    apiMock.getOAuthConnections
      .mockResolvedValueOnce({
        items: [
          {
            accountId: 7,
            siteId: 2,
            provider: 'codex',
            email: 'codex-user@example.com',
            accountKey: 'chatgpt-account-123',
            planType: 'plus',
            modelCount: 3,
            modelsPreview: ['gpt-5', 'gpt-5-mini', 'gpt-5.2-codex'],
            status: 'healthy',
            routeChannelCount: 2,
            site: {
              id: 2,
              name: 'ChatGPT Codex OAuth',
              url: 'https://chatgpt.com/backend-api/codex',
              platform: 'codex',
            },
          },
        ],
        total: 1,
        limit: 100,
        offset: 0,
      })
      .mockResolvedValueOnce({
        items: [
          {
            accountId: 7,
            siteId: 2,
            provider: 'codex',
            email: 'codex-user@example.com',
            accountKey: 'chatgpt-account-123',
            planType: 'plus',
            modelCount: 3,
            modelsPreview: ['gpt-5', 'gpt-5-mini', 'gpt-5.2-codex'],
            status: 'healthy',
            routeChannelCount: 2,
            site: {
              id: 2,
              name: 'ChatGPT Codex OAuth',
              url: 'https://chatgpt.com/backend-api/codex',
              platform: 'codex',
            },
          },
        ],
        total: 1,
        limit: 100,
        offset: 0,
      });
    apiMock.refreshOAuthConnectionQuotaBatch.mockResolvedValue({
      success: true,
      refreshed: 1,
      failed: 0,
      items: [
        {
          accountId: 7,
          success: true,
          quota: {
            status: 'supported',
            source: 'reverse_engineered',
            windows: {
              fiveHour: { supported: false },
              sevenDay: { supported: false },
            },
          },
        },
      ],
    });

    let root!: WebTestRenderer;
    try {
      await act(async () => {
        root = create(
          <ToastProvider>
            <MemoryRouter>
              <OAuthManagement />
            </MemoryRouter>
          </ToastProvider>,
        );
      });
      await flushMicrotasks();

      const text = collectText(root.root);
      expect(text).toContain('新建 OAuth 连接');
      expect(text).toContain('导入 JSON');
      expect(text).toContain('自动刷新');
      expect(findAllByClassName(root, 'oauth-toolbar-meta')).toHaveLength(0);

      const selectAll = root.root.find((node) => (
        node.type === 'input'
        && node.props.type === 'checkbox'
        && node.props['data-testid'] === 'oauth-select-all'
      ));

      await act(async () => {
        selectAll.props.onChange({ target: { checked: true } });
      });

      const batchRefreshButton = root.root.find((node) => (
        node.type === 'button'
        && typeof node.props.onClick === 'function'
        && collectText(node).includes('批量刷新额度')
      ));

      await act(async () => {
        await batchRefreshButton.props.onClick();
      });
      await flushMicrotasks();

      expect(apiMock.refreshOAuthConnectionQuotaBatch).toHaveBeenCalledWith([7]);
      expect(apiMock.getOAuthConnections).toHaveBeenCalledTimes(2);
    } finally {
      root?.unmount();
    }
  });

  it('opens a models modal from the model count trigger and loads the full model list', async () => {
    apiMock.getOAuthProviders.mockResolvedValue({
      providers: [
        {
          provider: 'codex',
          label: 'Codex',
          platform: 'codex',
          enabled: true,
          loginType: 'oauth',
          requiresProjectId: false,
          supportsDirectAccountRouting: true,
          supportsCloudValidation: true,
          supportsNativeProxy: true,
        },
      ],
    });
    apiMock.getOAuthConnections.mockResolvedValue({
      items: [
        {
          accountId: 52,
          siteId: 44,
          provider: 'codex',
          username: 'Juricek Team A',
          email: 'juricek.chen@gmail.com',
          accountKey: 'chatgpt-account-123',
          planType: 'team',
          modelCount: 12,
          modelsPreview: ['gpt-5.4', 'gpt-5.4-mini', 'gpt-5.3-codex'],
          status: 'healthy',
          routeChannelCount: 12,
          site: {
            id: 44,
            name: 'ChatGPT Codex OAuth',
            url: 'https://chatgpt.com/backend-api/codex',
            platform: 'codex',
          },
        },
      ],
      total: 1,
      limit: 100,
      offset: 0,
    });
    apiMock.getAccountModels.mockResolvedValue({
      siteId: 44,
      siteName: 'ChatGPT Codex OAuth',
      totalCount: 4,
      disabledCount: 1,
      models: [
        { name: 'gpt-5.4', latencyMs: 120, disabled: false },
        { name: 'gpt-5.4-mini', latencyMs: 90, disabled: false },
        { name: 'gpt-5.3-codex', latencyMs: 110, disabled: false },
        { name: 'gpt-5.2-codex', latencyMs: null, disabled: true, isManual: true },
      ],
    });

    let root!: WebTestRenderer;
    try {
      await act(async () => {
        root = create(
          <ToastProvider>
            <MemoryRouter>
              <OAuthManagement />
            </MemoryRouter>
          </ToastProvider>,
        );
      });
      await flushMicrotasks();

      await clickButton(root, 'Juricek Team A');

      await vi.waitFor(async () => {
        await flushMicrotasks();
        const text = collectText(root.root);
        expect(text).toContain('模型列表 · Juricek Team A');
        expect(text).toContain('ChatGPT Codex OAuth · 共 4 个模型');
        expect(text).toContain('gpt-5.2-codex');
        expect(text).toContain('禁用');
      });

      expect(apiMock.getAccountModels).toHaveBeenCalledWith(52);
    } finally {
      root?.unmount();
    }
  });

  it('renders supported quota windows without duplicating raw counters beside the percent', async () => {
    apiMock.getOAuthProviders.mockResolvedValue({
      providers: [
        {
          provider: 'codex',
          label: 'Codex',
          platform: 'codex',
          enabled: true,
          loginType: 'oauth',
          requiresProjectId: false,
          supportsDirectAccountRouting: true,
          supportsCloudValidation: true,
          supportsNativeProxy: true,
        },
      ],
    });
    apiMock.getOAuthConnections.mockResolvedValue({
      items: [
        {
          accountId: 91,
          provider: 'codex',
          email: 'quota-user@example.com',
          planType: 'team',
          modelCount: 12,
          modelsPreview: ['gpt-5.4'],
          status: 'healthy',
          quota: {
            status: 'supported',
            source: 'reverse_engineered',
            lastSyncAt: '2026-03-18T01:00:00.000Z',
            windows: {
              fiveHour: {
                supported: true,
                used: 100,
                limit: 100,
                resetAt: '2999-03-18T01:28:00.000Z',
              },
              sevenDay: {
                supported: true,
                used: 81,
                limit: 100,
                resetAt: '2999-03-22T17:00:00.000Z',
              },
            },
          },
        },
      ],
      total: 1,
      limit: 100,
      offset: 0,
    });

    let root!: WebTestRenderer;
    try {
      await act(async () => {
        root = create(
          <ToastProvider>
            <MemoryRouter>
              <OAuthManagement />
            </MemoryRouter>
          </ToastProvider>,
        );
      });
      await vi.waitFor(async () => {
        await flushMicrotasks();
        const text = collectText(root.root);
        expect(text).toContain('100%');
        expect(text).toContain('81%');
        expect(text).not.toContain('100 / 100');
        expect(text).not.toContain('81 / 100');
        expect(findHeaders(root, '模型 / 路由')).toHaveLength(0);
        expect(findHeaders(root, '同步')).toHaveLength(0);
      });
    } finally {
      root?.unmount();
    }
  });

  it('previews native oauth json in the workbench modal and closes after adding', async () => {
    apiMock.getOAuthProviders.mockResolvedValue({
      providers: [
        {
          provider: 'codex',
          label: 'Codex',
          platform: 'codex',
          enabled: true,
          loginType: 'oauth',
          requiresProjectId: false,
          supportsDirectAccountRouting: true,
          supportsCloudValidation: true,
          supportsNativeProxy: true,
        },
      ],
    });
    apiMock.getOAuthConnections
      .mockResolvedValueOnce({ items: [], total: 0, limit: 100, offset: 0 })
      .mockResolvedValueOnce({
        items: [
          {
            accountId: 7,
            provider: 'codex',
            email: 'imported@example.com',
            accountKey: 'chatgpt-account-123',
            planType: 'plus',
            modelCount: 0,
            modelsPreview: [],
            status: 'healthy',
          },
        ],
        total: 1,
        limit: 100,
        offset: 0,
      });
    apiMock.importOAuthConnections.mockResolvedValue({
      success: true,
      imported: 1,
      skipped: 0,
      failed: 0,
      items: [
        {
          name: 'Imported Codex OAuth',
          status: 'imported',
          accountId: 7,
          provider: 'codex',
        },
      ],
    });

    let root!: WebTestRenderer;
    try {
      await act(async () => {
        root = create(
          <ToastProvider>
            <MemoryRouter>
              <OAuthManagement />
            </MemoryRouter>
          </ToastProvider>,
        );
      });
      await flushMicrotasks();

      await clickButton(root, '导入 JSON');

      const textarea = root.root.find((node) => (
        node.type === 'textarea'
        && typeof node.props.placeholder === 'string'
        && node.props.placeholder.includes('"access_token"')
      ));

      expect(collectText(root.root)).not.toContain('sub2api');

      await act(async () => {
        textarea.props.onChange({
          target: {
            value: JSON.stringify({
              type: 'codex',
              access_token: 'oauth-access-token',
              refresh_token: 'oauth-refresh-token',
            }),
          },
        });
      });

      expect(collectText(root.root)).toContain('识别结果');
      expect(collectText(root.root)).toContain('结构有效');
      expect(collectText(root.root)).toContain('Codex');

      await clickButton(root, '添加');

      expect(apiMock.importOAuthConnections).toHaveBeenCalledWith({
        type: 'codex',
        access_token: 'oauth-access-token',
        refresh_token: 'oauth-refresh-token',
      });
      await act(async () => {
        vi.advanceTimersByTime(300);
      });
      await flushMicrotasks();
      expect(collectText(root.root)).toContain('已添加 1 个 OAuth 连接');
      expect(collectText(root.root)).not.toContain('导入 OAuth 连接 JSON');
      expect(apiMock.getOAuthConnections).toHaveBeenCalledTimes(2);
    } finally {
      root?.unmount();
    }
  });

  it('supports selecting multiple json files and imports them sequentially', async () => {
    apiMock.getOAuthProviders.mockResolvedValue({
      providers: [
        {
          provider: 'codex',
          label: 'Codex',
          platform: 'codex',
          enabled: true,
          loginType: 'oauth',
          requiresProjectId: false,
          supportsDirectAccountRouting: true,
          supportsCloudValidation: true,
          supportsNativeProxy: true,
        },
      ],
    });
    apiMock.getOAuthConnections
      .mockResolvedValueOnce({ items: [], total: 0, limit: 100, offset: 0 })
      .mockResolvedValueOnce({
        items: [
          {
            accountId: 9,
            provider: 'codex',
            email: 'imported@example.com',
            accountKey: 'chatgpt-account-456',
            planType: 'team',
            modelCount: 0,
            modelsPreview: [],
            status: 'healthy',
          },
        ],
        total: 1,
        limit: 100,
        offset: 0,
      });
    apiMock.importOAuthConnections
      .mockResolvedValueOnce({
        success: true,
        imported: 1,
        skipped: 0,
        failed: 0,
        items: [
          {
            name: 'Workspace A',
            status: 'imported',
            accountId: 7,
            provider: 'codex',
          },
        ],
      })
      .mockResolvedValueOnce({
        success: true,
        imported: 1,
        skipped: 1,
        failed: 0,
        items: [
          {
            name: 'Workspace B',
            status: 'imported',
            accountId: 9,
            provider: 'codex',
          },
          {
            name: 'Skipped API Key',
            status: 'skipped',
            message: 'not oauth',
          },
        ],
      });

    const fileA = {
      name: 'workspace-a.json',
      text: vi.fn().mockResolvedValue(JSON.stringify({
        type: 'codex',
        access_token: 'oauth-access-token-a',
        email: 'workspace-a@example.com',
      })),
    };
    const fileB = {
      name: 'workspace-b.json',
      text: vi.fn().mockResolvedValue(JSON.stringify({
        type: 'codex',
        access_token: 'oauth-access-token-b',
        email: 'workspace-b@example.com',
      })),
    };

    let root!: WebTestRenderer;
    try {
      await act(async () => {
        root = create(
          <ToastProvider>
            <MemoryRouter>
              <OAuthManagement />
            </MemoryRouter>
          </ToastProvider>,
        );
      });
      await flushMicrotasks();

      await clickButton(root, '导入 JSON');

      const fileInput = root.root.find((node) => (
        node.type === 'input'
        && node.props.type === 'file'
        && node.props['data-testid'] === 'oauth-import-file-input'
      ));

      expect(fileInput.props.multiple).toBe(true);

      await act(async () => {
        await fileInput.props.onChange({
          target: {
            files: [fileA, fileB],
          },
        });
      });
      await flushMicrotasks();

      const importText = collectText(root.root);
      expect(importText).toContain('workspace-a.json');
      expect(importText).toContain('workspace-b.json');
      expect(importText).toContain('已识别 2 份 JSON');
      expect(importText).toContain('结构有效');

      await clickButton(root, '添加');

      expect(apiMock.importOAuthConnections).toHaveBeenCalledTimes(2);
      expect(apiMock.importOAuthConnections).toHaveBeenNthCalledWith(1, {
        type: 'codex',
        access_token: 'oauth-access-token-a',
        email: 'workspace-a@example.com',
      });
      expect(apiMock.importOAuthConnections).toHaveBeenNthCalledWith(2, {
        type: 'codex',
        access_token: 'oauth-access-token-b',
        email: 'workspace-b@example.com',
      });
      await act(async () => {
        vi.advanceTimersByTime(300);
      });
      await flushMicrotasks();
      expect(collectText(root.root)).toContain('已添加 2 个 OAuth 连接');
      expect(collectText(root.root)).not.toContain('导入 OAuth 连接 JSON');
      expect(apiMock.getOAuthConnections).toHaveBeenCalledTimes(2);
    } finally {
      root?.unmount();
    }
  });

  it('shows native oauth guidance when import starts without sources', async () => {
    apiMock.getOAuthProviders.mockResolvedValue({
      providers: [
        {
          provider: 'codex',
          label: 'Codex',
          platform: 'codex',
          enabled: true,
          loginType: 'oauth',
          requiresProjectId: false,
          supportsDirectAccountRouting: true,
          supportsCloudValidation: true,
          supportsNativeProxy: true,
        },
      ],
    });
    apiMock.getOAuthConnections.mockResolvedValue({ items: [], total: 0, limit: 100, offset: 0 });

    let root!: WebTestRenderer;
    try {
      await act(async () => {
        root = create(
          <ToastProvider>
            <MemoryRouter>
              <OAuthManagement />
            </MemoryRouter>
          </ToastProvider>,
        );
      });
      await flushMicrotasks();

      await clickButton(root, '导入 JSON');
      await clickButton(root, '添加');

      expect(collectText(root.root)).toContain('请先选择 JSON 文件或粘贴 OAuth 连接 JSON 内容');
    } finally {
      root?.unmount();
    }
  });

  it('shows invalid preview feedback before adding oauth json', async () => {
    apiMock.getOAuthProviders.mockResolvedValue({
      providers: [
        {
          provider: 'codex',
          label: 'Codex',
          platform: 'codex',
          enabled: true,
          loginType: 'oauth',
          requiresProjectId: false,
          supportsDirectAccountRouting: true,
          supportsCloudValidation: true,
          supportsNativeProxy: true,
        },
      ],
    });
    apiMock.getOAuthConnections.mockResolvedValue({ items: [], total: 0, limit: 100, offset: 0 });

    let root!: WebTestRenderer;
    try {
      await act(async () => {
        root = create(
          <ToastProvider>
            <MemoryRouter>
              <OAuthManagement />
            </MemoryRouter>
          </ToastProvider>,
        );
      });
      await flushMicrotasks();

      await clickButton(root, '导入 JSON');

      const textarea = root.root.find((node) => (
        node.type === 'textarea'
        && typeof node.props.placeholder === 'string'
        && node.props.placeholder.includes('"access_token"')
      ));

      await act(async () => {
        textarea.props.onChange({
          target: {
            value: '{"type":"codex"}',
          },
        });
      });

      const addButton = findButton(root, '添加');
      expect(addButton.props.disabled).toBe(true);
      expect(collectText(root.root)).toContain('结构无效');
      expect(collectText(root.root)).toContain('缺少 access_token');
    } finally {
      root?.unmount();
    }
  });

  it('starts oauth, opens popup, polls status, and refreshes connection list after success', async () => {
    apiMock.getOAuthProviders.mockResolvedValue({
      providers: [
        {
          provider: 'codex',
          label: 'Codex',
          platform: 'codex',
          enabled: true,
          loginType: 'oauth',
          requiresProjectId: false,
          supportsDirectAccountRouting: true,
          supportsCloudValidation: true,
          supportsNativeProxy: true,
        },
        {
          provider: 'gemini-cli',
          label: 'Gemini CLI',
          platform: 'gemini-cli',
          enabled: true,
          loginType: 'oauth',
          requiresProjectId: true,
          supportsDirectAccountRouting: true,
          supportsCloudValidation: true,
          supportsNativeProxy: true,
        },
      ],
    });
    apiMock.getOAuthConnections
      .mockResolvedValueOnce({ items: [], total: 0, limit: 100, offset: 0 })
      .mockResolvedValueOnce({
        items: [
          {
            accountId: 7,
            provider: 'codex',
            email: 'codex-user@example.com',
            accountKey: 'chatgpt-account-123',
            planType: 'plus',
            modelCount: 3,
            modelsPreview: ['gpt-5', 'gpt-5-mini', 'gpt-5.2-codex'],
            status: 'healthy',
          },
        ],
        total: 1,
        limit: 100,
        offset: 0,
      });
    apiMock.startOAuthProvider.mockResolvedValue({
      provider: 'codex',
      state: 'oauth-state-123',
      authorizationUrl: 'https://auth.openai.com/oauth/authorize?state=oauth-state-123',
      instructions: {
        redirectUri: 'http://localhost:1455/auth/callback',
        callbackPort: 1455,
        callbackPath: '/auth/callback',
        manualCallbackDelayMs: 15000,
        sshTunnelCommand: 'ssh -L 1455:127.0.0.1:1455 root@metapi.example -p 22',
      },
    });
    apiMock.getOAuthSession
      .mockResolvedValueOnce({
        provider: 'codex',
        state: 'oauth-state-123',
        status: 'pending',
      })
      .mockResolvedValueOnce({
        provider: 'codex',
        state: 'oauth-state-123',
        status: 'success',
        accountId: 7,
      });

    let root!: WebTestRenderer;
    try {
      await act(async () => {
        root = create(
          <ToastProvider>
            <MemoryRouter>
              <OAuthManagement />
            </MemoryRouter>
          </ToastProvider>,
        );
      });
      await vi.waitFor(async () => {
        await flushMicrotasks();
      });

      await clickButton(root!, '新建 OAuth 连接');

      const proxyToggle = findOauthSettingInput(root!, 'use-custom-proxy');

      await act(async () => {
        proxyToggle.props.onChange({ target: { checked: true } });
      });

      const proxyInput = findOauthSettingInput(root!, 'proxy-url');

      await act(async () => {
        proxyInput.props.onChange({ target: { value: 'http://127.0.0.1:7890' } });
      });

      await clickButton(root!, '连接 Codex');
      await vi.waitFor(async () => {
        await flushMicrotasks();
      });

      expect(apiMock.startOAuthProvider).toHaveBeenCalledWith('codex', {
        projectId: undefined,
        proxyUrl: 'http://127.0.0.1:7890',
        useSystemProxy: false,
      });
      expect(openMock).toHaveBeenCalledWith(
        'https://auth.openai.com/oauth/authorize?state=oauth-state-123',
        'oauth-codex',
        expect.stringContaining('width=540'),
      );
      expect(collectText(root!.root)).toContain('本地部署');
      expect(collectText(root!.root)).toContain('云端部署');
      expect(collectText(root!.root)).toContain('ssh -L 1455:127.0.0.1:1455 root@metapi.example -p 22');

      await act(async () => {
        vi.advanceTimersByTime(1600);
      });
      await vi.waitFor(async () => {
        await flushMicrotasks();
      });

      await act(async () => {
        vi.advanceTimersByTime(1600);
      });
      await vi.waitFor(async () => {
        await flushMicrotasks();
      });

      expect(apiMock.getOAuthSession).toHaveBeenCalledWith('oauth-state-123');
      expect(apiMock.getOAuthConnections).toHaveBeenCalledTimes(2);
      const text = collectText(root!.root);
      expect(text).toContain('授权成功');
      expect(text).toContain('codex-user@example.com');
    } finally {
      root?.unmount();
    }
  });

  it('reveals manual callback input after delay and submits the pasted callback url', async () => {
    apiMock.getOAuthProviders.mockResolvedValue({
      providers: [
        {
          provider: 'claude',
          label: 'Claude',
          platform: 'claude',
          enabled: true,
          loginType: 'oauth',
          requiresProjectId: false,
          supportsDirectAccountRouting: true,
          supportsCloudValidation: true,
          supportsNativeProxy: true,
        },
      ],
    });
    apiMock.getOAuthConnections.mockResolvedValue({ items: [], total: 0, limit: 100, offset: 0 });
    apiMock.startOAuthProvider.mockResolvedValue({
      provider: 'claude',
      state: 'oauth-state-456',
      authorizationUrl: 'https://claude.ai/oauth/authorize?state=oauth-state-456',
      instructions: {
        redirectUri: 'http://localhost:54545/callback',
        callbackPort: 54545,
        callbackPath: '/callback',
        manualCallbackDelayMs: 15000,
        sshTunnelCommand: 'ssh -L 54545:127.0.0.1:54545 root@metapi.example -p 22',
      },
    });
    apiMock.getOAuthSession.mockResolvedValue({
      provider: 'claude',
      state: 'oauth-state-456',
      status: 'pending',
    });
    apiMock.submitOAuthManualCallback.mockResolvedValue({ success: true });

    let root!: WebTestRenderer;
    try {
      await act(async () => {
        root = create(
          <ToastProvider>
            <MemoryRouter>
              <OAuthManagement />
            </MemoryRouter>
          </ToastProvider>,
        );
      });
      await vi.waitFor(async () => {
        await flushMicrotasks();
      });

      await clickButton(root!, '新建 OAuth 连接');
      await clickButton(root!, '连接 Claude');
      await vi.waitFor(async () => {
        await flushMicrotasks();
      });

      expect(collectText(root!.root)).not.toContain('提交回调 URL');

      await act(async () => {
        vi.advanceTimersByTime(15000);
      });
      await vi.waitFor(async () => {
        await flushMicrotasks();
        expect(collectText(root!.root)).toContain('提交回调 URL');
        expect(collectText(root!.root)).toContain('手动回调');
      });

      const textInput = root!.root.find((node) => (
        node.type === 'textarea'
        && node.props.value !== undefined
      ));

      await act(async () => {
        textInput.props.onChange({ target: { value: 'http://localhost:54545/callback?code=test-code&state=oauth-state-456' } });
      });

      const submitButton = root!.root.find((node) => (
        node.type === 'button'
        && typeof node.props.onClick === 'function'
        && collectText(node).includes('提交回调 URL')
      ));

      await act(async () => {
        await submitButton.props.onClick();
      });
      await vi.waitFor(async () => {
        await flushMicrotasks();
      });

      expect(apiMock.submitOAuthManualCallback).toHaveBeenCalledWith(
        'oauth-state-456',
        'http://localhost:54545/callback?code=test-code&state=oauth-state-456',
      );
      expect(collectText(root!.root)).toContain('如果浏览器停在 localhost 错误页');
    } finally {
      root?.unmount();
    }
  });

  it('explains oauth usage and disables unavailable providers', async () => {
    apiMock.getOAuthProviders.mockResolvedValue({
      providers: [
        {
          provider: 'codex',
          label: 'Codex',
          platform: 'codex',
          enabled: false,
          loginType: 'oauth',
          requiresProjectId: false,
          supportsDirectAccountRouting: true,
          supportsCloudValidation: true,
          supportsNativeProxy: true,
        },
      ],
    });
    apiMock.getOAuthConnections.mockResolvedValue({
      items: [],
      total: 0,
      limit: 100,
      offset: 0,
    });

    let root!: WebTestRenderer;
    try {
      await act(async () => {
        root = create(
          <ToastProvider>
            <MemoryRouter>
              <OAuthManagement />
            </MemoryRouter>
          </ToastProvider>,
        );
      });
      await vi.waitFor(async () => {
        await flushMicrotasks();
        const text = collectText(root!.root);
        expect(text).toContain('官方上游连接');
        expect(text).toContain('CLI');
        expect(text).toContain('API Key');
      });

      await clickButton(root!, '新建 OAuth 连接');
      const startButton = findButton(root!, '连接 Codex');
      expect(startButton.props.disabled).toBe(true);
      expect(collectText(root!.root)).toContain('当前环境未启用');
    } finally {
      root?.unmount();
    }
  });

  it('prefers renamed account title and still shows oauth email', async () => {
    apiMock.getOAuthProviders.mockResolvedValue({
      providers: [
        {
          provider: 'codex',
          label: 'Codex',
          platform: 'codex',
          enabled: true,
          loginType: 'oauth',
          requiresProjectId: false,
          supportsDirectAccountRouting: true,
          supportsCloudValidation: true,
          supportsNativeProxy: true,
        },
      ],
    });
    apiMock.getOAuthConnections.mockResolvedValue({
      items: [
        {
          accountId: 7,
          provider: 'codex',
          username: 'Juricek Team A',
          email: 'juricek.chen@gmail.com',
          accountKey: 'chatgpt-account-123',
          planType: 'team',
          modelCount: 11,
          modelsPreview: ['gpt-5.4'],
          status: 'healthy',
          routeChannelCount: 11,
        },
      ],
      total: 1,
      limit: 100,
      offset: 0,
    });

    let root!: WebTestRenderer;
    try {
      await act(async () => {
        root = create(
          <ToastProvider>
            <MemoryRouter>
              <OAuthManagement />
            </MemoryRouter>
          </ToastProvider>,
        );
      });
      await vi.waitFor(async () => {
        await flushMicrotasks();
        const text = collectText(root!.root);
        expect(text).toContain('Juricek Team A');
        expect(text).toContain('juricek.chen@gmail.com');
      });
    } finally {
      root?.unmount();
    }
  });

  it('allows starting gemini oauth without entering a project id', async () => {
    promptMock.mockReturnValueOnce('');
    apiMock.getOAuthProviders.mockResolvedValue({
      providers: [
        {
          provider: 'gemini-cli',
          label: 'Gemini CLI',
          platform: 'gemini-cli',
          enabled: true,
          loginType: 'oauth',
          requiresProjectId: true,
          supportsDirectAccountRouting: true,
          supportsCloudValidation: true,
          supportsNativeProxy: true,
        },
      ],
    });
    apiMock.getOAuthConnections.mockResolvedValue({
      items: [],
      total: 0,
      limit: 100,
      offset: 0,
    });
    apiMock.startOAuthProvider.mockResolvedValue({
      provider: 'gemini-cli',
      state: 'gemini-state-123',
      authorizationUrl: 'https://accounts.google.com/o/oauth2/v2/auth?state=gemini-state-123',
      instructions: {
        redirectUri: 'http://localhost:8085/oauth2callback',
        callbackPort: 8085,
        callbackPath: '/oauth2callback',
        manualCallbackDelayMs: 15000,
      },
    });
    apiMock.getOAuthSession.mockResolvedValue({
      provider: 'gemini-cli',
      state: 'gemini-state-123',
      status: 'pending',
    });

    let root!: WebTestRenderer;
    try {
      await act(async () => {
        root = create(
          <ToastProvider>
            <MemoryRouter>
              <OAuthManagement />
            </MemoryRouter>
          </ToastProvider>,
        );
      });
      await vi.waitFor(async () => {
        await flushMicrotasks();
      });

      await clickButton(root!, '新建 OAuth 连接');
      await clickButton(root!, '连接 Gemini CLI');
      await vi.waitFor(async () => {
        await flushMicrotasks();
      });

      expect(apiMock.startOAuthProvider).toHaveBeenCalledWith('gemini-cli', { projectId: undefined });
      expect(openMock).toHaveBeenCalledWith(
        'https://accounts.google.com/o/oauth2/v2/auth?state=gemini-state-123',
        'oauth-gemini-cli',
        expect.stringContaining('width=540'),
      );
      expect(collectText(root!.root)).not.toContain('Gemini CLI 连接需要 Project ID');
    } finally {
      root?.unmount();
    }
  });

  it('rebinds gemini oauth without prompting for a project id again', async () => {
    apiMock.getOAuthProviders.mockResolvedValue({
      providers: [
        {
          provider: 'gemini-cli',
          label: 'Gemini CLI',
          platform: 'gemini-cli',
          enabled: true,
          loginType: 'oauth',
          requiresProjectId: true,
          supportsDirectAccountRouting: true,
          supportsCloudValidation: true,
          supportsNativeProxy: true,
        },
      ],
    });
    apiMock.getOAuthConnections.mockResolvedValue({
      items: [
        {
          accountId: 11,
          provider: 'gemini-cli',
          email: 'gemini-user@example.com',
          planType: 'cloud',
          modelCount: 2,
          modelsPreview: ['gemini-2.5-pro', 'gemini-2.5-flash'],
          status: 'healthy',
          projectId: 'project-demo',
          routeChannelCount: 0,
        },
      ],
      total: 1,
      limit: 100,
      offset: 0,
    });
    apiMock.rebindOAuthConnection.mockResolvedValue({
      provider: 'gemini-cli',
      state: 'gemini-rebind-123',
      authorizationUrl: 'https://accounts.google.com/o/oauth2/v2/auth?state=gemini-rebind-123',
      instructions: {
        redirectUri: 'http://localhost:8085/oauth2callback',
        callbackPort: 8085,
        callbackPath: '/oauth2callback',
        manualCallbackDelayMs: 15000,
      },
    });
    apiMock.getOAuthSession.mockResolvedValue({
      provider: 'gemini-cli',
      state: 'gemini-rebind-123',
      status: 'pending',
    });

    let root!: WebTestRenderer;
    try {
      await act(async () => {
        root = create(
          <ToastProvider>
            <MemoryRouter>
              <OAuthManagement />
            </MemoryRouter>
          </ToastProvider>,
        );
      });
      await vi.waitFor(async () => {
        await flushMicrotasks();
      });

      await clickButton(root!, '重新授权');
      await clickButton(root!, '重新授权 Gemini CLI');
      await vi.waitFor(async () => {
        await flushMicrotasks();
      });

      expect(promptMock).not.toHaveBeenCalled();
      expect(apiMock.rebindOAuthConnection).toHaveBeenCalledWith(11, {});
      expect(openMock).toHaveBeenCalledWith(
        'https://accounts.google.com/o/oauth2/v2/auth?state=gemini-rebind-123',
        'oauth-gemini-cli',
        expect.stringContaining('width=540'),
      );
    } finally {
      root?.unmount();
    }
  });

  it('reuses the stored account proxy for rebind when no new override is selected', async () => {
    apiMock.getOAuthProviders.mockResolvedValue({
      providers: [
        {
          provider: 'gemini-cli',
          label: 'Gemini CLI',
          platform: 'gemini-cli',
          enabled: true,
          loginType: 'oauth',
          requiresProjectId: true,
          supportsDirectAccountRouting: true,
          supportsCloudValidation: true,
          supportsNativeProxy: true,
        },
      ],
    });
    apiMock.getOAuthConnections.mockResolvedValue({
      items: [
        {
          accountId: 11,
          provider: 'gemini-cli',
          email: 'gemini@example.com',
          projectId: 'project-demo',
          modelCount: 5,
          modelsPreview: ['gemini-2.5-pro'],
          status: 'healthy',
          proxyUrl: 'http://127.0.0.1:7890',
        },
      ],
      total: 1,
      limit: 100,
      offset: 0,
    });
    apiMock.rebindOAuthConnection.mockResolvedValue({
      provider: 'gemini-cli',
      state: 'gemini-rebind-proxy',
      authorizationUrl: 'https://accounts.google.com/o/oauth2/v2/auth?state=gemini-rebind-proxy',
      instructions: {
        redirectUri: 'http://localhost:8085/oauth2callback',
        callbackPort: 8085,
        callbackPath: '/oauth2callback',
        manualCallbackDelayMs: 15000,
      },
    });
    apiMock.getOAuthSession.mockResolvedValue({
      provider: 'gemini-cli',
      state: 'gemini-rebind-proxy',
      status: 'pending',
    });

    let root!: WebTestRenderer;
    try {
      await act(async () => {
        root = create(
          <ToastProvider>
            <MemoryRouter>
              <OAuthManagement />
            </MemoryRouter>
          </ToastProvider>,
        );
      });
      await flushMicrotasks();

      await clickButton(root!, '重新授权');
      await clickButton(root!, '重新授权 Gemini CLI');
      await flushMicrotasks();

      expect(apiMock.rebindOAuthConnection).toHaveBeenCalledWith(11, {
        proxyUrl: 'http://127.0.0.1:7890',
        useSystemProxy: false,
      });
    } finally {
      root?.unmount();
    }
  });

  it('opens oauth proxy settings from the dedicated proxy action', async () => {
    apiMock.getOAuthProviders.mockResolvedValue({
      providers: [
        {
          provider: 'gemini-cli',
          label: 'Gemini CLI',
          platform: 'gemini-cli',
          enabled: true,
          loginType: 'oauth',
          requiresProjectId: true,
          supportsDirectAccountRouting: true,
          supportsCloudValidation: true,
          supportsNativeProxy: true,
        },
      ],
    });
    apiMock.getOAuthConnections.mockResolvedValue({
      items: [
        {
          accountId: 11,
          provider: 'gemini-cli',
          email: 'gemini@example.com',
          projectId: 'project-demo',
          modelCount: 5,
          modelsPreview: ['gemini-2.5-pro'],
          status: 'healthy',
          proxyUrl: 'http://127.0.0.1:7890',
        },
      ],
      total: 1,
      limit: 100,
      offset: 0,
    });

    let root!: WebTestRenderer;
    try {
      await act(async () => {
        root = create(
          <ToastProvider>
            <MemoryRouter>
              <OAuthManagement />
            </MemoryRouter>
          </ToastProvider>,
        );
      });
      await flushMicrotasks();

      await clickButton(root!, '代理设置');

      expect(collectText(root!.root)).toContain('已打开 OAuth 代理设置');
      expect(collectText(root!.root)).toContain('代理设置 · gemini@example.com');

      const proxyToggle = findOauthSettingInput(root!, 'use-custom-proxy');
      const proxyInput = findOauthSettingInput(root!, 'proxy-url');

      expect(findOauthSettingInput(root!, 'use-system-proxy').props.checked).toBe(false);

      expect(proxyToggle).toBeTruthy();
      expect(proxyToggle.props.checked).toBe(true);
      expect(proxyInput).toBeTruthy();
      expect(proxyInput.props.disabled).toBe(false);
      expect(proxyInput.props.value).toBe('http://127.0.0.1:7890');
    } finally {
      root?.unmount();
    }
  });

  it('can clear the stored account proxy by turning off both proxy options', async () => {
    apiMock.getOAuthProviders.mockResolvedValue({
      providers: [
        {
          provider: 'gemini-cli',
          label: 'Gemini CLI',
          platform: 'gemini-cli',
          enabled: true,
          loginType: 'oauth',
          requiresProjectId: true,
          supportsDirectAccountRouting: true,
          supportsCloudValidation: true,
          supportsNativeProxy: true,
        },
      ],
    });
    apiMock.getOAuthConnections.mockResolvedValue({
      items: [
        {
          accountId: 11,
          provider: 'gemini-cli',
          email: 'gemini@example.com',
          projectId: 'project-demo',
          modelCount: 5,
          modelsPreview: ['gemini-2.5-pro'],
          status: 'healthy',
          proxyUrl: 'http://127.0.0.1:7890',
        },
      ],
      total: 1,
      limit: 100,
      offset: 0,
    });
    apiMock.rebindOAuthConnection.mockResolvedValue({
      provider: 'gemini-cli',
      state: 'gemini-rebind-clear',
      authorizationUrl: 'https://accounts.google.com/o/oauth2/v2/auth?state=gemini-rebind-clear',
      instructions: {
        redirectUri: 'http://localhost:8085/oauth2callback',
        callbackPort: 8085,
        callbackPath: '/oauth2callback',
        manualCallbackDelayMs: 15000,
      },
    });
    apiMock.getOAuthSession.mockResolvedValue({
      provider: 'gemini-cli',
      state: 'gemini-rebind-clear',
      status: 'pending',
    });

    let root!: WebTestRenderer;
    try {
      await act(async () => {
        root = create(
          <ToastProvider>
            <MemoryRouter>
              <OAuthManagement />
            </MemoryRouter>
          </ToastProvider>,
        );
      });
      await flushMicrotasks();

      await clickButton(root!, '代理设置');
      const customProxyToggle = findOauthSettingInput(root!, 'use-custom-proxy');

      await act(async () => {
        customProxyToggle.props.onChange({ target: { checked: false } });
      });

      await clickButton(root!, '保存代理并重新授权');
      await flushMicrotasks();

      expect(apiMock.rebindOAuthConnection).toHaveBeenCalledWith(11, {
        proxyUrl: null,
        useSystemProxy: false,
      });
    } finally {
      root?.unmount();
    }
  });

  it('starts oauth with the configured system proxy when selected', async () => {
    apiMock.getOAuthProviders.mockResolvedValue({
      providers: [
        {
          provider: 'codex',
          label: 'ChatGPT Codex',
          platform: 'codex',
          enabled: true,
          loginType: 'oauth',
          requiresProjectId: false,
          supportsDirectAccountRouting: true,
          supportsCloudValidation: true,
          supportsNativeProxy: true,
        },
      ],
    });
    apiMock.getOAuthConnections.mockResolvedValue({ items: [], total: 0, limit: 100, offset: 0 });
    apiMock.startOAuthProvider.mockResolvedValue({
      provider: 'codex',
      state: 'oauth-state-system-proxy',
      authorizationUrl: 'https://auth.openai.com/oauth/authorize?state=oauth-state-system-proxy',
      instructions: {
        redirectUri: 'http://localhost:1455/auth/callback',
        callbackPort: 1455,
        callbackPath: '/auth/callback',
        manualCallbackDelayMs: 15000,
      },
    });
    apiMock.getOAuthSession.mockResolvedValue({
      provider: 'codex',
      state: 'oauth-state-system-proxy',
      status: 'pending',
    });

    let root!: WebTestRenderer;
    try {
      await act(async () => {
        root = create(
          <ToastProvider>
            <MemoryRouter>
              <OAuthManagement />
            </MemoryRouter>
          </ToastProvider>,
        );
      });
      await flushMicrotasks();

      await clickButton(root!, '新建 OAuth 连接');
      const systemProxyToggle = findOauthSettingInput(root!, 'use-system-proxy');

      await act(async () => {
        systemProxyToggle.props.onChange({ target: { checked: true } });
      });

      await clickButton(root!, '连接 ChatGPT Codex');
      await flushMicrotasks();

      expect(apiMock.startOAuthProvider).toHaveBeenCalledWith('codex', {
        projectId: undefined,
        proxyUrl: null,
        useSystemProxy: true,
      });
    } finally {
      root?.unmount();
    }
  });

  it('resets temporary oauth proxy settings after starting an authorization flow', async () => {
    apiMock.getOAuthProviders.mockResolvedValue({
      providers: [
        {
          provider: 'codex',
          label: 'ChatGPT Codex',
          platform: 'codex',
          enabled: true,
          loginType: 'oauth',
          requiresProjectId: false,
          supportsDirectAccountRouting: true,
          supportsCloudValidation: true,
          supportsNativeProxy: true,
        },
        {
          provider: 'claude',
          label: 'Claude',
          platform: 'claude',
          enabled: true,
          loginType: 'oauth',
          requiresProjectId: false,
          supportsDirectAccountRouting: true,
          supportsCloudValidation: true,
          supportsNativeProxy: true,
        },
      ],
    });
    apiMock.getOAuthConnections.mockResolvedValue({
      items: [],
      total: 0,
      limit: 100,
      offset: 0,
    });
    apiMock.startOAuthProvider
      .mockResolvedValueOnce({
        provider: 'codex',
        state: 'oauth-state-codex',
        authorizationUrl: 'https://auth.openai.com/oauth/authorize?state=oauth-state-codex',
        instructions: {
          redirectUri: 'http://localhost:1455/auth/callback',
          callbackPort: 1455,
          callbackPath: '/auth/callback',
          manualCallbackDelayMs: 15000,
        },
      })
      .mockResolvedValueOnce({
        provider: 'claude',
        state: 'oauth-state-claude',
        authorizationUrl: 'https://console.anthropic.com/oauth/authorize?state=oauth-state-claude',
        instructions: {
          redirectUri: 'http://localhost:54545/callback',
          callbackPort: 54545,
          callbackPath: '/callback',
          manualCallbackDelayMs: 15000,
        },
      });
    apiMock.getOAuthSession.mockResolvedValue({
      provider: 'codex',
      state: 'oauth-state-codex',
      status: 'pending',
    });

    let root!: WebTestRenderer;
    try {
      await act(async () => {
        root = create(
          <ToastProvider>
            <MemoryRouter>
              <OAuthManagement />
            </MemoryRouter>
          </ToastProvider>,
        );
      });
      await flushMicrotasks();

      await clickButton(root, '新建 OAuth 连接');

      const proxyToggle = findOauthSettingInput(root, 'use-custom-proxy');
      const proxyInput = findOauthSettingInput(root, 'proxy-url');

      await act(async () => {
        proxyToggle.props.onChange({ target: { checked: true } });
      });
      await act(async () => {
        proxyInput.props.onChange({ target: { value: 'http://127.0.0.1:7890' } });
      });
      await clickButton(root, '连接 ChatGPT Codex');
      await flushMicrotasks();

      expect(apiMock.startOAuthProvider).toHaveBeenNthCalledWith(1, 'codex', {
        projectId: undefined,
        proxyUrl: 'http://127.0.0.1:7890',
        useSystemProxy: false,
      });

      const resetProxyToggle = findOauthSettingInput(root, 'use-custom-proxy');
      const resetProxyInput = findOauthSettingInput(root, 'proxy-url');
      const resetSystemProxyToggle = findOauthSettingInput(root, 'use-system-proxy');

      expect(resetProxyToggle.props.checked).toBe(false);
      expect(resetProxyInput.props.value).toBe('');
      expect(resetSystemProxyToggle.props.checked).toBe(false);
    } finally {
      root?.unmount();
    }
  });

  it('shows oauth connection status metadata and allows deleting a connection', async () => {
    apiMock.getOAuthProviders.mockResolvedValue({
      providers: [
        {
          provider: 'codex',
          label: 'Codex',
          platform: 'codex',
          enabled: true,
          loginType: 'oauth',
          requiresProjectId: false,
          supportsDirectAccountRouting: true,
          supportsCloudValidation: true,
          supportsNativeProxy: true,
        },
      ],
    });
    apiMock.getOAuthConnections
      .mockResolvedValueOnce({
        items: [
          {
            accountId: 7,
            provider: 'codex',
            email: 'codex-user@example.com',
            planType: 'team',
            modelCount: 11,
            modelsPreview: ['gpt-5.4', 'gpt-5.3-codex', 'gpt-5.2-codex'],
            status: 'abnormal',
            quota: {
              status: 'error',
              source: 'reverse_engineered',
              lastError: '{"detail":{"code":"deactivated_workspace"}}',
              subscription: {
                planType: 'team',
                activeStart: '2026-03-01T00:00:00.000Z',
                activeUntil: '2026-04-01T00:00:00.000Z',
              },
              lastLimitResetAt: '2026-03-17T13:00:00.000Z',
              windows: {
                fiveHour: {
                  supported: false,
                  message: 'official 5h quota window is not exposed by current codex oauth artifacts',
                },
                sevenDay: {
                  supported: false,
                  message: 'official 7d quota window is not exposed by current codex oauth artifacts',
                },
              },
            },
            routeChannelCount: 1,
            lastModelSyncAt: '2026-03-17T08:00:00.000Z',
            lastModelSyncError: 'Codex 模型获取失败（HTTP 403: forbidden）',
            proxyUrl: 'http://oauth-user:secret@127.0.0.1:7890',
          },
        ],
        total: 1,
        limit: 100,
        offset: 0,
      })
      .mockResolvedValueOnce({ items: [], total: 0, limit: 100, offset: 0 });
    apiMock.deleteOAuthConnection.mockResolvedValue({ success: true });

    let root!: WebTestRenderer;
    try {
      await act(async () => {
        root = create(
          <ToastProvider>
            <MemoryRouter>
              <OAuthManagement />
            </MemoryRouter>
          </ToastProvider>,
        );
      });
      await vi.waitFor(async () => {
        await flushMicrotasks();
        const text = collectText(root!.root);
        expect(text).toContain('异常');
        expect(text).toContain('Codex 模型获取失败');
        expect(text).toContain('HTTP 403: forbidden');
        expect(text).toContain('team');
        expect(text).toContain('11 个模型');
        expect(text).toContain('deactivated_workspace');
        expect(text).not.toContain('当前 Codex OAuth 未暴露官方 5h 窗口');
        expect(text).not.toContain('当前 Codex OAuth 未暴露官方 7d 窗口');
        expect(text).toContain('http://***@127.0.0.1:7890');
        expect(text).not.toContain('oauth-user:secret');
      });

      const deleteButton = root!.root.find((node) => (
        node.type === 'button'
        && typeof node.props.onClick === 'function'
        && collectText(node).includes('删除连接')
      ));

      await act(async () => {
        await deleteButton.props.onClick();
      });
      await vi.waitFor(async () => {
        await flushMicrotasks();
      });

      expect(confirmMock).toHaveBeenCalled();
      expect(apiMock.deleteOAuthConnection).toHaveBeenCalledWith(7);
      expect(apiMock.getOAuthConnections).toHaveBeenCalledTimes(2);
    } finally {
      root?.unmount();
    }
  });

  it('refreshes quota for a connection and reloads the connection list', async () => {
    apiMock.getOAuthProviders.mockResolvedValue({
      providers: [
        {
          provider: 'codex',
          label: 'Codex',
          platform: 'codex',
          enabled: true,
          loginType: 'oauth',
          requiresProjectId: false,
          supportsDirectAccountRouting: true,
          supportsCloudValidation: true,
          supportsNativeProxy: true,
        },
      ],
    });
    apiMock.getOAuthConnections
      .mockResolvedValueOnce({
        items: [
          {
            accountId: 7,
            provider: 'codex',
            email: 'codex-user@example.com',
            planType: 'team',
            modelCount: 11,
            modelsPreview: ['gpt-5.4'],
            status: 'healthy',
            quota: {
              status: 'supported',
              source: 'reverse_engineered',
              windows: {
                fiveHour: {
                  supported: false,
                  message: 'official 5h quota window is not exposed by current codex oauth artifacts',
                },
                sevenDay: {
                  supported: false,
                  message: 'official 7d quota window is not exposed by current codex oauth artifacts',
                },
              },
            },
          },
        ],
        total: 1,
        limit: 100,
        offset: 0,
      })
      .mockResolvedValueOnce({
        items: [
          {
            accountId: 7,
            provider: 'codex',
            email: 'codex-user@example.com',
            planType: 'team',
            modelCount: 11,
            modelsPreview: ['gpt-5.4'],
            status: 'healthy',
            quota: {
              status: 'supported',
              source: 'reverse_engineered',
              lastSyncAt: '2026-03-18T01:00:00.000Z',
              windows: {
                fiveHour: {
                  supported: false,
                  message: 'official 5h quota window is not exposed by current codex oauth artifacts',
                },
                sevenDay: {
                  supported: false,
                  message: 'official 7d quota window is not exposed by current codex oauth artifacts',
                },
              },
            },
          },
        ],
        total: 1,
        limit: 100,
        offset: 0,
      });
    apiMock.refreshOAuthConnectionQuota.mockResolvedValue({
      success: true,
      quota: {
        status: 'supported',
        source: 'reverse_engineered',
        lastSyncAt: '2026-03-18T01:00:00.000Z',
        windows: {
          fiveHour: {
            supported: false,
            message: 'official 5h quota window is not exposed by current codex oauth artifacts',
          },
          sevenDay: {
            supported: false,
            message: 'official 7d quota window is not exposed by current codex oauth artifacts',
          },
        },
      },
    });

    let root!: WebTestRenderer;
    try {
      await act(async () => {
        root = create(
          <ToastProvider>
            <MemoryRouter>
              <OAuthManagement />
            </MemoryRouter>
          </ToastProvider>,
        );
      });
      await vi.waitFor(async () => {
        await flushMicrotasks();
        expect(collectText(root!.root)).toContain('刷新额度');
      });

      const refreshButton = root!.root.find((node) => (
        node.type === 'button'
        && typeof node.props.onClick === 'function'
        && collectText(node).includes('刷新额度')
      ));

      await act(async () => {
        await refreshButton.props.onClick();
      });
      await vi.waitFor(async () => {
        await flushMicrotasks();
      });

      expect(apiMock.refreshOAuthConnectionQuota).toHaveBeenCalledWith(7);
      expect(apiMock.getOAuthConnections).toHaveBeenCalledTimes(2);
      expect(collectText(root!.root)).toContain('额度信息已刷新');
      expect(collectText(root!.root)).not.toContain('当前 Codex OAuth 未暴露官方 5h 窗口');
      expect(collectText(root!.root)).not.toContain('当前 Codex OAuth 未暴露官方 7d 窗口');
    } finally {
      root?.unmount();
    }
  });
});
