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
    rebindOAuthConnection: vi.fn(),
    deleteOAuthConnection: vi.fn(),
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

    let root: ReturnType<typeof create> | null = null;
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

    let root: ReturnType<typeof create> | null = null;
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

      const startButton = root!.root.find((node) => (
        node.type === 'button'
        && typeof node.props.onClick === 'function'
        && collectText(node).includes('连接 Codex')
      ));

      await act(async () => {
        await startButton.props.onClick();
      });
      await vi.waitFor(async () => {
        await flushMicrotasks();
      });

      expect(apiMock.startOAuthProvider).toHaveBeenCalledWith('codex', { projectId: undefined });
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

    let root: ReturnType<typeof create> | null = null;
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

      const startButton = root!.root.find((node) => (
        node.type === 'button'
        && typeof node.props.onClick === 'function'
        && collectText(node).includes('连接 Claude')
      ));

      await act(async () => {
        await startButton.props.onClick();
      });
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

    let root: ReturnType<typeof create> | null = null;
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
        expect(text).toContain('下游密钥');
      });

      const startButton = root!.root.find((node) => (
        node.type === 'button'
        && collectText(node).includes('当前不可用')
      ));
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

    let root: ReturnType<typeof create> | null = null;
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

    let root: ReturnType<typeof create> | null = null;
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

      const startButton = root!.root.find((node) => (
        node.type === 'button'
        && typeof node.props.onClick === 'function'
        && collectText(node).includes('连接 Gemini CLI')
      ));

      await act(async () => {
        await startButton.props.onClick();
      });
      await vi.waitFor(async () => {
        await flushMicrotasks();
      });

      expect(promptMock).toHaveBeenCalled();
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

    let root: ReturnType<typeof create> | null = null;
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

      const rebindButton = root!.root.find((node) => (
        node.type === 'button'
        && typeof node.props.onClick === 'function'
        && collectText(node).includes('重新授权')
      ));

      await act(async () => {
        await rebindButton.props.onClick();
      });
      await vi.waitFor(async () => {
        await flushMicrotasks();
      });

      expect(promptMock).not.toHaveBeenCalled();
      expect(apiMock.rebindOAuthConnection).toHaveBeenCalledWith(11);
      expect(openMock).toHaveBeenCalledWith(
        'https://accounts.google.com/o/oauth2/v2/auth?state=gemini-rebind-123',
        'oauth-gemini-cli',
        expect.stringContaining('width=540'),
      );
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
              status: 'supported',
              source: 'reverse_engineered',
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
          },
        ],
        total: 1,
        limit: 100,
        offset: 0,
      })
      .mockResolvedValueOnce({ items: [], total: 0, limit: 100, offset: 0 });
    apiMock.deleteOAuthConnection.mockResolvedValue({ success: true });

    let root: ReturnType<typeof create> | null = null;
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
        expect(text).toContain('1 条路由');
        expect(text).toContain('Codex 模型获取失败');
        expect(text).toContain('额度状态');
        expect(text).toContain('team');
        expect(text).toContain('2026-03-01T00:00:00.000Z');
        expect(text).toContain('2026-04-01T00:00:00.000Z');
        expect(text).toContain('2026-03-17T13:00:00.000Z');
        expect(text).toContain('官方未提供');
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

    let root: ReturnType<typeof create> | null = null;
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
      expect(collectText(root!.root)).toContain('2026-03-18T01:00:00.000Z');
    } finally {
      root?.unmount();
    }
  });
});
