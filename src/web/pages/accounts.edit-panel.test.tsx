import type { ReactNode } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, create, type ReactTestInstance } from 'react-test-renderer';
import { MemoryRouter } from 'react-router-dom';
import { ToastProvider } from '../components/Toast.js';
import Accounts from './Accounts.js';

const { apiMock, toastMock } = vi.hoisted(() => ({
  apiMock: {
    getAccounts: vi.fn(),
    getSites: vi.fn(),
    updateAccount: vi.fn(),
    updateSiteDisabledModels: vi.fn(),
    rebuildRoutes: vi.fn(),
    refreshAccountHealth: vi.fn(),
    checkModels: vi.fn(),
    getAccountModels: vi.fn(),
  },
  toastMock: {
    success: vi.fn(),
    error: vi.fn(),
    info: vi.fn(),
    toast: vi.fn(),
  },
}));

vi.mock('../api.js', () => ({
  api: apiMock,
}));

vi.mock('../components/Toast.js', () => ({
  ToastProvider: ({ children }: { children: ReactNode }) => children,
  useToast: () => toastMock,
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

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

describe('Accounts edit panel', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    apiMock.getSites.mockResolvedValue([
      { id: 1, name: 'Site A', platform: 'new-api', status: 'active' },
    ]);
    apiMock.getAccounts.mockResolvedValue([
      {
        id: 1,
        siteId: 1,
        username: 'alpha',
        accessToken: 'session-alpha',
        status: 'active',
        site: { id: 1, name: 'Site A', status: 'active', platform: 'new-api' },
      },
    ]);
    apiMock.updateAccount.mockResolvedValue({ success: true });
    apiMock.updateSiteDisabledModels.mockResolvedValue({ success: true });
    apiMock.rebuildRoutes.mockResolvedValue({ success: true });
    apiMock.refreshAccountHealth.mockResolvedValue({ success: true });
    apiMock.getAccountModels.mockResolvedValue({
      siteId: 1,
      siteName: 'Site A',
      models: [
        { name: 'gpt-4', latencyMs: 120, disabled: false },
        { name: 'gpt-3.5', latencyMs: 80, disabled: false },
      ],
      totalCount: 2,
      disabledCount: 0,
    });
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('opens edit panel from account row action', async () => {
    let root!: WebTestRenderer;
    try {
      await act(async () => {
        root = create(
          <MemoryRouter initialEntries={['/accounts']}>
            <ToastProvider>
              <Accounts />
            </ToastProvider>
          </MemoryRouter>,
        );
      });
      await flushMicrotasks();

      const editButton = root.root.find((node) => (
        node.type === 'button'
        && typeof node.props.onClick === 'function'
        && collectText(node).trim() === '编辑'
      ));

      await act(async () => {
        editButton.props.onClick();
      });
      await flushMicrotasks();

      const usernameInput = root.root.find((node) => (
        node.type === 'input'
        && node.props.placeholder === '账号名称'
      ));
      expect(usernameInput.props.value).toBe('alpha');
    } finally {
      root?.unmount();
    }
  });

  it('opens model modal when clicking model button', async () => {
    apiMock.getAccountModels.mockResolvedValue({
      siteId: 1,
      siteName: 'Site A',
      models: [
        { name: 'gpt-4', latencyMs: 120, disabled: false },
        { name: 'gpt-3.5', latencyMs: 80, disabled: false },
      ],
      totalCount: 2,
      disabledCount: 0,
    });

    let root!: WebTestRenderer;
    try {
      await act(async () => {
        root = create(
          <MemoryRouter initialEntries={['/accounts']}>
            <ToastProvider>
              <Accounts />
            </ToastProvider>
          </MemoryRouter>,
        );
      });
      await flushMicrotasks();

      const modelButtons = root.root.findAll((node) => (
        node.type === 'button'
        && typeof node.props.onClick === 'function'
        && typeof node.props.className === 'string'
        && node.props.className.includes('btn-link-info')
        && collectText(node).trim() === '模型'
      ));
      expect(modelButtons.length).toBeGreaterThan(0);

      await act(async () => {
        await modelButtons[0]!.props.onClick();
      });
      await flushMicrotasks();

      // Should call getAccountModels to open the model management modal
      expect(apiMock.getAccountModels).toHaveBeenCalledWith(1);
    } finally {
      root?.unmount();
    }
  });

  it('ignores stale model modal loads after switching accounts', async () => {
    const firstLoad = deferred<any>();
    const secondLoad = deferred<any>();
    apiMock.getAccounts.mockResolvedValue([
      {
        id: 1,
        siteId: 1,
        username: 'alpha',
        accessToken: 'session-alpha',
        status: 'active',
        site: { id: 1, name: 'Site A', status: 'active', platform: 'new-api' },
      },
      {
        id: 2,
        siteId: 2,
        username: 'beta',
        accessToken: 'session-beta',
        status: 'active',
        site: { id: 2, name: 'Site B', status: 'active', platform: 'new-api' },
      },
    ]);
    apiMock.getSites.mockResolvedValue([
      { id: 1, name: 'Site A', platform: 'new-api', status: 'active' },
      { id: 2, name: 'Site B', platform: 'new-api', status: 'active' },
    ]);
    apiMock.getAccountModels.mockImplementation((accountId: number) => {
      if (accountId === 1) return firstLoad.promise;
      if (accountId === 2) return secondLoad.promise;
      return Promise.resolve({ siteId: accountId, siteName: 'Unknown', models: [] });
    });

    let root!: WebTestRenderer;
    try {
      await act(async () => {
        root = create(
          <MemoryRouter initialEntries={['/accounts']}>
            <ToastProvider>
              <Accounts />
            </ToastProvider>
          </MemoryRouter>,
        );
      });
      await flushMicrotasks();

      const modelButtons = root.root.findAll((node) => (
        node.type === 'button'
        && typeof node.props.onClick === 'function'
        && typeof node.props.className === 'string'
        && node.props.className.includes('btn-link-info')
        && collectText(node).trim() === '模型'
      ));

      await act(async () => {
        void modelButtons[0]!.props.onClick();
      });
      await flushMicrotasks();

      await act(async () => {
        void modelButtons[1]!.props.onClick();
      });
      await flushMicrotasks();

      secondLoad.resolve({
        siteId: 2,
        siteName: 'Site B',
        models: [{ name: 'model-b', latencyMs: 66, disabled: false }],
      });
      await flushMicrotasks();

      firstLoad.resolve({
        siteId: 1,
        siteName: 'Site A',
        models: [{ name: 'model-a', latencyMs: 33, disabled: false }],
      });
      await flushMicrotasks();

      const rendered = JSON.stringify(root.toJSON());
      expect(rendered).toContain('模型管理 · Site B');
      expect(rendered).toContain('model-b');
      expect(rendered).not.toContain('model-a');
    } finally {
      root?.unmount();
    }
  });

  it('reports route rebuild failure without claiming success', async () => {
    apiMock.getAccountModels.mockResolvedValue({
      siteId: 1,
      siteName: 'Site A',
      models: [{ name: 'gpt-4', latencyMs: 120, disabled: false }],
      totalCount: 1,
      disabledCount: 0,
    });
    apiMock.rebuildRoutes.mockRejectedValue(new Error('rebuild failed'));

    let root!: WebTestRenderer;
    try {
      await act(async () => {
        root = create(
          <MemoryRouter initialEntries={['/accounts']}>
            <ToastProvider>
              <Accounts />
            </ToastProvider>
          </MemoryRouter>,
        );
      });
      await flushMicrotasks();

      const modelButton = root.root.find((node) => (
        node.type === 'button'
        && typeof node.props.onClick === 'function'
        && typeof node.props.className === 'string'
        && node.props.className.includes('btn-link-info')
        && collectText(node).trim() === '模型'
      ));

      await act(async () => {
        await modelButton.props.onClick();
      });
      await flushMicrotasks();

      const saveButtons = root.root.findAll((node) => (
        node.type === 'button'
        && typeof node.props.onClick === 'function'
        && collectText(node).trim() === '保存'
      ));

      await act(async () => {
        await saveButtons[saveButtons.length - 1]!.props.onClick();
      });
      await flushMicrotasks();

      expect(apiMock.updateSiteDisabledModels).toHaveBeenCalledWith(1, []);
      expect(apiMock.rebuildRoutes).toHaveBeenCalledWith(false, false);
      expect(toastMock.error).toHaveBeenCalledWith('模型禁用设置已保存，但路由重建失败，请手动刷新路由');
      expect(toastMock.success).not.toHaveBeenCalledWith('模型禁用设置已保存，路由已重建');
    } finally {
      root?.unmount();
    }
  });
});


