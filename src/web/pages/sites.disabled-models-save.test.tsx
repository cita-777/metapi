import type { ReactNode } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, create, type ReactTestInstance } from 'react-test-renderer';
import { MemoryRouter } from 'react-router-dom';
import { ToastProvider } from '../components/Toast.js';
import Sites from './Sites.js';

const { apiMock, toastMock } = vi.hoisted(() => ({
  apiMock: {
    getSites: vi.fn(),
    getSiteDisabledModels: vi.fn(),
    getSiteAvailableModels: vi.fn(),
    updateSiteDisabledModels: vi.fn(),
    rebuildRoutes: vi.fn(),
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
  const children = node.children || [];
  return children.map((child) => {
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

describe('Sites disabled models save', () => {
  let consoleWarnSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    vi.clearAllMocks();
    consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    apiMock.getSites.mockResolvedValue([
      {
        id: 1,
        name: 'Demo Site',
        url: 'https://example.com',
        platform: 'new-api',
        status: 'active',
      },
    ]);
    apiMock.getSiteDisabledModels.mockResolvedValue({ models: [] });
    apiMock.getSiteAvailableModels.mockResolvedValue({ models: [] });
    apiMock.updateSiteDisabledModels.mockResolvedValue({ success: true });
  });

  afterEach(() => {
    consoleWarnSpy.mockRestore();
    vi.clearAllMocks();
  });

  async function renderSitesEditor(): Promise<WebTestRenderer> {
    let root!: WebTestRenderer;
    await act(async () => {
      root = create(
        <MemoryRouter initialEntries={['/sites']}>
          <ToastProvider>
            <Sites />
          </ToastProvider>
        </MemoryRouter>,
      );
    });
    await flushMicrotasks();

    const editButton = root.root.find((node: ReactTestInstance) => (
      node.type === 'button'
      && typeof node.props.onClick === 'function'
      && collectText(node).trim() === '编辑'
    ));

    await act(async () => {
      editButton.props.onClick();
    });
    await flushMicrotasks();

    return root;
  }

  it('reports route rebuild failure after saving disabled models from sites editor', async () => {
    apiMock.rebuildRoutes.mockRejectedValue(new Error('rebuild failed'));

    let root!: WebTestRenderer;
    try {
      root = await renderSitesEditor();

      const saveButton = root.root.find((node) => (
        node.type === 'button'
        && typeof node.props.onClick === 'function'
        && collectText(node).includes('保存禁用列表')
      ));

      await act(async () => {
        await saveButton.props.onClick();
      });
      await flushMicrotasks();

      expect(apiMock.updateSiteDisabledModels).toHaveBeenCalledWith(1, []);
      expect(apiMock.rebuildRoutes).toHaveBeenCalledWith(false, false);
      expect(toastMock.error).toHaveBeenCalledWith('禁用模型列表已保存，但路由重建失败，请手动刷新路由');
      expect(toastMock.success).not.toHaveBeenCalledWith('禁用模型列表已保存，路由已重建');
    } finally {
      root?.unmount();
    }
  });

  it('preserves existing disabled models when available-model loading fails', async () => {
    apiMock.getSiteDisabledModels.mockResolvedValue({ models: ['gpt-4o'] });
    apiMock.getSiteAvailableModels.mockRejectedValue(new Error('available models failed'));
    apiMock.rebuildRoutes.mockResolvedValue({ success: true });

    let root!: WebTestRenderer;
    try {
      root = await renderSitesEditor();

      const saveButton = root.root.find((node: ReactTestInstance) => (
        node.type === 'button'
        && typeof node.props.onClick === 'function'
        && collectText(node).includes('保存禁用列表')
      ));

      await act(async () => {
        await saveButton.props.onClick();
      });
      await flushMicrotasks();

      expect(apiMock.updateSiteDisabledModels).toHaveBeenCalledWith(1, ['gpt-4o']);
    } finally {
      root?.unmount();
    }
  });

  it('allows adding a disabled model manually when no available models are discovered', async () => {
    apiMock.rebuildRoutes.mockResolvedValue({ success: true });

    let root!: WebTestRenderer;
    try {
      root = await renderSitesEditor();

      const manualInput = root.root.find((node: ReactTestInstance) => (
        node.type === 'input'
        && node.props.placeholder === '输入模型名称，如 gpt-4o'
      ));

      await act(async () => {
        manualInput.props.onChange({ target: { value: 'gpt-4o' } });
      });

      const addButton = root.root.find((node: ReactTestInstance) => (
        node.type === 'button'
        && typeof node.props.onClick === 'function'
        && collectText(node).trim() === '添加模型'
      ));

      await act(async () => {
        addButton.props.onClick();
      });
      await flushMicrotasks();

      const saveButton = root.root.find((node: ReactTestInstance) => (
        node.type === 'button'
        && typeof node.props.onClick === 'function'
        && collectText(node).includes('保存禁用列表')
      ));

      await act(async () => {
        await saveButton.props.onClick();
      });
      await flushMicrotasks();

      expect(apiMock.updateSiteDisabledModels).toHaveBeenCalledWith(1, ['gpt-4o']);
    } finally {
      root?.unmount();
    }
  });
});
