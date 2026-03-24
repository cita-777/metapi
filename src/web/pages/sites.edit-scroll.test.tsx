import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, create, type ReactTestInstance } from 'react-test-renderer';
import { MemoryRouter } from 'react-router-dom';
import { ToastProvider } from '../components/Toast.js';
import Sites from './Sites.js';

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    getSites: vi.fn(),
    getSiteDisabledModels: vi.fn().mockResolvedValue({ models: [] }),
    getSiteAvailableModels: vi.fn().mockResolvedValue({ models: [] }),
  },
}));

vi.mock('../api.js', () => ({
  api: apiMock,
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

describe('Sites edit behavior', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('scrolls to page top when entering edit mode', async () => {
    apiMock.getSites.mockResolvedValue([
      {
        id: 1,
        name: 'Demo Site',
        url: 'https://example.com',
        platform: 'new-api',
        status: 'active',
      },
    ]);

    const scrollToMock = vi.fn();
    Object.defineProperty(globalThis, 'scrollTo', {
      configurable: true,
      writable: true,
      value: scrollToMock,
    });

    let root!: WebTestRenderer;
    try {
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

      const editButton = root.root.find((node) => (
        node.type === 'button'
        && typeof node.props.onClick === 'function'
        && collectText(node).trim() === '编辑'
      ));

      await act(async () => {
        editButton.props.onClick();
      });
      await flushMicrotasks();

      expect(scrollToMock).toHaveBeenCalledWith({ top: 0, behavior: 'smooth' });
    } finally {
      root?.unmount();
    }
  });

  it('restores header add button label after closing add modal', async () => {
    apiMock.getSites.mockResolvedValue([]);

    let root!: WebTestRenderer;
    try {
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

      const openAddButton = root.root.find((node) => (
        node.type === 'button'
        && typeof node.props.onClick === 'function'
        && typeof node.props.className === 'string'
        && node.props.className.includes('btn btn-primary')
        && collectText(node).includes('添加站点')
      ));

      await act(async () => {
        openAddButton.props.onClick();
      });
      await flushMicrotasks();

      const closeModalButton = root.root.find((node) => (
        node.type === 'button'
        && typeof node.props.onClick === 'function'
        && typeof node.props.className === 'string'
        && node.props.className.includes('btn btn-ghost')
        && collectText(node).trim() === '取消'
      ));

      await act(async () => {
        closeModalButton.props.onClick();
      });
      await flushMicrotasks();

      const headerAddButton = root.root.find((node) => (
        node.type === 'button'
        && typeof node.props.className === 'string'
        && node.props.className.includes('btn btn-primary')
        && collectText(node).includes('添加站点')
      ));

      expect(collectText(headerAddButton)).toContain('添加站点');
    } finally {
      root?.unmount();
    }
  });
});
