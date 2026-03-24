import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, create, type ReactTestInstance } from 'react-test-renderer';
import { MemoryRouter } from 'react-router-dom';
import { ToastProvider } from '../components/Toast.js';
import Models from './Models.js';

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    getModelsMarketplace: vi.fn(),
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
  });
}

describe('Models mobile layout', () => {
  const originalDocument = globalThis.document;
  const originalMutationObserver = globalThis.MutationObserver;
  const originalWindow = globalThis.window;
  const originalMatchMedia = globalThis.matchMedia;

  beforeEach(() => {
    vi.clearAllMocks();
    globalThis.document = {
      documentElement: {
        getAttribute: () => 'light',
      },
    } as unknown as Document;
    globalThis.MutationObserver = class {
      observe() {}
      disconnect() {}
    } as unknown as typeof MutationObserver;
    const nextWindow = (originalWindow ? { ...originalWindow } : {}) as Window & typeof globalThis;
    nextWindow.innerWidth = 768;
    nextWindow.addEventListener = nextWindow.addEventListener || (() => {});
    nextWindow.removeEventListener = nextWindow.removeEventListener || (() => {});
    nextWindow.matchMedia = (() => ({
      matches: true,
      media: '(max-width: 768px)',
      onchange: null,
      addEventListener: () => {},
      removeEventListener: () => {},
      addListener: () => {},
      removeListener: () => {},
      dispatchEvent: () => false,
    })) as typeof window.matchMedia;
    globalThis.window = nextWindow;
    globalThis.matchMedia = nextWindow.matchMedia;
    apiMock.getModelsMarketplace.mockResolvedValue({
      models: [
        {
          name: 'gpt-4o',
          accountCount: 2,
          tokenCount: 3,
          avgLatency: 420,
          successRate: 96,
          description: '旗舰聊天模型',
          tags: ['chat'],
          supportedEndpointTypes: ['openai'],
          pricingSources: [],
          accounts: [
            {
              id: 1,
              site: '站点 A',
              username: 'alice',
              latency: 320,
              balance: 12.5,
              tokens: [{ id: 1, name: 'default', isDefault: true }],
            },
            {
              id: 2,
              site: '站点 B',
              username: 'bob',
              latency: 540,
              balance: 8.4,
              tokens: [{ id: 2, name: 'backup', isDefault: false }],
            },
          ],
        },
      ],
    });
  });

  afterEach(() => {
    vi.clearAllMocks();
    globalThis.document = originalDocument;
    globalThis.MutationObserver = originalMutationObserver;
    globalThis.window = originalWindow;
    globalThis.matchMedia = originalMatchMedia;
  });

  it('keeps a mobile filter entry and hides the table-view toggle on small screens', async () => {
    let root!: WebTestRenderer;

    try {
      await act(async () => {
        root = create(
          <MemoryRouter initialEntries={['/models']}>
            <ToastProvider>
              <Models />
            </ToastProvider>
          </MemoryRouter>,
        );
      });
      await flushMicrotasks();

      expect(collectText(root!.root)).toContain('筛选');
      expect(root!.root.findAll((node) => (
        node.type === 'button'
        && node.props['aria-label'] === '表格视图'
      ))).toHaveLength(0);
    } finally {
      root?.unmount();
    }
  });

  it('renders stacked account detail cards instead of tables when a mobile card expands', async () => {
    let root!: WebTestRenderer;

    try {
      await act(async () => {
        root = create(
          <MemoryRouter initialEntries={['/models']}>
            <ToastProvider>
              <Models />
            </ToastProvider>
          </MemoryRouter>,
        );
      });
      await flushMicrotasks();

      const modelCard = root!.root.find((node) => (
        node.type === 'div'
        && typeof node.props.className === 'string'
        && node.props.className.includes('model-card')
        && typeof node.props.onClick === 'function'
      ));

      await act(async () => {
        modelCard.props.onClick();
      });
      await flushMicrotasks();

      expect(collectText(root!.root)).toContain('账号明细');
      expect(collectText(root!.root)).toContain('站点 A');
      expect(collectText(root!.root)).toContain('alice');
      expect(root!.root.findAll((node) => node.type === 'table')).toHaveLength(0);
    } finally {
      root?.unmount();
    }
  });
});
