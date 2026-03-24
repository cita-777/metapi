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

describe('Models marketplace text', () => {
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
    apiMock.getModelsMarketplace.mockResolvedValue({
      models: [
        {
          name: 'gpt-4o',
          accountCount: 1,
          tokenCount: 1,
          avgLatency: 320,
          successRate: 98,
          description: null,
          tags: [],
          supportedEndpointTypes: [],
          pricingSources: [],
          accounts: [
            {
              id: 1,
              site: 'Demo Site',
              username: 'tester',
              latency: 320,
              balance: 12.5,
              tokens: [{ id: 1, name: 'default', isDefault: true }],
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

  it('renders readable Chinese labels and fallback descriptions for marketplace models', async () => {
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

      const initialText = collectText(root!.root);
      expect(initialText).toContain('品牌');
      expect(initialText).toContain('排序方式');
      expect(initialText).toContain('模型广场');

      const cards = root!.root.findAll((node) => (
        node.type === 'div'
        && typeof node.props.className === 'string'
        && node.props.className.includes('model-card')
        && typeof node.props.onClick === 'function'
      ));
      expect(cards.length).toBeGreaterThan(0);

      await act(async () => {
        cards[0]!.props.onClick();
      });
      await flushMicrotasks();

      const expandedText = collectText(root!.root);
      expect(expandedText).toContain('当前上游仅返回模型 ID，未返回描述字段。');
      expect(expandedText).toContain('基础信息');
      expect(expandedText).toContain('站点');
      expect(expandedText).toContain('余额');
    } finally {
      root?.unmount();
    }
  });

  it('shows newly recognized brands in the marketplace filter panel', async () => {
    apiMock.getModelsMarketplace.mockResolvedValue({
      models: [
        {
          name: 'nvidia/vila',
          accountCount: 1,
          tokenCount: 1,
          avgLatency: 210,
          successRate: 97,
          description: null,
          tags: [],
          supportedEndpointTypes: [],
          pricingSources: [],
          accounts: [
            {
              id: 1,
              site: '公益站 A',
              username: 'tester',
              latency: 210,
              balance: 6.5,
              tokens: [{ id: 1, name: 'default', isDefault: true }],
            },
          ],
        },
        {
          name: 'deepl-zh-en',
          accountCount: 1,
          tokenCount: 1,
          avgLatency: 160,
          successRate: 99,
          description: null,
          tags: [],
          supportedEndpointTypes: [],
          pricingSources: [],
          accounts: [
            {
              id: 2,
              site: '公益站 B',
              username: 'tester',
              latency: 160,
              balance: 8.8,
              tokens: [{ id: 2, name: 'default', isDefault: true }],
            },
          ],
        },
      ],
    });

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

      const text = collectText(root!.root);
      expect(text).toContain('NVIDIA');
      expect(text).toContain('DeepL');
      expect(text).not.toContain('其他未归类的模型');
    } finally {
      root?.unmount();
    }
  });

  it('keeps a visible mobile filter entry on small screens', async () => {
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
    } finally {
      root?.unmount();
    }
  });

  it('keeps the mobile filter entry visible even while the first screen is still loading', async () => {
    globalThis.window = {
      innerWidth: 768,
      addEventListener: () => {},
      removeEventListener: () => {},
    } as unknown as Window & typeof globalThis;
    apiMock.getModelsMarketplace.mockImplementation(() => new Promise(() => {}));

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

      expect(collectText(root!.root)).toContain('筛选');
    } finally {
      root?.unmount();
    }
  });

  it('limits expanded account and pricing detail to the selected site filter', async () => {
    apiMock.getModelsMarketplace.mockResolvedValue({
      models: [
        {
          name: 'gpt-4o',
          accountCount: 2,
          tokenCount: 3,
          avgLatency: 500,
          successRate: 96,
          description: 'demo model',
          tags: ['chat'],
          supportedEndpointTypes: ['openai'],
          pricingSources: [
            {
              siteId: 1,
              siteName: '站点 A',
              accountId: 1,
              username: 'user-a',
              ownerBy: null,
              enableGroups: [],
              groupPricing: {
                default: {
                  quotaType: 0,
                  inputPerMillion: 1,
                  outputPerMillion: 2,
                },
              },
            },
            {
              siteId: 2,
              siteName: '站点 B',
              accountId: 2,
              username: 'user-b',
              ownerBy: null,
              enableGroups: [],
              groupPricing: {
                default: {
                  quotaType: 0,
                  inputPerMillion: 3,
                  outputPerMillion: 4,
                },
              },
            },
          ],
          accounts: [
            {
              id: 1,
              site: '站点 A',
              username: 'user-a',
              latency: 320,
              balance: 12.5,
              tokens: [
                { id: 1, name: 'token-a-1', isDefault: true },
                { id: 2, name: 'token-a-2', isDefault: false },
              ],
            },
            {
              id: 2,
              site: '站点 B',
              username: 'user-b',
              latency: 680,
              balance: 8.4,
              tokens: [
                { id: 3, name: 'token-b-1', isDefault: true },
              ],
            },
          ],
        },
      ],
    });

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

      const siteFilterItem = root!.root.find((node) => (
        node.type === 'div'
        && typeof node.props.className === 'string'
        && node.props.className.includes('filter-item')
        && typeof node.props.onClick === 'function'
        && collectText(node).includes('站点 A')
      ));

      await act(async () => {
        siteFilterItem.props.onClick();
      });
      await flushMicrotasks();

      const cards = root!.root.findAll((node) => (
        node.type === 'div'
        && typeof node.props.className === 'string'
        && node.props.className.includes('model-card')
        && typeof node.props.onClick === 'function'
      ));
      expect(cards.length).toBeGreaterThan(0);

      await act(async () => {
        cards[0]!.props.onClick();
      });
      await flushMicrotasks();

      const expandedSections = root!.root.findAll((node) => (
        node.type === 'div'
        && typeof node.props.className === 'string'
        && node.props.className.includes('model-card-expand')
      ));
      expect(expandedSections.length).toBe(1);

      const expandedText = collectText(expandedSections[0]!);
      expect(expandedText).toContain('站点 A');
      expect(expandedText).toContain('user-a');
      expect(expandedText).toContain('token-a-1');
      expect(expandedText).not.toContain('站点 B');
      expect(expandedText).not.toContain('user-b');
      expect(expandedText).not.toContain('token-b-1');
    } finally {
      root?.unmount();
    }
  });

  it('re-sorts models using site-scoped counts after selecting a site filter', async () => {
    apiMock.getModelsMarketplace.mockResolvedValue({
      models: [
        {
          name: 'gpt-4o',
          accountCount: 4,
          tokenCount: 4,
          avgLatency: 300,
          successRate: 98,
          description: null,
          tags: [],
          supportedEndpointTypes: [],
          pricingSources: [],
          accounts: [
            {
              id: 1,
              site: '站点 A',
              username: 'user-a-1',
              latency: 300,
              balance: 8,
              tokens: [{ id: 1, name: 'token-a-1', isDefault: true }],
            },
            {
              id: 2,
              site: '站点 B',
              username: 'user-b-1',
              latency: 200,
              balance: 8,
              tokens: [{ id: 2, name: 'token-b-1', isDefault: true }],
            },
            {
              id: 3,
              site: '站点 B',
              username: 'user-b-2',
              latency: 250,
              balance: 8,
              tokens: [{ id: 3, name: 'token-b-2', isDefault: true }],
            },
            {
              id: 4,
              site: '站点 B',
              username: 'user-b-3',
              latency: 260,
              balance: 8,
              tokens: [{ id: 4, name: 'token-b-3', isDefault: true }],
            },
          ],
        },
        {
          name: 'claude-3-5-sonnet',
          accountCount: 2,
          tokenCount: 2,
          avgLatency: 420,
          successRate: 95,
          description: null,
          tags: [],
          supportedEndpointTypes: [],
          pricingSources: [],
          accounts: [
            {
              id: 5,
              site: '站点 A',
              username: 'user-a-2',
              latency: 410,
              balance: 9,
              tokens: [{ id: 5, name: 'token-a-2', isDefault: true }],
            },
            {
              id: 6,
              site: '站点 A',
              username: 'user-a-3',
              latency: 430,
              balance: 9,
              tokens: [{ id: 6, name: 'token-a-3', isDefault: true }],
            },
          ],
        },
      ],
    });

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

      const siteFilterItem = root!.root.find((node) => (
        node.type === 'div'
        && typeof node.props.className === 'string'
        && node.props.className.includes('filter-item')
        && typeof node.props.onClick === 'function'
        && collectText(node).includes('站点 A')
      ));

      await act(async () => {
        siteFilterItem.props.onClick();
      });
      await flushMicrotasks();

      const cards = root!.root.findAll((node) => (
        node.type === 'div'
        && typeof node.props.className === 'string'
        && node.props.className.split(' ').includes('model-card')
        && typeof node.props.onClick === 'function'
      ));

      expect(cards.length).toBe(2);
      expect(collectText(cards[0]!)).toContain('claude-3-5-sonnet');
      expect(collectText(cards[1]!)).toContain('gpt-4o');
    } finally {
      root?.unmount();
    }
  });

  it('renders unknown latency instead of falling back to another site latency', async () => {
    apiMock.getModelsMarketplace.mockResolvedValue({
      models: [
        {
          name: 'gpt-4o',
          accountCount: 2,
          tokenCount: 2,
          avgLatency: 680,
          successRate: 93,
          description: null,
          tags: [],
          supportedEndpointTypes: [],
          pricingSources: [],
          accounts: [
            {
              id: 1,
              site: '站点 A',
              username: 'user-a',
              latency: null,
              balance: 12,
              tokens: [{ id: 1, name: 'token-a', isDefault: true }],
            },
            {
              id: 2,
              site: '站点 B',
              username: 'user-b',
              latency: 680,
              balance: 12,
              tokens: [{ id: 2, name: 'token-b', isDefault: true }],
            },
          ],
        },
      ],
    });

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

      const siteFilterItem = root!.root.find((node) => (
        node.type === 'div'
        && typeof node.props.className === 'string'
        && node.props.className.includes('filter-item')
        && typeof node.props.onClick === 'function'
        && collectText(node).includes('站点 A')
      ));

      await act(async () => {
        siteFilterItem.props.onClick();
      });
      await flushMicrotasks();

      const latencyBadge = root!.root.find((node) => (
        node.type === 'span'
        && node.props['data-tooltip'] === '平均延迟'
      ));

      expect(String(latencyBadge.props.className || '')).toContain('badge-muted');
      expect(collectText(latencyBadge)).toContain('延迟');
      expect(collectText(latencyBadge)).toContain('—');
      expect(collectText(root!.root)).not.toContain('680ms');
    } finally {
      root?.unmount();
    }
  });
});
