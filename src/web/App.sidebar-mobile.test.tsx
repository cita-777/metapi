import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { ReactNode } from 'react';
import { act, create, type ReactTestInstance } from 'react-test-renderer';
import { MemoryRouter } from 'react-router-dom';
import App from './App.js';

const { apiMock, authSessionMock } = vi.hoisted(() => ({
  apiMock: {
    getEvents: vi.fn(),
  },
  authSessionMock: {
    hasValidAuthSession: vi.fn(),
    persistAuthSession: vi.fn(),
    clearAuthSession: vi.fn(),
  },
}));

vi.mock('react-dom', async () => {
  const actual = await vi.importActual<typeof import('react-dom')>('react-dom');
  return {
    ...actual,
    createPortal: (node: unknown) => node,
  };
});

vi.mock('./api.js', () => ({
  api: apiMock,
}));

vi.mock('./authSession.js', () => ({
  hasValidAuthSession: authSessionMock.hasValidAuthSession,
  persistAuthSession: authSessionMock.persistAuthSession,
  clearAuthSession: authSessionMock.clearAuthSession,
}));

vi.mock('./components/SearchModal.js', () => ({
  default: () => null,
}));

vi.mock('./components/NotificationPanel.js', () => ({
  default: () => null,
}));

vi.mock('./components/TooltipLayer.js', () => ({
  default: () => null,
}));

vi.mock('./components/useAnimatedVisibility.js', () => ({
  useAnimatedVisibility: (open: boolean) => ({
    shouldRender: open,
    isVisible: open,
  }),
}));

vi.mock('./i18n.js', () => ({
  I18nProvider: ({ children }: { children: ReactNode }) => children,
  useI18n: () => ({
    language: 'zh',
    toggleLanguage: vi.fn(),
    t: (text: string) => text,
  }),
}));

vi.mock('./pages/Dashboard.js', () => ({
  default: () => <div>Dashboard</div>,
}));

function createLocalStorage() {
  const store = new Map<string, string>([
    ['metapi.theme.mode', 'light'],
    ['metapi.firstUseDocReminder', '1'],
    ['metapi.userProfile', JSON.stringify({
      name: '管理员',
      avatarSeed: 'seed-1',
      avatarStyle: 'identicon',
    })],
  ]);

  return {
    getItem: (key: string) => store.get(key) ?? null,
    setItem: (key: string, value: string) => {
      store.set(key, String(value));
    },
    removeItem: (key: string) => {
      store.delete(key);
    },
  };
}

function setupRuntime(width: number) {
  const matchMedia = (query: string) => ({
    matches: query.includes('prefers-color-scheme')
      ? false
      : width <= 768,
    media: query,
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    addListener: vi.fn(),
    removeListener: vi.fn(),
    dispatchEvent: vi.fn(),
    onchange: null,
  });

  vi.stubGlobal('localStorage', createLocalStorage());
  vi.stubGlobal('window', {
    innerWidth: width,
    matchMedia,
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
  });
  vi.stubGlobal('document', {
    body: { style: {} },
    documentElement: {
      setAttribute: vi.fn(),
      getAttribute: vi.fn(),
    },
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
  });
}

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

describe('App mobile sidebar', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers();
    apiMock.getEvents.mockResolvedValue([]);
    authSessionMock.hasValidAuthSession.mockReturnValue(true);
  });

  afterEach(() => {
    vi.runOnlyPendingTimers();
    vi.useRealTimers();
    vi.unstubAllGlobals();
    vi.clearAllMocks();
  });

  it('opens the mobile drawer from the hamburger trigger and exposes the close affordance', async () => {
    setupRuntime(768);
    let root!: WebTestRenderer;

    try {
      await act(async () => {
        root = create(
          <MemoryRouter initialEntries={['/']}>
            <App />
          </MemoryRouter>,
        );
      });
      await flushMicrotasks();

      const openButton = root.root.find((node) => (
        node.type === 'button'
        && node.props['aria-label'] === '打开导航'
      ));

      await act(async () => {
        openButton.props.onClick();
      });
      await flushMicrotasks();

      expect(collectText(root.root)).toContain('导航菜单');

      const closeButton = root.root.find((node) => (
        node.type === 'button'
        && node.props['aria-label'] === '关闭导航'
      ));

      await act(async () => {
        closeButton.props.onClick();
      });
      await act(async () => {
        vi.advanceTimersByTime(300);
      });
      await flushMicrotasks();

      expect(collectText(root.root)).not.toContain('导航菜单');
    } finally {
      if (root) {
        await act(async () => {
          root.unmount();
        });
      }
    }
  });
});
