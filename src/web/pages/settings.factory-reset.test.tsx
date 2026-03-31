import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, create, type ReactTestInstance } from 'react-test-renderer';
import { MemoryRouter } from 'react-router-dom';
import { ToastProvider } from '../components/Toast.js';
import Settings from './Settings.js';

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    getAuthInfo: vi.fn(),
    getRuntimeSettings: vi.fn(),
    getDownstreamApiKeys: vi.fn(),
    getRoutesLite: vi.fn(),
    getRuntimeDatabaseConfig: vi.fn(),
    getBrandList: vi.fn(),
    factoryReset: vi.fn(),
    getModelTokenCandidates: vi.fn(),
  },
}));

vi.mock('../api.js', () => ({
  api: apiMock,
}));

vi.mock('../components/BrandIcon.js', () => ({
  BrandGlyph: () => null,
  InlineBrandIcon: () => null,
  getBrand: () => null,
  normalizeBrandIconKey: (icon: string) => icon,
}));

function collectText(node: ReactTestInstance): string {
  return (node.children || []).map((child) => {
    if (typeof child === 'string') return child;
    return collectText(child);
  }).join('');
}

function createStorage(initial: Record<string, string> = {}) {
  const store = new Map(Object.entries(initial));
  return {
    getItem: (key: string) => store.has(key) ? store.get(key)! : null,
    setItem: (key: string, value: string) => {
      store.set(key, value);
    },
    removeItem: (key: string) => {
      store.delete(key);
    },
    dump: () => Object.fromEntries(store.entries()),
  };
}

async function flushMicrotasks() {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
  });
}

describe('Settings factory reset', () => {
  const reload = vi.fn();
  let storage: ReturnType<typeof createStorage>;

  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers();

    apiMock.getAuthInfo.mockResolvedValue({ masked: 'sk-****' });
    apiMock.getRuntimeSettings.mockResolvedValue({
      checkinCron: '0 8 * * *',
      balanceRefreshCron: '0 * * * *',
      logCleanupCron: '0 6 * * *',
      logCleanupUsageLogsEnabled: false,
      logCleanupProgramLogsEnabled: false,
      logCleanupRetentionDays: 30,
      routingFallbackUnitCost: 1,
      routingWeights: {},
      adminIpAllowlist: [],
      systemProxyUrl: '',
    });
    apiMock.getDownstreamApiKeys.mockResolvedValue({ items: [] });
    apiMock.getRoutesLite.mockResolvedValue([]);
    apiMock.getBrandList.mockResolvedValue({ brands: [] });
    apiMock.getRuntimeDatabaseConfig.mockResolvedValue({
      active: { dialect: 'sqlite', connection: '(default sqlite path)', ssl: false },
      saved: null,
      restartRequired: false,
    });
    apiMock.factoryReset.mockResolvedValue({ success: true });
    apiMock.getModelTokenCandidates.mockResolvedValue({ models: {} });

    storage = createStorage({
      auth_token: 'before-reset-token',
      auth_token_expires_at: String(Date.now() + 60_000),
      theme_mode: 'dark',
      theme: 'dark',
      user_profile: JSON.stringify({ name: '管理员', avatarSeed: 'seed', avatarStyle: 'bottts' }),
      metapi_first_use_docs_reminder_seen_v1: '1',
    });

    Object.defineProperty(globalThis, 'localStorage', {
      value: storage,
      configurable: true,
      writable: true,
    });
    Object.defineProperty(globalThis, 'window', {
      value: {
        location: { reload },
      },
      configurable: true,
      writable: true,
    });
  });

  afterEach(() => {
    vi.runOnlyPendingTimers();
    vi.useRealTimers();
    vi.clearAllMocks();
  });

  it('shows a 3 second danger confirmation and clears local state after reset', async () => {
    let root!: WebTestRenderer;
    try {
      await act(async () => {
        root = create(
          <MemoryRouter>
            <ToastProvider>
              <Settings />
            </ToastProvider>
          </MemoryRouter>,
        );
      });
      await flushMicrotasks();

      const triggerButton = root.root.find((node) => (
        node.type === 'button'
        && typeof node.props.onClick === 'function'
        && collectText(node).trim() === '重新初始化系统'
      ));

      await act(async () => {
        triggerButton.props.onClick();
      });
      await flushMicrotasks();

      expect(JSON.stringify(root.toJSON())).toContain('确认重新初始化系统');
      expect(JSON.stringify(root.toJSON())).toContain('change-me-admin-token');

      const lockedConfirmButton = root.root.find((node) => (
        node.type === 'button'
        && collectText(node).includes('确认重新初始化系统')
        && node.props.className === 'btn btn-danger'
      ));
      expect(lockedConfirmButton.props.disabled).toBe(true);
      expect(collectText(lockedConfirmButton)).toContain('3s');

      await act(async () => {
        vi.advanceTimersByTime(3000);
      });
      await flushMicrotasks();

      const confirmButton = root.root.find((node) => (
        node.type === 'button'
        && collectText(node).trim() === '确认重新初始化系统'
        && node.props.className === 'btn btn-danger'
      ));
      expect(confirmButton.props.disabled).toBe(false);

      await act(async () => {
        confirmButton.props.onClick();
      });
      await flushMicrotasks();

      expect(apiMock.factoryReset).toHaveBeenCalledTimes(1);
      expect(storage.dump()).toEqual({});
      expect(reload).toHaveBeenCalledTimes(1);
    } finally {
      root?.unmount();
    }
  });
});
