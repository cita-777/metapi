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
    updateRuntimeSettings: vi.fn(),
    testSystemProxy: vi.fn(),
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

async function flushMicrotasks() {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
  });
}

describe('Settings system proxy', () => {
  beforeEach(() => {
    vi.clearAllMocks();
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
    apiMock.updateRuntimeSettings.mockResolvedValue({
      success: true,
      systemProxyUrl: 'http://127.0.0.1:7890',
    });
    apiMock.testSystemProxy.mockResolvedValue({
      success: true,
      proxyUrl: 'http://127.0.0.1:7890',
      probeUrl: 'https://www.gstatic.com/generate_204',
      finalUrl: 'https://www.gstatic.com/generate_204',
      reachable: true,
      ok: true,
      statusCode: 204,
      latencyMs: 321,
    });
    apiMock.getModelTokenCandidates.mockResolvedValue({ models: {} });
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('saves system proxy url from settings', async () => {
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

      const proxyInput = root.root.find((node) => (
        node.type === 'input'
        && node.props.placeholder === '系统代理 URL（可选，如 http://127.0.0.1:7890 或 socks5://127.0.0.1:1080）'
      ));
      await act(async () => {
        proxyInput.props.onChange({ target: { value: 'http://127.0.0.1:7890' } });
      });

      const saveButton = root.root.find((node) => (
        node.type === 'button'
        && typeof node.props.onClick === 'function'
        && collectText(node).trim() === '保存系统代理'
      ));
      await act(async () => {
        saveButton.props.onClick();
      });
      await flushMicrotasks();

      expect(apiMock.updateRuntimeSettings).toHaveBeenCalledWith({
        systemProxyUrl: 'http://127.0.0.1:7890',
      });
    } finally {
      root?.unmount();
    }
  });

  it('tests system proxy from settings', async () => {
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

      const proxyInput = root.root.find((node) => (
        node.type === 'input'
        && node.props.placeholder === '系统代理 URL（可选，如 http://127.0.0.1:7890 或 socks5://127.0.0.1:1080）'
      ));
      await act(async () => {
        proxyInput.props.onChange({ target: { value: 'http://127.0.0.1:7890' } });
      });

      const testButton = root.root.find((node) => (
        node.type === 'button'
        && typeof node.props.onClick === 'function'
        && collectText(node).trim() === '测试系统代理'
      ));
      await act(async () => {
        testButton.props.onClick();
      });
      await flushMicrotasks();

      expect(apiMock.testSystemProxy).toHaveBeenCalledWith({
        proxyUrl: 'http://127.0.0.1:7890',
      });
      expect(collectText(root.root)).toContain('连通成功，延迟 321 ms');
    } finally {
      root?.unmount();
    }
  });
});
