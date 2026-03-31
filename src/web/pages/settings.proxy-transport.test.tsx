import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, create, type ReactTestInstance, type ReactTestRenderer } from 'react-test-renderer';
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

describe('Settings proxy transport', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    apiMock.getAuthInfo.mockResolvedValue({ masked: 'sk-****' });
    apiMock.getRuntimeSettings.mockResolvedValue({
      checkinCron: '0 8 * * *',
      checkinScheduleMode: 'interval',
      checkinIntervalHours: 6,
      balanceRefreshCron: '0 * * * *',
      logCleanupCron: '15 4 * * *',
      logCleanupUsageLogsEnabled: true,
      logCleanupProgramLogsEnabled: true,
      logCleanupRetentionDays: 14,
      codexUpstreamWebsocketEnabled: false,
      proxySessionChannelConcurrencyLimit: 4,
      proxySessionChannelQueueWaitMs: 3200,
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
      codexUpstreamWebsocketEnabled: true,
      proxySessionChannelConcurrencyLimit: 6,
      proxySessionChannelQueueWaitMs: 4200,
    });
    apiMock.getModelTokenCandidates.mockResolvedValue({ models: {} });
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('saves codex upstream websocket and session lease settings from the settings page', async () => {
    let root!: ReactTestRenderer;
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

      const websocketToggleLabel = root.root.find((node) => (
        node.type === 'label'
        && collectText(node).includes('允许 metapi 到 Codex 上游使用 WebSocket')
      ));
      const websocketToggle = websocketToggleLabel.findByType('input');
      expect(websocketToggle.props.checked).toBe(false);

      const concurrencyInput = root.root.find((node) => (
        node.type === 'input'
        && node.props.type === 'number'
        && node.props.value === 4
      ));
      const queueWaitInput = root.root.find((node) => (
        node.type === 'input'
        && node.props.type === 'number'
        && node.props.value === 3200
      ));

      await act(async () => {
        websocketToggle.props.onChange({ target: { checked: true } });
        concurrencyInput.props.onChange({ target: { value: '6' } });
        queueWaitInput.props.onChange({ target: { value: '4200' } });
      });

      const saveButton = root.root.find((node) => (
        node.type === 'button'
        && typeof node.props.onClick === 'function'
        && collectText(node).trim() === '保存传输与并发'
      ));
      await act(async () => {
        saveButton.props.onClick();
      });
      await flushMicrotasks();

      expect(apiMock.updateRuntimeSettings).toHaveBeenCalledWith({
        codexUpstreamWebsocketEnabled: true,
        proxySessionChannelConcurrencyLimit: 6,
        proxySessionChannelQueueWaitMs: 4200,
      });
    } finally {
      root?.unmount();
    }
  });
});
