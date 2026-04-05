import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, create, type ReactTestInstance, type ReactTestRenderer } from 'react-test-renderer';
import { MemoryRouter } from 'react-router-dom';
import { ToastProvider } from '../components/Toast.js';
import Settings from './Settings.js';

const MODEL_AVAILABILITY_PROBE_CONFIRM_TEXT = '我确认我使用的中转站全部允许批量测活，如因开启此功能被中转站封号，自行负责。';

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

describe('Settings model availability probe confirmation', () => {
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
      modelAvailabilityProbeEnabled: false,
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
      modelAvailabilityProbeEnabled: true,
    });
    apiMock.getModelTokenCandidates.mockResolvedValue({ models: {} });
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('requires the exact confirmation text before enabling model availability probing', async () => {
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

      const probeCard = root.root.find((node) => (
        node.type === 'div'
        && node.props['data-settings-card'] === 'model-availability-probe'
      ));
      expect(collectText(probeCard)).toContain('已关闭');
      expect(collectText(probeCard)).toContain('高风险操作');

      const toggleLabel = root.root.find((node) => (
        node.type === 'label'
        && collectText(node).includes('允许 metapi 后台主动批量测活')
      ));
      const toggle = toggleLabel.findByType('input');
      expect(toggle.props.checked).toBe(false);

      await act(async () => {
        toggle.props.onChange({ target: { checked: true } });
      });

      expect(collectText(probeCard)).toContain('待保存');

      const saveButton = root.root.find((node) => (
        node.type === 'button'
        && typeof node.props.onClick === 'function'
        && collectText(node).trim() === '保存批量测活设置'
      ));
      await act(async () => {
        saveButton.props.onClick();
      });
      await flushMicrotasks();

      expect(JSON.stringify(root.toJSON())).toContain(MODEL_AVAILABILITY_PROBE_CONFIRM_TEXT);
      expect(apiMock.updateRuntimeSettings).not.toHaveBeenCalled();

      const confirmButtonBeforeTyping = root.root.find((node) => (
        node.type === 'button'
        && collectText(node).trim() === '确认开启批量测活'
        && node.props.className === 'btn btn-danger'
      ));
      expect(confirmButtonBeforeTyping.props.disabled).toBe(true);

      const confirmInput = root.root.find((node) => (
        node.type === 'textarea'
        && node.props.placeholder === '请输入上方确认语句'
      ));
      await act(async () => {
        confirmInput.props.onChange({ target: { value: MODEL_AVAILABILITY_PROBE_CONFIRM_TEXT } });
      });

      const confirmButton = root.root.find((node) => (
        node.type === 'button'
        && collectText(node).trim() === '确认开启批量测活'
        && node.props.className === 'btn btn-danger'
      ));
      expect(confirmButton.props.disabled).toBe(false);

      await act(async () => {
        confirmButton.props.onClick();
      });
      await flushMicrotasks();

      expect(apiMock.updateRuntimeSettings).toHaveBeenCalledWith({
        modelAvailabilityProbeEnabled: true,
      });
    } finally {
      root?.unmount();
    }
  });
});
