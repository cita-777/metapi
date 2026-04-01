import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, create, type ReactTestInstance, type ReactTestRenderer } from 'react-test-renderer';
import { MemoryRouter } from 'react-router-dom';
import { ToastProvider } from '../components/Toast.js';
import ModernSelect from '../components/ModernSelect.js';
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

describe('Settings route cooldown cap', () => {
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
      routingFallbackUnitCost: 1,
      routingWeights: {},
      tokenRouterFailureCooldownMaxSec: 30 * 24 * 60 * 60,
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
    apiMock.updateRuntimeSettings.mockResolvedValue({ success: true });
    apiMock.getModelTokenCandidates.mockResolvedValue({ models: {} });
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('converts the selected route cooldown unit back into seconds when saving routing settings', async () => {
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

      const cooldownInput = root.root.find((node) => (
        node.type === 'input'
        && node.props.type === 'number'
        && node.props['aria-label'] === '路由失败冷却上限数值'
      ));
      const cooldownUnitSelect = root.root.find((node) => (
        node.type === ModernSelect
        && node.props.placeholder === '选择单位'
      ));

      await act(async () => {
        cooldownInput.props.onChange({ target: { value: '10' } });
        cooldownUnitSelect.props.onChange('second');
      });

      const saveButton = root.root.find((node) => (
        node.type === 'button'
        && typeof node.props.onClick === 'function'
        && collectText(node).trim() === '保存路由策略'
      ));

      await act(async () => {
        saveButton.props.onClick();
      });
      await flushMicrotasks();

      expect(apiMock.updateRuntimeSettings).toHaveBeenCalledWith({
        routingWeights: {
          baseWeightFactor: 0.5,
          valueScoreFactor: 0.5,
          costWeight: 0.4,
          balanceWeight: 0.3,
          usageWeight: 0.3,
        },
        routingFallbackUnitCost: 1,
        tokenRouterFailureCooldownMaxSec: 10,
        disableCrossProtocolFallback: false,
      });
    } finally {
      root?.unmount();
    }
  });

  it('infers seconds as the editing unit when the saved cap is not an even day/hour/minute multiple', async () => {
    apiMock.getRuntimeSettings.mockResolvedValueOnce({
      checkinCron: '0 8 * * *',
      checkinScheduleMode: 'interval',
      checkinIntervalHours: 6,
      balanceRefreshCron: '0 * * * *',
      logCleanupCron: '15 4 * * *',
      logCleanupUsageLogsEnabled: true,
      logCleanupProgramLogsEnabled: true,
      logCleanupRetentionDays: 14,
      routingFallbackUnitCost: 1,
      routingWeights: {},
      tokenRouterFailureCooldownMaxSec: 10,
      adminIpAllowlist: [],
      systemProxyUrl: '',
    });

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

      const cooldownInput = root.root.find((node) => (
        node.type === 'input'
        && node.props.type === 'number'
        && node.props['aria-label'] === '路由失败冷却上限数值'
      ));
      const cooldownUnitSelect = root.root.find((node) => (
        node.type === ModernSelect
        && node.props.placeholder === '选择单位'
      ));

      expect(cooldownInput.props.value).toBe(10);
      expect(cooldownUnitSelect.props.value).toBe('second');
    } finally {
      root?.unmount();
    }
  });
});
