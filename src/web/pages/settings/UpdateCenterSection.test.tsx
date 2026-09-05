import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, create, type ReactTestInstance, type ReactTestRenderer } from 'react-test-renderer';
import { ToastProvider } from '../../components/Toast.js';

import UpdateCenterSection from './UpdateCenterSection.js';

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    getUpdateCenterStatus: vi.fn(),
    saveUpdateCenterConfig: vi.fn(),
    checkUpdateCenter: vi.fn(),
    deployUpdateCenter: vi.fn(),
    rollbackUpdateCenter: vi.fn(),
    streamUpdateCenterTaskLogs: vi.fn(),
    getTask: vi.fn(),
  },
}));

vi.mock('../../api.js', () => ({ api: apiMock }));

function collectText(node: ReactTestInstance): string {
  return (node.children || []).map((child) => typeof child === 'string' ? child : collectText(child)).join('');
}

const baseStatus = {
  supported: true,
  mode: 'local-bundle',
  reason: null,
  currentVersion: '1.2.3',
  latestRelease: {
    source: 'github-release',
    rawVersion: 'v1.3.0',
    normalizedVersion: '1.3.0',
    tagName: 'v1.3.0',
    displayVersion: '1.3.0',
    url: null,
    publishedAt: null,
    assets: [],
  },
  installedVersions: [
    { version: '1.2.3', current: true, previous: false },
    { version: '1.1.0', current: false, previous: true },
  ],
  updateState: 'healthy',
  restartPending: false,
  canUpdate: true,
  canRollback: true,
  lastError: null,
  config: { enabled: true, channel: 'stable', autoCheck: false },
};

describe('UpdateCenterSection', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    apiMock.getUpdateCenterStatus.mockResolvedValue(baseStatus);
    apiMock.checkUpdateCenter.mockResolvedValue(baseStatus);
    apiMock.saveUpdateCenterConfig.mockResolvedValue({ config: baseStatus.config });
    apiMock.deployUpdateCenter.mockResolvedValue({ task: { id: 'task-1' } });
    apiMock.rollbackUpdateCenter.mockResolvedValue({ task: { id: 'task-2' } });
    apiMock.streamUpdateCenterTaskLogs.mockResolvedValue(undefined);
  });

  afterEach(() => vi.clearAllMocks());

  it('renders capability, release and local version history', async () => {
    let root!: ReactTestRenderer;
    try {
      await act(async () => {
        root = create(<ToastProvider><UpdateCenterSection /></ToastProvider>);
      });
      await act(async () => { await Promise.resolve(); await Promise.resolve(); });
      const text = collectText(root.root);
      expect(text).toContain('支持一键升级');
      expect(text).toContain('1.3.0');
      expect(text).toContain('已安装版本');
      expect(text).toContain('1.1.0');
      expect(text).not.toContain('Helm');
    } finally {
      root?.unmount();
    }
  });

  it('disables update and rollback actions when the runtime is unsupported', async () => {
    apiMock.getUpdateCenterStatus.mockResolvedValue({
      ...baseStatus,
      supported: false,
      reason: 'runtime directory is not marked as a persistent volume',
      canUpdate: false,
      canRollback: false,
    });
    let root!: ReactTestRenderer;
    try {
      await act(async () => {
        root = create(<ToastProvider><UpdateCenterSection /></ToastProvider>);
      });
      await act(async () => { await Promise.resolve(); await Promise.resolve(); });
      const buttons = root.root.findAllByType('button');
      const updateButton = buttons.find((button) => collectText(button) === '一键升级');
      const rollbackButton = buttons.find((button) => collectText(button) === '回滚');
      expect(updateButton?.props.disabled).toBe(true);
      expect(rollbackButton?.props.disabled).toBe(true);
    } finally {
      root?.unmount();
    }
  });

  it('keeps the task stream abortable when the section unmounts', async () => {
    let streamSignal: AbortSignal | undefined;
    apiMock.streamUpdateCenterTaskLogs.mockImplementation(async (_taskId: string, handlers: { signal?: AbortSignal; onLog?: (entry: { message?: string }) => void }) => {
      streamSignal = handlers.signal;
      handlers.onLog?.({ message: '下载中' });
      await new Promise<void>((resolve) => {
        handlers.signal?.addEventListener('abort', () => resolve(), { once: true });
      });
    });
    let root!: ReactTestRenderer;
    await act(async () => {
      root = create(<ToastProvider><UpdateCenterSection /></ToastProvider>);
    });
    await act(async () => { await Promise.resolve(); await Promise.resolve(); });
    const updateButton = root.root.findAllByType('button').find((button) => collectText(button) === '一键升级');
    await act(async () => {
      updateButton?.props.onClick();
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(streamSignal).toBeDefined();
    await act(async () => { root.unmount(); });
    expect(streamSignal?.aborted).toBe(true);
  });

  it('coalesces repeated manual checks while the first request is pending', async () => {
    let resolveCheck!: (value: typeof baseStatus) => void;
    apiMock.checkUpdateCenter.mockImplementation(() => new Promise((resolve) => { resolveCheck = resolve; }));
    let root!: ReactTestRenderer;
    try {
      await act(async () => {
        root = create(<ToastProvider><UpdateCenterSection /></ToastProvider>);
      });
      await act(async () => { await Promise.resolve(); await Promise.resolve(); });
      const checkButton = root.root.findAllByType('button').find((button) => collectText(button) === '检查更新');
      await act(async () => {
        checkButton?.props.onClick();
        checkButton?.props.onClick();
        await Promise.resolve();
      });
      expect(apiMock.checkUpdateCenter).toHaveBeenCalledTimes(1);
      resolveCheck(baseStatus);
      await act(async () => { await Promise.resolve(); await Promise.resolve(); });
    } finally {
      root?.unmount();
    }
  });

  it('does not let settlement polling supersede a manual check', async () => {
    vi.useFakeTimers();
    let resolveCheck!: (value: typeof baseStatus) => void;
    apiMock.checkUpdateCenter.mockImplementation(() => new Promise((resolve) => { resolveCheck = resolve; }));
    apiMock.streamUpdateCenterTaskLogs.mockRejectedValue(new Error('stream disconnected'));
    apiMock.getTask.mockResolvedValue({ task: { status: 'running', logs: [] } });
    let root!: ReactTestRenderer;
    try {
      await act(async () => {
        root = create(<ToastProvider><UpdateCenterSection /></ToastProvider>);
      });
      await act(async () => { await Promise.resolve(); await Promise.resolve(); });
      const updateButton = root.root.findAllByType('button').find((button) => collectText(button) === '一键升级');
      await act(async () => {
        updateButton?.props.onClick();
        await Promise.resolve();
        await Promise.resolve();
        await Promise.resolve();
      });
      const statusCallsBeforeCheck = apiMock.getUpdateCenterStatus.mock.calls.length;
      const checkButton = root.root.findAllByType('button').find((button) => collectText(button) === '检查更新');
      await act(async () => {
        checkButton?.props.onClick();
        await Promise.resolve();
        await Promise.resolve();
      });
      expect(apiMock.checkUpdateCenter).toHaveBeenCalledTimes(1);

      await act(async () => {
        vi.advanceTimersByTime(2_000);
        await Promise.resolve();
        await Promise.resolve();
      });
      expect(apiMock.getUpdateCenterStatus.mock.calls.length).toBe(statusCallsBeforeCheck);

      resolveCheck(baseStatus);
      await act(async () => { await Promise.resolve(); await Promise.resolve(); });
    } finally {
      root?.unmount();
      vi.useRealTimers();
    }
  });

  it('handles a synchronous status adapter failure without an unhandled rejection', async () => {
    apiMock.getUpdateCenterStatus.mockImplementation(() => {
      throw new Error('status adapter unavailable');
    });
    let root!: ReactTestRenderer;
    try {
      await act(async () => {
        root = create(<ToastProvider><UpdateCenterSection /></ToastProvider>);
        await Promise.resolve();
        await Promise.resolve();
      });
      expect(collectText(root.root)).toContain('更新中心');
    } finally {
      root?.unmount();
    }
  });

  it('handles a synchronous manual-check adapter failure', async () => {
    apiMock.checkUpdateCenter.mockImplementation(() => {
      throw new Error('check adapter unavailable');
    });
    let root!: ReactTestRenderer;
    try {
      await act(async () => {
        root = create(<ToastProvider><UpdateCenterSection /></ToastProvider>);
      });
      await act(async () => { await Promise.resolve(); await Promise.resolve(); });
      const checkButton = root.root.findAllByType('button').find((button) => collectText(button) === '检查更新');
      await act(async () => {
        checkButton?.props.onClick();
        await Promise.resolve();
        await Promise.resolve();
      });
      expect(apiMock.checkUpdateCenter).toHaveBeenCalledTimes(1);
    } finally {
      root?.unmount();
    }
  });

  it('keeps polling after the task stream disconnects once a task id is known', async () => {
    vi.useFakeTimers();
    apiMock.streamUpdateCenterTaskLogs.mockRejectedValue(new Error('stream disconnected'));
    apiMock.getTask.mockResolvedValue({ task: { status: 'running', logs: [] } });
    let root!: ReactTestRenderer;
    try {
      await act(async () => {
        root = create(<ToastProvider><UpdateCenterSection /></ToastProvider>);
      });
      await act(async () => { await Promise.resolve(); await Promise.resolve(); });
      const initialStatusCalls = apiMock.getUpdateCenterStatus.mock.calls.length;
      const updateButton = root.root.findAllByType('button').find((button) => collectText(button) === '一键升级');
      await act(async () => {
        updateButton?.props.onClick();
        await Promise.resolve();
        await Promise.resolve();
        await Promise.resolve();
      });
      await act(async () => {
        vi.advanceTimersByTime(2_000);
        await Promise.resolve();
        await Promise.resolve();
      });
      expect(apiMock.getUpdateCenterStatus.mock.calls.length).toBeGreaterThan(initialStatusCalls);
    } finally {
      root?.unmount();
      vi.useRealTimers();
    }
  });
});
