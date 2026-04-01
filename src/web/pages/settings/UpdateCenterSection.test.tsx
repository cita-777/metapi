import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, create, type ReactTestInstance, type ReactTestRenderer } from 'react-test-renderer';
import { MemoryRouter } from 'react-router-dom';
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
  },
}));

vi.mock('../../api.js', () => ({
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

describe('UpdateCenterSection', () => {
  const originalDocument = globalThis.document;

  beforeEach(() => {
    vi.clearAllMocks();
    globalThis.document = {
      body: {
        nodeType: 1,
        style: {
          overflow: '',
        },
      },
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
    } as unknown as Document;
    apiMock.getUpdateCenterStatus.mockResolvedValue({
      currentVersion: '1.2.3',
      config: {
        enabled: true,
        helperBaseUrl: 'http://metapi-deploy-helper.ai.svc.cluster.local:9850',
        namespace: 'ai',
        releaseName: 'metapi',
        chartRef: 'oci://ghcr.io/cita-777/charts/metapi',
        imageRepository: '1467078763/metapi',
        githubReleasesEnabled: true,
        dockerHubTagsEnabled: true,
        defaultDeploySource: 'github-release',
      },
      githubRelease: {
        normalizedVersion: '1.3.0',
        displayVersion: '1.3.0',
      },
      dockerHubTag: {
        normalizedVersion: 'latest',
        tagName: 'latest',
        digest: 'sha256:efb2ee6553866bd3268dcc54c02fa5f9789728c51ed4af63328aaba6da67df35',
        displayVersion: 'latest @ sha256:efb2ee655386',
        publishedAt: '2026-03-29T11:54:35.591877Z',
      },
      helper: {
        ok: true,
        healthy: true,
        revision: '17',
        imageTag: 'latest',
        imageDigest: 'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
        history: [
          {
            revision: '17',
            updatedAt: '2026-03-29T12:00:00Z',
            status: 'deployed',
            description: 'Upgrade complete',
            imageRepository: '1467078763/metapi',
            imageTag: 'latest',
            imageDigest: 'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
          },
          {
            revision: '16',
            updatedAt: '2026-03-28T12:00:00Z',
            status: 'superseded',
            description: 'Rollback to stable digest',
            imageRepository: '1467078763/metapi',
            imageTag: 'main',
            imageDigest: 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
          },
          {
            revision: '15',
            updatedAt: '2026-03-27T12:00:00Z',
            status: 'superseded',
            description: 'Earlier stable release',
            imageRepository: '1467078763/metapi',
            imageTag: '1.2.2',
            imageDigest: 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
          },
        ],
      },
      runtime: {
        lastCheckedAt: '2026-03-30 20:30:00',
        lastCheckError: null,
        lastResolvedSource: 'github-release',
        lastResolvedDisplayVersion: '1.3.0',
        lastResolvedCandidateKey: 'github-release:v1.3.0',
        lastNotifiedCandidateKey: 'github-release:v1.3.0',
        lastNotifiedAt: '2026-03-30 20:31:00',
      },
      runningTask: null,
      lastFinishedTask: null,
    });
    apiMock.saveUpdateCenterConfig.mockResolvedValue({
      success: true,
      config: {
        enabled: true,
        helperBaseUrl: 'http://updated-helper.ai.svc.cluster.local:9850',
        namespace: 'ai',
        releaseName: 'metapi',
        chartRef: 'oci://ghcr.io/cita-777/charts/metapi',
        imageRepository: '1467078763/metapi',
        githubReleasesEnabled: true,
        dockerHubTagsEnabled: true,
        defaultDeploySource: 'github-release',
      },
    });
    apiMock.checkUpdateCenter.mockResolvedValue({
      currentVersion: '1.2.3',
      config: {
        enabled: true,
        helperBaseUrl: 'http://metapi-deploy-helper.ai.svc.cluster.local:9850',
        namespace: 'ai',
        releaseName: 'metapi',
        chartRef: 'oci://ghcr.io/cita-777/charts/metapi',
        imageRepository: '1467078763/metapi',
        githubReleasesEnabled: true,
        dockerHubTagsEnabled: true,
        defaultDeploySource: 'github-release',
      },
      githubRelease: {
        normalizedVersion: '1.3.0',
        displayVersion: '1.3.0',
      },
      dockerHubTag: {
        normalizedVersion: 'latest',
        tagName: 'latest',
        digest: 'sha256:efb2ee6553866bd3268dcc54c02fa5f9789728c51ed4af63328aaba6da67df35',
        displayVersion: 'latest @ sha256:efb2ee655386',
        publishedAt: '2026-03-29T11:54:35.591877Z',
      },
      helper: {
        ok: true,
        healthy: true,
        revision: '18',
        imageTag: 'latest',
        imageDigest: 'sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
        history: [],
      },
      runtime: {
        lastCheckedAt: '2026-03-30 20:35:00',
        lastCheckError: null,
        lastResolvedSource: 'github-release',
        lastResolvedDisplayVersion: '1.3.0',
        lastResolvedCandidateKey: 'github-release:v1.3.0',
        lastNotifiedCandidateKey: 'github-release:v1.3.0',
        lastNotifiedAt: '2026-03-30 20:31:00',
      },
      runningTask: null,
      lastFinishedTask: null,
    });
    apiMock.deployUpdateCenter.mockResolvedValue({
      success: true,
      reused: false,
      task: {
        id: 'task-1',
      },
    });
    apiMock.rollbackUpdateCenter.mockResolvedValue({
      success: true,
      reused: false,
      task: {
        id: 'task-2',
      },
    });
    apiMock.streamUpdateCenterTaskLogs.mockImplementation(async (_taskId: string, handlers: { onLog?: (entry: { message: string }) => void; onDone?: (payload: { status: string }) => void }) => {
      handlers.onLog?.({ message: 'Running helm upgrade' });
      handlers.onLog?.({ message: 'Waiting for rollout' });
      handlers.onDone?.({ status: 'succeeded' });
    });
  });

  afterEach(() => {
    vi.clearAllMocks();
    globalThis.document = originalDocument;
  });

  it('loads status, saves config updates, and renders streamed deploy logs', async () => {
    let root!: ReactTestRenderer;
    try {
      await act(async () => {
        root = create(
          <MemoryRouter>
            <ToastProvider>
              <UpdateCenterSection />
            </ToastProvider>
          </MemoryRouter>,
        );
      });
      await flushMicrotasks();

      const helperInput = root.root.find((node) => (
        node.type === 'input'
        && node.props.value === 'http://metapi-deploy-helper.ai.svc.cluster.local:9850'
      ));

      await act(async () => {
        helperInput.props.onChange({ target: { value: 'http://updated-helper.ai.svc.cluster.local:9850' } });
      });
      const checkboxInputs = root.root.findAll((node) => node.type === 'input' && node.props.type === 'checkbox');

      await act(async () => {
        checkboxInputs[1].props.onChange({ target: { checked: false } });
        checkboxInputs[2].props.onChange({ target: { checked: false } });
      });

      const defaultSourceTrigger = root.root.find((node) => (
        node.type === 'button'
        && typeof node.props.className === 'string'
        && node.props.className.includes('modern-select-trigger')
      ));

      await act(async () => {
        defaultSourceTrigger.props.onClick();
      });

      const dockerHubOption = root.root.find((node) => (
        node.type === 'button'
        && typeof node.props.className === 'string'
        && node.props.className.includes('modern-select-option')
        && collectText(node).includes('Docker Hub Tags')
      ));

      await act(async () => {
        dockerHubOption.props.onClick();
      });

      const saveButton = root.root.find((node) => (
        node.type === 'button'
        && typeof node.props.onClick === 'function'
        && collectText(node).includes('保存更新中心配置')
      ));

      await act(async () => {
        await saveButton.props.onClick();
      });
      await flushMicrotasks();

      expect(apiMock.saveUpdateCenterConfig).toHaveBeenCalledWith(expect.objectContaining({
        helperBaseUrl: 'http://updated-helper.ai.svc.cluster.local:9850',
        githubReleasesEnabled: false,
        dockerHubTagsEnabled: false,
        defaultDeploySource: 'docker-hub-tag',
      }));

      const deployButton = root.root.find((node) => (
        node.type === 'button'
        && typeof node.props.onClick === 'function'
        && collectText(node).includes('部署 GitHub 稳定版')
      ));

      await act(async () => {
        await deployButton.props.onClick();
      });
      await flushMicrotasks();

      expect(apiMock.deployUpdateCenter).toHaveBeenCalledWith({
        source: 'github-release',
        targetTag: '1.3.0',
        targetDigest: null,
      });
      expect(apiMock.streamUpdateCenterTaskLogs).toHaveBeenCalledWith('task-1', expect.any(Object));
      expect(apiMock.checkUpdateCenter).toHaveBeenCalledTimes(1);

      const text = collectText(root.root);
      expect(text).toContain('latest @ sha256:efb2ee655386');
      expect(text).toContain('发现新版本');
      expect(text).toContain('后台检查');
      expect(text).toContain('1.3.0');
      expect(text).toContain('Running helm upgrade');
      expect(text).toContain('Waiting for rollout');
      expect(text).toContain('任务状态 · 已完成');
    } finally {
      root?.unmount();
    }
  });

  it('disables deploy actions when the helper is unhealthy', async () => {
    apiMock.getUpdateCenterStatus.mockResolvedValueOnce({
      currentVersion: '1.2.3',
      config: {
        enabled: true,
        helperBaseUrl: 'http://metapi-deploy-helper.ai.svc.cluster.local:9850',
        namespace: 'ai',
        releaseName: 'metapi',
        chartRef: 'oci://ghcr.io/cita-777/charts/metapi',
        imageRepository: '1467078763/metapi',
        githubReleasesEnabled: true,
        dockerHubTagsEnabled: true,
        defaultDeploySource: 'github-release',
      },
      githubRelease: {
        normalizedVersion: '1.3.0',
      },
      dockerHubTag: {
        normalizedVersion: 'latest',
        displayVersion: 'latest @ sha256:efb2ee655386',
      },
      helper: {
        ok: false,
        healthy: false,
        error: 'helper unavailable',
      },
      runningTask: null,
      lastFinishedTask: null,
    });

    let root!: ReactTestRenderer;
    try {
      await act(async () => {
        root = create(
          <MemoryRouter>
            <ToastProvider>
              <UpdateCenterSection />
            </ToastProvider>
          </MemoryRouter>,
        );
      });
      await flushMicrotasks();

      const githubDeployButton = root.root.find((node) => (
        node.type === 'button'
        && typeof node.props.className === 'string'
        && node.props.className.includes('btn')
        && collectText(node).includes('部署 GitHub 稳定版')
      ));
      const dockerDeployButton = root.root.find((node) => (
        node.type === 'button'
        && typeof node.props.className === 'string'
        && node.props.className.includes('btn')
        && collectText(node).includes('部署 Docker Hub 标签')
      ));

      expect(githubDeployButton.props.disabled).toBe(true);
      expect(dockerDeployButton.props.disabled).toBe(true);

      await act(async () => {
        githubDeployButton.props.onClick?.();
        dockerDeployButton.props.onClick?.();
      });

      expect(apiMock.deployUpdateCenter).not.toHaveBeenCalled();
    } finally {
      root?.unmount();
    }
  });

  it('keeps rollback history compact and opens the full revision list in a centered modal', async () => {
    let root!: ReactTestRenderer;
    try {
      await act(async () => {
        root = create(
          <MemoryRouter>
            <ToastProvider>
              <UpdateCenterSection />
            </ToastProvider>
          </MemoryRouter>,
        );
      });
      await flushMicrotasks();

      const compactText = collectText(root.root);
      expect(compactText).toContain('展开全部 3 条');
      expect(compactText).not.toContain('Earlier stable release');
      expect(compactText).not.toContain('回退到 revision 15');

      const openHistoryButton = root.root.find((node) => (
        node.type === 'button'
        && typeof node.props.onClick === 'function'
        && collectText(node).includes('展开全部 3 条')
      ));

      await act(async () => {
        await openHistoryButton.props.onClick();
      });
      await flushMicrotasks();

      const modal = root.root.find((node) => (
        typeof node.props.className === 'string'
        && node.props.className.includes('modal-content')
        && collectText(node).includes('全部 revision')
      ));

      expect(collectText(modal)).toContain('Earlier stable release');
      expect(collectText(modal)).toContain('回退到 revision 15');
    } finally {
      root?.unmount();
    }
  });

  it('blocks Docker Hub deploys when the current helper image already matches the target digest', async () => {
    apiMock.getUpdateCenterStatus.mockResolvedValueOnce({
      currentVersion: '1.2.3',
      config: {
        enabled: true,
        helperBaseUrl: 'http://metapi-deploy-helper.ai.svc.cluster.local:9850',
        namespace: 'ai',
        releaseName: 'metapi',
        chartRef: 'oci://ghcr.io/cita-777/charts/metapi',
        imageRepository: '1467078763/metapi',
        githubReleasesEnabled: true,
        dockerHubTagsEnabled: true,
        defaultDeploySource: 'docker-hub-tag',
      },
      githubRelease: {
        normalizedVersion: '1.3.0',
        displayVersion: '1.3.0',
      },
      dockerHubTag: {
        normalizedVersion: 'latest',
        tagName: 'latest',
        digest: 'sha256:efb2ee6553866bd3268dcc54c02fa5f9789728c51ed4af63328aaba6da67df35',
        displayVersion: 'latest @ sha256:efb2ee655386',
      },
      helper: {
        ok: true,
        healthy: true,
        revision: '17',
        imageTag: 'latest',
        imageDigest: 'sha256:efb2ee6553866bd3268dcc54c02fa5f9789728c51ed4af63328aaba6da67df35',
      },
      runningTask: null,
      lastFinishedTask: null,
    });

    let root!: ReactTestRenderer;
    try {
      await act(async () => {
        root = create(
          <MemoryRouter>
            <ToastProvider>
              <UpdateCenterSection />
            </ToastProvider>
          </MemoryRouter>,
        );
      });
      await flushMicrotasks();

      const dockerDeployButton = root.root.find((node) => (
        node.type === 'button'
        && typeof node.props.className === 'string'
        && node.props.className.includes('btn')
        && collectText(node).includes('部署 Docker Hub 标签')
      ));

      expect(dockerDeployButton.props.disabled).toBe(true);
      expect(collectText(root.root)).toContain('当前已运行该镜像');
    } finally {
      root?.unmount();
    }
  });

  it('parses timezone-less SQL runtime timestamps as UTC before formatting', async () => {
    const parseSpy = vi.spyOn(Date, 'parse');
    let root!: ReactTestRenderer;
    try {
      await act(async () => {
        root = create(
          <MemoryRouter>
            <ToastProvider>
              <UpdateCenterSection />
            </ToastProvider>
          </MemoryRouter>,
        );
      });
      await flushMicrotasks();

      const parseInputs = parseSpy.mock.calls.map(([value]) => String(value));
      expect(parseInputs).toContain('2026-03-30T20:30:00Z');
      expect(parseInputs).not.toContain('2026-03-30 20:30:00');
    } finally {
      parseSpy.mockRestore();
      root?.unmount();
    }
  });

  it('renders rollback history and triggers rollback tasks for previous revisions', async () => {
    let root!: ReactTestRenderer;
    try {
      await act(async () => {
        root = create(
          <MemoryRouter>
            <ToastProvider>
              <UpdateCenterSection />
            </ToastProvider>
          </MemoryRouter>,
        );
      });
      await flushMicrotasks();

      const rollbackButton = root.root.find((node) => (
        node.type === 'button'
        && typeof node.props.onClick === 'function'
        && collectText(node).includes('回退到 revision 16')
      ));

      await act(async () => {
        await rollbackButton.props.onClick();
      });
      await flushMicrotasks();

      expect(apiMock.rollbackUpdateCenter).toHaveBeenCalledWith({
        targetRevision: '16',
      });
      expect(apiMock.streamUpdateCenterTaskLogs).toHaveBeenCalledWith('task-2', expect.any(Object));
      expect(apiMock.checkUpdateCenter).toHaveBeenCalledTimes(1);

      const text = collectText(root.root);
      expect(text).toContain('最近状态：succeeded');
    } finally {
      root?.unmount();
    }
  });
});
