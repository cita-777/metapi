import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, create, type ReactTestInstance, type ReactTestRenderer } from 'react-test-renderer';
import { MemoryRouter } from 'react-router-dom';
import { ToastProvider } from '../components/Toast.js';
import { ROUTE_DECISION_REFRESH_TASK_TYPE } from '../../shared/tokenRouteContract.js';
import TokenRoutes from './TokenRoutes.js';

const { apiMock, getBrandMock } = vi.hoisted(() => ({
  apiMock: {
    getRoutesSummary: vi.fn(),
    refreshRouteDecisionSnapshots: vi.fn(),
    getRouteChannels: vi.fn(),
    getTask: vi.fn(),
    getTasks: vi.fn(),
    getModelTokenCandidates: vi.fn(),
    getRouteDecisionsBatch: vi.fn(),
    getRouteWideDecisionsBatch: vi.fn(),
  },
  getBrandMock: vi.fn(),
}));

vi.mock('../api.js', () => ({
  api: apiMock,
}));

vi.mock('../components/BrandIcon.js', () => ({
  BrandGlyph: ({ brand, icon, model }: { brand?: { name?: string } | null; icon?: string | null; model?: string | null }) => (
    <span>{brand?.name || icon || model || ''}</span>
  ),
  InlineBrandIcon: ({ model }: { model: string }) => model ? <span>{model}</span> : null,
  getBrand: (...args: unknown[]) => getBrandMock(...args),
  hashColor: () => 'linear-gradient(135deg,#4f46e5,#818cf8)',
  normalizeBrandIconKey: (icon: string) => icon,
}));

function collectText(node: ReactTestInstance): string {
  return (node.children || []).map((child) => {
    if (typeof child === 'string') return child;
    return collectText(child);
  }).join('');
}

function findButtonByText(root: ReactTestInstance, text: string): ReactTestInstance {
  return root.find((node) => (
    node.type === 'button'
    && typeof node.props.onClick === 'function'
    && collectText(node).includes(text)
  ));
}

async function flushMicrotasks() {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
  });
}

describe('TokenRoutes refresh decision action', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getBrandMock.mockReset();
    getBrandMock.mockReturnValue(null);
    apiMock.getRoutesSummary.mockResolvedValue([
      {
        id: 1, modelPattern: 'gpt-4o-mini', displayName: 'gpt-4o-mini',
        displayIcon: null, modelMapping: null, enabled: true,
        channelCount: 0, enabledChannelCount: 0, siteNames: [],
        decisionSnapshot: null, decisionRefreshedAt: null,
      },
      {
        id: 2, modelPattern: 're:^claude-(opus|sonnet)-4-6$', displayName: 'claude-group',
        displayIcon: null, modelMapping: null, enabled: true,
        channelCount: 0, enabledChannelCount: 0, siteNames: [],
        decisionSnapshot: null, decisionRefreshedAt: null,
      },
    ]);
    apiMock.getRouteChannels.mockResolvedValue([]);
    apiMock.refreshRouteDecisionSnapshots.mockResolvedValue({ queued: true, jobId: 'task-1', status: 'pending' });
    apiMock.getTasks.mockResolvedValue({ tasks: [] });
    apiMock.getTask.mockResolvedValue({ task: { id: 'task-1', status: 'succeeded' } });
    apiMock.getModelTokenCandidates.mockResolvedValue({ models: {} });
    apiMock.getRouteDecisionsBatch.mockResolvedValue({ decisions: {} });
    apiMock.getRouteWideDecisionsBatch.mockResolvedValue({ decisions: {} });
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('queues a background snapshot refresh task when user clicks refresh selection probability', async () => {
    let root!: ReactTestRenderer;
    try {
      apiMock.getRoutesSummary
        .mockResolvedValueOnce([
          {
            id: 1, modelPattern: 'gpt-4o-mini', displayName: 'gpt-4o-mini',
            displayIcon: null, modelMapping: null, enabled: true,
            channelCount: 0, enabledChannelCount: 0, siteNames: [],
            decisionSnapshot: null, decisionRefreshedAt: null,
          },
          {
            id: 2, modelPattern: 're:^claude-(opus|sonnet)-4-6$', displayName: 'claude-group',
            displayIcon: null, modelMapping: null, enabled: true,
            channelCount: 0, enabledChannelCount: 0, siteNames: [],
            decisionSnapshot: null, decisionRefreshedAt: null,
          },
        ])
        .mockResolvedValueOnce([
          {
            id: 1, modelPattern: 'gpt-4o-mini', displayName: 'gpt-4o-mini',
            displayIcon: null, modelMapping: null, enabled: true,
            channelCount: 0, enabledChannelCount: 0, siteNames: [],
            decisionSnapshot: { matched: true, candidates: [] }, decisionRefreshedAt: '2026-04-01T00:00:00.000Z',
          },
          {
            id: 2, modelPattern: 're:^claude-(opus|sonnet)-4-6$', displayName: 'claude-group',
            displayIcon: null, modelMapping: null, enabled: true,
            channelCount: 0, enabledChannelCount: 0, siteNames: [],
            decisionSnapshot: { matched: true, candidates: [] }, decisionRefreshedAt: '2026-04-01T00:00:00.000Z',
          },
        ]);

      await act(async () => {
        root = create(
          <MemoryRouter initialEntries={['/routes']}>
            <ToastProvider>
              <TokenRoutes />
            </ToastProvider>
          </MemoryRouter>,
        );
      });
      await flushMicrotasks();

      const refreshButton = findButtonByText(root.root, '刷新选中概率');
      await act(async () => {
        await refreshButton.props.onClick();
      });
      await flushMicrotasks();
      await flushMicrotasks();

      expect(apiMock.refreshRouteDecisionSnapshots).toHaveBeenCalledTimes(1);
      expect(apiMock.getTask).toHaveBeenCalledWith('task-1');
      expect(apiMock.getRoutesSummary).toHaveBeenCalledTimes(2);
      expect(apiMock.getRouteDecisionsBatch).not.toHaveBeenCalled();
      expect(apiMock.getRouteWideDecisionsBatch).not.toHaveBeenCalled();
    } finally {
      root?.unmount();
    }
  });

  it('resumes a running background probability refresh task when revisiting the page', async () => {
    let root!: ReactTestRenderer;
    try {
      apiMock.getRoutesSummary
        .mockResolvedValueOnce([
          {
            id: 1, modelPattern: 'gpt-4o-mini', displayName: 'gpt-4o-mini',
            displayIcon: null, modelMapping: null, enabled: true,
            channelCount: 0, enabledChannelCount: 0, siteNames: [],
            decisionSnapshot: null, decisionRefreshedAt: null,
          },
        ])
        .mockResolvedValueOnce([
          {
            id: 1, modelPattern: 'gpt-4o-mini', displayName: 'gpt-4o-mini',
            displayIcon: null, modelMapping: null, enabled: true,
            channelCount: 0, enabledChannelCount: 0, siteNames: [],
            decisionSnapshot: { matched: true, candidates: [] }, decisionRefreshedAt: '2026-04-01T00:00:00.000Z',
          },
        ]);
      apiMock.getTasks.mockResolvedValue({
        tasks: [
          {
            id: 'task-restore',
            type: ROUTE_DECISION_REFRESH_TASK_TYPE,
            status: 'running',
          },
        ],
      });
      apiMock.getTask.mockResolvedValue({ task: { id: 'task-restore', status: 'succeeded' } });

      await act(async () => {
        root = create(
          <MemoryRouter initialEntries={['/routes']}>
            <ToastProvider>
              <TokenRoutes />
            </ToastProvider>
          </MemoryRouter>,
        );
      });
      await flushMicrotasks();
      await flushMicrotasks();

      expect(apiMock.getTasks).toHaveBeenCalled();
      expect(apiMock.getTask).toHaveBeenCalledWith('task-restore');
      expect(apiMock.getRoutesSummary).toHaveBeenCalledTimes(2);
    } finally {
      root?.unmount();
    }
  });
});
