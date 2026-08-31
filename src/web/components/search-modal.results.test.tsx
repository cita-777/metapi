import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, create, type ReactTestInstance } from 'react-test-renderer';
import { MemoryRouter, useLocation } from 'react-router-dom';
import SearchModal from './SearchModal.js';

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    search: vi.fn(),
  },
}));

vi.mock('../api.js', () => ({
  api: apiMock,
}));

vi.mock('../i18n.js', () => ({
  useI18n: () => ({
    t: (value: string) => value,
  }),
}));

function collectText(node: ReactTestInstance): string {
  const children = node.children || [];
  return children.map((child) => {
    if (typeof child === 'string') return child;
    return collectText(child);
  }).join('');
}

function LocationProbe() {
  const location = useLocation();
  return <div id="location-probe">{`${location.pathname}${location.search}`}</div>;
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

function modelResult(name: string) {
  return {
    models: [{ name, accountCount: 1, tokenCount: 1, siteCount: 1 }],
    sites: [],
    checkinLogs: [],
    proxyLogs: [],
    accounts: [],
    accountTokens: [],
  };
}

async function flushMicrotasks() {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
  });
}

describe('SearchModal results', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers();
    Object.defineProperty(globalThis, 'window', {
      value: globalThis,
      configurable: true,
      writable: true,
    });
    Object.defineProperty(globalThis, 'document', {
      value: {
        addEventListener: () => undefined,
        removeEventListener: () => undefined,
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

  it('renders account token results and navigates API key accounts to the apikey segment', async () => {
    apiMock.search.mockResolvedValue({
      models: [],
      sites: [],
      checkinLogs: [],
      proxyLogs: [],
      accounts: [
        {
          id: 8,
          username: '',
          balance: 0,
          segment: 'apikey',
          site: { name: 'Key Search Site' },
        },
      ],
      accountTokens: [
        {
          id: 15,
          name: 'search-token',
          tokenGroup: 'default',
          accountId: 8,
          account: { username: '' },
          site: { name: 'Key Search Site' },
        },
      ],
    });

    const onClose = vi.fn();
    let root!: WebTestRenderer;
    try {
      await act(async () => {
        root = create(
          <MemoryRouter initialEntries={['/']}>
            <LocationProbe />
            <SearchModal open onClose={onClose} />
          </MemoryRouter>,
        );
      });

      const input = root.root.findByType('input');
      await act(async () => {
        input.props.onChange({ target: { value: 'search' } });
        vi.advanceTimersByTime(300);
        await Promise.resolve();
      });
      await flushMicrotasks();

      const rendered = JSON.stringify(root.toJSON());
      expect(rendered).toContain('账号令牌');
      expect(rendered).toContain('search-token');
      expect(rendered).toContain('API Key 连接');

      const buttons = root.root.findAll((node) => node.type === 'button');
      const accountButton = buttons.find((node) => collectText(node).includes('API Key 连接'));
      expect(accountButton).toBeTruthy();

      await act(async () => {
        accountButton!.props.onClick();
      });
      const locationAfterAccountClick = root.root.find((node) => node.props?.id === 'location-probe');
      expect(collectText(locationAfterAccountClick)).toBe('/accounts?segment=apikey&focusAccountId=8');
    } finally {
      root?.unmount();
    }
  });

  it('aborts stale searches and only renders the newest query response', async () => {
    const first = deferred<ReturnType<typeof modelResult>>();
    const second = deferred<ReturnType<typeof modelResult>>();
    const calls: Array<{ query: string; signal?: AbortSignal }> = [];
    apiMock.search.mockImplementation((query: string, options?: { signal?: AbortSignal }) => {
      calls.push({ query, signal: options?.signal });
      return query === 'q1' ? first.promise : second.promise;
    });

    let root!: WebTestRenderer;
    try {
      await act(async () => {
        root = create(
          <MemoryRouter>
            <SearchModal open onClose={() => {}} />
          </MemoryRouter>,
        );
      });
      const input = root.root.findByType('input');

      await act(async () => {
        input.props.onChange({ target: { value: 'q1' } });
        vi.advanceTimersByTime(300);
        await Promise.resolve();
      });
      expect(calls).toHaveLength(1);
      expect(calls[0]).toMatchObject({ query: 'q1' });
      expect(calls[0]?.signal).toBeInstanceOf(AbortSignal);

      await act(async () => {
        input.props.onChange({ target: { value: 'q2' } });
      });
      expect(calls[0]?.signal?.aborted).toBe(true);

      await act(async () => {
        vi.advanceTimersByTime(300);
        await Promise.resolve();
      });
      expect(calls.map((call) => call.query)).toEqual(['q1', 'q2']);

      await act(async () => {
        first.resolve(modelResult('stale-q1'));
        second.resolve(modelResult('fresh-q2'));
        await Promise.all([first.promise, second.promise]);
        await Promise.resolve();
      });

      const rendered = JSON.stringify(root.toJSON());
      expect(rendered).toContain('fresh-q2');
      expect(rendered).not.toContain('stale-q1');
    } finally {
      root?.unmount();
    }
  });

  it('shows a visible error state instead of swallowing search failures', async () => {
    apiMock.search.mockRejectedValue(new Error('network unavailable'));
    let root!: WebTestRenderer;
    try {
      await act(async () => {
        root = create(
          <MemoryRouter>
            <SearchModal open onClose={() => {}} />
          </MemoryRouter>,
        );
      });
      const input = root.root.findByType('input');
      await act(async () => {
        input.props.onChange({ target: { value: 'broken' } });
        vi.advanceTimersByTime(300);
        await Promise.resolve();
        await Promise.resolve();
      });

      const alert = root.root.findByProps({ role: 'alert' });
      expect(collectText(alert)).toContain('请求失败');
      expect(collectText(alert)).toContain('network unavailable');
      expect(JSON.stringify(root.toJSON())).not.toContain('没有找到匹配结果');
    } finally {
      root?.unmount();
    }
  });

  it('clears debounce/focus timers and aborts an in-flight request on close', async () => {
    const pending = deferred<ReturnType<typeof modelResult>>();
    let signal!: AbortSignal;
    apiMock.search.mockImplementation((_query: string, options?: { signal?: AbortSignal }) => {
      signal = options?.signal as AbortSignal;
      return pending.promise;
    });

    const onClose = vi.fn();
    let root!: WebTestRenderer;
    try {
      await act(async () => {
        root = create(
          <MemoryRouter>
            <SearchModal open onClose={onClose} />
          </MemoryRouter>,
        );
      });
      const input = root.root.findByType('input');
      await act(async () => {
        input.props.onChange({ target: { value: 'pending' } });
        vi.advanceTimersByTime(300);
        await Promise.resolve();
      });
      expect(signal).toBeInstanceOf(AbortSignal);

      const backdrop = root.root.find((node) => (
        typeof node.props.className === 'string'
        && node.props.className.includes('modal-backdrop')
      ));
      await act(async () => {
        backdrop.props.onClick();
      });

      expect(onClose).toHaveBeenCalledTimes(1);
      expect(signal.aborted).toBe(true);
      expect(vi.getTimerCount()).toBe(0);

      pending.resolve(modelResult('late'));
      await act(async () => {
        await Promise.resolve();
      });
      expect(JSON.stringify(root.toJSON())).not.toContain('late');
    } finally {
      root?.unmount();
    }
  });

  it('cleans the delayed focus timer when the modal unmounts before focus', async () => {
    let root!: WebTestRenderer;
    try {
      await act(async () => {
        root = create(
          <MemoryRouter>
            <SearchModal open onClose={() => {}} />
          </MemoryRouter>,
        );
      });
      expect(vi.getTimerCount()).toBeGreaterThan(0);
      await act(async () => {
        root.unmount();
      });
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      root?.unmount();
    }
  });
});
