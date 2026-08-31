import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, create, type ReactTestRenderer } from 'react-test-renderer';
import ModelTester, { parseStreamErrorText } from './ModelTester.js';
import {
  DEBUG_TABS,
  DEFAULT_INPUTS,
  DEFAULT_MODE_STATE,
  DEFAULT_PARAMETER_ENABLED,
  MODEL_TESTER_STORAGE_KEY,
  serializeModelTesterSession,
} from './helpers/modelTesterSession.js';

const { apiMock, debugResponseSnapshots } = vi.hoisted(() => ({
  apiMock: {
    getModelsMarketplace: vi.fn(),
    getRoutes: vi.fn(),
    getRouteDecision: vi.fn(),
    proxyTestStream: vi.fn(),
    getProxyTestJob: vi.fn(),
    deleteProxyTestJob: vi.fn(),
  },
  debugResponseSnapshots: [] as string[],
}));

let storageRef: Map<string, string> | null = null;

vi.mock('../api.js', () => ({ api: apiMock }));
vi.mock('../authSession.js', () => ({
  clearAuthSession: vi.fn(),
  getAuthToken: vi.fn(() => null),
}));
vi.mock('./model-tester/DebugPanel.js', () => ({
  default: (props: { activeDebugTab: string; debugTabContent: string }) => {
    if (props.activeDebugTab === 'response') {
      debugResponseSnapshots.push(props.debugTabContent);
    }
    return null;
  },
}));
vi.mock('../components/useAnimatedVisibility.js', () => ({
  useAnimatedVisibility: () => ({ shouldRender: false, isVisible: false }),
}));
vi.mock('../components/useIsMobile.js', () => ({ useIsMobile: () => false }));
vi.mock('../i18n.js', () => ({ tr: (value: string) => value }));
vi.mock('./model-tester/ConversationComposer.js', () => ({
  default: (props: any) => (
    <div>
      <textarea data-testid="composer-input" value={props.input} onChange={(event) => props.onInputChange(event.target.value)} />
      <button type="button" data-testid="send" onClick={() => props.onSend()}>send</button>
      <button type="button" data-testid="stop" onClick={() => props.onStop()}>stop</button>
    </div>
  ),
}));

const collectText = (node: any): string => {
  const children = node?.children || [];
  return children.map((child: any) => (typeof child === 'string' ? child : collectText(child))).join('');
};

describe('ModelTester stream batching', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    debugResponseSnapshots.length = 0;
    const storage = new Map<string, string>([[MODEL_TESTER_STORAGE_KEY, serializeModelTesterSession({
      input: '',
      inputs: { ...DEFAULT_INPUTS, model: 'gpt-test', stream: true },
      parameterEnabled: DEFAULT_PARAMETER_ENABLED,
      messages: [],
      conversationFiles: [],
      pendingPayload: null,
      pendingJobId: null,
      forcedChannelId: null,
      customRequestMode: false,
      customRequestBody: '',
      showDebugPanel: false,
      activeDebugTab: DEBUG_TABS.PREVIEW,
      modeState: DEFAULT_MODE_STATE,
    })]]);
    storageRef = storage;
    vi.stubGlobal('localStorage', {
      getItem: (key: string) => storage.get(key) ?? null,
      setItem: (key: string, value: string) => storage.set(key, value),
      removeItem: (key: string) => storage.delete(key),
    });
    apiMock.getModelsMarketplace.mockResolvedValue({ models: [{ name: 'gpt-test' }] });
    apiMock.getRoutes.mockResolvedValue([]);
    apiMock.getRouteDecision.mockResolvedValue({ decision: { candidates: [] } });
    apiMock.deleteProxyTestJob.mockResolvedValue({});
    apiMock.proxyTestStream.mockImplementation(async (_payload: unknown, signal: AbortSignal) => {
      const encoder = new TextEncoder();
      const frames = [
        `data: ${JSON.stringify({ choices: [{ delta: { content: 'a' } }] })}\n\n`,
        `data: ${JSON.stringify({ choices: [{ delta: { content: 'ab' } }] })}\n\n`,
        'data: [DONE]\n\n',
      ];
      const body = new ReadableStream<Uint8Array>({
        start(controller) {
          if (signal.aborted) {
            controller.error(new Error('aborted'));
            return;
          }
          for (const frame of frames) controller.enqueue(encoder.encode(frame));
          controller.close();
        },
      });
      return new Response(body, { status: 200 });
    });
  });

  afterEach(() => vi.unstubAllGlobals());

  it('preserves abort and timeout errors while reading a non-OK stream body', async () => {
    const abortError = Object.assign(new Error('The operation was aborted.'), {
      name: 'AbortError',
    });
    const timeoutError = Object.assign(new Error('请求超时（30s）'), {
      name: 'TimeoutError',
    });
    const abortResponse = {
      status: 504,
      text: vi.fn().mockRejectedValue(abortError),
    } as unknown as Response;
    const timeoutResponse = {
      status: 504,
      text: vi.fn().mockRejectedValue(timeoutError),
    } as unknown as Response;

    await expect(parseStreamErrorText(abortResponse)).rejects.toBe(abortError);
    await expect(parseStreamErrorText(timeoutResponse)).rejects.toBe(timeoutError);
  });

  it('keeps cumulative delta content equivalent', async () => {
    let root: ReactTestRenderer | undefined;
    try {
      await act(async () => { root = create(<ModelTester />); });
      await act(async () => {
        await Promise.resolve();
        await Promise.resolve();
        await Promise.resolve();
      });
      const textarea = root!.root.findByProps({ 'data-testid': 'composer-input' });
      await act(async () => { textarea.props.onChange({ target: { value: 'hello' } }); });
      const sendButton = root!.root.findByProps({ 'data-testid': 'send' });
      const snapshotsBeforeStream = debugResponseSnapshots.length;
      await act(async () => { await sendButton.props.onClick(); });
      await act(async () => {
        await Promise.resolve();
        await Promise.resolve();
      });
      expect(collectText(root!.toJSON())).toContain('ab');
      expect(collectText(root!.toJSON())).not.toContain('aab');
      expect(debugResponseSnapshots.at(-1)).toContain('[DONE]');
      expect(debugResponseSnapshots.at(-1)).toContain('"content":"a"');
      const rawSnapshots = debugResponseSnapshots
        .slice(snapshotsBeforeStream)
        .filter((snapshot) => snapshot.includes('[DONE]'));
      expect(new Set(rawSnapshots).size).toBe(1);
    } finally {
      root?.unmount();
    }
  });

  it('flushes the pending delta before a user stop and cancels the reader', async () => {
    vi.useFakeTimers();
    let readerCancelled = false;
    apiMock.proxyTestStream.mockImplementationOnce(async (_payload: unknown, _signal: AbortSignal) => {
      const encoder = new TextEncoder();
      const body = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(encoder.encode(
            `data: ${JSON.stringify({ choices: [{ delta: { content: 'a' } }] })}\n\n`,
          ));
        },
        cancel() {
          readerCancelled = true;
        },
      });
      return new Response(body, { status: 200 });
    });

    let root: ReactTestRenderer | undefined;
    try {
      await act(async () => { root = create(<ModelTester />); });
      await act(async () => {
        await Promise.resolve();
        await Promise.resolve();
        await Promise.resolve();
      });
      const textarea = root!.root.findByProps({ 'data-testid': 'composer-input' });
      await act(async () => { textarea.props.onChange({ target: { value: 'hello' } }); });
      const sendButton = root!.root.findByProps({ 'data-testid': 'send' });
      await act(async () => {
        void sendButton.props.onClick();
        await Promise.resolve();
        await Promise.resolve();
      });
      await act(async () => {
        await Promise.resolve();
        await Promise.resolve();
      });

      const stopButton = root!.root.findByProps({ 'data-testid': 'stop' });
      await act(async () => { await stopButton.props.onClick(); });
      expect(collectText(root!.toJSON())).toContain('a');
      expect(readerCancelled).toBe(true);
    } finally {
      root?.unmount();
      vi.useRealTimers();
    }
  });

  it('forwards an abort signal to pending-job polling and stops the loop', async () => {
    const stored = JSON.parse(storageRef!.get(MODEL_TESTER_STORAGE_KEY) || '{}') as Record<string, unknown>;
    stored.pendingJobId = 'job-42';
    storageRef!.set(MODEL_TESTER_STORAGE_KEY, JSON.stringify(stored));
    apiMock.getProxyTestJob.mockReturnValue(new Promise(() => { }));

    let root: ReactTestRenderer | undefined;
    try {
      await act(async () => { root = create(<ModelTester />); });
      await act(async () => {
        await Promise.resolve();
        await Promise.resolve();
        await Promise.resolve();
      });

      // Pending sessions render the reconnect state before polling starts.
      expect(collectText(root!.toJSON())).toContain('发现未完成的任务');

      await vi.waitFor(() => {
        expect(apiMock.getProxyTestJob).toHaveBeenCalled();
      });

      expect(apiMock.getProxyTestJob).toHaveBeenCalledWith(
        'job-42',
        { signal: expect.any(AbortSignal) },
      );
      const signal = apiMock.getProxyTestJob.mock.calls[0][1].signal as AbortSignal;
      const stopButton = root!.root.findByProps({ 'data-testid': 'stop' });
      await act(async () => { await stopButton.props.onClick(); });
      expect(signal.aborted).toBe(true);
      expect(apiMock.deleteProxyTestJob).toHaveBeenCalledWith('job-42');
    } finally {
      root?.unmount();
    }
  });
});
