/** @vitest-environment jsdom */

import { act, StrictMode } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import ModelTester from './ModelTester.js';
import {
  DEBUG_TABS,
  DEFAULT_INPUTS,
  DEFAULT_MODE_STATE,
  DEFAULT_PARAMETER_ENABLED,
  MODEL_TESTER_STORAGE_KEY,
  serializeModelTesterSession,
  type ModelTesterSessionState,
} from './helpers/modelTesterSession.js';

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    getModelsMarketplace: vi.fn(),
    getRoutes: vi.fn(),
    getRouteDecision: vi.fn(),
    proxyTestStream: vi.fn(),
    getProxyTestJob: vi.fn(),
    deleteProxyTestJob: vi.fn(),
  },
}));

type ComposerMockProps = {
  input: string;
  onInputChange: (value: string) => void;
  onSend: () => void;
  onStop: () => void;
};

type SelectMockProps = {
  value: string;
  disabled?: boolean;
  onChange: (value: string) => void;
  options?: Array<{ value: string; label: string }>;
  'data-testid'?: string;
};

vi.mock('../api.js', () => ({ api: apiMock }));
vi.mock('../authSession.js', () => ({
  clearAuthSession: vi.fn(),
  getAuthToken: vi.fn(() => null),
}));
vi.mock('../components/useAnimatedVisibility.js', () => ({
  useAnimatedVisibility: () => ({ shouldRender: false, isVisible: false }),
}));
vi.mock('../components/useIsMobile.js', () => ({ useIsMobile: () => false }));
vi.mock('../i18n.js', () => ({ tr: (value: string) => value }));
vi.mock('./model-tester/DebugPanel.js', () => ({
  default: () => null,
}));
vi.mock('./model-tester/ConversationComposer.js', () => ({
  default: (props: ComposerMockProps) => (
    <div>
      <textarea
        data-testid="composer-input"
        value={props.input}
        onChange={(event) => props.onInputChange(event.target.value)}
      />
      <button type="button" data-testid="set-input" onClick={() => props.onInputChange('latest prompt')}>set input</button>
      <button type="button" data-testid="send" onClick={() => props.onSend()}>send</button>
      <button type="button" data-testid="stop" onClick={() => props.onStop()}>stop</button>
    </div>
  ),
}));
vi.mock('../components/ModernSelect.js', () => ({
  default: (props: SelectMockProps) => (
    <select
      data-testid={props['data-testid']}
      value={props.value}
      disabled={props.disabled}
      onChange={(event) => props.onChange(event.target.value)}
    >
      {(props.options || []).map((option: { value: string; label: string }) => (
        <option key={option.value} value={option.value}>{option.label}</option>
      ))}
    </select>
  ),
}));

const flushMicrotasks = async (rounds = 8) => {
  for (let index = 0; index < rounds; index += 1) {
    await Promise.resolve();
  }
};

const createStorage = (initial?: string) => {
  const values = new Map<string, string>();
  if (initial !== undefined) values.set(MODEL_TESTER_STORAGE_KEY, initial);
  return {
    values,
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => values.set(key, value),
    removeItem: (key: string) => values.delete(key),
  };
};

const createSession = (overrides: Partial<ModelTesterSessionState> = {}) => serializeModelTesterSession({
  input: '',
  inputs: { ...DEFAULT_INPUTS, model: 'gpt-test' },
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
  ...overrides,
});

async function renderTester(): Promise<{ root: Root; container: HTMLDivElement }> {
  const container = document.createElement('div');
  document.body.appendChild(container);
  const root = createRoot(container);
  await act(async () => {
    root.render(
      <StrictMode>
        <ModelTester />
      </StrictMode>,
    );
    await flushMicrotasks();
  });
  return { root, container };
}

describe('ModelTester lifecycle', () => {
  let storage: ReturnType<typeof createStorage>;

  beforeEach(() => {
    vi.clearAllMocks();
    apiMock.getModelsMarketplace.mockResolvedValue({ models: [{ name: 'gpt-test' }] });
    apiMock.getRoutes.mockResolvedValue([]);
    apiMock.getRouteDecision.mockResolvedValue({ decision: { candidates: [] } });
    apiMock.deleteProxyTestJob.mockResolvedValue({});
    storage = createStorage();
    vi.stubGlobal('localStorage', storage);
    (globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
  });

  afterEach(() => {
    vi.useRealTimers();
    document.body.innerHTML = '';
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('finishes model hydration when mounted under React StrictMode', async () => {
    let root: Root | undefined;
    try {
      const rendered = await renderTester();
      root = rendered.root;
      await act(async () => {
        await flushMicrotasks(12);
      });

      expect(rendered.container.querySelector('.skeleton')).toBeNull();
      expect(rendered.container.textContent).toContain('gpt-test');
      expect(apiMock.getModelsMarketplace.mock.calls.length).toBeGreaterThanOrEqual(2);
    } finally {
      if (root) {
        await act(async () => {
          root?.unmount();
        });
      }
    }
  });

  it('flushes the latest session snapshot during unmount', async () => {
    vi.useFakeTimers();
    let root: Root | undefined;
    try {
      const rendered = await renderTester();
      root = rendered.root;
      await act(async () => {
        await flushMicrotasks(12);
      });

      const input = rendered.container.querySelector<HTMLTextAreaElement>('[data-testid="composer-input"]');
      const setInputButton = rendered.container.querySelector<HTMLButtonElement>('[data-testid="set-input"]');
      expect(input).not.toBeNull();
      expect(setInputButton).not.toBeNull();
      await act(async () => {
        setInputButton!.click();
        await flushMicrotasks();
      });

      expect(storage.values.has(MODEL_TESTER_STORAGE_KEY)).toBe(false);
      await act(async () => {
        root?.unmount();
      });
      root = undefined;

      const persisted = JSON.parse(storage.values.get(MODEL_TESTER_STORAGE_KEY) || '{}') as Record<string, unknown>;
      expect(persisted.input).toBe('latest prompt');
    } finally {
      if (root) {
        await act(async () => {
          root?.unmount();
        });
      }
    }
  });

  it('does not recreate the session after clearChat followed by unmount', async () => {
    vi.useFakeTimers();
    let root: Root | undefined;
    storage = createStorage(createSession({
      messages: [{ id: 'msg-1', role: 'user', content: 'old', createAt: 1 }],
    }));
    vi.stubGlobal('localStorage', storage);

    try {
      const rendered = await renderTester();
      root = rendered.root;
      await act(async () => {
        await flushMicrotasks(12);
      });

      const clearButton = Array.from(rendered.container.querySelectorAll('button'))
        .find((button) => button.textContent?.trim() === '清除');
      expect(clearButton).toBeDefined();
      await act(async () => {
        clearButton!.click();
        await flushMicrotasks();
      });
      expect(storage.values.has(MODEL_TESTER_STORAGE_KEY)).toBe(false);

      await act(async () => {
        root?.unmount();
      });
      root = undefined;
      expect(storage.values.has(MODEL_TESTER_STORAGE_KEY)).toBe(false);
    } finally {
      if (root) {
        await act(async () => {
          root?.unmount();
        });
      }
    }
  });
});
