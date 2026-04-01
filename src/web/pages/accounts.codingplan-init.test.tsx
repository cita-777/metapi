import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, create, type ReactTestInstance, type ReactTestRenderer } from 'react-test-renderer';
import { MemoryRouter } from 'react-router-dom';
import { ToastProvider } from '../components/Toast.js';
import Accounts from './Accounts.js';

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    getAccounts: vi.fn(),
    getSites: vi.fn(),
    getAccountTokens: vi.fn(),
    addAccount: vi.fn(),
    addAccountAvailableModels: vi.fn(),
  },
}));

vi.mock('../api.js', () => ({
  api: apiMock,
}));

function collectText(node: ReactTestInstance): string {
  const children = node.children || [];
  return children.map((child) => {
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

describe('Accounts CodingPlan initialization', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    apiMock.getAccounts.mockResolvedValue([]);
    apiMock.getSites.mockResolvedValue([
      { id: 10, name: 'Aliyun CodingPlan', url: 'https://coding.dashscope.aliyuncs.com/v1', platform: 'openai', status: 'active' },
    ]);
    apiMock.getAccountTokens.mockResolvedValue([]);
    apiMock.addAccount.mockResolvedValue({
      id: 18,
      siteId: 10,
      tokenType: 'apikey',
      queued: false,
    });
    apiMock.addAccountAvailableModels.mockResolvedValue({ success: true });
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('preloads CodingPlan guidance, defaults skip-model-fetch, and seeds recommended models after add', async () => {
    let root!: ReactTestRenderer;
    try {
      await act(async () => {
        root = create(
          <MemoryRouter initialEntries={['/accounts?segment=apikey&create=1&siteId=10&initPreset=codingplan-openai']}>
            <ToastProvider>
              <Accounts />
            </ToastProvider>
          </MemoryRouter>,
        );
      });
      await flushMicrotasks();

      const rendered = JSON.stringify(root.toJSON());
      expect(rendered).toContain('添加 API Key 连接');
      expect(rendered).toContain('阿里云 CodingPlan / OpenAI');
      expect(rendered).toContain('qwen3-coder-plus');

      const checkedBoxes = root.root.findAll((node) => (
        node.type === 'input'
        && node.props.type === 'checkbox'
        && node.props.checked === true
      ));
      expect(checkedBoxes.length).toBeGreaterThanOrEqual(2);

      const tokenInput = root.root.find((node) => (
        node.type === 'textarea'
        && node.props.placeholder === '粘贴 API Key'
      ));
      const addButton = root.root.find((node) => (
        node.type === 'button'
        && typeof node.props.onClick === 'function'
        && collectText(node).includes('添加连接')
      ));

      await act(async () => {
        tokenInput.props.onChange({ target: { value: 'sk-codingplan-demo' } });
      });

      await act(async () => {
        await addButton.props.onClick();
      });
      await flushMicrotasks();

      expect(apiMock.addAccount).toHaveBeenCalledWith(expect.objectContaining({
        siteId: 10,
        accessToken: 'sk-codingplan-demo',
        credentialMode: 'apikey',
        skipModelFetch: true,
      }));
      expect(apiMock.addAccountAvailableModels).toHaveBeenCalledWith(
        18,
        expect.arrayContaining(['qwen3-coder-plus', 'qwen3.5-plus', 'glm-5']),
      );
    } finally {
      root?.unmount();
    }
  });

  it('preloads vendor-specific recommendations for new code presets such as DeepSeek', async () => {
    apiMock.getSites.mockResolvedValue([
      { id: 11, name: 'DeepSeek Official', url: 'https://api.deepseek.com/v1', platform: 'openai', status: 'active' },
    ]);
    apiMock.addAccount.mockResolvedValue({
      id: 19,
      siteId: 11,
      tokenType: 'apikey',
      queued: false,
    });

    let root!: ReactTestRenderer;
    try {
      await act(async () => {
        root = create(
          <MemoryRouter initialEntries={['/accounts?segment=apikey&create=1&siteId=11&initPreset=deepseek-openai']}>
            <ToastProvider>
              <Accounts />
            </ToastProvider>
          </MemoryRouter>,
        );
      });
      await flushMicrotasks();

      const rendered = JSON.stringify(root.toJSON());
      expect(rendered).toContain('DeepSeek / OpenAI');
      expect(rendered).toContain('deepseek-chat');
      expect(rendered).toContain('deepseek-reasoner');

      const tokenInput = root.root.find((node) => (
        node.type === 'textarea'
        && node.props.placeholder === '粘贴 API Key'
      ));
      const addButton = root.root.find((node) => (
        node.type === 'button'
        && typeof node.props.onClick === 'function'
        && collectText(node).includes('添加连接')
      ));

      await act(async () => {
        tokenInput.props.onChange({ target: { value: 'sk-deepseek-demo' } });
      });

      await act(async () => {
        await addButton.props.onClick();
      });
      await flushMicrotasks();

      expect(apiMock.addAccount).toHaveBeenCalledWith(expect.objectContaining({
        siteId: 11,
        accessToken: 'sk-deepseek-demo',
        credentialMode: 'apikey',
        skipModelFetch: true,
      }));
      expect(apiMock.addAccountAvailableModels).toHaveBeenCalledWith(
        19,
        ['deepseek-chat', 'deepseek-reasoner'],
      );
    } finally {
      root?.unmount();
    }
  });
});
