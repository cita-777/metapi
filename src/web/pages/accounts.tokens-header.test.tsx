import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, create, type ReactTestInstance } from 'react-test-renderer';
import { MemoryRouter } from 'react-router-dom';
import { ToastProvider } from '../components/Toast.js';
import Accounts from './Accounts.js';

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    getAccounts: vi.fn(),
    getSites: vi.fn(),
    getAccountTokens: vi.fn(),
  },
}));

vi.mock('../api.js', () => ({
  api: apiMock,
}));

function collectText(node: ReactTestInstance): string {
  const children = node.children || [];
  return children
    .map((child) => {
      if (typeof child === 'string') return child;
      return collectText(child);
    })
    .join('');
}

async function flushMicrotasks() {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
  });
}

describe('Accounts tokens embedded header', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('reuses the accounts page header when showing the 账号令牌 segment', async () => {
    apiMock.getAccounts.mockResolvedValue([
      {
        id: 1,
        username: 'session-user',
        accessToken: 'session-token',
        status: 'active',
        credentialMode: 'session',
        capabilities: { canCheckin: true, canRefreshBalance: true, proxyOnly: false },
        site: { id: 10, name: 'Session Site', platform: 'new-api', status: 'active', url: 'https://session.example.com' },
      },
    ]);
    apiMock.getSites.mockResolvedValue([
      { id: 10, name: 'Session Site', platform: 'new-api', status: 'active' },
    ]);
    apiMock.getAccountTokens.mockResolvedValue([]);

    let root!: WebTestRenderer;
    try {
      await act(async () => {
        root = create(
          <MemoryRouter initialEntries={['/accounts?segment=tokens']}>
            <ToastProvider>
              <Accounts />
            </ToastProvider>
          </MemoryRouter>,
        );
      });
      await flushMicrotasks();

      const pageHeaders = root.root.findAll((node) => {
        const className = node.props?.className;
        return typeof className === 'string' && className.split(/\s+/).includes('page-header');
      });
      expect(pageHeaders).toHaveLength(1);

      const buttonTexts = root.root
        .findAll((node) => node.type === 'button')
        .map((node) => collectText(node));
      expect(buttonTexts).toContain('同步站点令牌');
      expect(buttonTexts).toContain('同步全部账号');
      expect(buttonTexts).toContain('+ 新增令牌');
    } finally {
      root?.unmount();
    }
  });
});
