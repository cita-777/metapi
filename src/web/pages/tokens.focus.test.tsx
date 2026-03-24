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

describe('Tokens focus navigation', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('highlights the focused token row in the 账号令牌 segment', async () => {
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
    apiMock.getAccountTokens.mockResolvedValue([
      {
        id: 22,
        name: 'focus-token',
        tokenMasked: 'sk-focus****',
        enabled: true,
        isDefault: false,
        updatedAt: '2026-03-07 10:00:00',
        accountId: 1,
        account: { username: 'session-user' },
        site: { name: 'Session Site', url: 'https://session.example.com' },
      },
    ]);

    let root!: WebTestRenderer;
    try {
      await act(async () => {
        root = create(
          <MemoryRouter initialEntries={['/accounts?segment=tokens&focusTokenId=22']}>
            <ToastProvider>
              <Accounts />
            </ToastProvider>
          </MemoryRouter>,
          {
            createNodeMock: (element) => {
              if (element.type === 'tr') {
                return {
                  scrollIntoView: () => undefined,
                };
              }
              return {};
            },
          },
        );
      });
      await flushMicrotasks();

      const highlightedRow = root.root.findAll((node) => {
        if (node.type !== 'tr') return false;
        const className = typeof node.props?.className === 'string' ? node.props.className : '';
        return className.includes('row-focus-highlight') && collectText(node).includes('focus-token');
      });
      expect(highlightedRow).toHaveLength(1);
    } finally {
      root?.unmount();
    }
  });
});
