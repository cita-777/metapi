import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, create, type ReactTestInstance } from 'react-test-renderer';
import { MemoryRouter } from 'react-router-dom';
import { ToastProvider } from '../components/Toast.js';
import ModernSelect from '../components/ModernSelect.js';
import Accounts from './Accounts.js';
import {
  buildAddAccountPrereqHint,
  buildVerifyFailureHint,
  normalizeVerifyFailureMessage,
} from './helpers/accountVerifyFeedback.js';

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    getAccounts: vi.fn(),
    getSites: vi.fn(),
    verifyToken: vi.fn(),
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

describe('Accounts verify feedback', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('shows connectivity guidance instead of blaming the token when verification request fails', async () => {
    apiMock.getAccounts.mockResolvedValue([]);
    apiMock.getSites.mockResolvedValue([
      { id: 10, name: 'Demo Site', platform: 'new-api', status: 'active' },
    ]);
    apiMock.verifyToken.mockRejectedValueOnce(new Error('Failed to fetch'));

    let root!: WebTestRenderer;
    try {
      await act(async () => {
        root = create(
          <MemoryRouter initialEntries={['/accounts']}>
            <ToastProvider>
              <Accounts />
            </ToastProvider>
          </MemoryRouter>,
        );
      });
      await flushMicrotasks();

      const addButton = root.root.find((node) => (
        node.type === 'button'
        && typeof node.props.onClick === 'function'
        && typeof node.props.className === 'string'
        && node.props.className.includes('btn btn-primary')
      ));

      await act(async () => {
        addButton.props.onClick();
      });
      await flushMicrotasks();

      const selects = root.root.findAllByType(ModernSelect);
      expect(selects.length).toBeGreaterThan(1);

      await act(async () => {
        selects[1]!.props.onChange('10');
      });

      const textareas = root.root.findAll((node) => node.type === 'textarea');
      expect(textareas.length).toBeGreaterThan(0);

      await act(async () => {
        textareas[0]!.props.onChange({ target: { value: 'demo-token' } });
      });

      const verifyButton = root.root.find((node) => (
        node.type === 'button'
        && typeof node.props.onClick === 'function'
        && typeof node.props.className === 'string'
        && node.props.className.includes('btn btn-ghost')
        && collectText(node).includes('Token')
      ));

      await act(async () => {
        await verifyButton.props.onClick();
      });
      await flushMicrotasks();

      const rendered = JSON.stringify(root.toJSON());
      expect(rendered).toContain(normalizeVerifyFailureMessage('Failed to fetch'));
      expect(rendered).toContain(buildVerifyFailureHint({ success: false, message: 'Failed to fetch' })!);
      expect(rendered).toContain(buildAddAccountPrereqHint({ success: false, message: 'Failed to fetch' }));
      expect(rendered).not.toContain('请检查 Token 是否正确');
    } finally {
      root?.unmount();
    }
  });
});
