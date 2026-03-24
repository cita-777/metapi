import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, create, type ReactTestInstance } from 'react-test-renderer';
import { MemoryRouter } from 'react-router-dom';
import { ToastProvider } from '../components/Toast.js';
import ProgramLogs from './ProgramLogs.js';

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    getEvents: vi.fn(),
    markEventRead: vi.fn(),
    markAllEventsRead: vi.fn(),
    clearEvents: vi.fn(),
  },
}));

vi.mock('../api.js', () => ({
  api: apiMock,
}));

vi.mock('../components/useIsMobile.js', () => ({
  useIsMobile: () => true,
}));

function collectText(node: ReactTestInstance): string {
  const children = node.children || [];
  return children.map((child) => {
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

describe('ProgramLogs mobile layout', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    apiMock.getEvents.mockResolvedValue([
      {
        id: 1,
        type: 'status',
        title: '同步完成',
        message: '成功 3，失败 0',
        level: 'info',
        read: false,
        createdAt: '2026-03-04T06:43:03.000Z',
      },
    ]);
    apiMock.markEventRead.mockResolvedValue({ success: true });
    apiMock.markAllEventsRead.mockResolvedValue({ success: true });
    apiMock.clearEvents.mockResolvedValue({ success: true });
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('renders mobile cards instead of only the desktop table on small screens', async () => {
    let root!: WebTestRenderer;

    try {
      await act(async () => {
        root = create(
          <MemoryRouter initialEntries={['/events']}>
            <ToastProvider>
              <ProgramLogs />
            </ToastProvider>
          </MemoryRouter>,
        );
      });
      await flushMicrotasks();

      const cards = root!.root.findAll((node) => node.props?.className === 'mobile-card');
      expect(cards.length).toBeGreaterThan(0);
      expect(collectText(root!.root)).toContain('同步完成');
      expect(collectText(root!.root)).toContain('筛选');
      expect(collectText(root!.root)).toContain('标记已读');

      const markReadButton = findButtonByText(root!.root, '标记已读');
      await act(async () => {
        markReadButton.props.onClick();
      });
      await flushMicrotasks();

      expect(apiMock.markEventRead).toHaveBeenCalledWith(1);
    } finally {
      root?.unmount();
    }
  });
});
