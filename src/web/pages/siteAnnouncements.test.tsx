import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, create } from 'react-test-renderer';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { ToastProvider } from '../components/Toast.js';
import SiteAnnouncements from './SiteAnnouncements.js';
import { sidebarGroups } from '../App.js';

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    getSiteAnnouncements: vi.fn(),
    getSites: vi.fn(),
    getRuntimeSettings: vi.fn(),
    markSiteAnnouncementRead: vi.fn(),
    markAllSiteAnnouncementsRead: vi.fn(),
    clearSiteAnnouncements: vi.fn(),
    syncSiteAnnouncements: vi.fn(),
  },
}));

vi.mock('../api.js', () => ({
  api: apiMock,
}));

vi.mock('./helpers/siteAnnouncementPresentation.js', async () => {
  const actual = await vi.importActual<typeof import('./helpers/siteAnnouncementPresentation.js')>('./helpers/siteAnnouncementPresentation.js');
  return {
    ...actual,
    readClientTimeZone: () => 'Asia/Shanghai',
  };
});

async function flushMicrotasks() {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
  });
}

function collectText(node: any): string {
  const children = node?.children || [];
  return children.map((child: any) => {
    if (typeof child === 'string') return child;
    return collectText(child);
  }).join('');
}

describe('SiteAnnouncements page', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    apiMock.getSites.mockResolvedValue([
      { id: 9, name: 'Sub Site', platform: 'sub2api' },
    ]);
    apiMock.getRuntimeSettings.mockResolvedValue({
      serverTimeZone: 'UTC',
    });
    apiMock.getSiteAnnouncements.mockResolvedValue([
      {
        id: 12,
        siteId: 9,
        platform: 'sub2api',
        sourceKey: 'announcement:12',
        title: 'Maintenance',
        content: 'Window starts at 10:00',
        level: 'info',
        firstSeenAt: '2026-03-20 04:23:27',
        lastSeenAt: '2026-03-20 04:23:27',
        readAt: null,
      },
    ]);
    apiMock.clearSiteAnnouncements.mockResolvedValue({ success: true });
    apiMock.markAllSiteAnnouncementsRead.mockResolvedValue({ success: true });
    apiMock.syncSiteAnnouncements.mockResolvedValue({ success: true, queued: true, taskId: 'task-1' });
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('exposes the renamed sidebar item and the site announcements entry', () => {
    const consoleGroup = sidebarGroups.find((group) => group.label === '控制台');
    const labels = (consoleGroup?.items || []).map((item) => item.label);

    expect(labels).toContain('站点管理');
    expect(labels).toContain('站点公告');
  });

  it('loads announcements, highlights the focused row, and clears local rows', async () => {
    let root!: WebTestRenderer;
    try {
      await act(async () => {
        root = create(
          <ToastProvider>
            <MemoryRouter initialEntries={['/site-announcements?focusAnnouncementId=12']}>
              <Routes>
                <Route path="/site-announcements" element={<SiteAnnouncements />} />
              </Routes>
            </MemoryRouter>
          </ToastProvider>,
          {
            createNodeMock: (element) => {
              if (element.type === 'div') {
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

      expect(apiMock.getSiteAnnouncements).toHaveBeenCalled();
      expect(apiMock.getSites).toHaveBeenCalled();
      expect(apiMock.getRuntimeSettings).toHaveBeenCalled();
      expect(JSON.stringify(root!.toJSON())).toContain('站点公告');
      expect(JSON.stringify(root!.toJSON())).toContain('Maintenance');
      expect(JSON.stringify(root!.toJSON())).toContain('2026/03/20 12:23:27');

      const highlightedRows = root!.root.findAll((node) => {
        const className = typeof node.props.className === 'string' ? node.props.className : '';
        return className.includes('row-focus-highlight') && collectText(node).includes('Maintenance');
      });
      expect(highlightedRows).toHaveLength(1);

      const clearButton = root!.root.find((node) => (
        node.type === 'button'
        && typeof node.props.onClick === 'function'
        && collectText(node).includes('清空公告')
      ));

      await act(async () => {
        await clearButton.props.onClick();
      });
      await flushMicrotasks();

      expect(apiMock.clearSiteAnnouncements).toHaveBeenCalledTimes(1);
    } finally {
      root?.unmount();
    }
  });
});
