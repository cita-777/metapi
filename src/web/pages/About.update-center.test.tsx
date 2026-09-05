import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, create, type ReactTestInstance, type ReactTestRenderer } from 'react-test-renderer';
import { MemoryRouter } from 'react-router-dom';

import About from './About.js';

const { apiMock } = vi.hoisted(() => ({
  apiMock: { getUpdateCenterStatus: vi.fn() },
}));

vi.mock('../api.js', () => ({ api: apiMock }));

function collectText(node: ReactTestInstance): string {
  return (node.children || []).map((child) => typeof child === 'string' ? child : collectText(child)).join('');
}

describe('About update center', () => {
  beforeEach(() => {
    apiMock.getUpdateCenterStatus.mockResolvedValue({
      currentVersion: '1.2.3',
      latestRelease: {
        normalizedVersion: '1.3.0',
        displayVersion: '1.3.0',
        tagName: 'v1.3.0',
        publishedAt: '2026-09-04T00:00:00Z',
        assets: [],
      },
    });
  });
  afterEach(() => vi.clearAllMocks());

  it('shows the current version and the latest official release', async () => {
    let root!: ReactTestRenderer;
    try {
      await act(async () => {
        root = create(<MemoryRouter><About /></MemoryRouter>);
      });
      await act(async () => { await Promise.resolve(); await Promise.resolve(); });
      const text = collectText(root.root);
      expect(text).toContain('v1.2.3');
      expect(text).toContain('官方稳定版');
      expect(text).toContain('1.3.0');
      expect(text).toContain('发现新版本');
      expect(text).toContain('前往更新中心');
    } finally {
      root?.unmount();
    }
  });
});
