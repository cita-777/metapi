import { describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, create } from 'react-test-renderer';
import MobileDrawer from './MobileDrawer.js';

vi.mock('react-dom', () => ({
  createPortal: (node: unknown) => node,
}));

describe('MobileDrawer', () => {
  it('renders content, locks body scroll, and exposes explicit close affordances', async () => {
    const onClose = vi.fn();
    let root!: WebTestRenderer;
    vi.stubGlobal('document', {
      body: {
        style: {
          overflow: '',
        },
      },
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
    });

    try {
      await act(async () => {
        root = create(
          <MobileDrawer open onClose={onClose} title="导航菜单">
            <div>DrawerContent</div>
          </MobileDrawer>,
        );
      });

      const text = root.root.findAll(() => true)
        .flatMap((instance) => instance.children)
        .filter((child): child is string => typeof child === 'string')
        .join('');

      expect(text).toContain('DrawerContent');
      expect(text).toContain('导航菜单');
      expect(document.body.style.overflow).toBe('hidden');

      const backdrop = root.root.find((node) => node.props.className === 'mobile-drawer-backdrop');
      expect(backdrop.type).toBe('div');

      const closeButton = root.root.find((node) => (
        node.type === 'button'
        && node.props.className === 'mobile-drawer-close'
      ));
      await act(async () => {
        closeButton.props.onClick();
      });

      expect(onClose).toHaveBeenCalledTimes(1);
    } finally {
      if (root) {
        await act(async () => {
          root.unmount();
        });
      }
      expect(document.body.style.overflow).toBe('');
      vi.unstubAllGlobals();
    }
  });

  it('defines independent right-side drawer animations in shared css', () => {
    const css = readFileSync(resolve(process.cwd(), 'src/web/index.css'), 'utf8').replace(/\r\n/g, '\n');

    expect(css).toContain('@keyframes drawer-slide-in-right');
    expect(css).toContain('@keyframes drawer-slide-out-right');
    expect(css).toMatch(/\.mobile-drawer-panel-right\s*\{[\s\S]*animation:\s*drawer-slide-in-right/);
    expect(css).toMatch(/\.mobile-drawer-root\.is-closing \.mobile-drawer-panel-right\s*\{[\s\S]*animation:\s*drawer-slide-out-right/);
  });
});
