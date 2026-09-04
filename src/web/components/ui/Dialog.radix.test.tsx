/** @vitest-environment jsdom */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { Dialog, Drawer } from './Dialog.js';
import { getBodyScrollLockCount } from './lifecycle.js';

describe('Radix browser renderer', () => {
  let host: HTMLDivElement;
  let root: Root;
  const previousActEnvironment = (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT;
  const previousForceRadix = (globalThis as { __METAPI_FORCE_RADIX_RENDERER__?: boolean }).__METAPI_FORCE_RADIX_RENDERER__;

  beforeEach(() => {
    (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
    (globalThis as { __METAPI_FORCE_RADIX_RENDERER__?: boolean }).__METAPI_FORCE_RADIX_RENDERER__ = true;
    host = document.createElement('div');
    document.body.appendChild(host);
    root = createRoot(host);
  });

  afterEach(async () => {
    await act(async () => {
      root.unmount();
    });
    host.remove();
    (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = previousActEnvironment;
    (globalThis as { __METAPI_FORCE_RADIX_RENDERER__?: boolean }).__METAPI_FORCE_RADIX_RENDERER__ = previousForceRadix;
  });

  it('mounts an accessible dialog into the body portal and closes from the backdrop once', async () => {
    const onClose = vi.fn();
    await act(async () => {
      root.render(
        <Dialog open onClose={onClose} title="浏览器对话框" closeOnBackdrop>
          <div>内容</div>
        </Dialog>,
      );
    });

    const panel = document.body.querySelector('[data-ui-surface="dialog"]');
    expect(panel).toBeTruthy();
    expect(panel?.getAttribute('role')).toBe('dialog');
    // Radix's browser RemoveScroll is the sole browser lock owner; the
    // project reference-counted fallback must not be acquired a second time.
    expect(getBodyScrollLockCount()).toBe(0);
    const backdrop = document.body.querySelector('.modal-backdrop') as HTMLElement;
    await act(async () => {
      backdrop.click();
    });
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('moves initial focus into a dialog when it opens', async () => {
    await act(async () => {
      root.render(
        <Dialog open onClose={() => {}} title="聚焦对话框" showCloseButton={false}>
          <button type="button">首个操作</button>
        </Dialog>,
      );
    });

    const firstAction = document.body.querySelector('[data-ui-surface="dialog"] button');
    expect(document.activeElement).toBe(firstAction);
  });

  it('restores the document scroll state after the browser surface unmounts', async () => {
    document.body.style.overflow = 'scroll';
    await act(async () => {
      root.render(
        <Dialog open onClose={() => {}} title="滚动清理">
          <div>内容</div>
        </Dialog>,
      );
    });
    await act(async () => {
      root.render(null);
    });
    expect(document.body.style.overflow).toBe('scroll');
    expect(getBodyScrollLockCount()).toBe(0);
  });

  it('uses the same Radix lifecycle for a right-side drawer', async () => {
    await act(async () => {
      root.render(
        <Drawer open onClose={() => {}} title="浏览器抽屉" side="right">
          <div>内容</div>
        </Drawer>,
      );
    });
    const panel = document.body.querySelector('[data-ui-surface="drawer"]');
    expect(panel?.className).toContain('mobile-drawer-panel-right');
    expect(document.body.querySelector('.mobile-drawer-backdrop')).toBeTruthy();
  });

  it('moves initial focus into a drawer when it opens', async () => {
    await act(async () => {
      root.render(
        <Drawer open onClose={() => {}} title="聚焦抽屉" showCloseButton={false}>
          <button type="button">首个操作</button>
        </Drawer>,
      );
    });

    const firstAction = document.body.querySelector('[data-ui-surface="drawer"] button');
    expect(document.activeElement).toBe(firstAction);
  });

  it('honors the explicit Escape policy in the Radix path', async () => {
    const onClose = vi.fn();
    await act(async () => {
      root.render(
        <Dialog open onClose={onClose} title="禁用 Escape" closeOnEscape={false}>
          <div>内容</div>
        </Dialog>,
      );
    });
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
    expect(onClose).not.toHaveBeenCalled();
  });

  it('closes a backdrop gesture exactly once when pointerdown precedes click', async () => {
    const onClose = vi.fn();
    await act(async () => {
      root.render(
        <Drawer open onClose={onClose} title="单次关闭" closeOnBackdrop closeOnEscape>
          <div>内容</div>
        </Drawer>,
      );
    });

    const backdrop = document.body.querySelector('.mobile-drawer-backdrop') as HTMLElement;
    expect(backdrop).toBeTruthy();

    // Radix's DismissableLayer observes pointerdown on the document before
    // the browser dispatches the matching click. The facade must keep that
    // gesture from invoking the close callback twice.
    backdrop.dispatchEvent(new MouseEvent('pointerdown', {
      bubbles: true,
      cancelable: true,
      button: 0,
    }));
    await act(async () => {
      backdrop.click();
    });
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});
