import { describe, expect, it, vi } from 'vitest';
import {
  attachDesktopNavigationGuard,
  resolveDesktopNavigationAction,
  type DesktopWebContentsLike,
  type DesktopWillNavigateEvent,
  type DesktopWindowOpenDetails,
} from './navigationGuard.js';

function createWebContentsHarness() {
  let openHandler: ((details: DesktopWindowOpenDetails) => { action: 'allow' | 'deny' }) | null = null;
  let navigateHandler: ((event: DesktopWillNavigateEvent, url: string) => void) | null = null;

  const webContents: DesktopWebContentsLike = {
    setWindowOpenHandler: (handler) => {
      openHandler = handler;
    },
    on: (event, listener) => {
      if (event === 'will-navigate') {
        navigateHandler = listener;
      }
    },
  };

  return {
    webContents,
    getOpenHandler() {
      if (!openHandler) throw new Error('window open handler not registered');
      return openHandler;
    },
    getNavigateHandler() {
      if (!navigateHandler) throw new Error('will-navigate handler not registered');
      return navigateHandler;
    },
  };
}

describe('desktop navigation guard', () => {
  const appUrl = 'http://127.0.0.1:5173/dashboard';

  it('routes cross-origin popup links to the default browser', () => {
    expect(resolveDesktopNavigationAction('https://github.com/cita-777/metapi', appUrl)).toBe('deny');
  });

  it('keeps same-origin popup links inside the desktop app', () => {
    expect(resolveDesktopNavigationAction('/monitor-proxy/ldoh/', appUrl)).toBe('allow');
    expect(resolveDesktopNavigationAction('about:blank', appUrl)).toBe('allow');
  });

  it('opens cross-origin window.open targets externally and denies the popup', () => {
    const openExternal = vi.fn();
    const harness = createWebContentsHarness();

    attachDesktopNavigationGuard({
      appUrl,
      openExternal,
      webContents: harness.webContents,
    });

    const result = harness.getOpenHandler()({
      url: 'https://metapi.cita777.me',
    });

    expect(result).toEqual({ action: 'deny' });
    expect(openExternal).toHaveBeenCalledWith('https://metapi.cita777.me');
  });

  it('prevents same-window cross-origin navigations and opens them externally', () => {
    const openExternal = vi.fn();
    const preventDefault = vi.fn();
    const harness = createWebContentsHarness();

    attachDesktopNavigationGuard({
      appUrl,
      openExternal,
      webContents: harness.webContents,
    });

    harness.getNavigateHandler()({ preventDefault }, 'https://example.com/docs');

    expect(preventDefault).toHaveBeenCalledTimes(1);
    expect(openExternal).toHaveBeenCalledWith('https://example.com/docs');
  });

  it('does not block same-origin navigations', () => {
    const openExternal = vi.fn();
    const preventDefault = vi.fn();
    const harness = createWebContentsHarness();

    attachDesktopNavigationGuard({
      appUrl,
      openExternal,
      webContents: harness.webContents,
    });

    harness.getNavigateHandler()({ preventDefault }, 'http://127.0.0.1:5173/monitor-proxy/ldoh/');

    expect(preventDefault).not.toHaveBeenCalled();
    expect(openExternal).not.toHaveBeenCalled();
  });
});
