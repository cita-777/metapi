import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { act, create } from 'react-test-renderer';
import { useIsMobile } from './useIsMobile.js';

function Probe() {
  return <div data-mobile={String(useIsMobile())} />;
}

describe('useIsMobile', () => {
  const widthRef = { current: 768 };
  const listeners = new Map<string, Set<() => void>>();

  beforeEach(() => {
    widthRef.current = 768;
    listeners.clear();
    vi.stubGlobal('window', {
      innerWidth: widthRef.current,
      addEventListener: (event: string, handler: () => void) => {
        if (!listeners.has(event)) listeners.set(event, new Set());
        listeners.get(event)!.add(handler);
      },
      removeEventListener: (event: string, handler: () => void) => {
        listeners.get(event)?.delete(handler);
      },
      dispatchEvent: (event: Event) => {
        listeners.get(event.type)?.forEach((handler) => handler());
        return true;
      },
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it('does not throw when a partial window mock lacks resize listener APIs', async () => {
    vi.stubGlobal('window', {
      innerWidth: 767,
    });

    let root!: WebTestRenderer;

    try {
      await act(async () => {
        root = create(<Probe />);
      });

      expect(root.root.findByType('div').props['data-mobile']).toBe('true');
    } finally {
      if (root) {
        await act(async () => {
          root.unmount();
        });
      }
    }
  });

  it('does not throw when matchMedia only exposes addEventListener', async () => {
    vi.stubGlobal('window', {
      innerWidth: 767,
      matchMedia: () => ({
        matches: true,
        media: '(max-width: 768px)',
        addEventListener: () => {},
      }),
    });

    let root!: WebTestRenderer;

    try {
      await act(async () => {
        root = create(<Probe />);
      });

      expect(root.root.findByType('div').props['data-mobile']).toBe('true');
    } finally {
      if (root) {
        await act(async () => {
          root.unmount();
        });
      }
    }
  });

  it('treats 767 and 768 as mobile, but 769 as desktop', async () => {
    let root!: WebTestRenderer;

    try {
      await act(async () => {
        root = create(<Probe />);
      });

      const probe = root.root.findByType('div');
      expect(probe.props['data-mobile']).toBe('true');

      widthRef.current = 767;
      window.innerWidth = 767;
      await act(async () => {
        window.dispatchEvent(new Event('resize'));
      });

      expect(root.root.findByType('div').props['data-mobile']).toBe('true');

      widthRef.current = 768;
      window.innerWidth = 768;
      await act(async () => {
        window.dispatchEvent(new Event('resize'));
      });

      expect(root.root.findByType('div').props['data-mobile']).toBe('true');

      widthRef.current = 769;
      window.innerWidth = 769;
      await act(async () => {
        window.dispatchEvent(new Event('resize'));
      });

      expect(root.root.findByType('div').props['data-mobile']).toBe('false');
    } finally {
      if (root) {
        await act(async () => {
          root.unmount();
        });
      }
    }
  });
});
