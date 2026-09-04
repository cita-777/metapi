/** @vitest-environment jsdom */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { StrictMode, act, useEffect } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { ToastProvider, useToast } from './Toast.js';

describe('ToastProvider StrictMode lifecycle', () => {
  let host: HTMLDivElement | null = null;
  let root: Root | null = null;
  const previousActEnvironment = (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT;

  beforeEach(() => {
    (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
    vi.useFakeTimers();
    host = document.createElement('div');
    document.body.appendChild(host);
    root = createRoot(host);
  });

  afterEach(async () => {
    if (root) {
      await act(async () => {
        root?.unmount();
      });
    }
    host?.remove();
    root = null;
    host = null;
    vi.useRealTimers();
    (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = previousActEnvironment;
  });

  it('re-arms a retained toast after StrictMode replays provider effects', async () => {
    let emitted = false;

    function FirstUseReminder() {
      const toast = useToast();
      useEffect(() => {
        if (emitted) return;
        emitted = true;
        toast.info('首次使用提醒');
      }, [toast]);
      return null;
    }

    await act(async () => {
      root?.render(
        <StrictMode>
          <ToastProvider>
            <FirstUseReminder />
          </ToastProvider>
        </StrictMode>,
      );
    });

    expect(document.querySelectorAll('[role="status"]')).toHaveLength(1);
    expect(vi.getTimerCount()).toBeGreaterThan(0);

    await act(async () => {
      vi.advanceTimersByTime(3200);
    });
    await act(async () => {
      vi.advanceTimersByTime(250);
    });

    expect(document.querySelector('[role="status"]')).toBeNull();
  });
});
