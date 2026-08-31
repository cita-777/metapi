import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, create } from 'react-test-renderer';
import { useEffect } from 'react';
import { ToastProvider, useToast } from './Toast.js';

afterEach(() => {
  vi.useRealTimers();
});
describe('ToastProvider accessibility and lifecycle', () => {
  it('keeps the public useToast API and exposes live status semantics', async () => {
    function EffectEmitter() {
      const toast = useToast();
      useEffect(() => {
        toast.success('保存成功');
      }, [toast]);
      return null;
    }

    let root!: WebTestRenderer;
    await act(async () => {
      root = create(
        <ToastProvider>
          <EffectEmitter />
        </ToastProvider>,
      );
    });

    const region = root.root.find((node) => node.props.role === 'region');
    expect(region.props['aria-live']).toBe('polite');
    const status = root.root.find((node) => node.props.role === 'status');
    expect(status.props['aria-live']).toBe('polite');
    expect(status.props['aria-label']).toBe('保存成功');
    root.unmount();
  });

  it('cleans auto-dismiss and exit timers when the provider unmounts', async () => {
    vi.useFakeTimers();
    let root!: WebTestRenderer;

    function Emitter() {
      const toast = useToast();
      useEffect(() => {
        toast.info('稍后刷新');
      }, [toast]);
      return null;
    }

    await act(async () => {
      root = create(
        <ToastProvider>
          <Emitter />
        </ToastProvider>,
      );
    });
    expect(vi.getTimerCount()).toBeGreaterThan(0);

    await act(async () => {
      root.unmount();
    });
    expect(vi.getTimerCount()).toBe(0);
  });
});
