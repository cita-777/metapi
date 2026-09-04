import { useEffect, useState } from 'react';

export function useAnimatedVisibility(
  visible: boolean,
  durationMs = 220,
  manageLifecycle = true,
) {
  const [shouldRender, setShouldRender] = useState(visible);
  const [isVisible, setIsVisible] = useState(visible);

  useEffect(() => {
    // A shared surface may receive an already-managed presence object from a
    // parent during an incremental migration. Keep the hook call unconditional
    // (React's rules of hooks) but do not schedule a second RAF/timer owner.
    if (!manageLifecycle) return undefined;
    if (visible) {
      setShouldRender(true);
      if (typeof window !== 'undefined' && typeof window.requestAnimationFrame === 'function') {
        const rafId = window.requestAnimationFrame(() => setIsVisible(true));
        return () => window.cancelAnimationFrame(rafId);
      }
      setIsVisible(true);
      return undefined;
    }

    setIsVisible(false);
    if (durationMs <= 0) {
      setShouldRender(false);
      return undefined;
    }

    const timerId = globalThis.setTimeout(() => setShouldRender(false), durationMs);
    return () => globalThis.clearTimeout(timerId);
  }, [durationMs, manageLifecycle, visible]);

  return { shouldRender, isVisible };
}
