import { useEffect, useState } from 'react';
import { MOBILE_BREAKPOINT, MOBILE_MEDIA_QUERY } from './mobileLayout.js';

export function useIsMobile(breakpoint = MOBILE_BREAKPOINT) {
  const [isMobile, setIsMobile] = useState(() => (
    typeof window !== 'undefined' ? window.innerWidth <= breakpoint : false
  ));

  useEffect(() => {
    // Capture the host object for the complete effect lifetime. Embedded
    // shells and tests may replace globalThis.window while the component is
    // still mounted; cleanup must detach from the same object that received
    // the listener instead of reading a possibly missing global later.
    const hostWindow = typeof window === 'undefined' ? null : window;
    if (!hostWindow) return;
    const query = breakpoint === MOBILE_BREAKPOINT
      ? MOBILE_MEDIA_QUERY
      : `(max-width: ${breakpoint}px)`;
    const media = typeof hostWindow.matchMedia === 'function' ? hostWindow.matchMedia(query) : null;
    const update = () => setIsMobile(media ? media.matches : hostWindow.innerWidth <= breakpoint);
    update();

    if (media && typeof media.addEventListener === 'function') {
      media.addEventListener('change', update);
      return () => {
        if (typeof media.removeEventListener === 'function') {
          media.removeEventListener('change', update);
        }
      };
    }

    const addResizeListener = typeof hostWindow.addEventListener === 'function';
    const removeResizeListener = typeof hostWindow.removeEventListener === 'function';
    if (!addResizeListener) return;

    hostWindow.addEventListener('resize', update);
    return () => {
      if (removeResizeListener) {
        hostWindow.removeEventListener('resize', update);
      }
    };
  }, [breakpoint]);

  return isMobile;
}
