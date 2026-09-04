import { useEffect, useLayoutEffect, useRef, type ReactNode } from 'react';
import { createPortal } from 'react-dom';

/**
 * The web app has a number of independently mounted overlays.  Keeping the
 * lock in this module (instead of in each overlay) means closing one overlay
 * cannot accidentally re-enable page scrolling while another one is open.
 */
type BodyLockState = {
  body: HTMLElement;
  count: number;
  previousOverflow: string;
};

let bodyLockState: BodyLockState | null = null;

function getDocument(): Document | null {
  return typeof document === 'undefined' ? null : document;
}

function isTestRuntime(): boolean {
  const processLike = (globalThis as {
    process?: { env?: Record<string, string | undefined> };
  }).process;
  return processLike?.env?.NODE_ENV === 'test';
}

function getBody(): HTMLElement | null {
  const body = getDocument()?.body;
  if (!body || !body.style) return null;
  return body;
}

/** Return the current portal target when the browser exposes a usable body. */
export function getPortalTarget(): HTMLElement | null {
  const body = getBody();
  if (!body) return null;

  // ReactDOM.createPortal validates these methods.  Test renderers often
  // provide a small document stub, so gracefully use the inline fallback in
  // that environment instead of throwing while rendering an overlay.
  if (
    typeof body.appendChild !== 'function'
    || typeof body.removeChild !== 'function'
  ) {
    return null;
  }

  return body;
}

/**
 * Render a node in document.body when possible, otherwise keep it in the
 * current React tree.  The fallback is useful for SSR and react-test-renderer
 * and also keeps a broken document stub from crashing the whole page.
 */
export function renderInPortal(node: ReactNode): ReactNode {
  // React test renderer cannot reconcile a ReactDOM portal even when a jsdom
  // document is present. Keep tests deterministic and exercise the same
  // inline fallback used by SSR; browser builds still portal to body.
  if (isTestRuntime()) return node;
  const target = getPortalTarget();
  if (!target) return node;

  try {
    return createPortal(node, target);
  } catch {
    return node;
  }
}

/** Acquire one reference-counted body-scroll lock. */
export function acquireBodyScrollLock(): () => void {
  const body = getBody();
  if (!body) return () => undefined;

  if (bodyLockState && bodyLockState.body === body) {
    bodyLockState.count += 1;
    body.style.overflow = 'hidden';
  } else {
    // A document can be replaced by a host shell (or by a test) while an
    // overlay is mounted. Restore the old body before switching ownership.
    if (bodyLockState) {
      bodyLockState.body.style.overflow = bodyLockState.previousOverflow;
    }
    bodyLockState = {
      body,
      count: 1,
      previousOverflow: body.style.overflow || '',
    };
    body.style.overflow = 'hidden';
  }

  let released = false;
  return () => {
    if (released) return;
    released = true;

    if (!bodyLockState || bodyLockState.body !== body) return;
    bodyLockState.count -= 1;
    if (bodyLockState.count > 0) return;

    body.style.overflow = bodyLockState.previousOverflow;
    bodyLockState = null;
  };
}

/** React hook wrapper for the shared body lock. */
export function useBodyScrollLock(active: boolean): void {
  useEffect(() => {
    if (!active) return undefined;
    return acquireBodyScrollLock();
  }, [active]);
}

type FocusTarget = HTMLElement & {
  isConnected?: boolean;
};

function isFocusableTarget(value: Element | null): value is FocusTarget {
  if (!value || typeof (value as FocusTarget).focus !== 'function') return false;
  // Older test doubles do not expose isConnected. In that case a focus call
  // is still the safest best effort and mirrors browser behavior.
  return (value as FocusTarget).isConnected !== false;
}

function focusWithoutScroll(target: FocusTarget): void {
  try {
    target.focus({ preventScroll: true });
  } catch {
    // Some narrow DOM/test doubles only implement focus() without options.
    try {
      target.focus();
    } catch {
      // Focus restoration is an enhancement; never make closing an overlay
      // fail because a host document has a partial focus implementation.
    }
  }
}

// Capture the trigger before Radix (or a browser) moves focus into the panel.
const useSafeLayoutEffect = typeof window !== 'undefined' ? useLayoutEffect : useEffect;

/**
 * Remember the element that was focused when an overlay opened and return
 * focus to it after close. The cleanup path also handles an unmount while the
 * overlay is still open.
 */
export function useFocusReturn(active: boolean, fallback?: FocusTarget | null): void {
  const triggerRef = useRef<FocusTarget | null>(null);
  const wasActiveRef = useRef(false);

  useSafeLayoutEffect(() => {
    const doc = getDocument();

    if (active) {
      if (!wasActiveRef.current && doc && isFocusableTarget(doc.activeElement)) {
        // Do not remember body itself as a trigger. Returning focus to body is
        // both noisy for keyboard users and less useful than the supplied
        // fallback (typically the close button or page heading).
        triggerRef.current = doc.activeElement === doc.body
          ? (fallback ?? null)
          : doc.activeElement;
      }
      wasActiveRef.current = true;
      return undefined;
    }

    if (!wasActiveRef.current) return undefined;
    wasActiveRef.current = false;
    const remembered = triggerRef.current;
    const target = remembered && isFocusableTarget(remembered)
      ? remembered
      : (fallback ?? null);
    triggerRef.current = null;
    if (target && isFocusableTarget(target)) {
      // Queue after the close state has committed, so a parent that removes
      // the trigger and re-adds it in the same tick gets the final node.
      const timer = globalThis.setTimeout(() => focusWithoutScroll(target), 0);
      return () => globalThis.clearTimeout(timer);
    }
    return undefined;
  }, [active, fallback]);

  useEffect(() => () => {
    if (!wasActiveRef.current) return;
    wasActiveRef.current = false;
    const remembered = triggerRef.current;
    const target = remembered && isFocusableTarget(remembered)
      ? remembered
      : (fallback ?? null);
    triggerRef.current = null;
    if (target && isFocusableTarget(target)) focusWithoutScroll(target);
  }, [fallback]);
}

type EscapeRegistration = {
  token: symbol;
  callbackRef: { current: (event: KeyboardEvent) => void };
};

// Only the top-most overlay handles Escape. This matters for a drawer opened
// over a dialog and avoids closing two surfaces from one key press.
const escapeStack: EscapeRegistration[] = [];

/** Register a top-most Escape handler with complete listener cleanup. */
export function useEscapeKey(active: boolean, onEscape: (event: KeyboardEvent) => void): void {
  const callbackRef = useRef(onEscape);
  callbackRef.current = onEscape;
  const tokenRef = useRef<symbol | undefined>(undefined);
  if (!tokenRef.current) tokenRef.current = Symbol('overlay-escape');

  useEffect(() => {
    const doc = getDocument();
    if (!active || !doc || typeof doc.addEventListener !== 'function') return undefined;

    const registration: EscapeRegistration = {
      token: tokenRef.current as symbol,
      callbackRef,
    };
    escapeStack.push(registration);

    const handleKeydown = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return;
      const top = escapeStack[escapeStack.length - 1];
      if (!top || top.token !== registration.token) return;
      top.callbackRef.current(event);
    };

    doc.addEventListener('keydown', handleKeydown);
    return () => {
      doc.removeEventListener('keydown', handleKeydown);
      const index = escapeStack.findIndex((item) => item.token === registration.token);
      if (index >= 0) escapeStack.splice(index, 1);
    };
  }, [active, callbackRef, tokenRef]);
}

/** Exposed only for focused tests and diagnostics; production code uses the hook. */
export function getBodyScrollLockCount(): number {
  return bodyLockState?.count ?? 0;
}
