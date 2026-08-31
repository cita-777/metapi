import { useCallback, useId, useMemo, useRef, type CSSProperties, type ReactNode } from 'react';
import * as RadixDialog from '@radix-ui/react-dialog';
import { useAnimatedVisibility } from '../useAnimatedVisibility.js';
import {
  getPortalTarget,
  renderInPortal,
  useBodyScrollLock,
  useEscapeKey,
  useFocusReturn,
} from './lifecycle.js';

type SurfaceKind = 'dialog' | 'drawer';

/** Compatibility shape for callers that already own an exit-animation hook. */
export type DialogPresence = {
  shouldRender: boolean;
  isVisible: boolean;
};

export type DialogProps = {
  open: boolean;
  onClose: () => void;
  title?: ReactNode;
  children: ReactNode;
  footer?: ReactNode;
  maxWidth?: number | string;
  bodyStyle?: CSSProperties;
  closeOnBackdrop?: boolean;
  closeOnEscape?: boolean;
  showCloseButton?: boolean;
  closeLabel?: string;
  ariaLabel?: string;
  ariaDescribedBy?: string;
  /** Optional state announced while an async action keeps the surface busy. */
  ariaBusy?: boolean;
  className?: string;
  contentClassName?: string;
  /** Additional styles for the surface panel (merged after the max-width). */
  contentStyle?: CSSProperties;
  animationDuration?: number;
  /** Optional externally managed presence, retained for incremental migrations. */
  presence?: DialogPresence;
};

export type DrawerProps = {
  open: boolean;
  onClose: () => void;
  children: ReactNode;
  title?: ReactNode;
  closeLabel?: string;
  side?: 'left' | 'right';
  closeOnBackdrop?: boolean;
  closeOnEscape?: boolean;
  showCloseButton?: boolean;
  ariaLabel?: string;
  ariaDescribedBy?: string;
  /** Optional state announced while an async action keeps the surface busy. */
  ariaBusy?: boolean;
  className?: string;
  contentClassName?: string;
  /** Additional styles for the surface panel. */
  contentStyle?: CSSProperties;
  animationDuration?: number;
  /** Optional externally managed presence, retained for incremental migrations. */
  presence?: DialogPresence;
};

type DialogSurfaceProps = {
  kind: SurfaceKind;
  open: boolean;
  onClose: () => void;
  title?: ReactNode;
  children: ReactNode;
  footer?: ReactNode;
  maxWidth?: number | string;
  bodyStyle?: CSSProperties;
  closeOnBackdrop: boolean;
  closeOnEscape: boolean;
  showCloseButton: boolean;
  closeLabel: string;
  ariaLabel?: string;
  ariaDescribedBy?: string;
  ariaBusy?: boolean;
  side?: 'left' | 'right';
  className?: string;
  contentClassName?: string;
  contentStyle?: CSSProperties;
  animationDuration: number;
  presence?: DialogPresence;
};

function joinClasses(...classes: Array<string | undefined | false>): string | undefined {
  const value = classes.filter(Boolean).join(' ').trim();
  return value || undefined;
}

function isTestRuntime(): boolean {
  const processLike = (globalThis as {
    process?: { env?: Record<string, string | undefined> };
  }).process;
  return processLike?.env?.NODE_ENV === 'test';
}

/**
 * Radix's DOM portal is enabled for the browser build. Vitest's
 * react-test-renderer intentionally has no DOM host, so the same semantic
 * shell falls back to a plain React tree there. This keeps SSR/test rendering
 * deterministic while retaining Radix focus/dismiss behavior for users.
 */
function canUseRadixRenderer(target: HTMLElement | null): target is HTMLElement {
  const forceRadix = (globalThis as { __METAPI_FORCE_RADIX_RENDERER__?: boolean }).__METAPI_FORCE_RADIX_RENDERER__ === true;
  if ((isTestRuntime() && !forceRadix) || typeof window === 'undefined' || !target) return false;
  return typeof target.ownerDocument?.createElement === 'function';
}

function hasTitle(title: ReactNode): boolean {
  return title !== undefined && title !== null && title !== false;
}

type SurfaceInnerProps = {
  kind: SurfaceKind;
  title?: ReactNode;
  titleId: string;
  children: ReactNode;
  footer?: ReactNode;
  bodyStyle?: CSSProperties;
  closeLabel: string;
  showCloseButton: boolean;
  onClose: () => void;
  useRadixTitle: boolean;
};

function SurfaceTitle({
  title,
  titleId,
  useRadixTitle,
}: Pick<SurfaceInnerProps, 'title' | 'titleId' | 'useRadixTitle'>) {
  if (!hasTitle(title)) {
    return <div className="modal-title" aria-hidden="true" />;
  }

  const titleNode = (
    <div className={useRadixTitle ? 'modal-title' : 'modal-title'} id={titleId}>
      {title}
    </div>
  );

  return useRadixTitle ? (
    <RadixDialog.Title asChild>{titleNode}</RadixDialog.Title>
  ) : titleNode;
}

function DialogInner({
  kind,
  title,
  titleId,
  children,
  footer,
  bodyStyle,
  closeLabel,
  showCloseButton,
  onClose,
  useRadixTitle,
}: SurfaceInnerProps) {
  if (kind === 'drawer') {
    return (
      <>
        <div className="mobile-drawer-toolbar">
          {hasTitle(title) ? (
            <div className="mobile-drawer-title" id={titleId}>
              {useRadixTitle ? (
                <RadixDialog.Title asChild>
                  <span>{title}</span>
                </RadixDialog.Title>
              ) : title}
            </div>
          ) : (useRadixTitle
            ? <RadixDialog.Title asChild><span className="ui-visually-hidden">抽屉</span></RadixDialog.Title>
            : <div />)}
          {showCloseButton ? (
            <button
              type="button"
              className="mobile-drawer-close"
              onClick={onClose}
              aria-label={closeLabel}
            >
              ×
            </button>
          ) : null}
        </div>
        {children}
      </>
    );
  }

  return (
    <>
      {!hasTitle(title) && useRadixTitle ? (
        <RadixDialog.Title asChild>
          <span className="ui-visually-hidden" id={titleId}>对话框</span>
        </RadixDialog.Title>
      ) : null}
      {hasTitle(title) || showCloseButton ? (
        <div className="modal-header">
          <SurfaceTitle title={title} titleId={titleId} useRadixTitle={useRadixTitle} />
          {showCloseButton ? (
            <button
              type="button"
              className="modal-close-button"
              onClick={onClose}
              aria-label={closeLabel}
            >
              ×
            </button>
          ) : null}
        </div>
      ) : null}
      <div className="modal-body" style={bodyStyle}>
        {children}
      </div>
      {footer ? <div className="modal-footer">{footer}</div> : null}
    </>
  );
}

function DialogSurface({
  kind,
  open,
  onClose,
  title,
  children,
  footer,
  maxWidth = 860,
  bodyStyle,
  closeOnBackdrop,
  closeOnEscape,
  showCloseButton,
  closeLabel,
  ariaLabel,
  ariaDescribedBy,
  ariaBusy,
  side = 'left',
  className,
  contentClassName,
  contentStyle: contentStyleProp,
  animationDuration,
  presence,
}: DialogSurfaceProps) {
  const internalPresence = useAnimatedVisibility(
    open,
    animationDuration,
    !presence,
  );
  const resolvedPresence = presence ?? internalPresence;
  const lifecycleOpen = presence ? open && presence.isVisible : open;
  const portalTarget = getPortalTarget();
  const useRadixRenderer = canUseRadixRenderer(portalTarget);
  const titleId = useId();
  const labelledBy = hasTitle(title) ? titleId : undefined;
  const isVisible = resolvedPresence.isVisible;
  const closingClass = isVisible ? undefined : 'is-closing';
  const fallbackFocusTarget = typeof document !== 'undefined' ? document.body : null;

  const closeGuardRef = useRef(false);
  const requestClose = useCallback(() => {
    // Radix can report both an outside interaction and an overlay click for
    // one pointer gesture. Keep all close paths single-flight for that tick.
    if (closeGuardRef.current) return;
    closeGuardRef.current = true;
    const resetGuard = () => {
      closeGuardRef.current = false;
    };
    if (typeof globalThis.queueMicrotask === 'function') {
      globalThis.queueMicrotask(resetGuard);
    } else {
      void Promise.resolve().then(resetGuard);
    }
    onClose();
  }, [onClose]);

  // Radix's modal overlay owns body scrolling in the browser renderer. The
  // project lock remains the fallback for SSR/test/partial DOM renderers, and
  // avoiding two independent owners prevents cleanup order from restoring a
  // stale overflow value after the last surface closes.
  useBodyScrollLock(lifecycleOpen && !useRadixRenderer);
  useFocusReturn(lifecycleOpen, fallbackFocusTarget);
  // CenteredModal historically skipped document listeners when no usable
  // portal/body existed; retain that SSR/test fallback. Drawers still accept
  // a lightweight document stub because their close policy is independent of
  // whether the portal target can be attached. Radix owns Escape handling in
  // the browser path, so registering a second listener there would double
  // invoke the caller.
  useEscapeKey(
    lifecycleOpen && closeOnEscape && !useRadixRenderer && (portalTarget !== null || kind === 'drawer'),
    requestClose,
  );

  const rootClassName = useMemo(
    () => kind === 'dialog'
      ? joinClasses('modal-backdrop', closingClass, className)
      : joinClasses('mobile-drawer-root', closingClass, className),
    [className, closingClass, kind],
  );

  const panelClassName = useMemo(
    () => kind === 'dialog'
      ? joinClasses('modal-content', closingClass, contentClassName)
      : joinClasses('mobile-drawer-panel', `mobile-drawer-panel-${side}`, contentClassName),
    [closingClass, contentClassName, kind, side],
  );

  if (!resolvedPresence.shouldRender) return null;

  const contentStyle = kind === 'dialog'
    ? { maxWidth, ...contentStyleProp }
    : contentStyleProp;
  const contentAria = {
    role: 'dialog' as const,
    'aria-modal': true,
    'aria-labelledby': labelledBy,
    'aria-label': labelledBy ? undefined : (ariaLabel ?? (kind === 'drawer' ? '抽屉' : '对话框')),
    'aria-describedby': ariaDescribedBy,
    'aria-busy': ariaBusy || undefined,
    tabIndex: -1,
    'data-ui-surface': kind,
    'data-state': lifecycleOpen ? 'open' : 'closed',
  };

  const handleBackdropClick = closeOnBackdrop ? requestClose : undefined;
  const inner = (
    <DialogInner
      kind={kind}
      title={title}
      titleId={titleId}
      footer={footer}
      bodyStyle={bodyStyle}
      closeLabel={closeLabel}
      showCloseButton={showCloseButton}
      onClose={requestClose}
      useRadixTitle={false}
    >
      {children}
    </DialogInner>
  );

  if (useRadixRenderer) {
    const radixInner = (
      <DialogInner
        kind={kind}
        title={title}
        titleId={titleId}
        footer={footer}
        bodyStyle={bodyStyle}
        closeLabel={closeLabel}
        showCloseButton={showCloseButton}
        onClose={requestClose}
        useRadixTitle
      >
        {children}
      </DialogInner>
    );

    const radixSurface = kind === 'dialog' ? (
      <RadixDialog.Root
        open={lifecycleOpen}
        onOpenChange={(nextOpen) => {
          // Root can receive a dismissal event from Radix's document-level
          // listener even when the controlled surface explicitly disables
          // Escape. The facade's close policy is authoritative.
          if (!nextOpen && lifecycleOpen && closeOnEscape) requestClose();
        }}
      >
        <RadixDialog.Portal container={portalTarget} forceMount={resolvedPresence.shouldRender}>
          <RadixDialog.Overlay
            asChild
            forceMount={resolvedPresence.shouldRender}
            onClick={kind === 'dialog' ? handleBackdropClick : undefined}
          >
            <div className={rootClassName}>
              <RadixDialog.Content
                forceMount={resolvedPresence.shouldRender}
                {...contentAria}
                className={panelClassName}
                style={contentStyle}
                onClick={(event) => event.stopPropagation()}
                onOpenAutoFocus={(event) => event.preventDefault()}
                onCloseAutoFocus={(event) => event.preventDefault()}
                onEscapeKeyDown={(event) => {
                  if (!closeOnEscape) event.preventDefault();
                }}
                onPointerDownOutside={(event) => {
                  // The backdrop has an explicit click owner below. Prevent
                  // Radix's dismissable layer from also closing on the
                  // preceding pointerdown; otherwise one gesture can invoke
                  // onClose twice (pointerdown + click), especially when
                  // closeOnEscape is enabled as well.
                  event.preventDefault();
                }}
                onInteractOutside={(event) => {
                  // Keep backdrop dismissal under the facade's explicit
                  // closeOnBackdrop click policy (see onPointerDownOutside).
                  event.preventDefault();
                }}
              >
                {radixInner}
              </RadixDialog.Content>
            </div>
          </RadixDialog.Overlay>
        </RadixDialog.Portal>
      </RadixDialog.Root>
    ) : (
      <RadixDialog.Root
        open={lifecycleOpen}
        onOpenChange={(nextOpen) => {
          if (!nextOpen && lifecycleOpen && closeOnEscape) requestClose();
        }}
      >
        <RadixDialog.Portal container={portalTarget} forceMount={resolvedPresence.shouldRender}>
          <RadixDialog.Overlay
            asChild
            forceMount={resolvedPresence.shouldRender}
            onClick={undefined}
          >
            <div className={rootClassName}>
              <div
                className="mobile-drawer-backdrop"
                onClick={handleBackdropClick}
                aria-hidden="true"
              />
              <RadixDialog.Content
                forceMount={resolvedPresence.shouldRender}
                {...contentAria}
                className={panelClassName}
                style={contentStyle}
                onClick={(event) => event.stopPropagation()}
                onOpenAutoFocus={(event) => event.preventDefault()}
                onCloseAutoFocus={(event) => event.preventDefault()}
                onEscapeKeyDown={(event) => {
                  if (!closeOnEscape) event.preventDefault();
                }}
                onPointerDownOutside={(event) => {
                  // The nested drawer backdrop owns pointer dismissal. Stop
                  // Radix's pointerdown dismissal so the following click does
                  // not produce a second onClose call.
                  event.preventDefault();
                }}
                onInteractOutside={(event) => {
                  event.preventDefault();
                }}
              >
                {radixInner}
              </RadixDialog.Content>
            </div>
          </RadixDialog.Overlay>
        </RadixDialog.Portal>
      </RadixDialog.Root>
    );

    return radixSurface;
  }

  const fallbackSurface = kind === 'dialog' ? (
    <div className={rootClassName} onClick={handleBackdropClick}>
      <div
        className={panelClassName}
        style={contentStyle}
        {...contentAria}
        onClick={(event) => event.stopPropagation()}
      >
        {inner}
      </div>
    </div>
  ) : (
    <div className={rootClassName}>
      <div
        className="mobile-drawer-backdrop"
        onClick={handleBackdropClick}
        aria-hidden="true"
      />
      <div
        className={panelClassName}
        style={contentStyle}
        {...contentAria}
        onClick={(event) => event.stopPropagation()}
      >
        {inner}
      </div>
    </div>
  );

  return renderInPortal(fallbackSurface);
}

/** Project-owned centered dialog API. */
export function Dialog({
  open,
  onClose,
  title,
  children,
  footer,
  maxWidth = 860,
  bodyStyle,
  closeOnBackdrop = false,
  closeOnEscape = false,
  showCloseButton = true,
  closeLabel = '关闭弹框',
  ariaLabel,
  ariaDescribedBy,
  ariaBusy,
  className,
  contentClassName,
  contentStyle,
  animationDuration = 220,
  presence,
}: DialogProps) {
  return (
    <DialogSurface
      kind="dialog"
      open={open}
      onClose={onClose}
      title={title}
      footer={footer}
      maxWidth={maxWidth}
      bodyStyle={bodyStyle}
      closeOnBackdrop={closeOnBackdrop}
      closeOnEscape={closeOnEscape}
      showCloseButton={showCloseButton}
      closeLabel={closeLabel}
      ariaLabel={ariaLabel}
      ariaDescribedBy={ariaDescribedBy}
      ariaBusy={ariaBusy}
      className={className}
      contentClassName={contentClassName}
      contentStyle={contentStyle}
      animationDuration={animationDuration}
      presence={presence}
    >
      {children}
    </DialogSurface>
  );
}

/** Project-owned drawer API sharing the dialog lifecycle implementation. */
export function Drawer({
  open,
  onClose,
  children,
  title,
  closeLabel = '关闭导航',
  side = 'left',
  closeOnBackdrop = true,
  closeOnEscape = true,
  showCloseButton = true,
  ariaLabel,
  ariaDescribedBy,
  ariaBusy,
  className,
  contentClassName,
  contentStyle,
  animationDuration = 280,
  presence,
}: DrawerProps) {
  return (
    <DialogSurface
      kind="drawer"
      open={open}
      onClose={onClose}
      title={title}
      side={side}
      closeOnBackdrop={closeOnBackdrop}
      closeOnEscape={closeOnEscape}
      showCloseButton={showCloseButton}
      closeLabel={closeLabel}
      ariaLabel={ariaLabel}
      ariaDescribedBy={ariaDescribedBy}
      ariaBusy={ariaBusy}
      className={className}
      contentClassName={contentClassName}
      contentStyle={contentStyle}
      animationDuration={animationDuration}
      presence={presence}
    >
      {children}
    </DialogSurface>
  );
}

export { DialogSurface };

export default Dialog;
