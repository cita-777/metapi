import { useCallback, useEffect, useRef, useState } from "react";

/**
 * Context supplied to an async loader for each invocation.
 *
 * Loaders are deliberately kept at the `api.ts` boundary.  The hook only
 * owns lifecycle concerns (abort, stale-result protection and UI state) and
 * does not cache domain data.
 */
export type AsyncLoadContext = {
  silent: boolean;
  /** Whether the caller explicitly requested a server-side cache refresh. */
  forceRefresh: boolean;
};

export type AsyncLoader<T> = (
  signal: AbortSignal,
  context: AsyncLoadContext,
) => Promise<T>;

export type AsyncErrorKind = "none" | "abort" | "timeout" | "error";

export type AsyncReloadOptions = {
  /** Keep the current data visible while the request is running. */
  silent?: boolean;
  /** Reuse the current request instead of aborting and starting another one. */
  dedupe?: boolean;
  forceRefresh?: boolean;
};

export type UseAsyncResourceOptions<T> = {
  enabled?: boolean;
  autoLoad?: boolean;
  initialData?: T | null;
  onError?: (error: Error, context: AsyncLoadContext) => void;
};

export type AsyncResource<T> = {
  data: T | null;
  loading: boolean;
  refreshing: boolean;
  error: Error | null;
  errorKind: AsyncErrorKind;
  /** True when the current request was cancelled by the caller or lifecycle. */
  cancelled: boolean;
  reload: (options?: AsyncReloadOptions) => Promise<T | undefined>;
  cancel: () => void;
};

function errorName(value: unknown): string {
  if (typeof value !== "object" || value === null) return "";
  const name = (value as { name?: unknown }).name;
  return typeof name === "string" ? name : "";
}

function errorMessage(value: unknown): string {
  if (value instanceof Error) return value.message;
  if (typeof value === "string") return value;
  if (typeof value === "object" && value !== null) {
    const message = (value as { message?: unknown }).message;
    if (typeof message === "string") return message;
  }
  return "请求失败";
}

function toError(value: unknown): Error {
  return value instanceof Error ? value : new Error(errorMessage(value));
}

/** Public so page-level tests and API adapters can share the same semantics. */
export function isAbortError(value: unknown): boolean {
  const name = errorName(value);
  if (name === "AbortError") return true;
  return (
    typeof DOMException !== "undefined" &&
    value instanceof DOMException &&
    value.name === "AbortError"
  );
}

/** API timeout errors are intentionally kept distinct from user cancellation. */
export function isTimeoutError(value: unknown): boolean {
  const name = errorName(value);
  if (name === "TimeoutError") return true;
  return /(?:timeout|timed out|超时)/i.test(errorMessage(value));
}

export function classifyAsyncError(value: unknown): AsyncErrorKind {
  if (isAbortError(value)) return "abort";
  if (isTimeoutError(value)) return "timeout";
  return "error";
}

type ActiveRequest<T> = {
  id: number;
  controller: AbortController;
  promise: Promise<T | undefined>;
};

/**
 * Manage one cancellable async resource without introducing a global cache.
 *
 * A new request aborts the previous one, and every state write is guarded by
 * both a mounted flag and a monotonically increasing request id.  Callers may
 * pass `dedupe: true` for polling so a slow request cannot create a pile-up.
 */
export function useAsyncResource<T>(
  loader: AsyncLoader<T>,
  options: UseAsyncResourceOptions<T> = {},
): AsyncResource<T> {
  const {
    enabled = true,
    autoLoad = true,
    initialData = null,
    onError,
  } = options;
  const [state, setState] = useState<
    Omit<AsyncResource<T>, "reload" | "cancel">
  >({
    data: initialData,
    loading: autoLoad && enabled,
    refreshing: false,
    error: null,
    errorKind: "none",
    cancelled: false,
  });

  const loaderRef = useRef(loader);
  loaderRef.current = loader;
  const onErrorRef = useRef(onError);
  onErrorRef.current = onError;
  const enabledRef = useRef(enabled);
  enabledRef.current = enabled;
  const mountedRef = useRef(true);
  const requestIdRef = useRef(0);
  const activeRequestRef = useRef<ActiveRequest<T> | null>(null);

  const cancel = useCallback(() => {
    requestIdRef.current += 1;
    const active = activeRequestRef.current;
    activeRequestRef.current = null;
    active?.controller.abort();

    // A no-op cancel (for example when `enabled` starts false) should not
    // manufacture an abort state that the user never initiated.
    if (active && mountedRef.current) {
      setState((current) => ({
        ...current,
        loading: false,
        refreshing: false,
        error: null,
        errorKind: "abort",
        cancelled: true,
      }));
    }
  }, []);

  const reload = useCallback(
    (reloadOptions: AsyncReloadOptions = {}): Promise<T | undefined> => {
      if (!enabledRef.current || !mountedRef.current) {
        return Promise.resolve(undefined);
      }

      const silent = reloadOptions.silent === true;
      const active = activeRequestRef.current;
      if (active && reloadOptions.dedupe) return active.promise;
      if (active) {
        activeRequestRef.current = null;
        active.controller.abort();
      }

      const id = ++requestIdRef.current;
      const controller = new AbortController();
      const context: AsyncLoadContext = {
        silent,
        forceRefresh: reloadOptions.forceRefresh === true,
      };
      setState((current) => ({
        ...current,
        loading: !silent || current.data === null,
        refreshing: silent && current.data !== null,
        error: null,
        errorKind: "none",
        cancelled: false,
      }));

      // Invoke the loader synchronously after creating the controller.  A
      // rejected promise wrapper handles synchronous throws while ensuring
      // the active request record is installed before the promise can settle.
      let loaderPromise: Promise<T>;
      try {
        loaderPromise = Promise.resolve(
          loaderRef.current(controller.signal, context),
        );
      } catch (rawError) {
        loaderPromise = Promise.reject(rawError);
      }

      const promise = (async () => {
        try {
          const value = await loaderPromise;
          if (
            !mountedRef.current ||
            id !== requestIdRef.current ||
            controller.signal.aborted
          ) {
            return undefined;
          }
          setState((current) => ({
            ...current,
            data: value,
            loading: false,
            refreshing: false,
            error: null,
            errorKind: "none",
            cancelled: false,
          }));
          return value;
        } catch (rawError) {
          const kind = classifyAsyncError(rawError);
          if (
            !mountedRef.current ||
            id !== requestIdRef.current ||
            controller.signal.aborted
          ) {
            return undefined;
          }

          const error = toError(rawError);
          if (kind === "abort") {
            setState((current) => ({
              ...current,
              loading: false,
              refreshing: false,
              error: null,
              errorKind: "abort",
              cancelled: true,
            }));
          } else {
            setState((current) => ({
              ...current,
              loading: false,
              refreshing: false,
              error,
              errorKind: kind,
              cancelled: false,
            }));
            try {
              onErrorRef.current?.(error, context);
            } catch {
              // Error reporting must not turn a handled request failure into
              // an unhandled rejection or prevent lifecycle cleanup.
            }
          }
          return undefined;
        } finally {
          if (activeRequestRef.current?.id === id) {
            activeRequestRef.current = null;
          }
          if (mountedRef.current && id === requestIdRef.current) {
            setState((current) => ({
              ...current,
              loading: false,
              refreshing: false,
            }));
          }
        }
      })();

      activeRequestRef.current = { id, controller, promise };
      return promise;
    },
    [],
  );

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      requestIdRef.current += 1;
      const active = activeRequestRef.current;
      activeRequestRef.current = null;
      active?.controller.abort();
    };
  }, []);

  useEffect(() => {
    if (!enabled) {
      cancel();
      return undefined;
    }
    if (!autoLoad) return undefined;

    // Defer automatic bootstrap by one microtask.  React StrictMode replays
    // effects in development; the first replay cleanup marks this callback
    // cancelled before it can create a real request, avoiding duplicate
    // network work while explicit `reload()` remains synchronous.
    let scheduled = true;
    const run = () => {
      if (scheduled) void reload();
    };
    if (typeof queueMicrotask === "function") queueMicrotask(run);
    else void Promise.resolve().then(run);
    return () => {
      scheduled = false;
    };
  }, [autoLoad, cancel, enabled, reload]);

  return {
    ...state,
    reload,
    cancel,
  };
}
