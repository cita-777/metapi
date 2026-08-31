import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';

export type ToastType = 'success' | 'error' | 'info';

type Toast = {
  id: number;
  type: ToastType;
  message: string;
  exiting?: boolean;
}

interface ToastContextValue {
  toast: (type: ToastType, message: string) => void;
  success: (message: string) => void;
  error: (message: string) => void;
  info: (message: string) => void;
}

const ToastContext = createContext<ToastContextValue | null>(null);

export function useToast() {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error('useToast must be used within ToastProvider');
  return ctx;
}

const icons: Record<ToastType, React.ReactNode> = {
  success: <svg width="18" height="18" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M5 13l4 4L19 7" /></svg>,
  error: <svg width="18" height="18" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M6 18L18 6M6 6l12 12" /></svg>,
  info: <svg width="18" height="18" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>,
};

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const idRef = useRef(0);
  // React runs child effects before parent effects. Start true so a child that
  // emits a toast from its first effect is not dropped before this provider's
  // mount effect has run; the cleanup flips it to false on unmount.
  const mountedRef = useRef(true);
  const dismissTimersRef = useRef(new Map<number, ReturnType<typeof globalThis.setTimeout>>());
  const removeTimersRef = useRef(new Map<number, ReturnType<typeof globalThis.setTimeout>>());

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      dismissTimersRef.current.forEach((timer) => globalThis.clearTimeout(timer));
      removeTimersRef.current.forEach((timer) => globalThis.clearTimeout(timer));
      dismissTimersRef.current.clear();
      removeTimersRef.current.clear();
    };
  }, []);

  const clearDismissTimer = useCallback((id: number) => {
    const timer = dismissTimersRef.current.get(id);
    if (timer === undefined) return;
    globalThis.clearTimeout(timer);
    dismissTimersRef.current.delete(id);
  }, []);

  const removeToast = useCallback((id: number) => {
    if (!mountedRef.current) return;
    clearDismissTimer(id);
    if (removeTimersRef.current.has(id)) return;
    setToasts(prev => prev.map(t => t.id === id ? { ...t, exiting: true } : t));
    const timer = globalThis.setTimeout(() => {
      removeTimersRef.current.delete(id);
      if (!mountedRef.current) return;
      setToasts(prev => prev.filter(t => t.id !== id));
    }, 250);
    removeTimersRef.current.set(id, timer);
  }, [clearDismissTimer]);

  const addToast = useCallback((type: ToastType, message: string) => {
    const id = ++idRef.current;
    if (!mountedRef.current) return;
    setToasts(prev => [...prev, { id, type, message }]);
    const timer = globalThis.setTimeout(() => {
      dismissTimersRef.current.delete(id);
      removeToast(id);
    }, 3200);
    dismissTimersRef.current.set(id, timer);
  }, [removeToast]);

  const success = useCallback((msg: string) => addToast('success', msg), [addToast]);
  const error = useCallback((msg: string) => addToast('error', msg), [addToast]);
  const info = useCallback((msg: string) => addToast('info', msg), [addToast]);

  // Keep the context object stable so effect dependencies on `useToast()` do not refire
  // every time the toast list changes.
  const value = useMemo<ToastContextValue>(() => ({
    toast: addToast,
    success,
    error,
    info,
  }), [addToast, error, info, success]);

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div
        className="toast-container"
        role="region"
        aria-live="polite"
        aria-relevant="additions text"
        aria-label="通知"
      >
        {toasts.map(t => (
          <div
            key={t.id}
            className={`toast toast-${t.type} ${t.exiting ? 'toast-exit' : ''}`}
            onClick={() => removeToast(t.id)}
            onKeyDown={(event) => {
              if (event.key === 'Enter' || event.key === ' ') {
                event.preventDefault();
                removeToast(t.id);
              }
            }}
            role="status"
            aria-live="polite"
            aria-atomic="true"
            tabIndex={0}
            aria-label={t.message}
            style={{ cursor: 'pointer' }}
          >
            <span style={{ flexShrink: 0, marginTop: 1 }}>{icons[t.type]}</span>
            <span style={{ fontSize: 13, lineHeight: 1.5 }}>{t.message}</span>
            <div className="toast-progress" aria-hidden="true" />
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}
