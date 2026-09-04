import type { ReactNode } from 'react';

export type LoadingStateProps = {
  label?: ReactNode;
  className?: string;
  size?: 'sm' | 'md' | 'lg';
};

export function LoadingState({
  label = '加载中...',
  className,
  size = 'md',
}: LoadingStateProps) {
  return (
    <div
      className={['ui-loading-state', className].filter(Boolean).join(' ')}
      role="status"
      aria-live="polite"
      aria-label={typeof label === 'string' ? label : undefined}
    >
      <span className={`spinner spinner-${size}`} aria-hidden="true" />
      {label !== null ? <span>{label}</span> : null}
    </div>
  );
}

export type EmptyStateProps = {
  title?: ReactNode;
  description?: ReactNode;
  icon?: ReactNode;
  action?: ReactNode;
  className?: string;
};

export function EmptyState({
  title = '暂无数据',
  description,
  icon,
  action,
  className,
}: EmptyStateProps) {
  return (
    <div className={['empty-state', className].filter(Boolean).join(' ')} role="status">
      {icon ? <div className="empty-state-icon">{icon}</div> : null}
      <div className="empty-state-title">{title}</div>
      {description ? <div className="empty-state-desc">{description}</div> : null}
      {action ? <div className="empty-state-action">{action}</div> : null}
    </div>
  );
}

export type ErrorStateProps = {
  title?: ReactNode;
  description?: ReactNode;
  action?: ReactNode;
  className?: string;
};

export function ErrorState({
  title = '加载失败',
  description,
  action,
  className,
}: ErrorStateProps) {
  return (
    <div
      className={['alert', 'alert-error', className].filter(Boolean).join(' ')}
      role="alert"
      aria-live="assertive"
    >
      <div className="alert-title">{title}</div>
      {description ? <div>{description}</div> : null}
      {action ? <div className="error-state-action">{action}</div> : null}
    </div>
  );
}
