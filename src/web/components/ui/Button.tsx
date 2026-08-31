import { forwardRef, type ButtonHTMLAttributes, type ReactNode } from 'react';

export type ButtonVariant =
  | 'primary'
  | 'soft-primary'
  | 'danger'
  | 'success'
  | 'ghost'
  | 'link';

export type ButtonSize = 'sm' | 'md' | 'lg';

export type ButtonProps = Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'type'> & {
  /** Native type is opt-in; non-form actions default to `button`. */
  type?: ButtonHTMLAttributes<HTMLButtonElement>['type'];
  variant?: ButtonVariant;
  size?: ButtonSize;
  /** Shows a spinner and disables the button while an action is pending. */
  loading?: boolean;
  /** Optional replacement text announced/rendered while loading. */
  loadingLabel?: ReactNode;
};

function classNames(
  className: string | undefined,
  variant: ButtonVariant,
  size: ButtonSize,
): string {
  const classes = [
    'btn',
    `btn-${variant}`,
    size === 'md' ? undefined : `btn-${size}`,
    className,
  ].filter(Boolean);
  return [...new Set(classes.flatMap((value) => value!.split(/\s+/).filter(Boolean)))].join(' ');
}

/** Project-owned button facade that preserves the existing .btn-* theme. */
export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button({
  type = 'button',
  variant = 'primary',
  size = 'md',
  loading = false,
  loadingLabel,
  className,
  children,
  disabled,
  ...props
}, ref) {
  const isDisabled = Boolean(disabled || loading);
  return (
    <button
      {...props}
      ref={ref}
      type={type}
      className={classNames(className, variant, size)}
      disabled={isDisabled}
      aria-busy={loading || undefined}
    >
      {loading ? <span className="spinner spinner-sm" aria-hidden="true" /> : null}
      {loading && loadingLabel !== undefined ? loadingLabel : children}
    </button>
  );
});

export type AsyncButtonProps = Omit<ButtonProps, 'loading'> & {
  /** `pending` is an ergonomic alias for callers that model async state that way. */
  pending?: boolean;
  loading?: boolean;
};

/** Semantic alias for mutations; supports both loading and pending naming. */
export const AsyncButton = forwardRef<HTMLButtonElement, AsyncButtonProps>(function AsyncButton({
  pending = false,
  loading = false,
  ...props
}, ref) {
  return <Button ref={ref} {...props} loading={loading || pending} />;
});

export default Button;
