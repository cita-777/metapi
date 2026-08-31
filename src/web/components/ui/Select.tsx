import { useEffect, useId, useMemo, useRef, useState, type KeyboardEvent as ReactKeyboardEvent, type ReactNode } from 'react';

export type ModernSelectOption = {
  value: string;
  label: string;
  description?: string;
  disabled?: boolean;
  iconNode?: ReactNode;
  iconUrl?: string;
  iconText?: string;
};

export type ModernSelectProps = {
  value: string;
  onChange: (value: string) => void;
  options: ModernSelectOption[];
  'data-testid'?: string;
  placeholder?: string;
  disabled?: boolean;
  emptyLabel?: string;
  menuMaxHeight?: number;
  className?: string;
  size?: 'md' | 'sm';
  searchable?: boolean;
  searchPlaceholder?: string;
};

function optionText(option: ModernSelectOption): string {
  return [option.label, option.description, option.value]
    .filter((value): value is string => typeof value === 'string' && value.trim().length > 0)
    .join(' ')
    .toLowerCase();
}

function firstEnabledIndex(options: ModernSelectOption[], start = 0): number {
  for (let index = Math.max(0, start); index < options.length; index += 1) {
    if (!options[index]?.disabled) return index;
  }
  return -1;
}

/**
 * Metapi's select facade. The public contract intentionally stays independent
 * of a third-party Select primitive so pages and tests can migrate in place.
 * Its listbox semantics and keyboard behavior match the eventual Radix Select
 * adapter without exposing Radix nodes to callers.
 */
export default function ModernSelect({
  value,
  onChange,
  options,
  'data-testid': dataTestId,
  placeholder = 'Select',
  disabled = false,
  emptyLabel = 'No options',
  menuMaxHeight = 280,
  className = '',
  size = 'md',
  searchable = false,
  searchPlaceholder = 'Search...',
}: ModernSelectProps) {
  const [open, setOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [highlightedIndex, setHighlightedIndex] = useState(-1);
  const rootRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const listboxId = useId();

  const selected = useMemo(
    () => options.find((item) => item.value === value),
    [options, value],
  );

  const visibleOptions = useMemo(() => {
    const query = searchQuery.trim().toLowerCase();
    if (!searchable || !query) return options;
    return options.filter((item) => optionText(item).includes(query));
  }, [options, searchQuery, searchable]);

  useEffect(() => {
    if (!open || typeof document === 'undefined') return undefined;

    const handleOutsideClick = (event: MouseEvent) => {
      if (!rootRef.current) return;
      if (!rootRef.current.contains(event.target as Node)) setOpen(false);
    };
    const handleEscape = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return;
      setOpen(false);
      triggerRef.current?.focus();
    };

    document.addEventListener('mousedown', handleOutsideClick);
    document.addEventListener('keydown', handleEscape);
    return () => {
      document.removeEventListener('mousedown', handleOutsideClick);
      document.removeEventListener('keydown', handleEscape);
    };
  }, [open]);

  useEffect(() => {
    if (disabled) setOpen(false);
  }, [disabled]);

  useEffect(() => {
    if (!open) {
      if (searchQuery) setSearchQuery('');
      setHighlightedIndex(-1);
      return;
    }

    const selectedIndex = visibleOptions.findIndex((item) => item.value === value && !item.disabled);
    setHighlightedIndex(selectedIndex >= 0 ? selectedIndex : firstEnabledIndex(visibleOptions));
  }, [open, searchQuery, value, visibleOptions]);

  const selectOption = (item: ModernSelectOption) => {
    if (disabled || item.disabled) return;
    onChange(item.value);
    setOpen(false);
    triggerRef.current?.focus();
  };

  const handleTriggerKeyDown = (event: ReactKeyboardEvent<HTMLButtonElement>) => {
    if (disabled) return;
    if (!open) {
      if (event.key === 'Enter' || event.key === ' ' || event.key === 'ArrowDown' || event.key === 'ArrowUp') {
        event.preventDefault();
        setOpen(true);
      }
      return;
    }

    if (event.key === 'Escape') {
      event.preventDefault();
      setOpen(false);
      return;
    }

    if (event.key === 'ArrowUp' || event.key === 'ArrowDown') {
      event.preventDefault();
      const direction = event.key === 'ArrowDown' ? 1 : -1;
      const enabledIndices = visibleOptions
        .map((item, index) => (item.disabled ? -1 : index))
        .filter((index) => index >= 0);
      if (enabledIndices.length === 0) return;
      const currentPosition = enabledIndices.indexOf(highlightedIndex);
      const basePosition = currentPosition >= 0
        ? currentPosition
        : (direction > 0 ? -1 : 0);
      const nextPosition = (basePosition + direction + enabledIndices.length) % enabledIndices.length;
      setHighlightedIndex(enabledIndices[nextPosition] ?? -1);
      return;
    }

    if ((event.key === 'Enter' || event.key === ' ') && highlightedIndex >= 0) {
      event.preventDefault();
      const item = visibleOptions[highlightedIndex];
      if (item) selectOption(item);
    }
  };

  const renderOptionIcon = (item: ModernSelectOption) => {
    if (item.iconNode) return item.iconNode;
    if (item.iconUrl) {
      return <img className="modern-select-option-icon" src={item.iconUrl} alt="" loading="lazy" />;
    }
    if (item.iconText) return <span className="modern-select-option-icon-text">{item.iconText}</span>;
    return null;
  };

  return (
    <div
      ref={rootRef}
      data-testid={dataTestId}
      className={`modern-select ${open ? 'is-open' : ''} ${disabled ? 'is-disabled' : ''} ${size === 'sm' ? 'is-sm' : ''} ${className}`.trim()}
    >
      <button
        ref={triggerRef}
        type="button"
        className="modern-select-trigger"
        onClick={() => {
          if (!disabled) setOpen((prev) => !prev);
        }}
        onKeyDown={handleTriggerKeyDown}
        aria-expanded={open}
        aria-haspopup="listbox"
        aria-controls={listboxId}
        aria-activedescendant={open && highlightedIndex >= 0 ? `${listboxId}-option-${highlightedIndex}` : undefined}
        disabled={disabled}
      >
        <span className={`modern-select-value ${selected ? '' : 'is-placeholder'}`.trim()}>
          {selected ? (
            <span className="modern-select-value-content">
              {renderOptionIcon(selected)}
              <span>{selected.label}</span>
            </span>
          ) : placeholder}
        </span>
        <svg
          className="modern-select-chevron"
          width="14"
          height="14"
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
          aria-hidden="true"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      <div
        id={listboxId}
        className="modern-select-panel"
        style={{ maxHeight: menuMaxHeight }}
        role="listbox"
        aria-hidden={!open}
        aria-label={placeholder}
      >
        {searchable && (
          <div className="modern-select-search-shell">
            <input
              type="text"
              value={searchQuery}
              onChange={(event) => setSearchQuery(event.target.value)}
              placeholder={searchPlaceholder}
              aria-label={searchPlaceholder}
              className="modern-select-search-input"
            />
          </div>
        )}

        {visibleOptions.length === 0 ? (
          <div className="modern-select-empty" role="status">{emptyLabel}</div>
        ) : (
          visibleOptions.map((item, index) => {
            const active = item.value === value;
            const highlighted = index === highlightedIndex;
            return (
              <button
                key={item.value}
                id={`${listboxId}-option-${index}`}
                type="button"
                role="option"
                aria-selected={active}
                className={`modern-select-option ${active ? 'is-active' : ''} ${highlighted ? 'is-highlighted' : ''} ${item.disabled ? 'is-disabled' : ''}`.trim()}
                onMouseEnter={() => setHighlightedIndex(index)}
                onClick={() => selectOption(item)}
                disabled={item.disabled}
              >
                <div className="modern-select-option-main">
                  {renderOptionIcon(item)}
                  <div style={{ minWidth: 0 }}>
                    <div className="modern-select-option-label">{item.label}</div>
                    {item.description && (
                      <div className="modern-select-option-desc">{item.description}</div>
                    )}
                  </div>
                </div>
                {active && (
                  <svg width="14" height="14" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                  </svg>
                )}
              </button>
            );
          })
        )}
      </div>
    </div>
  );
}
