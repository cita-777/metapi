import React from 'react';
import MobileFilterSheet from './MobileFilterSheet.js';

type ResponsiveFilterPanelProps = {
  isMobile: boolean;
  mobileOpen: boolean;
  onMobileOpen?: () => void;
  onMobileClose: () => void;
  mobileTitle: string;
  mobileContent: React.ReactNode;
  desktopContent?: React.ReactNode;
  mobileTrigger?: React.ReactNode;
  mobileTriggerLabel?: string;
  mobileTriggerWrapperClassName?: string;
  mobileTriggerWrapperStyle?: React.CSSProperties;
  mobileTriggerButtonClassName?: string;
  mobileTriggerButtonStyle?: React.CSSProperties;
};

export default function ResponsiveFilterPanel({
  isMobile,
  mobileOpen,
  onMobileOpen,
  onMobileClose,
  mobileTitle,
  mobileContent,
  desktopContent = null,
  mobileTrigger,
  mobileTriggerLabel = '筛选',
  mobileTriggerWrapperClassName = 'mobile-filter-row',
  mobileTriggerWrapperStyle,
  mobileTriggerButtonClassName = 'btn btn-ghost',
  mobileTriggerButtonStyle = { border: '1px solid var(--color-border)' },
}: ResponsiveFilterPanelProps) {
  if (!isMobile) {
    return <>{desktopContent}</>;
  }

  return (
    <>
      {mobileTrigger ?? (onMobileOpen ? (
        <div className={mobileTriggerWrapperClassName} style={mobileTriggerWrapperStyle}>
          <button
            type="button"
            className={mobileTriggerButtonClassName}
            style={mobileTriggerButtonStyle}
            onClick={onMobileOpen}
          >
            {mobileTriggerLabel}
          </button>
        </div>
      ) : null)}
      <MobileFilterSheet open={mobileOpen} onClose={onMobileClose} title={mobileTitle}>
        {mobileContent}
      </MobileFilterSheet>
    </>
  );
}
