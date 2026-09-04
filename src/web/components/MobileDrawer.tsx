import type React from 'react';
import { Drawer } from './ui/Dialog.js';

export type MobileDrawerProps = {
  open: boolean;
  onClose: () => void;
  children: React.ReactNode;
  title?: React.ReactNode;
  closeLabel?: string;
  side?: 'left' | 'right';
  closeOnBackdrop?: boolean;
  closeOnEscape?: boolean;
  showCloseButton?: boolean;
  ariaLabel?: string;
  ariaDescribedBy?: string;
};

function MobileDrawer({
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
}: MobileDrawerProps) {
  return (
    <Drawer
      open={open}
      onClose={onClose}
      title={title}
      closeLabel={closeLabel}
      side={side}
      closeOnBackdrop={closeOnBackdrop}
      closeOnEscape={closeOnEscape}
      showCloseButton={showCloseButton}
      ariaLabel={ariaLabel}
      ariaDescribedBy={ariaDescribedBy}
    >
      {children}
    </Drawer>
  );
}

export { MobileDrawer };
export default MobileDrawer;
