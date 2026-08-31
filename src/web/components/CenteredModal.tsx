import type React from 'react';
import { Dialog } from './ui/Dialog.js';

// Compatibility facade: the Dialog wrapper owns useAnimatedVisibility and
// createPortal while preserving the modal-backdrop/modal-content class names.
export type CenteredModalProps = {
  open: boolean;
  onClose: () => void;
  title: React.ReactNode;
  children: React.ReactNode;
  footer?: React.ReactNode;
  maxWidth?: number;
  bodyStyle?: React.CSSProperties;
  closeOnBackdrop?: boolean;
  closeOnEscape?: boolean;
  showCloseButton?: boolean;
};

export default function CenteredModal({
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
}: CenteredModalProps) {
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={title}
      footer={footer}
      maxWidth={maxWidth}
      bodyStyle={bodyStyle}
      closeOnBackdrop={closeOnBackdrop}
      closeOnEscape={closeOnEscape}
      showCloseButton={showCloseButton}
      closeLabel="关闭弹框"
    >
      {children}
    </Dialog>
  );
}
