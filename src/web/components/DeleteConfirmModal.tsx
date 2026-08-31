import React from 'react';
import CenteredModal from './CenteredModal.js';
import { AsyncButton, Button } from './ui/Button.js';

type DeleteConfirmModalProps = {
  open: boolean;
  title?: string;
  description: React.ReactNode;
  confirmText?: string;
  cancelText?: string;
  loading?: boolean;
  onConfirm: () => void;
  onClose: () => void;
};

export default function DeleteConfirmModal({
  open,
  title = '确认删除',
  description,
  confirmText = '确认删除',
  cancelText = '取消',
  loading = false,
  onConfirm,
  onClose,
}: DeleteConfirmModalProps) {
  return (
    <CenteredModal
      open={open}
      onClose={onClose}
      title={title}
      maxWidth={560}
      bodyStyle={{ display: 'flex', flexDirection: 'column', gap: 12 }}
      footer={(
        <>
          <Button onClick={onClose} variant="ghost" disabled={loading}>{cancelText}</Button>
          <AsyncButton onClick={onConfirm} variant="danger" loading={loading} loadingLabel="删除中...">
            {confirmText}
          </AsyncButton>
        </>
      )}
    >
      <div className="alert alert-error" style={{ margin: 0 }}>
        <div className="alert-title">此操作不可撤销</div>
        <div style={{ marginTop: 6, fontSize: 13 }}>{description}</div>
      </div>
    </CenteredModal>
  );
}
