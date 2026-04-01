import React from 'react';
import { createPortal } from 'react-dom';

type ModalPresence = {
  shouldRender: boolean;
  isVisible: boolean;
};

type ModelAvailabilityProbeConfirmModalProps = {
  presence: ModalPresence;
  confirmText: string;
  confirmationInput: string;
  saving: boolean;
  onConfirmationInputChange: (value: string) => void;
  onClose: () => void;
  onConfirm: () => void;
};

export default function ModelAvailabilityProbeConfirmModal({
  presence,
  confirmText,
  confirmationInput,
  saving,
  onConfirmationInputChange,
  onClose,
  onConfirm,
}: ModelAvailabilityProbeConfirmModalProps) {
  if (!presence.shouldRender) {
    return null;
  }

  const canConfirm = confirmationInput.trim() === confirmText;
  const titleId = 'model-availability-probe-confirm-modal-title';
  const descriptionId = 'model-availability-probe-confirm-modal-description';
  const handleRequestClose = () => {
    if (saving) return;
    onClose();
  };

  const modal = (
    <div className={`modal-backdrop ${presence.isVisible ? '' : 'is-closing'}`.trim()} onClick={handleRequestClose}>
      <div
        className={`modal-content ${presence.isVisible ? '' : 'is-closing'}`.trim()}
        style={{ maxWidth: 760, border: '1px solid color-mix(in srgb, var(--color-danger) 35%, var(--color-border))' }}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={descriptionId}
        aria-busy={saving}
        onClick={(e) => e.stopPropagation()}
      >
        <div id={titleId} className="modal-header" style={{ color: 'var(--color-danger)' }}>确认开启批量测活</div>
        <div id={descriptionId} className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div style={{ padding: 12, borderRadius: 'var(--radius-sm)', background: 'var(--color-danger-bg)', color: 'var(--color-danger)', fontSize: 12, lineHeight: 1.8 }}>
            开启后，metapi 会在后台对活跃账号模型做最小化探测请求。这可能被部分中转站视为批量测活或异常行为，请务必先确认你的中转站明确允许此类探测。
          </div>
          <div style={{ fontSize: 13, color: 'var(--color-text-secondary)', lineHeight: 1.9 }}>
            请手动输入以下整句后再开启：
          </div>
          <div
            style={{
              padding: 12,
              borderRadius: 'var(--radius-sm)',
              border: '1px solid var(--color-border-light)',
              background: 'var(--color-bg)',
              color: 'var(--color-text-primary)',
              fontSize: 13,
              lineHeight: 1.8,
            }}
          >
            {confirmText}
          </div>
          <textarea
            value={confirmationInput}
            onChange={(e) => onConfirmationInputChange(e.target.value)}
            placeholder="请输入上方确认语句"
            spellCheck={false}
            style={{
              width: '100%',
              minHeight: 96,
              padding: '10px 14px',
              border: '1px solid var(--color-border)',
              borderRadius: 'var(--radius-sm)',
              fontSize: 13,
              outline: 'none',
              resize: 'vertical',
              background: 'var(--color-bg)',
              color: 'var(--color-text-primary)',
            }}
          />
        </div>
        <div className="modal-footer">
          <button onClick={handleRequestClose} disabled={saving} className="btn btn-ghost">取消</button>
          <button onClick={onConfirm} disabled={saving || !canConfirm} className="btn btn-danger">
            {saving
              ? <><span className="spinner spinner-sm" style={{ borderTopColor: 'white', borderColor: 'rgba(255,255,255,0.3)' }} /> 确认开启中...</>
              : '确认开启批量测活'}
          </button>
        </div>
      </div>
    </div>
  );

  return typeof document !== 'undefined' ? createPortal(modal, document.body) : modal;
}
