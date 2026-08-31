import { Dialog, type DialogPresence } from '../../components/ui/Dialog.js';
import { AsyncButton, Button } from '../../components/ui/Button.js';

type ModalPresence = DialogPresence;

type ModelAvailabilityProbeConfirmModalProps = {
  presence: ModalPresence;
  confirmText: string;
  confirmationInput: string;
  saving: boolean;
  onConfirmationInputChange: (value: string) => void;
  onClose: () => void;
  onConfirm: () => void;
};

/** Confirmation gate for the high-risk model availability probe setting. */
export default function ModelAvailabilityProbeConfirmModal({
  presence,
  confirmText,
  confirmationInput,
  saving,
  onConfirmationInputChange,
  onClose,
  onConfirm,
}: ModelAvailabilityProbeConfirmModalProps) {
  const canConfirm = confirmationInput.trim() === confirmText;
  const descriptionId = 'model-availability-probe-confirm-modal-description';
  const handleRequestClose = () => {
    if (saving) return;
    onClose();
  };

  return (
    <Dialog
      open={presence.isVisible}
      onClose={handleRequestClose}
      presence={presence}
      title={<span style={{ color: 'var(--color-danger)' }}>确认开启批量测活</span>}
      maxWidth={760}
      contentStyle={{ border: '1px solid color-mix(in srgb, var(--color-danger) 35%, var(--color-border))' }}
      closeOnBackdrop
      closeOnEscape={false}
      showCloseButton={false}
      ariaLabel="确认开启批量测活"
      ariaDescribedBy={descriptionId}
      ariaBusy={saving}
      footer={(
        <>
          <Button onClick={handleRequestClose} disabled={saving} variant="ghost">
            取消
          </Button>
          <AsyncButton
            onClick={onConfirm}
            disabled={saving || !canConfirm}
            variant="danger"
            pending={saving}
            loadingLabel="确认开启中..."
          >
            确认开启批量测活
          </AsyncButton>
        </>
      )}
    >
      <div id={descriptionId} style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
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
          onChange={(event) => onConfirmationInputChange(event.target.value)}
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
    </Dialog>
  );
}
