import { Dialog, type DialogPresence } from '../../components/ui/Dialog.js';
import { AsyncButton, Button } from '../../components/ui/Button.js';

type ModalPresence = DialogPresence;

type FactoryResetModalProps = {
  presence: ModalPresence;
  factoryResetting: boolean;
  factoryResetSecondsLeft: number;
  adminToken: string;
  onClose: () => void;
  onConfirm: () => void;
};

/**
 * Destructive reset confirmation surface.
 *
 * The settings page owns the open/exit presence state; handing that state to
 * the shared Dialog keeps the existing animation timing while centralising
 * portal, focus, scroll-lock, and accessibility behaviour.
 */
export default function FactoryResetModal({
  presence,
  factoryResetting,
  factoryResetSecondsLeft,
  adminToken,
  onClose,
  onConfirm,
}: FactoryResetModalProps) {
  const confirmLabel = factoryResetting
    ? '重新初始化中...'
    : (factoryResetSecondsLeft > 0
      ? `确认重新初始化系统（${factoryResetSecondsLeft}s）`
      : '确认重新初始化系统');

  return (
    <Dialog
      open={presence.isVisible}
      onClose={onClose}
      presence={presence}
      title={<span style={{ color: 'var(--color-danger)' }}>确认重新初始化系统</span>}
      maxWidth={720}
      contentStyle={{ border: '1px solid color-mix(in srgb, var(--color-danger) 35%, var(--color-border))' }}
      bodyStyle={{ display: 'flex', flexDirection: 'column', gap: 12 }}
      closeOnBackdrop
      closeOnEscape={false}
      showCloseButton={false}
      ariaLabel="确认重新初始化系统"
      footer={(
        <>
          <Button onClick={onClose} disabled={factoryResetting} variant="ghost">
            取消
          </Button>
          <AsyncButton
            onClick={onConfirm}
            disabled={factoryResetting || factoryResetSecondsLeft > 0}
            variant="danger"
            pending={factoryResetting}
            loadingLabel={confirmLabel}
          >
            {confirmLabel}
          </AsyncButton>
        </>
      )}
    >
      <div style={{ padding: 12, borderRadius: 'var(--radius-sm)', background: 'var(--color-danger-bg)', color: 'var(--color-danger)', fontSize: 12, lineHeight: 1.8 }}>
        这是不可逆操作。系统会清空当前 metapi 使用中的全部数据库内容，并在成功后立即退出当前登录状态。
      </div>
      <div style={{ fontSize: 13, color: 'var(--color-text-secondary)', lineHeight: 1.9 }}>
        <div>• 当前若使用外部 MySQL/Postgres，也会先清空该外部库中的 metapi 数据。</div>
        <div>• 系统随后会强制切回默认 SQLite。</div>
        <div>• 管理员 Token 将重置为 <code style={{ fontFamily: 'var(--font-mono)' }}>{adminToken}</code>。</div>
        <div>• 完成后会立即退出登录并刷新页面，回到当前首装初始状态。</div>
      </div>
    </Dialog>
  );
}
