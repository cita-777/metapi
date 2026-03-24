import React from 'react';
import { createPortal } from 'react-dom';

type ModalPresence = {
  shouldRender: boolean;
  isVisible: boolean;
};

type FactoryResetModalProps = {
  presence: ModalPresence;
  factoryResetting: boolean;
  factoryResetSecondsLeft: number;
  adminToken: string;
  onClose: () => void;
  onConfirm: () => void;
};

export default function FactoryResetModal({
  presence,
  factoryResetting,
  factoryResetSecondsLeft,
  adminToken,
  onClose,
  onConfirm,
}: FactoryResetModalProps) {
  if (!presence.shouldRender) {
    return null;
  }

  const confirmLabel = factoryResetting
    ? '重新初始化中...'
    : (factoryResetSecondsLeft > 0
      ? `确认重新初始化系统（${factoryResetSecondsLeft}s）`
      : '确认重新初始化系统');

  const modal = (
    <div className={`modal-backdrop ${presence.isVisible ? '' : 'is-closing'}`.trim()} onClick={onClose}>
      <div
        className={`modal-content ${presence.isVisible ? '' : 'is-closing'}`.trim()}
        style={{ maxWidth: 720, border: '1px solid color-mix(in srgb, var(--color-danger) 35%, var(--color-border))' }}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="modal-header" style={{ color: 'var(--color-danger)' }}>确认重新初始化系统</div>
        <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div style={{ padding: 12, borderRadius: 'var(--radius-sm)', background: 'var(--color-danger-bg)', color: 'var(--color-danger)', fontSize: 12, lineHeight: 1.8 }}>
            这是不可逆操作。系统会清空当前 metapi 使用中的全部数据库内容，并在成功后立即退出当前登录状态。
          </div>
          <div style={{ fontSize: 13, color: 'var(--color-text-secondary)', lineHeight: 1.9 }}>
            <div>• 当前若使用外部 MySQL/Postgres，也会先清空该外部库中的 metapi 数据。</div>
            <div>• 系统随后会强制切回默认 SQLite。</div>
            <div>• 管理员 Token 将重置为 <code style={{ fontFamily: 'var(--font-mono)' }}>{adminToken}</code>。</div>
            <div>• 完成后会立即退出登录并刷新页面，回到当前首装初始状态。</div>
          </div>
        </div>
        <div className="modal-footer">
          <button onClick={onClose} disabled={factoryResetting} className="btn btn-ghost">取消</button>
          <button onClick={onConfirm} disabled={factoryResetting || factoryResetSecondsLeft > 0} className="btn btn-danger">
            {factoryResetting
              ? <><span className="spinner spinner-sm" style={{ borderTopColor: 'white', borderColor: 'rgba(255,255,255,0.3)' }} /> {confirmLabel}</>
              : confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );

  return typeof document !== 'undefined' ? createPortal(modal, document.body) : modal;
}
