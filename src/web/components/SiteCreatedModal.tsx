import { useEffect, useRef } from 'react';
import { getSiteInitializationPreset } from '../../shared/siteInitializationPresets.js';

type NextStepChoice = 'session' | 'apikey' | 'later';

type Props = {
  siteName: string;
  initializationPresetId?: string | null;
  initialSegment?: 'session' | 'apikey';
  onChoice: (choice: NextStepChoice) => void;
  onClose: () => void;
};

export default function SiteCreatedModal({
  siteName,
  initializationPresetId,
  initialSegment = 'session',
  onChoice,
  onClose,
}: Props) {
  const dialogRef = useRef<HTMLDialogElement>(null);
  const preset = getSiteInitializationPreset(initializationPresetId);
  const apiKeyFirst = initialSegment === 'apikey';
  const helperText = preset?.description
    || (apiKeyFirst
      ? '该平台更适合直接通过 Base URL + API Key 接入，后续再补模型初始化。'
      : '接下来您可以继续补充登录连接或 API Key。');

  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;

    if (!dialog.open) {
      dialog.showModal();
    }

    return () => {
      if (dialog.open) {
        dialog.close();
      }
    };
  }, []);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape') {
      e.preventDefault();
      onChoice('later');
    }
  };

  return (
    <dialog
      ref={dialogRef}
      className="modal"
      onCancel={(e) => {
        e.preventDefault();
        onClose();
      }}
      onKeyDown={handleKeyDown}
      onClick={(e) => {
        if (e.target === dialogRef.current) {
          onChoice('later');
        }
      }}
    >
      <div className="modal-box" style={{ maxWidth: 480 }}>
        <h3 className="font-bold text-lg mb-2">
          站点创建成功
        </h3>
        <p className="py-2 text-sm" style={{ color: 'var(--color-text-muted)' }}>
          站点 <strong>"{siteName}"</strong> 已添加成功。
        </p>
        {preset && (
          <div className="alert alert-info" style={{ marginBottom: 12 }}>
            <div className="alert-title">{preset.label}</div>
            <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginTop: 4, lineHeight: 1.7 }}>
              {helperText}
            </div>
          </div>
        )}
        {!preset && (
          <p className="py-1 text-sm" style={{ color: 'var(--color-text-muted)' }}>
            {helperText}
          </p>
        )}

        <div className="modal-action" style={{ flexDirection: 'column', gap: 12 }}>
          {apiKeyFirst ? (
            <button
              className="btn btn-primary btn-block"
              onClick={() => onChoice('apikey')}
            >
              添加 API Key（推荐）
            </button>
          ) : (
            <button
              className="btn btn-primary btn-block"
              onClick={() => onChoice('session')}
            >
              添加账号（用户名密码登录）
            </button>
          )}
          {!apiKeyFirst && (
            <button
              className="btn btn-outline btn-block"
              onClick={() => onChoice('apikey')}
            >
              添加 API Key
            </button>
          )}
          <button
            className="btn btn-ghost btn-block"
            onClick={() => onChoice('later')}
          >
            稍后配置
          </button>
        </div>

        <p className="text-xs mt-3" style={{ color: 'var(--color-text-muted)' }}>
          提示：您可以随时在"站点管理"页面配置账号信息
        </p>
      </div>
    </dialog>
  );
}
