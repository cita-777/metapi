import { useEffect, useRef } from 'react';

type NextStepChoice = 'session' | 'apikey' | 'later';

type Props = {
  siteName: string;
  platform?: string | null;
  onChoice: (choice: NextStepChoice) => void;
  onClose: () => void;
};

export default function SiteCreatedModal({ siteName, platform, onChoice, onClose }: Props) {
  const dialogRef = useRef<HTMLDialogElement>(null);

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

  return (
    <dialog
      ref={dialogRef}
      className="modal"
      onCancel={(event) => {
        event.preventDefault();
        onClose();
      }}
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
          站点 <strong>"{siteName}"</strong> 已添加成功。接下来您想做什么？
        </p>

        <div className="modal-action" style={{ flexDirection: 'column', gap: 12 }}>
          <button
            className="btn btn-primary btn-block"
            onClick={() => onChoice('session')}
          >
            添加账号（用户名密码登录）
          </button>
          <button
            className="btn btn-outline btn-block"
            onClick={() => onChoice('apikey')}
          >
            添加 API Key
          </button>
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
