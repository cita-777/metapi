import CenteredModal from './CenteredModal.js';
import { getSiteInitializationPreset } from '../../shared/siteInitializationPresets.js';

type NextStepChoice = 'session' | 'apikey' | 'later';

type Props = {
  siteName: string;
  initializationPresetId?: string | null;
  initialSegment?: 'session' | 'apikey';
  sessionLabel?: string;
  onChoice: (choice: NextStepChoice) => void;
  onClose: () => void;
};

export default function SiteCreatedModal({
  siteName,
  initializationPresetId,
  initialSegment = 'session',
  sessionLabel = '添加账号（用户名密码登录）',
  onChoice,
  onClose,
}: Props) {
  const preset = getSiteInitializationPreset(initializationPresetId);
  const apiKeyFirst = initialSegment === 'apikey';
  const helperText = preset?.description
    || (apiKeyFirst
      ? '该平台更适合直接通过 Base URL + API Key 接入，后续再补模型初始化。'
      : '接下来您可以继续补充登录连接或 API Key。');
  const primaryAction = apiKeyFirst
    ? {
      choice: 'apikey' as const,
      label: '添加 API Key（推荐）',
    }
    : {
      choice: 'session' as const,
      label: sessionLabel,
    };
  const secondaryAction = apiKeyFirst
    ? {
      choice: 'session' as const,
      label: sessionLabel,
    }
    : {
      choice: 'apikey' as const,
      label: '添加 API Key',
    };

  return (
    <CenteredModal
      open
      onClose={onClose}
      title="站点创建成功"
      maxWidth={520}
      closeOnBackdrop
      closeOnEscape
      bodyStyle={{ display: 'flex', flexDirection: 'column', gap: 12 }}
      footer={(
        <>
          <button onClick={() => onChoice('later')} className="btn btn-ghost">
            稍后配置
          </button>
          <button
            onClick={() => onChoice(secondaryAction.choice)}
            className="btn btn-ghost"
            style={{ border: '1px solid var(--color-border)' }}
          >
            {secondaryAction.label}
          </button>
          <button
            onClick={() => onChoice(primaryAction.choice)}
            className="btn btn-primary"
          >
            {primaryAction.label}
          </button>
        </>
      )}
    >
      <div className="alert alert-success animate-scale-in" style={{ margin: 0 }}>
        <div className="alert-title">站点已添加成功</div>
        <div className="site-created-summary">
          站点 <strong>"{siteName}"</strong> 已加入列表，您现在可以继续补充连接信息。
        </div>
      </div>

      {preset ? (
        <div className="alert alert-info" style={{ margin: 0 }}>
          <div className="alert-title">{preset.label}</div>
          <div className="site-created-helper-text">
            {helperText}
          </div>
        </div>
      ) : (
        <p className="site-created-helper-text">
          {helperText}
        </p>
      )}

      <p className="site-created-note">
        提示：您可以随时在“站点管理”页面补充账号或 API Key。
      </p>
    </CenteredModal>
  );
}
