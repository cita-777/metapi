import React from 'react';
import CenteredModal from '../../components/CenteredModal.js';

export type OAuthModelItem = {
  name: string;
  latencyMs: number | null;
  disabled: boolean;
  isManual?: boolean;
};

type OAuthModelsModalProps = {
  open: boolean;
  title: string;
  siteName?: string | null;
  loading: boolean;
  refreshing: boolean;
  models: OAuthModelItem[];
  totalCount: number;
  disabledCount: number;
  onClose: () => void;
  onRefresh: () => Promise<void> | void;
};

export default function OAuthModelsModal({
  open,
  title,
  siteName,
  loading,
  refreshing,
  models,
  totalCount,
  disabledCount,
  onClose,
  onRefresh,
}: OAuthModelsModalProps) {
  const enabledCount = Math.max(0, totalCount - disabledCount);

  return (
    <CenteredModal
      open={open}
      onClose={onClose}
      title={title}
      maxWidth={620}
      footer={(
        <>
          <button type="button" className="btn btn-ghost" onClick={onClose}>
            关闭
          </button>
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => void onRefresh()}
            disabled={loading || refreshing}
          >
            {refreshing ? <><span className="spinner spinner-sm" />刷新中...</> : '刷新模型'}
          </button>
        </>
      )}
    >
      {loading ? (
        <div className="oauth-models-empty">
          <span className="spinner" />
          <span className="oauth-models-empty-copy">正在加载模型列表...</span>
        </div>
      ) : (
        <div className="oauth-models-layout">
          <div className="oauth-models-summary">
            <div className="oauth-models-summary-title">
              {siteName ? `${siteName} · 共 ${totalCount} 个模型` : `共 ${totalCount} 个模型`}
            </div>
            <div className="oauth-models-summary-copy">
              已启用 {enabledCount} 个，已禁用 {disabledCount} 个。点击“刷新模型”可重新拉取当前账号支持的模型列表。
            </div>
          </div>

          {models.length === 0 ? (
            <div className="oauth-models-empty">
              <div className="oauth-models-empty-title">暂无模型</div>
              <div className="oauth-models-empty-copy">当前账号还没有同步到可用模型，可点击右下角“刷新模型”重试。</div>
            </div>
          ) : (
            <div className="oauth-models-list">
              {models.map((model) => (
                <div key={model.name} className={`oauth-models-item ${model.disabled ? 'is-disabled' : ''}`.trim()}>
                  <div className="oauth-models-item-main">
                    <div className="oauth-models-item-name">{model.name}</div>
                    <div className="oauth-models-item-meta">
                      {model.latencyMs != null ? <span>{model.latencyMs}ms</span> : null}
                      {model.isManual ? <span className="badge badge-info oauth-models-badge">手动</span> : null}
                      {model.disabled ? <span className="badge badge-warning oauth-models-badge">禁用</span> : null}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </CenteredModal>
  );
}
