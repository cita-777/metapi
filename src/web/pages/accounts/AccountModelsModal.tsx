import React from 'react';
import CenteredModal from '../../components/CenteredModal.js';

type AccountModelRow = {
  name: string;
  latencyMs: number | null;
  disabled: boolean;
  isManual?: boolean;
};

type AccountModelModalState = {
  open: boolean;
  account: any | null;
  models: AccountModelRow[];
  pendingDisabled: Set<string>;
  loading: boolean;
  saving: boolean;
  siteName: string;
  manualModelsInput: string;
  addingManualModels: boolean;
};

type AccountModelsModalProps = {
  modelModal: AccountModelModalState;
  inputStyle: React.CSSProperties;
  onClose: () => void;
  onSave: () => void;
  onRefresh: () => Promise<void> | void;
  onToggleModelDisabled: (modelName: string) => void;
  onSetPendingDisabled: (pendingDisabled: Set<string>) => void;
  onManualInputChange: (value: string) => void;
  onAddManualModels: () => Promise<void> | void;
};

export default function AccountModelsModal({
  modelModal,
  inputStyle,
  onClose,
  onSave,
  onRefresh,
  onToggleModelDisabled,
  onSetPendingDisabled,
  onManualInputChange,
  onAddManualModels,
}: AccountModelsModalProps) {
  return (
    <CenteredModal
      open={modelModal.open}
      onClose={onClose}
      title={modelModal.siteName ? `模型管理 · ${modelModal.siteName}` : '模型管理'}
      maxWidth={600}
      footer={(
        <>
          <button onClick={onClose} className="btn btn-ghost">取消</button>
          <button
            onClick={onSave}
            disabled={modelModal.saving || modelModal.loading}
            className="btn btn-primary"
          >
            {modelModal.saving ? <><span className="spinner spinner-sm" />保存中...</> : '保存'}
          </button>
        </>
      )}
    >
      {modelModal.loading ? (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '48px 0', gap: 10 }}>
          <span className="spinner" />
          <span style={{ color: 'var(--color-text-muted)', fontSize: 14 }}>加载模型列表...</span>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {modelModal.models.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '32px 0' }}>
              <div style={{ fontSize: 32, marginBottom: 8 }}>🤖</div>
              <div style={{ fontSize: 14, color: 'var(--color-text-muted)', marginBottom: 8 }}>暂无可用模型</div>
              <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginBottom: 16 }}>请先点击账号操作栏中的「刷新」或「模型」按钮获取模型</div>
              <button
                onClick={() => void onRefresh()}
                className="btn btn-soft-primary"
              >
                立即获取模型
              </button>
            </div>
          ) : (
            <>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', userSelect: 'none' }}>
                  <input
                    type="checkbox"
                    checked={modelModal.pendingDisabled.size === 0}
                    ref={(el) => {
                      if (el) {
                        const total = modelModal.models.length;
                        const disabled = modelModal.pendingDisabled.size;
                        el.indeterminate = disabled > 0 && disabled < total;
                      }
                    }}
                    onChange={() => {
                      const allEnabled = modelModal.pendingDisabled.size === 0;
                      onSetPendingDisabled(allEnabled ? new Set(modelModal.models.map((model) => model.name)) : new Set());
                    }}
                    style={{ accentColor: 'var(--color-primary)', width: 15, height: 15 }}
                  />
                  <span style={{ fontSize: 13, color: 'var(--color-text-muted)' }}>
                    已启用 <strong style={{ color: 'var(--color-text-primary)' }}>{modelModal.models.length - modelModal.pendingDisabled.size}</strong> / {modelModal.models.length} 个模型
                  </span>
                </label>
                <div style={{ display: 'flex', gap: 6 }}>
                  <button
                    onClick={() => void onRefresh()}
                    disabled={modelModal.saving}
                    className="btn btn-ghost"
                    style={{ fontSize: 12, padding: '4px 10px' }}
                  >
                    刷新模型
                  </button>
                  <button
                    onClick={() => {
                      const next = new Set<string>();
                      for (const model of modelModal.models) {
                        if (!modelModal.pendingDisabled.has(model.name)) next.add(model.name);
                      }
                      onSetPendingDisabled(next);
                    }}
                    className="btn btn-ghost"
                    style={{ fontSize: 12, padding: '4px 10px' }}
                  >
                    反选
                  </button>
                  <button
                    onClick={() => onSetPendingDisabled(new Set(modelModal.models.map((model) => model.name)))}
                    className="btn btn-ghost"
                    style={{ fontSize: 12, padding: '4px 10px' }}
                  >
                    全部禁用
                  </button>
                  <button
                    onClick={() => onSetPendingDisabled(new Set())}
                    className="btn btn-ghost"
                    style={{ fontSize: 12, padding: '4px 10px' }}
                  >
                    全部启用
                  </button>
                </div>
              </div>

              <div style={{
                maxHeight: 280,
                overflowY: 'auto',
                border: '1px solid var(--color-border-light)',
                borderRadius: 'var(--radius-sm)',
              }}>
                {modelModal.models.map((model, idx) => {
                  const isDisabled = modelModal.pendingDisabled.has(model.name);
                  return (
                    <label
                      key={model.name}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: 10,
                        padding: '9px 14px',
                        cursor: 'pointer',
                        background: isDisabled ? 'var(--color-bg)' : undefined,
                        borderBottom: idx < modelModal.models.length - 1 ? '1px solid var(--color-border-light)' : undefined,
                        opacity: isDisabled ? 0.55 : 1,
                        transition: 'opacity 0.15s, background 0.15s',
                      }}
                    >
                      <input
                        type="checkbox"
                        checked={!isDisabled}
                        onChange={() => onToggleModelDisabled(model.name)}
                        style={{ accentColor: 'var(--color-primary)', width: 15, height: 15, flexShrink: 0 }}
                      />
                      <span style={{ flex: 1, fontSize: 13, fontFamily: 'var(--font-mono)', wordBreak: 'break-all' }}>
                        {model.name}
                      </span>
                      {model.latencyMs != null ? (
                        <span style={{ fontSize: 11, color: 'var(--color-text-muted)', flexShrink: 0 }}>
                          {model.latencyMs}ms
                        </span>
                      ) : null}
                      {model.isManual ? (
                        <span className="badge badge-info" style={{ fontSize: 10, flexShrink: 0, padding: '0 4px' }}>手动</span>
                      ) : null}
                      {isDisabled ? (
                        <span className="badge badge-error" style={{ fontSize: 10, flexShrink: 0 }}>禁用</span>
                      ) : null}
                    </label>
                  );
                })}
              </div>
              <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginTop: 4 }}>
                💡 禁用的模型将对整个站点生效，该站点下所有连接都不会使用这些模型进行代理。
              </div>
            </>
          )}

          <div style={{ marginTop: 16, padding: '12px', background: 'var(--color-bg)', border: '1px solid var(--color-border-light)', borderRadius: 'var(--radius-sm)' }}>
            <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 8, color: 'var(--color-text-primary)' }}>手动添加可用模型</div>
            <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginBottom: 8 }}>
              如果您的账号支持某些未在上方列表中显示的模型，可以在此手动添加（多个以英文逗号分隔）。
            </div>
            <div style={{ display: 'flex', gap: 8 }}>
              <input
                placeholder="例如: gpt-4-custom, claude-3-5-sonnet-20241022"
                value={modelModal.manualModelsInput}
                onChange={(e) => onManualInputChange(e.target.value)}
                style={{ ...inputStyle, flex: 1, fontFamily: 'var(--font-mono)' }}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && !modelModal.addingManualModels) {
                    void onAddManualModels();
                  }
                }}
              />
              <button
                disabled={!modelModal.manualModelsInput.trim() || modelModal.addingManualModels}
                onClick={() => void onAddManualModels()}
                className="btn btn-primary btn-sm"
                style={{ whiteSpace: 'nowrap' }}
              >
                {modelModal.addingManualModels ? <span className="spinner spinner-sm" /> : '添加'}
              </button>
            </div>
          </div>
        </div>
      )}
    </CenteredModal>
  );
}
