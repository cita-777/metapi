import React from 'react';
import { createPortal } from 'react-dom';

type ModalPresence = {
  shouldRender: boolean;
  isVisible: boolean;
};

type DownstreamCreateForm = {
  name: string;
  key: string;
  description: string;
  maxCost: string;
  maxRequests: string;
  expiresAt: string;
  selectedModels: string[];
  selectedGroupRouteIds: number[];
};

type DownstreamApiKeyModalProps = {
  presence: ModalPresence;
  editingDownstreamId: number | null;
  downstreamCreate: DownstreamCreateForm;
  downstreamSaving: boolean;
  inputStyle: React.CSSProperties;
  onChange: (updater: (prev: DownstreamCreateForm) => DownstreamCreateForm) => void;
  onOpenSelector: () => Promise<void> | void;
  onClose: () => void;
  onSave: () => Promise<void> | void;
};

export default function DownstreamApiKeyModal({
  presence,
  editingDownstreamId,
  downstreamCreate,
  downstreamSaving,
  inputStyle,
  onChange,
  onOpenSelector,
  onClose,
  onSave,
}: DownstreamApiKeyModalProps) {
  if (!presence.shouldRender) {
    return null;
  }

  const modal = (
    <div className={`modal-backdrop ${presence.isVisible ? '' : 'is-closing'}`.trim()} onClick={onClose}>
      <div
        className={`modal-content ${presence.isVisible ? '' : 'is-closing'}`.trim()}
        style={{ maxWidth: 860 }}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="modal-header">
          {editingDownstreamId ? '编辑下游 API Key' : '新增下游 API Key'}
        </div>
        <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 10 }}>
            <input
              value={downstreamCreate.name}
              onChange={(e) => onChange((prev) => ({ ...prev, name: e.target.value }))}
              placeholder="Name (e.g. cc-project)"
              style={inputStyle}
            />
            <input
              value={downstreamCreate.key}
              onChange={(e) => onChange((prev) => ({ ...prev, key: e.target.value.trim() }))}
              placeholder="sk-xxxx"
              style={{ ...inputStyle, fontFamily: 'var(--font-mono)' }}
            />
            <input
              value={downstreamCreate.maxCost}
              onChange={(e) => onChange((prev) => ({ ...prev, maxCost: e.target.value }))}
              placeholder="最大费用（可选）"
              type="number"
              min={0}
              step={0.000001}
              style={inputStyle}
            />
            <input
              value={downstreamCreate.maxRequests}
              onChange={(e) => onChange((prev) => ({ ...prev, maxRequests: e.target.value }))}
              placeholder="最大请求数（可选）"
              type="number"
              min={0}
              step={1}
              style={inputStyle}
            />
            <input
              value={downstreamCreate.expiresAt}
              onChange={(e) => onChange((prev) => ({ ...prev, expiresAt: e.target.value }))}
              type="datetime-local"
              placeholder="过期时间（可选）"
              style={inputStyle}
            />
            <input
              value={downstreamCreate.description}
              onChange={(e) => onChange((prev) => ({ ...prev, description: e.target.value }))}
              placeholder="备注（可选）"
              style={inputStyle}
            />
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>
              已选模型 {downstreamCreate.selectedModels.length} 个，已选群组 {downstreamCreate.selectedGroupRouteIds.length} 个
            </div>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              <button
                onClick={() => void onOpenSelector()}
                className="btn btn-ghost"
                style={{ border: '1px solid var(--color-border)' }}
              >
                勾选模型和群组
              </button>
              {(downstreamCreate.selectedModels.length > 0 || downstreamCreate.selectedGroupRouteIds.length > 0) ? (
                <button
                  onClick={() => onChange((prev) => ({ ...prev, selectedModels: [], selectedGroupRouteIds: [] }))}
                  className="btn btn-link btn-link-warning"
                >
                  清空选择
                </button>
              ) : null}
            </div>
          </div>
        </div>
        <div className="modal-footer">
          <button onClick={onClose} className="btn btn-ghost">取消</button>
          <button onClick={() => void onSave()} disabled={downstreamSaving} className="btn btn-primary">
            {downstreamSaving
              ? <><span className="spinner spinner-sm" style={{ borderTopColor: 'white', borderColor: 'rgba(255,255,255,0.3)' }} /> 保存中...</>
              : (editingDownstreamId ? '更新 API Key' : '新增 API Key')}
          </button>
        </div>
      </div>
    </div>
  );

  return typeof document !== 'undefined' ? createPortal(modal, document.body) : modal;
}
