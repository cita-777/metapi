import React from 'react';
import { createPortal } from 'react-dom';
import { BrandGlyph, InlineBrandIcon, getBrand } from '../../components/BrandIcon.js';
import {
  resolveRouteBrand,
  resolveRouteIcon,
  resolveRouteTitle,
} from '../token-routes/utils.js';

type RouteSelectorItem = {
  id: number;
  modelPattern: string;
  displayName?: string | null;
  displayIcon?: string | null;
  enabled: boolean;
};

type ModalPresence = {
  shouldRender: boolean;
  isVisible: boolean;
};

type DownstreamRouteSelection = {
  selectedModels: string[];
  selectedGroupRouteIds: number[];
};

type RouteSelectorModalProps = {
  presence: ModalPresence;
  loading: boolean;
  exactModelOptions: string[];
  filteredExactModelOptions: string[];
  groupRouteOptions: RouteSelectorItem[];
  filteredGroupRouteOptions: RouteSelectorItem[];
  selectorModelSearch: string;
  selectorGroupSearch: string;
  onSelectorModelSearchChange: (value: string) => void;
  onSelectorGroupSearchChange: (value: string) => void;
  selection: DownstreamRouteSelection;
  onToggleModelSelection: (modelName: string) => void;
  onToggleGroupRouteSelection: (routeId: number) => void;
  onClose: () => void;
  inputStyle: React.CSSProperties;
};

export default function RouteSelectorModal({
  presence,
  loading,
  exactModelOptions,
  filteredExactModelOptions,
  groupRouteOptions,
  filteredGroupRouteOptions,
  selectorModelSearch,
  selectorGroupSearch,
  onSelectorModelSearchChange,
  onSelectorGroupSearchChange,
  selection,
  onToggleModelSelection,
  onToggleGroupRouteSelection,
  onClose,
  inputStyle,
}: RouteSelectorModalProps) {
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
        <div className="modal-header">勾选模型和群组</div>
        <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>
            选择结果会保存到当前下游 API Key：精确模型用于模型白名单，群组用于路由范围限制。
          </div>
          {loading ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, color: 'var(--color-text-muted)' }}>
              <span className="spinner spinner-sm" />
              加载路由中...
            </div>
          ) : (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 12 }}>
              <div style={{ border: '1px solid var(--color-border-light)', borderRadius: 'var(--radius-sm)', padding: 10 }}>
                <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 8 }}>
                  精确模型 ({selectorModelSearch.trim()
                    ? `${filteredExactModelOptions.length}/${exactModelOptions.length}`
                    : exactModelOptions.length})
                </div>
                <input
                  value={selectorModelSearch}
                  onChange={(e) => onSelectorModelSearchChange(e.target.value)}
                  placeholder="搜索精确模型（支持模糊匹配）"
                  style={{ ...inputStyle, padding: '8px 10px', fontSize: 12, marginBottom: 8 }}
                />
                <div style={{ maxHeight: 280, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 8 }}>
                  {exactModelOptions.length === 0 ? (
                    <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>暂无可选精确模型</div>
                  ) : filteredExactModelOptions.length === 0 ? (
                    <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>没有匹配的精确模型</div>
                  ) : filteredExactModelOptions.map((modelName) => {
                    const checked = selection.selectedModels.includes(modelName);
                    const brand = getBrand(modelName);
                    return (
                      <label
                        key={modelName}
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: 10,
                          cursor: 'pointer',
                          border: `1px solid ${checked ? 'color-mix(in srgb, var(--color-primary) 45%, transparent)' : 'var(--color-border-light)'}`,
                          borderRadius: 10,
                          padding: '8px 10px',
                          background: checked
                            ? 'color-mix(in srgb, var(--color-primary) 9%, var(--color-bg-card))'
                            : 'var(--color-bg-card)',
                          transition: 'all 0.15s ease',
                        }}
                      >
                        <input
                          type="checkbox"
                          checked={checked}
                          onChange={() => onToggleModelSelection(modelName)}
                          style={{ width: 18, height: 18, accentColor: 'var(--color-primary)', flexShrink: 0 }}
                        />
                        <div style={{ minWidth: 0, display: 'flex', flexDirection: 'column', gap: 4 }}>
                          <code
                            style={{
                              fontWeight: 600,
                              fontSize: 12,
                              background: 'var(--color-bg)',
                              padding: '4px 10px',
                              borderRadius: 8,
                              color: 'var(--color-text-primary)',
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: 6,
                              maxWidth: '100%',
                            }}
                          >
                            {brand ? (
                              <InlineBrandIcon model={modelName} size={18} />
                            ) : (
                              <span
                                style={{
                                  width: 18,
                                  height: 18,
                                  borderRadius: 6,
                                  background: 'var(--color-bg-card)',
                                  display: 'inline-flex',
                                  alignItems: 'center',
                                  justifyContent: 'center',
                                  fontSize: 10,
                                  color: 'var(--color-text-muted)',
                                  flexShrink: 0,
                                }}
                              >
                                {modelName.slice(0, 1).toUpperCase()}
                              </span>
                            )}
                            <span style={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>
                              {modelName}
                            </span>
                          </code>
                          {brand ? (
                            <div style={{ fontSize: 11, color: 'var(--color-text-muted)', paddingLeft: 6 }}>
                              {brand.name}
                            </div>
                          ) : null}
                        </div>
                      </label>
                    );
                  })}
                </div>
              </div>

              <div style={{ border: '1px solid var(--color-border-light)', borderRadius: 'var(--radius-sm)', padding: 10 }}>
                <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 8 }}>
                  群组 ({selectorGroupSearch.trim()
                    ? `${filteredGroupRouteOptions.length}/${groupRouteOptions.length}`
                    : groupRouteOptions.length})
                </div>
                <input
                  value={selectorGroupSearch}
                  onChange={(e) => onSelectorGroupSearchChange(e.target.value)}
                  placeholder="Search groups (name / pattern)"
                  style={{ ...inputStyle, padding: '8px 10px', fontSize: 12, marginBottom: 8 }}
                />
                <div style={{ maxHeight: 280, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 8 }}>
                  {groupRouteOptions.length === 0 ? (
                    <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>暂无可选群组</div>
                  ) : filteredGroupRouteOptions.length === 0 ? (
                    <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>没有匹配的群组</div>
                  ) : filteredGroupRouteOptions.map((route) => {
                    const checked = selection.selectedGroupRouteIds.includes(route.id);
                    const routeTitle = resolveRouteTitle(route);
                    const routeIcon = resolveRouteIcon(route);
                    const routeBrand = resolveRouteBrand(route);
                    return (
                      <label
                        key={route.id}
                        style={{
                          display: 'flex',
                          alignItems: 'flex-start',
                          gap: 10,
                          cursor: 'pointer',
                          border: `1px solid ${checked ? 'color-mix(in srgb, var(--color-primary) 45%, transparent)' : 'var(--color-border-light)'}`,
                          borderRadius: 10,
                          padding: '8px 10px',
                          background: checked
                            ? 'color-mix(in srgb, var(--color-primary) 9%, var(--color-bg-card))'
                            : 'var(--color-bg-card)',
                          transition: 'all 0.15s ease',
                        }}
                      >
                        <input
                          type="checkbox"
                          style={{ marginTop: 4, width: 18, height: 18, accentColor: 'var(--color-primary)', flexShrink: 0 }}
                          checked={checked}
                          onChange={() => onToggleGroupRouteSelection(route.id)}
                        />
                        <div style={{ minWidth: 0, display: 'flex', flexDirection: 'column', gap: 4 }}>
                          <code
                            style={{
                              fontWeight: 600,
                              fontSize: 12,
                              background: 'var(--color-bg)',
                              padding: '4px 10px',
                              borderRadius: 8,
                              color: 'var(--color-text-primary)',
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: 6,
                              maxWidth: '100%',
                            }}
                          >
                            <span
                              style={{
                                width: 18,
                                height: 18,
                                display: 'inline-flex',
                                alignItems: 'center',
                                justifyContent: 'center',
                                borderRadius: 6,
                                background: 'var(--color-bg-card)',
                                flexShrink: 0,
                                overflow: 'hidden',
                                fontSize: 12,
                                lineHeight: 1,
                              }}
                            >
                              {routeIcon.kind === 'brand' ? (
                                <BrandGlyph
                                  icon={routeIcon.value}
                                  alt={routeTitle}
                                  size={18}
                                  fallbackText={routeTitle}
                                />
                              ) : routeIcon.kind === 'text' ? (
                                routeIcon.value
                              ) : routeIcon.kind === 'auto' && routeBrand ? (
                                <BrandGlyph brand={routeBrand} alt={routeTitle} size={18} fallbackText={routeTitle} />
                              ) : routeIcon.kind === 'auto' ? (
                                <InlineBrandIcon model={route.modelPattern} size={18} />
                              ) : routeIcon.kind === 'none' ? null : null}
                            </span>
                            <span style={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>
                              {routeTitle}
                            </span>
                            {!route.enabled ? (
                              <span
                                style={{
                                  fontSize: 10,
                                  padding: '1px 6px',
                                  borderRadius: 999,
                                  background: 'var(--color-danger-bg)',
                                  color: 'var(--color-danger)',
                                }}
                              >
                                已禁用
                              </span>
                            ) : null}
                          </code>
                          <code style={{ fontSize: 11, color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)', paddingLeft: 6 }}>
                            {route.modelPattern}
                          </code>
                        </div>
                      </label>
                    );
                  })}
                </div>
              </div>
            </div>
          )}
        </div>
        <div className="modal-footer">
          <button onClick={onClose} className="btn btn-ghost">关闭</button>
        </div>
      </div>
    </div>
  );

  return typeof document !== 'undefined' ? createPortal(modal, document.body) : modal;
}
