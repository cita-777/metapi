import React, { useEffect, useMemo, useState } from 'react';
import CenteredModal from '../../components/CenteredModal.js';
import { generateDownstreamSkKey } from '../helpers/generateDownstreamSkKey.js';

const PROXY_TOKEN_PREFIX = 'sk-';

export type DownstreamExcludedCredentialRef =
  | {
    kind: 'account_token';
    siteId: number;
    accountId: number;
    tokenId: number;
  }
  | {
    kind: 'default_api_key';
    siteId: number;
    accountId: number;
  };

export type DownstreamKeyEditorForm = {
  name: string;
  key: string;
  description: string;
  groupName: string;
  tags: string[];
  maxCost: string;
  maxRequests: string;
  expiresAt: string;
  enabled: boolean;
  selectedModels: string[];
  selectedGroupRouteIds: number[];
  siteWeightMultipliersText: string;
  excludedSiteIds: number[];
  excludedCredentialRefs: DownstreamExcludedCredentialRef[];
};

export type DownstreamSiteOption = {
  siteId: number;
  siteName: string;
  accountCount: number;
};

export type DownstreamCredentialOption = {
  key: string;
  ref: DownstreamExcludedCredentialRef;
  siteName: string;
  accountName: string;
  label: string;
  detail: string;
};

type RouteSelectorItem = {
  id: number;
  modelPattern: string;
  displayName?: string | null;
  enabled: boolean;
};

function parseTagText(value: string): string[] {
  return value
    .split(/[\r\n,，]+/g)
    .map((item) => item.trim())
    .filter(Boolean);
}

function normalizeTags(values: string[]): string[] {
  const result: string[] = [];
  const seen = new Set<string>();
  for (const raw of values) {
    const value = String(raw || '').trim();
    if (!value) continue;
    const normalized = value.slice(0, 32);
    const dedupeKey = normalized.toLowerCase();
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);
    result.push(normalized);
    if (result.length >= 20) break;
  }
  return result;
}

function uniqStrings(values: string[]): string[] {
  return [...new Set(values.map((value) => String(value || '').trim()).filter(Boolean))];
}

function uniqIds(values: number[]): number[] {
  return [...new Set(values.map((value) => Number(value)).filter((value) => Number.isFinite(value) && value > 0).map((value) => Math.trunc(value)))];
}

function isExactModelPattern(modelPattern: string): boolean {
  const normalized = modelPattern.trim();
  if (!normalized) return false;
  if (normalized.toLowerCase().startsWith('re:')) return false;
  return !/[\*\?]/.test(normalized);
}

function isGroupRouteOption(route: RouteSelectorItem): boolean {
  return !isExactModelPattern(route.modelPattern);
}

function routeTitle(route: RouteSelectorItem): string {
  const displayName = (route.displayName || '').trim();
  return displayName || route.modelPattern;
}

function tagChipStyle(kind: 'normal' | 'accent' = 'normal'): React.CSSProperties {
  return {
    display: 'inline-flex',
    alignItems: 'center',
    gap: 6,
    padding: '2px 8px',
    borderRadius: 999,
    fontSize: 11,
    border: '1px solid var(--color-border-light)',
    color: kind === 'accent' ? 'var(--color-primary)' : 'var(--color-text-secondary)',
    background: kind === 'accent'
      ? 'color-mix(in srgb, var(--color-primary) 10%, transparent)'
      : 'var(--color-bg-card)',
  };
}

function buildExcludedCredentialRefKey(ref: DownstreamExcludedCredentialRef): string {
  return ref.kind === 'account_token'
    ? `${ref.kind}:${ref.siteId}:${ref.accountId}:${ref.tokenId}`
    : `${ref.kind}:${ref.siteId}:${ref.accountId}`;
}

function normalizeExcludedSiteIds(values: number[]): number[] {
  return uniqIds(values).sort((left, right) => left - right);
}

function normalizeExcludedCredentialRefs(values: DownstreamExcludedCredentialRef[]): DownstreamExcludedCredentialRef[] {
  const deduped = new Map<string, DownstreamExcludedCredentialRef>();
  for (const value of values) {
    if (!value || !Number.isFinite(value.siteId) || !Number.isFinite(value.accountId)) continue;
    if (value.kind === 'account_token') {
      if (!Number.isFinite(value.tokenId)) continue;
      const normalized: DownstreamExcludedCredentialRef = {
        kind: 'account_token',
        siteId: Math.trunc(value.siteId),
        accountId: Math.trunc(value.accountId),
        tokenId: Math.trunc(value.tokenId),
      };
      deduped.set(buildExcludedCredentialRefKey(normalized), normalized);
      continue;
    }
    const normalized: DownstreamExcludedCredentialRef = {
      kind: 'default_api_key',
      siteId: Math.trunc(value.siteId),
      accountId: Math.trunc(value.accountId),
    };
    deduped.set(buildExcludedCredentialRefKey(normalized), normalized);
  }
  return Array.from(deduped.values()).sort((left, right) => buildExcludedCredentialRefKey(left).localeCompare(buildExcludedCredentialRefKey(right)));
}

export function TagInput({
  tags,
  onChange,
  suggestions = [],
  placeholder,
}: {
  tags: string[];
  onChange: (tags: string[]) => void;
  suggestions?: string[];
  placeholder?: string;
}) {
  const [draft, setDraft] = useState('');

  useEffect(() => {
    setDraft('');
  }, [tags.length]);

  const commitDraft = () => {
    const nextTags = normalizeTags([...tags, ...parseTagText(draft)]);
    if (nextTags.length !== tags.length) {
      onChange(nextTags);
    }
    setDraft('');
  };

  const removeTag = (target: string) => {
    onChange(tags.filter((tag) => tag !== target));
  };

  const suggestionPool = suggestions.filter((tag) => !tags.some((current) => current.toLowerCase() === tag.toLowerCase())).slice(0, 12);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      <div style={{ border: '1px solid var(--color-border)', borderRadius: 'var(--radius-sm)', background: 'var(--color-bg)', padding: 10, display: 'flex', flexDirection: 'column', gap: 8 }}>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
          {tags.map((tag) => (
            <button
              key={tag}
              type="button"
              onClick={() => removeTag(tag)}
              style={{ ...tagChipStyle('accent'), cursor: 'pointer' }}
              title={`移除 ${tag}`}
            >
              <span>{tag}</span>
              <span aria-hidden="true">×</span>
            </button>
          ))}
        </div>
        <input
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onBlur={commitDraft}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ',') {
              e.preventDefault();
              commitDraft();
            } else if (e.key === 'Backspace' && !draft && tags.length > 0) {
              e.preventDefault();
              onChange(tags.slice(0, -1));
            }
          }}
          placeholder={placeholder || '输入标签后按回车或逗号'}
          style={{ width: '100%', border: 'none', outline: 'none', background: 'transparent', color: 'var(--color-text-primary)', padding: 0, fontSize: 13, lineHeight: 1.45 }}
        />
      </div>
      {suggestionPool.length > 0 ? (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
          {suggestionPool.map((tag) => (
            <button
              key={tag}
              type="button"
              className="btn btn-ghost"
              style={{ ...tagChipStyle(), cursor: 'pointer' }}
              onClick={() => onChange(normalizeTags([...tags, tag]))}
            >
              {tag}
            </button>
          ))}
        </div>
      ) : null}
    </div>
  );
}

export default function DownstreamKeyEditorModal({
  open,
  editingItem,
  form,
  onChange,
  onClose,
  onSave,
  saving,
  routeOptions,
  groupSuggestions,
  tagSuggestions,
  exclusionSourceLoading,
  siteOptions,
  credentialOptions,
}: {
  open: boolean;
  editingItem: { id: number } | null;
  form: DownstreamKeyEditorForm;
  onChange: (updater: (prev: DownstreamKeyEditorForm) => DownstreamKeyEditorForm) => void;
  onClose: () => void;
  onSave: () => void;
  saving: boolean;
  routeOptions: RouteSelectorItem[];
  groupSuggestions: string[];
  tagSuggestions: string[];
  exclusionSourceLoading: boolean;
  siteOptions: DownstreamSiteOption[];
  credentialOptions: DownstreamCredentialOption[];
}) {
  const [modelSearch, setModelSearch] = useState('');
  const [groupSearch, setGroupSearch] = useState('');
  const [siteSearch, setSiteSearch] = useState('');
  const [credentialSearch, setCredentialSearch] = useState('');
  const [advancedOpen, setAdvancedOpen] = useState(false);

  useEffect(() => {
    if (!open) {
      setModelSearch('');
      setGroupSearch('');
      setSiteSearch('');
      setCredentialSearch('');
      setAdvancedOpen(false);
    }
  }, [open]);

  const exactModels = useMemo(
    () => uniqStrings(routeOptions.filter((item) => isExactModelPattern(item.modelPattern)).map((item) => item.modelPattern)).sort((a, b) => a.localeCompare(b)),
    [routeOptions],
  );
  const groupRouteOptions = useMemo(
    () => routeOptions.filter(isGroupRouteOption),
    [routeOptions],
  );
  const validGroupRouteIdSet = useMemo(
    () => new Set(groupRouteOptions.map((route) => route.id)),
    [groupRouteOptions],
  );
  const normalizedSelectedGroupRouteIds = useMemo(
    () => uniqIds(form.selectedGroupRouteIds.filter((id) => validGroupRouteIdSet.has(id))),
    [form.selectedGroupRouteIds, validGroupRouteIdSet],
  );

  const filteredModels = useMemo(() => {
    const keyword = modelSearch.trim().toLowerCase();
    if (!keyword) return exactModels;
    return exactModels.filter((model) => model.toLowerCase().includes(keyword));
  }, [exactModels, modelSearch]);

  const filteredGroups = useMemo(() => {
    const keyword = groupSearch.trim().toLowerCase();
    if (!keyword) return groupRouteOptions;
    return groupRouteOptions.filter((route) => {
      const title = routeTitle(route).toLowerCase();
      return title.includes(keyword) || route.modelPattern.toLowerCase().includes(keyword);
    });
  }, [groupRouteOptions, groupSearch]);

  const filteredSites = useMemo(() => {
    const keyword = siteSearch.trim().toLowerCase();
    if (!keyword) return siteOptions;
    return siteOptions.filter((site) => site.siteName.toLowerCase().includes(keyword));
  }, [siteOptions, siteSearch]);

  const filteredCredentials = useMemo(() => {
    const keyword = credentialSearch.trim().toLowerCase();
    if (!keyword) return credentialOptions;
    return credentialOptions.filter((item) => (
      item.siteName.toLowerCase().includes(keyword)
      || item.accountName.toLowerCase().includes(keyword)
      || item.label.toLowerCase().includes(keyword)
      || item.detail.toLowerCase().includes(keyword)
    ));
  }, [credentialOptions, credentialSearch]);

  const selectedModelCount = form.selectedModels.length;
  const selectedGroupCount = normalizedSelectedGroupRouteIds.length;
  const inputStyle: React.CSSProperties = {
    width: '100%',
    padding: '10px 12px',
    border: '1px solid var(--color-border)',
    borderRadius: 'var(--radius-sm)',
    background: 'var(--color-bg)',
    color: 'var(--color-text-primary)',
    fontSize: 13,
    lineHeight: 1.45,
  };

  return (
    <CenteredModal
      open={open}
      onClose={onClose}
      title={editingItem ? '编辑下游密钥' : '新增下游密钥'}
      maxWidth={860}
      bodyStyle={{ display: 'flex', flexDirection: 'column', gap: 12 }}
      footer={(
        <>
          <button onClick={onClose} className="btn btn-ghost" disabled={saving}>取消</button>
          <button onClick={onSave} className="btn btn-primary" disabled={saving}>
            {saving
              ? <><span className="spinner spinner-sm" style={{ borderTopColor: 'white', borderColor: 'rgba(255,255,255,0.3)' }} /> 保存中...</>
              : (editingItem ? '保存修改' : '创建密钥')}
          </button>
        </>
      )}
    >
      <div className="info-tip" style={{ marginBottom: 0 }}>
        支持为每个下游密钥独立配置分组、标签、额度与有效期。高级限制项可按需展开。
      </div>

      <div className="downstream-key-modal-grid" style={{ gridTemplateColumns: '1fr' }}>
        <div className="downstream-key-modal-field downstream-key-modal-field-full">
          <div className="downstream-key-modal-label">名称</div>
          <input value={form.name} onChange={(e) => onChange((prev) => ({ ...prev, name: e.target.value }))} placeholder="例如：项目 A / 移动端" style={inputStyle} />
        </div>
        <div className="downstream-key-modal-field">
          <div className="downstream-key-modal-label">下游密钥</div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'stretch', minWidth: 0 }}>
            <input
              value={form.key}
              onChange={(e) => onChange((prev) => ({ ...prev, key: e.target.value }))}
              placeholder="sk-..."
              style={{ ...inputStyle, flex: 1, minWidth: 0, fontFamily: 'var(--font-mono)' }}
            />
            <button
              type="button"
              className="btn btn-ghost"
              style={{ flexShrink: 0, whiteSpace: 'nowrap', alignSelf: 'stretch' }}
              onClick={() => onChange((prev) => ({ ...prev, key: generateDownstreamSkKey(PROXY_TOKEN_PREFIX) }))}
            >
              随机
            </button>
          </div>
        </div>
        <div className="downstream-key-modal-field">
          <div className="downstream-key-modal-label">主分组</div>
          <input
            value={form.groupName}
            onChange={(e) => onChange((prev) => ({ ...prev, groupName: e.target.value }))}
            placeholder="例如：VIP / 内部项目 / A组"
            list="downstream-group-suggestions"
            style={inputStyle}
          />
        </div>
        <div className="downstream-key-modal-field">
          <div className="downstream-key-modal-label">请求额度</div>
          <input value={form.maxRequests} onChange={(e) => onChange((prev) => ({ ...prev, maxRequests: e.target.value }))} placeholder="留空表示不限" style={inputStyle} />
        </div>
        <div className="downstream-key-modal-field">
          <div className="downstream-key-modal-label">成本额度</div>
          <input value={form.maxCost} onChange={(e) => onChange((prev) => ({ ...prev, maxCost: e.target.value }))} placeholder="留空表示不限" style={inputStyle} />
        </div>
        <div className="downstream-key-modal-field">
          <div className="downstream-key-modal-label">过期时间</div>
          <input type="datetime-local" value={form.expiresAt} onChange={(e) => onChange((prev) => ({ ...prev, expiresAt: e.target.value }))} style={inputStyle} />
        </div>
        <label className="downstream-key-modal-toggle">
          <input type="checkbox" checked={form.enabled} onChange={(e) => onChange((prev) => ({ ...prev, enabled: e.target.checked }))} />
          <div>
            <div className="downstream-key-modal-toggle-title">创建后立即启用</div>
            <div className="downstream-key-modal-help">关闭后该密钥将无法继续分发请求</div>
          </div>
        </label>
      </div>

      <div className="downstream-key-modal-field downstream-key-modal-field-full">
        <div className="downstream-key-modal-label">备注说明</div>
        <textarea
          value={form.description}
          onChange={(e) => onChange((prev) => ({ ...prev, description: e.target.value }))}
          placeholder="填写业务场景、负责人或限制说明"
          style={{ ...inputStyle, minHeight: 84, resize: 'vertical' }}
        />
      </div>

      <div className="downstream-key-modal-field downstream-key-modal-field-full">
        <div className="downstream-key-modal-label">标签</div>
        <TagInput
          tags={form.tags}
          onChange={(tags) => onChange((prev) => ({ ...prev, tags }))}
          suggestions={tagSuggestions}
          placeholder="输入标签后按回车或逗号，例如：移动端、VIP、项目A"
        />
        <div className="downstream-key-modal-help">标签用于搜索、筛选和辅助归类，不影响路由与权限。</div>
      </div>

      <div className="downstream-key-advanced">
        <button type="button" className={`downstream-key-advanced-toggle ${advancedOpen ? 'is-open' : ''}`.trim()} onClick={() => setAdvancedOpen((value) => !value)}>
          <span>高级配置</span>
          <span style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>{advancedOpen ? '收起' : '展开'}</span>
        </button>
        {advancedOpen ? (
          <div className="downstream-key-advanced-content">
            <div className="downstream-key-modal-field downstream-key-modal-field-full">
              <div className="downstream-key-modal-label">站点倍率 JSON</div>
              <textarea
                value={form.siteWeightMultipliersText}
                onChange={(e) => onChange((prev) => ({ ...prev, siteWeightMultipliersText: e.target.value }))}
                placeholder={'例如：{\n  "1": 1.2,\n  "7": 0.8\n}'}
                style={{ ...inputStyle, minHeight: 96, resize: 'vertical', fontFamily: 'var(--font-mono)' }}
              />
              <div className="downstream-key-modal-help">用于对特定站点做分发倍率微调；留空或 `{}` 表示走默认倍率。</div>
            </div>

            <div className="downstream-key-advanced-grid" style={{ gridTemplateColumns: '1fr' }}>
              <div className="downstream-key-advanced-panel">
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
                  <div>
                    <div className="downstream-key-modal-section-title">模型白名单</div>
                    <div className="downstream-key-modal-help">只展示精确模型；未勾选时默认不允许任何精确模型，可点“全选”一次性放开。</div>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <button type="button" className="btn btn-ghost" style={{ border: '1px solid var(--color-border)' }} onClick={() => onChange((prev) => ({ ...prev, selectedModels: exactModels }))}>全选</button>
                    <button type="button" className="btn btn-ghost" style={{ border: '1px solid var(--color-border)' }} onClick={() => onChange((prev) => ({ ...prev, selectedModels: [] }))}>清空</button>
                  </div>
                </div>
                <div className="downstream-key-modal-meta">已选 {selectedModelCount} 个模型</div>
                <div className="toolbar-search" style={{ maxWidth: '100%' }}>
                  <svg width="16" height="16" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                  </svg>
                  <input value={modelSearch} onChange={(e) => setModelSearch(e.target.value)} placeholder="搜索模型" />
                </div>
                <div style={{ maxHeight: 280, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 8 }}>
                  {filteredModels.length === 0 ? (
                    <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>暂无匹配模型</div>
                  ) : filteredModels.map((model) => {
                    const checked = form.selectedModels.includes(model);
                    return (
                      <label key={model} style={{ display: 'flex', alignItems: 'center', gap: 10, cursor: 'pointer', padding: '8px 10px', borderRadius: 10, border: '1px solid var(--color-border-light)', background: checked ? 'color-mix(in srgb, var(--color-primary) 10%, var(--color-bg-card))' : 'var(--color-bg-card)' }}>
                        <input
                          type="checkbox"
                          checked={checked}
                          onChange={() => onChange((prev) => ({
                            ...prev,
                            selectedModels: checked ? prev.selectedModels.filter((item) => item !== model) : [...prev.selectedModels, model],
                          }))}
                        />
                        <code style={{ color: 'var(--color-text-primary)', fontSize: 12 }}>{model}</code>
                      </label>
                    );
                  })}
                </div>
              </div>

              <div className="downstream-key-advanced-panel">
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
                  <div>
                    <div className="downstream-key-modal-section-title">群组范围</div>
                    <div className="downstream-key-modal-help">限制可访问的群组路由；未勾选时默认不允许任何群组，可点“全选”一次性放开。</div>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <button type="button" className="btn btn-ghost" style={{ border: '1px solid var(--color-border)' }} onClick={() => onChange((prev) => ({ ...prev, selectedGroupRouteIds: groupRouteOptions.map((route) => route.id) }))}>全选</button>
                    <button type="button" className="btn btn-ghost" style={{ border: '1px solid var(--color-border)' }} onClick={() => onChange((prev) => ({ ...prev, selectedGroupRouteIds: [] }))}>清空</button>
                  </div>
                </div>
                <div className="downstream-key-modal-meta">已选 {selectedGroupCount} 个群组</div>
                <div className="toolbar-search" style={{ maxWidth: '100%' }}>
                  <svg width="16" height="16" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                  </svg>
                  <input value={groupSearch} onChange={(e) => setGroupSearch(e.target.value)} placeholder="搜索群组或模型模式" />
                </div>
                <div style={{ maxHeight: 280, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 8 }}>
                  {filteredGroups.length === 0 ? (
                    <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>暂无匹配群组</div>
                  ) : filteredGroups.map((route) => {
                    const checked = normalizedSelectedGroupRouteIds.includes(route.id);
                    return (
                      <label key={route.id} style={{ display: 'flex', alignItems: 'flex-start', gap: 10, cursor: 'pointer', padding: '8px 10px', borderRadius: 10, border: '1px solid var(--color-border-light)', background: checked ? 'color-mix(in srgb, var(--color-primary) 10%, var(--color-bg-card))' : 'var(--color-bg-card)' }}>
                        <input
                          type="checkbox"
                          checked={checked}
                          onChange={() => onChange((prev) => ({
                            ...prev,
                            selectedGroupRouteIds: checked
                              ? prev.selectedGroupRouteIds.filter((item) => item !== route.id)
                              : uniqIds([...prev.selectedGroupRouteIds.filter((item) => validGroupRouteIdSet.has(item)), route.id]),
                          }))}
                          style={{ marginTop: 2 }}
                        />
                        <div style={{ minWidth: 0 }}>
                          <div style={{ color: 'var(--color-text-primary)', fontSize: 13, fontWeight: 600 }}>
                            {routeTitle(route)}
                            {!route.enabled ? <span style={{ marginLeft: 8, fontSize: 11, color: 'var(--color-danger)' }}>已禁用</span> : null}
                          </div>
                          <code style={{ display: 'block', marginTop: 4, fontSize: 11, color: 'var(--color-text-muted)' }}>{route.modelPattern}</code>
                        </div>
                      </label>
                    );
                  })}
                </div>
              </div>

              <div className="downstream-key-advanced-panel">
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
                  <div>
                    <div className="downstream-key-modal-section-title">排除站点</div>
                    <div className="downstream-key-modal-help">命中的站点会直接跳过，不参与当前下游密钥的通道路由。</div>
                  </div>
                  <button type="button" className="btn btn-ghost" style={{ border: '1px solid var(--color-border)' }} onClick={() => onChange((prev) => ({ ...prev, excludedSiteIds: [] }))}>清空</button>
                </div>
                <div className="downstream-key-modal-meta">已排除 {form.excludedSiteIds.length} 个站点</div>
                <div className="toolbar-search" style={{ maxWidth: '100%' }}>
                  <svg width="16" height="16" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                  </svg>
                  <input value={siteSearch} onChange={(e) => setSiteSearch(e.target.value)} placeholder="搜索站点" />
                </div>
                <div style={{ maxHeight: 240, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 8 }}>
                  {exclusionSourceLoading ? (
                    <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>加载站点与令牌中...</div>
                  ) : filteredSites.length === 0 ? (
                    <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>暂无可排除站点</div>
                  ) : filteredSites.map((site) => {
                    const checked = form.excludedSiteIds.includes(site.siteId);
                    return (
                      <label key={site.siteId} style={{ display: 'flex', alignItems: 'center', gap: 10, cursor: 'pointer', padding: '8px 10px', borderRadius: 10, border: '1px solid var(--color-border-light)', background: checked ? 'color-mix(in srgb, var(--color-primary) 10%, var(--color-bg-card))' : 'var(--color-bg-card)' }}>
                        <input
                          type="checkbox"
                          checked={checked}
                          onChange={(e) => onChange((prev) => ({
                            ...prev,
                            excludedSiteIds: normalizeExcludedSiteIds(
                              e.target.checked
                                ? [...prev.excludedSiteIds, site.siteId]
                                : prev.excludedSiteIds.filter((item) => item !== site.siteId),
                            ),
                          }))}
                        />
                        <div style={{ minWidth: 0 }}>
                          <div style={{ color: 'var(--color-text-primary)', fontSize: 13, fontWeight: 600 }}>{site.siteName}</div>
                          <div style={{ marginTop: 4, fontSize: 11, color: 'var(--color-text-muted)' }}>{site.accountCount} 个账号</div>
                        </div>
                      </label>
                    );
                  })}
                </div>
              </div>

              <div className="downstream-key-advanced-panel">
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
                  <div>
                    <div className="downstream-key-modal-section-title">排除 API Key/令牌</div>
                    <div className="downstream-key-modal-help">支持排除显式令牌，以及 `tokenId` 为空时实际使用的默认 API Key。</div>
                  </div>
                  <button type="button" className="btn btn-ghost" style={{ border: '1px solid var(--color-border)' }} onClick={() => onChange((prev) => ({ ...prev, excludedCredentialRefs: [] }))}>清空</button>
                </div>
                <div className="downstream-key-modal-meta">已排除 {form.excludedCredentialRefs.length} 个凭证</div>
                <div className="toolbar-search" style={{ maxWidth: '100%' }}>
                  <svg width="16" height="16" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                  </svg>
                  <input value={credentialSearch} onChange={(e) => setCredentialSearch(e.target.value)} placeholder="搜索站点 / 账号 / 令牌" />
                </div>
                <div style={{ maxHeight: 280, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 8 }}>
                  {exclusionSourceLoading ? (
                    <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>加载站点与令牌中...</div>
                  ) : filteredCredentials.length === 0 ? (
                    <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>暂无可排除 API Key/令牌</div>
                  ) : filteredCredentials.map((item) => {
                    const checked = form.excludedCredentialRefs.some((ref) => buildExcludedCredentialRefKey(ref) === buildExcludedCredentialRefKey(item.ref));
                    return (
                      <label key={item.key} style={{ display: 'flex', alignItems: 'flex-start', gap: 10, cursor: 'pointer', padding: '8px 10px', borderRadius: 10, border: '1px solid var(--color-border-light)', background: checked ? 'color-mix(in srgb, var(--color-primary) 10%, var(--color-bg-card))' : 'var(--color-bg-card)' }}>
                        <input
                          type="checkbox"
                          checked={checked}
                          onChange={(e) => onChange((prev) => ({
                            ...prev,
                            excludedCredentialRefs: normalizeExcludedCredentialRefs(
                              e.target.checked
                                ? [...prev.excludedCredentialRefs, item.ref]
                                : prev.excludedCredentialRefs.filter((ref) => buildExcludedCredentialRefKey(ref) !== buildExcludedCredentialRefKey(item.ref)),
                            ),
                          }))}
                          style={{ marginTop: 2 }}
                        />
                        <div style={{ minWidth: 0 }}>
                          <div style={{ color: 'var(--color-text-primary)', fontSize: 13, fontWeight: 600 }}>{item.label}</div>
                          <div style={{ marginTop: 4, fontSize: 11, color: 'var(--color-text-muted)' }}>
                            {item.siteName} / {item.accountName}
                          </div>
                          <div style={{ marginTop: 2, fontSize: 11, color: 'var(--color-text-muted)' }}>{item.detail}</div>
                        </div>
                      </label>
                    );
                  })}
                </div>
              </div>
            </div>
          </div>
        ) : null}
      </div>
      <datalist id="downstream-group-suggestions">
        {groupSuggestions.map((group) => <option key={group} value={group} />)}
      </datalist>
    </CenteredModal>
  );
}
