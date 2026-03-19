import { useEffect, useMemo, useState, type Dispatch, type ReactNode, type SetStateAction } from 'react';
import { BrandGlyph, InlineBrandIcon, hashColor, type BrandInfo } from '../../components/BrandIcon.js';
import CenteredModal from '../../components/CenteredModal.js';
import ModernSelect from '../../components/ModernSelect.js';
import { tr } from '../../i18n.js';
import type { RouteIconOption, RouteMode, RouteSummaryRow } from './types.js';
import {
  ROUTE_ICON_NONE_VALUE,
  getModelPatternError,
  isExactModelPattern,
  isRouteIconNoneValue,
  matchesModelPattern,
  normalizeRouteDisplayIconValue,
  normalizeRouteMode,
  resolveEndpointTypeIconModel,
  resolveRouteBrand,
  siteAvatarLetters,
} from './utils.js';

type RouteEditorForm = {
  routeMode: RouteMode;
  displayName: string;
  displayIcon: string;
  modelPattern: string;
  sourceRouteIds: number[];
  advancedOpen: boolean;
};

type ManualRoutePanelProps = {
  show: boolean;
  editingRouteId: number | null;
  form: RouteEditorForm;
  setForm: Dispatch<SetStateAction<RouteEditorForm>>;
  saving: boolean;
  canSave: boolean;
  routeIconSelectOptions: RouteIconOption[];
  previewModelSamples: string[];
  exactSourceRouteOptions: RouteSummaryRow[];
  sourceEndpointTypesByRouteId: Record<number, string[]>;
  onSave: () => void;
  onCancel: () => void;
};

function renderRouteOptionLabel(route: RouteSummaryRow): string {
  const displayName = (route.displayName || '').trim();
  return displayName || route.modelPattern;
}

function toggleSourceRouteId(sourceRouteIds: number[], routeId: number): number[] {
  if (sourceRouteIds.includes(routeId)) {
    return sourceRouteIds.filter((id) => id !== routeId);
  }
  return [...sourceRouteIds, routeId].sort((a, b) => a - b);
}

function SearchField({
  value,
  onChange,
  placeholder,
}: {
  value: string;
  onChange: (nextValue: string) => void;
  placeholder: string;
}) {
  return (
    <div className="toolbar-search" style={{ width: '100%' }}>
      <svg width="14" height="14" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
      </svg>
      <input
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
      />
    </div>
  );
}

function FilterChip({
  active,
  label,
  count,
  icon,
  onClick,
}: {
  active: boolean;
  label: string;
  count?: number;
  icon?: ReactNode;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      className={`filter-chip ${active ? 'active' : ''}`}
      onClick={onClick}
    >
      {icon ? <span className="filter-chip-icon">{icon}</span> : null}
      <span className="filter-chip-label">{label}</span>
      {count !== undefined ? <span className="filter-chip-count">{count}</span> : null}
    </button>
  );
}

function FilterRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="route-filter-row">
      <span className="route-filter-row-label">{label}</span>
      <div className="route-filter-row-chips">{children}</div>
    </div>
  );
}

export default function ManualRoutePanel({
  show,
  editingRouteId,
  form,
  setForm,
  saving,
  canSave,
  routeIconSelectOptions,
  previewModelSamples,
  exactSourceRouteOptions,
  sourceEndpointTypesByRouteId,
  onSave,
  onCancel,
}: ManualRoutePanelProps) {
  const [showSourcePicker, setShowSourcePicker] = useState(false);
  const [sourceSearch, setSourceSearch] = useState('');
  const [sourcePickerSelection, setSourcePickerSelection] = useState<number[]>([]);
  const [activeSourceBrand, setActiveSourceBrand] = useState<string | null>(null);
  const [activeSourceSite, setActiveSourceSite] = useState<string | null>(null);
  const [activeSourceEndpointType, setActiveSourceEndpointType] = useState<string | null>(null);

  useEffect(() => {
    if (!show) {
      setShowSourcePicker(false);
      setSourceSearch('');
      setSourcePickerSelection([]);
      setActiveSourceBrand(null);
      setActiveSourceSite(null);
      setActiveSourceEndpointType(null);
    }
  }, [show]);

  const routeMode = normalizeRouteMode(form.routeMode);
  const editingLegacyPatternGroup = editingRouteId !== null && routeMode === 'pattern';

  const modelPatternError = useMemo(
    () => getModelPatternError(form.modelPattern),
    [form.modelPattern],
  );

  const routeIconOptionValues = useMemo(
    () => new Set(routeIconSelectOptions.map((option) => option.value)),
    [routeIconSelectOptions],
  );

  const routeIconSelectValue = routeIconOptionValues.has(normalizeRouteDisplayIconValue(form.displayIcon))
    ? normalizeRouteDisplayIconValue(form.displayIcon)
    : '';

  const previewMatchedModels = useMemo(() => {
    const normalizedPattern = form.modelPattern.trim();
    if (!normalizedPattern || modelPatternError) return [] as string[];
    return previewModelSamples.filter((modelName) => matchesModelPattern(modelName, normalizedPattern));
  }, [form.modelPattern, modelPatternError, previewModelSamples]);

  const sourceRouteBrandById = useMemo(() => {
    const next = new Map<number, BrandInfo | null>();
    for (const route of exactSourceRouteOptions) {
      next.set(route.id, resolveRouteBrand(route));
    }
    return next;
  }, [exactSourceRouteOptions]);

  const sourceBrandList = useMemo(() => {
    const grouped = new Map<string, { count: number; brand: BrandInfo }>();
    let otherCount = 0;

    for (const route of exactSourceRouteOptions) {
      const brand = sourceRouteBrandById.get(route.id) || null;
      if (!brand) {
        otherCount += 1;
        continue;
      }
      const existing = grouped.get(brand.name);
      if (existing) {
        existing.count += 1;
      } else {
        grouped.set(brand.name, { count: 1, brand });
      }
    }

    return {
      list: [...grouped.entries()].sort((a, b) => {
        if (a[1].count === b[1].count) {
          return a[0].localeCompare(b[0], undefined, { sensitivity: 'base' });
        }
        return b[1].count - a[1].count;
      }) as [string, { count: number; brand: BrandInfo }][],
      otherCount,
    };
  }, [exactSourceRouteOptions, sourceRouteBrandById]);

  const sourceSiteList = useMemo(() => {
    const grouped = new Map<string, number>();

    for (const route of exactSourceRouteOptions) {
      const seenSites = new Set<string>();
      for (const siteName of route.siteNames || []) {
        const normalizedSite = String(siteName || '').trim();
        if (!normalizedSite || seenSites.has(normalizedSite)) continue;
        seenSites.add(normalizedSite);
        grouped.set(normalizedSite, (grouped.get(normalizedSite) || 0) + 1);
      }
    }

    return [...grouped.entries()].sort((a, b) => {
      if (a[1] === b[1]) {
        return a[0].localeCompare(b[0], undefined, { sensitivity: 'base' });
      }
      return b[1] - a[1];
    }) as [string, number][];
  }, [exactSourceRouteOptions]);

  const sourceEndpointTypeList = useMemo(() => {
    const grouped = new Map<string, number>();

    for (const route of exactSourceRouteOptions) {
      const endpointTypes = sourceEndpointTypesByRouteId[route.id] || [];
      for (const endpointType of endpointTypes) {
        const normalizedType = String(endpointType || '').trim();
        if (!normalizedType) continue;
        grouped.set(normalizedType, (grouped.get(normalizedType) || 0) + 1);
      }
    }

    return [...grouped.entries()].sort((a, b) => {
      if (a[1] === b[1]) {
        return a[0].localeCompare(b[0], undefined, { sensitivity: 'base' });
      }
      return b[1] - a[1];
    }) as [string, number][];
  }, [exactSourceRouteOptions, sourceEndpointTypesByRouteId]);

  const filteredSourceRoutes = useMemo(() => {
    let list = [...exactSourceRouteOptions];

    if (activeSourceBrand) {
      if (activeSourceBrand === '__other__') {
        list = list.filter((route) => !(sourceRouteBrandById.get(route.id) || null));
      } else {
        list = list.filter((route) => (sourceRouteBrandById.get(route.id)?.name || '') === activeSourceBrand);
      }
    }

    if (activeSourceSite) {
      list = list.filter((route) => (route.siteNames || []).includes(activeSourceSite));
    }

    if (activeSourceEndpointType) {
      list = list.filter((route) => (sourceEndpointTypesByRouteId[route.id] || []).includes(activeSourceEndpointType));
    }

    const normalizedSearch = sourceSearch.trim().toLowerCase();
    if (normalizedSearch) {
      list = list.filter((route) => {
        const label = renderRouteOptionLabel(route).toLowerCase();
        const modelPattern = route.modelPattern.toLowerCase();
        const brandName = (sourceRouteBrandById.get(route.id)?.name || '').toLowerCase();
        const siteText = (route.siteNames || []).join(' ').toLowerCase();
        const endpointTypes = (sourceEndpointTypesByRouteId[route.id] || []).join(' ').toLowerCase();
        return (
          label.includes(normalizedSearch)
          || modelPattern.includes(normalizedSearch)
          || brandName.includes(normalizedSearch)
          || siteText.includes(normalizedSearch)
          || endpointTypes.includes(normalizedSearch)
        );
      });
    }

    return list.sort((a, b) => {
      if (a.channelCount === b.channelCount) {
        return renderRouteOptionLabel(a).localeCompare(renderRouteOptionLabel(b), undefined, { sensitivity: 'base' });
      }
      return b.channelCount - a.channelCount;
    });
  }, [
    activeSourceBrand,
    activeSourceEndpointType,
    activeSourceSite,
    exactSourceRouteOptions,
    sourceEndpointTypesByRouteId,
    sourceRouteBrandById,
    sourceSearch,
  ]);

  const selectedSourceRoutes = useMemo(() => {
    const routeById = new Map(exactSourceRouteOptions.map((route) => [route.id, route]));
    return form.sourceRouteIds
      .map((routeId) => routeById.get(routeId))
      .filter((route): route is RouteSummaryRow => !!route);
  }, [exactSourceRouteOptions, form.sourceRouteIds]);

  const sourcePickerSelectionSet = useMemo(
    () => new Set(sourcePickerSelection),
    [sourcePickerSelection],
  );

  const autoBrandIconEnabled = !isRouteIconNoneValue(form.displayIcon);
  const hasExplicitIconValue = !!normalizeRouteDisplayIconValue(form.displayIcon);

  const openSourcePicker = () => {
    setSourcePickerSelection([...form.sourceRouteIds]);
    setSourceSearch('');
    setActiveSourceBrand(null);
    setActiveSourceSite(null);
    setActiveSourceEndpointType(null);
    setShowSourcePicker(true);
  };

  const closeSourcePicker = () => {
    setShowSourcePicker(false);
    setSourceSearch('');
    setActiveSourceBrand(null);
    setActiveSourceSite(null);
    setActiveSourceEndpointType(null);
  };

  const confirmSourcePicker = () => {
    setForm((current) => ({
      ...current,
      sourceRouteIds: [...sourcePickerSelection].sort((a, b) => a - b),
    }));
    setShowSourcePicker(false);
    setSourceSearch('');
    setActiveSourceBrand(null);
    setActiveSourceSite(null);
    setActiveSourceEndpointType(null);
  };

  const footer = (
    <>
      <button
        type="button"
        onClick={onCancel}
        className="btn btn-ghost"
        style={{ border: '1px solid var(--color-border)' }}
      >
        {editingRouteId ? tr('取消编辑') : tr('取消')}
      </button>
      <button
        type="button"
        onClick={onSave}
        disabled={!canSave}
        className="btn btn-success"
      >
        {saving ? (
          <>
            <span
              className="spinner spinner-sm"
              style={{ borderTopColor: 'white', borderColor: 'rgba(255,255,255,0.3)' }}
            />{' '}
            {tr('保存中...')}
          </>
        ) : (
          tr(editingRouteId ? '保存群组' : '创建群组')
        )}
      </button>
    </>
  );

  const sourcePickerFooter = (
    <>
      <button
        type="button"
        onClick={closeSourcePicker}
        className="btn btn-ghost"
        style={{ border: '1px solid var(--color-border)' }}
      >
        {tr('取消')}
      </button>
      <button
        type="button"
        onClick={() => setSourcePickerSelection([])}
        className="btn btn-ghost"
        disabled={sourcePickerSelection.length === 0}
      >
        {tr('清空')}
      </button>
      <button
        type="button"
        onClick={confirmSourcePicker}
        className="btn btn-primary"
      >
        {`确认选择 (${sourcePickerSelection.length})`}
      </button>
    </>
  );

  return (
    <>
      <CenteredModal
        open={show}
        onClose={onCancel}
        title={editingRouteId ? tr('编辑群组') : tr('新建群组')}
        footer={footer}
        maxWidth={860}
        closeOnEscape
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {editingLegacyPatternGroup ? (
            <div
              style={{
                border: '1px solid var(--color-border)',
                borderRadius: 'var(--radius-md)',
                padding: '12px 14px',
                background: 'var(--color-bg-card)',
              }}
            >
              <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--color-text-primary)', marginBottom: 6 }}>
                {tr('高级规则群组')}
              </div>
              <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>
                {tr('该群组使用高级模型匹配规则创建，普通模式不可编辑；修改后会按当前可用模型重新匹配自动通道。')}
              </div>
            </div>
          ) : routeMode === 'explicit_group' ? (
            <div
              style={{
                border: '1px solid var(--color-border)',
                borderRadius: 'var(--radius-md)',
                padding: '12px 14px',
                background: 'var(--color-bg-card)',
              }}
            >
              <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--color-text-primary)', marginBottom: 6 }}>
                {tr('模型重定向')}
              </div>
              <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>
                {tr('将多个现有模型合并为一个对外模型名，实现模型重定向。')}
              </div>
            </div>
          ) : (
            <div
              style={{
                border: '1px solid var(--color-border)',
                borderRadius: 'var(--radius-md)',
                padding: '12px 14px',
                background: 'var(--color-bg-card)',
              }}
            >
              <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--color-text-primary)', marginBottom: 6 }}>
                {tr('高级规则群组')}
              </div>
              <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>
                {tr('使用模型匹配规则创建群组，适合需要 regex / glob 的高级场景。')}
              </div>
            </div>
          )}

          {routeMode === 'explicit_group' ? (
            <>
              <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr)', gap: 12 }}>
                <label style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  <span style={{ fontSize: 12, color: 'var(--color-text-secondary)' }}>{tr('对外模型名')}</span>
                  <input
                    placeholder={tr('对外模型名（例如 claude-opus-4-6）')}
                    value={form.displayName}
                    onChange={(event) => setForm((current) => ({ ...current, displayName: event.target.value }))}
                    style={{
                      width: '100%',
                      padding: '10px 14px',
                      border: '1px solid var(--color-border)',
                      borderRadius: 'var(--radius-sm)',
                      fontSize: 13,
                      outline: 'none',
                      background: 'var(--color-bg)',
                      color: 'var(--color-text-primary)',
                    }}
                  />
                </label>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap' }}>
                  <div>
                    <div style={{ fontSize: 12, color: 'var(--color-text-secondary)', marginBottom: 4 }}>
                      {tr('来源模型')}
                    </div>
                    <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>
                      {tr('选择一个或多个现有精确模型路由作为来源。')}
                    </div>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                    {!editingRouteId && (
                      <button
                        type="button"
                        className="btn btn-link"
                        onClick={() => setForm((current) => ({ ...current, routeMode: 'pattern', advancedOpen: true }))}
                      >
                        {tr('改用高级规则')}
                      </button>
                    )}
                    <button
                      type="button"
                      className="btn btn-ghost"
                      onClick={openSourcePicker}
                    >
                      {tr('选择来源模型')}
                    </button>
                  </div>
                </div>

                <div
                  style={{
                    border: '1px solid var(--color-border)',
                    borderRadius: 'var(--radius-md)',
                    padding: '12px 14px',
                    background: 'var(--color-bg-card)',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: 12,
                  }}
                >
                  <div style={{ fontSize: 12, color: 'var(--color-text-secondary)' }}>
                    {selectedSourceRoutes.length > 0
                      ? `已选择 ${selectedSourceRoutes.length} 个来源模型`
                      : tr('尚未选择来源模型。')}
                  </div>

                  {selectedSourceRoutes.length > 0 ? (
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                      {selectedSourceRoutes.slice(0, 8).map((route) => (
                        <button
                          key={`selected-${route.id}`}
                          type="button"
                          className="badge badge-info"
                          style={{ fontSize: 11, cursor: 'pointer' }}
                          onClick={() => setForm((current) => ({
                            ...current,
                            sourceRouteIds: toggleSourceRouteId(current.sourceRouteIds, route.id),
                          }))}
                        >
                          {renderRouteOptionLabel(route)} ×
                        </button>
                      ))}
                      {selectedSourceRoutes.length > 8 && (
                        <span className="badge badge-muted" style={{ fontSize: 11 }}>
                          {`+${selectedSourceRoutes.length - 8}`}
                        </span>
                      )}
                    </div>
                  ) : (
                    <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>
                      {tr('点击“选择来源模型”打开大列表，搜索后快速勾选。')}
                    </div>
                  )}
                </div>
              </div>

              <div
                style={{
                  border: '1px solid var(--color-border)',
                  borderRadius: 'var(--radius-md)',
                  padding: '12px 14px',
                  background: 'var(--color-bg-card)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 12,
                }}
              >
                <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--color-text-primary)' }}>
                  {tr('高级配置')}
                </div>

                <label style={{ display: 'flex', alignItems: 'flex-start', gap: 10, cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={autoBrandIconEnabled}
                    onChange={(event) => {
                      const checked = !!event.target.checked;
                      setForm((current) => ({
                        ...current,
                        displayIcon: checked
                          ? (isRouteIconNoneValue(current.displayIcon) ? '' : current.displayIcon)
                          : ROUTE_ICON_NONE_VALUE,
                      }));
                    }}
                    style={{ marginTop: 2, width: 16, height: 16, accentColor: 'var(--color-primary)' }}
                  />
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                    <span style={{ fontSize: 13, color: 'var(--color-text-primary)' }}>{tr('自动品牌图标')}</span>
                    <span style={{ fontSize: 12, color: 'var(--color-text-muted)', lineHeight: 1.5 }}>
                      {autoBrandIconEnabled
                        ? tr('开启后会优先保留现有图标策略；未设置固定图标时按模型自动识别品牌。')
                        : tr('关闭后该群组不显示品牌图标，只保留文字标题。')}
                    </span>
                    {hasExplicitIconValue && autoBrandIconEnabled && (
                      <span style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>
                        {tr('当前群组如果已设置固定品牌图标，保持开启不会移除它。')}
                      </span>
                    )}
                  </div>
                </label>
              </div>
            </>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              {!editingLegacyPatternGroup && (
                <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                  <button
                    type="button"
                    className="btn btn-link"
                    onClick={() => setForm((current) => ({
                      ...current,
                      routeMode: 'explicit_group',
                      advancedOpen: false,
                    }))}
                  >
                    {tr('返回简单模式')}
                  </button>
                </div>
              )}

              <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) 220px', gap: 12 }}>
                <label style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  <span style={{ fontSize: 12, color: 'var(--color-text-secondary)' }}>{tr('群组显示名')}</span>
                  <input
                    placeholder={tr('群组显示名（可选，例如 claude-opus-4-6）')}
                    value={form.displayName}
                    onChange={(event) => setForm((current) => ({ ...current, displayName: event.target.value }))}
                    style={{
                      width: '100%',
                      padding: '10px 14px',
                      border: '1px solid var(--color-border)',
                      borderRadius: 'var(--radius-sm)',
                      fontSize: 13,
                      outline: 'none',
                      background: 'var(--color-bg)',
                      color: 'var(--color-text-primary)',
                    }}
                  />
                </label>

                <label style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  <span style={{ fontSize: 12, color: 'var(--color-text-secondary)' }}>{tr('群组图标')}</span>
                  <ModernSelect
                    value={routeIconSelectValue}
                    onChange={(nextValue) => setForm((current) => ({ ...current, displayIcon: nextValue }))}
                    options={routeIconSelectOptions}
                    placeholder={tr('图标（可选，选择品牌图标）')}
                    emptyLabel={tr('暂无可选品牌图标')}
                  />
                </label>
              </div>

              <label style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                <span style={{ fontSize: 12, color: 'var(--color-text-secondary)' }}>{tr('模型匹配')}</span>
                <input
                  placeholder={tr('模型匹配（如 gpt-4o、claude-*、re:^claude-.*$）')}
                  value={form.modelPattern}
                  onChange={(event) => setForm((current) => ({ ...current, modelPattern: event.target.value }))}
                  style={{
                    width: '100%',
                    padding: '10px 14px',
                    border: `1px solid ${modelPatternError ? 'var(--color-danger)' : 'var(--color-border)'}`,
                    borderRadius: 'var(--radius-sm)',
                    fontSize: 13,
                    outline: 'none',
                    background: 'var(--color-bg)',
                    color: 'var(--color-text-primary)',
                    fontFamily: 'var(--font-mono)',
                  }}
                />
              </label>

              <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginTop: -4 }}>
                {isExactModelPattern(form.modelPattern)
                  ? tr('当前为精确模型匹配。')
                  : tr('正则请使用 re: 前缀；例如 re:^claude-(opus|sonnet)-4-6$')}
              </div>

              {modelPatternError && (
                <div style={{ fontSize: 12, color: 'var(--color-danger)', marginTop: -4 }}>
                  {modelPatternError}
                </div>
              )}

              {form.modelPattern.trim() && !modelPatternError && (
                <div
                  style={{
                    border: '1px solid var(--color-border)',
                    borderRadius: 'var(--radius-sm)',
                    padding: '10px 12px',
                    background: 'var(--color-bg)',
                  }}
                >
                  <div style={{ fontSize: 12, color: 'var(--color-text-secondary)', marginBottom: 8 }}>
                    {tr('规则预览：命中样本')} {previewMatchedModels.length} / {previewModelSamples.length}
                  </div>

                  {previewModelSamples.length === 0 ? (
                    <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>
                      {tr('当前暂无可预览模型，请先同步模型。')}
                    </div>
                  ) : previewMatchedModels.length === 0 ? (
                    <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>
                      {tr('当前规则未命中任何样本模型。')}
                    </div>
                  ) : (
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                      {previewMatchedModels.slice(0, 12).map((modelName) => (
                        <code
                          key={modelName}
                          style={{
                            fontSize: 11,
                            padding: '2px 6px',
                            borderRadius: 6,
                            border: '1px solid var(--color-border)',
                            background: 'var(--color-bg-card)',
                          }}
                        >
                          {modelName}
                        </code>
                      ))}
                    </div>
                  )}

                  {previewMatchedModels.length > 12 && (
                    <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginTop: 8 }}>
                      {tr('仅展示前 12 个命中样本。')}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      </CenteredModal>

      <CenteredModal
        open={show && showSourcePicker}
        onClose={closeSourcePicker}
        title={tr('选择来源模型')}
        footer={sourcePickerFooter}
        maxWidth={980}
        closeOnEscape
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap' }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              <div style={{ fontSize: 12, color: 'var(--color-text-secondary)' }}>
                {`已选择 ${sourcePickerSelection.length} 个来源模型`}
              </div>
              <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>
                {`候选 ${filteredSourceRoutes.length} / ${exactSourceRouteOptions.length}`}
              </div>
            </div>
          </div>

          <SearchField
            value={sourceSearch}
            onChange={setSourceSearch}
            placeholder={tr('搜索来源模型')}
          />

          <div className="route-filter-bar">
            <div className="route-filter-bar-expanded" style={{ opacity: 1, transform: 'none' }}>
              <FilterRow label={tr('品牌')}>
                <FilterChip
                  active={!activeSourceBrand}
                  label={tr('全部')}
                  count={exactSourceRouteOptions.length}
                  icon={<span style={{ fontSize: 10 }}>✦</span>}
                  onClick={() => setActiveSourceBrand(null)}
                />
                {sourceBrandList.list.map(([brandName, { count, brand }]) => (
                  <FilterChip
                    key={brandName}
                    active={activeSourceBrand === brandName}
                    label={brandName}
                    count={count}
                    icon={<BrandGlyph brand={brand} size={12} fallbackText={brandName} />}
                    onClick={() => setActiveSourceBrand(activeSourceBrand === brandName ? null : brandName)}
                  />
                ))}
                {sourceBrandList.otherCount > 0 ? (
                  <FilterChip
                    active={activeSourceBrand === '__other__'}
                    label={tr('其他')}
                    count={sourceBrandList.otherCount}
                    icon={<span style={{ fontSize: 10 }}>?</span>}
                    onClick={() => setActiveSourceBrand(activeSourceBrand === '__other__' ? null : '__other__')}
                  />
                ) : null}
              </FilterRow>

              {sourceSiteList.length > 0 ? (
                <FilterRow label={tr('站点')}>
                  <FilterChip
                    active={!activeSourceSite}
                    label={tr('全部')}
                    count={exactSourceRouteOptions.length}
                    icon={<span style={{ fontSize: 10 }}>⚡</span>}
                    onClick={() => setActiveSourceSite(null)}
                  />
                  {sourceSiteList.map(([siteName, count]) => (
                    <FilterChip
                      key={siteName}
                      active={activeSourceSite === siteName}
                      label={siteName}
                      count={count}
                      icon={(
                        <span
                          style={{
                            fontSize: 8,
                            background: hashColor(siteName),
                            color: 'white',
                            borderRadius: 3,
                            padding: '1px 2px',
                            lineHeight: 1,
                          }}
                        >
                          {siteAvatarLetters(siteName)}
                        </span>
                      )}
                      onClick={() => setActiveSourceSite(activeSourceSite === siteName ? null : siteName)}
                    />
                  ))}
                </FilterRow>
              ) : null}

              <FilterRow label={tr('能力')}>
                <FilterChip
                  active={!activeSourceEndpointType}
                  label={tr('全部')}
                  count={exactSourceRouteOptions.length}
                  icon={<span style={{ fontSize: 10 }}>⚙</span>}
                  onClick={() => setActiveSourceEndpointType(null)}
                />
                {sourceEndpointTypeList.map(([endpointType, count]) => {
                  const iconModel = resolveEndpointTypeIconModel(endpointType);
                  return (
                    <FilterChip
                      key={endpointType}
                      active={activeSourceEndpointType === endpointType}
                      label={endpointType}
                      count={count}
                      icon={iconModel ? <InlineBrandIcon model={iconModel} size={12} /> : <span style={{ fontSize: 10 }}>⚙</span>}
                      onClick={() => setActiveSourceEndpointType(activeSourceEndpointType === endpointType ? null : endpointType)}
                    />
                  );
                })}
                {sourceEndpointTypeList.length === 0 ? (
                  <span style={{ fontSize: 11, color: 'var(--color-text-muted)' }}>{tr('暂无接口能力数据')}</span>
                ) : null}
              </FilterRow>
            </div>
          </div>

          <div style={{ maxHeight: 520, overflowY: 'auto', paddingRight: 4 }}>
            {filteredSourceRoutes.length === 0 ? (
              <div style={{ fontSize: 12, color: 'var(--color-text-muted)', padding: '12px 0', textAlign: 'center' }}>
                {exactSourceRouteOptions.length === 0
                  ? tr('当前没有可选的精确模型路由。')
                  : tr('没有匹配的来源模型。')}
              </div>
            ) : (
              <div
                className="source-route-picker-grid"
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))',
                  gap: 10,
                  alignItems: 'stretch',
                }}
              >
                {filteredSourceRoutes.map((route) => {
                  const selected = sourcePickerSelectionSet.has(route.id);
                  const label = renderRouteOptionLabel(route);
                  const brand = sourceRouteBrandById.get(route.id) || null;
                  const endpointTypes = (sourceEndpointTypesByRouteId[route.id] || []).slice(0, 3);
                  const siteNames = Array.from(new Set((route.siteNames || []).filter((siteName) => String(siteName || '').trim())));

                  return (
                    <button
                      key={route.id}
                      type="button"
                      onClick={() => setSourcePickerSelection((current) => toggleSourceRouteId(current, route.id))}
                      className="btn btn-ghost source-route-picker-card"
                      style={{
                        minHeight: 156,
                        display: 'flex',
                        alignItems: 'stretch',
                        textAlign: 'left',
                        padding: 0,
                        border: `1px solid ${selected ? 'var(--color-primary)' : 'var(--color-border)'}`,
                        background: selected
                          ? 'color-mix(in srgb, var(--color-primary) 8%, var(--color-bg-card))'
                          : 'var(--color-bg-card)',
                        boxShadow: selected
                          ? '0 0 0 1px color-mix(in srgb, var(--color-primary) 18%, transparent)'
                          : 'none',
                      }}
                    >
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 12, width: '100%', padding: '14px 15px' }}>
                        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 10 }}>
                          <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10, minWidth: 0, flex: 1 }}>
                            <input
                              type="checkbox"
                              checked={selected}
                              readOnly
                              style={{ marginTop: 2, cursor: 'pointer', pointerEvents: 'none', flexShrink: 0 }}
                            />
                            <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10, minWidth: 0, flex: 1 }}>
                              <span style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', width: 22, height: 22, flexShrink: 0 }}>
                                {brand ? <BrandGlyph brand={brand} size={18} fallbackText={label} /> : <InlineBrandIcon model={route.modelPattern} size={18} />}
                              </span>
                              <div style={{ display: 'flex', flexDirection: 'column', gap: 5, minWidth: 0, flex: 1 }}>
                                <span
                                  style={{
                                    fontSize: 13,
                                    fontWeight: 600,
                                    color: 'var(--color-text-primary)',
                                    overflow: 'hidden',
                                    textOverflow: 'ellipsis',
                                    whiteSpace: 'nowrap',
                                  }}
                                >
                                  {label}
                                </span>
                                {label !== route.modelPattern ? (
                                  <code
                                    style={{
                                      fontSize: 11,
                                      color: 'var(--color-text-muted)',
                                      overflow: 'hidden',
                                      textOverflow: 'ellipsis',
                                      whiteSpace: 'nowrap',
                                    }}
                                  >
                                    {route.modelPattern}
                                  </code>
                                ) : null}
                              </div>
                            </div>
                          </div>
                          <span className={selected ? 'badge badge-info' : 'badge badge-muted'} style={{ fontSize: 10, flexShrink: 0 }}>
                            {selected ? tr('已选中') : tr('可选择')}
                          </span>
                        </div>

                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                          <span className="badge badge-info" style={{ fontSize: 10 }}>
                            {route.channelCount} {tr('通道')}
                          </span>
                          <span className="badge badge-muted" style={{ fontSize: 10 }}>
                            {siteNames.length} {tr('站点')}
                          </span>
                          {endpointTypes.map((endpointType) => (
                            <span key={`${route.id}-${endpointType}`} className="badge badge-muted" style={{ fontSize: 10 }}>
                              {endpointType}
                            </span>
                          ))}
                        </div>

                        {siteNames.length > 0 ? (
                          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                            {siteNames.slice(0, 3).map((siteName) => (
                              <span
                                key={`${route.id}-${siteName}`}
                                className="badge badge-muted"
                                style={{ fontSize: 10 }}
                              >
                                {siteName}
                              </span>
                            ))}
                            {siteNames.length > 3 ? (
                              <span className="badge badge-muted" style={{ fontSize: 10 }}>
                                +{siteNames.length - 3}
                              </span>
                            ) : null}
                          </div>
                        ) : (
                          <div style={{ fontSize: 11, color: 'var(--color-text-muted)' }}>
                            {tr('当前未绑定站点信息')}
                          </div>
                        )}
                      </div>
                    </button>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      </CenteredModal>
    </>
  );
}
