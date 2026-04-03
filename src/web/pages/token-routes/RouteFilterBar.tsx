import { useEffect, useLayoutEffect, useState, type ReactNode } from 'react';
import { BrandGlyph, InlineBrandIcon, hashColor, type BrandInfo } from '../../components/BrandIcon.js';
import { tr } from '../../i18n.js';
import type { GroupFilter, GroupRouteItem } from './types.js';
import { resolveEndpointTypeIconModel, siteAvatarLetters } from './utils.js';

export type EnabledFilter = 'all' | 'enabled' | 'disabled';

const FILTER_EXPANDED_CONTENT_UNMOUNT_MS = 180;

type RouteFilterBarProps = {
  totalRouteCount: number;
  activeBrand: string | null;
  setActiveBrand: (brand: string | null) => void;
  activeSite: string | null;
  setActiveSite: (site: string | null) => void;
  activeEndpointType: string | null;
  setActiveEndpointType: (endpointType: string | null) => void;
  activeGroupFilter: GroupFilter;
  setActiveGroupFilter: (filter: GroupFilter) => void;
  enabledFilter: EnabledFilter;
  setEnabledFilter: (filter: EnabledFilter) => void;
  enabledCounts: { enabled: number; disabled: number };
  brandList: { list: [string, { count: number; brand: BrandInfo }][]; otherCount: number };
  siteList: [string, { count: number; siteId: number }][];
  endpointTypeList: [string, number][];
  groupRouteList: GroupRouteItem[];
  collapsed: boolean;
  onToggle: () => void;
};

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
      {icon && <span className="filter-chip-icon">{icon}</span>}
      <span className="filter-chip-label">{label}</span>
      {count !== undefined && <span className="filter-chip-count">{count}</span>}
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

function ActiveFilterSummary({
  activeBrand,
  activeSite,
  activeGroupFilter,
  activeEndpointType,
  enabledFilter,
}: Pick<RouteFilterBarProps, 'activeBrand' | 'activeSite' | 'activeGroupFilter' | 'activeEndpointType' | 'enabledFilter'>) {
  const tags: string[] = [];
  if (enabledFilter === 'enabled') tags.push('状态=启用');
  else if (enabledFilter === 'disabled') tags.push('状态=禁用');
  if (activeBrand) tags.push(`品牌=${activeBrand === '__other__' ? '其他' : activeBrand}`);
  if (activeSite) tags.push(`站点=${activeSite}`);
  if (activeGroupFilter === '__all__') tags.push('群组=全部');
  else if (typeof activeGroupFilter === 'number') tags.push(`群组=#${activeGroupFilter}`);
  if (activeEndpointType) tags.push(`能力=${activeEndpointType}`);

  if (tags.length === 0) return <span style={{ color: 'var(--color-text-muted)' }}>{tr('全部')}</span>;
  return <span>{tags.join(', ')}</span>;
}

export default function RouteFilterBar(props: RouteFilterBarProps) {
  const {
    totalRouteCount,
    activeBrand,
    setActiveBrand,
    activeSite,
    setActiveSite,
    activeEndpointType,
    setActiveEndpointType,
    activeGroupFilter,
    setActiveGroupFilter,
    enabledFilter,
    setEnabledFilter,
    enabledCounts,
    brandList,
    siteList,
    endpointTypeList,
    groupRouteList,
    collapsed,
    onToggle,
  } = props;
  const [renderExpandedContent, setRenderExpandedContent] = useState(!collapsed);
  const [presenceOpen, setPresenceOpen] = useState(!collapsed);

  useEffect(() => {
    if (!collapsed) return undefined;

    const timerId = globalThis.setTimeout(() => setRenderExpandedContent(false), FILTER_EXPANDED_CONTENT_UNMOUNT_MS);
    return () => globalThis.clearTimeout(timerId);
  }, [collapsed]);

  useLayoutEffect(() => {
    if (collapsed) {
      setPresenceOpen(false);
      return undefined;
    }

    setRenderExpandedContent(true);
    setPresenceOpen(false);
    if (typeof window !== 'undefined' && typeof window.requestAnimationFrame === 'function') {
      const rafId = window.requestAnimationFrame(() => setPresenceOpen(true));
      return () => window.cancelAnimationFrame(rafId);
    }
    setPresenceOpen(true);
    return undefined;
  }, [collapsed]);

  return (
    <div className="route-filter-bar">
      {/* Collapsed summary */}
      <button
        type="button"
        className="route-filter-bar-summary"
        onClick={onToggle}
      >
        <svg
          width="12" height="12" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="2"
          style={{ transform: collapsed ? 'rotate(0deg)' : 'rotate(180deg)', transition: 'transform 0.2s ease' }}
          aria-hidden
        >
          <path d="m5 7 5 6 5-6" />
        </svg>
        <span style={{ fontWeight: 500, fontSize: 13 }}>{tr('筛选')}:</span>
        <ActiveFilterSummary
          activeBrand={activeBrand}
          activeSite={activeSite}
          activeGroupFilter={activeGroupFilter}
          activeEndpointType={activeEndpointType}
          enabledFilter={enabledFilter}
        />
      </button>

      {/* Expanded panel */}
      <div className={`anim-collapse route-filter-bar-presence ${presenceOpen ? 'is-open' : ''}`.trim()}>
        <div className="anim-collapse-inner">
          {renderExpandedContent && (
            <div className="route-filter-bar-expanded">
              {/* Status row */}
              <FilterRow label={tr('状态')}>
                <FilterChip
                  active={enabledFilter === 'all'}
                  label={tr('全部')}
                  count={totalRouteCount}
                  icon={<span style={{ fontSize: 10 }}>✦</span>}
                  onClick={() => setEnabledFilter('all')}
                />
                <FilterChip
                  active={enabledFilter === 'enabled'}
                  label={tr('仅启用')}
                  count={enabledCounts.enabled}
                  icon={<span style={{ fontSize: 10, color: 'var(--color-success)' }}>●</span>}
                  onClick={() => setEnabledFilter(enabledFilter === 'enabled' ? 'all' : 'enabled')}
                />
                <FilterChip
                  active={enabledFilter === 'disabled'}
                  label={tr('仅禁用')}
                  count={enabledCounts.disabled}
                  icon={<span style={{ fontSize: 10, color: 'var(--color-text-muted)' }}>●</span>}
                  onClick={() => setEnabledFilter(enabledFilter === 'disabled' ? 'all' : 'disabled')}
                />
              </FilterRow>

              {/* Brand row */}
              <FilterRow label={tr('品牌')}>
                <FilterChip
                  active={!activeBrand}
                  label={tr('全部')}
                  count={totalRouteCount}
                  icon={<span style={{ fontSize: 10 }}>✦</span>}
                  onClick={() => setActiveBrand(null)}
                />
                {brandList.list.map(([brandName, { count, brand }]) => (
                  <FilterChip
                    key={brandName}
                    active={activeBrand === brandName}
                    label={brandName}
                    count={count}
                    icon={<BrandGlyph brand={brand} size={12} fallbackText={brandName} />}
                    onClick={() => setActiveBrand(activeBrand === brandName ? null : brandName)}
                  />
                ))}
                {brandList.otherCount > 0 && (
                  <FilterChip
                    active={activeBrand === '__other__'}
                    label={tr('其他')}
                    count={brandList.otherCount}
                    icon={<span style={{ fontSize: 10 }}>?</span>}
                    onClick={() => setActiveBrand(activeBrand === '__other__' ? null : '__other__')}
                  />
                )}
              </FilterRow>

              {/* Site row */}
              {siteList.length > 0 && (
                <FilterRow label={tr('站点')}>
                  <FilterChip
                    active={!activeSite}
                    label={tr('全部')}
                    count={totalRouteCount}
                    icon={<span style={{ fontSize: 10 }}>⚡</span>}
                    onClick={() => setActiveSite(null)}
                  />
                  {siteList.map(([siteName, { count }]) => (
                    <FilterChip
                      key={siteName}
                      active={activeSite === siteName}
                      label={siteName}
                      count={count}
                      icon={
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
                      }
                      onClick={() => setActiveSite(activeSite === siteName ? null : siteName)}
                    />
                  ))}
                </FilterRow>
              )}

              {/* Group row */}
              <FilterRow label={tr('群组')}>
                <FilterChip
                  active={activeGroupFilter === '__all__'}
                  label={tr('全部群组')}
                  count={groupRouteList.length}
                  icon={<span style={{ fontSize: 10 }}>◎</span>}
                  onClick={() => setActiveGroupFilter(activeGroupFilter === '__all__' ? null : '__all__')}
                />
                {groupRouteList.map((groupRoute) => (
                  <FilterChip
                    key={groupRoute.id}
                    active={activeGroupFilter === groupRoute.id}
                    label={groupRoute.title}
                    count={groupRoute.sourceRouteCount > 0 ? groupRoute.sourceRouteCount : groupRoute.channelCount}
                    icon={
                      groupRoute.icon.kind === 'brand' ? (
                        <BrandGlyph icon={groupRoute.icon.value} alt={groupRoute.title} size={12} fallbackText={groupRoute.title} />
                      ) : groupRoute.icon.kind === 'text' ? (
                        <span style={{ fontSize: 10, lineHeight: 1 }}>{groupRoute.icon.value}</span>
                      ) : groupRoute.icon.kind === 'auto' && groupRoute.brand ? (
                        <BrandGlyph brand={groupRoute.brand} alt={groupRoute.title} size={12} fallbackText={groupRoute.title} />
                      ) : groupRoute.icon.kind === 'auto' ? (
                        <InlineBrandIcon model={groupRoute.modelPattern} size={12} />
                      ) : undefined
                    }
                    onClick={() => setActiveGroupFilter(activeGroupFilter === groupRoute.id ? null : groupRoute.id)}
                  />
                ))}
              </FilterRow>

              {/* Endpoint type row */}
              <FilterRow label={tr('能力')}>
                <FilterChip
                  active={!activeEndpointType}
                  label={tr('全部')}
                  count={totalRouteCount}
                  icon={<span style={{ fontSize: 10 }}>⚙</span>}
                  onClick={() => setActiveEndpointType(null)}
                />
                {endpointTypeList.map(([endpointType, count]) => {
                  const iconModel = resolveEndpointTypeIconModel(endpointType);
                  return (
                    <FilterChip
                      key={endpointType}
                      active={activeEndpointType === endpointType}
                      label={endpointType}
                      count={count}
                      icon={iconModel ? <InlineBrandIcon model={iconModel} size={12} /> : <span style={{ fontSize: 10 }}>⚙</span>}
                      onClick={() => setActiveEndpointType(activeEndpointType === endpointType ? null : endpointType)}
                    />
                  );
                })}
                {endpointTypeList.length === 0 && (
                  <span style={{ fontSize: 11, color: 'var(--color-text-muted)' }}>{tr('暂无接口能力数据')}</span>
                )}
              </FilterRow>

              <div style={{ display: 'flex', justifyContent: 'flex-end', paddingTop: 4 }}>
                <button
                  className="btn btn-ghost"
                  style={{ fontSize: 12, padding: '4px 10px', border: '1px solid var(--color-border)' }}
                  onClick={onToggle}
                >
                  {tr('收起筛选面板')}
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
