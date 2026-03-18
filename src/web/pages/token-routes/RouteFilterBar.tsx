import type { ReactNode } from 'react';
import { BrandGlyph, InlineBrandIcon, hashColor, type BrandInfo } from '../../components/BrandIcon.js';
import { useAnimatedVisibility } from '../../components/useAnimatedVisibility.js';
import { tr } from '../../i18n.js';
import type { GroupFilter, GroupRouteItem } from './types.js';
import { resolveEndpointTypeIconModel, siteAvatarLetters } from './utils.js';

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
}: Pick<RouteFilterBarProps, 'activeBrand' | 'activeSite' | 'activeGroupFilter' | 'activeEndpointType'>) {
  const tags: string[] = [];
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
    brandList,
    siteList,
    endpointTypeList,
    groupRouteList,
    collapsed,
    onToggle,
  } = props;

  const expandPresence = useAnimatedVisibility(!collapsed, 220);

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
        />
      </button>

      {/* Expanded panel */}
      {expandPresence.shouldRender && (
        <div className={`route-filter-bar-expanded ${expandPresence.isVisible ? '' : 'is-closing'}`.trim()}>
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
  );
}
