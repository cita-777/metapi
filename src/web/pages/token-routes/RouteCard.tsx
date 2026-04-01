import { memo, useState, type ReactNode } from 'react';
import {
  DndContext,
  KeyboardSensor,
  PointerSensor,
  closestCenter,
  type DragEndEvent,
  type DragOverEvent,
  type DragStartEvent,
  useDroppable,
  useSensor,
  useSensors,
} from '@dnd-kit/core';
import {
  SortableContext,
  verticalListSortingStrategy,
  sortableKeyboardCoordinates,
} from '@dnd-kit/sortable';
import { BrandGlyph, InlineBrandIcon, type BrandInfo } from '../../components/BrandIcon.js';
import ModernSelect from '../../components/ModernSelect.js';
import { useAnimatedVisibility } from '../../components/useAnimatedVisibility.js';
import { tr } from '../../i18n.js';
import { formatDateTimeMinuteLocal } from '../helpers/checkinLogTime.js';
import type {
  RouteSummaryRow,
  RouteChannel,
  RouteDecision,
  RouteDecisionCandidate,
  MissingTokenRouteSiteActionItem,
  MissingTokenGroupRouteSiteActionItem,
  RouteRoutingStrategy,
} from './types.js';
import type { RouteCandidateView, RouteTokenOption } from '../helpers/routeModelCandidatesIndex.js';
import { SortableChannelRow } from './SortableChannelRow.js';
import {
  getRouteRoutingStrategyLabel,
  normalizeRouteRoutingStrategyValue,
} from './routingStrategy.js';
import {
  isRouteExactModel,
  isExplicitGroupRoute,
  resolveRouteTitle,
  resolveRouteIcon,
} from './utils.js';
import {
  buildPriorityBuckets,
} from './priorityBuckets.js';
import {
  buildPriorityRailNodeStyle,
  buildPriorityRailSections,
  createPriorityRailNewLayerId,
  isPriorityRailNewLayerId,
} from './priorityRail.js';

type RouteCardProps = {
  route: RouteSummaryRow;
  brand: BrandInfo | null;
  expanded: boolean;
  compact?: boolean;
  onToggleExpand: (routeId: number) => void;
  onEdit: (route: RouteSummaryRow) => void;
  onDelete: (routeId: number) => void;
  onToggleEnabled: (route: RouteSummaryRow) => void;
  onClearCooldown: (routeId: number) => void;
  clearingCooldown: boolean;
  onRoutingStrategyChange: (route: RouteSummaryRow, strategy: RouteRoutingStrategy) => void;
  updatingRoutingStrategy: boolean;
  // Channel data (loaded on demand)
  channels: RouteChannel[] | undefined;
  loadingChannels: boolean;
  // Decision data
  routeDecision: RouteDecision | null;
  loadingDecision: boolean;
  // Channel interaction
  candidateView: RouteCandidateView;
  channelTokenDraft: Record<number, number>;
  updatingChannel: Record<number, boolean>;
  savingPriority: boolean;
  onTokenDraftChange: (channelId: number, tokenId: number) => void;
  onSaveToken: (routeId: number, channelId: number, accountId: number) => void;
  onDeleteChannel: (channelId: number, routeId: number) => void;
  onToggleChannelEnabled: (channelId: number, routeId: number, enabled: boolean) => void;
  onChannelDragEnd: (routeId: number, event: DragEndEvent) => void;
  // Missing token hints
  missingTokenSiteItems: MissingTokenRouteSiteActionItem[];
  missingTokenGroupItems: MissingTokenGroupRouteSiteActionItem[];
  onCreateTokenForMissing: (accountId: number, modelName: string) => void;
  // Add channel
  onAddChannel: (routeId: number) => void;
  // Site block model
  onSiteBlockModel: (channelId: number, routeId: number) => void;
  // Source group expansion
  expandedSourceGroupMap: Record<string, boolean>;
  onToggleSourceGroup: (groupKey: string) => void;
};

function AnimatedCollapseSection({ open, children }: { open: boolean; children: ReactNode }) {
  const presence = useAnimatedVisibility(open, 220);
  if (!presence.shouldRender) return null;
  return (
    <div className={`anim-collapse ${presence.isVisible ? 'is-open' : ''}`.trim()}>
      <div className="anim-collapse-inner">
        {children}
      </div>
    </div>
  );
}

function PriorityRailNewLayerRow({
  id,
  highlighted,
}: {
  id: string;
  highlighted: boolean;
}) {
  const { setNodeRef, isOver } = useDroppable({ id });
  const active = highlighted || isOver;

  return (
    <div
      ref={setNodeRef}
      style={{
        display: 'grid',
        gridTemplateColumns: '86px minmax(0, 1fr)',
        gap: 12,
        alignItems: 'center',
      }}
    >
      <div
        style={{
          minWidth: 72,
          padding: '6px 10px',
          borderRadius: 999,
          border: `1px dashed ${active ? 'var(--color-primary)' : 'var(--color-border)'}`,
          background: active
            ? 'color-mix(in srgb, var(--color-primary) 10%, var(--color-bg))'
            : 'transparent',
          color: active ? 'var(--color-primary)' : 'var(--color-text-muted)',
          fontSize: 11,
          fontWeight: 600,
          textAlign: 'center',
          lineHeight: 1.2,
          transition: 'all 0.16s ease',
        }}
      >
        {tr('放到新档位')}
      </div>
      <div
        style={{
          height: 0,
          borderTop: `1px dashed ${active ? 'var(--color-primary)' : 'var(--color-border)'}`,
          opacity: active ? 1 : 0.75,
          transition: 'all 0.16s ease',
        }}
      />
    </div>
  );
}

function RouteCardInner({
  route,
  brand,
  expanded,
  compact = false,
  onToggleExpand,
  onEdit,
  onDelete,
  onToggleEnabled,
  onClearCooldown,
  clearingCooldown,
  onRoutingStrategyChange,
  updatingRoutingStrategy,
  channels,
  loadingChannels,
  routeDecision,
  loadingDecision,
  candidateView,
  channelTokenDraft,
  updatingChannel,
  savingPriority,
  onTokenDraftChange,
  onSaveToken,
  onDeleteChannel,
  onToggleChannelEnabled,
  onChannelDragEnd,
  missingTokenSiteItems,
  missingTokenGroupItems,
  onCreateTokenForMissing,
  onAddChannel,
  onSiteBlockModel,
  expandedSourceGroupMap,
  onToggleSourceGroup,
}: RouteCardProps) {
  const routeIcon = resolveRouteIcon(route);
  const exactRoute = isRouteExactModel(route);
  const explicitGroupRoute = isExplicitGroupRoute(route);
  const explicitGroupSourceCount = Array.isArray(route.sourceRouteIds) ? route.sourceRouteIds.length : 0;
  const readOnlyRoute = route.kind === 'zero_channel' || route.readOnly === true || route.isVirtual === true;
  const channelManagementDisabled = explicitGroupRoute;
  const title = resolveRouteTitle(route);
  const routingStrategy = normalizeRouteRoutingStrategyValue(route.routingStrategy);
  const hasCachedDecisionSnapshot = !!route.decisionSnapshot;
  const cachedDecisionTooltip = route.decisionRefreshedAt
    ? `${tr('最近刷新')}: ${formatDateTimeMinuteLocal(route.decisionRefreshedAt)}`
    : undefined;
  const routingStrategyOptions = [
    {
      value: 'weighted',
      label: tr('权重随机'),
      description: tr('按优先级、权重和成本信号综合选择'),
    },
    {
      value: 'round_robin',
      label: tr('轮询'),
      description: tr('按全局顺序轮流调用，忽略优先级，连续失败 3 次后进入分级冷却'),
    },
    {
      value: 'stable_first',
      label: tr('稳定优先'),
      description: tr('按优先级优先选择当前最稳、最快、成功率更高的通道，不做随机分流'),
    },
  ] as const;

  const sensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 4 } }),
    useSensor(KeyboardSensor, { coordinateGetter: sortableKeyboardCoordinates }),
  );

  const decisionMap = new Map<number, RouteDecisionCandidate>(
    (routeDecision?.candidates || []).map((c) => [c.channelId, c]),
  );

  const priorityBuckets = buildPriorityBuckets(channels || []);
  const priorityRailSections = buildPriorityRailSections(channels || []);
  const [activeDragChannelId, setActiveDragChannelId] = useState<number | null>(null);
  const [dragOverId, setDragOverId] = useState<string | number | null>(null);
  const activeDragBucketIndex = activeDragChannelId == null
    ? -1
    : priorityBuckets.findIndex((bucket) => bucket.channels.some((channel) => channel.id === activeDragChannelId));
  const hoveredBucketIndex = typeof dragOverId === 'number'
    ? priorityBuckets.findIndex((bucket) => bucket.channels.some((channel) => channel.id === dragOverId))
    : -1;
  const hoveredNewLayerBucketIndex = typeof dragOverId === 'string' && isPriorityRailNewLayerId(dragOverId)
    ? priorityBuckets.findIndex((bucket) => createPriorityRailNewLayerId(bucket.priority) === dragOverId)
    : -1;

  const clearDragState = () => {
    setActiveDragChannelId(null);
    setDragOverId(null);
  };

  const handleDragStart = (event: DragStartEvent) => {
    const nextId = Number(event.active.id);
    setActiveDragChannelId(Number.isFinite(nextId) ? nextId : null);
    setDragOverId(event.active.id);
  };

  const handleDragOver = (event: DragOverEvent) => {
    setDragOverId(event.over?.id ?? null);
  };

  const handleDragEnd = (event: DragEndEvent) => {
    onChannelDragEnd(route.id, event);
    clearDragState();
  };
  const renderClearCooldownButton = () => {
    if (readOnlyRoute) return null;
    return (
      <button onClick={() => onClearCooldown(route.id)} className="btn btn-link btn-link-info" disabled={clearingCooldown}>
        {clearingCooldown ? tr('清除中...') : tr('清除冷却')}
      </button>
    );
  };

  // Collapsed card
  if (!expanded) {
    return (
      <div
        className="card route-card-collapsed"
        onClick={() => onToggleExpand(route.id)}
        style={{ cursor: 'pointer' }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 0 }}>
          <span style={{ display: 'inline-flex', alignItems: 'center', flexShrink: 0, width: 20, height: 20 }}>
            {routeIcon.kind === 'brand' ? (
              <BrandGlyph icon={routeIcon.value} alt={title} size={18} fallbackText={title} />
            ) : routeIcon.kind === 'text' ? (
              <span style={{ fontSize: 14, lineHeight: 1 }}>{routeIcon.value}</span>
            ) : routeIcon.kind === 'auto' && brand ? (
              <BrandGlyph brand={brand} alt={title} size={18} fallbackText={title} />
            ) : routeIcon.kind === 'auto' ? (
              <InlineBrandIcon model={route.modelPattern} size={18} />
            ) : null}
          </span>

          <code style={{ fontWeight: 600, fontSize: 13, color: 'var(--color-text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', minWidth: 0, flex: 1 }}>
            {title}
          </code>

          {route.displayName && route.displayName.trim() !== route.modelPattern ? (
            <span
              className="badge badge-muted"
              title={route.modelPattern}
              style={{
                fontSize: 10,
                flexShrink: 1,
                minWidth: 0,
                maxWidth: 180,
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                whiteSpace: 'nowrap',
              }}
            >
              {route.modelPattern}
            </span>
          ) : null}

          {readOnlyRoute ? (
            <span className="badge badge-muted" style={{ fontSize: 10, flexShrink: 0 }}>
              {tr('未生成')}
            </span>
          ) : (
            <button
              className={`badge route-enable-toggle ${route.enabled ? 'is-enabled' : 'is-disabled'}`}
              style={{ fontSize: 11, cursor: 'pointer', border: 'none', flexShrink: 0, minWidth: 36, textAlign: 'center' }}
              onClick={(e) => { e.stopPropagation(); onToggleEnabled(route); }}
              data-tooltip={route.enabled ? '点击禁用此路由' : '点击启用此路由'}
            >
              {route.enabled ? tr('启用') : tr('禁用')}
            </button>
          )}

          {explicitGroupRoute && explicitGroupSourceCount > 0 ? (
            <>
              <span className="badge badge-info" style={{ fontSize: 10, flexShrink: 0 }}>
                {explicitGroupSourceCount} {tr('来源模型')}
              </span>
              <span className="badge badge-muted" style={{ fontSize: 10, flexShrink: 0 }}>
                {route.channelCount} {tr('通道')}
              </span>
            </>
          ) : (
            <span className="badge badge-info" style={{ fontSize: 10, flexShrink: 0 }}>
              {route.channelCount} {tr('通道')}
            </span>
          )}
          {hasCachedDecisionSnapshot ? (
            <span
              className="badge badge-success"
              data-tooltip={cachedDecisionTooltip}
              style={{ fontSize: 10, flexShrink: 0 }}
            >
              {tr('已缓存')}
            </span>
          ) : null}

          {readOnlyRoute ? (
            <span className="badge badge-warning" style={{ fontSize: 10, flexShrink: 0 }}>
              {tr('0 通道')}
            </span>
          ) : (
            <span className="badge badge-muted" style={{ fontSize: 10, flexShrink: 0 }}>
              {getRouteRoutingStrategyLabel(routingStrategy)}
            </span>
          )}

          <svg
            width="14" height="14" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="2"
            style={{ flexShrink: 0, color: 'var(--color-text-muted)' }}
            aria-hidden
          >
            <path d="m5 7 5 6 5-6" />
          </svg>
        </div>
      </div>
    );
  }

  // Expanded card
  return (
    <div className={`card route-card-expanded ${compact ? 'route-card-expanded-compact' : ''}`.trim()} style={{ padding: compact ? 14 : 16 }}>
      {!compact ? (
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12, gap: 8, flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <code style={{ fontWeight: 600, fontSize: 13, background: 'var(--color-bg)', padding: '4px 10px', borderRadius: 6, color: 'var(--color-text-primary)', display: 'inline-flex', alignItems: 'center', gap: 5 }}>
              {routeIcon.kind === 'brand' ? (
                <BrandGlyph icon={routeIcon.value} alt={title} size={20} fallbackText={title} />
              ) : routeIcon.kind === 'text' ? (
                <span style={{ width: 20, height: 20, display: 'inline-flex', alignItems: 'center', justifyContent: 'center', borderRadius: 8, background: 'var(--color-bg-card)', fontSize: 14, lineHeight: 1 }}>
                  {routeIcon.value}
                </span>
              ) : routeIcon.kind === 'auto' && brand ? (
                <BrandGlyph brand={brand} alt={title} size={20} fallbackText={title} />
              ) : routeIcon.kind === 'auto' ? (
                <InlineBrandIcon model={route.modelPattern} size={20} />
              ) : null}
              {title}
            </code>
            {route.displayName && route.displayName.trim() !== route.modelPattern ? (
              <span className="badge badge-muted" style={{ fontSize: 10 }}>{route.modelPattern}</span>
            ) : null}
            {readOnlyRoute ? (
              <span className="badge badge-muted" style={{ fontSize: 10 }}>
                {tr('未生成')}
              </span>
            ) : (
              <button
                className={`badge route-enable-toggle ${route.enabled ? 'is-enabled' : 'is-disabled'}`}
                style={{ fontSize: 11, cursor: 'pointer', border: 'none' }}
                onClick={(e) => { e.stopPropagation(); onToggleEnabled(route); }}
                data-tooltip={route.enabled ? '点击禁用此路由' : '点击启用此路由'}
              >
                {route.enabled ? tr('启用') : tr('禁用')}
              </button>
            )}
            {explicitGroupRoute && explicitGroupSourceCount > 0 ? (
              <>
                <span className="badge badge-info" style={{ fontSize: 10 }}>
                  {explicitGroupSourceCount} {tr('来源模型')}
                </span>
                <span className="badge badge-muted" style={{ fontSize: 10 }}>
                  {route.channelCount} {tr('通道')}
                </span>
              </>
            ) : (
              <span className="badge badge-info" style={{ fontSize: 10 }}>
                {route.channelCount} {tr('通道')}
              </span>
            )}
            {hasCachedDecisionSnapshot ? (
              <span
                className="badge badge-success"
                data-tooltip={cachedDecisionTooltip}
                style={{ fontSize: 10 }}
              >
                {tr('已缓存')}
              </span>
            ) : null}
            {readOnlyRoute && (
              <span className="badge badge-warning" style={{ fontSize: 10 }}>
                {tr('0 通道')}
              </span>
            )}
            {savingPriority && (
              <span className="badge badge-warning" style={{ fontSize: 10 }}>{tr('排序保存中')}</span>
            )}
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            {renderClearCooldownButton()}
            {!readOnlyRoute && (explicitGroupRoute || !exactRoute) && (
              <button onClick={() => onEdit(route)} className="btn btn-link">{tr('编辑群组')}</button>
            )}
            {!readOnlyRoute && <button onClick={() => onDelete(route.id)} className="btn btn-link btn-link-danger">{tr('删除路由')}</button>}
            <button
              onClick={() => onToggleExpand(route.id)}
              className="btn btn-ghost"
              style={{ padding: '4px 8px', border: '1px solid var(--color-border)' }}
              data-tooltip={tr('收起')}
            >
              <svg
                width="14" height="14" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="2"
                style={{ transform: 'rotate(180deg)' }}
                aria-hidden
              >
                <path d="m5 7 5 6 5-6" />
              </svg>
            </button>
          </div>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginBottom: 12 }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 10, flexWrap: 'wrap' }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--color-text-primary)' }}>
                {tr('路由详情与通道管理')}
              </div>
              <div style={{ fontSize: 11, color: 'var(--color-text-muted)' }}>
                {title}
              </div>
            </div>
            {!readOnlyRoute && (
              <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap', justifyContent: 'flex-end' }}>
                {renderClearCooldownButton()}
                {!exactRoute && (
                  <button onClick={() => onEdit(route)} className="btn btn-link">{explicitGroupRoute ? tr('编辑群组') : tr('编辑路由')}</button>
                )}
                <button onClick={() => onDelete(route.id)} className="btn btn-link btn-link-danger">{tr('删除路由')}</button>
              </div>
            )}
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
            {readOnlyRoute ? (
              <span className="badge badge-muted" style={{ fontSize: 10 }}>{tr('未生成')}</span>
            ) : (
              <span className={`badge ${route.enabled ? 'badge-success' : 'badge-muted'}`} style={{ fontSize: 10 }}>
                {route.enabled ? tr('启用') : tr('禁用')}
              </span>
            )}
            <span className="badge badge-info" style={{ fontSize: 10 }}>
              {route.channelCount} {tr('通道')}
            </span>
            {hasCachedDecisionSnapshot ? (
              <span
                className="badge badge-success"
                data-tooltip={cachedDecisionTooltip}
                style={{ fontSize: 10 }}
              >
                {tr('已缓存')}
              </span>
            ) : null}
            {explicitGroupRoute && explicitGroupSourceCount > 0 ? (
              <span className="badge badge-muted" style={{ fontSize: 10 }}>
                {explicitGroupSourceCount} {tr('来源模型')}
              </span>
            ) : null}
            {savingPriority ? <span className="badge badge-warning" style={{ fontSize: 10 }}>{tr('排序保存中')}</span> : null}
          </div>
        </div>
      )}

      {explicitGroupRoute ? (
        <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginBottom: 10 }}>
          {tr('该群组会将多个来源模型聚合为一个对外模型名；这里调整优先级桶时会直接回写来源通道。若某个来源模型被其他群组复用，保存前会提示影响范围。')}
        </div>
      ) : !exactRoute ? (
        <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginBottom: 10 }}>
          {tr('通配符路由按请求实时决策；下方优先级桶在整条路由内全局生效，来源模型只作为通道标签展示。')}
        </div>
      ) : null}

      {!readOnlyRoute && (
        <div style={{ display: 'flex', alignItems: compact ? 'stretch' : 'center', flexDirection: compact ? 'column' : 'row', justifyContent: 'space-between', gap: 12, marginBottom: 12, flexWrap: 'wrap' }}>
          <div style={{ fontSize: 12, color: 'var(--color-text-secondary)', minWidth: compact ? '100%' : undefined }}>
            {tr('路由策略')}
          </div>
          <div style={{ minWidth: compact ? '100%' : 220, maxWidth: compact ? '100%' : 320, flex: compact ? '1 1 100%' : '1 1 220px', width: compact ? '100%' : undefined }}>
            <ModernSelect
              size="sm"
              value={routingStrategy}
              disabled={updatingRoutingStrategy}
              onChange={(nextValue) => onRoutingStrategyChange(route, nextValue as RouteRoutingStrategy)}
              options={routingStrategyOptions.map((option) => ({ ...option }))}
              placeholder={tr('选择路由策略')}
              emptyLabel={tr('暂无可选策略')}
            />
          </div>
        </div>
      )}

      {/* Missing token hints + Add channel button */}
      <div style={{ display: 'flex', alignItems: compact ? 'stretch' : 'flex-start', flexDirection: compact ? 'column' : 'row', justifyContent: 'space-between', gap: 8, marginBottom: 10, flexWrap: 'wrap' }}>
        {!channelManagementDisabled && (missingTokenSiteItems.length > 0 || missingTokenGroupItems.length > 0) ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6, flex: 1 }}>
            {missingTokenSiteItems.length > 0 && (
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                <span style={{ fontSize: 12, color: 'var(--color-text-secondary)' }}>{tr('待注册站点')}:</span>
                {missingTokenSiteItems.map((item) => (
                  <button
                    key={`missing-${route.id}-${item.key}`}
                    type="button"
                    onClick={() => onCreateTokenForMissing(item.accountId, route.modelPattern)}
                    className="badge badge-info missing-token-site-tag"
                    data-tooltip={`点击跳转到令牌创建（预选 ${item.siteName}/${item.accountLabel}）`}
                    style={{ fontSize: 11, cursor: 'pointer' }}
                  >
                    {item.siteName}
                  </button>
                ))}
              </div>
            )}
            {missingTokenGroupItems.length > 0 && (
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                <span style={{ fontSize: 12, color: 'var(--color-text-secondary)' }}>{tr('缺少分组')}:</span>
                {missingTokenGroupItems.map((item) => (
                  <button
                    key={`missing-group-${route.id}-${item.key}`}
                    type="button"
                    onClick={() => onCreateTokenForMissing(item.accountId, route.modelPattern)}
                    className="badge badge-warning missing-token-group-tag"
                    data-tooltip={`缺少分组：${item.missingGroups.join('、') || '未知'}${item.availableGroups.length > 0 ? `；已覆盖：${item.availableGroups.join('、')}` : ''}${item.groupCoverageUncertain ? '；当前分组覆盖存在不确定性' : ''}`}
                    style={{ fontSize: 11, cursor: 'pointer' }}
                  >
                    {item.siteName}
                  </button>
                ))}
              </div>
            )}
          </div>
        ) : <div />}
        {!readOnlyRoute && !channelManagementDisabled && (
          <button
            onClick={() => onAddChannel(route.id)}
            className="btn btn-ghost"
            style={{ fontSize: 12, padding: '6px 10px', color: 'var(--color-primary)', border: '1px solid var(--color-border)', whiteSpace: compact ? 'normal' : 'nowrap', width: compact ? '100%' : 'auto' }}
          >
            + {tr('添加通道')}
          </button>
        )}
      </div>

      {/* Channel list */}
      {loadingChannels ? (
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '12px 0' }}>
          <span className="spinner spinner-sm" />
          <span style={{ fontSize: 13, color: 'var(--color-text-muted)' }}>{tr('加载通道中...')}</span>
        </div>
      ) : channels && channels.length > 0 ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          <DndContext
            sensors={sensors}
            collisionDetection={closestCenter}
            onDragStart={handleDragStart}
            onDragOver={handleDragOver}
            onDragCancel={clearDragState}
            onDragEnd={handleDragEnd}
          >
            <SortableContext items={(channels || []).map((channel) => channel.id)} strategy={verticalListSortingStrategy}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: compact ? 10 : 12 }}>
                {priorityBuckets.map((bucket, bucketIndex) => {
                  const railSection = priorityRailSections[bucketIndex];
                  const railLabel = `P${bucketIndex} · ${bucket.channels.length}`;
                  const mobileRailLabel = `${railLabel} ${tr('通道')}`;
                  const hoveredExistingLayer = activeDragChannelId != null && hoveredBucketIndex === bucketIndex;
                  const hoveredCrossLayer = hoveredExistingLayer && activeDragBucketIndex !== bucketIndex;
                  const hoveredNewLayer = activeDragChannelId != null && hoveredNewLayerBucketIndex === bucketIndex;
                  const railNodeStyle = buildPriorityRailNodeStyle(bucketIndex, hoveredExistingLayer);

                  return (
                    <div
                      key={`${route.id}-priority-bucket-${bucket.priority}-${bucketIndex}`}
                      style={{
                        display: 'flex',
                        flexDirection: 'column',
                        gap: compact ? 8 : 10,
                      }}
                    >
                      <div
                        style={{
                          display: compact ? 'flex' : 'grid',
                          flexDirection: compact ? 'column' : undefined,
                          gridTemplateColumns: compact ? undefined : '86px minmax(0, 1fr)',
                          gap: compact ? 8 : 12,
                          alignItems: compact ? 'stretch' : 'stretch',
                        }}
                      >
                        {compact ? (
                          <div
                            className="route-priority-bucket-header"
                            style={{
                              display: 'flex',
                              alignItems: 'center',
                              gap: 8,
                              flexWrap: 'wrap',
                              padding: '2px 2px 0',
                              fontSize: 12,
                              color: 'var(--color-text-secondary)',
                            }}
                          >
                            <span
                              style={{
                                fontSize: 12,
                                fontWeight: 600,
                                color: 'var(--color-text-secondary)',
                              }}
                            >
                              {mobileRailLabel}
                            </span>
                          </div>
                        ) : (
                          <div
                            aria-hidden
                            style={{
                              width: 86,
                              flexShrink: 0,
                              display: 'flex',
                              flexDirection: 'column',
                              alignItems: 'center',
                              paddingTop: 4,
                            }}
                          >
                            <div
                              style={{
                                minWidth: 72,
                                padding: '6px 10px',
                                borderRadius: 999,
                                fontSize: 11,
                                fontWeight: 600,
                                textAlign: 'center',
                                lineHeight: 1.2,
                                transition: 'all 0.16s ease',
                                ...railNodeStyle,
                              }}
                            >
                              {railSection ? `P${bucketIndex} · ${railSection.channelCount}` : railLabel}
                            </div>
                            {hoveredCrossLayer ? (
                              <div style={{ marginTop: 6, fontSize: 11, color: 'var(--color-primary)', textAlign: 'center' }}>
                                {`放到 P${bucketIndex}`}
                              </div>
                            ) : null}
                            {bucketIndex < priorityBuckets.length - 1 ? (
                              <div style={{ width: 1, flex: 1, marginTop: 8, background: 'var(--color-border)' }} />
                            ) : null}
                          </div>
                        )}

                        <div style={{ display: 'flex', flexDirection: 'column', gap: 6, minWidth: 0, flex: 1 }}>
                          {bucket.channels.map((channel) => {
                            const tokenOptions = candidateView.tokenOptionsByAccountId[channel.accountId] || [];
                            const activeTokenId = channelTokenDraft[channel.id] ?? channel.tokenId ?? 0;
                            return (
                              <SortableChannelRow
                                key={channel.id}
                                channel={channel}
                                displayPriority={bucketIndex}
                                showPriorityBadge={compact}
                                decisionCandidate={decisionMap.get(channel.id)}
                                isExactRoute={exactRoute}
                                loadingDecision={loadingDecision}
                                isSavingPriority={savingPriority}
                                readOnly={readOnlyRoute}
                                channelManagementDisabled={channelManagementDisabled}
                                mobile={compact}
                                tokenOptions={tokenOptions}
                                activeTokenId={activeTokenId}
                                isUpdatingToken={!!updatingChannel[channel.id]}
                                onTokenDraftChange={onTokenDraftChange}
                                onSaveToken={() => onSaveToken(route.id, channel.id, channel.accountId)}
                                onDeleteChannel={() => onDeleteChannel(channel.id, route.id)}
                                onToggleEnabled={(enabled) => onToggleChannelEnabled(channel.id, route.id, enabled)}
                                onSiteBlockModel={channelManagementDisabled ? undefined : () => onSiteBlockModel(channel.id, route.id)}
                              />
                            );
                          })}
                        </div>
                      </div>

                      {!compact && activeDragChannelId != null && !readOnlyRoute ? (
                        <PriorityRailNewLayerRow
                          id={createPriorityRailNewLayerId(bucket.priority)}
                          highlighted={hoveredNewLayer}
                        />
                      ) : null}
                    </div>
                  );
                })}
              </div>
            </SortableContext>
          </DndContext>
        </div>
      ) : (
        <div style={{ fontSize: 13, color: 'var(--color-text-muted)', paddingLeft: 4 }}>
          {readOnlyRoute ? tr('暂无通道，先补齐连接配置后再重建路由。') : tr('暂无通道')}
        </div>
      )}
    </div>
  );
}

const RouteCard = memo(RouteCardInner);
export default RouteCard;
