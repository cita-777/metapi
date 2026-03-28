import { memo, useState, type ReactNode } from 'react';
import {
  DndContext,
  KeyboardSensor,
  PointerSensor,
  closestCenter,
  type DragEndEvent,
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
  buildSourceGroupKey,
} from './utils.js';

type RouteCardProps = {
  route: RouteSummaryRow;
  brand: BrandInfo | null;
  expanded: boolean;
  compact?: boolean;
  onToggleExpand: (routeId: number) => void;
  onEdit: (route: RouteSummaryRow) => void;
  onDelete: (routeId: number) => void;
  onToggleEnabled: (route: RouteSummaryRow) => void;
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

function RouteCardInner({
  route,
  brand,
  expanded,
  compact = false,
  onToggleExpand,
  onEdit,
  onDelete,
  onToggleEnabled,
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

  const channelGroups = (() => {
    if (!channels || channels.length === 0) return [];
    const groups = new Map<string, RouteChannel[]>();
    for (const channel of channels) {
      const key = (channel.sourceModel || '').trim() || '__ungrouped__';
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key)!.push(channel);
    }
    return Array.from(groups.entries())
      .sort((a, b) => {
        if (a[0] === '__ungrouped__') return 1;
        if (b[0] === '__ungrouped__') return -1;
        return a[0].localeCompare(b[0], undefined, { sensitivity: 'base' });
      })
      .map(([sourceModel, chans]) => ({
        sourceModel: sourceModel === '__ungrouped__' ? '' : sourceModel,
        channels: chans,
      }));
  })();

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
          {tr('该群组会将多个来源模型聚合为一个对外模型名；当前策略以群组设置为准，来源模型会尽量跟随同步，但已单独自定义或被其他群组复用的来源模型不会被覆盖。')}
        </div>
      ) : !exactRoute ? (
        <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginBottom: 10 }}>
          {tr('通配符路由按请求实时决策；概率解释在当前路由内统一估算。')}
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
          <DndContext sensors={sensors} collisionDetection={closestCenter} onDragEnd={(event) => onChannelDragEnd(route.id, event)}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {channelGroups.map((group) => {
                const groupKey = buildSourceGroupKey(route.id, group.sourceModel || '');
                const supportsCollapse = !exactRoute && !!group.sourceModel;
                const isGroupExpanded = supportsCollapse ? !!expandedSourceGroupMap[groupKey] : true;

                return (
                  <div key={`${route.id}-${group.sourceModel || '__ungrouped__'}`} style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                    {group.sourceModel ? (
                      supportsCollapse ? (
                        <button
                          type="button"
                          onClick={() => onToggleSourceGroup(groupKey)}
                          aria-expanded={isGroupExpanded}
                          className="btn btn-ghost"
                          style={{
                            fontSize: 12, color: 'var(--color-text-secondary)', display: 'flex',
                            alignItems: 'center', justifyContent: 'space-between', gap: 8,
                            padding: '4px 6px', border: '1px dashed var(--color-border)',
                            borderRadius: 'var(--radius-sm)', background: 'transparent',
                          }}
                        >
                          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
                            <span>来源模型</span>
                            <code style={{ fontSize: 11, border: '1px solid var(--color-border)', borderRadius: 6, padding: '2px 6px', background: 'var(--color-bg)' }}>
                              {group.sourceModel}
                            </code>
                            <span style={{ color: 'var(--color-text-muted)' }}>{group.channels.length} 通道</span>
                          </span>
                          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, color: 'var(--color-text-muted)' }}>
                            {isGroupExpanded ? '收起' : '展开'}
                            <svg width="12" height="12" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="2"
                              style={{ transform: isGroupExpanded ? 'rotate(180deg)' : 'rotate(0deg)', transition: 'transform 0.2s ease' }}
                              aria-hidden
                            >
                              <path d="m5 7 5 6 5-6" />
                            </svg>
                          </span>
                        </button>
                      ) : (
                        <div style={{ fontSize: 12, color: 'var(--color-text-secondary)', display: 'flex', alignItems: 'center', gap: 8, paddingLeft: 2 }}>
                          <span>来源模型</span>
                          <code style={{ fontSize: 11, border: '1px solid var(--color-border)', borderRadius: 6, padding: '2px 6px', background: 'var(--color-bg)' }}>
                            {group.sourceModel}
                          </code>
                          <span style={{ color: 'var(--color-text-muted)' }}>{group.channels.length} 通道</span>
                        </div>
                      )
                    ) : null}

                    <AnimatedCollapseSection open={isGroupExpanded}>
                      {explicitGroupRoute ? (
                        <SortableContext items={group.channels.map((c) => c.id)} strategy={verticalListSortingStrategy}>
                          {group.channels.map((channel) => {
                            const tokenOptions = candidateView.tokenOptionsByAccountId[channel.accountId] || [];
                            const activeTokenId = channelTokenDraft[channel.id] ?? channel.tokenId ?? 0;
                            return (
                              <SortableChannelRow
                                key={channel.id}
                                channel={channel}
                                decisionCandidate={decisionMap.get(channel.id)}
                                isExactRoute={exactRoute}
                                loadingDecision={loadingDecision}
                                isSavingPriority={!!savingPriority}
                                readOnly
                                mobile={compact}
                                tokenOptions={tokenOptions}
                                activeTokenId={activeTokenId}
                                isUpdatingToken={!!updatingChannel[channel.id]}
                                onTokenDraftChange={onTokenDraftChange}
                                onSaveToken={() => onSaveToken(route.id, channel.id, channel.accountId)}
                                onDeleteChannel={() => onDeleteChannel(channel.id, route.id)}
                                onToggleEnabled={(enabled) => onToggleChannelEnabled(channel.id, route.id, enabled)}
                              />
                            );
                          })}
                        </SortableContext>
                      ) : (
                        <SortableContext items={group.channels.map((c) => c.id)} strategy={verticalListSortingStrategy}>
                          {group.channels.map((channel) => {
                            const tokenOptions = candidateView.tokenOptionsByAccountId[channel.accountId] || [];
                            const activeTokenId = channelTokenDraft[channel.id] ?? channel.tokenId ?? 0;
                            return (
                              <SortableChannelRow
                                key={channel.id}
                                channel={channel}
                                decisionCandidate={decisionMap.get(channel.id)}
                                isExactRoute={exactRoute}
                                loadingDecision={loadingDecision}
                                isSavingPriority={savingPriority}
                                mobile={compact}
                                tokenOptions={tokenOptions}
                                activeTokenId={activeTokenId}
                                isUpdatingToken={!!updatingChannel[channel.id]}
                                onTokenDraftChange={onTokenDraftChange}
                                onSaveToken={() => onSaveToken(route.id, channel.id, channel.accountId)}
                                onDeleteChannel={() => onDeleteChannel(channel.id, route.id)}
                                onToggleEnabled={(enabled) => onToggleChannelEnabled(channel.id, route.id, enabled)}
                                onSiteBlockModel={() => onSiteBlockModel(channel.id, route.id)}
                              />
                            );
                          })}
                        </SortableContext>
                      )}
                    </AnimatedCollapseSection>
                    {!isGroupExpanded && (
                      <div style={{ fontSize: 11, color: 'var(--color-text-muted)', paddingLeft: 6 }}>
                        已收起，点击展开查看通道
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
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
