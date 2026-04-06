import { Fragment, memo, useState, type CSSProperties, type ReactNode } from 'react';
import { createPortal } from 'react-dom';
import {
  DndContext,
  DragOverlay,
  KeyboardSensor,
  PointerSensor,
  closestCenter,
  type DragEndEvent,
  type DragStartEvent,
  useDroppable,
  useSensor,
  useSensors,
} from '@dnd-kit/core';
import {
  SortableContext,
  sortableKeyboardCoordinates,
  useSortable,
} from '@dnd-kit/sortable';
import { CSS } from '@dnd-kit/utilities';
import { BrandGlyph, InlineBrandIcon, type BrandInfo } from '../../components/BrandIcon.js';
import ModernSelect from '../../components/ModernSelect.js';
import { tr } from '../../i18n.js';
import { formatDateTimeMinuteLocal } from '../helpers/checkinLogTime.js';
import type {
  RouteSummaryRow,
  RouteChannel,
  RouteChannelRouteUnit,
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
  getRouteRoutingStrategyDescription,
  getRouteRoutingStrategyHint,
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
import { translateOnlyRectSortingStrategy } from './sortingStrategies.js';

type RouteCardProps = {
  route: RouteSummaryRow;
  brand: BrandInfo | null;
  expanded: boolean;
  compact?: boolean;
  summaryExpanded?: boolean;
  detailPanel?: boolean;
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

function getRouteUnitStrategyLabel(strategy: string | null | undefined): string {
  return strategy === 'stick_until_unavailable' ? '单个用到不可用再切' : '轮询';
}

function collectRouteUnits(channels: RouteChannel[] | undefined): RouteChannelRouteUnit[] {
  if (!Array.isArray(channels) || channels.length === 0) return [];
  const unitsById = new Map<string, RouteChannelRouteUnit>();
  for (const channel of channels) {
    const routeUnit = channel.routeUnit;
    if (!routeUnit) continue;
    const key = String(routeUnit.id);
    if (!unitsById.has(key)) {
      unitsById.set(key, routeUnit);
    }
  }
  return Array.from(unitsById.values());
}

function PriorityRailNewLayerRow({
  id,
  highlighted,
  compact = false,
}: {
  id: string;
  highlighted: boolean;
  compact?: boolean;
}) {
  const { setNodeRef, isOver } = useDroppable({ id });
  const active = highlighted || isOver;

  if (compact) {
    return (
      <div
        ref={setNodeRef}
        data-testid="route-priority-new-layer-target"
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          minHeight: 34,
          padding: '0 2px',
        }}
      >
        <div
          style={{
            flex: 1,
            borderTop: `1px dashed ${active ? 'var(--color-primary)' : 'var(--color-border)'}`,
            opacity: active ? 1 : 0.7,
            transition: 'border-color 0.16s ease, opacity 0.16s ease',
          }}
        />
        <div
          style={{
            minWidth: 84,
            padding: '5px 10px',
            borderRadius: 999,
            border: `1px dashed ${active ? 'var(--color-primary)' : 'var(--color-border)'}`,
            background: active
              ? 'color-mix(in srgb, var(--color-primary) 10%, var(--color-bg-card))'
              : 'color-mix(in srgb, var(--color-bg-card) 96%, white 4%)',
            color: active ? 'var(--color-primary)' : 'var(--color-text-muted)',
            fontSize: 11,
            fontWeight: 600,
            textAlign: 'center',
            lineHeight: 1.2,
            transition: 'border-color 0.16s ease, background 0.16s ease, color 0.16s ease',
          }}
        >
          {tr('放到新档位')}
        </div>
        <div
          style={{
            flex: 1,
            borderTop: `1px dashed ${active ? 'var(--color-primary)' : 'var(--color-border)'}`,
            opacity: active ? 1 : 0.7,
            transition: 'border-color 0.16s ease, opacity 0.16s ease',
          }}
        />
      </div>
    );
  }

  return (
    <div
      ref={setNodeRef}
      data-testid="route-priority-new-layer-target"
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
          transition: 'border-color 0.16s ease, background 0.16s ease, color 0.16s ease',
        }}
      >
        {tr('放到新档位')}
      </div>
      <div
        style={{
          height: 0,
          borderTop: `1px dashed ${active ? 'var(--color-primary)' : 'var(--color-border)'}`,
          opacity: active ? 1 : 0.75,
          transition: 'border-color 0.16s ease, opacity 0.16s ease',
        }}
      />
    </div>
  );
}

function PriorityBucketHeader({
  label,
  testId,
}: {
  label: string;
  testId?: string;
}) {
  return (
    <div
      data-testid={testId}
      className="route-priority-bucket-header"
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 6,
        flexWrap: 'wrap',
        padding: '0 2px',
        fontSize: 11,
        color: 'var(--color-text-secondary)',
      }}
    >
      <span
        style={{
          fontSize: 11,
          fontWeight: 600,
          color: 'var(--color-text-secondary)',
        }}
      >
        {label}
      </span>
    </div>
  );
}

function PriorityDragPreview({
  channel,
  displayPriority,
  width,
}: {
  channel: RouteChannel;
  displayPriority: number;
  width?: number | null;
}) {
  const resolvedWidth = Number.isFinite(width ?? Number.NaN) ? width ?? undefined : undefined;
  const effectiveTokenName = channel.token?.name || `account-${channel.accountId}`;

  return (
    <div
      data-testid="route-channel-drag-overlay"
      style={{
        width: resolvedWidth,
        height: '100%',
        maxWidth: 'calc(100vw - 32px)',
        boxSizing: 'border-box',
        display: 'grid',
        gridTemplateColumns: 'minmax(0, 1fr) auto',
        gap: 10,
        alignItems: 'center',
        padding: '10px 12px',
        borderRadius: 16,
        border: '1px solid color-mix(in srgb, var(--color-info) 36%, var(--color-border-light))',
        background: 'color-mix(in srgb, var(--color-bg-card) 80%, var(--color-info) 20%)',
        boxShadow: '0 18px 34px rgba(15, 23, 42, 0.14)',
        color: 'var(--color-text-primary)',
        pointerEvents: 'none',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 7, minWidth: 0, flexWrap: 'wrap' }}>
        <span
          className="badge"
          style={{
            fontSize: 10,
            fontWeight: 700,
            letterSpacing: 0.1,
            ...buildPriorityRailNodeStyle(displayPriority, true),
          }}
        >
          P{displayPriority}
        </span>
        <span style={{ fontWeight: 600, minWidth: 0 }}>
          {channel.account?.username || `account-${channel.accountId}`}
        </span>
        <span className="badge badge-muted" style={{ fontSize: 10 }}>
          {channel.site?.name || 'unknown'}
        </span>
        <span
          className="badge"
          style={{
            fontSize: 10,
            background: 'var(--color-info-soft)',
            color: 'var(--color-info)',
            maxWidth: 200,
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap',
          }}
        >
          当前生效：{effectiveTokenName}
        </span>
        {channel.sourceModel ? (
          <span className="badge badge-info" style={{ fontSize: 10 }}>
            {channel.sourceModel}
          </span>
        ) : null}
        {channel.manualOverride ? (
          <span className="badge badge-warning" style={{ fontSize: 10 }}>
            手动配置
          </span>
        ) : null}
      </div>
      <div style={{ fontSize: 11, color: 'var(--color-text-secondary)', whiteSpace: 'nowrap' }}>
        成功/失败 <span style={{ color: 'var(--color-success)', fontWeight: 600 }}>{channel.successCount || 0}</span>
        <span style={{ color: 'var(--color-text-muted)', margin: '0 2px' }}>/</span>
        <span style={{ color: 'var(--color-danger)', fontWeight: 600 }}>{channel.failCount || 0}</span>
      </div>
    </div>
  );
}

function renderDragOverlayNode(node: ReactNode) {
  if (typeof document === 'undefined' || !document.body) {
    return node;
  }
  return createPortal(node, document.body);
}

type SortableChannelShellProps = {
  channel: RouteChannel;
  bucketIndex: number;
  channelIndex: number;
  bucketChannelCount: number;
  totalBucketCount: number;
  compact: boolean;
  readOnlyRoute: boolean;
  savingPriority: boolean;
  candidateView: RouteCandidateView;
  channelTokenDraft: Record<number, number>;
  updatingChannel: Record<number, boolean>;
  activeDragChannelId: number | null;
  decisionMap: Map<number, RouteDecisionCandidate>;
  exactRoute: boolean;
  loadingDecision: boolean;
  channelManagementDisabled: boolean;
  routeId: number;
  onTokenDraftChange: (channelId: number, tokenId: number) => void;
  onSaveToken: (routeId: number, channelId: number, accountId: number) => void;
  onDeleteChannel: (channelId: number, routeId: number) => void;
  onToggleChannelEnabled: (channelId: number, routeId: number, enabled: boolean) => void;
  onSiteBlockModel: (channelId: number, routeId: number) => void;
  railLabel: string;
  mobileRailLabel: string;
  railNodeStyle: CSSProperties;
  showCompactRailHeader: boolean;
  useDragOverlay: boolean;
};

function SortableChannelShell({
  channel,
  bucketIndex,
  channelIndex,
  bucketChannelCount,
  totalBucketCount,
  compact,
  readOnlyRoute,
  savingPriority,
  candidateView,
  channelTokenDraft,
  updatingChannel,
  activeDragChannelId,
  decisionMap,
  exactRoute,
  loadingDecision,
  channelManagementDisabled,
  routeId,
  onTokenDraftChange,
  onSaveToken,
  onDeleteChannel,
  onToggleChannelEnabled,
  onSiteBlockModel,
  railLabel,
  mobileRailLabel,
  railNodeStyle,
  showCompactRailHeader,
  useDragOverlay,
}: SortableChannelShellProps) {
  const {
    attributes,
    listeners,
    setNodeRef,
    setActivatorNodeRef,
    transform,
    transition,
    isDragging,
  } = useSortable({
    id: channel.id,
    disabled: savingPriority || readOnlyRoute,
  });

  const tokenOptions = candidateView.tokenOptionsByAccountId[channel.accountId] || [];
  const activeTokenId = channelTokenDraft[channel.id] ?? channel.tokenId ?? 0;
  const showDesktopRailHeader = !compact && channelIndex === 0;
  const showDesktopRailLine = !compact
    && (bucketIndex < totalBucketCount - 1 || channelIndex < bucketChannelCount - 1);
  const shellTransition = [
    transition,
    'opacity 180ms ease',
  ].filter(Boolean).join(', ');
  const translatedTransform = transform
    ? { ...transform, scaleX: 1, scaleY: 1 }
    : null;

  return (
    <div
      ref={setNodeRef}
      data-testid="route-channel-shell"
      data-channel-id={channel.id}
      style={{
        visibility: useDragOverlay && isDragging ? 'hidden' : undefined,
        transform: CSS.Translate.toString(translatedTransform),
        transition: shellTransition || undefined,
        zIndex: isDragging ? 10 : undefined,
        willChange: isDragging || Boolean(transform) || Boolean(transition) ? 'transform' : undefined,
        display: compact ? 'flex' : 'grid',
        flexDirection: compact ? 'column' : undefined,
        gridTemplateColumns: compact ? undefined : '86px minmax(0, 1fr)',
        gap: compact ? 6 : 12,
        alignItems: 'stretch',
      }}
    >
      {compact && showCompactRailHeader ? (
        <PriorityBucketHeader label={mobileRailLabel} />
      ) : null}

      {!compact ? (
        <div
          aria-hidden
          style={{
            width: 86,
            flexShrink: 0,
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            paddingTop: showDesktopRailHeader ? 2 : 0,
          }}
        >
          {showDesktopRailHeader ? (
            <>
              <div
                style={{
                  minWidth: 64,
                  padding: '5px 8px',
                  borderRadius: 999,
                  fontSize: 11,
                  fontWeight: 600,
                  textAlign: 'center',
                  lineHeight: 1.2,
                  transition: 'border-color 0.16s ease, background 0.16s ease, color 0.16s ease',
                  ...railNodeStyle,
                }}
              >
                {railLabel}
              </div>
            </>
          ) : (
            <div style={{ minWidth: 64 }} />
          )}
          {showDesktopRailLine ? (
            <div
              style={{
                width: 1,
                flex: 1,
                minHeight: showDesktopRailHeader ? 10 : 0,
                marginTop: showDesktopRailHeader ? 6 : 0,
                background: 'var(--color-border)',
              }}
            />
          ) : null}
        </div>
      ) : null}

      <SortableChannelRow
        channel={channel}
        displayPriority={bucketIndex}
        showPriorityBadge={compact}
        dragging={isDragging}
        dragHandleProps={{ ...attributes, ...listeners }}
        dragHandleRef={setActivatorNodeRef}
        dragInProgress={activeDragChannelId != null}
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
        onSaveToken={() => onSaveToken(routeId, channel.id, channel.accountId)}
        onDeleteChannel={() => onDeleteChannel(channel.id, routeId)}
        onToggleEnabled={(enabled) => onToggleChannelEnabled(channel.id, routeId, enabled)}
        onSiteBlockModel={channelManagementDisabled ? undefined : () => onSiteBlockModel(channel.id, routeId)}
      />
    </div>
  );
}

function RouteCardInner({
  route,
  brand,
  expanded,
  compact = false,
  summaryExpanded = false,
  detailPanel = false,
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
  const routingStrategyDescription = getRouteRoutingStrategyDescription(routingStrategy);
  const routingStrategyHint = getRouteRoutingStrategyHint(routingStrategy);
  const hasCachedDecisionSnapshot = !!route.decisionSnapshot;
  const cachedDecisionTooltip = route.decisionRefreshedAt
    ? `${tr('最近刷新')}: ${formatDateTimeMinuteLocal(route.decisionRefreshedAt)}`
    : undefined;
  const showAddChannelButton = !readOnlyRoute && !channelManagementDisabled;
  const showMissingTokenHints = !channelManagementDisabled && (missingTokenSiteItems.length > 0 || missingTokenGroupItems.length > 0);
  const routeUnits = collectRouteUnits(channels);
  const routingStrategyOptions = [
    {
      value: 'weighted',
      label: tr('权重随机'),
      description: getRouteRoutingStrategyDescription('weighted'),
    },
    {
      value: 'round_robin',
      label: tr('轮询'),
      description: getRouteRoutingStrategyDescription('round_robin'),
    },
    {
      value: 'stable_first',
      label: tr('稳定优先'),
      description: getRouteRoutingStrategyDescription('stable_first'),
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
  const [activeDragRowWidth, setActiveDragRowWidth] = useState<number | null>(null);
  const useDragOverlay = compact && detailPanel;

  const clearDragState = () => {
    setActiveDragChannelId(null);
    setActiveDragRowWidth(null);
  };

  const handleDragStart = (event: DragStartEvent) => {
    const nextId = Number(event.active.id);
    setActiveDragChannelId(Number.isFinite(nextId) ? nextId : null);
    setActiveDragRowWidth(event.active.rect?.current?.initial?.width ?? null);
  };

  const handleDragEnd = (event: DragEndEvent) => {
    onChannelDragEnd(route.id, event);
    clearDragState();
  };
  const activeDragChannel = activeDragChannelId == null
    ? null
    : (channels || []).find((channel) => channel.id === activeDragChannelId) || null;
  const activeDragBucketIndex = activeDragChannel == null
    ? -1
    : priorityBuckets.findIndex((bucket) => bucket.channels.some((channel) => channel.id === activeDragChannel.id));
  const renderClearCooldownButton = () => {
    if (readOnlyRoute) return null;
    return (
      <button onClick={() => onClearCooldown(route.id)} className="btn btn-link btn-link-info" disabled={clearingCooldown}>
        {clearingCooldown ? tr('清除中...') : tr('清除冷却')}
      </button>
    );
  };
  const renderAddChannelButton = ({
    fullWidth = false,
    alignRight = false,
  }: {
    fullWidth?: boolean;
    alignRight?: boolean;
  } = {}) => (
    <button
      onClick={() => onAddChannel(route.id)}
      className="btn btn-ghost"
      style={{
        fontSize: 11.5,
        padding: '5px 10px',
        color: 'var(--color-text-secondary)',
        background: 'color-mix(in srgb, var(--color-bg-card) 96%, white 4%)',
        border: '1px dashed color-mix(in srgb, var(--color-border) 88%, transparent)',
        borderRadius: 12,
        whiteSpace: fullWidth ? 'normal' : 'nowrap',
        width: fullWidth ? '100%' : 'auto',
        marginLeft: alignRight ? 'auto' : undefined,
      }}
    >
      + {tr('添加通道')}
    </button>
  );

  // Collapsed card
  if (!expanded) {
    return (
      <div
        className={`card route-card-collapsed ${summaryExpanded ? 'is-active' : ''}`.trim()}
        onClick={() => onToggleExpand(route.id)}
        role="button"
        tabIndex={0}
        aria-expanded={summaryExpanded}
        onKeyDown={(event) => {
          if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault();
            onToggleExpand(route.id);
          }
        }}
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

          <div
            data-testid="collapsed-route-title-row"
            style={{ display: 'flex', alignItems: 'center', gap: 6, minWidth: 0, flex: '1 1 180px' }}
          >
            <code
              style={{
                fontWeight: 600,
                fontSize: 13,
                color: 'var(--color-text-primary)',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                whiteSpace: 'nowrap',
                minWidth: 0,
                flex: '1 1 180px',
              }}
            >
              {title}
            </code>

            {route.displayName && route.displayName.trim() !== route.modelPattern ? (
              <span
                className="badge badge-muted"
                title={route.modelPattern}
                style={{
                  fontSize: 10,
                  flex: '0 1 116px',
                  minWidth: 0,
                  maxWidth: 116,
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                }}
              >
                {route.modelPattern}
              </span>
            ) : null}
          </div>

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
            <span
              className="badge badge-muted"
              style={{ fontSize: 10, flexShrink: 0 }}
              data-tooltip={`${getRouteRoutingStrategyLabel(routingStrategy)}：${routingStrategyDescription}`}
            >
              {getRouteRoutingStrategyLabel(routingStrategy)}
            </span>
          )}

          <svg
            width="14" height="14" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="2"
            style={{
              flexShrink: 0,
              color: 'var(--color-text-muted)',
              transform: summaryExpanded ? 'rotate(180deg)' : 'none',
              transition: 'transform 0.18s ease',
            }}
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
    <div
      className={`card route-card-expanded ${compact ? 'route-card-expanded-compact' : ''} ${detailPanel ? 'route-card-detail-panel' : ''}`.trim()}
      style={{ padding: compact ? 10 : 14 }}
    >
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
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginBottom: 8 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, flexWrap: 'wrap' }}>
            <div
              data-testid="compact-route-header-main"
              style={{ display: 'flex', flexDirection: 'row', alignItems: 'center', gap: 5, flexWrap: 'wrap', minWidth: 0, flex: 1 }}
            >
              <code
                style={{
                  fontWeight: 600,
                  fontSize: 12.5,
                  background: 'var(--color-bg)',
                  padding: '3px 8px',
                  borderRadius: 6,
                  color: 'var(--color-text-primary)',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 5,
                  minWidth: 0,
                  maxWidth: '100%',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                }}
              >
                {title}
              </code>
              {route.displayName && route.displayName.trim() !== route.modelPattern ? (
                <span className="badge badge-muted" style={{ fontSize: 10 }}>{route.modelPattern}</span>
              ) : null}
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
            {!readOnlyRoute && (
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', justifyContent: 'flex-end' }}>
                {renderClearCooldownButton()}
                {(explicitGroupRoute || !exactRoute) && (
                  <button onClick={() => onEdit(route)} className="btn btn-link">{tr('编辑群组')}</button>
                )}
                <button onClick={() => onDelete(route.id)} className="btn btn-link btn-link-danger">{tr('删除路由')}</button>
                {detailPanel && (
                  <button
                    onClick={() => onToggleExpand(route.id)}
                    className="btn btn-ghost"
                    style={{ padding: '3px 8px', border: '1px solid var(--color-border)' }}
                  >
                    {tr('收起详情')}
                  </button>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {!compact && explicitGroupRoute ? (
        <div style={{ fontSize: 11, lineHeight: 1.45, color: 'var(--color-text-muted)', marginBottom: 6 }}>
          {tr('该群组会将多个来源模型聚合为一个对外模型名；这里调整优先级桶时会直接回写来源通道。若某个来源模型被其他群组复用，保存前会提示影响范围。')}
        </div>
      ) : !compact && !exactRoute ? (
        <div style={{ fontSize: 11, lineHeight: 1.45, color: 'var(--color-text-muted)', marginBottom: 6 }}>
          {tr('通配符路由按请求实时决策；下方优先级桶在整条路由内全局生效，来源模型只作为通道标签展示。')}
        </div>
      ) : null}

      {routeUnits.length > 0 ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginBottom: 8 }}>
          <div style={{ fontSize: 11.5, color: 'var(--color-text-secondary)' }}>
            OAuth 路由池
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
            {routeUnits.map((routeUnit) => (
              <span
                key={`route-unit-${String(routeUnit.id)}`}
                className="badge badge-info"
                style={{
                  fontSize: 10.5,
                  maxWidth: '100%',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                }}
                title={`${routeUnit.name?.trim() || 'OAuth 路由池'} · ${routeUnit.memberCount} 个成员 · ${getRouteUnitStrategyLabel(routeUnit.strategy)}`}
              >
                {(routeUnit.name?.trim() || 'OAuth 路由池')} · {routeUnit.memberCount} 个成员 · {getRouteUnitStrategyLabel(routeUnit.strategy)}
              </span>
            ))}
          </div>
        </div>
      ) : null}

      {!readOnlyRoute && (
        <div
          data-testid={compact ? 'compact-route-action-row' : undefined}
          style={{
            display: 'flex',
            alignItems: compact ? 'center' : 'center',
            flexDirection: compact ? 'row' : 'row',
            justifyContent: compact ? 'flex-start' : 'space-between',
            gap: compact ? 6 : 8,
            marginBottom: 8,
            flexWrap: 'wrap',
          }}
        >
          {compact ? (
            <>
              <div
                style={{ display: 'flex', alignItems: 'center', gap: 6, minWidth: 0 }}
                data-tooltip={`${routingStrategyDescription} ${routingStrategyHint}`}
              >
                <div
                  style={{ fontSize: 11.5, color: 'var(--color-text-secondary)', flexShrink: 0 }}
                >
                  {tr('路由策略')}
                </div>
                <div
                  data-testid="compact-route-strategy-select"
                  style={{
                    flex: '0 0 168px',
                    minWidth: 168,
                    maxWidth: 168,
                  }}
                >
                  <ModernSelect
                    size="sm"
                    value={routingStrategy}
                    disabled={updatingRoutingStrategy}
                    onChange={(nextValue) => onRoutingStrategyChange(route, nextValue as RouteRoutingStrategy)}
                    options={routingStrategyOptions.map((option) => ({ value: option.value, label: option.label }))}
                    placeholder={tr('选择路由策略')}
                    emptyLabel={tr('暂无可选策略')}
                  />
                </div>
              </div>
              {showAddChannelButton ? renderAddChannelButton({ alignRight: true }) : null}
            </>
          ) : (
            <>
              <div
                style={{ fontSize: 11.5, color: 'var(--color-text-secondary)', minWidth: undefined }}
                data-tooltip={undefined}
              >
                {tr('路由策略')}
              </div>
              <div
                style={{
                  minWidth: 220,
                  maxWidth: 320,
                  flex: '1 1 220px',
                }}
              >
                <ModernSelect
                  size="sm"
                  value={routingStrategy}
                  disabled={updatingRoutingStrategy}
                  onChange={(nextValue) => onRoutingStrategyChange(route, nextValue as RouteRoutingStrategy)}
                  options={routingStrategyOptions.map((option) => ({ ...option }))}
                  placeholder={tr('选择路由策略')}
                  emptyLabel={tr('暂无可选策略')}
                />
                <div style={{ marginTop: 6, display: 'flex', flexDirection: 'column', gap: 2 }}>
                  <div style={{ fontSize: 11.5, lineHeight: 1.45, color: 'var(--color-text-secondary)' }}>
                    {routingStrategyDescription}
                  </div>
                  <div style={{ fontSize: 10.5, lineHeight: 1.4, color: 'var(--color-text-muted)' }}>
                    {routingStrategyHint}
                  </div>
                </div>
              </div>
            </>
          )}
        </div>
      )}

      {/* Missing token hints + Add channel button */}
      <div style={{ display: 'flex', alignItems: compact ? 'stretch' : 'flex-start', flexDirection: compact ? 'column' : 'row', justifyContent: 'space-between', gap: 6, marginBottom: 8, flexWrap: 'wrap' }}>
        {showMissingTokenHints ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4, flex: 1 }}>
            {missingTokenSiteItems.length > 0 && (
              <div style={{ display: 'flex', alignItems: 'center', gap: 5, flexWrap: 'wrap' }}>
                <span style={{ fontSize: 11, color: 'var(--color-text-secondary)' }}>{tr('待注册站点')}:</span>
                {missingTokenSiteItems.map((item) => (
                  <button
                    key={`missing-${route.id}-${item.key}`}
                    type="button"
                    onClick={() => onCreateTokenForMissing(item.accountId, route.modelPattern)}
                    className="badge badge-info missing-token-site-tag"
                    data-tooltip={`点击跳转到令牌创建（预选 ${item.siteName}/${item.accountLabel}）`}
                    style={{ fontSize: 10.5, cursor: 'pointer' }}
                  >
                    {item.siteName}
                  </button>
                ))}
              </div>
            )}
            {missingTokenGroupItems.length > 0 && (
              <div style={{ display: 'flex', alignItems: 'center', gap: 5, flexWrap: 'wrap' }}>
                <span style={{ fontSize: 11, color: 'var(--color-text-secondary)' }}>{tr('缺少分组')}:</span>
                {missingTokenGroupItems.map((item) => (
                  <button
                    key={`missing-group-${route.id}-${item.key}`}
                    type="button"
                    onClick={() => onCreateTokenForMissing(item.accountId, route.modelPattern)}
                    className="badge badge-warning missing-token-group-tag"
                    data-tooltip={`缺少分组：${item.missingGroups.join('、') || '未知'}${item.availableGroups.length > 0 ? `；已覆盖：${item.availableGroups.join('、')}` : ''}${item.groupCoverageUncertain ? '；当前分组覆盖存在不确定性' : ''}`}
                    style={{ fontSize: 10.5, cursor: 'pointer' }}
                  >
                    {item.siteName}
                  </button>
                ))}
              </div>
            )}
          </div>
        ) : (!compact && showAddChannelButton ? <div /> : null)}
        {!compact && showAddChannelButton ? renderAddChannelButton() : null}
      </div>

      {/* Channel list */}
      {loadingChannels ? (
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 0' }}>
          <span className="spinner spinner-sm" />
          <span style={{ fontSize: 13, color: 'var(--color-text-muted)' }}>{tr('加载通道中...')}</span>
        </div>
      ) : channels && channels.length > 0 ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          <DndContext
            sensors={sensors}
            collisionDetection={closestCenter}
            onDragStart={handleDragStart}
            onDragCancel={clearDragState}
            onDragEnd={handleDragEnd}
          >
            <SortableContext items={(channels || []).map((channel) => channel.id)} strategy={translateOnlyRectSortingStrategy}>
              <div
                data-testid="route-channel-sortable-list"
                style={{ display: 'flex', flexDirection: 'column', gap: compact ? 8 : 4 }}
              >
                {priorityBuckets.map((bucket, bucketIndex) => {
                  const railSection = priorityRailSections[bucketIndex];
                  const railLabel = `P${bucketIndex} · ${bucket.channels.length}`;
                  const mobileRailLabel = `${railLabel} ${tr('通道')}`;
                  const railNodeStyle = buildPriorityRailNodeStyle(bucketIndex, false);
                  const showStandaloneCompactRailHeader = compact && detailPanel;
                  const showNewLayerTarget = activeDragChannelId != null
                    && !readOnlyRoute
                    && (!compact || detailPanel);

                  return (
                    <Fragment key={`${route.id}-priority-bucket-${bucket.priority}-${bucketIndex}`}>
                      {showStandaloneCompactRailHeader ? (
                        <PriorityBucketHeader
                          label={mobileRailLabel}
                          testId="route-priority-bucket-header"
                        />
                      ) : null}

                      {bucket.channels.map((channel, channelIndex) => {
                        return (
                          <SortableChannelShell
                            key={channel.id}
                            channel={channel}
                            bucketIndex={bucketIndex}
                            channelIndex={channelIndex}
                            bucketChannelCount={bucket.channels.length}
                            totalBucketCount={priorityBuckets.length}
                            compact={compact}
                            readOnlyRoute={readOnlyRoute}
                            savingPriority={savingPriority}
                            candidateView={candidateView}
                            channelTokenDraft={channelTokenDraft}
                            updatingChannel={updatingChannel}
                            activeDragChannelId={activeDragChannelId}
                            decisionMap={decisionMap}
                            exactRoute={exactRoute}
                            loadingDecision={loadingDecision}
                            channelManagementDisabled={channelManagementDisabled}
                            routeId={route.id}
                            onTokenDraftChange={onTokenDraftChange}
                            onSaveToken={onSaveToken}
                            onDeleteChannel={onDeleteChannel}
                            onToggleChannelEnabled={onToggleChannelEnabled}
                            onSiteBlockModel={onSiteBlockModel}
                            railLabel={railSection ? `P${bucketIndex} · ${railSection.channelCount}` : railLabel}
                            mobileRailLabel={mobileRailLabel}
                            railNodeStyle={railNodeStyle}
                            showCompactRailHeader={!showStandaloneCompactRailHeader && channelIndex === 0}
                            useDragOverlay={useDragOverlay}
                          />
                        );
                      })}

                      {showNewLayerTarget ? (
                        <PriorityRailNewLayerRow
                          id={createPriorityRailNewLayerId(bucket.priority)}
                          highlighted={false}
                          compact={compact}
                        />
                      ) : null}
                    </Fragment>
                  );
                })}
              </div>
            </SortableContext>
            {useDragOverlay ? renderDragOverlayNode(
              <DragOverlay>
                {activeDragChannel ? (
                  <PriorityDragPreview
                    channel={activeDragChannel}
                    displayPriority={Math.max(0, activeDragBucketIndex)}
                    width={activeDragRowWidth}
                  />
                ) : null}
              </DragOverlay>,
            ) : null}
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

function buildChannelInteractionSignature(
  channels: RouteChannel[] | undefined,
  channelTokenDraft: Record<number, number>,
  updatingChannel: Record<number, boolean>,
): string {
  if (!Array.isArray(channels) || channels.length === 0) return '';
  return channels
    .map((channel) => `${channel.id}:${channelTokenDraft[channel.id] ?? ''}:${updatingChannel[channel.id] ? 1 : 0}`)
    .join('|');
}

function areRouteCardPropsEqual(prev: RouteCardProps, next: RouteCardProps): boolean {
  if (
    prev.route !== next.route
    || prev.brand !== next.brand
    || prev.expanded !== next.expanded
    || prev.compact !== next.compact
    || prev.summaryExpanded !== next.summaryExpanded
    || prev.detailPanel !== next.detailPanel
    || prev.onToggleExpand !== next.onToggleExpand
    || prev.onToggleEnabled !== next.onToggleEnabled
  ) {
    return false;
  }

  if (!next.expanded) {
    return true;
  }

  if (
    prev.onEdit !== next.onEdit
    || prev.onDelete !== next.onDelete
    || prev.onClearCooldown !== next.onClearCooldown
    || prev.onRoutingStrategyChange !== next.onRoutingStrategyChange
    || prev.onTokenDraftChange !== next.onTokenDraftChange
    || prev.onSaveToken !== next.onSaveToken
    || prev.onDeleteChannel !== next.onDeleteChannel
    || prev.onToggleChannelEnabled !== next.onToggleChannelEnabled
    || prev.onChannelDragEnd !== next.onChannelDragEnd
    || prev.onCreateTokenForMissing !== next.onCreateTokenForMissing
    || prev.onAddChannel !== next.onAddChannel
    || prev.onSiteBlockModel !== next.onSiteBlockModel
    || prev.onToggleSourceGroup !== next.onToggleSourceGroup
    || prev.clearingCooldown !== next.clearingCooldown
    || prev.updatingRoutingStrategy !== next.updatingRoutingStrategy
    || prev.savingPriority !== next.savingPriority
    || prev.loadingChannels !== next.loadingChannels
    || prev.loadingDecision !== next.loadingDecision
    || prev.routeDecision !== next.routeDecision
    || prev.candidateView !== next.candidateView
    || prev.missingTokenSiteItems !== next.missingTokenSiteItems
    || prev.missingTokenGroupItems !== next.missingTokenGroupItems
    || prev.channels !== next.channels
  ) {
    return false;
  }

  return buildChannelInteractionSignature(prev.channels, prev.channelTokenDraft, prev.updatingChannel)
    === buildChannelInteractionSignature(next.channels, next.channelTokenDraft, next.updatingChannel);
}

const RouteCard = memo(RouteCardInner, areRouteCardPropsEqual);
export default RouteCard;
