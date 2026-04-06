import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, create, type ReactTestInstance } from 'react-test-renderer';
import { SortableContext } from '@dnd-kit/sortable';

const sortableState = vi.hoisted(() => ({
  activeId: null as number | string | null,
}));

vi.mock('@dnd-kit/sortable', async () => {
  const actual = await vi.importActual<typeof import('@dnd-kit/sortable')>('@dnd-kit/sortable');
  return {
    ...actual,
    useSortable: ({ id }: { id: number | string }) => ({
      attributes: {},
      listeners: {},
      setNodeRef: vi.fn(),
      setActivatorNodeRef: vi.fn(),
      transform: null,
      transition: null,
      isDragging: sortableState.activeId === id,
    }),
  };
});

import RouteCard from './RouteCard.js';
import type { RouteChannel, RouteSummaryRow } from './types.js';
import { getRouteRoutingStrategyDescription } from './routingStrategy.js';
import { translateOnlyRectSortingStrategy } from './sortingStrategies.js';

function collectText(node: ReactTestInstance): string {
  return (node.children || []).map((child) => {
    if (typeof child === 'string') return child;
    return collectText(child);
  }).join('');
}

afterEach(() => {
  sortableState.activeId = null;
});

const LONG_REGEX_PATTERN = 're:(?:.*|.*/)(minimax-m2.1)$';

function buildRoute(overrides: Partial<RouteSummaryRow> = {}): RouteSummaryRow {
  return {
    id: 42,
    modelPattern: LONG_REGEX_PATTERN,
    displayName: 'm.',
    displayIcon: null,
    modelMapping: null,
    routingStrategy: 'weighted',
    enabled: true,
    channelCount: 4,
    enabledChannelCount: 4,
    siteNames: ['site-a'],
    decisionSnapshot: null,
    decisionRefreshedAt: null,
    ...overrides,
  };
}

function buildChannel(overrides: Partial<RouteChannel> = {}): RouteChannel {
  return {
    id: 11,
    accountId: 101,
    tokenId: 1001,
    sourceModel: 'gpt-4o-mini',
    priority: 0,
    weight: 1,
    enabled: true,
    manualOverride: false,
    successCount: 0,
    failCount: 0,
    account: { username: 'user_a' },
    site: { id: 1, name: 'site-a', platform: 'openai' },
    token: { id: 1001, name: 'token-a', accountId: 101, enabled: true, isDefault: true },
    ...overrides,
  };
}

describe('RouteCard', () => {
  it('renders oauth route unit summary and member labels on expanded channels', () => {
    const root = create(
      <RouteCard
        route={buildRoute({
          modelPattern: 'gpt-4.1',
          displayName: 'gpt-4.1',
          channelCount: 1,
          enabledChannelCount: 1,
        })}
        brand={null}
        expanded
        onToggleExpand={vi.fn()}
        onEdit={vi.fn()}
        onDelete={vi.fn()}
        onToggleEnabled={vi.fn()}
        onClearCooldown={vi.fn()}
        clearingCooldown={false}
        onRoutingStrategyChange={vi.fn()}
        updatingRoutingStrategy={false}
        channels={[
          buildChannel({
            account: { username: 'route-unit-anchor' },
            routeUnit: {
              id: 'pool-1',
              name: 'Codex Pool A',
              strategy: 'round_robin',
              memberCount: 3,
              members: [
                { accountId: 101, username: 'route-unit-anchor', siteName: 'site-a' },
                { accountId: 102, username: 'route-unit-backup', siteName: 'site-b' },
                { accountId: 103, username: 'route-unit-third', siteName: 'site-c' },
              ],
            },
          }),
        ]}
        loadingChannels={false}
        routeDecision={null}
        loadingDecision={false}
        candidateView={{ routeCandidates: [], accountOptions: [], tokenOptionsByAccountId: {} }}
        channelTokenDraft={{}}
        updatingChannel={{}}
        savingPriority={false}
        onTokenDraftChange={vi.fn()}
        onSaveToken={vi.fn()}
        onDeleteChannel={vi.fn()}
        onToggleChannelEnabled={vi.fn()}
        onChannelDragEnd={vi.fn()}
        missingTokenSiteItems={[]}
        missingTokenGroupItems={[]}
        onCreateTokenForMissing={vi.fn()}
        onAddChannel={vi.fn()}
        onSiteBlockModel={vi.fn()}
        expandedSourceGroupMap={{}}
        onToggleSourceGroup={vi.fn()}
      />,
    );

    const text = collectText(root.root);
    expect(text).toContain('Codex Pool A');
    expect(text).toContain('3 个成员');
    expect(text).toContain('轮询');
    expect(text).toContain('成员摘要');
    expect(text).toContain('route-unit-anchor');
    expect(text).toContain('route-unit-backup');
    expect(text).toContain('route-unit-third');
  });

  it('truncates the collapsed regex badge while keeping the group name primary', () => {
    const root = create(
      <RouteCard
        route={buildRoute()}
        brand={null}
        expanded={false}
        onToggleExpand={vi.fn()}
        onEdit={vi.fn()}
        onDelete={vi.fn()}
        onToggleEnabled={vi.fn()}
        onClearCooldown={vi.fn()}
        clearingCooldown={false}
        onRoutingStrategyChange={vi.fn()}
        updatingRoutingStrategy={false}
        channels={undefined}
        loadingChannels={false}
        routeDecision={null}
        loadingDecision={false}
        candidateView={{ routeCandidates: [], accountOptions: [], tokenOptionsByAccountId: {} }}
        channelTokenDraft={{}}
        updatingChannel={{}}
        savingPriority={false}
        onTokenDraftChange={vi.fn()}
        onSaveToken={vi.fn()}
        onDeleteChannel={vi.fn()}
        onToggleChannelEnabled={vi.fn()}
        onChannelDragEnd={vi.fn()}
        missingTokenSiteItems={[]}
        missingTokenGroupItems={[]}
        onCreateTokenForMissing={vi.fn()}
        onAddChannel={vi.fn()}
        onSiteBlockModel={vi.fn()}
        expandedSourceGroupMap={{}}
        onToggleSourceGroup={vi.fn()}
      />,
    );

    expect(collectText(root.root)).toContain('m.');

    const regexBadge = root.root.find((node) => (
      node.type === 'span'
      && typeof node.props.className === 'string'
      && node.props.className.includes('badge-muted')
      && collectText(node) === LONG_REGEX_PATTERN
    ));

    expect(regexBadge.props.style).toMatchObject({
      flex: '0 1 116px',
      maxWidth: 116,
      minWidth: 0,
      overflow: 'hidden',
      textOverflow: 'ellipsis',
      whiteSpace: 'nowrap',
    });
  });

  it('gives the collapsed group title more layout priority than the regex badge', () => {
    const root = create(
      <RouteCard
        route={buildRoute({
          displayName: 'minimax m2.1 群组名称',
        })}
        brand={null}
        expanded={false}
        onToggleExpand={vi.fn()}
        onEdit={vi.fn()}
        onDelete={vi.fn()}
        onToggleEnabled={vi.fn()}
        onClearCooldown={vi.fn()}
        clearingCooldown={false}
        onRoutingStrategyChange={vi.fn()}
        updatingRoutingStrategy={false}
        channels={undefined}
        loadingChannels={false}
        routeDecision={null}
        loadingDecision={false}
        candidateView={{ routeCandidates: [], accountOptions: [], tokenOptionsByAccountId: {} }}
        channelTokenDraft={{}}
        updatingChannel={{}}
        savingPriority={false}
        onTokenDraftChange={vi.fn()}
        onSaveToken={vi.fn()}
        onDeleteChannel={vi.fn()}
        onToggleChannelEnabled={vi.fn()}
        onChannelDragEnd={vi.fn()}
        missingTokenSiteItems={[]}
        missingTokenGroupItems={[]}
        onCreateTokenForMissing={vi.fn()}
        onAddChannel={vi.fn()}
        onSiteBlockModel={vi.fn()}
        expandedSourceGroupMap={{}}
        onToggleSourceGroup={vi.fn()}
      />,
    );

    const titleRow = root.root.find((node) => (
      node.type === 'div'
      && node.props['data-testid'] === 'collapsed-route-title-row'
    ));
    const titleNode = titleRow.find((node) => (
      node.type === 'code'
      && collectText(node) === 'minimax m2.1 群组名称'
    ));
    const regexBadge = titleRow.find((node) => (
      node.type === 'span'
      && typeof node.props.className === 'string'
      && node.props.className.includes('badge-muted')
      && collectText(node) === LONG_REGEX_PATTERN
    ));

    expect(titleNode.props.style.flex).toBe('1 1 180px');
    expect(regexBadge.props.style.flex).toBe('0 1 116px');
    expect(regexBadge.props.style.maxWidth).toBe(116);
  });

  it('renders a clear cooldown action on expanded cards', () => {
    const onClearCooldown = vi.fn();
    const root = create(
      <RouteCard
        route={buildRoute()}
        brand={null}
        expanded
        onToggleExpand={vi.fn()}
        onEdit={vi.fn()}
        onDelete={vi.fn()}
        onToggleEnabled={vi.fn()}
        onClearCooldown={onClearCooldown}
        clearingCooldown={false}
        onRoutingStrategyChange={vi.fn()}
        updatingRoutingStrategy={false}
        channels={[]}
        loadingChannels={false}
        routeDecision={null}
        loadingDecision={false}
        candidateView={{ routeCandidates: [], accountOptions: [], tokenOptionsByAccountId: {} }}
        channelTokenDraft={{}}
        updatingChannel={{}}
        savingPriority={false}
        onTokenDraftChange={vi.fn()}
        onSaveToken={vi.fn()}
        onDeleteChannel={vi.fn()}
        onToggleChannelEnabled={vi.fn()}
        onChannelDragEnd={vi.fn()}
        missingTokenSiteItems={[]}
        missingTokenGroupItems={[]}
        onCreateTokenForMissing={vi.fn()}
        onAddChannel={vi.fn()}
        onSiteBlockModel={vi.fn()}
        expandedSourceGroupMap={{}}
        onToggleSourceGroup={vi.fn()}
      />,
    );

    const button = root.root.find((node) => (
      node.type === 'button'
      && typeof node.props.onClick === 'function'
      && collectText(node).trim() === '清除冷却'
    ));

    button.props.onClick();
    expect(onClearCooldown).toHaveBeenCalledTimes(1);
  });

  it('lets keyboard users toggle the collapsed summary card', () => {
    const onToggleExpand = vi.fn();
    const root = create(
      <RouteCard
        route={buildRoute()}
        brand={null}
        expanded={false}
        summaryExpanded={false}
        onToggleExpand={onToggleExpand}
        onEdit={vi.fn()}
        onDelete={vi.fn()}
        onToggleEnabled={vi.fn()}
        onClearCooldown={vi.fn()}
        clearingCooldown={false}
        onRoutingStrategyChange={vi.fn()}
        updatingRoutingStrategy={false}
        channels={undefined}
        loadingChannels={false}
        routeDecision={null}
        loadingDecision={false}
        candidateView={{ routeCandidates: [], accountOptions: [], tokenOptionsByAccountId: {} }}
        channelTokenDraft={{}}
        updatingChannel={{}}
        savingPriority={false}
        onTokenDraftChange={vi.fn()}
        onSaveToken={vi.fn()}
        onDeleteChannel={vi.fn()}
        onToggleChannelEnabled={vi.fn()}
        onChannelDragEnd={vi.fn()}
        missingTokenSiteItems={[]}
        missingTokenGroupItems={[]}
        onCreateTokenForMissing={vi.fn()}
        onAddChannel={vi.fn()}
        onSiteBlockModel={vi.fn()}
        expandedSourceGroupMap={{}}
        onToggleSourceGroup={vi.fn()}
      />,
    );

    const summaryCard = root.root.find((node) => (
      node.type === 'div'
      && String(node.props.className || '').includes('route-card-collapsed')
    ));

    expect(summaryCard.props.role).toBe('button');
    expect(summaryCard.props.tabIndex).toBe(0);
    expect(summaryCard.props['aria-expanded']).toBe(false);

    summaryCard.props.onKeyDown({ key: 'Enter', preventDefault: vi.fn() });
    summaryCard.props.onKeyDown({ key: ' ', preventDefault: vi.fn() });

    expect(onToggleExpand).toHaveBeenCalledTimes(2);
  });

  it('renders desktop priority rail summaries for multiple channel layers', () => {
    const root = create(
      <RouteCard
        route={buildRoute()}
        brand={null}
        expanded
        onToggleExpand={vi.fn()}
        onEdit={vi.fn()}
        onDelete={vi.fn()}
        onToggleEnabled={vi.fn()}
        onClearCooldown={vi.fn()}
        clearingCooldown={false}
        onRoutingStrategyChange={vi.fn()}
        updatingRoutingStrategy={false}
        channels={[
          buildChannel({
            id: 11,
            priority: 0,
            account: { username: 'user_a' },
            site: { id: 1, name: 'site-a', platform: 'openai' },
          }),
          buildChannel({
            id: 12,
            accountId: 102,
            tokenId: 1002,
            priority: 1,
            sourceModel: 'gpt-4.1',
            account: { username: 'user_b' },
            site: { id: 2, name: 'site-b', platform: 'openai' },
            token: { id: 1002, name: 'token-b', accountId: 102, enabled: true, isDefault: false },
          }),
        ]}
        loadingChannels={false}
        routeDecision={null}
        loadingDecision={false}
        candidateView={{ routeCandidates: [], accountOptions: [], tokenOptionsByAccountId: {} }}
        channelTokenDraft={{}}
        updatingChannel={{}}
        savingPriority={false}
        onTokenDraftChange={vi.fn()}
        onSaveToken={vi.fn()}
        onDeleteChannel={vi.fn()}
        onToggleChannelEnabled={vi.fn()}
        onChannelDragEnd={vi.fn()}
        missingTokenSiteItems={[]}
        missingTokenGroupItems={[]}
        onCreateTokenForMissing={vi.fn()}
        onAddChannel={vi.fn()}
        onSiteBlockModel={vi.fn()}
        expandedSourceGroupMap={{}}
        onToggleSourceGroup={vi.fn()}
      />,
    );

    const text = collectText(root.root);
    expect(text).toContain('P0 · 1');
    expect(text).toContain('P1 · 1');
    expect(text).toContain('user_a');
    expect(text).toContain('user_b');

    const p0RailNode = root.root.find((node) => (
      node.type === 'div'
      && collectText(node) === 'P0 · 1'
      && node.props?.style?.borderRadius === 999
    ));
    const p1RailNode = root.root.find((node) => (
      node.type === 'div'
      && collectText(node) === 'P1 · 1'
      && node.props?.style?.borderRadius === 999
    ));

    expect(p0RailNode.props.style.background).not.toBe('var(--color-bg)');
    expect(p1RailNode.props.style.background).not.toBe('var(--color-bg)');
    expect(p0RailNode.props.style.color).not.toBe(p1RailNode.props.style.color);
  });

  it('renders oauth route unit summary badges on expanded cards', () => {
    const root = create(
      <RouteCard
        route={buildRoute()}
        brand={null}
        expanded
        onToggleExpand={vi.fn()}
        onEdit={vi.fn()}
        onDelete={vi.fn()}
        onToggleEnabled={vi.fn()}
        onClearCooldown={vi.fn()}
        clearingCooldown={false}
        onRoutingStrategyChange={vi.fn()}
        updatingRoutingStrategy={false}
        channels={[
          buildChannel({
            id: 11,
            account: { username: 'pool-representative' },
            site: { id: 1, name: 'site-a', platform: 'openai' },
            ...( {
              routeUnit: {
                id: 7,
                name: 'Codex 池',
                memberCount: 3,
                strategy: 'round_robin',
                members: [
                  { accountId: 101, username: 'user_a', siteName: 'site-a' },
                  { accountId: 102, username: 'user_b', siteName: 'site-b' },
                  { accountId: 103, username: 'user_c', siteName: 'site-c' },
                ],
              },
            } as any ),
          }),
        ]}
        loadingChannels={false}
        routeDecision={null}
        loadingDecision={false}
        candidateView={{ routeCandidates: [], accountOptions: [], tokenOptionsByAccountId: {} }}
        channelTokenDraft={{}}
        updatingChannel={{}}
        savingPriority={false}
        onTokenDraftChange={vi.fn()}
        onSaveToken={vi.fn()}
        onDeleteChannel={vi.fn()}
        onToggleChannelEnabled={vi.fn()}
        onChannelDragEnd={vi.fn()}
        missingTokenSiteItems={[]}
        missingTokenGroupItems={[]}
        onCreateTokenForMissing={vi.fn()}
        onAddChannel={vi.fn()}
        onSiteBlockModel={vi.fn()}
        expandedSourceGroupMap={{}}
        onToggleSourceGroup={vi.fn()}
      />,
    );

    const text = collectText(root.root);
    expect(text).toContain('OAuth 路由池');
    expect(text).toContain('Codex 池');
    expect(text).toContain('3 个成员');
    expect(text).toContain('轮询');
    expect(text).toContain('成员摘要');
  });

  it('uses translate-only rect sorting for flat channel shell rows', () => {
    const root = create(
      <RouteCard
        route={buildRoute()}
        brand={null}
        expanded
        onToggleExpand={vi.fn()}
        onEdit={vi.fn()}
        onDelete={vi.fn()}
        onToggleEnabled={vi.fn()}
        onClearCooldown={vi.fn()}
        clearingCooldown={false}
        onRoutingStrategyChange={vi.fn()}
        updatingRoutingStrategy={false}
        channels={[
          buildChannel({ id: 11, priority: 0 }),
          buildChannel({ id: 12, accountId: 102, tokenId: 1002, priority: 1 }),
        ]}
        loadingChannels={false}
        routeDecision={null}
        loadingDecision={false}
        candidateView={{ routeCandidates: [], accountOptions: [], tokenOptionsByAccountId: {} }}
        channelTokenDraft={{}}
        updatingChannel={{}}
        savingPriority={false}
        onTokenDraftChange={vi.fn()}
        onSaveToken={vi.fn()}
        onDeleteChannel={vi.fn()}
        onToggleChannelEnabled={vi.fn()}
        onChannelDragEnd={vi.fn()}
        missingTokenSiteItems={[]}
        missingTokenGroupItems={[]}
        onCreateTokenForMissing={vi.fn()}
        onAddChannel={vi.fn()}
        onSiteBlockModel={vi.fn()}
        expandedSourceGroupMap={{}}
        onToggleSourceGroup={vi.fn()}
      />,
    );

    const sortableContext = root.root.findByType(SortableContext);
    expect(sortableContext.props.strategy).toBe(translateOnlyRectSortingStrategy);
  });

  it('shows a new-layer drop target while dragging inside compact desktop detail panels', () => {
    const renderCard = () => (
      <RouteCard
        route={buildRoute()}
        brand={null}
        expanded
        compact
        detailPanel
        onToggleExpand={vi.fn()}
        onEdit={vi.fn()}
        onDelete={vi.fn()}
        onToggleEnabled={vi.fn()}
        onClearCooldown={vi.fn()}
        clearingCooldown={false}
        onRoutingStrategyChange={vi.fn()}
        updatingRoutingStrategy={false}
        channels={[
          buildChannel({ id: 11, priority: 0 }),
          buildChannel({ id: 12, accountId: 102, tokenId: 1002, priority: 0 }),
        ]}
        loadingChannels={false}
        routeDecision={null}
        loadingDecision={false}
        candidateView={{ routeCandidates: [], accountOptions: [], tokenOptionsByAccountId: {} }}
        channelTokenDraft={{}}
        updatingChannel={{}}
        savingPriority={false}
        onTokenDraftChange={vi.fn()}
        onSaveToken={vi.fn()}
        onDeleteChannel={vi.fn()}
        onToggleChannelEnabled={vi.fn()}
        onChannelDragEnd={vi.fn()}
        missingTokenSiteItems={[]}
        missingTokenGroupItems={[]}
        onCreateTokenForMissing={vi.fn()}
        onAddChannel={vi.fn()}
        onSiteBlockModel={vi.fn()}
        expandedSourceGroupMap={{}}
        onToggleSourceGroup={vi.fn()}
      />
    );
    const root = create(renderCard());

    const dndContext = root.root.find((node) => (
      typeof node.props.onDragStart === 'function'
      && typeof node.props.onDragEnd === 'function'
      && typeof node.props.onDragCancel === 'function'
    ));

    act(() => {
      sortableState.activeId = 12;
      dndContext.props.onDragStart?.({
        active: { id: 12 },
      });
      root.update(renderCard());
    });

    expect(collectText(root.root)).toContain('放到新档位');
    const shells = root.root.findAll((node) => (
      node.type === 'div'
      && node.props['data-testid'] === 'route-channel-shell'
    ));
    const activeShell = shells.find((node) => node.props['data-channel-id'] === 12);
    expect(activeShell).toBeDefined();
    expect(activeShell?.props.style.visibility).toBe('hidden');

    const newLayerTarget = root.root.find((node) => (
      node.type === 'div'
      && node.props['data-testid'] === 'route-priority-new-layer-target'
    ));
    expect(newLayerTarget.props.style.display).toBe('flex');
    expect(newLayerTarget.props.style.minHeight).toBe(34);
  });

  it('keeps compact desktop detail bucket headers outside draggable channel shells', () => {
    const root = create(
      <RouteCard
        route={buildRoute()}
        brand={null}
        expanded
        compact
        detailPanel
        onToggleExpand={vi.fn()}
        onEdit={vi.fn()}
        onDelete={vi.fn()}
        onToggleEnabled={vi.fn()}
        onClearCooldown={vi.fn()}
        clearingCooldown={false}
        onRoutingStrategyChange={vi.fn()}
        updatingRoutingStrategy={false}
        channels={[
          buildChannel({ id: 11, priority: 0 }),
          buildChannel({ id: 12, accountId: 102, tokenId: 1002, priority: 0 }),
          buildChannel({ id: 21, accountId: 103, tokenId: 1003, priority: 1 }),
        ]}
        loadingChannels={false}
        routeDecision={null}
        loadingDecision={false}
        candidateView={{ routeCandidates: [], accountOptions: [], tokenOptionsByAccountId: {} }}
        channelTokenDraft={{}}
        updatingChannel={{}}
        savingPriority={false}
        onTokenDraftChange={vi.fn()}
        onSaveToken={vi.fn()}
        onDeleteChannel={vi.fn()}
        onToggleChannelEnabled={vi.fn()}
        onChannelDragEnd={vi.fn()}
        missingTokenSiteItems={[]}
        missingTokenGroupItems={[]}
        onCreateTokenForMissing={vi.fn()}
        onAddChannel={vi.fn()}
        onSiteBlockModel={vi.fn()}
        expandedSourceGroupMap={{}}
        onToggleSourceGroup={vi.fn()}
      />,
    );

    const bucketHeaders = root.root.findAll((node) => (
      node.type === 'div'
      && node.props['data-testid'] === 'route-priority-bucket-header'
    ));
    const shells = root.root.findAll((node) => (
      node.type === 'div'
      && node.props['data-testid'] === 'route-channel-shell'
    ));

    expect(bucketHeaders.map((node) => collectText(node))).toEqual([
      'P0 · 2 通道',
      'P1 · 1 通道',
    ]);
    expect(shells).toHaveLength(3);
    expect(collectText(shells[0]!)).not.toContain('P0 · 2 通道');
    expect(collectText(shells[2]!)).not.toContain('P1 · 1 通道');
  });

  it('renders desktop channel rows in sortable shell order within a single sortable list', () => {
    const root = create(
      <RouteCard
        route={buildRoute()}
        brand={null}
        expanded
        onToggleExpand={vi.fn()}
        onEdit={vi.fn()}
        onDelete={vi.fn()}
        onToggleEnabled={vi.fn()}
        onClearCooldown={vi.fn()}
        clearingCooldown={false}
        onRoutingStrategyChange={vi.fn()}
        updatingRoutingStrategy={false}
        channels={[
          buildChannel({ id: 11, priority: 0 }),
          buildChannel({ id: 12, accountId: 102, tokenId: 1002, priority: 0 }),
          buildChannel({ id: 21, accountId: 103, tokenId: 1003, priority: 1 }),
        ]}
        loadingChannels={false}
        routeDecision={null}
        loadingDecision={false}
        candidateView={{ routeCandidates: [], accountOptions: [], tokenOptionsByAccountId: {} }}
        channelTokenDraft={{}}
        updatingChannel={{}}
        savingPriority={false}
        onTokenDraftChange={vi.fn()}
        onSaveToken={vi.fn()}
        onDeleteChannel={vi.fn()}
        onToggleChannelEnabled={vi.fn()}
        onChannelDragEnd={vi.fn()}
        missingTokenSiteItems={[]}
        missingTokenGroupItems={[]}
        onCreateTokenForMissing={vi.fn()}
        onAddChannel={vi.fn()}
        onSiteBlockModel={vi.fn()}
        expandedSourceGroupMap={{}}
        onToggleSourceGroup={vi.fn()}
      />,
    );

    const sortableList = root.root.find((node) => (
      node.type === 'div'
      && node.props['data-testid'] === 'route-channel-sortable-list'
    ));
    const directShells = sortableList.findAll((node) => (
      node.type === 'div'
      && node.props['data-testid'] === 'route-channel-shell'
    ));

    expect(directShells.map((child) => child.props['data-channel-id'])).toEqual([11, 12, 21]);
  });

  it('omits long explanatory copy in compact detail panels', () => {
    const root = create(
      <RouteCard
        route={buildRoute({
          modelPattern: 'gpt-4o-*',
          displayName: 'gpt-4o',
        })}
        brand={null}
        expanded
        compact
        detailPanel
        onToggleExpand={vi.fn()}
        onEdit={vi.fn()}
        onDelete={vi.fn()}
        onToggleEnabled={vi.fn()}
        onClearCooldown={vi.fn()}
        clearingCooldown={false}
        onRoutingStrategyChange={vi.fn()}
        updatingRoutingStrategy={false}
        channels={[buildChannel()]}
        loadingChannels={false}
        routeDecision={null}
        loadingDecision={false}
        candidateView={{ routeCandidates: [], accountOptions: [], tokenOptionsByAccountId: {} }}
        channelTokenDraft={{}}
        updatingChannel={{}}
        savingPriority={false}
        onTokenDraftChange={vi.fn()}
        onSaveToken={vi.fn()}
        onDeleteChannel={vi.fn()}
        onToggleChannelEnabled={vi.fn()}
        onChannelDragEnd={vi.fn()}
        missingTokenSiteItems={[]}
        missingTokenGroupItems={[]}
        onCreateTokenForMissing={vi.fn()}
        onAddChannel={vi.fn()}
        onSiteBlockModel={vi.fn()}
        expandedSourceGroupMap={{}}
        onToggleSourceGroup={vi.fn()}
      />,
    );

    const detailText = collectText(root.root);
    expect(detailText).not.toContain('通配符路由按请求实时决策');
    expect(detailText).not.toContain(getRouteRoutingStrategyDescription('weighted'));
  });

  it('places compact route strategy and add channel controls on the same row', () => {
    const root = create(
      <RouteCard
        route={buildRoute()}
        brand={null}
        expanded
        compact
        detailPanel
        onToggleExpand={vi.fn()}
        onEdit={vi.fn()}
        onDelete={vi.fn()}
        onToggleEnabled={vi.fn()}
        onClearCooldown={vi.fn()}
        clearingCooldown={false}
        onRoutingStrategyChange={vi.fn()}
        updatingRoutingStrategy={false}
        channels={[buildChannel()]}
        loadingChannels={false}
        routeDecision={null}
        loadingDecision={false}
        candidateView={{ routeCandidates: [], accountOptions: [], tokenOptionsByAccountId: {} }}
        channelTokenDraft={{}}
        updatingChannel={{}}
        savingPriority={false}
        onTokenDraftChange={vi.fn()}
        onSaveToken={vi.fn()}
        onDeleteChannel={vi.fn()}
        onToggleChannelEnabled={vi.fn()}
        onChannelDragEnd={vi.fn()}
        missingTokenSiteItems={[]}
        missingTokenGroupItems={[]}
        onCreateTokenForMissing={vi.fn()}
        onAddChannel={vi.fn()}
        onSiteBlockModel={vi.fn()}
        expandedSourceGroupMap={{}}
        onToggleSourceGroup={vi.fn()}
      />,
    );

    const compactActionRow = root.root.find((node) => (
      node.type === 'div'
      && node.props['data-testid'] === 'compact-route-action-row'
    ));
    const strategySelectWrap = compactActionRow.find((node) => (
      node.type === 'div'
      && node.props['data-testid'] === 'compact-route-strategy-select'
    ));
    const addChannelButton = compactActionRow.find((node) => (
      node.type === 'button'
      && collectText(node).includes('添加通道')
    ));

    expect(compactActionRow.props.style.flexDirection).toBe('row');
    expect(compactActionRow.props.style.justifyContent).toBe('flex-start');
    expect(collectText(compactActionRow)).toContain('路由策略');
    expect(collectText(compactActionRow)).toContain('添加通道');
    expect(strategySelectWrap.props.style.flex).toBe('0 0 168px');
    expect(addChannelButton.props.style.marginLeft).toBe('auto');
  });

  it('keeps compact status badges inline with the route name', () => {
    const root = create(
      <RouteCard
        route={buildRoute({
          modelPattern: 'gpt-5.2-codex',
          channelCount: 16,
        })}
        brand={null}
        expanded
        compact
        detailPanel
        onToggleExpand={vi.fn()}
        onEdit={vi.fn()}
        onDelete={vi.fn()}
        onToggleEnabled={vi.fn()}
        onClearCooldown={vi.fn()}
        clearingCooldown={false}
        onRoutingStrategyChange={vi.fn()}
        updatingRoutingStrategy={false}
        channels={[buildChannel()]}
        loadingChannels={false}
        routeDecision={null}
        loadingDecision={false}
        candidateView={{ routeCandidates: [], accountOptions: [], tokenOptionsByAccountId: {} }}
        channelTokenDraft={{}}
        updatingChannel={{}}
        savingPriority={false}
        onTokenDraftChange={vi.fn()}
        onSaveToken={vi.fn()}
        onDeleteChannel={vi.fn()}
        onToggleChannelEnabled={vi.fn()}
        onChannelDragEnd={vi.fn()}
        missingTokenSiteItems={[]}
        missingTokenGroupItems={[]}
        onCreateTokenForMissing={vi.fn()}
        onAddChannel={vi.fn()}
        onSiteBlockModel={vi.fn()}
        expandedSourceGroupMap={{}}
        onToggleSourceGroup={vi.fn()}
      />,
    );

    const compactHeaderMain = root.root.find((node) => (
      node.type === 'div'
      && node.props['data-testid'] === 'compact-route-header-main'
    ));

    expect(compactHeaderMain.props.style.flexDirection).toBe('row');
    expect(collectText(compactHeaderMain)).toContain('gpt-5.2-codex');
    expect(collectText(compactHeaderMain)).toContain('启用');
    expect(collectText(compactHeaderMain)).toContain('16 通道');
  });

  it('skips collapsed rerenders when only expanded-channel state changes', () => {
    const routeTarget = buildRoute();
    let modelPatternReadCount = 0;
    const route = new Proxy(routeTarget, {
      get(target, property, receiver) {
        if (property === 'modelPattern') {
          modelPatternReadCount += 1;
        }
        return Reflect.get(target, property, receiver);
      },
    }) as RouteSummaryRow;
    const callbacks = {
      onToggleExpand: vi.fn(),
      onEdit: vi.fn(),
      onDelete: vi.fn(),
      onToggleEnabled: vi.fn(),
      onClearCooldown: vi.fn(),
      onRoutingStrategyChange: vi.fn(),
      onTokenDraftChange: vi.fn(),
      onSaveToken: vi.fn(),
      onDeleteChannel: vi.fn(),
      onToggleChannelEnabled: vi.fn(),
      onChannelDragEnd: vi.fn(),
      onCreateTokenForMissing: vi.fn(),
      onAddChannel: vi.fn(),
      onSiteBlockModel: vi.fn(),
      onToggleSourceGroup: vi.fn(),
    };
    const candidateView = { routeCandidates: [], accountOptions: [], tokenOptionsByAccountId: {} };

    const renderCard = (channelTokenDraft: Record<number, number>, updatingChannel: Record<number, boolean>) => (
      <RouteCard
        route={route}
        brand={null}
        expanded={false}
        onToggleExpand={callbacks.onToggleExpand}
        onEdit={callbacks.onEdit}
        onDelete={callbacks.onDelete}
        onToggleEnabled={callbacks.onToggleEnabled}
        onClearCooldown={callbacks.onClearCooldown}
        clearingCooldown={false}
        onRoutingStrategyChange={callbacks.onRoutingStrategyChange}
        updatingRoutingStrategy={false}
        channels={undefined}
        loadingChannels={false}
        routeDecision={null}
        loadingDecision={false}
        candidateView={candidateView}
        channelTokenDraft={channelTokenDraft}
        updatingChannel={updatingChannel}
        savingPriority={false}
        onTokenDraftChange={callbacks.onTokenDraftChange}
        onSaveToken={callbacks.onSaveToken}
        onDeleteChannel={callbacks.onDeleteChannel}
        onToggleChannelEnabled={callbacks.onToggleChannelEnabled}
        onChannelDragEnd={callbacks.onChannelDragEnd}
        missingTokenSiteItems={[]}
        missingTokenGroupItems={[]}
        onCreateTokenForMissing={callbacks.onCreateTokenForMissing}
        onAddChannel={callbacks.onAddChannel}
        onSiteBlockModel={callbacks.onSiteBlockModel}
        expandedSourceGroupMap={{}}
        onToggleSourceGroup={callbacks.onToggleSourceGroup}
      />
    );

    let root!: WebTestRenderer;
    act(() => {
      root = create(renderCard({}, {}));
    });

    const initialReadCount = modelPatternReadCount;

    act(() => {
      root.update(renderCard({ 11: 1001 }, { 11: true }));
    });

    expect(modelPatternReadCount).toBe(initialReadCount);
  });

  it('skips collapsed rerenders when only expanded-only callback identities change', () => {
    const routeTarget = buildRoute();
    let modelPatternReadCount = 0;
    const route = new Proxy(routeTarget, {
      get(target, property, receiver) {
        if (property === 'modelPattern') {
          modelPatternReadCount += 1;
        }
        return Reflect.get(target, property, receiver);
      },
    }) as RouteSummaryRow;
    const callbacksA = {
      onToggleExpand: vi.fn(),
      onEdit: vi.fn(),
      onDelete: vi.fn(),
      onToggleEnabled: vi.fn(),
      onClearCooldown: vi.fn(),
      onRoutingStrategyChange: vi.fn(),
      onTokenDraftChange: vi.fn(),
      onSaveToken: vi.fn(),
      onDeleteChannel: vi.fn(),
      onToggleChannelEnabled: vi.fn(),
      onChannelDragEnd: vi.fn(),
      onCreateTokenForMissing: vi.fn(),
      onAddChannel: vi.fn(),
      onSiteBlockModel: vi.fn(),
      onToggleSourceGroup: vi.fn(),
    };
    const callbacksB = {
      ...callbacksA,
      onEdit: vi.fn(),
      onDelete: vi.fn(),
      onClearCooldown: vi.fn(),
      onRoutingStrategyChange: vi.fn(),
      onTokenDraftChange: vi.fn(),
      onSaveToken: vi.fn(),
      onDeleteChannel: vi.fn(),
      onToggleChannelEnabled: vi.fn(),
      onChannelDragEnd: vi.fn(),
      onCreateTokenForMissing: vi.fn(),
      onAddChannel: vi.fn(),
      onSiteBlockModel: vi.fn(),
      onToggleSourceGroup: vi.fn(),
    };
    const candidateView = { routeCandidates: [], accountOptions: [], tokenOptionsByAccountId: {} };

    const renderCard = (callbacks: typeof callbacksA) => (
      <RouteCard
        route={route}
        brand={null}
        expanded={false}
        onToggleExpand={callbacks.onToggleExpand}
        onEdit={callbacks.onEdit}
        onDelete={callbacks.onDelete}
        onToggleEnabled={callbacks.onToggleEnabled}
        onClearCooldown={callbacks.onClearCooldown}
        clearingCooldown={false}
        onRoutingStrategyChange={callbacks.onRoutingStrategyChange}
        updatingRoutingStrategy={false}
        channels={undefined}
        loadingChannels={false}
        routeDecision={null}
        loadingDecision={false}
        candidateView={candidateView}
        channelTokenDraft={{}}
        updatingChannel={{}}
        savingPriority={false}
        onTokenDraftChange={callbacks.onTokenDraftChange}
        onSaveToken={callbacks.onSaveToken}
        onDeleteChannel={callbacks.onDeleteChannel}
        onToggleChannelEnabled={callbacks.onToggleChannelEnabled}
        onChannelDragEnd={callbacks.onChannelDragEnd}
        missingTokenSiteItems={[]}
        missingTokenGroupItems={[]}
        onCreateTokenForMissing={callbacks.onCreateTokenForMissing}
        onAddChannel={callbacks.onAddChannel}
        onSiteBlockModel={callbacks.onSiteBlockModel}
        expandedSourceGroupMap={{}}
        onToggleSourceGroup={callbacks.onToggleSourceGroup}
      />
    );

    const root = create(renderCard(callbacksA));
    const initialReadCount = modelPatternReadCount;

    act(() => {
      root.update(renderCard(callbacksB));
    });

    expect(modelPatternReadCount).toBe(initialReadCount);
  });
});
