import { describe, expect, it, vi } from 'vitest';
import { create, type ReactTestInstance } from 'react-test-renderer';
import RouteCard from './RouteCard.js';
import type { RouteChannel, RouteSummaryRow } from './types.js';

function collectText(node: ReactTestInstance): string {
  return (node.children || []).map((child) => {
    if (typeof child === 'string') return child;
    return collectText(child);
  }).join('');
}

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
      maxWidth: 180,
      minWidth: 0,
      overflow: 'hidden',
      textOverflow: 'ellipsis',
      whiteSpace: 'nowrap',
      flexShrink: 1,
    });
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
});
