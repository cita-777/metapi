import { describe, expect, it, vi } from 'vitest';
import { create, type ReactTestInstance } from 'react-test-renderer';

vi.mock('@dnd-kit/sortable', async () => {
  const actual = await vi.importActual<typeof import('@dnd-kit/sortable')>('@dnd-kit/sortable');
  return {
    ...actual,
    useSortable: () => ({
      attributes: { 'data-sortable-handle': 'true' },
      listeners: {},
      setNodeRef: vi.fn(),
      setActivatorNodeRef: vi.fn(),
      transform: { x: 0, y: 18, scaleX: 0.82, scaleY: 1.24 },
      transition: 'transform 200ms ease',
      isDragging: false,
    }),
  };
});

import RouteCard from './RouteCard.js';
import type { RouteChannel, RouteSummaryRow } from './types.js';

function collectText(node: ReactTestInstance): string {
  return (node.children || []).map((child) => {
    if (typeof child === 'string') return child;
    return collectText(child);
  }).join('');
}

function buildRoute(overrides: Partial<RouteSummaryRow> = {}): RouteSummaryRow {
  return {
    id: 42,
    modelPattern: 'gpt-5.4',
    displayName: 'gpt-5.4',
    displayIcon: null,
    modelMapping: null,
    routingStrategy: 'weighted',
    enabled: true,
    channelCount: 3,
    enabledChannelCount: 3,
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
    sourceModel: 'gpt-5.4',
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

describe('RouteCard sortable shell', () => {
  it('applies sortable transform to the outer channel shell instead of the inner row card', () => {
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

    const shell = root.root.find((node) => (
      node.type === 'div'
      && node.props['data-testid'] === 'route-channel-shell'
      && node.props['data-channel-id'] === 11
    ));
    const innerRow = shell.find((node) => (
      node.type === 'div'
      && node.props.style
      && node.props.style.borderRadius === 14
      && collectText(node).includes('user_a')
    ));

    expect(shell.props.style.transform).toContain('translate3d');
    expect(shell.props.style.transform).not.toContain('scale');
    expect(String(shell.props.style.transition || '')).toContain('transform');
    expect(innerRow.props.style.transform).toBeUndefined();
  });
});
