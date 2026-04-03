import { act, create } from 'react-test-renderer';
import { afterEach, describe, expect, it, vi } from 'vitest';
import RouteFilterBar from './RouteFilterBar.js';

function renderBar(collapsed: boolean) {
  return (
    <RouteFilterBar
      totalRouteCount={3}
      activeBrand={null}
      setActiveBrand={vi.fn()}
      activeSite={null}
      setActiveSite={vi.fn()}
      activeEndpointType={null}
      setActiveEndpointType={vi.fn()}
      activeGroupFilter={null}
      setActiveGroupFilter={vi.fn()}
      enabledFilter="all"
      setEnabledFilter={vi.fn()}
      enabledCounts={{ enabled: 2, disabled: 1 }}
      brandList={{ list: [], otherCount: 0 }}
      siteList={[]}
      endpointTypeList={[]}
      groupRouteList={[]}
      collapsed={collapsed}
      onToggle={vi.fn()}
    />
  );
}

describe('RouteFilterBar', () => {
  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it('uses the shared collapse presence wrapper while expanded', () => {
    const root = create(renderBar(false));

    const presence = root.root.find((node) => (
      node.type === 'div'
      && String(node.props.className || '').includes('route-filter-bar-presence')
    ));
    const expandedPanel = root.root.find((node) => (
      node.type === 'div'
      && String(node.props.className || '').includes('route-filter-bar-expanded')
    ));

    expect(String(presence.props.className)).toContain('anim-collapse');
    expect(String(presence.props.className)).toContain('is-open');
    expect(String(expandedPanel.props.className)).not.toContain('is-closing');
  });

  it('keeps the collapse wrapper mounted while collapsed so expand can animate from existing layout', () => {
    const root = create(renderBar(true));
    const presence = root.root.find((node) => (
      node.type === 'div'
      && String(node.props.className || '').includes('route-filter-bar-presence')
    ));
    expect(String(presence.props.className)).not.toContain('is-open');
  });

  it('keeps expanded controls mounted briefly while closing, then removes them after the collapse window', () => {
    vi.useFakeTimers();
    const root = create(renderBar(false));

    act(() => {
      root.update(renderBar(true));
    });

    const presence = root.root.find((node) => (
      node.type === 'div'
      && String(node.props.className || '').includes('route-filter-bar-presence')
    ));
    expect(String(presence.props.className)).not.toContain('is-open');

    const expandedWhileClosing = root.root.findAll((node) => (
      node.type === 'div'
      && String(node.props.className || '').includes('route-filter-bar-expanded')
    ));
    expect(expandedWhileClosing).toHaveLength(1);

    act(() => {
      vi.advanceTimersByTime(181);
    });

    const expandedAfterWindow = root.root.findAll((node) => (
      node.type === 'div'
      && String(node.props.className || '').includes('route-filter-bar-expanded')
    ));
    expect(expandedAfterWindow).toHaveLength(0);
  });

  it('mounts expanded controls before flipping the presence wrapper open so expand does not start from an empty shell', () => {
    const rafCallbacks: FrameRequestCallback[] = [];
    vi.stubGlobal('window', {
      requestAnimationFrame: (callback: FrameRequestCallback) => {
        rafCallbacks.push(callback);
        return rafCallbacks.length;
      },
      cancelAnimationFrame: vi.fn(),
    });

    const root = create(renderBar(true));

    act(() => {
      root.update(renderBar(false));
    });

    const presence = root.root.find((node) => (
      node.type === 'div'
      && String(node.props.className || '').includes('route-filter-bar-presence')
    ));
    const expandedBeforeOpen = root.root.findAll((node) => (
      node.type === 'div'
      && String(node.props.className || '').includes('route-filter-bar-expanded')
    ));

    expect(expandedBeforeOpen).toHaveLength(1);
    expect(String(presence.props.className)).not.toContain('is-open');
    expect(rafCallbacks).toHaveLength(1);

    act(() => {
      rafCallbacks[0](0);
    });

    const openPresence = root.root.find((node) => (
      node.type === 'div'
      && String(node.props.className || '').includes('route-filter-bar-presence')
    ));
    expect(String(openPresence.props.className)).toContain('is-open');
  });
});
