import { describe, expect, it } from 'vitest';
import {
  applyPriorityRailDrop,
  buildPriorityRailNodeStyle,
  buildPriorityRailDragTargets,
  buildPriorityRailSections,
  createPriorityRailNewLayerId,
} from './priorityRail.js';

describe('priorityRail helpers', () => {
  it('groups channels into visible priority sections and preserves in-layer order', () => {
    const sections = buildPriorityRailSections([
      { id: 11, priority: 0 },
      { id: 12, priority: 0 },
      { id: 21, priority: 1 },
    ]);

    expect(sections).toEqual([
      { priority: 0, channelCount: 2, channelIds: [11, 12] },
      { priority: 1, channelCount: 1, channelIds: [21] },
    ]);
  });

  it('exposes a temporary new-layer target only when drag state requests it', () => {
    const sections = buildPriorityRailSections([
      { id: 11, priority: 0 },
      { id: 21, priority: 1 },
    ]);

    expect(
      buildPriorityRailDragTargets(sections, {
        activeChannelId: 11,
        hoveredPriority: 1,
        showNewLayerTarget: true,
      }),
    ).toEqual([
      { kind: 'existing_layer', priority: 0, highlighted: false },
      { kind: 'existing_layer', priority: 1, highlighted: true },
      { kind: 'new_layer', priority: 2, highlighted: false },
    ]);
  });

  it('moves a channel into an existing layer when dropped onto another channel', () => {
    const reordered = applyPriorityRailDrop(
      [
        { id: 11, priority: 0 },
        { id: 12, priority: 0 },
        { id: 21, priority: 1 },
      ],
      21,
      11,
    );

    expect(reordered).toEqual([
      { id: 11, priority: 0 },
      { id: 12, priority: 0 },
      { id: 21, priority: 0 },
    ]);
  });

  it('creates a new next layer when dropped onto a drag-only new-layer target', () => {
    const reordered = applyPriorityRailDrop(
      [
        { id: 11, priority: 0 },
        { id: 12, priority: 0 },
        { id: 21, priority: 1 },
      ],
      12,
      createPriorityRailNewLayerId(0),
    );

    expect(reordered).toEqual([
      { id: 11, priority: 0 },
      { id: 12, priority: 1 },
      { id: 21, priority: 2 },
    ]);
  });

  it('keeps priority color hierarchy even when a rail node is highlighted', () => {
    const p0 = buildPriorityRailNodeStyle(0, false);
    const p0Highlighted = buildPriorityRailNodeStyle(0, true);
    const p1Highlighted = buildPriorityRailNodeStyle(1, true);

    expect(p0.background).not.toBe('var(--color-bg)');
    expect(String(p0Highlighted.background)).toContain('var(--color-bg)');
    expect(String(p0Highlighted.background)).not.toContain('white');
    expect(p0Highlighted.color).toBe('var(--color-primary)');
    expect(p0Highlighted.background).not.toBe(p1Highlighted.background);
  });
});
