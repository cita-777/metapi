import { describe, expect, it } from 'vitest';
import { translateOnlyRectSortingStrategy } from './sortingStrategies.js';

describe('translateOnlyRectSortingStrategy', () => {
  it('uses rect deltas without introducing scale for variable-height rows', () => {
    const rects = [
      { top: 0, left: 0, width: 200, height: 80, right: 200, bottom: 80 },
      { top: 92, left: 0, width: 200, height: 56, right: 200, bottom: 148 },
      { top: 160, left: 0, width: 200, height: 120, right: 200, bottom: 280 },
    ];

    const siblingTransform = translateOnlyRectSortingStrategy({
      rects,
      activeIndex: 0,
      overIndex: 2,
      index: 1,
      activeNodeRect: rects[0],
    });

    expect(siblingTransform).toEqual({
      x: 0,
      y: -92,
      scaleX: 1,
      scaleY: 1,
    });
  });
});
