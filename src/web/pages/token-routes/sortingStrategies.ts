import { arrayMove, type SortingStrategy } from '@dnd-kit/sortable';

export const translateOnlyRectSortingStrategy: SortingStrategy = ({
  rects,
  activeIndex,
  overIndex,
  index,
}) => {
  const newRects = arrayMove(rects, overIndex, activeIndex);
  const oldRect = rects[index];
  const newRect = newRects[index];

  if (!newRect || !oldRect) {
    return null;
  }

  return {
    x: newRect.left - oldRect.left,
    y: newRect.top - oldRect.top,
    scaleX: 1,
    scaleY: 1,
  };
};
