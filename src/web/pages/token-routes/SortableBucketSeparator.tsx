import { type CSSProperties } from 'react';
import { useSortable } from '@dnd-kit/sortable';
import { CSS } from '@dnd-kit/utilities';

type SortableBucketSeparatorProps = {
  id: string;
  beforePriority: number;
  afterPriority: number;
  isSavingPriority: boolean;
};

export function SortableBucketSeparator({
  id,
  beforePriority,
  afterPriority,
  isSavingPriority,
}: SortableBucketSeparatorProps) {
  const {
    attributes,
    listeners,
    setNodeRef,
    setActivatorNodeRef,
    transform,
    transition,
    isDragging,
  } = useSortable({
    id,
    disabled: isSavingPriority,
  });

  const style: CSSProperties = {
    transform: CSS.Transform.toString(transform),
    transition,
    opacity: isDragging ? 0.8 : 1,
    display: 'flex',
    alignItems: 'center',
    gap: 10,
    padding: '4px 2px',
    color: 'var(--color-text-muted)',
  };

  return (
    <div ref={setNodeRef} style={style}>
      <div style={{ flex: 1, height: 1, background: 'var(--color-border)' }} />
      <button
        type="button"
        ref={setActivatorNodeRef}
        {...attributes}
        {...listeners}
        disabled={isSavingPriority}
        className="btn btn-ghost"
        aria-label={`拖拽调整 P${beforePriority} / P${afterPriority} 分界线`}
        data-tooltip={`拖拽调整 P${beforePriority} / P${afterPriority} 分界线`}
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: 6,
          border: '1px solid var(--color-border)',
          borderRadius: 999,
          background: 'var(--color-bg)',
          padding: '2px 10px',
          fontSize: 11,
          color: 'var(--color-text-muted)',
          cursor: isSavingPriority ? 'not-allowed' : 'grab',
        }}
      >
        <span>{`P${beforePriority}`}</span>
        <span style={{ fontSize: 10 }}>||</span>
        <span>{`P${afterPriority}`}</span>
      </button>
      <div style={{ flex: 1, height: 1, background: 'var(--color-border)' }} />
    </div>
  );
}
