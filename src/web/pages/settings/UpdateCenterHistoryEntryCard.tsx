export type UpdateCenterHistoryEntry = {
  revision?: string;
  updatedAt?: string | null;
  status?: string | null;
  description?: string | null;
  imageTag?: string | null;
  imageDigest?: string | null;
};

type UpdateCenterHistoryEntryCardProps = {
  entry: UpdateCenterHistoryEntry;
  currentRevision: string;
  helperHealthy: boolean;
  deploying: boolean;
  compact?: boolean;
  formatTaskTime: (value?: string | null) => string;
  formatImageTarget: (tag?: string | null, digest?: string | null) => string;
  onRollback: (revision: string) => void;
};

export default function UpdateCenterHistoryEntryCard({
  entry,
  currentRevision,
  helperHealthy,
  deploying,
  compact = false,
  formatTaskTime,
  formatImageTarget,
  onRollback,
}: UpdateCenterHistoryEntryCardProps) {
  const revision = String(entry?.revision || '').trim();
  const isCurrentRevision = revision && revision === currentRevision;

  return (
    <div
      style={{
        border: '1px solid var(--color-border-light)',
        borderRadius: 'var(--radius-sm)',
        padding: compact ? 10 : 12,
        display: 'grid',
        gap: compact ? 5 : 6,
        background: isCurrentRevision
          ? 'color-mix(in srgb, var(--color-primary) 6%, var(--color-bg-card))'
          : 'var(--color-bg-card)',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, flexWrap: 'wrap' }}>
        <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--color-text-primary)' }}>
          revision {revision || '-'}
        </div>
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
          {entry?.status ? <span className="badge badge-muted">{entry.status}</span> : null}
          {isCurrentRevision ? <span className="badge badge-info">当前运行</span> : null}
        </div>
      </div>
      <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--color-text-primary)', fontFamily: 'var(--font-mono)' }}>
        {formatImageTarget(entry?.imageTag, entry?.imageDigest) || '未记录镜像信息'}
      </div>
      {entry?.description ? (
        <div style={{ fontSize: 12, color: 'var(--color-text-muted)', lineHeight: 1.5 }}>
          {entry.description}
        </div>
      ) : null}
      <div style={{ fontSize: 12, color: 'var(--color-text-muted)', lineHeight: 1.5 }}>
        更新时间：{formatTaskTime(entry?.updatedAt)}
      </div>
      <div>
        <button
          type="button"
          onClick={() => {
            if (isCurrentRevision) return;
            onRollback(revision);
          }}
          disabled={!helperHealthy || deploying || isCurrentRevision || !revision}
          className="btn btn-ghost"
          style={{ border: '1px solid var(--color-border)' }}
        >
          回退到 revision {revision}
        </button>
      </div>
    </div>
  );
}
