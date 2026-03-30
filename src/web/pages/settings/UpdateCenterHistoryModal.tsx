import CenteredModal from '../../components/CenteredModal.js';

type UpdateCenterHistoryEntry = {
  revision?: string;
  updatedAt?: string | null;
  status?: string | null;
  description?: string | null;
  imageTag?: string | null;
  imageDigest?: string | null;
};

type UpdateCenterHistoryModalProps = {
  open: boolean;
  helperHealthy: boolean;
  deploying: boolean;
  currentRevision: string;
  history: UpdateCenterHistoryEntry[];
  formatTaskTime: (value?: string | null) => string;
  formatImageTarget: (tag?: string | null, digest?: string | null) => string;
  onClose: () => void;
  onRollback: (revision: string) => void;
};

export default function UpdateCenterHistoryModal({
  open,
  helperHealthy,
  deploying,
  currentRevision,
  history,
  formatTaskTime,
  formatImageTarget,
  onClose,
  onRollback,
}: UpdateCenterHistoryModalProps) {
  return (
    <CenteredModal
      open={open}
      onClose={onClose}
      title="全部 revision"
      maxWidth={880}
      closeOnBackdrop
      closeOnEscape
      footer={(
        <button type="button" className="btn btn-ghost" onClick={onClose}>
          关闭
        </button>
      )}
    >
      <div style={{ display: 'grid', gap: 10 }}>
        <div style={{ fontSize: 12, color: 'var(--color-text-muted)', lineHeight: 1.6 }}>
          这里保留 helper 读到的全部 Helm revision。默认列表只显示最近几条，弹窗里再展开全部回退记录，避免设置页被历史卡片拉得过长。
        </div>
        <div style={{ display: 'grid', gap: 10, maxHeight: 520, overflowY: 'auto', paddingRight: 4 }}>
          {history.map((entry) => {
            const revision = String(entry?.revision || '').trim();
            const isCurrentRevision = revision && revision === currentRevision;
            return (
              <div
                key={revision || 'unknown-revision-modal'}
                style={{
                  border: '1px solid var(--color-border-light)',
                  borderRadius: 'var(--radius-sm)',
                  padding: 12,
                  display: 'grid',
                  gap: 6,
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
                <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>
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
          })}
        </div>
      </div>
    </CenteredModal>
  );
}
