import { useEffect, useMemo, useState } from 'react';
import { api } from '../api.js';
import { MobileCard, MobileField } from '../components/MobileCard.js';
import ResponsiveFilterPanel from '../components/ResponsiveFilterPanel.js';
import { useToast } from '../components/Toast.js';
import { useIsMobile } from '../components/useIsMobile.js';
import { formatDateTimeLocal } from './helpers/checkinLogTime.js';
import ModernSelect from '../components/ModernSelect.js';
import { tr } from '../i18n.js';

type ProgramEvent = {
  id: number;
  type: string;
  title: string;
  message?: string | null;
  level: 'info' | 'warning' | 'error';
  read: boolean;
  relatedId?: number | null;
  relatedType?: string | null;
  createdAt?: string | null;
};

const PAGE_SIZE = 50;

const TYPE_OPTIONS = [
  { value: '', label: '全部类型' },
  { value: 'checkin', label: '签到' },
  { value: 'balance', label: '余额' },
  { value: 'token', label: '令牌' },
  { value: 'proxy', label: '代理' },
  { value: 'status', label: '状态' },
  { value: 'site_notice', label: '站点公告' },
];

function levelLabel(level: string) {
  if (level === 'error') return { label: '错误', cls: 'badge-error' };
  if (level === 'warning') return { label: '警告', cls: 'badge-warning' };
  return { label: '信息', cls: 'badge-info' };
}

function eventStatusLabel(row: ProgramEvent) {
  const text = `${row.title || ''} ${row.message || ''}`.toLowerCase();

  const parseCount = (pattern: RegExp): number | undefined => {
    const match = text.match(pattern);
    if (!match?.[1]) return undefined;
    const value = Number.parseInt(match[1], 10);
    return Number.isFinite(value) ? value : undefined;
  };

  const summary = {
    success: parseCount(/成功[^\d]{0,6}(\d+)/i) ?? parseCount(/success(?:ful)?[^\d]{0,6}(\d+)/i),
    skipped: parseCount(/跳过[^\d]{0,6}(\d+)/i) ?? parseCount(/skipped?[^\d]{0,6}(\d+)/i),
    failed: parseCount(/失败[^\d]{0,6}(\d+)/i) ?? parseCount(/failed[^\d]{0,6}(\d+)/i),
  };

  if (summary.failed !== undefined || summary.success !== undefined || summary.skipped !== undefined) {
    if ((summary.failed ?? 0) > 0) {
      return { label: '失败', cls: 'badge-error' };
    }
    if ((summary.success ?? 0) > 0) {
      return { label: '成功', cls: 'badge-success' };
    }
    if ((summary.skipped ?? 0) > 0) {
      return { label: '跳过', cls: 'badge-warning' };
    }
    return { label: '成功', cls: 'badge-success' };
  }

  if (text.includes('失败') || text.includes('failed') || text.includes('error')) {
    return { label: '失败', cls: 'badge-error' };
  }
  if (text.includes('跳过') || text.includes('skipped')) {
    return { label: '跳过', cls: 'badge-warning' };
  }
  if (text.includes('进行中') || text.includes('已开始') || text.includes('running') || text.includes('pending')) {
    return { label: '进行中', cls: 'badge-info' };
  }
  if (text.includes('成功') || text.includes('已完成') || text.includes('completed') || text.includes('finished')) {
    return { label: '成功', cls: 'badge-success' };
  }

  if (row.level === 'error') return { label: '异常', cls: 'badge-error' };
  if (row.level === 'warning') return { label: '警告', cls: 'badge-warning' };
  return { label: '信息', cls: 'badge-info' };
}

export default function ProgramLogs() {
  const [events, setEvents] = useState<ProgramEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [filterType, setFilterType] = useState('');
  const [onlyUnread, setOnlyUnread] = useState(false);
  const [offset, setOffset] = useState(0);
  const [hasMore, setHasMore] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [markingAll, setMarkingAll] = useState(false);
  const [clearing, setClearing] = useState(false);
  const [rowLoading, setRowLoading] = useState<Record<number, boolean>>({});
  const [showFilters, setShowFilters] = useState(false);
  const isMobile = useIsMobile();
  const toast = useToast();

  const load = async (silent = false, append = false) => {
    if (append) setLoadingMore(true);
    else if (silent) setRefreshing(true);
    else setLoading(true);

    try {
      const nextOffset = append ? offset : 0;
      const params = new URLSearchParams();
      params.set('limit', String(PAGE_SIZE));
      params.set('offset', String(nextOffset));
      if (filterType) params.set('type', filterType);
      if (onlyUnread) params.set('read', 'false');
      const rows = await api.getEvents(params.toString());
      const safeRows = Array.isArray(rows) ? rows : [];
      setEvents((prev) => (append ? [...prev, ...safeRows] : safeRows));
      const loaded = append ? nextOffset + safeRows.length : safeRows.length;
      setOffset(loaded);
      setHasMore(safeRows.length >= PAGE_SIZE);
    } catch (e: any) {
      toast.error(e.message || '加载程序日志失败');
    } finally {
      setLoading(false);
      setLoadingMore(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    load();
  }, [filterType, onlyUnread]);

  const visibleRows = useMemo(() => events, [events]);

  const withRowLoading = async (id: number, fn: () => Promise<void>) => {
    setRowLoading((prev) => ({ ...prev, [id]: true }));
    try {
      await fn();
    } finally {
      setRowLoading((prev) => ({ ...prev, [id]: false }));
    }
  };

  const markOneRead = async (id: number) => {
    await withRowLoading(id, async () => {
      await api.markEventRead(id);
      setEvents((prev) => {
        if (onlyUnread) return prev.filter((item) => item.id !== id);
        return prev.map((item) => (item.id === id ? { ...item, read: true } : item));
      });
    });
  };

  const markAllRead = async () => {
    setMarkingAll(true);
    try {
      await api.markAllEventsRead();
      if (onlyUnread) setEvents([]);
      else setEvents((prev) => prev.map((item) => ({ ...item, read: true })));
      toast.success('已标记全部为已读');
    } catch (e: any) {
      toast.error(e.message || '标记失败');
    } finally {
      setMarkingAll(false);
    }
  };

  const clearAll = async () => {
    setClearing(true);
    try {
      await api.clearEvents();
      setEvents([]);
      setOffset(0);
      setHasMore(false);
      toast.success('日志已清空');
    } catch (e: any) {
      toast.error(e.message || '清空失败');
    } finally {
      setClearing(false);
    }
  };

  return (
    <div className="animate-fade-in">
      <div className="page-header">
        <h2 className="page-title">{tr('程序日志')}</h2>
        <div className="page-actions">
          <button
            onClick={() => load(true)}
            disabled={refreshing}
            className="btn btn-ghost"
            style={{ border: '1px solid var(--color-border)', padding: '8px 14px' }}
          >
            {refreshing ? <><span className="spinner spinner-sm" /> 刷新中...</> : '刷新'}
          </button>
          <button
            onClick={markAllRead}
            disabled={markingAll}
            className="btn btn-ghost"
            style={{ border: '1px solid var(--color-border)', padding: '8px 14px' }}
          >
            {markingAll ? <><span className="spinner spinner-sm" /> 标记中...</> : '全部已读'}
          </button>
          <button
            onClick={clearAll}
            disabled={clearing}
            className="btn btn-link btn-link-danger"
          >
            {clearing ? <><span className="spinner spinner-sm" /> 清空中...</> : '清空日志'}
          </button>
        </div>
      </div>

      <ResponsiveFilterPanel
        isMobile={isMobile}
        mobileOpen={showFilters}
        onMobileOpen={() => setShowFilters(true)}
        onMobileClose={() => setShowFilters(false)}
        mobileTitle="筛选程序日志"
        mobileContent={(
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <ModernSelect
              size="sm"
              value={filterType}
              onChange={(nextValue) => setFilterType(nextValue)}
              options={TYPE_OPTIONS.map((item) => ({
                value: item.value,
                label: item.label,
              }))}
              placeholder="全部类型"
            />
            <label style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'var(--color-text-secondary)' }}>
              <input
                type="checkbox"
                checked={onlyUnread}
                onChange={(e) => {
                  setOffset(0);
                  setHasMore(true);
                  setOnlyUnread(e.target.checked);
                }}
              />
              仅看未读
            </label>
            <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>
              共 {visibleRows.length} 条
            </div>
          </div>
        )}
        desktopContent={(
          <div className="card" style={{ padding: 14, marginBottom: 12, display: 'flex', gap: 10, alignItems: 'center' }}>
            <div style={{ minWidth: 170 }}>
              <ModernSelect
                size="sm"
                value={filterType}
                onChange={(nextValue) => setFilterType(nextValue)}
                options={TYPE_OPTIONS.map((item) => ({
                  value: item.value,
                  label: item.label,
                }))}
                placeholder="全部类型"
              />
            </div>

            <label style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'var(--color-text-secondary)' }}>
              <input
                type="checkbox"
                checked={onlyUnread}
                onChange={(e) => {
                  setOffset(0);
                  setHasMore(true);
                  setOnlyUnread(e.target.checked);
                }}
              />
              仅看未读
            </label>

            <div style={{ marginLeft: 'auto', fontSize: 12, color: 'var(--color-text-muted)' }}>
              共 {visibleRows.length} 条
            </div>
          </div>
        )}
      />

      <div className="card" style={{ overflowX: 'auto' }}>
        {loading ? (
          <div style={{ padding: 20 }}>
            <div className="skeleton" style={{ width: '100%', height: 34, marginBottom: 8 }} />
            <div className="skeleton" style={{ width: '100%', height: 34, marginBottom: 8 }} />
            <div className="skeleton" style={{ width: '100%', height: 34 }} />
          </div>
        ) : isMobile ? (
          <div className="mobile-card-list">
            {visibleRows.length > 0 ? visibleRows.map((row) => {
              const level = levelLabel(row.level || 'info');
              const eventStatus = eventStatusLabel(row);
              return (
                <MobileCard
                  key={row.id}
                  title={row.title || '-'}
                  headerActions={(
                    <span className={`badge ${eventStatus.cls}`} style={{ fontSize: 10 }}>
                      {eventStatus.label}
                    </span>
                  )}
                  footerActions={(
                    row.read ? (
                      <span className="badge badge-muted" style={{ fontSize: 11 }}>已读</span>
                    ) : (
                      <button
                        type="button"
                        onClick={() => markOneRead(row.id)}
                        disabled={!!rowLoading[row.id]}
                        className="btn btn-link btn-link-primary"
                      >
                        {rowLoading[row.id] ? <span className="spinner spinner-sm" /> : '标记已读'}
                      </button>
                    )
                  )}
                >
                  <MobileField label="时间" value={formatDateTimeLocal(row.createdAt)} />
                  <MobileField label="类型" value={<span className="badge badge-muted" style={{ fontSize: 11 }}>{row.type || '-'}</span>} />
                  <MobileField label="级别" value={<span className={`badge ${level.cls}`} style={{ fontSize: 11 }}>{level.label}</span>} />
                  <MobileField label="状态" value={<span className={`badge ${eventStatus.cls}`} style={{ fontSize: 11 }}>{eventStatus.label}</span>} />
                  <MobileField label="内容" value={row.message || '-'} stacked />
                </MobileCard>
              );
            }) : (
              <div className="empty-state">
                <svg className="empty-state-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l4.414 4.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
                <div className="empty-state-title">暂无日志</div>
                <div className="empty-state-desc">当前筛选条件下没有程序日志。</div>
              </div>
            )}
          </div>
        ) : visibleRows.length > 0 ? (
          <table className="data-table program-logs-table">
            <colgroup>
              <col style={{ width: 170 }} />
              <col style={{ width: 90 }} />
              <col style={{ width: 90 }} />
              <col style={{ width: 260 }} />
              <col />
              <col style={{ width: 110 }} />
              <col style={{ width: 140 }} />
            </colgroup>
            <thead>
              <tr>
                <th>时间</th>
                <th>类型</th>
                <th>级别</th>
                <th>标题</th>
                <th>内容</th>
                <th>状态</th>
                <th style={{ textAlign: 'right' }}>操作</th>
              </tr>
            </thead>
            <tbody>
              {visibleRows.map((row, idx) => {
                const level = levelLabel(row.level || 'info');
                const eventStatus = eventStatusLabel(row);
                return (
                  <tr key={row.id} className={`animate-slide-up stagger-${Math.min(idx + 1, 5)}`}>
                    <td style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>
                      {formatDateTimeLocal(row.createdAt)}
                    </td>
                    <td>
                      <span className="badge badge-muted" style={{ fontSize: 11 }}>
                        {row.type || '-'}
                      </span>
                    </td>
                    <td>
                      <span className={`badge ${level.cls}`} style={{ fontSize: 11 }}>
                        {level.label}
                      </span>
                    </td>
                    <td className="program-logs-title-cell">
                      {row.title || '-'}
                    </td>
                    <td className="program-logs-content-cell">
                      {row.message || '-'}
                    </td>
                    <td>
                      <span className={`badge ${eventStatus.cls}`} style={{ fontSize: 11 }}>
                        {eventStatus.label}
                      </span>
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: 8 }}>
                        {row.read ? (
                          <span className="badge badge-muted" style={{ fontSize: 11 }}>已读</span>
                        ) : (
                          <span className="badge badge-warning" style={{ fontSize: 11 }}>未读</span>
                        )}
                        {!row.read && (
                          <button
                            onClick={() => markOneRead(row.id)}
                            disabled={!!rowLoading[row.id]}
                            className="btn btn-link btn-link-primary"
                          >
                            {rowLoading[row.id] ? <span className="spinner spinner-sm" /> : '标记已读'}
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        ) : (
          <div className="empty-state">
            <svg className="empty-state-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l4.414 4.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
            <div className="empty-state-title">暂无日志</div>
            <div className="empty-state-desc">当前筛选条件下没有程序日志。</div>
          </div>
        )}
      </div>

      {!loading && visibleRows.length > 0 && hasMore && (
        <div style={{ marginTop: 12, display: 'flex', justifyContent: 'center' }}>
          <button
            className="btn btn-ghost"
            onClick={() => load(false, true)}
            disabled={loadingMore}
            style={{ border: '1px solid var(--color-border)', padding: '8px 16px' }}
          >
            {loadingMore ? <><span className="spinner spinner-sm" /> 加载中...</> : '加载更多'}
          </button>
        </div>
      )}
    </div>
  );
}
