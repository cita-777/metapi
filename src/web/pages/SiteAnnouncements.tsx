import { useEffect, useMemo, useRef, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { api } from '../api.js';
import { useToast } from '../components/Toast.js';
import { clearFocusParams, readFocusAnnouncementId } from './helpers/navigationFocus.js';
import {
  formatSiteAnnouncementSeenAt,
  readClientTimeZone,
  resolveSiteAnnouncementTimeZone,
  SiteAnnouncementContent,
} from './helpers/siteAnnouncementPresentation.js';
import { tr } from '../i18n.js';

type SiteAnnouncementRow = {
  id: number;
  siteId: number;
  platform: string;
  sourceKey: string;
  title: string;
  content: string;
  level: 'info' | 'warning' | 'error';
  firstSeenAt?: string | null;
  lastSeenAt?: string | null;
  readAt?: string | null;
};

type SiteRow = {
  id: number;
  name: string;
  platform?: string | null;
};

export default function SiteAnnouncements() {
  const location = useLocation();
  const navigate = useNavigate();
  const toast = useToast();
  const [rows, setRows] = useState<SiteAnnouncementRow[]>([]);
  const [sites, setSites] = useState<SiteRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [clearing, setClearing] = useState(false);
  const [markingAll, setMarkingAll] = useState(false);
  const [serverTimeZone, setServerTimeZone] = useState<string | undefined>(undefined);
  const [highlightAnnouncementId, setHighlightAnnouncementId] = useState<number | null>(null);
  const rowRefs = useRef<Map<number, HTMLDivElement>>(new Map());
  const highlightTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const viewerTimeZone = useMemo(() => readClientTimeZone(), []);
  const displayTimeZone = resolveSiteAnnouncementTimeZone(viewerTimeZone, serverTimeZone);

  const siteNameById = useMemo(() => {
    const map = new Map<number, string>();
    for (const site of sites) {
      map.set(site.id, site.name);
    }
    return map;
  }, [sites]);

  const load = async (silent = false) => {
    if (silent) setRefreshing(true);
    else setLoading(true);
    try {
      const [announcementRows, siteRows, runtimeInfo] = await Promise.all([
        api.getSiteAnnouncements(),
        api.getSites(),
        api.getRuntimeSettings().catch(() => null),
      ]);
      setRows(Array.isArray(announcementRows) ? announcementRows : []);
      setSites(Array.isArray(siteRows) ? siteRows : []);
      const nextServerTimeZone = typeof runtimeInfo?.serverTimeZone === 'string'
        ? runtimeInfo.serverTimeZone.trim()
        : '';
      setServerTimeZone(nextServerTimeZone || undefined);
    } catch (error: any) {
      toast.error(error?.message || '加载站点公告失败');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    void load();
    return () => {
      const win = globalThis as typeof globalThis & {
        clearTimeout?: typeof clearTimeout;
      };
      if (highlightTimerRef.current && typeof win.clearTimeout === 'function') {
        win.clearTimeout(highlightTimerRef.current);
      }
    };
  }, []);

  useEffect(() => {
    const focusAnnouncementId = readFocusAnnouncementId(location.search);
    if (!focusAnnouncementId || loading) return;
    const row = rowRefs.current.get(focusAnnouncementId);
    const nextSearch = clearFocusParams(location.search);
    const win = globalThis as typeof globalThis & {
      setTimeout?: typeof setTimeout;
      clearTimeout?: typeof clearTimeout;
    };
    if (!row) {
      navigate({ pathname: location.pathname, search: nextSearch }, { replace: true });
      return;
    }
    row.scrollIntoView?.({ behavior: 'smooth', block: 'center' });
    setHighlightAnnouncementId(focusAnnouncementId);
    if (highlightTimerRef.current && typeof win.clearTimeout === 'function') {
      win.clearTimeout(highlightTimerRef.current);
    }
    if (typeof win.setTimeout === 'function') {
      highlightTimerRef.current = win.setTimeout(() => {
        setHighlightAnnouncementId((current) => (current === focusAnnouncementId ? null : current));
      }, 2200);
    }
    navigate({ pathname: location.pathname, search: nextSearch }, { replace: true });
  }, [loading, location.pathname, location.search, navigate, rows]);

  const clearAll = async () => {
    setClearing(true);
    try {
      await api.clearSiteAnnouncements();
      setRows([]);
      toast.success('公告已清空');
    } catch (error: any) {
      toast.error(error?.message || '清空公告失败');
    } finally {
      setClearing(false);
    }
  };

  const markAllRead = async () => {
    setMarkingAll(true);
    try {
      await api.markAllSiteAnnouncementsRead();
      setRows((current) => current.map((row) => ({
        ...row,
        readAt: row.readAt || new Date().toISOString(),
      })));
      toast.success('已标记全部为已读');
    } catch (error: any) {
      toast.error(error?.message || '标记失败');
    } finally {
      setMarkingAll(false);
    }
  };

  const triggerSync = async () => {
    try {
      await api.syncSiteAnnouncements();
      toast.success('公告同步任务已启动');
    } catch (error: any) {
      toast.error(error?.message || '启动同步失败');
    }
  };

  return (
    <div className="animate-fade-in">
      <div className="page-header">
        <h2 className="page-title">{tr('站点公告')}</h2>
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
            onClick={triggerSync}
            className="btn btn-ghost"
            style={{ border: '1px solid var(--color-border)', padding: '8px 14px' }}
          >
            手动同步
          </button>
          <button
            onClick={clearAll}
            disabled={clearing}
            className="btn btn-link btn-link-danger"
          >
            {clearing ? <><span className="spinner spinner-sm" /> 清空中...</> : '清空公告'}
          </button>
        </div>
      </div>

      <div className="card" style={{ padding: 0 }}>
        {loading ? (
          <div style={{ padding: 24, textAlign: 'center' }}>
            <span className="spinner spinner-sm" />
          </div>
        ) : rows.length === 0 ? (
          <div style={{ padding: 32, textAlign: 'center' }}>
            <div className="empty-state-title">暂无公告</div>
            <div className="empty-state-desc">当前没有可显示的站点公告。</div>
          </div>
        ) : (
          rows.map((row, index) => (
            <div
              key={row.id}
              ref={(node) => {
                if (node) rowRefs.current.set(row.id, node);
                else rowRefs.current.delete(row.id);
              }}
              className={`animate-slide-up stagger-${Math.min(index + 1, 5)} ${highlightAnnouncementId === row.id ? 'row-focus-highlight' : ''}`.trim()}
              style={{
                padding: '16px 18px',
                borderBottom: index === rows.length - 1 ? 'none' : '1px solid var(--color-border-light)',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, alignItems: 'center', marginBottom: 6 }}>
                <div style={{ fontSize: 15, fontWeight: 600 }}>{row.title}</div>
                <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                  <span className="badge badge-muted">{siteNameById.get(row.siteId) || `站点 #${row.siteId}`}</span>
                  <span className="badge badge-info">{row.platform}</span>
                  <span className={`badge ${row.readAt ? 'badge-muted' : 'badge-warning'}`}>{row.readAt ? '已读' : '未读'}</span>
                </div>
              </div>
              <SiteAnnouncementContent content={row.content} />
              <div
                style={{ marginTop: 8, fontSize: 12, color: 'var(--color-text-muted)' }}
                title={displayTimeZone ? `本地时区：${displayTimeZone}` : undefined}
              >
                首次发现：{formatSiteAnnouncementSeenAt(row.firstSeenAt || row.lastSeenAt || '', displayTimeZone)}
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
