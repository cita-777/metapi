import React, { useDeferredValue, useEffect, useMemo, useRef, useState, useCallback } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import {
  api,
  type ProxyLogBillingDetails,
  type ProxyLogDetail,
  type ProxyLogListItem,
  type ProxyLogsSummary,
  type ProxyLogStatusFilter,
} from '../api.js';
import { useToast } from '../components/Toast.js';
import { ModelBadge } from '../components/BrandIcon.js';
import { MobileCard, MobileField } from '../components/MobileCard.js';
import { MobileDrawer } from '../components/MobileDrawer.js';
import { useIsMobile } from '../components/useIsMobile.js';
import { formatDateTimeLocal } from './helpers/checkinLogTime.js';
import ModernSelect from '../components/ModernSelect.js';
import { parseProxyLogPathMeta } from './helpers/proxyLogPathMeta.js';
import { tr } from '../i18n.js';

type ProxyLogRenderItem = ProxyLogListItem & {
  billingDetails?: ProxyLogBillingDetails;
  username?: string | null;
  siteName?: string | null;
  siteUrl?: string | null;
  errorMessage?: string | null;
};

type ProxyLogDetailState = {
  loading: boolean;
  data?: ProxyLogDetail;
  error?: string;
};

const PAGE_SIZES = [20, 50, 100];
const DEFAULT_PAGE_SIZE = 50;
const EMPTY_SUMMARY: ProxyLogsSummary = {
  totalCount: 0,
  successCount: 0,
  failedCount: 0,
  totalCost: 0,
  totalTokensAll: 0,
};

function formatLatency(ms: number) {
  if (ms >= 1000) {
    return `${(ms / 1000).toFixed(ms >= 10000 ? 0 : 1)}s`;
  }
  return `${ms}ms`;
}

function latencyColor(ms: number) {
  if (ms >= 3000) return 'var(--color-danger)';
  if (ms >= 2000) return 'color-mix(in srgb, var(--color-warning) 30%, var(--color-danger))';
  if (ms >= 1500) return 'color-mix(in srgb, var(--color-warning) 60%, var(--color-danger))';
  if (ms >= 1000) return 'var(--color-warning)';
  if (ms > 500) return 'color-mix(in srgb, var(--color-success) 60%, var(--color-warning))';
  return 'var(--color-success)';
}

function latencyBgColor(ms: number) {
  if (ms >= 3000) return 'color-mix(in srgb, var(--color-danger) 12%, transparent)';
  if (ms >= 1000) return 'color-mix(in srgb, var(--color-warning) 12%, transparent)';
  return 'color-mix(in srgb, var(--color-success) 12%, transparent)';
}

function formatCompactNumber(value: number, digits = 6) {
  if (!Number.isFinite(value)) return '0';
  const formatted = value.toFixed(digits).replace(/\.?0+$/, '');
  return formatted || '0';
}

function formatPerMillionPrice(value: number) {
  return `$${formatCompactNumber(value)} / 1M tokens`;
}

function formatBillingDetailSummary(log: ProxyLogRenderItem) {
  const detail = log.billingDetails;
  if (!detail) return null;
  return `模型倍率 ${formatCompactNumber(detail.pricing.modelRatio)}，输出倍率 ${formatCompactNumber(detail.pricing.completionRatio)}，缓存倍率 ${formatCompactNumber(detail.pricing.cacheRatio)}，缓存创建倍率 ${formatCompactNumber(detail.pricing.cacheCreationRatio)}，分组倍率 ${formatCompactNumber(detail.pricing.groupRatio)}`;
}

function buildBillingProcessLines(log: ProxyLogRenderItem) {
  const detail = log.billingDetails;
  if (!detail) return [];

  const lines = [
    `提示价格：${formatPerMillionPrice(detail.breakdown.inputPerMillion)}`,
    `补全价格：${formatPerMillionPrice(detail.breakdown.outputPerMillion)}`,
  ];

  if (detail.usage.cacheReadTokens > 0) {
    lines.push(`缓存价格：${formatPerMillionPrice(detail.breakdown.cacheReadPerMillion)} (缓存倍率: ${formatCompactNumber(detail.pricing.cacheRatio)})`);
  }

  if (detail.usage.cacheCreationTokens > 0) {
    lines.push(`缓存创建价格：${formatPerMillionPrice(detail.breakdown.cacheCreationPerMillion)} (缓存创建倍率: ${formatCompactNumber(detail.pricing.cacheCreationRatio)})`);
  }

  const parts = [
    `提示 ${detail.usage.billablePromptTokens.toLocaleString()} tokens / 1M tokens * $${formatCompactNumber(detail.breakdown.inputPerMillion)}`,
  ];

  if (detail.usage.cacheReadTokens > 0) {
    parts.push(`缓存 ${detail.usage.cacheReadTokens.toLocaleString()} tokens / 1M tokens * $${formatCompactNumber(detail.breakdown.cacheReadPerMillion)}`);
  }

  if (detail.usage.cacheCreationTokens > 0) {
    parts.push(`缓存创建 ${detail.usage.cacheCreationTokens.toLocaleString()} tokens / 1M tokens * $${formatCompactNumber(detail.breakdown.cacheCreationPerMillion)}`);
  }

  parts.push(`补全 ${detail.usage.completionTokens.toLocaleString()} tokens / 1M tokens * $${formatCompactNumber(detail.breakdown.outputPerMillion)} = $${detail.breakdown.totalCost.toFixed(6)}`);
  lines.push(parts.join(' + '));

  return lines;
}

function padDateTimeSegment(value: number) {
  return String(value).padStart(2, '0');
}

function formatDateTimeInputValue(value: Date) {
  return `${value.getFullYear()}-${padDateTimeSegment(value.getMonth() + 1)}-${padDateTimeSegment(value.getDate())}T${padDateTimeSegment(value.getHours())}:${padDateTimeSegment(value.getMinutes())}`;
}

function normalizeRoutePage(raw: string | null): number {
  const parsed = Number.parseInt(raw || '', 10);
  if (!Number.isFinite(parsed) || parsed <= 0) return 1;
  return parsed;
}

function normalizeRoutePageSize(raw: string | null): number {
  const parsed = Number.parseInt(raw || '', 10);
  return PAGE_SIZES.includes(parsed) ? parsed : DEFAULT_PAGE_SIZE;
}

function normalizeRouteStatus(raw: string | null): ProxyLogStatusFilter {
  if (raw === 'success' || raw === 'failed') return raw;
  return 'all';
}

function normalizeRouteSearch(raw: string | null): string {
  return (raw || '').trim();
}

function normalizeRouteSiteId(raw: string | null): number | null {
  const parsed = Number.parseInt(raw || '', 10);
  if (!Number.isFinite(parsed) || parsed <= 0) return null;
  return parsed;
}

function normalizeRouteDateTimeInput(raw: string | null): string {
  const text = (raw || '').trim();
  if (!text) return '';
  const parsed = new Date(text);
  if (Number.isNaN(parsed.getTime())) return '';
  return formatDateTimeInputValue(parsed);
}

function readProxyLogsRouteState(search: string) {
  const params = new URLSearchParams(search);
  return {
    page: normalizeRoutePage(params.get('page')),
    pageSize: normalizeRoutePageSize(params.get('pageSize')),
    status: normalizeRouteStatus(params.get('status')),
    search: normalizeRouteSearch(params.get('q')),
    siteId: normalizeRouteSiteId(params.get('siteId')),
    from: normalizeRouteDateTimeInput(params.get('from')),
    to: normalizeRouteDateTimeInput(params.get('to')),
  };
}

function buildProxyLogsRouteSearch(input: {
  page: number;
  pageSize: number;
  status: ProxyLogStatusFilter;
  search: string;
  siteId: number | null;
  from: string;
  to: string;
}) {
  const params = new URLSearchParams();
  if (input.page > 1) params.set('page', String(input.page));
  if (input.pageSize !== DEFAULT_PAGE_SIZE) params.set('pageSize', String(input.pageSize));
  if (input.status !== 'all') params.set('status', input.status);
  if (input.search.trim()) params.set('q', input.search.trim());
  if (input.siteId) params.set('siteId', String(input.siteId));
  if (input.from.trim()) params.set('from', input.from.trim());
  if (input.to.trim()) params.set('to', input.to.trim());
  const next = params.toString();
  return next ? `?${next}` : '';
}

function toApiTimeBoundary(value: string): string | undefined {
  const text = value.trim();
  if (!text) return undefined;
  const parsed = new Date(text);
  if (Number.isNaN(parsed.getTime())) return undefined;
  return parsed.toISOString();
}

export default function ProxyLogs() {
  const location = useLocation();
  const navigate = useNavigate();
  const initialRouteState = useMemo(() => readProxyLogsRouteState(location.search), [location.search]);
  const [logs, setLogs] = useState<ProxyLogListItem[]>([]);
  const [summary, setSummary] = useState<ProxyLogsSummary>(EMPTY_SUMMARY);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState<ProxyLogStatusFilter>(initialRouteState.status);
  const [searchInput, setSearchInput] = useState(initialRouteState.search);
  const deferredSearchInput = useDeferredValue(searchInput.trim());
  const [siteFilter, setSiteFilter] = useState<number | null>(initialRouteState.siteId);
  const [fromInput, setFromInput] = useState(initialRouteState.from);
  const [toInput, setToInput] = useState(initialRouteState.to);
  const [expanded, setExpanded] = useState<number | null>(null);
  const [page, setPage] = useState(initialRouteState.page);
  const [pageSize, setPageSize] = useState(initialRouteState.pageSize);
  const [detailById, setDetailById] = useState<Record<number, ProxyLogDetailState>>({});
  const [showFilters, setShowFilters] = useState(false);
  const [sites, setSites] = useState<Array<{ id: number; name: string; status?: string | null }>>([]);
  const isMobile = useIsMobile(768);
  const toast = useToast();
  const loadSeq = useRef(0);
  const fromApiBoundary = toApiTimeBoundary(fromInput);
  const toApiBoundaryValue = toApiTimeBoundary(toInput);
  const hasInvalidTimeRange = Boolean(
    fromApiBoundary
    && toApiBoundaryValue
    && new Date(fromApiBoundary).getTime() >= new Date(toApiBoundaryValue).getTime(),
  );

  useEffect(() => {
    const next = readProxyLogsRouteState(location.search);
    setStatusFilter((current) => (current === next.status ? current : next.status));
    setSearchInput((current) => (current === next.search ? current : next.search));
    setSiteFilter((current) => (current === next.siteId ? current : next.siteId));
    setFromInput((current) => (current === next.from ? current : next.from));
    setToInput((current) => (current === next.to ? current : next.to));
    setPage((current) => (current === next.page ? current : next.page));
    setPageSize((current) => (current === next.pageSize ? current : next.pageSize));
  }, [location.search]);

  useEffect(() => {
    const nextSearch = buildProxyLogsRouteSearch({
      page,
      pageSize,
      status: statusFilter,
      search: searchInput,
      siteId: siteFilter,
      from: fromInput,
      to: toInput,
    });
    if (nextSearch === location.search) return;
    navigate({ pathname: location.pathname, search: nextSearch }, { replace: true });
  }, [fromInput, location.pathname, location.search, navigate, page, pageSize, searchInput, siteFilter, statusFilter, toInput]);

  useEffect(() => {
    let cancelled = false;

    const loadSites = async () => {
      try {
        const result = await api.getSites();
        const rows = Array.isArray(result) ? result : (result?.sites || []);
        const normalized = rows
          .map((site: any) => ({
            id: Number(site?.id || 0),
            name: String(site?.name || '').trim() || `站点 #${site?.id ?? ''}`,
            status: typeof site?.status === 'string' ? site.status : null,
          }))
          .filter((site) => site.id > 0)
          .sort((left, right) => left.name.localeCompare(right.name, 'zh-CN'));
        if (!cancelled) setSites(normalized);
      } catch (error) {
        console.error('Failed to load sites for proxy log filters:', error);
      }
    };

    void loadSites();

    return () => {
      cancelled = true;
    };
  }, []);

  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const safePage = Math.min(page, totalPages);
  const currentOffset = (safePage - 1) * pageSize;
  const displayedStart = total === 0 ? 0 : currentOffset + 1;
  const displayedEnd = total === 0 ? 0 : Math.min(currentOffset + logs.length, total);

  const pageNumbers = useMemo(() => (
    Array.from({ length: Math.min(totalPages, 7) }, (_, i) => {
      if (totalPages <= 7) return i + 1;
      if (safePage <= 4) return i + 1;
      if (safePage >= totalPages - 3) return totalPages - 6 + i;
      return safePage - 3 + i;
    })
  ), [safePage, totalPages]);

  const siteOptions = useMemo(() => {
    const options = sites.map((site) => ({
      value: String(site.id),
      label: site.status === 'disabled' ? `${site.name}（已禁用）` : site.name,
    }));
    if (siteFilter && !options.some((option) => option.value === String(siteFilter))) {
      options.unshift({
        value: String(siteFilter),
        label: `站点 #${siteFilter}（已删除）`,
      });
    }
    return [
      { value: '', label: '全部站点' },
      ...options,
    ];
  }, [siteFilter, sites]);

  const activeSiteLabel = useMemo(() => {
    if (!siteFilter) return '全部站点';
    return siteOptions.find((option) => option.value === String(siteFilter))?.label || `站点 #${siteFilter}`;
  }, [siteFilter, siteOptions]);

  const load = useCallback(async () => {
    const seq = ++loadSeq.current;
    if (hasInvalidTimeRange) {
      setLogs([]);
      setTotal(0);
      setSummary(EMPTY_SUMMARY);
      if (seq === loadSeq.current) setLoading(false);
      return;
    }
    setLoading(true);
    try {
      const params = {
        limit: pageSize,
        offset: currentOffset,
        status: statusFilter,
        search: deferredSearchInput,
        ...(siteFilter ? { siteId: siteFilter } : {}),
        ...(fromApiBoundary ? { from: fromApiBoundary } : {}),
        ...(toApiBoundaryValue ? { to: toApiBoundaryValue } : {}),
      };
      const data = await api.getProxyLogs(params);
      if (seq !== loadSeq.current) return;
      setLogs(Array.isArray(data.items) ? data.items : []);
      setTotal(Number(data.total || 0));
      setSummary(data.summary || EMPTY_SUMMARY);
    } catch (e: any) {
      if (seq !== loadSeq.current) return;
      toast.error(e.message || '加载日志失败');
    } finally {
      if (seq === loadSeq.current) setLoading(false);
    }
  }, [currentOffset, deferredSearchInput, fromApiBoundary, hasInvalidTimeRange, pageSize, siteFilter, statusFilter, toApiBoundaryValue, toast]);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    if (page <= totalPages) return;
    setPage(totalPages);
  }, [page, totalPages]);

  useEffect(() => {
    setExpanded((current) => (
      current !== null && logs.some((log) => log.id === current)
        ? current
        : null
    ));
  }, [logs]);

  const loadDetail = useCallback(async (id: number) => {
    const existing = detailById[id];
    if (existing?.loading || existing?.data) return;

    setDetailById((current) => ({
      ...current,
      [id]: { loading: true },
    }));

    try {
      const data = await api.getProxyLogDetail(id);
      setDetailById((current) => ({
        ...current,
        [id]: { loading: false, data },
      }));
    } catch (e: any) {
      const message = e?.message || '加载日志详情失败';
      setDetailById((current) => ({
        ...current,
        [id]: { loading: false, error: message },
      }));
      toast.error(message);
    }
  }, [detailById, toast]);

  const handleToggleExpand = useCallback((id: number) => {
    const shouldExpand = expanded !== id;
    setExpanded(shouldExpand ? id : null);
    if (shouldExpand) {
      void loadDetail(id);
    }
  }, [expanded, loadDetail]);

  const filterControls = (
    <>
      <div className="pill-tabs">
        {([
          { key: 'all' as ProxyLogStatusFilter, label: '全部', count: summary.totalCount },
          { key: 'success' as ProxyLogStatusFilter, label: '成功', count: summary.successCount },
          { key: 'failed' as ProxyLogStatusFilter, label: '失败', count: summary.failedCount },
        ]).map((tab) => (
          <button
            key={tab.key}
            className={`pill-tab ${statusFilter === tab.key ? 'active' : ''}`}
            onClick={() => {
              setStatusFilter(tab.key);
              setPage(1);
            }}
          >
            {tab.label} <span style={{ fontVariantNumeric: 'tabular-nums', opacity: 0.7 }}>{tab.count}</span>
          </button>
        ))}
      </div>
      <div className="proxy-logs-filter-select">
        <ModernSelect
          size="sm"
          value={siteFilter ? String(siteFilter) : ''}
          onChange={(nextValue) => {
            setSiteFilter(nextValue ? Number(nextValue) : null);
            setPage(1);
          }}
          options={siteOptions}
          placeholder="全部站点"
        />
      </div>
      <label className="proxy-logs-time-field">
        <span>开始</span>
        <input
          type="datetime-local"
          value={fromInput}
          max={toInput || undefined}
          onChange={(e) => {
            setFromInput(e.target.value);
            setPage(1);
          }}
        />
      </label>
      <label className="proxy-logs-time-field">
        <span>结束</span>
        <input
          type="datetime-local"
          value={toInput}
          min={fromInput || undefined}
          onChange={(e) => {
            setToInput(e.target.value);
            setPage(1);
          }}
        />
      </label>
      <div className="toolbar-search" style={{ maxWidth: 280 }}>
        <svg width="14" height="14" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
        </svg>
        <input
          value={searchInput}
          onChange={(e) => {
            setSearchInput(e.target.value);
            setPage(1);
          }}
          placeholder="搜索模型名称..."
        />
      </div>
      <button
        type="button"
        className="btn btn-ghost proxy-logs-filter-reset"
        onClick={() => {
          setStatusFilter('all');
          setSiteFilter(null);
          setFromInput('');
          setToInput('');
          setSearchInput('');
          setPage(1);
        }}
      >
        清空筛选
      </button>
    </>
  );

  return (
    <div className="animate-fade-in">
      <div className="page-header" style={{ marginBottom: 16 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <h2 className="page-title">{tr('使用日志')}</h2>
          <span className="kpi-chip">
            {activeSiteLabel}
          </span>
          <span className="kpi-chip kpi-chip-success">
            消耗总额 ${summary.totalCost.toFixed(4)}
          </span>
          <span className="kpi-chip kpi-chip-warning">
            {summary.totalTokensAll.toLocaleString()} tokens
          </span>
        </div>
        <button onClick={load} disabled={loading} className="btn btn-ghost" style={{ border: '1px solid var(--color-border)', padding: '6px 14px' }}>
          <svg width="14" height="14" fill="none" viewBox="0 0 24 24" stroke="currentColor" style={{ animation: loading ? 'spin 1s linear infinite' : 'none' }}>
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
          </svg>
          {loading ? '加载中...' : '刷新'}
        </button>
      </div>

      {isMobile ? (
        <>
          <div className="mobile-filter-row">
            <button
              type="button"
              className="btn btn-ghost"
              style={{ border: '1px solid var(--color-border)' }}
              onClick={() => setShowFilters(true)}
            >
              筛选
            </button>
          </div>
          <MobileDrawer open={showFilters} onClose={() => setShowFilters(false)}>
            <div className="mobile-filter-panel">
              {filterControls}
            </div>
          </MobileDrawer>
        </>
      ) : (
        <div className="toolbar" style={{ marginBottom: 12 }}>
          {filterControls}
        </div>
      )}

      {hasInvalidTimeRange && (
        <div className="alert alert-error" style={{ marginBottom: 12 }}>
          结束时间必须晚于开始时间
        </div>
      )}

      <div className="card" style={{ overflowX: 'auto' }}>
        {loading ? (
          <div style={{ padding: 24, display: 'flex', flexDirection: 'column', gap: 10 }}>
            {[...Array(8)].map((_, i) => (
              <div key={i} style={{ display: 'flex', gap: 16 }}>
                <div className="skeleton" style={{ width: 140, height: 16 }} />
                <div className="skeleton" style={{ width: 200, height: 16 }} />
                <div className="skeleton" style={{ width: 50, height: 16 }} />
                <div className="skeleton" style={{ width: 50, height: 16 }} />
                <div className="skeleton" style={{ width: 50, height: 16 }} />
                <div className="skeleton" style={{ width: 70, height: 16 }} />
              </div>
            ))}
          </div>
        ) : isMobile ? (
          <div className="mobile-card-list">
            {logs.map((log) => {
              const detailState = detailById[log.id];
              const detail = detailState?.data;
              const detailLog: ProxyLogRenderItem = detail ? { ...log, ...detail } : log;
              const pathMeta = parseProxyLogPathMeta(detailLog.errorMessage);
              const billingDetailSummary = detail ? formatBillingDetailSummary(detailLog) : null;
              const billingProcessLines = detail ? buildBillingProcessLines(detailLog) : [];
              const isExpanded = expanded === log.id;

              return (
                <MobileCard
                  key={log.id}
                  title={detailLog.modelRequested || 'unknown'}
                  actions={(
                    <span className={`badge ${log.status === 'success' ? 'badge-success' : 'badge-error'}`} style={{ fontSize: 10 }}>
                      {log.status === 'success' ? '成功' : '失败'}
                    </span>
                  )}
                >
                  <MobileField label="时间" value={formatDateTimeLocal(log.createdAt)} />
                  <MobileField label="站点" value={log.siteName || '-'} />
                  <MobileField label="用时" value={formatLatency(log.latencyMs)} />
                  <MobileField label="输入" value={log.promptTokens?.toLocaleString() || '-'} />
                  <MobileField label="输出" value={log.completionTokens?.toLocaleString() || '-'} />
                  <MobileField
                    label="花费"
                    value={typeof log.estimatedCost === 'number' ? `$${log.estimatedCost.toFixed(6)}` : '-'}
                  />
                  {isExpanded ? (
                    <div className="mobile-card-extra">
                      <MobileField label="重试" value={log.retryCount > 0 ? log.retryCount : 0} />
                      {detailState?.loading && <div style={{ color: 'var(--color-text-muted)' }}>加载详情中...</div>}
                      {detailState?.error && <div style={{ color: 'var(--color-danger)' }}>{detailState.error}</div>}
                      {billingDetailSummary && <div style={{ color: 'var(--color-text-muted)' }}>{billingDetailSummary}</div>}
                      {billingProcessLines.length > 0 && (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                          {billingProcessLines.map((line, index) => (
                            <span key={`${log.id}-billing-mobile-${index}`}>{line}</span>
                          ))}
                        </div>
                      )}
                      {detail && pathMeta.errorMessage.trim().length > 0 && (
                        <div style={{ color: 'var(--color-danger)' }}>{pathMeta.errorMessage}</div>
                      )}
                    </div>
                  ) : null}
                  <div className="mobile-card-actions">
                    <button
                      type="button"
                      className="btn btn-link"
                      onClick={() => handleToggleExpand(log.id)}
                    >
                      {isExpanded ? '收起' : '详情'}
                    </button>
                  </div>
                </MobileCard>
              );
            })}
          </div>
        ) : (
          <table className="data-table" style={{ width: '100%' }}>
            <thead>
              <tr>
                <th style={{ width: 28 }} />
                <th>时间</th>
                <th>模型</th>
                <th>站点</th>
                <th>{tr('状态')}</th>
                <th style={{ textAlign: 'center' }}>用时</th>
                <th style={{ textAlign: 'right' }}>输入</th>
                <th style={{ textAlign: 'right' }}>输出</th>
                <th style={{ textAlign: 'right' }}>花费</th>
                <th style={{ textAlign: 'center' }}>重试</th>
              </tr>
            </thead>
            <tbody>
              {logs.map((log) => {
                const detailState = detailById[log.id];
                const detail = detailState?.data;
                const detailLog: ProxyLogRenderItem = detail ? { ...log, ...detail } : log;
                const pathMeta = parseProxyLogPathMeta(detailLog.errorMessage);
                const billingDetailSummary = detail ? formatBillingDetailSummary(detailLog) : null;
                const billingProcessLines = detail ? buildBillingProcessLines(detailLog) : [];

                return (
                  <React.Fragment key={log.id}>
                    <tr
                      data-testid={`proxy-log-row-${log.id}`}
                      onClick={() => handleToggleExpand(log.id)}
                      style={{
                        cursor: 'pointer',
                        background: expanded === log.id ? 'var(--color-primary-light)' : undefined,
                        transition: 'background 0.15s',
                      }}
                    >
                      <td style={{ padding: '8px 4px 8px 12px' }}>
                        <svg width="10" height="10" fill="none" viewBox="0 0 24 24" stroke="currentColor" style={{
                          transform: expanded === log.id ? 'rotate(90deg)' : 'none',
                          transition: 'transform 0.2s',
                          color: 'var(--color-text-muted)',
                        }}>
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M9 5l7 7-7 7" />
                        </svg>
                      </td>
                      <td style={{ fontSize: 12, whiteSpace: 'nowrap', fontVariantNumeric: 'tabular-nums', color: 'var(--color-text-secondary)' }}>
                        {formatDateTimeLocal(log.createdAt)}
                      </td>
                      <td>
                        <ModelBadge model={log.modelRequested} />
                      </td>
                      <td style={{ fontSize: 12, color: 'var(--color-text-secondary)' }}>
                        {log.siteName || '-'}
                      </td>
                      <td>
                        <span className={`badge ${log.status === 'success' ? 'badge-success' : 'badge-error'}`} style={{ fontSize: 11, fontWeight: 600 }}>
                          <span style={{
                            width: 6, height: 6, borderRadius: '50%',
                            background: log.status === 'success' ? 'var(--color-success)' : 'var(--color-danger)',
                          }} />
                          {log.status === 'success' ? '成功' : '失败'}
                        </span>
                      </td>
                      <td style={{ textAlign: 'center' }}>
                        <span style={{
                          fontVariantNumeric: 'tabular-nums',
                          fontSize: 12,
                          fontWeight: 600,
                          color: latencyColor(log.latencyMs),
                          background: latencyBgColor(log.latencyMs),
                          padding: '2px 8px',
                          borderRadius: 4,
                        }}>
                          {formatLatency(log.latencyMs)}
                        </span>
                      </td>
                      <td style={{ textAlign: 'right', fontSize: 12, fontVariantNumeric: 'tabular-nums', color: 'var(--color-text-secondary)' }}>
                        {log.promptTokens?.toLocaleString() || '-'}
                      </td>
                      <td style={{ textAlign: 'right', fontSize: 12, fontVariantNumeric: 'tabular-nums', color: 'var(--color-text-secondary)' }}>
                        {log.completionTokens?.toLocaleString() || '-'}
                      </td>
                      <td style={{ textAlign: 'right', fontSize: 12, fontVariantNumeric: 'tabular-nums', fontWeight: 500 }}>
                        {typeof log.estimatedCost === 'number' ? `$${log.estimatedCost.toFixed(6)}` : '-'}
                      </td>
                      <td style={{ textAlign: 'center' }}>
                        {log.retryCount > 0 ? (
                          <span className="badge badge-warning" style={{ fontSize: 11 }}>{log.retryCount}</span>
                        ) : (
                          <span style={{ color: 'var(--color-text-muted)', fontSize: 12 }}>0</span>
                        )}
                      </td>
                    </tr>
                    {expanded === log.id && (
                      <tr style={{ background: 'var(--color-bg)' }}>
                        <td colSpan={10} style={{ padding: 0 }}>
                          <div className="anim-collapse is-open">
                            <div className="anim-collapse-inner">
                              <div className="animate-fade-in" style={{
                                padding: '14px 20px 14px 40px',
                                borderTop: '1px solid var(--color-border-light)',
                                borderBottom: '1px solid var(--color-border-light)',
                                fontSize: 12,
                                lineHeight: 1.9,
                                color: 'var(--color-text-secondary)',
                              }}>
                                <div style={{ display: 'flex', gap: 6 }}>
                                  <span style={{ fontWeight: 600, color: 'var(--color-warning)', flexShrink: 0 }}>日志详情</span>
                                  <div>
                                    <div>
                                      请求模型: <strong style={{ color: 'var(--color-text-primary)' }}>{detailLog.modelRequested}</strong>
                                      {detailLog.modelActual && detailLog.modelActual !== detailLog.modelRequested && (
                                        <>{' -> '}实际模型: <strong style={{ color: 'var(--color-text-primary)' }}>{detailLog.modelActual}</strong></>
                                      )}
                                      ，状态: <strong style={{ color: detailLog.status === 'success' ? 'var(--color-success)' : 'var(--color-danger)' }}>{detailLog.status === 'success' ? '成功' : '失败'}</strong>
                                      ，用时: <strong style={{ color: latencyColor(detailLog.latencyMs) }}>{formatLatency(detailLog.latencyMs)}</strong>
                                      {detail && (
                                        <>
                                          ，站点: <strong style={{ color: 'var(--color-text-primary)' }}>{detailLog.siteName || '未知站点'}</strong>
                                          ，账号: <strong style={{ color: 'var(--color-text-primary)' }}>{detailLog.username || '未知账号'}</strong>
                                        </>
                                      )}
                                    </div>
                                    {detailState?.loading && <div style={{ color: 'var(--color-text-muted)' }}>加载详情中...</div>}
                                    {detailState?.error && <div style={{ color: 'var(--color-danger)' }}>{detailState.error}</div>}
                                    {billingDetailSummary && (
                                      <div style={{ color: 'var(--color-text-muted)' }}>{billingDetailSummary}</div>
                                    )}
                                  </div>
                                </div>

                                {detailLog.billingDetails && detailLog.billingDetails.usage.cacheReadTokens > 0 && (
                                  <div style={{ display: 'flex', gap: 6 }}>
                                    <span style={{ fontWeight: 600, color: 'var(--color-warning)', flexShrink: 0 }}>缓存 Tokens</span>
                                    <span>{detailLog.billingDetails.usage.cacheReadTokens.toLocaleString()}</span>
                                  </div>
                                )}

                                {detailLog.billingDetails && detailLog.billingDetails.usage.cacheCreationTokens > 0 && (
                                  <div style={{ display: 'flex', gap: 6 }}>
                                    <span style={{ fontWeight: 600, color: 'var(--color-warning)', flexShrink: 0 }}>缓存创建 Tokens</span>
                                    <span>{detailLog.billingDetails.usage.cacheCreationTokens.toLocaleString()}</span>
                                  </div>
                                )}

                                <div style={{ display: 'flex', gap: 6 }}>
                                  <span style={{ fontWeight: 600, color: 'var(--color-info)', flexShrink: 0 }}>计费过程</span>
                                  {billingProcessLines.length > 0 ? (
                                    <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                                      {billingProcessLines.map((line, index) => (
                                        <span key={`${log.id}-billing-${index}`}>{line}</span>
                                      ))}
                                      <span style={{ color: 'var(--color-text-muted)' }}>仅供参考，以实际扣费为准</span>
                                    </div>
                                  ) : (
                                    <span>
                                      输入 {detailLog.promptTokens?.toLocaleString() || 0} tokens
                                      {' + '}输出 {detailLog.completionTokens?.toLocaleString() || 0} tokens
                                      {' = '}总计 {detailLog.totalTokens?.toLocaleString() || 0} tokens
                                      {typeof detailLog.estimatedCost === 'number' && (
                                        <>，预估费用 <strong style={{ color: 'var(--color-text-primary)' }}>${detailLog.estimatedCost.toFixed(6)}</strong></>
                                      )}
                                    </span>
                                  )}
                                </div>

                                <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                                  <span style={{ fontWeight: 600, color: 'var(--color-primary)', flexShrink: 0 }}>下游请求路径</span>
                                  {detail && pathMeta.downstreamPath ? (
                                    <code style={{
                                      fontFamily: 'var(--font-mono)', fontSize: 12,
                                      background: 'var(--color-bg-card)', padding: '1px 8px', borderRadius: 4,
                                      border: '1px solid var(--color-border-light)',
                                    }}>
                                      {pathMeta.downstreamPath}
                                    </code>
                                  ) : (
                                    <span style={{ color: 'var(--color-text-muted)' }}>未记录</span>
                                  )}
                                </div>

                                <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                                  <span style={{ fontWeight: 600, color: 'var(--color-primary)', flexShrink: 0 }}>上游请求路径</span>
                                  {detail && pathMeta.upstreamPath ? (
                                    <code style={{
                                      fontFamily: 'var(--font-mono)', fontSize: 12,
                                      background: 'var(--color-bg-card)', padding: '1px 8px', borderRadius: 4,
                                      border: '1px solid var(--color-border-light)',
                                    }}>
                                      {pathMeta.upstreamPath}
                                    </code>
                                  ) : (
                                    <span style={{ color: 'var(--color-text-muted)' }}>未记录</span>
                                  )}
                                </div>

                                {detail && pathMeta.errorMessage.trim().length > 0 && (
                                  <div style={{ display: 'flex', gap: 6 }}>
                                    <span style={{ fontWeight: 600, color: 'var(--color-danger)', flexShrink: 0 }}>错误信息</span>
                                    <span style={{ color: 'var(--color-danger)' }}>{pathMeta.errorMessage}</span>
                                  </div>
                                )}
                              </div>
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
        )}
        {!loading && logs.length === 0 && (
          <div className="empty-state">
            <svg className="empty-state-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" /></svg>
            <div className="empty-state-title">{tr('暂无使用日志')}</div>
            <div className="empty-state-desc">当请求通过代理时，日志将显示在这里</div>
          </div>
        )}
      </div>

      {total > 0 && (
        <div className="pagination">
          <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginRight: 'auto' }}>
            显示第 {displayedStart} - {displayedEnd} 条，共 {total} 条
          </div>
          <button className="pagination-btn" disabled={safePage <= 1} onClick={() => setPage((current) => current - 1)}>
            <svg width="14" height="14" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" /></svg>
          </button>
          {pageNumbers.map((num) => (
            <button key={num} className={`pagination-btn ${safePage === num ? 'active' : ''}`} onClick={() => setPage(num)}>
              {num}
            </button>
          ))}
          <button className="pagination-btn" disabled={safePage >= totalPages} onClick={() => setPage((current) => current + 1)}>
            <svg width="14" height="14" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" /></svg>
          </button>
          <div className="pagination-size">
            每页条数:
            <div style={{ minWidth: 86 }}>
              <ModernSelect
                size="sm"
                value={String(pageSize)}
                onChange={(nextValue) => {
                  setPageSize(Number(nextValue));
                  setPage(1);
                }}
                options={PAGE_SIZES.map((s) => ({ value: String(s), label: String(s) }))}
                placeholder={String(pageSize)}
              />
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
