import React, { useDeferredValue, useEffect, useMemo, useRef, useState, useCallback } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import {
  api,
  type RuntimeSettingsPayload,
  type ProxyDebugTraceDetail,
  type ProxyDebugTraceListItem,
  type ProxyLogBillingDetails,
  type ProxyLogClientOption,
  type ProxyLogDetail,
  type ProxyLogListItem,
  type ProxyLogsSummary,
  type ProxyLogStatusFilter,
} from '../api.js';
import { useToast } from '../components/Toast.js';
import { ModelBadge } from '../components/BrandIcon.js';
import CenteredModal from '../components/CenteredModal.js';
import MobileDrawer from '../components/MobileDrawer.js';
import ResponsiveFormGrid from '../components/ResponsiveFormGrid.js';
import SiteBadgeLink from '../components/SiteBadgeLink.js';
import { MobileCard, MobileField } from '../components/MobileCard.js';
import ResponsiveFilterPanel from '../components/ResponsiveFilterPanel.js';
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

type ProxyLogSiteFilterOption = {
  id: number;
  name: string;
  status: string | null;
};

type ProxyDebugSettingsState = {
  proxyDebugTraceEnabled: boolean;
  proxyDebugCaptureHeaders: boolean;
  proxyDebugCaptureBodies: boolean;
  proxyDebugCaptureStreamChunks: boolean;
  proxyDebugTargetSessionId: string;
  proxyDebugTargetClientKind: string;
  proxyDebugTargetModel: string;
  proxyDebugRetentionHours: number;
  proxyDebugMaxBodyBytes: number;
};

type ProxyDebugTraceDetailState = {
  loading: boolean;
  data?: ProxyDebugTraceDetail;
  error?: string;
};

type ProxyDebugTraceAttempt = ProxyDebugTraceDetail['attempts'][number];
type StoredDebugPreviewPayload = {
  __metapiTruncated?: boolean;
  preview?: string;
  originalBytes?: number;
  storedBytes?: number;
};

const PAGE_SIZES = [20, 50, 100];
const DEFAULT_PAGE_SIZE = 50;
const TRACE_TABLE_LIMIT = 20;
const DEBUG_TRACE_PAGE_SIZE = 5;
const PROXY_LOGS_DEBUG_TRACE_PANEL_STORAGE_KEY = 'metapi.proxyLogs.debugTracePanelExpanded';
const PROXY_LOG_CLIENT_FAMILY_LABELS: Record<string, string> = {
  codex: 'Codex',
  claude_code: 'Claude Code',
  gemini_cli: 'Gemini CLI',
  generic: '通用',
};
const EMPTY_SUMMARY: ProxyLogsSummary = {
  totalCount: 0,
  successCount: 0,
  failedCount: 0,
  totalCost: 0,
  totalTokensAll: 0,
};
const DEFAULT_PROXY_DEBUG_SETTINGS: ProxyDebugSettingsState = {
  proxyDebugTraceEnabled: false,
  proxyDebugCaptureHeaders: true,
  proxyDebugCaptureBodies: false,
  proxyDebugCaptureStreamChunks: false,
  proxyDebugTargetSessionId: '',
  proxyDebugTargetClientKind: '',
  proxyDebugTargetModel: '',
  proxyDebugRetentionHours: 24,
  proxyDebugMaxBodyBytes: 262144,
};
const DEBUG_REFRESH_INTERVAL_MS = 2000;
const formInputStyle: React.CSSProperties = {
  width: '100%',
  padding: '10px 14px',
  border: '1px solid var(--color-border)',
  borderRadius: 'var(--radius-sm)',
  fontSize: 13,
  outline: 'none',
  background: 'var(--color-bg)',
  color: 'var(--color-text-primary)',
};
const formSectionStyle: React.CSSProperties = {
  display: 'flex',
  flexDirection: 'column',
  gap: 12,
  padding: 14,
  border: '1px solid var(--color-border-light)',
  borderRadius: 'var(--radius-md)',
  background: 'var(--color-bg-card)',
};
const formSectionLabelStyle: React.CSSProperties = {
  fontSize: 12,
  fontWeight: 600,
  color: 'var(--color-text-secondary)',
  letterSpacing: '0.02em',
};
const debugCheckboxRowStyle: React.CSSProperties = {
  display: 'flex',
  alignItems: 'center',
  gap: 8,
  color: 'var(--color-text-primary)',
};
const compactSummaryMetricStyle: React.CSSProperties = {
  display: 'grid',
  gap: 4,
  minWidth: 112,
};
const debugCodeBlockStyle: React.CSSProperties = {
  whiteSpace: 'pre-wrap',
  wordBreak: 'break-word',
  margin: 0,
  padding: 12,
  borderRadius: 'var(--radius-sm)',
  border: '1px solid var(--color-border-light)',
  background: 'var(--color-bg)',
  fontFamily: 'var(--font-mono)',
  fontSize: 12,
  lineHeight: 1.5,
  overflowX: 'auto',
};
const detailInfoGridStyle: React.CSSProperties = {
  display: 'grid',
  gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
  gap: 12,
};
const detailInfoItemStyle: React.CSSProperties = {
  display: 'grid',
  gap: 4,
  minWidth: 0,
};
const detailInfoLabelStyle: React.CSSProperties = {
  fontSize: 12,
  color: 'var(--color-text-muted)',
};
const detailInfoValueStyle: React.CSSProperties = {
  fontSize: 13,
  color: 'var(--color-text-primary)',
  fontWeight: 600,
  minWidth: 0,
  wordBreak: 'break-word',
};
const detailSectionTitleStyle: React.CSSProperties = {
  fontSize: 13,
  fontWeight: 600,
  color: 'var(--color-text-primary)',
};
const detailExpandableCardStyle: React.CSSProperties = {
  border: '1px solid var(--color-border-light)',
  borderRadius: 'var(--radius-sm)',
  background: 'var(--color-bg-card)',
  overflow: 'hidden',
};
const detailExpandableSummaryStyle: React.CSSProperties = {
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'space-between',
  gap: 10,
  width: '100%',
  padding: '10px 12px',
  fontSize: 13,
  fontWeight: 600,
  color: 'var(--color-text-primary)',
  borderBottom: '1px solid var(--color-border-light)',
  background: 'color-mix(in srgb, var(--color-bg-card) 86%, var(--color-bg) 14%)',
};

type DetailDisclosureCardProps = {
  title: string;
  defaultOpen?: boolean;
  children: React.ReactNode;
};

function DetailDisclosureCard({ title, defaultOpen = false, children }: DetailDisclosureCardProps) {
  const [open, setOpen] = useState(defaultOpen);

  return (
    <div style={detailExpandableCardStyle}>
      <button
        type="button"
        aria-label={`${open ? '收起' : '展开'}${title}`}
        style={{ ...detailExpandableSummaryStyle, border: 'none', cursor: 'pointer' }}
        onClick={() => setOpen((current) => !current)}
      >
        <span>{title}</span>
        <span style={{ fontSize: 12, color: 'var(--color-text-muted)', flexShrink: 0 }}>
          {open ? '收起' : '展开'}
        </span>
      </button>
      {open ? children : null}
    </div>
  );
}

async function copyTextToClipboard(text: string) {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(text);
    return;
  }

  const textarea = document.createElement('textarea');
  textarea.value = text;
  textarea.style.position = 'fixed';
  textarea.style.opacity = '0';
  textarea.style.left = '-9999px';
  document.body.appendChild(textarea);
  textarea.focus();
  textarea.select();
  document.execCommand('copy');
  document.body.removeChild(textarea);
}

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

function renderDownstreamKeySummary(log: ProxyLogRenderItem) {
  const parts = [
    log.downstreamKeyName ? `下游 Key: ${log.downstreamKeyName}` : null,
    log.downstreamKeyGroupName ? `主分组: ${log.downstreamKeyGroupName}` : null,
    Array.isArray(log.downstreamKeyTags) && log.downstreamKeyTags.length > 0 ? `标签: ${log.downstreamKeyTags.join(' / ')}` : null,
  ].filter(Boolean);
  return parts.length > 0 ? parts.join('，') : null;
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

function normalizeRouteClient(raw: string | null): string {
  const text = (raw || '').trim();
  if (!text) return '';
  return /^((app|family):)/i.test(text) ? text : '';
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
    client: normalizeRouteClient(params.get('client')),
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
  client: string;
  siteId: number | null;
  from: string;
  to: string;
}) {
  const params = new URLSearchParams();
  if (input.page > 1) params.set('page', String(input.page));
  if (input.pageSize !== DEFAULT_PAGE_SIZE) params.set('pageSize', String(input.pageSize));
  if (input.status !== 'all') params.set('status', input.status);
  if (input.search.trim()) params.set('q', input.search.trim());
  if (input.client.trim()) params.set('client', input.client.trim());
  if (input.siteId) params.set('siteId', String(input.siteId));
  if (input.from.trim()) params.set('from', input.from.trim());
  if (input.to.trim()) params.set('to', input.to.trim());
  const next = params.toString();
  return next ? `?${next}` : '';
}

function formatProxyLogClientFamilyLabel(clientFamily?: string | null, options?: { includeGeneric?: boolean }) {
  const normalized = typeof clientFamily === 'string' ? clientFamily.trim().toLowerCase() : '';
  if (!normalized) return null;
  if (!options?.includeGeneric && normalized === 'generic') return null;
  return PROXY_LOG_CLIENT_FAMILY_LABELS[normalized] || clientFamily || null;
}

function resolveProxyLogClientDisplay(
  log: Pick<ProxyLogRenderItem, 'clientFamily' | 'clientAppName' | 'clientConfidence'>,
  options?: { includeGeneric?: boolean },
) {
  const familyLabel = formatProxyLogClientFamilyLabel(log.clientFamily, options);
  const appName = typeof log.clientAppName === 'string' ? log.clientAppName.trim() : '';
  if (appName) {
    return {
      primary: appName,
      secondary: familyLabel,
      heuristic: log.clientConfidence === 'heuristic',
    };
  }
  return {
    primary: familyLabel,
    secondary: null,
    heuristic: false,
  };
}

function renderProxyLogClientCell(
  log: Pick<ProxyLogRenderItem, 'clientFamily' | 'clientAppName' | 'clientConfidence'>,
  options?: { includeGeneric?: boolean },
) {
  const display = resolveProxyLogClientDisplay(log, options);
  if (!display.primary) {
    return <span style={{ color: 'var(--color-text-muted)' }}>-</span>;
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
        <span>{display.primary}</span>
        {display.heuristic ? (
          <span
            className="badge"
            style={{
              fontSize: 10,
              color: 'var(--color-text-muted)',
              borderColor: 'var(--color-border)',
            }}
          >
            推测
          </span>
        ) : null}
      </div>
      {display.secondary ? (
        <span style={{ fontSize: 11, color: 'var(--color-text-muted)' }}>{display.secondary}</span>
      ) : null}
    </div>
  );
}

function toApiTimeBoundary(value: string): string | undefined {
  const text = value.trim();
  if (!text) return undefined;
  const parsed = new Date(text);
  if (Number.isNaN(parsed.getTime())) return undefined;
  return parsed.toISOString();
}

function normalizeProxyDebugSettings(value: any): ProxyDebugSettingsState {
  return {
    proxyDebugTraceEnabled: !!value?.proxyDebugTraceEnabled,
    proxyDebugCaptureHeaders: value?.proxyDebugCaptureHeaders !== false,
    proxyDebugCaptureBodies: !!value?.proxyDebugCaptureBodies,
    proxyDebugCaptureStreamChunks: !!value?.proxyDebugCaptureStreamChunks,
    proxyDebugTargetSessionId: String(value?.proxyDebugTargetSessionId || ''),
    proxyDebugTargetClientKind: String(value?.proxyDebugTargetClientKind || ''),
    proxyDebugTargetModel: String(value?.proxyDebugTargetModel || ''),
    proxyDebugRetentionHours: Number(value?.proxyDebugRetentionHours || 24),
    proxyDebugMaxBodyBytes: Number(value?.proxyDebugMaxBodyBytes || 262144),
  };
}

function buildProxyDebugSettingsPayload(settings: ProxyDebugSettingsState): RuntimeSettingsPayload {
  return {
    proxyDebugTraceEnabled: settings.proxyDebugTraceEnabled,
    proxyDebugCaptureHeaders: settings.proxyDebugCaptureHeaders,
    proxyDebugCaptureBodies: settings.proxyDebugCaptureBodies,
    proxyDebugCaptureStreamChunks: settings.proxyDebugCaptureStreamChunks,
    proxyDebugTargetSessionId: settings.proxyDebugTargetSessionId.trim(),
    proxyDebugTargetClientKind: settings.proxyDebugTargetClientKind.trim(),
    proxyDebugTargetModel: settings.proxyDebugTargetModel.trim(),
    proxyDebugRetentionHours: Math.max(1, Math.trunc(Number(settings.proxyDebugRetentionHours || 24))),
    proxyDebugMaxBodyBytes: Math.max(1024, Math.trunc(Number(settings.proxyDebugMaxBodyBytes || 262144))),
  };
}

function formatProxyDebugCaptureSummary(settings: ProxyDebugSettingsState) {
  const parts = ['路由决策'];
  if (settings.proxyDebugCaptureHeaders) parts.push('请求/响应头');
  if (settings.proxyDebugCaptureBodies) parts.push('请求/响应体');
  if (settings.proxyDebugCaptureStreamChunks) parts.push('流式分片');
  return parts.join('、');
}

function formatProxyDebugTargetSummary(settings: ProxyDebugSettingsState) {
  const parts = [
    settings.proxyDebugTargetSessionId ? `Session ${settings.proxyDebugTargetSessionId}` : null,
    settings.proxyDebugTargetClientKind ? `客户端 ${settings.proxyDebugTargetClientKind}` : null,
    settings.proxyDebugTargetModel ? `模型 ${settings.proxyDebugTargetModel}` : null,
  ].filter(Boolean);
  return parts.length > 0 ? parts.join('，') : '不过滤，记录所有命中的新请求';
}

function stringifyStoredDebugValue(value: unknown): string | null {
  if (value == null) return null;
  if (typeof value === 'string') return value;
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

function parseStoredDebugPreview(value: unknown): {
  raw: string | null;
  displayText: string;
  truncated: boolean;
  note: string | null;
} {
  const raw = stringifyStoredDebugValue(value);
  if (!raw) {
    return {
      raw: null,
      displayText: '-',
      truncated: false,
      note: null,
    };
  }

  try {
    const parsed = JSON.parse(raw) as StoredDebugPreviewPayload | string;
    if (typeof parsed === 'string') {
      return {
        raw,
        displayText: parsed || '-',
        truncated: false,
        note: null,
      };
    }

    if (parsed && typeof parsed === 'object' && parsed.__metapiTruncated && typeof parsed.preview === 'string') {
      const originalBytes = Number(parsed.originalBytes || 0);
      const storedBytes = Number(parsed.storedBytes || 0);
      return {
        raw,
        displayText: parsed.preview || '-',
        truncated: true,
        note: originalBytes > 0 && storedBytes > 0
          ? `内容已截断展示，原始 ${originalBytes} bytes，当前保留 ${storedBytes} bytes。复制按钮会复制当前数据库里保存的内容。`
          : '内容已截断展示。复制按钮会复制当前数据库里保存的内容。',
      };
    }
  } catch {
    // Fall through to display the saved raw value directly.
  }

  return {
    raw,
    displayText: raw,
    truncated: false,
    note: null,
  };
}

function CompactSummaryMetric({
  label,
  value,
}: {
  label: string;
  value: string;
}) {
  return (
    <div style={compactSummaryMetricStyle}>
      <span style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>{label}</span>
      <strong style={{ fontSize: 14, color: 'var(--color-text-primary)', fontWeight: 700 }}>{value}</strong>
    </div>
  );
}

function readStoredDebugTracePanelExpanded(): boolean {
  try {
    const stored = globalThis.localStorage?.getItem(PROXY_LOGS_DEBUG_TRACE_PANEL_STORAGE_KEY);
    if (stored == null) return true;
    return stored !== 'false';
  } catch {
    return true;
  }
}

function persistDebugTracePanelExpanded(expanded: boolean) {
  try {
    globalThis.localStorage?.setItem(PROXY_LOGS_DEBUG_TRACE_PANEL_STORAGE_KEY, expanded ? 'true' : 'false');
  } catch {
    // Ignore storage write failures and keep UI responsive.
  }
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
  const [clientFilter, setClientFilter] = useState(initialRouteState.client);
  const [siteFilter, setSiteFilter] = useState<number | null>(initialRouteState.siteId);
  const [fromInput, setFromInput] = useState(initialRouteState.from);
  const [toInput, setToInput] = useState(initialRouteState.to);
  const [expanded, setExpanded] = useState<number | null>(null);
  const [page, setPage] = useState(initialRouteState.page);
  const [pageSize, setPageSize] = useState(initialRouteState.pageSize);
  const [detailById, setDetailById] = useState<Record<number, ProxyLogDetailState>>({});
  const [showFilters, setShowFilters] = useState(false);
  const [sites, setSites] = useState<Array<{ id: number; name: string; status?: string | null }>>([]);
  const [clientOptions, setClientOptions] = useState<ProxyLogClientOption[]>([]);
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [showDebugSettingsModal, setShowDebugSettingsModal] = useState(false);
  const [debugPanelLoading, setDebugPanelLoading] = useState(false);
  const [debugPanelSaving, setDebugPanelSaving] = useState(false);
  const [debugTracePanelExpanded, setDebugTracePanelExpanded] = useState(() => readStoredDebugTracePanelExpanded());
  const [debugSettings, setDebugSettings] = useState<ProxyDebugSettingsState>(DEFAULT_PROXY_DEBUG_SETTINGS);
  const [debugDraftSettings, setDebugDraftSettings] = useState<ProxyDebugSettingsState>(DEFAULT_PROXY_DEBUG_SETTINGS);
  const [debugTraces, setDebugTraces] = useState<ProxyDebugTraceListItem[]>([]);
  const [debugTracePage, setDebugTracePage] = useState(1);
  const [selectedDebugTraceId, setSelectedDebugTraceId] = useState<number | null>(null);
  const [showDebugTraceDetailModal, setShowDebugTraceDetailModal] = useState(false);
  const [debugDetailById, setDebugDetailById] = useState<Record<number, ProxyDebugTraceDetailState>>({});
  const isMobile = useIsMobile(768);
  const toast = useToast();
  const loadSeq = useRef(0);
  const selectedDebugTraceIdRef = useRef<number | null>(null);
  const debugDetailByIdRef = useRef<Record<number, ProxyDebugTraceDetailState>>({});
  const debugDetailInFlightRef = useRef<Set<number>>(new Set());
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
    setClientFilter((current) => (current === next.client ? current : next.client));
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
      client: clientFilter,
      siteId: siteFilter,
      from: fromInput,
      to: toInput,
    });
    if (nextSearch === location.search) return;
    navigate({ pathname: location.pathname, search: nextSearch }, { replace: true });
  }, [clientFilter, fromInput, location.pathname, location.search, navigate, page, pageSize, searchInput, siteFilter, statusFilter, toInput]);

  useEffect(() => {
    let cancelled = false;

    const loadSites = async () => {
      try {
        const result = await api.getSites();
        const rows = Array.isArray(result) ? result : (result?.sites || []);
        const normalized: ProxyLogSiteFilterOption[] = rows
          .map((site: any) => ({
            id: Number(site?.id || 0),
            name: String(site?.name || '').trim() || `站点 #${site?.id ?? ''}`,
            status: typeof site?.status === 'string' ? site.status : null,
          }))
          .filter((site: ProxyLogSiteFilterOption) => site.id > 0)
          .sort(
            (left: ProxyLogSiteFilterOption, right: ProxyLogSiteFilterOption) =>
              left.name.localeCompare(right.name, 'zh-CN'),
          );
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
  const debugTraceTotalPages = Math.max(1, Math.ceil(debugTraces.length / DEBUG_TRACE_PAGE_SIZE));
  const safeDebugTracePage = Math.min(debugTracePage, debugTraceTotalPages);
  const debugTraceOffset = (safeDebugTracePage - 1) * DEBUG_TRACE_PAGE_SIZE;
  const visibleDebugTraces = debugTraces.slice(debugTraceOffset, debugTraceOffset + DEBUG_TRACE_PAGE_SIZE);
  const debugTraceDisplayedStart = debugTraces.length === 0 ? 0 : debugTraceOffset + 1;
  const debugTraceDisplayedEnd = debugTraces.length === 0 ? 0 : Math.min(debugTraceOffset + visibleDebugTraces.length, debugTraces.length);

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

  const resolvedClientOptions = useMemo(() => {
    const options = [...clientOptions];
    if (clientFilter && !options.some((option) => option.value === clientFilter)) {
      options.unshift({
        value: clientFilter,
        label: clientFilter,
      });
    }
    return [
      { value: '', label: '全部客户端' },
      ...options,
    ];
  }, [clientFilter, clientOptions]);

  const activeSiteLabel = useMemo(() => {
    if (!siteFilter) return '全部站点';
    return siteOptions.find((option) => option.value === String(siteFilter))?.label || `站点 #${siteFilter}`;
  }, [siteFilter, siteOptions]);
  const siteIdByName = useMemo(() => {
    const index = new Map<string, number>();
    for (const site of sites) {
      const siteName = String(site?.name || '').trim();
      const siteId = Number(site?.id);
      if (!siteName || !Number.isFinite(siteId) || siteId <= 0 || index.has(siteName)) continue;
      index.set(siteName, Math.trunc(siteId));
    }
    return index;
  }, [sites]);

  const load = useCallback(async (silent = false) => {
    const seq = ++loadSeq.current;
    if (hasInvalidTimeRange) {
      setLogs([]);
      setTotal(0);
      setSummary(EMPTY_SUMMARY);
      if (seq === loadSeq.current) setLoading(false);
      return;
    }
    if (!silent) setLoading(true);
    try {
      const params = {
        limit: pageSize,
        offset: currentOffset,
        status: statusFilter,
        search: deferredSearchInput,
        ...(clientFilter ? { client: clientFilter } : {}),
        ...(siteFilter ? { siteId: siteFilter } : {}),
        ...(fromApiBoundary ? { from: fromApiBoundary } : {}),
        ...(toApiBoundaryValue ? { to: toApiBoundaryValue } : {}),
      };
      const data = await api.getProxyLogs(params);
      if (seq !== loadSeq.current) return;
      setLogs(Array.isArray(data.items) ? data.items : []);
      setTotal(Number(data.total || 0));
      setSummary(data.summary || EMPTY_SUMMARY);
      setClientOptions(Array.isArray(data.clientOptions) ? data.clientOptions : []);
    } catch (e: any) {
      if (seq !== loadSeq.current) return;
      if (!silent) toast.error(e.message || '加载日志失败');
    } finally {
      if (seq === loadSeq.current) setLoading(false);
    }
  }, [clientFilter, currentOffset, deferredSearchInput, fromApiBoundary, hasInvalidTimeRange, pageSize, siteFilter, statusFilter, toApiBoundaryValue, toast]);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    if (!autoRefresh) return;
    const timer = setInterval(() => { void load(true); }, 2000);
    return () => clearInterval(timer);
  }, [autoRefresh, load]);

  useEffect(() => {
    if (page <= totalPages) return;
    setPage(totalPages);
  }, [page, totalPages]);

  useEffect(() => {
    if (debugTracePage <= debugTraceTotalPages) return;
    setDebugTracePage(debugTraceTotalPages);
  }, [debugTracePage, debugTraceTotalPages]);

  useEffect(() => {
    setExpanded((current) => (
      current !== null && logs.some((log) => log.id === current)
        ? current
        : null
    ));
  }, [logs]);

  useEffect(() => {
    selectedDebugTraceIdRef.current = selectedDebugTraceId;
  }, [selectedDebugTraceId]);

  useEffect(() => {
    debugDetailByIdRef.current = debugDetailById;
  }, [debugDetailById]);

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

  const applyLoadedDebugSettings = useCallback((nextSettings: ProxyDebugSettingsState, options?: { syncDraft?: boolean }) => {
    setDebugSettings(nextSettings);
    if (options?.syncDraft || !showDebugSettingsModal) {
      setDebugDraftSettings(nextSettings);
    }
  }, [showDebugSettingsModal]);

  const loadDebugTraceDetail = useCallback(async (
    id: number,
    options?: { force?: boolean; suppressToast?: boolean; preserveVisibleData?: boolean },
  ) => {
    const existing = debugDetailByIdRef.current[id];
    if (debugDetailInFlightRef.current.has(id)) return;
    if (!options?.force && (existing?.loading || existing?.data)) return;

    debugDetailInFlightRef.current.add(id);

    if (!options?.preserveVisibleData || !existing?.data) {
      setDebugDetailById((current) => ({
        ...current,
        [id]: { loading: true },
      }));
    }

    try {
      const data = await api.getProxyDebugTraceDetail(id);
      setDebugDetailById((current) => ({
        ...current,
        [id]: { loading: false, data },
      }));
    } catch (error: any) {
      const message = error?.message || '加载调试追踪详情失败';
      setDebugDetailById((current) => ({
        ...current,
        [id]: { loading: false, error: message },
      }));
      if (!options?.suppressToast) {
        toast.error(message);
      }
    } finally {
      debugDetailInFlightRef.current.delete(id);
    }
  }, [toast]);

  const syncDebugTraceItems = useCallback(async (
    items: ProxyDebugTraceListItem[],
    options?: { refreshSelectedDetail?: boolean },
  ) => {
    setDebugTraces(items);
    const currentSelectedDebugTraceId = selectedDebugTraceIdRef.current;
    const nextSelectedDebugTraceId = (
      currentSelectedDebugTraceId && items.some((item) => item.id === currentSelectedDebugTraceId)
        ? currentSelectedDebugTraceId
        : null
    );
    selectedDebugTraceIdRef.current = nextSelectedDebugTraceId;
    setSelectedDebugTraceId(nextSelectedDebugTraceId);
    if (nextSelectedDebugTraceId && options?.refreshSelectedDetail) {
      await loadDebugTraceDetail(nextSelectedDebugTraceId, {
        force: true,
        suppressToast: true,
        preserveVisibleData: showDebugTraceDetailModal,
      });
    }
  }, [loadDebugTraceDetail, showDebugTraceDetailModal]);

  const loadDebugTraceList = useCallback(async (
    options?: { silent?: boolean; refreshSelectedDetail?: boolean; suppressToast?: boolean },
  ) => {
    if (!options?.silent) setDebugPanelLoading(true);
    try {
      const traceResponse = await api.getProxyDebugTraces({ limit: TRACE_TABLE_LIMIT });
      const items = Array.isArray(traceResponse?.items) ? traceResponse.items : [];
      await syncDebugTraceItems(items, { refreshSelectedDetail: options?.refreshSelectedDetail });
    } catch (error: any) {
      if (!options?.suppressToast) {
        toast.error(error?.message || '加载代理调试追踪失败');
      }
    } finally {
      if (!options?.silent) setDebugPanelLoading(false);
    }
  }, [syncDebugTraceItems, toast]);

  const loadDebugState = useCallback(async (silent = false) => {
    if (!silent) setDebugPanelLoading(true);
    try {
      const [runtimeSettings, traceResponse] = await Promise.all([
        api.getRuntimeSettings(),
        api.getProxyDebugTraces({ limit: TRACE_TABLE_LIMIT }),
      ]);
      applyLoadedDebugSettings(normalizeProxyDebugSettings(runtimeSettings), { syncDraft: true });
      const items = Array.isArray(traceResponse?.items) ? traceResponse.items : [];
      await syncDebugTraceItems(items, { refreshSelectedDetail: true });
    } catch (error: any) {
      toast.error(error?.message || '加载代理调试面板失败');
    } finally {
      if (!silent) setDebugPanelLoading(false);
    }
  }, [applyLoadedDebugSettings, syncDebugTraceItems, toast]);

  useEffect(() => {
    void loadDebugState();
  }, [loadDebugState]);

  useEffect(() => {
    if (!selectedDebugTraceId || !showDebugTraceDetailModal) return;
    void loadDebugTraceDetail(selectedDebugTraceId);
  }, [loadDebugTraceDetail, selectedDebugTraceId, showDebugTraceDetailModal]);

  useEffect(() => {
    if (!debugSettings.proxyDebugTraceEnabled) return;
    const timer = setInterval(() => {
      void loadDebugTraceList({
        silent: true,
        refreshSelectedDetail: true,
        suppressToast: true,
      });
    }, DEBUG_REFRESH_INTERVAL_MS);
    return () => clearInterval(timer);
  }, [debugSettings.proxyDebugTraceEnabled, loadDebugTraceList]);

  useEffect(() => {
    persistDebugTracePanelExpanded(debugTracePanelExpanded);
  }, [debugTracePanelExpanded]);

  const persistDebugSettings = useCallback(async (
    nextSettings: ProxyDebugSettingsState,
    options?: { successMessage?: string; closeAfterSave?: boolean },
  ) => {
    setDebugPanelSaving(true);
    try {
      const updated = await api.updateRuntimeSettings(buildProxyDebugSettingsPayload(nextSettings));
      const normalized = normalizeProxyDebugSettings(updated);
      applyLoadedDebugSettings(normalized, { syncDraft: true });
      if (normalized.proxyDebugTraceEnabled) {
        setDebugTracePanelExpanded(true);
      }
      if (options?.closeAfterSave) {
        setShowDebugSettingsModal(false);
      }
      if (options?.successMessage) {
        toast.success(options.successMessage);
      }
      await loadDebugTraceList({
        silent: true,
        refreshSelectedDetail: true,
        suppressToast: true,
      });
      return normalized;
    } catch (error: any) {
      toast.error(error?.message || '保存代理调试设置失败');
      return null;
    } finally {
      setDebugPanelSaving(false);
    }
  }, [applyLoadedDebugSettings, loadDebugTraceList, toast]);

  const handleSaveDebugSettings = useCallback(async () => {
    await persistDebugSettings(debugDraftSettings, {
      successMessage: '代理调试设置已保存',
      closeAfterSave: true,
    });
  }, [debugDraftSettings, persistDebugSettings]);

  const handleQuickToggleDebugTrace = useCallback(async () => {
    await persistDebugSettings({
      ...debugSettings,
      proxyDebugTraceEnabled: !debugSettings.proxyDebugTraceEnabled,
    }, {
      successMessage: debugSettings.proxyDebugTraceEnabled ? '代理调试追踪已关闭' : '代理调试追踪已开启',
    });
  }, [debugSettings, persistDebugSettings]);

  const handleToggleExpand = useCallback((id: number) => {
    const shouldExpand = expanded !== id;
    setExpanded(shouldExpand ? id : null);
    if (shouldExpand) {
      void loadDetail(id);
    }
  }, [expanded, loadDetail]);
  const selectedDebugTraceDetail = selectedDebugTraceId ? debugDetailById[selectedDebugTraceId] : undefined;
  const selectedDebugTraceListItem = selectedDebugTraceId
    ? debugTraces.find((trace) => trace.id === selectedDebugTraceId) || null
    : null;
  const closeDebugTraceDetailModal = useCallback(() => {
    setShowDebugTraceDetailModal(false);
  }, []);
  const openDebugTraceDetailModal = useCallback((traceId: number) => {
    selectedDebugTraceIdRef.current = traceId;
    setSelectedDebugTraceId(traceId);
    setShowDebugTraceDetailModal(true);
  }, []);
  const handleCopyStoredDebugValue = useCallback(async (label: string, value: unknown) => {
    const normalized = parseStoredDebugPreview(value);
    if (!normalized.raw) {
      toast.error(`${label}为空，无法复制`);
      return;
    }
    try {
      await copyTextToClipboard(normalized.raw);
      toast.success(`已复制${label}`);
    } catch (error: any) {
      toast.error(error?.message || `复制${label}失败`);
    }
  }, [toast]);

  function renderTraceStatusBadge(trace: ProxyDebugTraceListItem) {
    const failed = trace.finalStatus === 'failed';
    return (
      <span className={`badge ${failed ? 'badge-error' : 'badge-success'}`} style={{ fontSize: 11 }}>
        {failed ? '失败' : '成功'}
      </span>
    );
  }

  function renderAttemptDetail(attempt: ProxyDebugTraceAttempt) {
    const serializedAttempt = [
      `targetUrl: ${attempt.targetUrl}`,
      `runtimeExecutor: ${attempt.runtimeExecutor || '-'}`,
      `recoverApplied: ${attempt.recoverApplied ? 'true' : 'false'}`,
      `downgradeDecision: ${attempt.downgradeDecision ? 'true' : 'false'}`,
      `downgradeReason: ${attempt.downgradeReason || '-'}`,
      '',
      'requestHeaders:',
      stringifyStoredDebugValue(attempt.requestHeadersJson) || '-',
      '',
      'requestBody:',
      stringifyStoredDebugValue(attempt.requestBodyJson) || '-',
      '',
      'responseHeaders:',
      stringifyStoredDebugValue(attempt.responseHeadersJson) || '-',
      '',
      'responseBody:',
      stringifyStoredDebugValue(attempt.responseBodyJson) || '-',
      '',
      'rawErrorText:',
      attempt.rawErrorText || '-',
      '',
      'memoryWrite:',
      stringifyStoredDebugValue(attempt.memoryWriteJson) || '-',
    ].join('\n');

    return (
      <DetailDisclosureCard
        key={attempt.id}
        title={`#${attempt.attemptIndex + 1} · ${attempt.endpoint} · ${attempt.responseStatus ?? '-'} · ${attempt.requestPath}`}
      >
        <div style={{ padding: 12, display: 'grid', gap: 12 }}>
          <div style={detailInfoGridStyle}>
            <div style={detailInfoItemStyle}>
              <div style={detailInfoLabelStyle}>目标地址</div>
              <div style={{ ...detailInfoValueStyle, fontFamily: 'var(--font-mono)', fontSize: 12 }}>{attempt.targetUrl || '-'}</div>
            </div>
            <div style={detailInfoItemStyle}>
              <div style={detailInfoLabelStyle}>执行器</div>
              <div style={detailInfoValueStyle}>{attempt.runtimeExecutor || '-'}</div>
            </div>
            <div style={detailInfoItemStyle}>
              <div style={detailInfoLabelStyle}>恢复逻辑</div>
              <div style={detailInfoValueStyle}>{attempt.recoverApplied ? '已应用' : '未应用'}</div>
            </div>
            <div style={detailInfoItemStyle}>
              <div style={detailInfoLabelStyle}>降级决策</div>
              <div style={detailInfoValueStyle}>{attempt.downgradeDecision ? '已触发' : '未触发'}</div>
            </div>
          </div>
          {attempt.downgradeReason ? (
            <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>
              降级原因：{attempt.downgradeReason}
            </div>
          ) : null}
          <pre style={debugCodeBlockStyle}>{serializedAttempt}</pre>
        </div>
      </DetailDisclosureCard>
    );
  }

  function renderStoredDebugDetails(title: string, value: unknown, options?: { defaultOpen?: boolean; copyLabel?: string }) {
    const normalized = parseStoredDebugPreview(value);
    const copyLabel = options?.copyLabel || title;

    return (
      <DetailDisclosureCard title={title} defaultOpen={options?.defaultOpen}>
        <div style={{ padding: 12, display: 'grid', gap: 10 }}>
          <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
            <button
              type="button"
              className="btn btn-ghost"
              style={{ border: '1px solid var(--color-border)', padding: '6px 12px' }}
              aria-label={`复制${copyLabel}`}
              onClick={(event) => {
                event.preventDefault();
                event.stopPropagation();
                void handleCopyStoredDebugValue(copyLabel, value);
              }}
            >
              复制当前保存内容
            </button>
          </div>
          {normalized.note ? (
            <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>{normalized.note}</div>
          ) : null}
          <pre style={debugCodeBlockStyle}>{normalized.displayText}</pre>
        </div>
      </DetailDisclosureCard>
    );
  }

  function renderDebugTraceDetailContent() {
    if (!selectedDebugTraceId) {
      return (
        <div style={{ color: 'var(--color-text-muted)', fontSize: 13 }}>
          暂无追踪详情。请选择一条最近追踪后再查看。
        </div>
      );
    }

    if (selectedDebugTraceDetail?.loading) {
      return <div style={{ color: 'var(--color-text-muted)', fontSize: 13 }}>加载追踪详情中...</div>;
    }

    if (selectedDebugTraceDetail?.error) {
      return <div style={{ color: 'var(--color-danger)', fontSize: 13 }}>{selectedDebugTraceDetail.error}</div>;
    }

    if (!selectedDebugTraceDetail?.data) {
      return <div style={{ color: 'var(--color-text-muted)', fontSize: 13 }}>暂无追踪详情。</div>;
    }

    const traceDetail = selectedDebugTraceDetail.data.trace;

    return (
      <div style={{ display: 'grid', gap: 12 }}>
        <div style={{ ...formSectionStyle, gap: 10 }}>
          <div style={detailSectionTitleStyle}>基础信息</div>
          <div style={detailInfoGridStyle}>
            <div style={detailInfoItemStyle}>
              <div style={detailInfoLabelStyle}>下游路径</div>
              <div style={detailInfoValueStyle}>{traceDetail.downstreamPath || '-'}</div>
            </div>
            <div style={detailInfoItemStyle}>
              <div style={detailInfoLabelStyle}>Session</div>
              <div style={detailInfoValueStyle}>{traceDetail.sessionId || '-'}</div>
            </div>
            <div style={detailInfoItemStyle}>
              <div style={detailInfoLabelStyle}>模型</div>
              <div style={detailInfoValueStyle}>{traceDetail.requestedModel || '-'}</div>
            </div>
            <div style={detailInfoItemStyle}>
              <div style={detailInfoLabelStyle}>最终上游路径</div>
              <div style={detailInfoValueStyle}>{traceDetail.finalUpstreamPath || '-'}</div>
            </div>
          </div>
        </div>

        <div style={{ display: 'grid', gap: 10 }}>
          {renderStoredDebugDetails('候选 endpoint', traceDetail.endpointCandidatesJson, {
            copyLabel: '候选 endpoint',
          })}
          {renderStoredDebugDetails('原始下游请求头', traceDetail.requestHeadersJson, {
            copyLabel: '原始下游请求头',
          })}
          {renderStoredDebugDetails('原始下游请求体', traceDetail.requestBodyJson, {
            copyLabel: '原始下游请求体',
          })}
          {renderStoredDebugDetails('最终响应', traceDetail.finalResponseBodyJson, {
            copyLabel: '最终响应',
          })}
        </div>

        <DetailDisclosureCard title={`Attempt 记录 (${selectedDebugTraceDetail.data.attempts.length})`}>
          <div style={{ padding: 12, display: 'grid', gap: 8 }}>
            {selectedDebugTraceDetail.data.attempts.length === 0 ? (
              <div style={{ color: 'var(--color-text-muted)', fontSize: 13 }}>暂无 attempt 记录</div>
            ) : (
              selectedDebugTraceDetail.data.attempts.map(renderAttemptDetail)
            )}
          </div>
        </DetailDisclosureCard>
      </div>
    );
  }

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
          value={clientFilter}
          onChange={(nextValue) => {
            setClientFilter(nextValue);
            setPage(1);
          }}
          options={resolvedClientOptions}
          placeholder="全部客户端"
        />
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
          placeholder="搜索模型、下游 Key、主分组、标签..."
        />
      </div>
      <button
        type="button"
        className="btn btn-ghost proxy-logs-filter-reset"
        onClick={() => {
          setStatusFilter('all');
          setClientFilter('');
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

  const latestDebugTrace = debugTraces[0] || null;
  const debugSettingsFooter = (
    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', justifyContent: 'flex-end' }}>
      <button
        type="button"
        className="btn btn-ghost"
        onClick={() => setDebugDraftSettings(DEFAULT_PROXY_DEBUG_SETTINGS)}
      >
        重置为默认值
      </button>
      <button
        type="button"
        className="btn btn-primary"
        onClick={() => void handleSaveDebugSettings()}
        disabled={debugPanelSaving}
      >
        {debugPanelSaving ? '保存中...' : '保存调试设置'}
      </button>
    </div>
  );
  const debugSettingsForm = (
    <div style={{ display: 'grid', gap: 12 }}>
      <div className="info-tip" style={{ marginBottom: 0 }}>
        只记录开启后的新请求。需要更精确定位时，再按 Session、客户端或模型定向过滤。
      </div>

      <div style={formSectionStyle}>
        <div style={formSectionLabelStyle}>记录内容</div>
        <div style={{ display: 'grid', gap: 10 }}>
          <div style={{ display: 'grid', gap: 4 }}>
            <label style={debugCheckboxRowStyle}>
              <input
                type="checkbox"
                checked={debugDraftSettings.proxyDebugTraceEnabled}
                data-debug-setting="trace-enabled"
                onChange={(e) => setDebugDraftSettings((current) => ({ ...current, proxyDebugTraceEnabled: !!e.target.checked }))}
              />
              开启调试追踪
            </label>
            <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginLeft: 24 }}>后续新请求会写入调试追踪，不会回补旧请求。</div>
          </div>
          <div style={{ display: 'grid', gap: 4 }}>
            <label style={debugCheckboxRowStyle}>
              <input
                type="checkbox"
                checked={debugDraftSettings.proxyDebugCaptureHeaders}
                data-debug-setting="capture-headers"
                onChange={(e) => setDebugDraftSettings((current) => ({ ...current, proxyDebugCaptureHeaders: !!e.target.checked }))}
              />
              采集原始请求/响应头
            </label>
            <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginLeft: 24 }}>保留下游原始头和上游响应头，方便直接对照。</div>
          </div>
          <div style={{ display: 'grid', gap: 4 }}>
            <label style={debugCheckboxRowStyle}>
              <input
                type="checkbox"
                checked={debugDraftSettings.proxyDebugCaptureBodies}
                data-debug-setting="capture-bodies"
                onChange={(e) => setDebugDraftSettings((current) => ({ ...current, proxyDebugCaptureBodies: !!e.target.checked }))}
              />
              采集请求体和响应体
            </label>
            <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginLeft: 24 }}>默认不抓 body，只有显式开启后才记录。</div>
          </div>
          <div style={{ display: 'grid', gap: 4 }}>
            <label style={debugCheckboxRowStyle}>
              <input
                type="checkbox"
                checked={debugDraftSettings.proxyDebugCaptureStreamChunks}
                data-debug-setting="capture-stream-chunks"
                onChange={(e) => setDebugDraftSettings((current) => ({ ...current, proxyDebugCaptureStreamChunks: !!e.target.checked }))}
              />
              采集流式原始分片
            </label>
            <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginLeft: 24 }}>适合定位 SSE / streaming 过程中的兼容问题。</div>
          </div>
        </div>
      </div>

      <ResponsiveFormGrid columns={2}>
        <div style={formSectionStyle}>
          <div style={formSectionLabelStyle}>定向过滤</div>
          <label style={{ display: 'grid', gap: 6 }}>
            <span style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>目标 Session ID</span>
            <input
              type="text"
              value={debugDraftSettings.proxyDebugTargetSessionId}
              data-debug-setting="target-session-id"
              onChange={(e) => setDebugDraftSettings((current) => ({ ...current, proxyDebugTargetSessionId: e.target.value }))}
              placeholder="留空表示不过滤"
              style={formInputStyle}
            />
          </label>
          <label style={{ display: 'grid', gap: 6 }}>
            <span style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>目标客户端</span>
            <input
              type="text"
              value={debugDraftSettings.proxyDebugTargetClientKind}
              data-debug-setting="target-client-kind"
              onChange={(e) => setDebugDraftSettings((current) => ({ ...current, proxyDebugTargetClientKind: e.target.value }))}
              placeholder="如 codex / claude_code"
              style={formInputStyle}
            />
          </label>
          <label style={{ display: 'grid', gap: 6 }}>
            <span style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>目标模型</span>
            <input
              type="text"
              value={debugDraftSettings.proxyDebugTargetModel}
              data-debug-setting="target-model"
              onChange={(e) => setDebugDraftSettings((current) => ({ ...current, proxyDebugTargetModel: e.target.value }))}
              placeholder="如 gpt-4o"
              style={formInputStyle}
            />
          </label>
        </div>

        <div style={formSectionStyle}>
          <div style={formSectionLabelStyle}>保留策略</div>
          <label style={{ display: 'grid', gap: 6 }}>
            <span style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>保留时长（小时）</span>
            <input
              type="number"
              min={1}
              value={debugDraftSettings.proxyDebugRetentionHours}
              data-debug-setting="retention-hours"
              onChange={(e) => setDebugDraftSettings((current) => ({ ...current, proxyDebugRetentionHours: Number(e.target.value || 1) }))}
              style={formInputStyle}
            />
          </label>
          <label style={{ display: 'grid', gap: 6 }}>
            <span style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>抓取体积上限（字节）</span>
            <input
              type="number"
              min={1024}
              value={debugDraftSettings.proxyDebugMaxBodyBytes}
              data-debug-setting="max-body-bytes"
              onChange={(e) => setDebugDraftSettings((current) => ({ ...current, proxyDebugMaxBodyBytes: Number(e.target.value || 1024) }))}
              style={formInputStyle}
            />
          </label>
        </div>
      </ResponsiveFormGrid>

      {isMobile ? debugSettingsFooter : null}
    </div>
  );

  return (
    <div className="animate-fade-in">
      <div className="page-header" style={{ marginBottom: 16 }}>
        <div>
          <h2 className="page-title">{tr('使用日志')}</h2>
          <div className="page-subtitle">按站点、客户端和时间筛选代理请求，并在需要时查看最近调试追踪。</div>
        </div>
        <div className="page-actions" style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap', justifyContent: 'flex-end' }}>
          <span className="kpi-chip">{activeSiteLabel}</span>
          <span className="kpi-chip kpi-chip-success">消耗总额 ${summary.totalCost.toFixed(4)}</span>
          <span className="kpi-chip kpi-chip-warning">{summary.totalTokensAll.toLocaleString()} tokens</span>
          <button
            onClick={() => setAutoRefresh((v) => !v)}
            className={`btn btn-ghost${autoRefresh ? ' btn-ghost-active' : ''}`}
            style={{ border: '1px solid var(--color-border)', padding: '6px 14px' }}
            title={autoRefresh ? '关闭自动刷新' : '开启自动刷新（每2秒）'}
          >
            <svg width="14" height="14" fill="none" viewBox="0 0 24 24" stroke="currentColor" style={{ animation: autoRefresh ? 'spin 1s linear infinite' : 'none' }}>
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
            {autoRefresh ? '自动刷新中' : '自动刷新'}
          </button>
          <button onClick={() => load()} disabled={loading} className="btn btn-ghost" style={{ border: '1px solid var(--color-border)', padding: '6px 14px' }}>
            <svg width="14" height="14" fill="none" viewBox="0 0 24 24" stroke="currentColor" style={{ animation: loading ? 'spin 1s linear infinite' : 'none' }}>
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
            {loading ? '加载中...' : '刷新'}
          </button>
        </div>
      </div>

      <ResponsiveFilterPanel
        isMobile={isMobile}
        mobileOpen={showFilters}
        onMobileOpen={() => setShowFilters(true)}
        onMobileClose={() => setShowFilters(false)}
        mobileTitle={tr('筛选日志')}
        mobileContent={filterControls}
        desktopContent={(
          <div className="toolbar" style={{ marginBottom: 12 }}>
            {filterControls}
          </div>
        )}
      />

      <div className="card" style={{ marginBottom: 12, padding: 14, display: 'flex', flexDirection: 'column', gap: 12 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 12, flexWrap: 'wrap' }}>
          <div>
            <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--color-text-primary)' }}>代理调试追踪</div>
            <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginTop: 4 }}>
              未开启时不记录新追踪；追踪详情通过弹窗按需查看。
            </div>
          </div>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <button
              type="button"
              className="btn btn-ghost"
              style={{ border: '1px solid var(--color-border)' }}
              aria-expanded={debugTracePanelExpanded}
              data-debug-trace-panel-toggle
              onClick={() => setDebugTracePanelExpanded((current) => !current)}
            >
              <svg
                width="14"
                height="14"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
                style={{
                  transform: debugTracePanelExpanded ? 'rotate(180deg)' : 'rotate(0deg)',
                  transition: 'transform 0.2s ease',
                }}
              >
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
              </svg>
              {debugTracePanelExpanded ? '收起追踪面板' : '展开追踪面板'}
            </button>
            <button
              type="button"
              className={debugSettings.proxyDebugTraceEnabled ? 'btn btn-ghost btn-ghost-active' : 'btn btn-ghost'}
              style={{ border: '1px solid var(--color-border)' }}
              onClick={() => void handleQuickToggleDebugTrace()}
              disabled={debugPanelSaving}
            >
              {debugSettings.proxyDebugTraceEnabled ? '关闭调试' : '开启调试'}
            </button>
            <button
              type="button"
              className="btn btn-ghost"
              style={{ border: '1px solid var(--color-border)' }}
              onClick={() => {
                setDebugDraftSettings(debugSettings);
                setShowDebugSettingsModal(true);
              }}
            >
              调试设置
            </button>
            <button
              type="button"
              className="btn btn-ghost"
              style={{ border: '1px solid var(--color-border)' }}
              onClick={() => void loadDebugState()}
              disabled={debugPanelLoading}
            >
              {debugPanelLoading ? '刷新中...' : '刷新追踪'}
            </button>
          </div>
        </div>

        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '12px 18px', alignItems: 'center' }}>
          <CompactSummaryMetric label="状态" value={debugSettings.proxyDebugTraceEnabled ? '已开启' : '未开启'} />
          <CompactSummaryMetric label="最近追踪" value={`${debugTraces.length} 条`} />
          <CompactSummaryMetric label="最新时间" value={latestDebugTrace ? formatDateTimeLocal(latestDebugTrace.createdAt) : '暂无'} />
        </div>

        <div style={{ display: 'grid', gap: 4 }}>
          <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>记录内容：{formatProxyDebugCaptureSummary(debugSettings)}</div>
          <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>过滤范围：{formatProxyDebugTargetSummary(debugSettings)}</div>
        </div>
      </div>

      <div
        className={`anim-collapse ${debugTracePanelExpanded ? 'is-open' : ''}`.trim()}
        data-debug-trace-panel-body
        style={{ marginBottom: debugTracePanelExpanded ? 12 : 0 }}
      >
        <div className="anim-collapse-inner">
          <div className="card" style={{ padding: 12, overflowX: 'auto' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, flexWrap: 'wrap', marginBottom: 12 }}>
              <div>
                <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--color-text-primary)' }}>最近调试追踪</div>
                <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginTop: 4 }}>
                  最多抓最近 20 条，列表分页每页 5 条；打开详情后各段内容可按需展开和收起。
                </div>
              </div>
              <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>
                {debugSettings.proxyDebugTraceEnabled ? '开启中，结果会自动刷新' : '尚未开启'}
              </div>
            </div>

            {debugPanelLoading && debugTraces.length === 0 ? (
              <div style={{ color: 'var(--color-text-muted)', fontSize: 13, paddingBottom: 12 }}>加载调试追踪中...</div>
            ) : debugTraces.length === 0 ? (
              <div
                style={{
                  padding: 14,
                  borderRadius: 'var(--radius-sm)',
                  border: '1px solid var(--color-border-light)',
                  background: 'var(--color-bg)',
                  color: 'var(--color-text-muted)',
                  fontSize: 12,
                  lineHeight: 1.6,
                }}
              >
                {debugSettings.proxyDebugTraceEnabled
                  ? '暂时还没有新追踪。这里只显示开启后产生的新请求，等下一次代理请求进入就会出现在这里。'
                  : '调试追踪尚未开启。点击上方“开启调试”或“调试设置”后，新的代理请求会出现在这里。'}
              </div>
            ) : isMobile ? (
              <div className="mobile-card-list">
                {visibleDebugTraces.map((trace) => (
                  <MobileCard
                    key={trace.id}
                    title={trace.sessionId || `trace-${trace.id}`}
                    subtitle={formatDateTimeLocal(trace.createdAt)}
                    compact
                    headerActions={renderTraceStatusBadge(trace)}
                    footerActions={(
                      <button
                        type="button"
                        className="btn btn-link"
                        onClick={() => openDebugTraceDetailModal(trace.id)}
                      >
                        查看详情
                      </button>
                    )}
                  >
                    <MobileField label="模型" value={trace.requestedModel || '-'} />
                    <MobileField label="下游路径" value={trace.downstreamPath || '-'} />
                    <MobileField label="上游路径" value={trace.finalUpstreamPath || '-'} />
                    <MobileField label="客户端" value={trace.clientKind || '-'} />
                  </MobileCard>
                ))}
              </div>
            ) : (
              <table className="data-table" style={{ width: '100%' }}>
                <thead>
                  <tr>
                    <th>时间</th>
                    <th>Session</th>
                    <th>模型</th>
                    <th>下游路径</th>
                    <th>上游路径</th>
                    <th>客户端</th>
                    <th>{tr('状态')}</th>
                    <th style={{ textAlign: 'right' }}>操作</th>
                  </tr>
                </thead>
                <tbody>
                  {visibleDebugTraces.map((trace) => (
                    <tr key={trace.id}>
                      <td style={{ fontSize: 12, whiteSpace: 'nowrap', fontVariantNumeric: 'tabular-nums', color: 'var(--color-text-secondary)' }}>
                        {formatDateTimeLocal(trace.createdAt)}
                      </td>
                      <td style={{ fontSize: 12, fontWeight: 600 }}>{trace.sessionId || `trace-${trace.id}`}</td>
                      <td style={{ fontSize: 12 }}>{trace.requestedModel || '-'}</td>
                      <td style={{ fontSize: 12, color: 'var(--color-text-secondary)' }}>{trace.downstreamPath || '-'}</td>
                      <td style={{ fontSize: 12, color: 'var(--color-text-secondary)' }}>{trace.finalUpstreamPath || '-'}</td>
                      <td style={{ fontSize: 12, color: 'var(--color-text-secondary)' }}>{trace.clientKind || '-'}</td>
                      <td>{renderTraceStatusBadge(trace)}</td>
                      <td style={{ textAlign: 'right' }}>
                        <button
                          type="button"
                          className="btn btn-link"
                          onClick={() => openDebugTraceDetailModal(trace.id)}
                        >
                          查看详情
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            {debugTraces.length > 0 ? (
              <div className="pagination" style={{ marginTop: 12 }}>
                <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginRight: 'auto' }}>
                  显示第 {debugTraceDisplayedStart} - {debugTraceDisplayedEnd} 条，共 {debugTraces.length} 条
                </div>
                <button
                  className="pagination-btn"
                  aria-label="调试追踪上一页"
                  disabled={safeDebugTracePage <= 1}
                  onClick={() => setDebugTracePage((current) => current - 1)}
                >
                  <svg width="14" height="14" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" /></svg>
                </button>
                {Array.from({ length: debugTraceTotalPages }, (_, index) => index + 1).map((num) => (
                  <button
                    key={`debug-trace-page-${num}`}
                    className={`pagination-btn ${safeDebugTracePage === num ? 'active' : ''}`}
                    onClick={() => setDebugTracePage(num)}
                  >
                    {num}
                  </button>
                ))}
                <button
                  className="pagination-btn"
                  aria-label="调试追踪下一页"
                  disabled={safeDebugTracePage >= debugTraceTotalPages}
                  onClick={() => setDebugTracePage((current) => current + 1)}
                >
                  <svg width="14" height="14" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" /></svg>
                </button>
              </div>
            ) : null}
          </div>
        </div>
      </div>

      {isMobile ? (
        <MobileDrawer
          open={showDebugSettingsModal}
          onClose={() => {
            setShowDebugSettingsModal(false);
            setDebugDraftSettings(debugSettings);
          }}
          title="调试设置"
          closeLabel="关闭调试设置"
          side="right"
        >
          <div style={{ padding: 16, display: 'grid', gap: 16 }}>
            {debugSettingsForm}
          </div>
        </MobileDrawer>
      ) : (
        <CenteredModal
          open={showDebugSettingsModal}
          onClose={() => {
            setShowDebugSettingsModal(false);
            setDebugDraftSettings(debugSettings);
          }}
          title="调试设置"
          footer={debugSettingsFooter}
          maxWidth={880}
          closeOnBackdrop
          closeOnEscape
        >
          {debugSettingsForm}
        </CenteredModal>
      )}

      {isMobile ? (
        <MobileDrawer
          open={showDebugTraceDetailModal}
          onClose={closeDebugTraceDetailModal}
          title={selectedDebugTraceListItem?.sessionId || '追踪详情'}
          closeLabel="关闭追踪详情"
          side="right"
        >
          <div style={{ padding: 16, display: 'grid', gap: 16 }}>
            {renderDebugTraceDetailContent()}
          </div>
        </MobileDrawer>
      ) : (
        <CenteredModal
          open={showDebugTraceDetailModal}
          onClose={closeDebugTraceDetailModal}
          title={selectedDebugTraceListItem?.sessionId || '追踪详情'}
          maxWidth={920}
          closeOnBackdrop
          closeOnEscape
        >
          {renderDebugTraceDetailContent()}
        </CenteredModal>
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
              const pathMeta = parseProxyLogPathMeta(detailLog.errorMessage ?? undefined);
              const billingDetailSummary = detail ? formatBillingDetailSummary(detailLog) : null;
              const billingProcessLines = detail ? buildBillingProcessLines(detailLog) : [];
              const downstreamKeySummary = renderDownstreamKeySummary(detailLog);
              const isExpanded = expanded === log.id;
              const clientDisplay = resolveProxyLogClientDisplay(detailLog);

              return (
                <MobileCard
                  key={log.id}
                  title={detailLog.modelRequested || 'unknown'}
                  subtitle={formatDateTimeLocal(log.createdAt)}
                  compact
                  headerActions={(
                    <span className={`badge ${log.status === 'success' ? 'badge-success' : 'badge-error'}`} style={{ fontSize: 10 }}>
                      {log.status === 'success' ? '成功' : '失败'}
                    </span>
                  )}
                  footerActions={(
                    <button
                      type="button"
                      className="btn btn-link"
                      onClick={() => handleToggleExpand(log.id)}
                    >
                      {isExpanded ? '收起详情' : '详情'}
                    </button>
                  )}
                >
                  <div className="mobile-inline-meta-row">
                    <SiteBadgeLink siteId={siteIdByName.get(String(log.siteName || '').trim())} siteName={log.siteName} badgeStyle={{ fontSize: 11 }} />
                    {clientDisplay.primary ? (
                      <span className="badge badge-muted" style={{ fontSize: 10 }}>
                        {clientDisplay.primary}
                      </span>
                    ) : null}
                    {clientDisplay.secondary ? (
                      <span className="badge badge-muted" style={{ fontSize: 10 }}>
                        {clientDisplay.secondary}
                      </span>
                    ) : null}
                  </div>
                  <div className="mobile-summary-grid">
                    <div className="mobile-summary-metric">
                      <div className="mobile-summary-metric-label">用时</div>
                      <div className="mobile-summary-metric-value">{formatLatency(log.latencyMs)}</div>
                    </div>
                    <div className="mobile-summary-metric">
                      <div className="mobile-summary-metric-label">输入</div>
                      <div className="mobile-summary-metric-value">{log.promptTokens?.toLocaleString() || '-'}</div>
                    </div>
                    <div className="mobile-summary-metric">
                      <div className="mobile-summary-metric-label">输出</div>
                      <div className="mobile-summary-metric-value">{log.completionTokens?.toLocaleString() || '-'}</div>
                    </div>
                    <div className="mobile-summary-metric">
                      <div className="mobile-summary-metric-label">花费</div>
                      <div className="mobile-summary-metric-value">{typeof log.estimatedCost === 'number' ? `$${log.estimatedCost.toFixed(6)}` : '-'}</div>
                    </div>
                  </div>
                  {isExpanded ? (
                    <div className="mobile-card-extra">
                      <MobileField label="时间" value={formatDateTimeLocal(log.createdAt)} />
                      <MobileField label="站点" value={<SiteBadgeLink siteId={siteIdByName.get(String(log.siteName || '').trim())} siteName={log.siteName} badgeStyle={{ fontSize: 11 }} />} />
                      <MobileField label="重试" value={log.retryCount > 0 ? log.retryCount : 0} />
                      {detailState?.loading && <div style={{ color: 'var(--color-text-muted)' }}>加载详情中...</div>}
                      {detailState?.error && <div style={{ color: 'var(--color-danger)' }}>{detailState.error}</div>}
                      {billingDetailSummary && <div style={{ color: 'var(--color-text-muted)' }}>{billingDetailSummary}</div>}
                      <MobileField label="客户端详情" value={renderProxyLogClientCell(detailLog, { includeGeneric: true })} />
                      {downstreamKeySummary && <div style={{ color: 'var(--color-text-muted)' }}>{downstreamKeySummary}</div>}
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
                <th>客户端</th>
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
                const pathMeta = parseProxyLogPathMeta(detailLog.errorMessage ?? undefined);
                const billingDetailSummary = detail ? formatBillingDetailSummary(detailLog) : null;
                const billingProcessLines = detail ? buildBillingProcessLines(detailLog) : [];
                const downstreamKeySummary = renderDownstreamKeySummary(detailLog);

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
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                          <ModelBadge model={log.modelRequested} style={{ alignSelf: 'flex-start' }} />
                          {downstreamKeySummary ? (
                            <div style={{ fontSize: 11, lineHeight: 1.45, color: 'var(--color-text-muted)' }}>
                              {downstreamKeySummary}
                            </div>
                          ) : null}
                        </div>
                      </td>
                      <td style={{ fontSize: 12, color: 'var(--color-text-secondary)' }}>
                        <SiteBadgeLink siteId={siteIdByName.get(String(log.siteName || '').trim())} siteName={log.siteName} badgeStyle={{ fontSize: 11 }} />
                      </td>
                      <td style={{ fontSize: 12, color: 'var(--color-text-secondary)' }}>
                        {renderProxyLogClientCell(detailLog)}
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
                        <td colSpan={11} style={{ padding: 0 }}>
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
                                    <div style={{ display: 'flex', gap: 6, alignItems: 'flex-start' }}>
                                      <span style={{ color: 'var(--color-text-muted)', flexShrink: 0 }}>客户端</span>
                                      <div style={{ minWidth: 0 }}>
                                        {renderProxyLogClientCell(detailLog, { includeGeneric: true })}
                                      </div>
                                    </div>
                                    {downstreamKeySummary && (
                                      <div style={{ color: 'var(--color-text-muted)' }}>{downstreamKeySummary}</div>
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
                                    <span style={{ color: 'var(--color-danger)', whiteSpace: 'pre-wrap' }}>{pathMeta.errorMessage}</span>
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
