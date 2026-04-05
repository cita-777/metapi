import React from 'react';

export type Range = '24h' | '7d' | 'all';

export type SummaryItem = {
  id: number;
  name: string;
  keyMasked: string;
  enabled: boolean;
  description: string | null;
  groupName: string | null;
  tags: string[];
  expiresAt: string | null;
  maxCost: number | null;
  usedCost: number;
  maxRequests: number | null;
  usedRequests: number;
  supportedModels: string[];
  allowedRouteIds: number[];
  siteWeightMultipliers: Record<number, number>;
  excludedSiteIds: number[];
  excludedCredentialRefs: Array<
    | { kind: 'account_token'; siteId: number; accountId: number; tokenId: number }
    | { kind: 'default_api_key'; siteId: number; accountId: number }
  >;
  lastUsedAt: string | null;
  createdAt: string | null;
  updatedAt: string | null;
  rangeUsage: {
    totalRequests: number;
    successRequests: number;
    failedRequests: number;
    successRate: number | null;
    totalTokens: number;
    totalCost: number;
  };
};

export type AggregateUsage = {
  totalRequests: number;
  successRequests: number;
  failedRequests: number;
  successRate: number | null;
  totalTokens: number;
  totalCost: number;
};

export type OverviewResponse = {
  success: boolean;
  item: SummaryItem;
  usage: null | {
    last24h: AggregateUsage | null;
    last7d: AggregateUsage | null;
    all: AggregateUsage | null;
  };
};

export function formatIso(value: string | null | undefined): string {
  const text = (value || '').trim();
  if (!text) return '--';
  const date = new Date(text);
  if (Number.isNaN(date.getTime())) return text;
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

export function formatMoney(value: number): string {
  if (!Number.isFinite(value)) return '$0';
  if (value >= 1) return `$${value.toFixed(3)}`;
  return `$${value.toFixed(6)}`;
}

export function formatCompactTokens(value: number): string {
  if (!Number.isFinite(value)) return '0';
  if (value >= 1_000_000_000) return `${(value / 1_000_000_000).toFixed(2)}B`;
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(2)}M`;
  if (value >= 1_000) return `${(value / 1_000).toFixed(1)}K`;
  return String(Math.trunc(value));
}

export function TagChips({
  tags,
  accent = false,
  maxVisible = 3,
}: {
  tags: string[];
  accent?: boolean;
  maxVisible?: number;
}) {
  if (!Array.isArray(tags) || tags.length === 0) {
    return <span className="badge badge-muted" style={{ fontSize: 11 }}>无标签</span>;
  }

  const visible = tags.slice(0, maxVisible);
  const hidden = tags.length - visible.length;
  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
      {visible.map((tag) => (
        <span
          key={tag}
          className={`badge ${accent ? 'badge-info' : 'badge-muted'}`}
          style={{ fontSize: 11 }}
        >
          {tag}
        </span>
      ))}
      {hidden > 0 ? <span className="badge badge-muted" style={{ fontSize: 11 }}>{`+${hidden}`}</span> : null}
    </div>
  );
}

export function resolveOverviewUsageByRange(
  overview: OverviewResponse | null,
  range: Range,
): AggregateUsage | null {
  if (!overview?.usage) return null;
  if (range === '24h') return overview.usage.last24h;
  if (range === '7d') return overview.usage.last7d;
  return overview.usage.all;
}

export function TrendChartFallback({ height = 260 }: { height?: number }) {
  return (
    <div className="card" style={{ padding: 16 }}>
      <div className="skeleton" style={{ width: 140, height: 28, borderRadius: 'var(--radius-sm)', marginBottom: 10 }} />
      <div className="skeleton" style={{ width: '100%', height, borderRadius: 'var(--radius-sm)' }} />
    </div>
  );
}

export function RangeToggle({ range, onChange }: { range: Range; onChange: (r: Range) => void }) {
  const base: React.CSSProperties = {
    padding: '6px 12px',
    fontSize: 12,
    fontWeight: 600,
    border: '1px solid var(--color-border)',
    background: 'var(--color-bg-card)',
    color: 'var(--color-text-muted)',
    cursor: 'pointer',
  };

  const active: React.CSSProperties = {
    background: 'var(--color-primary)',
    color: '#fff',
    borderColor: 'var(--color-primary)',
  };

  return (
    <div style={{ display: 'inline-flex', borderRadius: 'var(--radius-sm)', overflow: 'hidden' }}>
      <button type="button" onClick={() => onChange('24h')} style={{ ...base, ...(range === '24h' ? active : {}), borderRight: 'none' }}>
        24h
      </button>
      <button type="button" onClick={() => onChange('7d')} style={{ ...base, ...(range === '7d' ? active : {}), borderRight: 'none' }}>
        7d
      </button>
      <button type="button" onClick={() => onChange('all')} style={{ ...base, ...(range === 'all' ? active : {}), borderTopRightRadius: 'var(--radius-sm)', borderBottomRightRadius: 'var(--radius-sm)' }}>
        全部
      </button>
    </div>
  );
}

export function StatusBadge({ enabled }: { enabled: boolean }) {
  return (
    <span className={`badge ${enabled ? 'badge-success' : 'badge-muted'}`} style={{ fontSize: 11 }}>
      {enabled ? '启用' : '禁用'}
    </span>
  );
}
