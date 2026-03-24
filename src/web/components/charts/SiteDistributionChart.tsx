import { useState, useMemo } from 'react';
import { VChart } from '@visactor/react-vchart';
import { useThemeLabelColor } from '../useThemeLabelColor.js';

interface SiteDistributionData {
  siteName: string;
  platform: string;
  totalBalance: number;
  totalSpend: number;
  accountCount: number;
}

interface SiteDistributionChartProps {
  data: SiteDistributionData[];
  loading?: boolean;
}

type ViewMode = 'balance' | 'spend';

function coerceDatumRecord(datum: unknown): Record<string, unknown> {
  return datum && typeof datum === 'object' ? datum as Record<string, unknown> : {};
}

function safeNumber(value: unknown): number {
  if (typeof value !== 'number' || Number.isNaN(value) || !Number.isFinite(value)) return 0;
  return value;
}

function SkeletonCircle() {
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '40px 0',
      }}
    >
      <div
        className="skeleton"
        style={{
          width: 200,
          height: 200,
          borderRadius: '50%',
        }}
      />
      <div style={{ marginLeft: 32, display: 'flex', flexDirection: 'column', gap: 12 }}>
        {[...Array(4)].map((_, i) => (
          <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <div className="skeleton" style={{ width: 12, height: 12, borderRadius: 3 }} />
            <div className="skeleton" style={{ width: 80 + i * 10, height: 12 }} />
          </div>
        ))}
      </div>
    </div>
  );
}

function EmptyState() {
  return (
    <div className="empty-state" style={{ padding: 40 }}>
      <div style={{ margin: '0 auto 16px', width: 64, height: 64, opacity: 0.35 }}>
        <svg
          width="64"
          height="64"
          fill="none"
          viewBox="0 0 24 24"
          stroke="var(--color-text-muted)"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={1.2}
            d="M11 3.055A9.001 9.001 0 1020.945 13H11V3.055z"
          />
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={1.2}
            d="M20.488 9H15V3.512A9.025 9.025 0 0120.488 9z"
          />
        </svg>
      </div>
      <div className="empty-state-title" style={{ marginBottom: 4 }}>
        暂无站点数据
      </div>
      <div className="empty-state-desc">添加站点后将自动展示分布图表</div>
    </div>
  );
}

export default function SiteDistributionChart({ data, loading }: SiteDistributionChartProps) {
  const [viewMode, setViewMode] = useState<ViewMode>('balance');
  const labelColor = useThemeLabelColor();

  const chartData = useMemo(() => {
    if (!data || data.length === 0) return [];
    return data.map((item) => ({
      siteName: item.siteName,
      platform: item.platform,
      value: safeNumber(viewMode === 'balance' ? item.totalBalance : item.totalSpend),
      accountCount: safeNumber(item.accountCount),
    }));
  }, [data, viewMode]);

  const hasData = chartData.length > 0 && chartData.some((d) => d.value > 0);

  const PIE_COLORS = ['#4f46e5', '#06b6d4', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#ec4899', '#14b8a6'];

  const spec = useMemo(() => {
    if (!hasData) return null;

    return {
      type: 'pie' as const,
      data: [{ id: 'siteData', values: chartData }],
      valueField: 'value',
      categoryField: 'siteName',
      outerRadius: 0.8,
      innerRadius: 0.55,
      pie: { style: { cornerRadius: 4, padAngle: 0.02 } },
      label: { visible: true, position: 'outside', formatter: '{_percent_}%', style: { fill: labelColor } },
      legends: { visible: false },
      tooltip: {
        mark: {
          content: [
            {
              key: (datum: unknown) => {
                const item = coerceDatumRecord(datum);
                return String(item.siteName || '-');
              },
              value: (datum: unknown) => {
                const item = coerceDatumRecord(datum);
                const val = safeNumber(item.value);
                return `$${val.toFixed(2)}`;
              },
            },
            {
              key: '占比',
              value: (datum: unknown) => {
                const item = coerceDatumRecord(datum);
                const pct = safeNumber(item._percent_);
                return `${pct.toFixed(1)}%`;
              },
            },
            {
              key: '账户数',
              value: (datum: unknown) => {
                const item = coerceDatumRecord(datum);
                return String(item.accountCount || 0);
              },
            },
          ] as any,
        },
      },
      color: PIE_COLORS,
      animation: true,
      background: 'transparent',
    };
  }, [chartData, hasData, labelColor]);

  const formatValue = (value: number): string => {
    if (value >= 1000) return `$${value.toFixed(2)}`;
    if (value >= 1) return `$${value.toFixed(3)}`;
    return `$${value.toFixed(6)}`;
  };

  return (
    <div
      className="chart-container animate-fade-in"
      style={{ padding: 20 }}
    >
      {/* Header */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          marginBottom: 16,
        }}
      >
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 6,
            fontSize: 14,
            fontWeight: 600,
            color: 'var(--color-text-primary)',
          }}
        >
          <svg
            width="16"
            height="16"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M11 3.055A9.001 9.001 0 1020.945 13H11V3.055z"
            />
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M20.488 9H15V3.512A9.025 9.025 0 0120.488 9z"
            />
          </svg>
          站点分布
        </div>

        {/* Toggle buttons */}
        <div
          style={{
            display: 'flex',
            gap: 0,
            background: 'var(--color-bg)',
            borderRadius: 'var(--radius-sm)',
            padding: 3,
            border: '1px solid var(--color-border-light)',
          }}
        >
          <button
            onClick={() => setViewMode('balance')}
            style={{
              padding: '5px 14px',
              fontSize: 12,
              fontWeight: 500,
              border: 'none',
              borderRadius: 'calc(var(--radius-sm) - 2px)',
              cursor: 'pointer',
              transition: 'all 0.2s ease',
              background: viewMode === 'balance' ? 'var(--color-primary)' : 'transparent',
              color: viewMode === 'balance' ? '#ffffff' : 'var(--color-text-secondary)',
              boxShadow: viewMode === 'balance' ? 'var(--shadow-sm)' : 'none',
            }}
          >
            余额分布
          </button>
          <button
            onClick={() => setViewMode('spend')}
            style={{
              padding: '5px 14px',
              fontSize: 12,
              fontWeight: 500,
              border: 'none',
              borderRadius: 'calc(var(--radius-sm) - 2px)',
              cursor: 'pointer',
              transition: 'all 0.2s ease',
              background: viewMode === 'spend' ? 'var(--color-primary)' : 'transparent',
              color: viewMode === 'spend' ? '#ffffff' : 'var(--color-text-secondary)',
              boxShadow: viewMode === 'spend' ? 'var(--shadow-sm)' : 'none',
            }}
          >
            消耗分布
          </button>
        </div>
      </div>

      {/* Content */}
      {loading ? (
        <SkeletonCircle />
      ) : !hasData ? (
        <EmptyState />
      ) : (
        <div>
          <div style={{ width: '100%', height: 300 }}>
            {spec && <VChart spec={spec} style={{ width: '100%', height: '100%' }} />}
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px 14px', marginTop: 10, padding: '0 4px' }}>
            {chartData.map((d, idx) => (
              <span key={d.siteName} style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 11, color: 'var(--color-text-secondary)' }}>
                <span style={{ width: 8, height: 8, borderRadius: 2, background: PIE_COLORS[idx % PIE_COLORS.length], flexShrink: 0 }} />
                <span style={{ maxWidth: 120, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{d.siteName}</span>
                <span style={{ fontVariantNumeric: 'tabular-nums', fontWeight: 600, color: 'var(--color-text-primary)' }}>
                  {formatValue(d.value)}
                </span>
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
