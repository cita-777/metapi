import React, { Suspense, lazy, useEffect, useMemo, useState } from 'react';
import { createPortal } from 'react-dom';
import { api, type DownstreamApiKeyTrendResponse } from '../../api.js';
import { useToast } from '../../components/Toast.js';
import { useAnimatedVisibility } from '../../components/useAnimatedVisibility.js';
import { readClientTimeZone } from '../helpers/siteAnnouncementPresentation.js';
import {
  formatCompactTokens,
  formatIso,
  formatMoney,
  type OverviewResponse,
  RangeToggle,
  resolveOverviewUsageByRange,
  StatusBadge,
  TagChips,
  TrendChartFallback,
  type Range,
  type SummaryItem,
} from './shared.js';

const DownstreamKeyTrendChart = lazy(() => import('../../components/charts/DownstreamKeyTrendChart.js'));
type DownstreamKeyTrendBucket = import('../../components/charts/DownstreamKeyTrendChart.js').DownstreamKeyTrendBucket;

type DownstreamKeyDrawerProps = {
  open: boolean;
  onClose: () => void;
  item: SummaryItem | null;
  initialRange: Range;
};

export default function DownstreamKeyDrawer({
  open,
  onClose,
  item,
  initialRange,
}: DownstreamKeyDrawerProps) {
  const toast = useToast();
  const presence = useAnimatedVisibility(open, 220);
  const [overview, setOverview] = useState<OverviewResponse | null>(null);
  const [overviewLoading, setOverviewLoading] = useState(false);
  const [trendRange, setTrendRange] = useState<Range>(initialRange);
  const [trendLoading, setTrendLoading] = useState(false);
  const [buckets, setBuckets] = useState<DownstreamKeyTrendBucket[]>([]);
  const [trendBucketSeconds, setTrendBucketSeconds] = useState<number>(initialRange === 'all' ? 86400 : 3600);
  const viewerTimeZone = useMemo(() => readClientTimeZone(), []);

  useEffect(() => {
    if (!open) return;
    setTrendRange(initialRange);
    setTrendBucketSeconds(initialRange === 'all' ? 86400 : 3600);
  }, [open, initialRange]);

  useEffect(() => {
    if (!open || !item?.id) return;
    let cancelled = false;
    setOverview(null);
    setOverviewLoading(true);
    api.getDownstreamApiKeyOverview(item.id)
      .then((res: any) => {
        if (cancelled) return;
        setOverview(res as OverviewResponse);
      })
      .catch((err: any) => {
        if (cancelled) return;
        toast.error(err?.message || '加载 Key 概览失败');
      })
      .finally(() => {
        if (cancelled) return;
        setOverviewLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [open, item?.id, toast]);

  useEffect(() => {
    if (!open || !item?.id) return;
    let cancelled = false;
    const fallbackBucketSeconds = trendRange === 'all' ? 86400 : 3600;
    setBuckets([]);
    setTrendBucketSeconds(fallbackBucketSeconds);
    setTrendLoading(true);
    const trendParams = trendRange === 'all' && viewerTimeZone
      ? { range: trendRange, timeZone: viewerTimeZone }
      : { range: trendRange };
    api.getDownstreamApiKeyTrend(item.id, trendParams)
      .then((res: DownstreamApiKeyTrendResponse) => {
        if (cancelled) return;
        setBuckets(Array.isArray(res.buckets) ? res.buckets : []);
        const nextBucketSeconds = Number(res.bucketSeconds);
        setTrendBucketSeconds(Number.isFinite(nextBucketSeconds) && nextBucketSeconds > 0 ? nextBucketSeconds : fallbackBucketSeconds);
      })
      .catch((err: any) => {
        if (cancelled) return;
        toast.error(err?.message || '加载趋势失败');
      })
      .finally(() => {
        if (cancelled) return;
        setTrendLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [open, item?.id, trendRange, toast, viewerTimeZone]);

  if (!presence.shouldRender) return null;

  const currentRangeUsage = resolveOverviewUsageByRange(overview, trendRange) || item?.rangeUsage || null;

  const panel = (
    <div
      className={`modal-backdrop ${presence.isVisible ? '' : 'is-closing'}`.trim()}
      onClick={onClose}
      style={{ justifyContent: 'flex-end', alignItems: 'stretch', padding: 0 }}
    >
      <div
        className={`modal-content ${presence.isVisible ? '' : 'is-closing'}`.trim()}
        onClick={(e) => e.stopPropagation()}
        style={{
          width: 'min(92vw, 560px)',
          maxWidth: 560,
          height: '100vh',
          maxHeight: '100vh',
          borderRadius: 0,
          animation: presence.isVisible ? 'drawer-slide-in 0.3s cubic-bezier(0.22, 1, 0.36, 1) both' : 'drawer-slide-out 0.22s cubic-bezier(0.4, 0, 1, 1) both',
        }}
      >
        <div className="modal-header" style={{ paddingTop: 18, paddingBottom: 12, display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12 }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <span>{item?.name || '--'}</span>
              <StatusBadge enabled={!!item?.enabled} />
            </div>
            <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>
              {item?.keyMasked || '****'}
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginTop: 6 }}>
              <span className={`badge ${item?.groupName ? 'badge-info' : 'badge-muted'}`} style={{ fontSize: 11 }}>
                {item?.groupName ? `主分组 · ${item.groupName}` : '未分组'}
              </span>
              <TagChips tags={item?.tags || []} accent maxVisible={4} />
            </div>
          </div>
          <button className="btn btn-ghost" onClick={onClose} style={{ border: '1px solid var(--color-border)' }}>
            关闭
          </button>
        </div>

        <div className="modal-body" style={{ paddingTop: 0 }}>
          <div className="card" style={{ padding: 16, marginBottom: 16 }}>
            <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12, marginBottom: 12, flexWrap: 'wrap' }}>
              <div>
                <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--color-text-primary)' }}>使用趋势</div>
                <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginTop: 4 }}>按选定时间窗口查看请求、Tokens 与成本变化。</div>
              </div>
              <RangeToggle range={trendRange} onChange={setTrendRange} />
            </div>

            <Suspense fallback={<TrendChartFallback height={260} />}>
              <DownstreamKeyTrendChart buckets={buckets} bucketSeconds={trendBucketSeconds} loading={trendLoading} height={260} />
            </Suspense>
          </div>

          <div className="card" style={{ padding: 16, marginBottom: 16 }}>
            <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--color-text-primary)', marginBottom: 10 }}>
              基础信息
            </div>
            {overviewLoading ? (
              <div className="skeleton" style={{ width: '100%', height: 72, borderRadius: 'var(--radius-sm)' }} />
            ) : (
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, fontSize: 12 }}>
                <div>
                  <div style={{ color: 'var(--color-text-muted)', marginBottom: 4 }}>最近使用</div>
                  <div style={{ color: 'var(--color-text-primary)', fontWeight: 600 }}>{formatIso(item?.lastUsedAt)}</div>
                </div>
                <div>
                  <div style={{ color: 'var(--color-text-muted)', marginBottom: 4 }}>累计请求</div>
                  <div style={{ color: 'var(--color-text-primary)', fontWeight: 600 }}>{(item?.usedRequests || 0).toLocaleString()}</div>
                </div>
                <div>
                  <div style={{ color: 'var(--color-text-muted)', marginBottom: 4 }}>累计成本</div>
                  <div style={{ color: 'var(--color-text-primary)', fontWeight: 600 }}>{formatMoney(Number(item?.usedCost || 0))}</div>
                </div>
                <div>
                  <div style={{ color: 'var(--color-text-muted)', marginBottom: 4 }}>到期时间</div>
                  <div style={{ color: 'var(--color-text-primary)', fontWeight: 600 }}>{formatIso(item?.expiresAt)}</div>
                </div>
                <div>
                  <div style={{ color: 'var(--color-text-muted)', marginBottom: 4 }}>主分组</div>
                  <div style={{ color: 'var(--color-text-primary)', fontWeight: 600 }}>{item?.groupName || '未分组'}</div>
                </div>
                <div style={{ gridColumn: '1 / -1' }}>
                  <div style={{ color: 'var(--color-text-muted)', marginBottom: 6 }}>标签</div>
                  <TagChips tags={item?.tags || []} accent maxVisible={6} />
                </div>
              </div>
            )}
          </div>

          <div className="card" style={{ padding: 16 }}>
            <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--color-text-primary)', marginBottom: 10 }}>
              当前范围汇总
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, fontSize: 12 }}>
              <div>
                <div style={{ color: 'var(--color-text-muted)', marginBottom: 4 }}>Tokens</div>
                <div style={{ color: 'var(--color-text-primary)', fontWeight: 700 }}>{formatCompactTokens(currentRangeUsage?.totalTokens || 0)}</div>
              </div>
              <div>
                <div style={{ color: 'var(--color-text-muted)', marginBottom: 4 }}>请求数</div>
                <div style={{ color: 'var(--color-text-primary)', fontWeight: 700 }}>{(currentRangeUsage?.totalRequests || 0).toLocaleString()}</div>
              </div>
              <div>
                <div style={{ color: 'var(--color-text-muted)', marginBottom: 4 }}>成功率</div>
                <div style={{ color: 'var(--color-text-primary)', fontWeight: 700 }}>{currentRangeUsage?.successRate == null ? '--' : `${currentRangeUsage.successRate}%`}</div>
              </div>
              <div>
                <div style={{ color: 'var(--color-text-muted)', marginBottom: 4 }}>成本</div>
                <div style={{ color: 'var(--color-text-primary)', fontWeight: 700 }}>{formatMoney(Number(currentRangeUsage?.totalCost || 0))}</div>
              </div>
            </div>
          </div>

          {overview?.usage ? (
            <div className="card" style={{ padding: 16, marginTop: 16 }}>
              <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--color-text-primary)', marginBottom: 10 }}>
                固定窗口对比
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12, fontSize: 12 }}>
                {[
                  { label: '24h', data: overview.usage.last24h },
                  { label: '7d', data: overview.usage.last7d },
                  { label: '全部', data: overview.usage.all },
                ].map((section) => (
                  <div key={section.label} style={{ border: '1px solid var(--color-border-light)', borderRadius: 'var(--radius-sm)', padding: 12 }}>
                    <div style={{ color: 'var(--color-text-primary)', fontWeight: 700, marginBottom: 8 }}>{section.label}</div>
                    <div style={{ color: 'var(--color-text-muted)', marginBottom: 4 }}>Tokens</div>
                    <div style={{ color: 'var(--color-text-primary)', fontWeight: 700, marginBottom: 8 }}>{formatCompactTokens(section.data?.totalTokens || 0)}</div>
                    <div style={{ color: 'var(--color-text-muted)', marginBottom: 4 }}>请求数</div>
                    <div style={{ color: 'var(--color-text-primary)', fontWeight: 700, marginBottom: 8 }}>{(section.data?.totalRequests || 0).toLocaleString()}</div>
                    <div style={{ color: 'var(--color-text-muted)', marginBottom: 4 }}>成功率</div>
                    <div style={{ color: 'var(--color-text-primary)', fontWeight: 700 }}>{section.data?.successRate == null ? '--' : `${section.data.successRate}%`}</div>
                  </div>
                ))}
              </div>
            </div>
          ) : null}
        </div>
      </div>
    </div>
  );

  return createPortal(panel, document.body);
}
