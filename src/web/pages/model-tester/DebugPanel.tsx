import React from 'react';
import { DEBUG_TABS, type DebugTab } from '../helpers/modelTesterSession.js';

type DebugTimelineEntry = {
  at: string;
  level: 'info' | 'warn' | 'error';
  text: string;
};

type DebugPanelPresence = {
  shouldRender: boolean;
  isVisible: boolean;
};

type DebugPanelProps = {
  presence: DebugPanelPresence;
  isMobile: boolean;
  debugTimestamp: string | null;
  activeDebugTab: DebugTab;
  onTabChange: (tab: DebugTab) => void;
  debugTabContent: string;
  debugTimeline: DebugTimelineEntry[];
};

export default function DebugPanel({
  presence,
  isMobile,
  debugTimestamp,
  activeDebugTab,
  onTabChange,
  debugTabContent,
  debugTimeline,
}: DebugPanelProps) {
  if (!presence.shouldRender) {
    return null;
  }

  return (
    <div
      className={`card panel-presence ${presence.isVisible ? '' : 'is-closing'}`.trim()}
      style={{
        padding: 14,
        minHeight: isMobile ? 'auto' : 680,
        maxHeight: isMobile ? 'none' : 740,
        display: 'flex',
        flexDirection: 'column',
        order: isMobile ? 3 : 0,
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
        <h3 style={{ margin: 0, fontSize: 15 }}>调试</h3>
        <div style={{ fontSize: 11, color: 'var(--color-text-muted)' }}>
          {debugTimestamp ? new Date(debugTimestamp).toLocaleString() : '--'}
        </div>
      </div>

      <div style={{ display: 'flex', gap: 8, marginBottom: 10, flexWrap: 'wrap' }}>
        <button
          className="btn btn-ghost"
          style={{
            border: activeDebugTab === DEBUG_TABS.PREVIEW ? '1px solid var(--color-primary)' : '1px solid var(--color-border)',
            color: activeDebugTab === DEBUG_TABS.PREVIEW ? 'var(--color-primary)' : 'var(--color-text-secondary)',
          }}
          onClick={() => onTabChange(DEBUG_TABS.PREVIEW)}
        >
          预览
        </button>
        <button
          className="btn btn-ghost"
          style={{
            border: activeDebugTab === DEBUG_TABS.REQUEST ? '1px solid var(--color-primary)' : '1px solid var(--color-border)',
            color: activeDebugTab === DEBUG_TABS.REQUEST ? 'var(--color-primary)' : 'var(--color-text-secondary)',
          }}
          onClick={() => onTabChange(DEBUG_TABS.REQUEST)}
        >
          请求
        </button>
        <button
          className="btn btn-ghost"
          style={{
            border: activeDebugTab === DEBUG_TABS.RESPONSE ? '1px solid var(--color-primary)' : '1px solid var(--color-border)',
            color: activeDebugTab === DEBUG_TABS.RESPONSE ? 'var(--color-primary)' : 'var(--color-text-secondary)',
          }}
          onClick={() => onTabChange(DEBUG_TABS.RESPONSE)}
        >
          响应
        </button>
      </div>

      <div style={{ flex: 1, overflow: 'hidden', border: '1px solid var(--color-border-light)', borderRadius: 'var(--radius-sm)', background: 'var(--color-bg)' }}>
        <pre style={{
          margin: 0,
          padding: 12,
          fontSize: 12,
          lineHeight: 1.55,
          fontFamily: 'var(--font-mono)',
          whiteSpace: 'pre-wrap',
          wordBreak: 'break-word',
          overflow: 'auto',
          maxHeight: '100%',
        }}>
          {debugTabContent || '// 暂无数据'}
        </pre>
      </div>

      <div style={{ marginTop: 10, fontSize: 12, fontWeight: 600 }}>时间线</div>
      <div style={{
        marginTop: 6,
        border: '1px solid var(--color-border-light)',
        borderRadius: 'var(--radius-sm)',
        padding: 8,
        minHeight: 120,
        maxHeight: 170,
        overflowY: 'auto',
        background: 'var(--color-bg)',
      }}>
        {debugTimeline.length === 0 ? (
          <div style={{ color: 'var(--color-text-muted)', fontSize: 12 }}>暂无事件。</div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {debugTimeline.map((item, index) => (
              <div key={`${item.at}-${index}`} style={{ fontSize: 11, color: 'var(--color-text-secondary)', lineHeight: 1.45 }}>
                <span style={{
                  display: 'inline-block',
                  minWidth: 40,
                  marginRight: 6,
                  color: item.level === 'error' ? 'var(--color-danger)' : item.level === 'warn' ? 'var(--color-warning)' : 'var(--color-primary)',
                  fontWeight: 700,
                  textTransform: 'uppercase',
                }}>
                  {item.level}
                </span>
                <span style={{ color: 'var(--color-text-muted)', marginRight: 6 }}>
                  {new Date(item.at).toLocaleTimeString()}
                </span>
                <span>{item.text}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
