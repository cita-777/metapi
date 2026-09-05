import { useEffect, useRef, useState, type CSSProperties } from 'react';

import { api, type UpdateCenterConfig, type UpdateCenterStatus } from '../../api.js';
import { useToast } from '../../components/Toast.js';
import { useIsMobile } from '../../components/useIsMobile.js';
import { buildUpdateReminder, describeUpdateState } from '../helpers/updateCenterPresentation.js';

const DEFAULT_CONFIG: UpdateCenterConfig = {
  enabled: false,
  channel: 'stable',
  autoCheck: false,
};

const panelStyle: CSSProperties = {
  border: '1px solid var(--color-border-light)',
  borderRadius: 'var(--radius-md)',
  padding: 14,
  background: 'var(--color-bg)',
};

const labelStyle: CSSProperties = {
  fontSize: 12,
  color: 'var(--color-text-muted)',
  marginBottom: 6,
};

const valueStyle: CSSProperties = {
  fontSize: 14,
  fontWeight: 600,
  color: 'var(--color-text-primary)',
  lineHeight: 1.45,
};

const hintStyle: CSSProperties = {
  fontSize: 12,
  color: 'var(--color-text-muted)',
  lineHeight: 1.55,
};

function formatTime(value?: string | null): string {
  if (!value) return '暂无记录';
  const timestamp = Date.parse(value.includes(' ') ? `${value.replace(' ', 'T')}Z` : value);
  return Number.isFinite(timestamp)
    ? new Date(timestamp).toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
    : value;
}

function errorMessage(error: unknown): string {
  return error instanceof Error && error.message ? error.message : '更新中心请求失败';
}

function taskLabel(status?: string | null): string {
  switch (status) {
    case 'pending': return '排队中';
    case 'running': return '执行中';
    case 'succeeded': return '已完成';
    case 'failed': return '失败';
    default: return '空闲';
  }
}

export default function UpdateCenterSection() {
  const toast = useToast();
  const isMobile = useIsMobile();
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [checking, setChecking] = useState(false);
  const [working, setWorking] = useState(false);
  const [status, setStatus] = useState<UpdateCenterStatus | null>(null);
  const [config, setConfig] = useState<UpdateCenterConfig>(DEFAULT_CONFIG);
  const [logs, setLogs] = useState<string[]>([]);
  const [taskStatus, setTaskStatus] = useState('');
  const streamAbortRef = useRef<AbortController | null>(null);
  const pollTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const pollStopTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const mountedRef = useRef(false);
  const statusRequestRef = useRef<Promise<UpdateCenterStatus> | null>(null);
  const checkRequestRef = useRef<Promise<UpdateCenterStatus> | null>(null);
  const statusRequestSequenceRef = useRef(0);

  const stopPolling = () => {
    if (pollTimerRef.current) clearInterval(pollTimerRef.current);
    if (pollStopTimerRef.current) clearTimeout(pollStopTimerRef.current);
    pollTimerRef.current = null;
    pollStopTimerRef.current = null;
  };

  const applyStatus = (next: UpdateCenterStatus) => {
    if (!mountedRef.current) return;
    setStatus(next);
    setConfig(next.config || DEFAULT_CONFIG);
    if (next.updateState) setTaskStatus(next.updateState);
    if (!next.restartPending && !next.runningTask && ['idle', 'healthy', 'failed', 'rolled_back', 'unsupported'].includes(next.updateState)) {
      stopPolling();
    }
  };

  const loadStatus = async (showError = true) => {
    if (!mountedRef.current || statusRequestRef.current || checkRequestRef.current) return;
    const requestSequence = ++statusRequestSequenceRef.current;
    const request = Promise.resolve().then(() => api.getUpdateCenterStatus());
    statusRequestRef.current = request;
    try {
      const next = await request;
      if (!mountedRef.current || requestSequence !== statusRequestSequenceRef.current) return;
      applyStatus(next);
    } catch (error) {
      if (mountedRef.current && requestSequence === statusRequestSequenceRef.current && showError) {
        toast.error(errorMessage(error));
      }
    } finally {
      if (statusRequestRef.current === request) statusRequestRef.current = null;
      if (mountedRef.current && requestSequence === statusRequestSequenceRef.current) setLoading(false);
    }
  };

  useEffect(() => {
    mountedRef.current = true;
    void loadStatus();
    return () => {
      mountedRef.current = false;
      statusRequestSequenceRef.current += 1;
      statusRequestRef.current = null;
      checkRequestRef.current = null;
      streamAbortRef.current?.abort();
      stopPolling();
    };
  }, []);

  const checkNow = async () => {
    if (!mountedRef.current || checkRequestRef.current) return;
    setChecking(true);
    const requestSequence = ++statusRequestSequenceRef.current;
    const request = Promise.resolve().then(() => api.checkUpdateCenter()) as Promise<UpdateCenterStatus>;
    checkRequestRef.current = request;
    try {
      const next = await request;
      if (!mountedRef.current || requestSequence !== statusRequestSequenceRef.current) return;
      applyStatus(next);
      toast.success('已刷新官方 Release 信息');
    } catch (error) {
      if (mountedRef.current && requestSequence === statusRequestSequenceRef.current) toast.error(errorMessage(error));
    } finally {
      if (checkRequestRef.current === request) checkRequestRef.current = null;
      if (mountedRef.current && requestSequence === statusRequestSequenceRef.current) {
        setChecking(false);
        setLoading(false);
      }
    }
  };

  const saveConfig = async () => {
    if (!mountedRef.current) return;
    setSaving(true);
    try {
      const response = await api.saveUpdateCenterConfig(config) as { config?: UpdateCenterConfig };
      if (!mountedRef.current) return;
      const nextConfig = response.config || config;
      setConfig(nextConfig);
      setStatus((previous) => previous ? { ...previous, config: nextConfig } : previous);
      toast.success('更新中心配置已保存');
    } catch (error) {
      toast.error(errorMessage(error));
    } finally {
      if (mountedRef.current) setSaving(false);
    }
  };

  const pollUntilSettled = () => {
    if (!mountedRef.current) return;
    stopPolling();
    pollTimerRef.current = setInterval(() => {
      void loadStatus(false);
    }, 2_000);
    pollStopTimerRef.current = setTimeout(() => {
      if (pollTimerRef.current) {
        clearInterval(pollTimerRef.current);
        pollTimerRef.current = null;
      }
      pollStopTimerRef.current = null;
    }, 70_000);
  };

  const runTask = async (kind: 'update' | 'rollback', targetVersion: string) => {
    if (!targetVersion || working || !mountedRef.current) return;
    setWorking(true);
    setLogs([]);
    setTaskStatus('running');
    streamAbortRef.current?.abort();
    const controller = new AbortController();
    streamAbortRef.current = controller;
    let taskId = '';
    try {
      const response = kind === 'update'
        ? await api.deployUpdateCenter({ targetVersion }) as { task?: { id?: string } }
        : await api.rollbackUpdateCenter({ targetVersion }) as { task?: { id?: string } };
      taskId = String(response.task?.id || '').trim();
      if (!taskId) throw new Error('服务器未返回任务编号');
      await api.streamUpdateCenterTaskLogs(taskId, {
        signal: controller.signal,
        onLog: (entry) => {
          if (!mountedRef.current || controller.signal.aborted) return;
          const message = String(entry?.message || '').trim();
          if (message) setLogs((previous) => [...previous, message].slice(-200));
        },
        onDone: (payload) => {
          if (mountedRef.current && !controller.signal.aborted) setTaskStatus(String(payload?.status || 'unknown'));
        },
      });
    } catch (error) {
      if (!mountedRef.current) return;
      if (taskId) {
        try {
          const snapshot = await api.getTask(taskId) as { task?: { status?: string; logs?: Array<{ message?: string }> } };
          if (snapshot.task) {
            setTaskStatus(String(snapshot.task.status || 'unknown'));
            setLogs((snapshot.task.logs || []).map((entry) => String(entry.message || '')).filter(Boolean));
          }
        } catch {
          toast.error(errorMessage(error));
        }
      } else if (!(error instanceof DOMException && error.name === 'AbortError')) {
        toast.error(errorMessage(error));
      }
    } finally {
      if (streamAbortRef.current === controller) streamAbortRef.current = null;
      if (mountedRef.current) {
        setWorking(false);
        if (taskId) pollUntilSettled();
        void loadStatus(false);
      }
    }
  };

  const latest = status?.latestRelease || null;
  const updateState = describeUpdateState({
    enabled: config.enabled,
    supported: !!status?.supported,
    reason: status?.reason,
    currentVersion: status?.currentVersion,
    candidate: latest,
  });
  const reminder = buildUpdateReminder({ currentVersion: status?.currentVersion, latestRelease: latest });
  const runningTask = status?.runningTask;
  const visibleTaskStatus = taskStatus || status?.updateState || runningTask?.status || 'idle';
  const installedVersions = Array.isArray(status?.installedVersions) ? status.installedVersions : [];
  const canUpdate = !working && !!status?.canUpdate && updateState.canDeploy;
  const canRollback = !working && !!status?.canRollback;

  if (loading) {
    return (
      <div className="card" style={{ padding: 20 }}>
        <div style={{ fontWeight: 600, fontSize: 14 }}>更新中心</div>
        <div style={{ ...hintStyle, marginTop: 6 }}>正在读取本地运行时状态...</div>
      </div>
    );
  }

  return (
    <div className="card" style={{ padding: 20 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, flexWrap: 'wrap', marginBottom: 6 }}>
        <div style={{ fontWeight: 600, fontSize: 14 }}>更新中心</div>
        <span className={`${reminder.badgeClassName} ${reminder.highlight ? 'stat-value-glow' : ''}`.trim()}>{reminder.label}</span>
      </div>
      <div style={{ ...hintStyle, marginBottom: 14 }}>{reminder.detail}</div>

      <div style={{ display: 'grid', gridTemplateColumns: isMobile ? '1fr' : 'repeat(3, minmax(0, 1fr))', gap: 12, marginBottom: 12 }}>
        <div style={panelStyle}>
          <div style={labelStyle}>当前版本</div>
          <div style={{ ...valueStyle, fontFamily: 'var(--font-mono)' }}>{status?.currentVersion || '-'}</div>
          <div style={hintStyle}>由当前运行目录的 manifest 决定。</div>
        </div>
        <div style={panelStyle}>
          <div style={labelStyle}>最新稳定 Release</div>
          <div style={{ ...valueStyle, fontFamily: 'var(--font-mono)' }}>{latest?.displayVersion || latest?.normalizedVersion || '尚未检查'}</div>
          <div style={hintStyle}>{latest?.publishedAt ? `发布于 ${formatTime(latest.publishedAt)}` : '来源固定为 Metapi 官方 GitHub 仓库。'}</div>
        </div>
        <div style={panelStyle}>
          <div style={labelStyle}>运行时能力</div>
          <div style={{ marginBottom: 4 }}><span className={status?.supported ? 'badge badge-success' : 'badge badge-warning'}>{status?.supported ? '支持一键升级' : '暂不支持'}</span></div>
          <div style={hintStyle}>{status?.reason || `模式：${status?.mode || 'local-bundle'}`}</div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: isMobile ? '1fr' : 'repeat(3, minmax(0, 1fr))', gap: 12, marginBottom: 12 }}>
        <label style={{ ...panelStyle, display: 'flex', gap: 10, alignItems: 'flex-start', cursor: 'pointer' }}>
          <input type="checkbox" checked={config.enabled} onChange={(event) => setConfig((previous) => ({ ...previous, enabled: event.target.checked }))} style={{ width: 16, height: 16, marginTop: 2, accentColor: 'var(--color-primary)' }} />
          <span style={{ display: 'grid', gap: 4 }}>
            <span style={{ fontSize: 13, fontWeight: 600 }}>启用应用内升级</span>
            <span style={hintStyle}>允许下载并切换官方服务器 Release。</span>
          </span>
        </label>
        <label style={{ ...panelStyle, display: 'flex', gap: 10, alignItems: 'flex-start', cursor: 'pointer' }}>
          <input type="checkbox" checked={config.autoCheck} onChange={(event) => setConfig((previous) => ({ ...previous, autoCheck: event.target.checked }))} style={{ width: 16, height: 16, marginTop: 2, accentColor: 'var(--color-primary)' }} />
          <span style={{ display: 'grid', gap: 4 }}>
            <span style={{ fontSize: 13, fontWeight: 600 }}>后台检查</span>
            <span style={hintStyle}>定期读取稳定 Release 并生成站内提醒。</span>
          </span>
        </label>
        <div style={panelStyle}>
          <div style={labelStyle}>更新通道</div>
          <div style={valueStyle}>Stable</div>
          <div style={hintStyle}>通道固定，避免从界面注入任意下载源。</div>
        </div>
      </div>

      <div style={{ ...panelStyle, marginBottom: 12 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10, flexWrap: 'wrap', marginBottom: 8 }}>
          <div style={{ fontWeight: 600, fontSize: 13 }}>操作</div>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <button type="button" className="btn btn-ghost" onClick={() => void checkNow()} disabled={checking}>{checking ? '检查中...' : '检查更新'}</button>
            <button type="button" className="btn btn-primary" onClick={() => latest?.normalizedVersion && void runTask('update', latest.normalizedVersion)} disabled={!canUpdate} title={updateState.reason}>一键升级</button>
            <button type="button" className="btn btn-ghost" onClick={saveConfig} disabled={saving}>{saving ? '保存中...' : '保存设置'}</button>
          </div>
        </div>
        <div style={{ ...hintStyle, marginBottom: 8 }}>{updateState.reason}</div>
        {status?.restartPending ? <div className="badge badge-warning">正在等待重启确认</div> : null}
      </div>

      <div style={{ ...panelStyle, marginBottom: 12 }}>
        <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 8 }}>已安装版本</div>
        {installedVersions.length ? (
          <div style={{ display: 'grid', gap: 8 }}>
            {installedVersions.map((entry) => (
              <div key={entry.version} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8, flexWrap: 'wrap', padding: 10, border: '1px solid var(--color-border-light)', borderRadius: 'var(--radius-sm)' }}>
                <div style={{ ...valueStyle, fontFamily: 'var(--font-mono)' }}>{entry.version}</div>
                <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>
                  {entry.current ? <span className="badge badge-info">当前</span> : null}
                  {entry.previous ? <span className="badge badge-muted">上一版本</span> : null}
                  {!entry.current ? <button type="button" className="btn btn-ghost" disabled={!canRollback} onClick={() => void runTask('rollback', entry.version)}>回滚</button> : null}
                </div>
              </div>
            ))}
          </div>
        ) : <div style={hintStyle}>暂无可回滚版本。</div>}
      </div>

      <div style={panelStyle}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8, marginBottom: 8 }}>
          <div style={{ fontWeight: 600, fontSize: 13 }}>任务日志</div>
          <span className="badge badge-muted">{taskLabel(visibleTaskStatus)}</span>
        </div>
        <div style={{ ...hintStyle, marginBottom: 8 }}>进程重启后，状态文件会继续提供最终结果。</div>
        <div style={{ minHeight: 100, border: '1px solid var(--color-border-light)', borderRadius: 'var(--radius-sm)', background: 'var(--color-bg-card)', padding: 12 }}>
          {logs.length ? <pre style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-word', fontSize: 12, lineHeight: 1.6, color: 'var(--color-text-secondary)', fontFamily: 'var(--font-mono)' }}>{logs.join('\n')}</pre> : <div style={{ ...hintStyle, minHeight: 76, display: 'flex', alignItems: 'center' }}>开始操作后，这里会显示下载、校验、切换与健康检查阶段。</div>}
        </div>
        {status?.lastError ? <div style={{ color: 'var(--color-danger)', ...hintStyle, marginTop: 8 }}>最近错误：{status.lastError}</div> : null}
        {status?.lastFinishedTask?.finishedAt ? <div style={{ ...hintStyle, marginTop: 8 }}>最近完成：{formatTime(status.lastFinishedTask.finishedAt)}</div> : null}
      </div>
    </div>
  );
}
