import React, { useEffect, useRef, useState, type CSSProperties } from 'react';

import { api } from '../../api.js';
import ModernSelect from '../../components/ModernSelect.js';
import { useToast } from '../../components/Toast.js';
import { useIsMobile } from '../../components/useIsMobile.js';
import {
  buildUpdateReminder,
  describeDockerDeployState,
  describeGitHubDeployState,
} from '../helpers/updateCenterPresentation.js';
import UpdateCenterHistoryModal from './UpdateCenterHistoryModal.js';
import UpdateCenterHistoryEntryCard from './UpdateCenterHistoryEntryCard.js';

type UpdateCenterStatus = {
  currentVersion?: string;
  config?: {
    enabled: boolean;
    helperBaseUrl: string;
    namespace: string;
    releaseName: string;
    chartRef: string;
    imageRepository: string;
    githubReleasesEnabled: boolean;
    dockerHubTagsEnabled: boolean;
    defaultDeploySource: 'github-release' | 'docker-hub-tag';
  };
  githubRelease?: {
    normalizedVersion?: string;
    displayVersion?: string;
    tagName?: string;
    digest?: string | null;
    publishedAt?: string | null;
  } | null;
  dockerHubTag?: {
    normalizedVersion?: string;
    displayVersion?: string;
    tagName?: string;
    digest?: string | null;
    publishedAt?: string | null;
  } | null;
  dockerHubRecentTags?: Array<{
    normalizedVersion?: string;
    displayVersion?: string;
    tagName?: string;
    digest?: string | null;
    publishedAt?: string | null;
  }> | null;
  helper?: {
    ok?: boolean;
    healthy?: boolean;
    error?: string | null;
    revision?: string | null;
    imageTag?: string | null;
    imageDigest?: string | null;
    history?: Array<{
      revision?: string;
      updatedAt?: string | null;
      status?: string | null;
      description?: string | null;
      imageRepository?: string | null;
      imageTag?: string | null;
      imageDigest?: string | null;
    }>;
  } | null;
  runningTask?: {
    id?: string;
    status?: string;
  } | null;
  lastFinishedTask?: {
    id?: string;
    status?: string;
    finishedAt?: string | null;
  } | null;
  runtime?: {
    lastCheckedAt?: string | null;
    lastCheckError?: string | null;
    lastResolvedSource?: 'github-release' | 'docker-hub-tag' | null;
    lastResolvedDisplayVersion?: string | null;
    lastResolvedCandidateKey?: string | null;
    lastNotifiedCandidateKey?: string | null;
    lastNotifiedAt?: string | null;
  } | null;
};

const DEFAULT_CONFIG: NonNullable<UpdateCenterStatus['config']> = {
  enabled: false,
  helperBaseUrl: '',
  namespace: 'default',
  releaseName: '',
  chartRef: '',
  imageRepository: '1467078763/metapi',
  githubReleasesEnabled: true,
  dockerHubTagsEnabled: true,
  defaultDeploySource: 'github-release',
};

const DEPLOY_SOURCE_OPTIONS = [
  {
    value: 'github-release',
    label: 'GitHub Releases',
    description: '优先跟踪仓库稳定版 release。',
  },
  {
    value: 'docker-hub-tag',
    label: 'Docker Hub Tags',
    description: '适合直接跟随镜像标签推进部署。',
  },
] as const;

const inputStyle: CSSProperties = {
  width: '100%',
  padding: '10px 14px',
  border: '1px solid var(--color-border)',
  borderRadius: 'var(--radius-sm)',
  fontSize: 13,
  outline: 'none',
  background: 'var(--color-bg)',
  color: 'var(--color-text-primary)',
};

const sectionPanelStyle: CSSProperties = {
  border: '1px solid var(--color-border-light)',
  borderRadius: 'var(--radius-md)',
  padding: 14,
  background: 'var(--color-bg)',
};

const summaryLabelStyle: CSSProperties = {
  fontSize: 12,
  color: 'var(--color-text-muted)',
  marginBottom: 6,
};

const summaryValueStyle: CSSProperties = {
  fontSize: 14,
  fontWeight: 600,
  color: 'var(--color-text-primary)',
  lineHeight: 1.4,
};

const fieldLabelStyle: CSSProperties = {
  fontSize: 12,
  color: 'var(--color-text-muted)',
  marginBottom: 6,
};

const fieldHintStyle: CSSProperties = {
  fontSize: 12,
  color: 'var(--color-text-muted)',
  lineHeight: 1.5,
};

function formatTaskTime(value?: string | null) {
  if (!value) return '暂无完成记录';
  const normalizedValue = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(value)
    ? `${value.replace(' ', 'T')}Z`
    : value;
  const timestamp = Date.parse(normalizedValue);
  if (!Number.isFinite(timestamp)) return value;
  return new Date(timestamp).toLocaleString('zh-CN', {
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function getTaskBadge(status?: string | null) {
  switch (status) {
    case 'running':
      return { className: 'badge badge-info', label: '进行中' };
    case 'pending':
      return { className: 'badge badge-warning', label: '排队中' };
    case 'succeeded':
      return { className: 'badge badge-success', label: '已完成' };
    case 'failed':
      return { className: 'badge badge-error', label: '失败' };
    default:
      return { className: 'badge badge-muted', label: '空闲' };
  }
}

function getHelperBadge(helper?: UpdateCenterStatus['helper'] | null, helperBaseUrl?: string) {
  if (!helperBaseUrl) {
    return { className: 'badge badge-muted', label: '未配置' };
  }
  if (helper?.healthy) {
    return { className: 'badge badge-success', label: 'Healthy' };
  }
  if (helper?.ok) {
    return { className: 'badge badge-warning', label: '可达但未就绪' };
  }
  return { className: 'badge badge-error', label: '不可用' };
}

function getSourceBadge(enabled: boolean, version?: string) {
  if (!enabled) {
    return { className: 'badge badge-muted', label: '已停用' };
  }
  if (version) {
    return { className: 'badge badge-success', label: '可部署' };
  }
  return { className: 'badge badge-warning', label: '未发现版本' };
}

function formatShortDigest(digest?: string | null) {
  const value = String(digest || '').trim();
  if (!value) return '';
  return value.slice(0, 'sha256:'.length + 12);
}

function formatImageTarget(tag?: string | null, digest?: string | null) {
  const normalizedTag = String(tag || '').trim();
  const shortDigest = formatShortDigest(digest);
  if (normalizedTag && shortDigest) {
    return `${normalizedTag} @ ${shortDigest}`;
  }
  if (normalizedTag) return normalizedTag;
  if (shortDigest) return shortDigest;
  return '';
}

type RecentDockerCandidate = NonNullable<NonNullable<UpdateCenterStatus['dockerHubRecentTags']>[number]>;

function normalizeRecentDockerCandidates(
  input?: UpdateCenterStatus['dockerHubRecentTags'] | null,
): Array<RecentDockerCandidate & { tagName: string }> {
  if (!Array.isArray(input)) return [];
  return input.filter(
    (entry): entry is RecentDockerCandidate & { tagName: string } => !!String(entry?.tagName || '').trim(),
  );
}

export default function UpdateCenterSection() {
  const toast = useToast();
  const isMobile = useIsMobile();
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [checking, setChecking] = useState(false);
  const [deploying, setDeploying] = useState(false);
  const [status, setStatus] = useState<UpdateCenterStatus | null>(null);
  const [config, setConfig] = useState(DEFAULT_CONFIG);
  const [manualDockerTarget, setManualDockerTarget] = useState({
    tag: '',
    digest: '',
  });
  const [logs, setLogs] = useState<string[]>([]);
  const [taskStatus, setTaskStatus] = useState('');
  const [historyModalOpen, setHistoryModalOpen] = useState(false);
  const streamAbortRef = useRef<AbortController | null>(null);

  const applyStatus = (next: UpdateCenterStatus) => {
    setStatus(next);
    setConfig(next.config || DEFAULT_CONFIG);
  };

  const loadStatus = async () => {
    setLoading(true);
    try {
      const next = await api.getUpdateCenterStatus() as UpdateCenterStatus;
      applyStatus(next);
    } catch (error: any) {
      toast.error(error?.message || '加载更新中心失败');
    } finally {
      setLoading(false);
    }
  };

  const refreshStatus = async (showErrorToast = true) => {
    try {
      const next = await api.checkUpdateCenter() as UpdateCenterStatus;
      applyStatus(next);
      return next;
    } catch (error: any) {
      if (showErrorToast) {
        toast.error(error?.message || '检查更新失败');
      }
      throw error;
    }
  };

  useEffect(() => {
    void loadStatus();
    return () => {
      streamAbortRef.current?.abort();
    };
  }, []);

  const saveConfig = async () => {
    setSaving(true);
    try {
      const result = await api.saveUpdateCenterConfig(config) as { config?: UpdateCenterStatus['config'] };
      const nextConfig = result.config || config;
      setConfig(nextConfig);
      setStatus((prev) => ({
        ...(prev || {}),
        config: nextConfig,
      }));
      toast.success('更新中心配置已保存');
    } catch (error: any) {
      toast.error(error?.message || '保存更新中心配置失败');
    } finally {
      setSaving(false);
    }
  };

  const checkNow = async () => {
    setChecking(true);
    try {
      await refreshStatus(true);
      toast.success('已刷新更新信息');
    } catch {
      // refreshStatus already handled the toast
    } finally {
      setChecking(false);
    }
  };

  const streamTaskLogs = async (taskId: string) => {
    await api.streamUpdateCenterTaskLogs(taskId, {
      signal: streamAbortRef.current?.signal,
      onLog: (entry) => {
        const message = String(entry?.message || '').trim();
        if (!message) return;
        setLogs((prev) => [...prev, message].slice(-200));
      },
      onDone: (payload) => {
        setTaskStatus(String(payload?.status || 'unknown'));
      },
    });
  };

  const hydrateTaskSnapshot = async (taskId: string) => {
    const taskResponse = await api.getTask(taskId) as { task?: { status?: string; logs?: Array<{ message?: string }> } };
    const task = taskResponse.task;
    if (!task) return false;
    setTaskStatus(String(task.status || 'unknown'));
    setLogs(Array.isArray(task.logs) ? task.logs.map((entry) => String(entry?.message || '')).filter(Boolean) : []);
    toast.info('实时日志流已断开，已回退到任务详情快照');
    return true;
  };

  const runDeploy = async (
    source: 'github-release' | 'docker-hub-tag',
    target: { tag?: string | null; digest?: string | null },
  ) => {
    const targetTag = String(target.tag || '').trim();
    if (!targetTag) return;
    setDeploying(true);
    setLogs([]);
    setTaskStatus('running');
    streamAbortRef.current?.abort();
    streamAbortRef.current = new AbortController();
    let taskId = '';

    try {
      const response = await api.deployUpdateCenter({
        source,
        targetTag,
        targetDigest: target.digest || null,
      }) as { task?: { id: string } };
      taskId = response.task?.id || '';
      if (!taskId) {
        throw new Error('部署任务未返回 taskId');
      }

      await streamTaskLogs(taskId);
    } catch (error: any) {
      if (taskId) {
        try {
          if (await hydrateTaskSnapshot(taskId)) {
            return;
          }
        } catch {
          // fall through to the generic error state
        }
      }
      setTaskStatus('failed');
      toast.error(error?.message || '部署失败');
    } finally {
      setDeploying(false);
      void refreshStatus(false).catch(() => {});
    }
  };

  const runRollback = async (targetRevision: string) => {
    if (!targetRevision) return;
    setDeploying(true);
    setLogs([]);
    setTaskStatus('running');
    streamAbortRef.current?.abort();
    streamAbortRef.current = new AbortController();
    let taskId = '';

    try {
      const response = await api.rollbackUpdateCenter({ targetRevision }) as { task?: { id: string } };
      taskId = response.task?.id || '';
      if (!taskId) {
        throw new Error('回退任务未返回 taskId');
      }

      await streamTaskLogs(taskId);
    } catch (error: any) {
      if (taskId) {
        try {
          if (await hydrateTaskSnapshot(taskId)) {
            return;
          }
        } catch {
          // fall through to the generic error state
        }
      }
      setTaskStatus('failed');
      toast.error(error?.message || '回退失败');
    } finally {
      setDeploying(false);
      void refreshStatus(false).catch(() => {});
    }
  };

  const helperHealthy = !!status?.helper?.healthy;
  const helperBadge = getHelperBadge(status?.helper, config.helperBaseUrl);
  const runningTaskBadge = getTaskBadge(status?.runningTask?.status || taskStatus || undefined);
  const lastFinishedTaskBadge = getTaskBadge(status?.lastFinishedTask?.status || undefined);
  const visibleTaskStatus = taskStatus || status?.runningTask?.status || status?.lastFinishedTask?.status || 'idle';
  const githubDeployState = describeGitHubDeployState({
    enabled: config.enabled && config.githubReleasesEnabled,
    helperHealthy,
    helperError: status?.helper?.error,
    currentVersion: status?.currentVersion,
    helperImageTag: status?.helper?.imageTag,
    candidate: status?.githubRelease,
  });
  const dockerDeployState = describeDockerDeployState({
    enabled: config.enabled && config.dockerHubTagsEnabled,
    helperHealthy,
    helperError: status?.helper?.error,
    currentVersion: status?.currentVersion,
    helper: status?.helper,
    candidate: status?.dockerHubTag,
  });
  const updateReminder = buildUpdateReminder({
    currentVersion: status?.currentVersion,
    helper: status?.helper,
    githubRelease: status?.githubRelease,
    dockerHubTag: status?.dockerHubTag,
  });
  const canDeployGithub = !deploying && githubDeployState.canDeploy;
  const canDeployDocker = !deploying && dockerDeployState.canDeploy;
  const manualDockerTag = String(manualDockerTarget.tag || '').trim();
  const manualDockerDigest = String(manualDockerTarget.digest || '').trim();
  const recentDockerCandidates = normalizeRecentDockerCandidates(status?.dockerHubRecentTags);
  const canDeployManualDocker = !deploying
    && config.enabled
    && config.dockerHubTagsEnabled
    && helperHealthy
    && !!manualDockerTag;
  const helperHistory = Array.isArray(status?.helper?.history) ? status.helper.history : [];
  const historyPreview = helperHistory.slice(0, 2);
  const currentRevision = String(status?.helper?.revision || '').trim();
  const runtimeStatus = status?.runtime || null;

  if (loading) {
    return (
      <div className="card" style={{ padding: 20 }}>
        <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 6 }}>更新中心</div>
        <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>
          正在加载部署来源、版本状态和 helper 健康检查...
        </div>
      </div>
    );
  }

  return (
    <div className="card" style={{ padding: 20 }}>
      <div style={{ marginBottom: 14 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, flexWrap: 'wrap', marginBottom: 6 }}>
          <div style={{ fontWeight: 600, fontSize: 14 }}>更新中心</div>
          <span className={`${updateReminder.badgeClassName} ${updateReminder.highlight ? 'stat-value-glow' : ''}`.trim()}>
            {updateReminder.label}
          </span>
        </div>
        <div style={{ fontSize: 12, color: 'var(--color-text-muted)', lineHeight: 1.55 }}>
          在设置页里统一查看 GitHub Releases、Docker Hub 版本和 K3s helper 状态，避免部署信息散落在多个入口。
        </div>
        <div style={{ fontSize: 12, color: 'var(--color-text-secondary)', lineHeight: 1.5, marginTop: 6 }}>
          {updateReminder.detail}
        </div>
      </div>

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: isMobile ? '1fr' : 'repeat(2, minmax(0, 1fr))',
          gap: 12,
          marginBottom: 12,
        }}
      >
        <div style={sectionPanelStyle}>
          <div style={summaryLabelStyle}>当前运行版本</div>
          <div style={{ ...summaryValueStyle, fontFamily: 'var(--font-mono)' }}>
            {status?.currentVersion || '-'}
          </div>
          <div style={fieldHintStyle}>以当前容器内运行版本为准。</div>
        </div>
        <div style={sectionPanelStyle}>
          <div style={summaryLabelStyle}>Deploy Helper</div>
          <div style={{ marginBottom: 6 }}>
            <span className={helperBadge.className}>{helperBadge.label}</span>
          </div>
          <div style={{ ...fieldHintStyle, fontFamily: config.helperBaseUrl ? 'var(--font-mono)' : 'inherit' }}>
            {config.helperBaseUrl || '尚未配置 Helper URL'}
          </div>
        </div>
        <div style={sectionPanelStyle}>
          <div style={summaryLabelStyle}>默认部署来源</div>
          <div style={summaryValueStyle}>
            {DEPLOY_SOURCE_OPTIONS.find((item) => item.value === config.defaultDeploySource)?.label || 'GitHub Releases'}
          </div>
          <div style={fieldHintStyle}>保存配置后，手动部署默认优先使用这里的来源。</div>
        </div>
        <div style={sectionPanelStyle}>
          <div style={summaryLabelStyle}>最近任务</div>
          <div style={{ marginBottom: 6 }}>
            <span className={status?.runningTask ? runningTaskBadge.className : lastFinishedTaskBadge.className}>
              {status?.runningTask ? `运行中 · ${runningTaskBadge.label}` : lastFinishedTaskBadge.label}
            </span>
          </div>
          <div style={fieldHintStyle}>
            {status?.runningTask?.id
              ? `任务 ID: ${status.runningTask.id}`
              : formatTaskTime(status?.lastFinishedTask?.finishedAt)}
          </div>
        </div>
        <div style={sectionPanelStyle}>
          <div style={summaryLabelStyle}>后台检查</div>
          <div style={summaryValueStyle}>
            {runtimeStatus?.lastCheckedAt ? formatTaskTime(runtimeStatus.lastCheckedAt) : '尚无检查记录'}
          </div>
          <div style={fieldHintStyle}>
            {runtimeStatus?.lastCheckError
              ? `最近错误：${runtimeStatus.lastCheckError}`
              : runtimeStatus?.lastResolvedDisplayVersion
                ? `最近发现：${runtimeStatus.lastResolvedDisplayVersion}`
                : '后台会定时检查新版本，并在首次发现时提醒一次。'}
          </div>
        </div>
      </div>

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: isMobile ? '1fr' : 'repeat(3, minmax(0, 1fr))',
          gap: 12,
          marginBottom: 12,
        }}
      >
        <label style={{ ...sectionPanelStyle, display: 'flex', gap: 10, alignItems: 'flex-start', cursor: 'pointer' }}>
          <input
            type="checkbox"
            checked={config.enabled}
            onChange={(e) => setConfig((prev) => ({ ...prev, enabled: e.target.checked }))}
            style={{ width: 16, height: 16, marginTop: 2, accentColor: 'var(--color-primary)' }}
          />
          <span style={{ display: 'grid', gap: 4 }}>
            <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--color-text-primary)' }}>启用更新中心</span>
            <span style={fieldHintStyle}>允许通过本页触发 K3s 部署。后台版本提醒会按已启用来源持续检查。</span>
          </span>
        </label>
        <label style={{ ...sectionPanelStyle, display: 'flex', gap: 10, alignItems: 'flex-start', cursor: 'pointer' }}>
          <input
            type="checkbox"
            checked={config.githubReleasesEnabled}
            onChange={(e) => setConfig((prev) => ({ ...prev, githubReleasesEnabled: e.target.checked }))}
            style={{ width: 16, height: 16, marginTop: 2, accentColor: 'var(--color-primary)' }}
          />
          <span style={{ display: 'grid', gap: 4 }}>
            <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--color-text-primary)' }}>GitHub Releases</span>
            <span style={fieldHintStyle}>从仓库稳定版 release 提取 SemVer 版本号并提供部署入口。</span>
          </span>
        </label>
        <label style={{ ...sectionPanelStyle, display: 'flex', gap: 10, alignItems: 'flex-start', cursor: 'pointer' }}>
          <input
            type="checkbox"
            checked={config.dockerHubTagsEnabled}
            onChange={(e) => setConfig((prev) => ({ ...prev, dockerHubTagsEnabled: e.target.checked }))}
            style={{ width: 16, height: 16, marginTop: 2, accentColor: 'var(--color-primary)' }}
          />
          <span style={{ display: 'grid', gap: 4 }}>
            <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--color-text-primary)' }}>Docker Hub</span>
            <span style={fieldHintStyle}>自动发现会保留稳定主候选，并额外列出最近的 dev / 分支 / sha 标签。</span>
          </span>
        </label>
      </div>

      <div style={{ ...sectionPanelStyle, marginBottom: 12 }}>
        <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 6 }}>部署配置</div>
        <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginBottom: 12 }}>
          和现有 Settings 区块保持同一套表单密度。这里保存的是 helper 和目标 release 的持久化配置。
        </div>

        <div
          style={{
            display: 'grid',
            gridTemplateColumns: isMobile ? '1fr' : 'repeat(2, minmax(0, 1fr))',
            gap: 12,
            marginBottom: 12,
          }}
        >
          <label>
            <div style={fieldLabelStyle}>Deploy Helper URL</div>
            <input
              value={config.helperBaseUrl}
              onChange={(e) => setConfig((prev) => ({ ...prev, helperBaseUrl: e.target.value }))}
              style={{ ...inputStyle, fontFamily: 'var(--font-mono)' }}
              placeholder="http://metapi-deploy-helper.namespace.svc.cluster.local:9850"
            />
          </label>
          <label>
            <div style={fieldLabelStyle}>默认部署来源</div>
            <ModernSelect
              value={config.defaultDeploySource}
              onChange={(value) => setConfig((prev) => ({
                ...prev,
                defaultDeploySource: value === 'docker-hub-tag' ? 'docker-hub-tag' : 'github-release',
              }))}
              options={DEPLOY_SOURCE_OPTIONS.map((item) => ({ ...item }))}
            />
          </label>
          <label>
            <div style={fieldLabelStyle}>Namespace</div>
            <input
              value={config.namespace}
              onChange={(e) => setConfig((prev) => ({ ...prev, namespace: e.target.value }))}
              style={inputStyle}
              placeholder="default"
            />
          </label>
          <label>
            <div style={fieldLabelStyle}>Release Name</div>
            <input
              value={config.releaseName}
              onChange={(e) => setConfig((prev) => ({ ...prev, releaseName: e.target.value }))}
              style={inputStyle}
              placeholder="metapi"
            />
          </label>
          <label>
            <div style={fieldLabelStyle}>Chart Ref</div>
            <input
              value={config.chartRef}
              onChange={(e) => setConfig((prev) => ({ ...prev, chartRef: e.target.value }))}
              style={{ ...inputStyle, fontFamily: 'var(--font-mono)' }}
              placeholder="oci://ghcr.io/cita-777/charts/metapi"
            />
          </label>
          <label>
            <div style={fieldLabelStyle}>Image Repository</div>
            <input
              value={config.imageRepository}
              onChange={(e) => setConfig((prev) => ({ ...prev, imageRepository: e.target.value }))}
              style={{ ...inputStyle, fontFamily: 'var(--font-mono)' }}
              placeholder="1467078763/metapi"
            />
          </label>
        </div>

        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <button type="button" onClick={saveConfig} disabled={saving} className="btn btn-primary">
            {saving ? '保存中...' : '保存更新中心配置'}
          </button>
          <button
            type="button"
            onClick={checkNow}
            disabled={checking}
            className="btn btn-ghost"
            style={{ border: '1px solid var(--color-border)' }}
          >
            {checking ? '检查中...' : '检查更新'}
          </button>
        </div>
      </div>

      <div style={{ ...sectionPanelStyle, marginBottom: 12 }}>
        <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 6 }}>可部署版本</div>
        <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginBottom: 12 }}>
          默认来源会用主按钮强调。Helper 未就绪时，部署入口会自动禁用，避免触发无效任务。
        </div>

        <div
          style={{
            display: 'grid',
            gridTemplateColumns: isMobile ? '1fr' : 'repeat(2, minmax(0, 1fr))',
            gap: 12,
            marginBottom: 12,
          }}
        >
          <div style={sectionPanelStyle}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, marginBottom: 10, flexWrap: 'wrap' }}>
              <div style={{ fontSize: 13, fontWeight: 600 }}>GitHub Releases</div>
              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                <span className={getSourceBadge(config.githubReleasesEnabled, status?.githubRelease?.normalizedVersion).className}>
                  {getSourceBadge(config.githubReleasesEnabled, status?.githubRelease?.normalizedVersion).label}
                </span>
                <span className={`${githubDeployState.badgeClassName} ${githubDeployState.highlight ? 'stat-value-glow' : ''}`.trim()}>
                  {githubDeployState.badgeLabel}
                </span>
                {config.defaultDeploySource === 'github-release' ? (
                  <span className="badge badge-info">默认来源</span>
                ) : null}
              </div>
            </div>
            <div style={{ ...fieldHintStyle, marginBottom: 10 }}>优先使用仓库稳定版 release，适合保留语义化版本节奏。</div>
            <div className={githubDeployState.highlight ? 'stat-value-glow' : ''} style={{ ...summaryValueStyle, fontFamily: 'var(--font-mono)', marginBottom: 8 }}>
              {status?.githubRelease?.displayVersion || status?.githubRelease?.normalizedVersion || '未发现'}
            </div>
            <div style={{ ...fieldHintStyle, marginBottom: 12 }}>
              {githubDeployState.reason}
            </div>
            <button
              type="button"
              onClick={() => {
                if (!helperHealthy) return;
                void runDeploy('github-release', {
                  tag: status?.githubRelease?.tagName || status?.githubRelease?.normalizedVersion || '',
                  digest: null,
                });
              }}
              disabled={!canDeployGithub}
              className={config.defaultDeploySource === 'github-release' ? 'btn btn-primary' : 'btn btn-ghost'}
              style={config.defaultDeploySource === 'github-release' ? undefined : { border: '1px solid var(--color-border)' }}
            >
              部署 GitHub 稳定版
            </button>
          </div>

          <div style={sectionPanelStyle}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, marginBottom: 10, flexWrap: 'wrap' }}>
              <div style={{ fontSize: 13, fontWeight: 600 }}>Docker Hub</div>
              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                <span className={getSourceBadge(config.dockerHubTagsEnabled, status?.dockerHubTag?.normalizedVersion).className}>
                  {getSourceBadge(config.dockerHubTagsEnabled, status?.dockerHubTag?.normalizedVersion).label}
                </span>
                <span className={`${dockerDeployState.badgeClassName} ${dockerDeployState.highlight ? 'stat-value-glow' : ''}`.trim()}>
                  {dockerDeployState.badgeLabel}
                </span>
                {config.defaultDeploySource === 'docker-hub-tag' ? (
                  <span className="badge badge-info">默认来源</span>
                ) : null}
              </div>
            </div>
            <div style={{ ...fieldHintStyle, marginBottom: 10 }}>主候选优先 latest / main / 稳定 SemVer；下方还会自动列出最近的 dev / 分支 / sha 标签。</div>
            <div className={dockerDeployState.highlight ? 'stat-value-glow' : ''} style={{ ...summaryValueStyle, fontFamily: 'var(--font-mono)', marginBottom: 8 }}>
              {status?.dockerHubTag?.displayVersion || status?.dockerHubTag?.normalizedVersion || '未发现'}
            </div>
            <div style={{ ...fieldHintStyle, marginBottom: 12 }}>
              {dockerDeployState.reason}
            </div>
            <div style={{ ...fieldHintStyle, marginBottom: 12 }}>
              最近推送：{formatTaskTime(status?.dockerHubTag?.publishedAt)}
            </div>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 12 }}>
              <button
                type="button"
                onClick={() => {
                  if (!helperHealthy) return;
                  void runDeploy('docker-hub-tag', {
                    tag: status?.dockerHubTag?.tagName || status?.dockerHubTag?.normalizedVersion || '',
                    digest: status?.dockerHubTag?.digest || null,
                  });
                }}
                disabled={!canDeployDocker}
                className={config.defaultDeploySource === 'docker-hub-tag' ? 'btn btn-primary' : 'btn btn-ghost'}
                style={config.defaultDeploySource === 'docker-hub-tag' ? undefined : { border: '1px solid var(--color-border)' }}
              >
                部署 Docker Hub 标签
              </button>
              {status?.dockerHubTag?.tagName ? (
                <button
                  type="button"
                  className="btn btn-ghost"
                  style={{ border: '1px solid var(--color-border)' }}
                  onClick={() => {
                    setManualDockerTarget({
                      tag: status?.dockerHubTag?.tagName || '',
                      digest: status?.dockerHubTag?.digest || '',
                    });
                  }}
                >
                  填入当前候选
                </button>
              ) : null}
            </div>
            <div style={{ borderTop: '1px dashed var(--color-border-light)', marginTop: 4, paddingTop: 12, marginBottom: 12 }}>
              <div style={{ fontSize: 12, color: 'var(--color-text-primary)', fontWeight: 600, marginBottom: 6 }}>
                最近非稳定 Docker 标签
              </div>
              <div style={{ ...fieldHintStyle, marginBottom: 10 }}>
                自动列出最近推送的 dev / 分支 / sha 标签；点部署即可直接使用，不必手动输入 tag 和 digest。
              </div>
              {recentDockerCandidates.length ? (
                <div style={{ display: 'grid', gap: 8 }}>
                  {recentDockerCandidates.map((candidate) => {
                    const candidateTag = String(candidate.tagName || '').trim();
                    const candidateDigest = String(candidate.digest || '').trim();
                    const candidateLabel = candidate.displayVersion || candidate.normalizedVersion || candidateTag;
                    const candidateDeployState = describeDockerDeployState({
                      enabled: config.enabled && config.dockerHubTagsEnabled,
                      helperHealthy,
                      helperError: status?.helper?.error,
                      currentVersion: status?.currentVersion,
                      helper: status?.helper,
                      candidate,
                    });
                    const canDeployCandidate = !deploying && candidateDeployState.canDeploy;
                    return (
                      <div
                        key={`${candidateTag}:${candidateDigest || 'no-digest'}`}
                        style={{
                          border: '1px solid var(--color-border-light)',
                          borderRadius: 'var(--radius-sm)',
                          padding: 10,
                          display: 'grid',
                          gap: 8,
                        }}
                      >
                        <div style={{ ...summaryValueStyle, fontFamily: 'var(--font-mono)', marginBottom: 0 }}>
                          {candidateLabel}
                        </div>
                        <div style={fieldHintStyle}>
                          最近推送：{formatTaskTime(candidate.publishedAt)}
                        </div>
                        {candidateDigest ? (
                          <div style={{ ...fieldHintStyle, fontFamily: 'var(--font-mono)' }} title={candidateDigest}>
                            Digest：{formatShortDigest(candidateDigest)}
                          </div>
                        ) : null}
                        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                          <button
                            type="button"
                            className="btn btn-ghost"
                            style={{ border: '1px solid var(--color-border)' }}
                            disabled={!canDeployCandidate || !candidateTag}
                            title={candidateDeployState.reason}
                            onClick={() => {
                              if (!canDeployCandidate || !candidateTag) return;
                              void runDeploy('docker-hub-tag', {
                                tag: candidateTag,
                                digest: candidateDigest || null,
                              });
                            }}
                          >
                            部署 {candidateTag}
                          </button>
                          <button
                            type="button"
                            className="btn btn-ghost"
                            style={{ border: '1px solid var(--color-border)' }}
                            onClick={() => {
                              setManualDockerTarget({
                                tag: candidateTag,
                                digest: candidateDigest,
                              });
                            }}
                          >
                            填入手动区
                          </button>
                        </div>
                      </div>
                    );
                  })}
                </div>
              ) : (
                <div style={fieldHintStyle}>
                  暂未发现最近的 dev / 分支 / sha 标签；仍可在下方手动填写任意 Docker 标签。
                </div>
              )}
            </div>
            <div style={{ borderTop: '1px dashed var(--color-border-light)', marginTop: 4, paddingTop: 12 }}>
              <div style={{ fontSize: 12, color: 'var(--color-text-primary)', fontWeight: 600, marginBottom: 6 }}>
                手动部署 Docker Hub 标签
              </div>
              <div style={{ ...fieldHintStyle, marginBottom: 10 }}>
                自动发现已经覆盖最近的非稳定标签；如果你要部署更老或更特殊的 tag，仍可直接在这里填写。
              </div>
              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: isMobile ? '1fr' : 'repeat(2, minmax(0, 1fr))',
                  gap: 8,
                  marginBottom: 8,
                }}
              >
                <input
                  value={manualDockerTarget.tag}
                  onChange={(e) => setManualDockerTarget((prev) => ({ ...prev, tag: e.target.value }))}
                  style={{ ...inputStyle, fontFamily: 'var(--font-mono)' }}
                  placeholder="dev / dev-20260417-f67ade2 / sha-f67ade2"
                />
                <input
                  value={manualDockerTarget.digest}
                  onChange={(e) => setManualDockerTarget((prev) => ({ ...prev, digest: e.target.value }))}
                  style={{ ...inputStyle, fontFamily: 'var(--font-mono)' }}
                  placeholder="可选 digest：sha256:..."
                />
              </div>
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
                <button
                  type="button"
                  className="btn btn-ghost"
                  style={{ border: '1px solid var(--color-border)' }}
                  disabled={!canDeployManualDocker}
                  onClick={() => {
                    if (!canDeployManualDocker) return;
                    void runDeploy('docker-hub-tag', {
                      tag: manualDockerTag,
                      digest: manualDockerDigest || null,
                    });
                  }}
                >
                  部署自定义 Docker 标签
                </button>
                <span style={fieldHintStyle}>
                  digest 选填；如果 chart 当前锁定了旧 digest，建议把 tag 和 digest 一起填写。
                </span>
              </div>
            </div>
          </div>
        </div>

        <div
          style={{
            display: 'grid',
            gridTemplateColumns: isMobile ? '1fr' : 'repeat(2, minmax(0, 1fr))',
            gap: 12,
          }}
        >
          <div style={sectionPanelStyle}>
            <div style={fieldLabelStyle}>Helper 健康摘要</div>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap', marginBottom: 6 }}>
              <span className={helperBadge.className}>{helperBadge.label}</span>
              <span className={runningTaskBadge.className}>当前任务 · {runningTaskBadge.label}</span>
            </div>
            <div style={fieldHintStyle}>
              {status?.helper?.error || 'Helper 正常时会先执行 helm upgrade，再等待 kubectl rollout status。'}
            </div>
            <div style={{ ...fieldHintStyle, marginTop: 6 }}>
              当前镜像：{formatImageTarget(status?.helper?.imageTag, status?.helper?.imageDigest) || '等待 helper 返回运行中镜像'}
            </div>
          </div>

          <div style={sectionPanelStyle}>
            <div style={fieldLabelStyle}>任务快照</div>
            <div style={{ display: 'grid', gap: 6, fontSize: 13, color: 'var(--color-text-primary)' }}>
              <div>
                运行中任务：
                <span style={{ marginLeft: 6, color: 'var(--color-text-secondary)' }}>
                  {status?.runningTask?.id ? `${status.runningTask.id} · ${status.runningTask.status || '-'}` : '无'}
                </span>
              </div>
              <div>
                最近完成：
                <span style={{ marginLeft: 6, color: 'var(--color-text-secondary)' }}>
                  {status?.lastFinishedTask?.id
                    ? `${status.lastFinishedTask.id} · ${status.lastFinishedTask.status || '-'}`
                    : '无'}
                </span>
              </div>
              <div style={fieldHintStyle}>
                完成时间：{formatTaskTime(status?.lastFinishedTask?.finishedAt)}
              </div>
            </div>
          </div>
        </div>
      </div>

      <div style={{ ...sectionPanelStyle, marginBottom: 12 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, marginBottom: 10, flexWrap: 'wrap' }}>
          <div style={{ fontWeight: 600, fontSize: 13 }}>回退历史</div>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            <span className="badge badge-muted">最近 revision</span>
            {helperHistory.length > historyPreview.length ? (
              <button
                type="button"
                className="btn btn-ghost"
                style={{ border: '1px solid var(--color-border)', padding: '4px 10px', minHeight: 0 }}
                onClick={() => setHistoryModalOpen(true)}
              >
                展开全部 {helperHistory.length} 条
              </button>
            ) : null}
          </div>
        </div>
        <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginBottom: 10 }}>
          页面里默认只保留最近 revision 预览，完整历史放进弹窗，避免设置页被长回退列表拖得过长。
        </div>
        {helperHistory.length > 0 ? (
          <div style={{ display: 'grid', gap: 10 }}>
            {historyPreview.map((entry) => {
              const revision = String(entry?.revision || '').trim();
              return (
                <UpdateCenterHistoryEntryCard
                  key={revision || 'unknown-revision'}
                  entry={entry}
                  currentRevision={currentRevision}
                  helperHealthy={helperHealthy}
                  deploying={deploying}
                  compact
                  formatTaskTime={formatTaskTime}
                  formatImageTarget={formatImageTarget}
                  onRollback={(nextRevision) => {
                    void runRollback(nextRevision);
                  }}
                />
              );
            })}
          </div>
        ) : (
          <div style={fieldHintStyle}>
            Helper 还没有返回可回退的 revision 历史。至少成功部署过一次后，这里才会稳定显示历史记录。
          </div>
        )}
      </div>

      <div style={sectionPanelStyle}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, marginBottom: 10, flexWrap: 'wrap' }}>
          <div style={{ fontWeight: 600, fontSize: 13 }}>部署日志</div>
          <span className={getTaskBadge(visibleTaskStatus).className}>
            任务状态 · {getTaskBadge(visibleTaskStatus).label}
          </span>
        </div>
        <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginBottom: 10 }}>
          日志流断开时会自动回退到任务快照。这里只保留最近 200 条输出，方便直接判断 Helm 与 rollout 卡在哪一步。
        </div>
        <div
          style={{
            border: '1px solid var(--color-border-light)',
            borderRadius: 'var(--radius-sm)',
            background: 'var(--color-bg-card)',
            padding: 12,
            minHeight: 120,
          }}
        >
          {logs.length > 0 ? (
            <pre
              style={{
                margin: 0,
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-word',
                fontSize: 12,
                lineHeight: 1.65,
                color: 'var(--color-text-secondary)',
                fontFamily: 'var(--font-mono)',
              }}
            >
              {logs.join('\n')}
            </pre>
          ) : (
            <div style={{ ...fieldHintStyle, minHeight: 94, display: 'flex', alignItems: 'center' }}>
              部署开始后，这里会实时显示 helm upgrade、kubectl rollout status 和回滚日志。
            </div>
          )}
        </div>
      </div>
      {status?.helper?.error ? (
        <div style={{ fontSize: 12, color: 'var(--color-danger)', marginTop: 10 }}>
          Helper 错误：{status.helper.error}
        </div>
      ) : null}
      <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginTop: 10 }}>
        最近状态：{visibleTaskStatus}
      </div>
      <UpdateCenterHistoryModal
        open={historyModalOpen}
        helperHealthy={helperHealthy}
        deploying={deploying}
        currentRevision={currentRevision}
        history={helperHistory}
        formatTaskTime={formatTaskTime}
        formatImageTarget={formatImageTarget}
        onClose={() => setHistoryModalOpen(false)}
        onRollback={(revision) => {
          setHistoryModalOpen(false);
          void runRollback(revision);
        }}
      />
    </div>
  );
}
