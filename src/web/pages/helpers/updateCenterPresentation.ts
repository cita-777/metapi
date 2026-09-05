import {
  compareStableVersions,
  resolveUpdateReminderCandidate,
  type UpdateVersionCandidateLike,
} from '../../../shared/updateCenterReminder.js';

export type UpdateDeployState = {
  kind: 'disabled' | 'missing' | 'unsupported' | 'same-version' | 'new-version' | 'available';
  badgeClassName: string;
  badgeLabel: string;
  reason: string;
  canDeploy: boolean;
  highlight: boolean;
};

export type UpdateReminder = {
  label: string;
  badgeClassName: string;
  detail: string;
  highlight: boolean;
};

function normalizeString(value?: string | null): string {
  return String(value || '').trim();
}

export function describeUpdateState(input: {
  enabled: boolean;
  supported: boolean;
  reason?: string | null;
  currentVersion?: string | null;
  candidate?: UpdateVersionCandidateLike | null;
}): UpdateDeployState {
  if (!input.enabled) {
    return {
      kind: 'disabled',
      badgeClassName: 'badge badge-muted',
      badgeLabel: '已停用',
      reason: '启用后才可以从官方 Release 执行应用内升级。',
      canDeploy: false,
      highlight: false,
    };
  }
  if (!input.supported) {
    return {
      kind: 'unsupported',
      badgeClassName: 'badge badge-warning',
      badgeLabel: '暂不支持',
      reason: input.reason || '当前运行环境不满足本地升级条件。',
      canDeploy: false,
      highlight: false,
    };
  }

  const candidateVersion = normalizeString(input.candidate?.normalizedVersion);
  if (!candidateVersion) {
    return {
      kind: 'missing',
      badgeClassName: 'badge badge-warning',
      badgeLabel: '暂无 Release',
      reason: '尚未获取到可用的稳定 Release。',
      canDeploy: false,
      highlight: false,
    };
  }

  const comparison = compareStableVersions(input.currentVersion, candidateVersion);
  if (comparison === 0) {
    return {
      kind: 'same-version',
      badgeClassName: 'badge badge-muted',
      badgeLabel: '当前版本',
      reason: '当前运行版本已经是该 Release。',
      canDeploy: false,
      highlight: false,
    };
  }
  if (comparison === -1) {
    return {
      kind: 'new-version',
      badgeClassName: 'badge badge-success',
      badgeLabel: '发现新版本',
      reason: '检测到更新的稳定 Release，可以开始一键升级。',
      canDeploy: true,
      highlight: true,
    };
  }
  return {
    kind: 'available',
    badgeClassName: 'badge badge-info',
    badgeLabel: '可安装',
    reason: '该 Release 已可安装。',
    canDeploy: true,
    highlight: false,
  };
}

export function buildUpdateReminder(input: {
  currentVersion?: string | null;
  latestRelease?: UpdateVersionCandidateLike | null;
}): UpdateReminder {
  const latestVersion = normalizeString(
    input.latestRelease?.displayVersion
      || input.latestRelease?.normalizedVersion
      || input.latestRelease?.tagName,
  );
  if (!latestVersion) {
    return {
      label: '等待检查',
      badgeClassName: 'badge badge-muted',
      detail: '点击“检查更新”获取官方稳定 Release。',
      highlight: false,
    };
  }

  const candidate = resolveUpdateReminderCandidate({
    currentVersion: input.currentVersion,
    latestRelease: input.latestRelease,
  });
  if (candidate) {
    return {
      label: '发现新版本',
      badgeClassName: 'badge badge-success',
      detail: `官方稳定版 ${candidate.displayVersion} 已可安装。`,
      highlight: true,
    };
  }
  return {
    label: '已是最新',
    badgeClassName: 'badge badge-muted',
    detail: `当前版本与 ${latestVersion} 一致。`,
    highlight: false,
  };
}
