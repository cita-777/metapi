import {
  compareStableVersions,
  isSameImageTarget,
  resolveUpdateReminderCandidate,
  type UpdateHelperRuntimeLike,
  type UpdateVersionCandidateLike,
} from '../../../shared/updateCenterReminder.js';

export type UpdateDeployState = {
  kind: 'disabled' | 'missing' | 'helper-unhealthy' | 'same-version' | 'same-image' | 'new-version' | 'new-digest' | 'available';
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

function normalizeDigest(value?: string | null): string {
  const digest = normalizeString(value);
  return /^sha256:[a-f0-9]{64}$/i.test(digest) ? digest.toLowerCase() : '';
}

export function describeGitHubDeployState(input: {
  enabled: boolean;
  helperHealthy: boolean;
  helperError?: string | null;
  currentVersion?: string | null;
  helperImageTag?: string | null;
  candidate: UpdateVersionCandidateLike | null | undefined;
}): UpdateDeployState {
  if (!input.enabled) {
    return {
      kind: 'disabled',
      badgeClassName: 'badge badge-muted',
      badgeLabel: '已停用',
      reason: '当前来源已停用，开启后才会参与检查和部署。',
      canDeploy: false,
      highlight: false,
    };
  }

  const candidateVersion = normalizeString(input.candidate?.normalizedVersion);
  const candidateTag = normalizeString(input.candidate?.tagName || candidateVersion);
  if (!candidateVersion && !candidateTag) {
    return {
      kind: 'missing',
      badgeClassName: 'badge badge-warning',
      badgeLabel: '未发现版本',
      reason: '当前来源还没有可部署版本。',
      canDeploy: false,
      highlight: false,
    };
  }

  if (!input.helperHealthy) {
    return {
      kind: 'helper-unhealthy',
      badgeClassName: 'badge badge-warning',
      badgeLabel: '等待 helper',
      reason: input.helperError || 'Deploy Helper 未健康，先修复 helper 再部署。',
      canDeploy: false,
      highlight: false,
    };
  }

  const candidateTargetVersion = candidateVersion || candidateTag;
  const versionCompare = compareStableVersions(input.currentVersion, candidateTargetVersion);
  const helperVersionCompare = compareStableVersions(input.helperImageTag, candidateTargetVersion);
  if (versionCompare === 0 || helperVersionCompare === 0 || helperVersionCompare === 1) {
    return {
      kind: 'same-version',
      badgeClassName: 'badge badge-muted',
      badgeLabel: '当前运行',
      reason: helperVersionCompare === 1
        ? 'Deploy Helper 已指向更高版本，无需回退到较旧的 GitHub 稳定版。'
        : '当前已运行该版本，无需重复部署。',
      canDeploy: false,
      highlight: false,
    };
  }

  if (versionCompare === -1) {
    return {
      kind: 'new-version',
      badgeClassName: 'badge badge-success',
      badgeLabel: '发现新版本',
      reason: '检测到比当前运行版本更新的稳定版，可直接发起部署。',
      canDeploy: true,
      highlight: true,
    };
  }

  return {
    kind: 'available',
    badgeClassName: 'badge badge-info',
    badgeLabel: '可部署',
    reason: '版本可用，点击按钮即可通过 helper 发起滚动更新。',
    canDeploy: true,
    highlight: false,
  };
}

export function describeDockerDeployState(input: {
  enabled: boolean;
  helperHealthy: boolean;
  helperError?: string | null;
  currentVersion?: string | null;
  helper: UpdateHelperRuntimeLike | null | undefined;
  candidate: UpdateVersionCandidateLike | null | undefined;
}): UpdateDeployState {
  if (!input.enabled) {
    return {
      kind: 'disabled',
      badgeClassName: 'badge badge-muted',
      badgeLabel: '已停用',
      reason: '当前来源已停用，开启后才会参与检查和部署。',
      canDeploy: false,
      highlight: false,
    };
  }

  const candidateVersion = normalizeString(input.candidate?.normalizedVersion);
  const candidateTag = normalizeString(input.candidate?.tagName || candidateVersion);
  const candidateDigest = normalizeDigest(input.candidate?.digest);
  if (!candidateVersion && !candidateTag) {
    return {
      kind: 'missing',
      badgeClassName: 'badge badge-warning',
      badgeLabel: '未发现版本',
      reason: '当前来源还没有可部署版本。',
      canDeploy: false,
      highlight: false,
    };
  }

  if (!input.helperHealthy) {
    return {
      kind: 'helper-unhealthy',
      badgeClassName: 'badge badge-warning',
      badgeLabel: '等待 helper',
      reason: input.helperError || 'Deploy Helper 未健康，先修复 helper 再部署。',
      canDeploy: false,
      highlight: false,
    };
  }

  if (isSameImageTarget(input.helper, { tag: candidateTag, digest: candidateDigest })) {
    return {
      kind: 'same-image',
      badgeClassName: 'badge badge-muted',
      badgeLabel: '当前运行',
      reason: '当前已运行该镜像，无需重复部署。',
      canDeploy: false,
      highlight: false,
    };
  }

  const candidateTargetVersion = candidateVersion || candidateTag;
  const helperVersionCompare = compareStableVersions(input.helper?.imageTag, candidateTargetVersion);
  if (helperVersionCompare === 1) {
    return {
      kind: 'same-version',
      badgeClassName: 'badge badge-muted',
      badgeLabel: '当前运行',
      reason: 'Deploy Helper 已指向更高版本，无需回退到较旧镜像。',
      canDeploy: false,
      highlight: false,
    };
  }

  const versionCompare = compareStableVersions(input.currentVersion, candidateTargetVersion);
  if (versionCompare === -1 && (helperVersionCompare == null || helperVersionCompare === -1)) {
    return {
      kind: 'new-version',
      badgeClassName: 'badge badge-success',
      badgeLabel: '发现新版本',
      reason: 'Docker Hub 已出现更高版本，可直接发起部署。',
      canDeploy: true,
      highlight: true,
    };
  }

  const helperDigest = normalizeDigest(input.helper?.imageDigest);
  const hasSameStableTag = isSameImageTarget(
    {
      imageTag: input.helper?.imageTag,
      imageDigest: null,
    },
    {
      tag: candidateTag,
      digest: null,
    },
  );
  if (candidateDigest && helperDigest && hasSameStableTag && helperDigest !== candidateDigest) {
    return {
      kind: 'new-digest',
      badgeClassName: 'badge badge-success',
      badgeLabel: '发现新 digest',
      reason: '标签未变，但镜像 digest 已更新，适合按镜像级别滚动更新。',
      canDeploy: true,
      highlight: true,
    };
  }

  return {
    kind: 'available',
    badgeClassName: 'badge badge-info',
    badgeLabel: '可部署',
    reason: '版本可用，点击按钮即可通过 helper 发起滚动更新。',
    canDeploy: true,
    highlight: false,
  };
}

export function buildUpdateReminder(input: {
  currentVersion?: string | null;
  helper: UpdateHelperRuntimeLike | null | undefined;
  githubRelease: UpdateVersionCandidateLike | null | undefined;
  dockerHubTag: UpdateVersionCandidateLike | null | undefined;
}): UpdateReminder {
  const hasGitHubCandidate = Boolean(normalizeString(
    input.githubRelease?.displayVersion
      || input.githubRelease?.normalizedVersion
      || input.githubRelease?.tagName,
  ));
  const hasDockerCandidate = Boolean(normalizeString(
    input.dockerHubTag?.displayVersion
      || input.dockerHubTag?.normalizedVersion
      || input.dockerHubTag?.tagName
      || input.dockerHubTag?.digest,
  ));
  if (!hasGitHubCandidate && !hasDockerCandidate) {
    return {
      label: '无法检查更新',
      badgeClassName: 'badge badge-muted',
      detail: '暂未获取到可比较的版本信息。',
      highlight: false,
    };
  }

  const candidate = resolveUpdateReminderCandidate({
    currentVersion: input.currentVersion,
    helper: input.helper,
    githubRelease: input.githubRelease,
    dockerHubTag: input.dockerHubTag,
  });
  if (candidate) {
    return {
      label: candidate.kind === 'new-digest' ? '发现新 digest' : '发现新版本',
      badgeClassName: 'badge badge-success',
      detail: candidate.kind === 'new-digest'
        ? 'Docker Hub 的 alias tag 已指向新 digest，可按需部署。'
        : candidate.source === 'github-release'
          ? `GitHub 稳定版 ${normalizeString(input.githubRelease?.displayVersion || input.githubRelease?.normalizedVersion)} 已可部署。`
          : `Docker Hub ${normalizeString(input.dockerHubTag?.displayVersion || input.dockerHubTag?.normalizedVersion)} 已可部署。`,
      highlight: true,
    };
  }

  return {
    label: '已是最新',
    badgeClassName: 'badge badge-muted',
    detail: '当前运行版本与已发现的部署目标没有明显差异。',
    highlight: false,
  };
}
